use super::{Account, Fields, Request, Response, State, Workspace, ROOM_LIMIT, SESSION_COOKIE,
    SESSION_LIFETIME, cookie, cookie_value, equal, fail, header, string, timestamp, token};
use super::transport::{encode, exchange, hmac, write_record};
use crate::Result;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const OAUTH_COOKIE: &str = "__Host-appdev-oauth";
const MENTIONS: &str = "/identity-management/?view=mentions";
const CALLBACK: &str = "/workspace/auth/x/callback";

pub(super) struct Pending {
    ticket: String,
    webhook_id: Value,
    disconnect: bool,
    grant: Value,
    revision: u64,
    expires: i64,
}

pub(super) struct Login {
    verifier: String,
    credentials: Value,
    revision: u64,
    mentions: Option<Pending>,
    expires: i64,
}

enum XAction { Register, Change }

struct XOperation<'a>(&'a Workspace, XAction);
impl Drop for XOperation<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state();
        match self.1 {
            XAction::Register => state.registering = false,
            XAction::Change => state.changing = false,
        }
    }
}

impl Workspace {
    pub(super) fn authorize(&self, request: &Request, query: &Fields, now: i64) -> Result<Response> {
        let mut state = self.state();
        let clear = cookie(OAUTH_COOKIE, "", 0);
        if state.credentials.is_null() { return Ok(redirect("/?sign-in=unavailable", clear)); }
        state.logins.remove(cookie_value(request, OAUTH_COOKIE));
        state.logins.retain(|_, attempt| attempt.expires > now);
        if state.logins.len() >= ROOM_LIMIT { return Ok(Response::text(503, "Sign-in is busy. Try again shortly.")); }
        let mentions = match query.get("mentions") {
            Some(ticket) => match state.pending_mentions.as_ref() {
                Some(pending) if equal(&pending.ticket, ticket) && pending.expires > now && pending.revision == state.credential_revision => {
                    let pending = state.pending_mentions.take().expect("pending X authorization");
                    if !self.grant_active(&state, &pending.grant)? {
                        return Ok(redirect(format!("{MENTIONS}&result=failed"), clear));
                    }
                    Some(pending)
                }
                _ => return Ok(redirect(format!("{MENTIONS}&result=failed"), clear)),
            },
            None => None,
        };
        let state_key = token::<32>()?;
        let verifier = token::<32>()?;
        let fields = self.run(json!({"program":"oauth","operation":"authorize","clientId":state.credentials["clientId"],
            "callback":format!("{}{CALLBACK}",self.runtime.origin),"state":state_key,
            "challenge":Base64UrlUnpadded::encode_string(&Sha256::digest(&verifier))}))?;
        let location = format!("https://x.com/i/oauth2/authorize?{}", encode(&fields)?);
        let attempt = Login { verifier, credentials: state.credentials.clone(), revision: state.credential_revision,
            mentions, expires: now + 600_000 };
        state.logins.insert(state_key.clone(), attempt);
        Ok(redirect(location, cookie(OAUTH_COOKIE, &state_key, 600)))
    }

    pub(super) fn callback(&self, request: &Request, query: &Fields, now: i64) -> Result<Response> {
        let key = cookie_value(request, OAUTH_COOKIE);
        let clear = cookie(OAUTH_COOKIE, "", 0);
        let mut state = self.state();
        if state.credentials.is_null() { return Ok(Response::empty(404)); }
        let attempt = state.logins.get(key).filter(|attempt| attempt.expires > now);
        let failure = if attempt.is_some_and(|attempt| attempt.mentions.is_some()) {
            format!("{MENTIONS}&result=failed")
        } else { "/?sign-in=failed".to_owned() };
        if !attempt.is_some_and(|attempt| attempt.revision == state.credential_revision) ||
            !query.get("state").is_some_and(|received| equal(received, key)) {
            return Ok(redirect(failure, clear));
        }
        let attempt = state.logins.remove(key).expect("validated X authorization");
        let code = query.get("code").filter(|code| !code.is_empty() && query.get("error").is_none());
        let Some(code) = code else { return Ok(redirect(failure, clear)); };
        state.sessions.retain(|_, (_, expires)| *expires > now);
        if let Some(mentions) = &attempt.mentions {
            if !self.grant_active(&state, &mentions.grant)? { return Ok(redirect(failure, clear)); }
        } else if state.sessions.len() >= ROOM_LIMIT { return Ok(redirect(failure, clear)); }
        drop(state);
        match self.exchange_login(request, &attempt, code) {
            Ok(Some((location, session))) => {
                let mut response = redirect(location, clear);
                if let Some(session) = session { response = response.with("Set-Cookie", cookie(SESSION_COOKIE, &session, SESSION_LIFETIME)); }
                Ok(response)
            }
            Ok(None) | Err(_) => Ok(redirect(failure, clear)),
        }
    }

    fn exchange_login(&self, request: &Request, attempt: &Login, code: &str) -> Result<Option<(String, Option<String>)>> {
        let fields = self.run(json!({"program":"oauth","operation":"exchange","code":code,
            "callback":format!("{}{CALLBACK}",self.runtime.origin),"verifier":attempt.verifier}))?;
        let client = string(&attempt.credentials["clientId"])?;
        let secret = string(&attempt.credentials["clientSecret"])?;
        let basic = format!("Basic {}", Base64::encode_string(format!("{client}:{secret}").as_bytes()));
        let token_response = exchange(&self.runtime.x_origin, "/2/oauth2/token", "POST",
            &[("Authorization", &basic), ("Content-Type", "application/x-www-form-urlencoded")], Some(&encode(&fields)?), "8")?;
        if !token_response.success() { return Ok(None); }
        let received: Value = serde_json::from_slice(&token_response.body)?;
        let access = string(&received["access_token"])?;
        if access.is_empty() { return Ok(None); }
        let profile = exchange(&self.runtime.x_origin, "/2/users/me", "GET", &[("Authorization", &format!("Bearer {access}"))], None, "8")?;
        if !profile.success() { return Ok(None); }
        let profile: Value = serde_json::from_slice(&profile.body)?;
        let user = &profile["data"];
        if self.run(json!({"program":"oauth","operation":"profile","profile":user}))? != true { return Ok(None); }
        let mut state = self.state();
        if attempt.revision != state.credential_revision { return Ok(None); }
        if let Some(mentions) = &attempt.mentions {
            if !self.grant_active(&state, &mentions.grant)? { return Ok(None); }
            let decision = if mentions.disconnect { "Authorized disconnecting the X inbox" } else { "Authorized connecting the X inbox" };
            self.receipt(&mut state, &mentions.grant, decision)?;
            let operation = self.office_operation(&mut state, &mentions.grant)?;
            drop(state);
            let outcome = self.change_subscription(mentions, user, access).unwrap_or_else(|_| "failed".to_owned());
            drop(operation);
            return Ok(Some((format!("{MENTIONS}&result={outcome}"), None)));
        }
        let (now, _) = timestamp();
        let account = Account::X(string(&user["username"])?.to_owned());
        Ok(state.start_local_session(request, account, now)?
            .map(|session| ("/workspace/home".to_owned(), Some(session))))
    }

    pub(super) fn mentions_setup(&self, request: &Request, query: &Fields, grant: &Value, fragment: bool) -> Result<Response> {
        if request.method == "GET" {
            let message = match query.get("result") {
                Some("connected") => "X mentions connected.",
                Some("disconnected") => "X mentions disconnected.",
                Some("failed") => "X could not complete the connection change. Check your X app access and authorize the intended account.",
                _ => "",
            };
            return self.mentions_view(200, message, "", fragment);
        }
        let mut state = self.state();
        let reject = if state.credentials.is_null() { Some("Save the X OAuth credentials first.") }
            else if header(request, "content-type") != "application/x-www-form-urlencoded" { Some("Invalid setup request.") }
            else if request.body.len() > 4096 { Some("The setup request is too large.") }
            else { None };
        if let Some(message) = reject {
            drop(state);
            return self.mentions_view(400, message, "", fragment);
        }
        let fields = Fields::parse(&request.body);
        let bearer = fields.get("bearer").unwrap_or_default().trim();
        let connection = &state.inbox["connection"];
        let decision = self.run(json!({"program":"mentions","operation":"setup","action":fields.get("action"),
            "bearer":bearer,"fieldCount":fields.len(),"connected":!connection.is_null(),
            "subscribed":connection["subscriptionId"].as_str().is_some_and(|id|!id.is_empty())}))?;
        if decision["allowed"] != true || state.registering {
            let message = if decision["allowed"] != true { "Enter a fresh app-only Bearer Token or use the connection controls." }
                else { "Webhook setup is already in progress." };
            drop(state);
            return self.mentions_view(400, message, "", fragment);
        }
        let disconnect = decision["disconnect"] == true;
        let revision = state.credential_revision;
        let current = connection["webhookId"].clone();
        state.registering = true;
        drop(state);
        let _operation = XOperation(self, XAction::Register);
        let webhook_id = if disconnect { Ok(current) } else { self.register_webhook(bearer) };
        let webhook_id = match webhook_id {
            Ok(id) => id,
            Err(ProviderError::Status(status)) => {
                let message = format!("X refused webhook setup (HTTP {status}). Check the app token and X API access.");
                return self.mentions_view(400, &message, "", fragment);
            }
            Err(ProviderError::Failed) => return self.registration_failed(fragment),
        };
        let mut state = self.state();
        if revision != state.credential_revision {
            drop(state);
            return self.registration_failed(fragment);
        }
        let ticket = token::<32>()?;
        let (now, _) = timestamp();
        state.pending_mentions = Some(Pending { ticket: ticket.clone(), webhook_id, disconnect, grant: grant.clone(),
            revision, expires: now + 600_000 });
        drop(state);
        let message = if disconnect { "Authorize the connected account to stop delivery." }
            else { "Webhook verified. Authorize the account whose mentions you want to receive." };
        self.mentions_view(200, message, &format!("{}/workspace/auth/x?mentions={ticket}", self.runtime.origin), fragment)
    }

    fn registration_failed(&self, fragment: bool) -> Result<Response> {
        self.mentions_view(400, "X could not verify the webhook. Check the app token and OAuth credentials, then try again.", "", fragment)
    }

    fn mentions_view(&self, status: u16, message: &str, authorization_url: &str, fragment: bool) -> Result<Response> {
        let content = self.mentions_content(&self.state(), message, authorization_url, false)?;
        self.render(status, "x-mentions", &content, fragment)
    }

    pub(super) fn mentions_content(&self, state: &State, message: &str, authorization_url: &str, read_only: bool) -> Result<String> {
        let html = self.run(json!({"program":"mentions","operation":"view","origin":self.runtime.origin,
            "configured":!state.credentials.is_null(),"connection":state.inbox["connection"],"posts":state.inbox["posts"],
            "message":message,"authorizationUrl":authorization_url,"readOnly":read_only}))?;
        Ok(string(&html)?.to_owned())
    }

    fn register_webhook(&self, bearer: &str) -> std::result::Result<Value, ProviderError> {
        let mut step = "start".to_owned();
        let mut response = json!({});
        let mut webhook_id = Value::Null;
        for _ in 0..4 {
            let plan = self.run(json!({"program":"mentions","operation":"register","origin":self.runtime.origin,
                "step":step,"response":response,"webhookId":webhook_id})).map_err(|_| ProviderError::Failed)?;
            match plan["outcome"].as_str() {
                Some("done") => return Ok(plan["webhookId"].clone()),
                Some("request") => {
                    response = self.x_action(&plan, bearer)?;
                    step = plan["step"].as_str().ok_or(ProviderError::Failed)?.to_owned();
                    webhook_id = plan["webhookId"].clone();
                }
                _ => break,
            }
        }
        Err(ProviderError::Failed)
    }

    fn change_subscription(&self, pending: &Pending, user: &Value, bearer: &str) -> Result<String> {
        let mut state = self.state();
        if state.changing || pending.revision != state.credential_revision { return Ok("failed".to_owned()); }
        state.changing = true;
        drop(state);
        let _operation = XOperation(self, XAction::Change);
        let mut step = "start".to_owned();
        let mut response = json!({});
        for _ in 0..4 {
            let mut state = self.state();
            if pending.revision != state.credential_revision { break; }
            let plan = self.run(json!({"program":"mentions","operation":"change","step":step,"response":response,
                "user":user,"webhookId":pending.webhook_id,"disconnect":pending.disconnect,"connection":state.inbox["connection"]}))?;
            if plan["write"] == true {
                let posts = state.inbox["posts"].clone();
                self.write_inbox(&mut state, &plan["connection"], &posts)?;
            }
            drop(state);
            if plan["outcome"] != "request" { return Ok(string(&plan["outcome"])?.to_owned()); }
            response = self.x_action(&plan, bearer).map_err(|_| fail("X subscription action failed"))?;
            step = string(&plan["step"])?.to_owned();
        }
        Ok("failed".to_owned())
    }

    fn x_action(&self, plan: &Value, bearer: &str) -> std::result::Result<Value, ProviderError> {
        let path = plan["path"].as_str().ok_or(ProviderError::Failed)?;
        let method = plan["method"].as_str().ok_or(ProviderError::Failed)?;
        let authorization = format!("Bearer {bearer}");
        let mut headers = vec![("Authorization", authorization.as_str())];
        let body = if plan["body"].is_null() { None } else {
            headers.push(("Content-Type", "application/json"));
            Some(plan["body"].to_string())
        };
        let response = exchange(&self.runtime.x_origin, path, method, &headers, body.as_deref(), "6")
            .map_err(|_| ProviderError::Failed)?;
        if response.status == 204 || response.status == 404 && plan["allowMissing"] == true { return Ok(json!({})); }
        if !response.success() { return Err(ProviderError::Status(response.status)); }
        serde_json::from_slice(&response.body).map_err(|_| ProviderError::Failed)
    }

    fn write_inbox(&self, state: &mut State, connection: &Value, posts: &Value) -> Result<()> {
        let record = json!({"connection":connection,"posts":posts});
        write_record(&self.runtime.private.join("x-mentions.json"), &record, true)?;
        state.inbox = record;
        Ok(())
    }

    pub(super) fn webhook(&self, request: &Request, query: &Fields) -> Result<Response> {
        let mut state = self.state();
        let Some(secret) = state.credentials["clientSecret"].as_str() else {
            return Ok(Response::text(503, "X webhook is awaiting configuration."));
        };
        if request.method == "GET" {
            let mut challenges = query.all("crc_token");
            let challenge = challenges.next().filter(|value| !value.is_empty() && value.encode_utf16().count() <= 512);
            let Some(challenge) = challenge.filter(|_| challenges.next().is_none()) else { return Ok(Response::empty(400)); };
            return Ok(Response::json(200, &json!({"response_token":hmac(secret.as_bytes(),challenge.as_bytes())})));
        }
        if request.method != "POST" { return Ok(Response::empty(405)); }
        let signature = header(request, "x-twitter-webhooks-signature-oauth2");
        if signature.len() != 51 || !equal(&hmac(secret.as_bytes(), &request.body), signature) {
            return Ok(Response::empty(401));
        }
        let Ok(payload) = serde_json::from_slice::<Value>(&request.body) else { return Ok(Response::empty(400)); };
        let connection = state.inbox["connection"].clone();
        if !connection.is_null() {
            let payload = &payload["data"];
            let events: Vec<_> = payload.as_array().map(Vec::as_slice).unwrap_or_else(|| std::slice::from_ref(payload))
                .iter().map(delivery_fields).collect();
            let posts = self.run(json!({"program":"mentions","operation":"delivery","events":events,
                "userId":connection["userId"],"posts":state.inbox["posts"]}))?;
            if !posts.is_null() { self.write_inbox(&mut state, &connection, &posts)?; }
        }
        Ok(Response::empty(200))
    }
}

enum ProviderError { Status(u16), Failed }

fn delivery_fields(event: &Value) -> Value {
    let post = &event["payload"];
    let created = post["created_at"].as_str().or_else(|| event["created_at"].as_str())
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|date| date.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Millis, true));
    let author = event["includes"]["users"].as_array()
        .and_then(|users| users.iter().find(|user| user["id"] == post["author_id"]))
        .and_then(|user| user["username"].as_str());
    json!({"eventType":event["event_type"],"tag":event["tag"],"userId":event["filter"]["user_id"],
        "id":post["id"],"authorId":post["author_id"],"text":post["text"],"username":author,"created":created})
}

fn redirect(location: impl Into<String>, cookie: String) -> Response {
    Response::empty(303).with("Location", location).with("Set-Cookie", cookie)
}
