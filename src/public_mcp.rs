use crate::{Result, fail, http, mcp_project_socket::Client, nonce, process::{HTML_PORTS, HTML_RENDERER, Meter, Programme}};
use serde_json::{Value, json};
use std::{cell::OnceCell, net::TcpStream};

const REQUEST_LIMIT: usize = 65_536;
const REPLY_LIMIT: u64 = 8 * 1024 * 1024;
const METER: usize = 20_000_000;

thread_local! {
    static POLICY: OnceCell<Programme> = const { OnceCell::new() };
}

fn policy() -> Result<Programme> {
    let sources = HTML_RENDERER.into_iter().chain([include_str!("public_mcp.encounter"),
        include_str!("mcp_project_portfolio.encounter"), include_str!("mcp_project_http.encounter"),
        include_str!("mcp_browser_selection.encounter"), include_str!("mcp_browser_consent.encounter"),
        include_str!("mcp_browser_authorize.encounter")]).map(str::to_owned).collect::<Vec<_>>();
    let ports = HTML_PORTS.into_iter().chain([
        "kernel.invoke", "record.fromEntries", "record.put",
        "text.lowerCase", "text.slice", "text.split", "digest.sha256",
    ]).collect();
    Programme::admit_entries(&sources,
        &["publicMcp.admitAuthorization", "publicMcp.route", "publicMcp.health", "publicMcp.refuse",
            "publicMcp.invalid", "publicMcp.oauth", "publicMcp.oauthUnavailable", "publicMcp.message", "publicMcp.sanitize",
            "publicMcp.ingress", "publicMcp.ingressError", "publicMcp.projectUnavailable",
            "mcpBrowserAuthorize.request", "publicMcp.oauthForm", "publicMcp.oauthError", "publicMcp.oauthTokenReply",
            "publicMcp.portfolioCookies", "publicMcp.consentCookies", "mcpBrowserSelection.error", "mcpBrowserConsent.error",
            "mcpBrowserAuthorize.page", "mcpBrowserAuthorize.loginPath", "mcpBrowserAuthorize.error"],
        &ports,
        &mut Meter::new(METER))
}

fn evaluate(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(METER))
}

struct Gateway {
    login: Option<String>,
    public_origin: String,
    oauth_resource: String,
    challenge: String,
    authorization_metadata: Reply,
    resource_metadata: Reply,
    project: Option<Client>,
}

fn json_type(mime: &str) -> bool {
    mime.eq_ignore_ascii_case("application/json")
        || mime.to_ascii_lowercase().strip_prefix("application/").is_some_and(|name| name.ends_with("+json"))
}

impl Gateway {
    fn new(plan: Value) -> Result<Self> {
        let string = |field| serde_json::from_value::<String>(plan[field].clone());
        Ok(Self {
            login:None,
            public_origin: string("origin")?,
            oauth_resource: serde_json::from_value(plan["resourceMetadata"]["resource"].clone())?,
            challenge: string("challenge")?,
            authorization_metadata: Reply::protocol("200 OK", plan["authorizationMetadata"].clone())?,
            resource_metadata: Reply::protocol("200 OK", plan["resourceMetadata"].clone())?,
            project:None,
        })
    }

    fn project(&self, policy: &Programme, request: &http::Request, message: Value) -> Result<Reply> {
        let header = |name| request.headers.get(name).map_or("", String::as_str);
        let id = message["id"].clone();
        let answer = self.project.as_ref().ok_or_else(|| fail("Native hosted project socket is required"))
            .and_then(|client| client.call(header("authorization").strip_prefix("Bearer ").unwrap_or(""),
                message, json!({"version":header("mcp-protocol-version"),"method":header("mcp-method"),
                    "name":header("mcp-name"),"session":header("mcp-session-id"),"userAgent":header("user-agent")})));
        let Ok(answer) = answer else {
            return Reply::protocol("503 Service Unavailable", evaluate(policy, "publicMcp.projectUnavailable", id)?);
        };
        let status = match answer["status"].as_u64() {
            Some(200) => "200 OK",
            Some(202) => return Ok(Reply::empty("202 Accepted")),
            Some(400) => "400 Bad Request",
            Some(401) => "401 Unauthorized",
            Some(403) => "403 Forbidden",
            Some(404) => "404 Not Found",
            Some(503) => "503 Service Unavailable",
            _ => return Reply::protocol("503 Service Unavailable", evaluate(policy, "publicMcp.projectUnavailable", id)?),
        };
        let mut reply = if let Some(events) = answer["events"].as_array() {
            let mut body = Vec::new();
            for event in events {
                body.extend_from_slice(b"event: message\ndata: ");
                serde_json::to_writer(&mut body, event)?;
                body.extend_from_slice(b"\n\n");
            }
            Reply { status:status.to_owned(), type_header:"text/event-stream; charset=utf-8".into(),
                headers:Vec::new(), body, form_origin:None }
        } else { Reply::protocol(status, answer["body"].clone())? };
        if let Some(session) = answer["session"].as_str().filter(|session| {
            session.strip_prefix("sourcery-handshake-").is_some_and(|id| id.len() == 36
                && id.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-'))
        }) {
            reply.headers.push(("mcp-session-id".into(), session.into()));
        }
        if let Some(challenge @ ("invalid_token" | "insufficient_scope")) = answer["challenge"].as_str() {
            let parameters = self.challenge.strip_prefix("Bearer ").ok_or_else(|| fail("Invalid public MCP challenge"))?;
            reply.headers.push(("www-authenticate".into(), format!("Bearer error=\"{challenge}\", {parameters}")));
        }
        reply.sanitize(policy, true)?;
        Ok(reply)
    }

    fn oauth_transaction(&self, policy: &Programme, path: &str, mime: &str, body: &[u8]) -> Result<Reply> {
        let fields: Vec<_> = form_urlencoded::parse(body).collect();
        let plan = evaluate(policy, "publicMcp.oauthForm", json!({
            "path":path,"mime":mime.to_ascii_lowercase(),"fields":fields
        }))?;
        if let Some(reason) = plan["error"].as_str() {
            return oauth_error(policy, reason, plan["detail"].as_str().unwrap_or_default());
        }
        let grant = plan["grant"].as_str().ok_or_else(|| fail("Invalid public OAuth form plan"))?.to_owned();
        let digest = plan["digest"].as_str().ok_or_else(|| fail("Missing public OAuth form digest"))?;
        if grant == "revoke" {
            let outcome = self.project.as_ref().ok_or_else(|| fail("Native public OAuth revocation authority is required"))
                .and_then(|client| client.revoke_oauth(digest));
            return if outcome.is_ok() { Ok(Reply::empty("200 OK")) } else { oauth_error(policy, "backend", "") };
        }
        let outcome = self.project.as_ref().ok_or_else(|| fail("Native public OAuth exchange authority is required"))
            .and_then(|client| client.exchange_oauth(plan));
        let Ok(outcome) = outcome else { return oauth_error(policy, "backend", ""); };
        if let Some(reason @ ("outside" | "unknown" | "target" | "replay")) = outcome["reason"].as_str() {
            return oauth_error(policy, reason, &grant);
        }
        let token = &outcome["token"];
        if evaluate(policy, "publicMcp.oauthTokenReply", json!({"success":true,"body":token}))? != true {
            return oauth_error(policy, "reply", "");
        }
        Reply::protocol("200 OK", token.clone())
    }

    fn browser_form(&self, policy: &Programme, request: &http::Request, mime: &str, consent: bool) -> Result<Reply> {
        let cookie = request.headers.get("cookie").map_or("", String::as_str);
        let mime = mime.to_ascii_lowercase();
        let fields: Vec<_> = if mime == "application/x-www-form-urlencoded" && request.body.len() <= 16 * 1024 {
            form_urlencoded::parse(&request.body).collect()
        } else { Vec::new() };
        let result = self.project.as_ref().ok_or_else(|| fail("Native hosted project socket is required"))
            .and_then(|client| client.browser_form(cookie, json!({
                "mime":mime,"size":request.body.len(),"fields":fields
            }), consent));
        let result = match result {
            Ok(result) => result,
            Err(_) => evaluate(policy, if consent { "mcpBrowserConsent.error" } else { "mcpBrowserSelection.error" },
                json!("backend"))?,
        };
        let status = match result["status"].as_u64() {
            Some(302) if consent => "302 Found",
            Some(303) if !consent => "303 See Other",
            Some(400) => "400 Bad Request",
            Some(401) => "401 Unauthorized",
            Some(403) => "403 Forbidden",
            Some(413) => "413 Content Too Large",
            Some(415) => "415 Unsupported Media Type",
            Some(503) => "503 Service Unavailable",
            _ => return Err(fail("Invalid native browser form response")),
        };
        let mut reply = if matches!(result["status"].as_u64(), Some(302 | 303)) {
            let location = result["location"].as_str().filter(|href| {
                let destination = if consent { href.starts_with("https://") || href.starts_with("http://") }
                    else { href.starts_with("/oauth/authorize?") };
                destination && href.bytes().all(|byte| byte.is_ascii_graphic()) && !href.contains(['#', '\\'])
            }).ok_or_else(|| fail("Invalid native browser redirect"))?;
            let mut reply = Reply::empty(status);
            reply.headers.push(("location".into(), location.into()));
            reply
        } else { Reply::protocol(status, result["body"].clone())? };
        let cookies: Vec<String> = serde_json::from_value(evaluate(policy,
            if consent { "publicMcp.consentCookies" } else { "publicMcp.portfolioCookies" }, Value::Null)?)?;
        reply.headers.extend(cookies.into_iter().map(|cookie| ("set-cookie".to_owned(), cookie)));
        reply.headers.push(("referrer-policy".into(), "no-referrer".into()));
        Ok(reply)
    }

    fn browser_authorization(&self, policy: &Programme, request: &http::Request) -> Result<Reply> {
        let cookie = request.headers.get("cookie").map_or("", String::as_str);
        let browser = self.project.as_ref().ok_or_else(|| fail("Native hosted project socket is required"))
            .and_then(|client| client.authorize_browser(cookie, &request.path))
            .unwrap_or_else(|_| json!({"error":"backend"}));
        if let Some(reason) = browser["error"].as_str() {
            if reason == "session" && let Some(login) = &self.login {
                let query = form_urlencoded::Serializer::new(String::new()).append_pair("return", &request.path).finish();
                let mut reply = Reply::empty("303 See Other");
                reply.headers.push(("location".into(), format!("{login}?{query}")));
                reply.headers.push(("referrer-policy".into(), "no-referrer".into()));
                return Ok(reply);
            }
            if matches!(reason, "parameter" | "authorizationTarget" | "challenge" | "responseType" | "outside") {
                return oauth_error(policy, reason, browser["detail"].as_str().unwrap_or_default());
            }
            let error = evaluate(policy, "mcpBrowserAuthorize.error", json!(reason))?;
            let status = error["status"].as_str().ok_or_else(|| fail("Missing native authorization error status"))?;
            return Reply::protocol(status, error["body"].clone());
        }
        let page = evaluate(policy, "mcpBrowserAuthorize.page", browser.clone())?;
        let body = page["body"].as_str().ok_or_else(|| fail("Missing native authorization page"))?.as_bytes().to_vec();
        let cookie = page["cookie"].as_str().ok_or_else(|| fail("Missing authorization form cookie"))?;
        let path = page["path"].as_str().ok_or_else(|| fail("Missing authorization form path"))?;
        let csrf = browser["csrf"].as_str().filter(|value| !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)))
            .ok_or_else(|| fail("Invalid native authorization form signature"))?;
        let mut reply = Reply::empty("200 OK");
        reply.type_header = "text/html; charset=utf-8".into();
        reply.body = body;
        reply.headers.push(("set-cookie".into(), format!("{cookie}=; Path={path}; Max-Age=0; Secure; HttpOnly; SameSite=Lax")));
        reply.headers.push(("set-cookie".into(), format!("{cookie}={csrf}; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax")));
        reply.headers.push(("referrer-policy".into(), "no-referrer".into()));
        reply.headers.push(("x-frame-options".into(), "DENY".into()));
        if browser["kind"] == "consent" {
            let uri = browser["redirectUri"].as_str().ok_or_else(|| fail("Missing native authorization callback"))?;
            let (scheme, tail) = uri.split_once("://").ok_or_else(|| fail("Invalid native authorization callback"))?;
            let (host, _) = tail.split_once('/').ok_or_else(|| fail("Missing native authorization callback path"))?;
            if !matches!(scheme, "https" | "http") || host.is_empty()
                || !host.bytes().all(|byte| byte.is_ascii_alphanumeric() || b":._-[]".contains(&byte)) {
                return Err(fail("Invalid native authorization callback origin"));
            }
            reply.form_origin = Some(format!("{scheme}://{host}"));
        }
        Ok(reply)
    }

    fn response(&self, policy: &Programme, request: &http::Request) -> Result<Reply> {
        if !request.path.starts_with('/') || request.path.starts_with("//") || request.path.contains(['\\', '#'])
            || !request.path.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(fail("Expected an origin-form public MCP request"));
        }
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        let content_type = request.headers.get("content-type").map_or("", String::as_str);
        let mime = content_type.split(';').next().unwrap_or_default().trim();
        let route = evaluate(policy, "publicMcp.route", json!({
            "path":path,"method":request.method,"query":!query.is_empty(),"type":mime
        }))?;
        match route.as_str() {
            Some("health") => return Reply::json("200 OK", evaluate(policy, "publicMcp.health", Value::Null)?),
            Some("portfolio" | "consent") => self.browser_form(policy, request, mime, route == "consent"),
            Some("mcp") => {
                let message: Value = serde_json::from_slice(&request.body)?;
                if evaluate(policy, "publicMcp.message", message.clone())? != true {
                    return refusal(policy, message["id"].clone());
                }
                let header = |name| request.headers.get(name).map_or("", String::as_str);
                let admission = evaluate(policy, "publicMcp.ingress", json!({
                    "accept":header("accept"), "authorization":header("authorization"),
                    "origin":header("origin"), "publicOrigin":self.public_origin
                }))?;
                match admission.as_str() {
                    Some("bearer") => {}
                    Some(reason @ ("accept" | "origin" | "challenge")) => {
                        let request_id = (reason == "accept").then(nonce::uuid_v4).transpose()?;
                        let rejected = evaluate(policy, "publicMcp.ingressError", json!({
                            "reason":reason, "requestId":request_id
                        }))?;
                        let status = rejected["status"].as_str().ok_or_else(|| fail("Expected a public MCP error status"))?;
                        let mut reply = Reply::protocol(status, rejected["body"].clone())?;
                        if reason == "challenge" {
                            reply.headers.push(("www-authenticate".to_owned(), self.challenge.clone()));
                        }
                        return Ok(reply);
                    }
                    _ => return Err(fail("Invalid public MCP ingress decision")),
                }
                return self.project(policy, request, message);
            }
            Some("authorize" | "oauth" | "oauthUnavailable" | "authorizationMetadata" | "resourceMetadata") => {
                let mut scopes = Vec::new();
                collect_scopes(query.as_bytes(), &mut scopes);
                let body = if request.method != "POST" { Vec::new() }
                else if json_type(mime) {
                    let message: Value = serde_json::from_slice(&request.body)?;
                    let object = message.as_object().ok_or_else(|| fail("Expected an OAuth object"))?;
                    scopes.extend(object.get("scope").cloned());
                    serde_json::to_vec(&message)?
                } else {
                    collect_scopes(&request.body, &mut scopes);
                    if let Ok(message) = serde_json::from_slice::<Value>(&request.body) {
                        scopes.extend(message.get("scope").cloned());
                    }
                    request.body.clone()
                };
                if evaluate(policy, "publicMcp.oauth", json!(scopes))? != true {
                    return refusal(policy, Value::Null);
                }
                if route == "authorizationMetadata" { return Ok(self.authorization_metadata.clone()); }
                if route == "resourceMetadata" { return Ok(self.resource_metadata.clone()); }
                if route == "oauthUnavailable" {
                    return Reply::protocol("404 Not Found", evaluate(policy, "publicMcp.oauthUnavailable", Value::Null)?);
                }
                if route == "oauth" { return self.oauth_transaction(policy, path, mime, &body); }
                let fields: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();
                let admission = evaluate(policy, "mcpBrowserAuthorize.request", json!({
                    "fields":fields,"resource":self.oauth_resource
                }))?;
                let error = admission["error"].as_str().ok_or_else(|| fail("Invalid public OAuth admission"))?;
                if !error.is_empty() {
                    return oauth_error(policy, error, admission["detail"].as_str().unwrap_or(""));
                }
                self.browser_authorization(policy, request)
            }
            Some("refuse") => refusal(policy, Value::Null),
            _ => Err(fail("Invalid public MCP route")),
        }
    }
}

fn collect_scopes(bytes: &[u8], scopes: &mut Vec<Value>) {
    scopes.extend(form_urlencoded::parse(bytes).filter(|(name, _)| name == "scope")
        .map(|(_, value)| json!(value)));
}

fn refusal(policy: &Programme, id: Value) -> Result<Reply> {
    Reply::json("403 Forbidden", evaluate(policy, "publicMcp.refuse", id)?)
}

fn oauth_error(policy: &Programme, reason: &str, detail: &str) -> Result<Reply> {
    let response = evaluate(policy, "publicMcp.oauthError", json!({"reason":reason,"detail":detail}))?;
    let status = response["status"].as_str().ok_or_else(|| fail("Missing public OAuth status"))?;
    Reply::protocol(status, response["body"].clone())
}

#[derive(Clone)]
struct Reply {
    status: String,
    type_header: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    form_origin: Option<String>,
}

impl Reply {
    fn empty(status: &str) -> Self {
        Self { status:status.to_owned(), type_header:"application/json".to_owned(), headers:Vec::new(), body:Vec::new(), form_origin:None }
    }

    fn json(status: &str, value: Value) -> Result<Self> {
        Ok(Self { status:status.to_owned(), type_header:"application/json".to_owned(),
            headers:Vec::new(), body:serde_json::to_vec(&value)?, form_origin:None })
    }

    fn protocol(status: &str, value: Value) -> Result<Self> {
        let mut reply = Self::json(status, value)?;
        reply.type_header.push_str("; charset=utf-8");
        Ok(reply)
    }

    fn sanitize(&mut self, policy: &Programme, mcp: bool) -> Result<()> {
        if self.body.is_empty() { return Ok(()); }
        let mime = self.type_header.split(';').next().unwrap_or_default().trim();
        let mut meter = Meter::new(METER);
        let sanitize = |data: &str, meter: &mut Meter| {
            policy.run("publicMcp.sanitize", serde_json::from_str(data)?, meter)
        };
        match mime {
            mime if json_type(mime) => {
                let value = sanitize(std::str::from_utf8(&self.body)?, &mut meter)?;
                self.body = serde_json::to_vec(&value)?;
            }
            "text/event-stream" => {
                let mut output = Vec::new();
                let text = std::str::from_utf8(&self.body)?.trim_start_matches('\u{feff}');
                let text = text.replace("\r\n", "\n");
                for (index, line) in text.split(['\r', '\n']).enumerate() {
                    if index > 0 { output.push(b'\n'); }
                    if let Some(data) = line.strip_prefix("data:") {
                        let value = sanitize(data.trim(), &mut meter)?;
                        output.extend_from_slice(b"data: ");
                        serde_json::to_writer(&mut output, &value)?;
                    } else {
                        output.extend_from_slice(line.as_bytes());
                    }
                    if output.len() as u64 > REPLY_LIMIT { return Err(fail("Public MCP projection exceeds its size limit")); }
                }
                self.body = output;
            }
            _ if mcp => return Err(fail("Expected a JSON or SSE public MCP reply")),
            _ => {}
        }
        if self.body.len() as u64 > REPLY_LIMIT { return Err(fail("Public MCP projection exceeds its size limit")); }
        Ok(())
    }

    fn write(&self, stream: &mut TcpStream) -> Result<()> {
        let mut headers = String::new();
        for (key, value) in &self.headers { headers.push_str(&format!("{key}: {value}\r\n")); }
        if let Some(origin) = &self.form_origin {
            return http::send_oauth_form(stream, &headers, &self.body, origin);
        }
        http::send_bytes(stream, &self.status, &self.type_header, &headers, &self.body)
    }
}

pub fn serve(port: u16, authorization: Value, project: Client) -> Result<()> {
    if port < 1024 { return Err(fail("Expected an unprivileged public MCP loopback port")); }
    let programme = policy()?;
    let mut gateway = Gateway::new(evaluate(&programme, "publicMcp.admitAuthorization", authorization)?)?;
    if let Ok(login) = std::env::var("SOURCERY_HOSTED_BROWSER_LOGIN_PATH") {
        let login = login.trim();
        if !login.is_empty() {
            if evaluate(&programme, "mcpBrowserAuthorize.loginPath", json!(login))? != true {
                return Err(fail("Hosted browser login must use a same-origin path"));
            }
            gateway.login = Some(login.to_owned());
        }
    }
    gateway.project = Some(project);
    http::serve_chunked_workers(port, 4, REQUEST_LIMIT, move |stream, request| {
        let reply = POLICY.with(|slot| {
            if slot.get().is_none() { let _ = slot.set(policy()?); }
            let policy = slot.get().expect("admitted public MCP policy");
            gateway.response(policy, &request).or_else(|_| Reply::json("400 Bad Request",
                evaluate(policy, "publicMcp.invalid", Value::Null)?))
        });
        if http::stopping() { return; }
        if let Err(error) = reply.and_then(|reply| reply.write(stream)) {
            if error.downcast_ref::<std::io::Error>().is_none() { eprintln!("Public MCP transport: {error}"); }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> Value {
        json!({
            "protocol":"sourcery-hosted-mcp-authorization/1",
            "resource":"https://mcp.sourcerytech.com.au/mcp",
            "authorizationServers":["https://mcp.sourcerytech.com.au/"],
            "clientRegistrationModes":["clientIdMetadataDocumentV1"],
            "discoveryScope":"authoring.read",
            "toolScopes":{"sourcery_project":"authoring.read","sourcery_knowledge_catalogue":"authoring.read"},
            "scopeImplications":{"authoring.read":[]},
            "modes":{
                "unmappedTool":"denyV1",
                "authorizationFlow":"authorizationCodePkceS256ResourceIndicatorV1",
                "consentInteraction":"authoredConsequenceSignedDoubleSubmitV1",
                "workspaceSelection":"explicitCurrentApplicationPortfolioEncryptedResumeV1",
                "authorizationCode":"singleUseDigestClientRedirectPkceResourceBoundV1",
                "accessToken":"opaqueDigestAudienceScopeGrantBoundV1",
                "refreshToken":"rotatingFamilyReplayRevocationV1"
            }
        })
    }

    #[test]
    fn public_mcp_requires_the_matched_read_authorization_contract() -> Result<()> {
        let policy = policy()?;
        let contract = contract();
        assert!(evaluate(&policy, "publicMcp.admitAuthorization", contract.clone()).is_ok());
        let mut moved = contract.clone();
        moved["toolScopes"]["sourcery_project"] = json!("authoring.write");
        assert!(evaluate(&policy, "publicMcp.admitAuthorization", moved).is_err());
        let mut widened = contract.clone();
        widened["scopeImplications"]["authoring.read"] = json!(["operations.execute"]);
        assert!(evaluate(&policy, "publicMcp.admitAuthorization", widened).is_err());
        let mut unsupported = contract.clone();
        unsupported["modes"]["authorizationFlow"] = json!("unrecognized");
        assert!(evaluate(&policy, "publicMcp.admitAuthorization", unsupported).is_err());
        let mut unsigned_consent = contract.clone();
        unsigned_consent["modes"]["consentInteraction"] = Value::Null;
        assert!(evaluate(&policy, "publicMcp.admitAuthorization", unsigned_consent).is_err());
        let mut crossed = contract;
        crossed["authorizationServers"] = json!(["https://mcp.sourcerytech.com.au/", "https://elsewhere.example/"]);
        assert!(evaluate(&policy, "publicMcp.admitAuthorization", crossed).is_err());
        Ok(())
    }

    #[test]
    fn public_mcp_refuses_writes_before_contacting_upstream() -> Result<()> {
        let policy = policy()?;
        let gateway = Gateway::new(evaluate(&policy, "publicMcp.admitAuthorization", contract())?)?;
        let post = |path: &str, mime: &str, body: &str| http::Request {
            method:"POST".into(), path:path.into(), headers:[("content-type".into(), mime.into())].into(),
            body:body.as_bytes().to_vec(),
        };
        for request in [
            post("/mcp", "application/json", r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sourcery_project","arguments":{"action":"create"}}}"#),
            post("/oauth/token?scope=authoring.read", "application/x-www-form-urlencoded", "scope=authoring.write"),
            post("/oauth/token", "application/x-www-form-urlencoded", "scope=authoring.read&scope=authoring.write"),
            post("/oauth/register", "Application/JSON", r#"{"scope":"authoring.write"}"#),
        ] {
            assert_eq!(gateway.response(&policy, &request)?.status, "403 Forbidden");
        }
        let development_tool = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"sourcery_knowledge_catalogue","arguments":{"operation":"inspect","entryId":"example"}
        }});
        let mut request = post("/mcp", "application/json", &development_tool.to_string());
        assert_eq!(gateway.response(&policy, &request)?.status, "403 Forbidden");
        request.headers.insert("mcp-protocol-version".into(), "2026-07-28".into());
        assert_eq!(gateway.response(&policy, &request)?.status, "403 Forbidden");
        let registered = gateway.response(&policy, &post("/oauth/register", "application/json",
            r#"{"redirect_uris":["http://127.0.0.1:1455/auth/callback"]}"#))?;
        assert_eq!(registered.status, "404 Not Found");
        assert_eq!(serde_json::from_slice::<Value>(&registered.body)?["error"], "invalid_request");
        let projected = evaluate(&policy, "publicMcp.sanitize", json!({"result":{
            "tools":[{"name":"sourcery_project"},{"name":"sourcery_knowledge_catalogue"}],
            "structuredContent":{"nextCall":{"tool":"sourcery_knowledge_catalogue","args":{"operation":"discover"}}}
        }}))?;
        assert_eq!(projected["result"]["tools"], json!([{"name":"sourcery_project","annotations":{"readOnlyHint":true}}]));
        assert!(projected["result"]["structuredContent"]["nextCall"].is_null());
        Ok(())
    }

    #[test]
    fn browser_authorization_validates_parameters_before_contacting_upstream() -> Result<()> {
        let policy = policy()?;
        let gateway = Gateway::new(evaluate(&policy, "publicMcp.admitAuthorization", contract())?)?;
        let authorize = format!("/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&resource=https%3A%2F%2Fmcp.sourcerytech.com.au%2Fmcp&scope=authoring.read&code_challenge={}&code_challenge_method=S256",
            "a".repeat(43));
        let request = |path| http::Request {
            method:"GET".into(), path, headers:Default::default(), body:Vec::new(),
        };
        for (path, expected) in [
            ("/oauth/authorize".to_owned(), "invalid_request"),
            (format!("{authorize}&%73tate=one&state=two"), "invalid_request"),
            (format!("{authorize}&state="), "invalid_request"),
            (format!("{authorize}&scope=authoring.read"), "invalid_request"),
            (authorize.replace("type=code", "type=token"), "unsupported_response_type"),
            (authorize.replace("method=S256", "method=plain"), "invalid_request"),
            (authorize.replace(&"a".repeat(43), &"a".repeat(42)), "invalid_request"),
            (authorize.replace("au%2Fmcp", "au%2Fother"), "invalid_target"),
            (authorize.replace("mcp.sourcerytech", "MCP.sourcerytech"), "invalid_target"),
        ] {
            let reply = gateway.response(&policy, &request(path))?;
            assert_eq!(reply.status, "400 Bad Request");
            assert_eq!(serde_json::from_slice::<Value>(&reply.body)?["error"], expected);
        }
        let reply = gateway.response(&policy, &request(authorize.replace("authoring.read", "authoring.write")))?;
        assert_eq!(reply.status, "403 Forbidden");

        let path = format!("{authorize}&state=a%2Bb&sourcery_portfolio=signed-selection");
        let reply = gateway.response(&policy, &request(path))?;
        assert_eq!(reply.status, "503 Service Unavailable");
        Ok(())
    }

    #[test]
    fn public_mcp_discovery_and_anonymous_refusals_work_without_upstream() -> Result<()> {
        let policy = policy()?;
        let gateway = Gateway::new(evaluate(&policy, "publicMcp.admitAuthorization", contract())?)?;
        let request = |method: &str, path: &str, headers: &[(&str, &str)]| http::Request {
            method:method.into(), path:path.into(),
            headers:headers.iter().map(|(name, value)| ((*name).into(), (*value).into())).collect(),
            body:if method == "POST" { br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec() } else { Vec::new() },
        };
        let metadata = gateway.response(&policy, &request("GET", "/.well-known/oauth-authorization-server", &[]))?;
        assert_eq!(metadata.status, "200 OK");
        assert_eq!(serde_json::from_slice::<Value>(&metadata.body)?["scopes_supported"], json!(["authoring.read"]));
        let crossed = gateway.response(&policy, &request("GET", "/.well-known/oauth-authorization-server?scope=operations.execute", &[]))?;
        assert_eq!(crossed.status, "403 Forbidden");
        let challenge = gateway.response(&policy, &request("POST", "/mcp", &[
            ("content-type","application/json"), ("accept","application/json, TEXT/EVENT-STREAM"),
            ("authorization","Basic invalid"), ("x-sourcery-ssh-assertion","private")
        ]))?;
        assert_eq!(challenge.status, "401 Unauthorized");
        assert_eq!(challenge.headers, vec![("www-authenticate".to_owned(),
            "Bearer resource_metadata=\"https://mcp.sourcerytech.com.au/.well-known/oauth-protected-resource/mcp\", scope=\"authoring.read\"".to_owned())]);
        assert_eq!(serde_json::from_slice::<Value>(&challenge.body)?["error"]["code"], -32001);
        let crossed_origin = gateway.response(&policy, &request("POST", "/mcp", &[
            ("content-type","application/json"), ("origin","https://crossed.invalid"), ("authorization","Bearer opaque")
        ]))?;
        assert_eq!(crossed_origin.status, "403 Forbidden");
        let unacceptable = gateway.response(&policy, &request("POST", "/mcp", &[("content-type","application/json")]))?;
        assert_eq!(unacceptable.status, "406 Not Acceptable");
        assert_eq!(serde_json::from_slice::<Value>(&unacceptable.body)?["error"]["data"]["sourceryCode"], "accept-invalid");
        Ok(())
    }

    #[test]
    fn modern_project_and_discovery_requests_require_the_native_authority() -> Result<()> {
        let policy = policy()?;
        let gateway = Gateway::new(evaluate(&policy, "publicMcp.admitAuthorization", contract())?)?;
        let mut request = http::Request {
            method:"POST".into(), path:"/mcp".into(),
            headers:[("content-type","application/json"), ("accept","application/json, text/event-stream"),
                ("authorization","Bearer src_mcp_access_fixture"), ("mcp-protocol-version","2026-07-28")]
                .into_iter().map(|(name, value)| (name.into(), value.into())).collect(),
            body:serde_json::to_vec(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":"sourcery_project","arguments":{"action":"list"}}}))?,
        };
        let response = gateway.response(&policy, &request)?;
        assert_eq!(response.status, "503 Service Unavailable");
        assert_eq!(serde_json::from_slice::<Value>(&response.body)?["id"], 4);
        for method in ["server/discover", "tools/list", "ping"] {
            request.body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":5,"method":method}))?;
            assert_eq!(gateway.response(&policy, &request)?.status, "503 Service Unavailable");
            request.body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":5,"method":method,
                "params":{"_meta":{"com.sourcery/projectConnection":{}}}}))?;
            assert_eq!(gateway.response(&policy, &request)?.status, "403 Forbidden");
            request.body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":5,"method":method,
                "params":{"arguments":{"projectContext":"fixture"}}}))?;
            assert_eq!(gateway.response(&policy, &request)?.status, "403 Forbidden");
        }
        let project_list = json!({"result":{"structuredContent":{"nextCall":null,"projects":[]}}});
        assert_eq!(evaluate(&policy, "publicMcp.sanitize", project_list.clone())?, project_list);
        Ok(())
    }

    #[test]
    fn public_oauth_exchange_requires_a_native_grant_and_a_read_only_reply() -> Result<()> {
        let policy = policy()?;
        let gateway = Gateway::new(evaluate(&policy, "publicMcp.admitAuthorization", contract())?)?;
        let mut request = http::Request {
            method:"POST".into(), path:"/oauth/token".into(),
            headers:[("content-type".into(), "application/x-www-form-urlencoded".into())].into(),
            body:b"grant_type=refresh_token&refresh_token=fixture&client_id=client&resource=resource".to_vec(),
        };
        assert_eq!(gateway.response(&policy, &request)?.status, "503 Service Unavailable");
        let mut revocation = http::Request {
            method:"POST".into(), path:"/oauth/revoke".into(), headers:request.headers.clone(),
            body:b"token=fixture&client_id=client".to_vec(),
        };
        assert_eq!(gateway.response(&policy, &revocation)?.status, "503 Service Unavailable");
        revocation.body.extend_from_slice(b"&token=duplicate");
        assert_eq!(gateway.response(&policy, &revocation)?.status, "400 Bad Request");
        request.body.extend_from_slice(b"&refresh_token=duplicate");
        assert_eq!(gateway.response(&policy, &request)?.status, "400 Bad Request");
        let reply = json!({"scope":"authoring.read","token_type":"Bearer","access_token":"fixture-access",
            "refresh_token":"fixture-refresh","expires_in":900});
        assert_eq!(evaluate(&policy, "publicMcp.oauthTokenReply", json!({"success":true,"body":reply}))?, true);
        let mut wider = reply;
        wider["scope"] = json!("authoring.read authoring.write");
        assert_eq!(evaluate(&policy, "publicMcp.oauthTokenReply", json!({"success":true,"body":wider}))?, false);
        let denied = json!({"error":"invalid_grant","error_description":"The authorization code or its binding is invalid."});
        assert_eq!(evaluate(&policy, "publicMcp.oauthTokenReply", json!({"success":false,"body":denied}))?, true);
        Ok(())
    }

    #[test]
    fn sse_projection_filters_every_event_line() -> Result<()> {
        let policy = policy()?;
        let mut reply = Reply { status:"200 OK".into(), type_header:"text/event-stream".into(), headers:Vec::new(), form_origin:None,
            body:"\u{feff}data: {\"tools\":[{\"name\":\"private\"}]}\r\revent: message\rdata: {\"nextCall\":{\"tool\":\"private\"}}\r\r".as_bytes().to_vec() };
        reply.sanitize(&policy, true)?;
        assert_eq!(std::str::from_utf8(&reply.body)?, "data: {\"tools\":[]}\n\nevent: message\ndata: {\"nextCall\":null}\n\n");
        Ok(())
    }
}
