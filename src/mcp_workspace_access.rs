use crate::{Result, fail, http, mcp_authorization, postgres::Connection, process::{Meter, Programme}, rel};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{collections::BTreeSet, ffi::CStr, io::{self, Read, Write}, path::{Path, PathBuf}, time::SystemTime};
use zeroize::Zeroizing;

const METER: usize = 20_000_000;
const WORKSPACE_QUERY: &CStr = c"WITH snapshot AS MATERIALIZED (
    SELECT sourcery_mcp_access.workspace_snapshot($1, $2, $3, $4, $5)::text AS document
    ) SELECT CASE WHEN octet_length(document) <= 131072 THEN document END FROM snapshot";
const PORTFOLIO_QUERY: &CStr = c"WITH snapshot AS MATERIALIZED (
    SELECT sourcery_mcp_access.portfolio_snapshot($1)::text AS document
    ) SELECT CASE WHEN octet_length(document) <= 4194304 THEN document END FROM snapshot";
const CREDENTIAL_QUERY: &CStr = c"WITH snapshot AS MATERIALIZED (
    SELECT sourcery_mcp_access.credential_snapshot($1)::text AS document
    ) SELECT CASE WHEN octet_length(document) <= 131072 THEN document END FROM snapshot";
const BROWSER_SESSION_QUERY: &CStr = c"WITH snapshot AS MATERIALIZED (
    SELECT sourcery_mcp_access.browser_session_snapshot($1)::text AS document
    ) SELECT CASE WHEN octet_length(document) <= 16384 THEN document END FROM snapshot";
const BROWSER_PORTFOLIO_QUERY: &CStr = c"WITH snapshot AS MATERIALIZED (
    SELECT sourcery_mcp_access.browser_portfolio_snapshot($1)::text AS document
    ) SELECT CASE WHEN octet_length(document) <= 4194304 THEN document END FROM snapshot";
const BROWSER_CONSENT_QUERY: &CStr = c"WITH snapshot AS MATERIALIZED (
    SELECT sourcery_mcp_access.browser_consent_snapshot($1,$2,$3)::text AS document
    ) SELECT CASE WHEN octet_length(document) <= 4194304 THEN document END FROM snapshot";
const BROWSER_CONSENT_READY: &CStr = c"SELECT jsonb_build_object('available', coalesce(has_function_privilege(
    to_regprocedure('sourcery_mcp_access.browser_consent_snapshot(text,text,text)'), 'EXECUTE'), false))";
const BROWSER_CONSENT_WRITE_READY: &CStr = c"SELECT jsonb_build_object('available', coalesce(has_function_privilege(
    to_regprocedure('sourcery_mcp_access.commit_browser_consent(text,text,text,bigint,bigint,bigint,text,text,text)'), 'EXECUTE'), false)
    AND sourcery_mcp_access.browser_consent_ready($1))";
const BROWSER_CONSENT_WRITE: &CStr = c"SELECT sourcery_mcp_access.commit_browser_consent($1,$2,$3,$4,$5,$6,$7,$8,$9)::text";
const BROWSER_AUTHORIZE_WRITE: &CStr = c"SELECT sourcery_mcp_access.begin_browser_authorization($1,$2,$3,$4,$5)::text";
const BROWSER_AUTHORIZE_READY: &CStr = c"SELECT jsonb_build_object('available', coalesce(has_function_privilege(
    to_regprocedure('sourcery_mcp_access.begin_browser_authorization(text,bigint,bigint,text,text)'), 'EXECUTE'), false))";
const OAUTH_SCOPE_QUERY: &CStr = c"WITH snapshot AS MATERIALIZED (
    SELECT sourcery_mcp_access.oauth_scope_snapshot($1, $2)::text AS document
    ) SELECT CASE WHEN octet_length(document) <= 32768 THEN document END FROM snapshot";
const OAUTH_REVOKE_QUERY: &CStr = c"SELECT sourcery_mcp_access.public_oauth_revoke($1, $2)::text";
const OAUTH_REVOKE_READY: &CStr = c"SELECT jsonb_build_object('available', coalesce(
    has_function_privilege(to_regprocedure('sourcery_mcp_access.public_oauth_revoke(text,bigint)'), 'EXECUTE'), false))";
const OAUTH_EXCHANGE_READY: &CStr = c"SELECT jsonb_build_object('available', coalesce(has_function_privilege(
    to_regprocedure('sourcery_mcp_access.public_oauth_exchange(text,text,text,text,text,text,bigint,jsonb)'), 'EXECUTE'), false))";
const OAUTH_EXCHANGE_SNAPSHOT: &CStr = c"SELECT sourcery_mcp_access.oauth_exchange_snapshot($1,$2,$3,$4,$5,$6)::text";
const OAUTH_EXCHANGE_QUERY: &CStr = c"SELECT sourcery_mcp_access.public_oauth_exchange($1,$2,$3,$4,$5,$6,$7,$8)::text";

enum Snapshot<'a> {
    Workspace(&'a [String; 4]),
    Portfolio,
    Credential,
    OAuthScope(&'a [String; 1]),
}

pub(crate) enum BrowserLookup {
    Session,
    Portfolio,
}

impl Connection {
    fn snapshot(&self, digest: &str, selection: Snapshot<'_>) -> Result<Value> {
        let (query, scope, limit): (_, &[String], _) = match selection {
            Snapshot::Workspace(scope) => (WORKSPACE_QUERY, scope, 128 * 1024),
            Snapshot::Portfolio => (PORTFOLIO_QUERY, &[], 4 * 1024 * 1024),
            Snapshot::Credential => (CREDENTIAL_QUERY, &[], 128 * 1024),
            Snapshot::OAuthScope(operation) => (OAUTH_SCOPE_QUERY, operation, 32 * 1024),
        };
        let parameters = std::iter::once(digest).chain(scope.iter().map(String::as_str)).collect::<Vec<_>>();
        self.document(query, &parameters, limit)
    }

    fn revoke(&self, digest: &str, revision: u64) -> Result<Value> {
        self.transaction(OAUTH_REVOKE_QUERY, &[digest, &revision.to_string()], "encounter/public-mcp-oauth-revoke/1",
            &["revoked", "unchanged", "stale"])
    }

    fn transaction(&self, query: &CStr, parameters: &[&str], protocol: &str, statuses: &[&str]) -> Result<Value> {
        self.command(c"BEGIN ISOLATION LEVEL READ COMMITTED", c"BEGIN")?;
        let outcome = self.document(query, parameters, 1024)?;
        if outcome["protocol"] != protocol
            || !outcome["status"].as_str().is_some_and(|status| statuses.contains(&status)) {
            return Err(fail("Invalid public OAuth transaction receipt"));
        }
        self.command(c"COMMIT", c"COMMIT")?;
        Ok(outcome)
    }
}

fn parse_expirations(snapshot: &mut Value) {
    if let Some(tokens) = snapshot["tokens"].as_array_mut() {
        for token in tokens {
            token["expiresMs"] = json!(expiration_ms(&token["expiresAt"]));
        }
    }
}

fn expiration_ms(value: &Value) -> Option<i64> {
    let value = DateTime::parse_from_rfc3339(value.as_str()?).ok()?;
    Some(value.timestamp_millis())
}

pub(crate) struct Access {
    socket: PathBuf,
    port: u16,
    database: String,
    role: String,
    contract: Value,
    programme: Programme,
}

pub(crate) struct Portfolio {
    snapshot: Value,
    auth: Value,
    pub(crate) read: bool,
}

impl Portfolio {
    pub(crate) fn subject(&self) -> &Value { &self.auth["token"] }
}

fn oauth_token(token: &str) -> bool {
    token.len() <= 2048 && token.strip_prefix("src_mcp_access_").is_some_and(|secret| !secret.is_empty())
        && token.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn personal_credential_id(token: &str) -> Option<&str> {
    let (id, secret) = token.strip_prefix("src_dev_")?.split_once('.')?;
    let coordinate = id.strip_prefix("dvc_")?;
    (token.len() <= 2048 && coordinate.len() == 24 && coordinate.bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && !secret.is_empty() && secret.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))).then_some(id)
}

pub(crate) fn portfolio_bearer(token: &str) -> bool {
    oauth_token(token) || personal_credential_id(token).is_some()
}

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("mcp_workspace_access.encounter").to_owned(),
        include_str!("mcp_project_portfolio.encounter").to_owned(), include_str!("mcp_oauth_scope.encounter").to_owned(),
        include_str!("mcp_browser_session.encounter").to_owned(), include_str!("mcp_browser_consent.encounter").to_owned()],
        &["mcpWorkspaceAccess.snapshot", "mcpWorkspaceAccess.admit", "mcpProjectPortfolio.authenticate", "mcpProjectPortfolio.select",
            "mcpOAuthScope.snapshot", "mcpOAuthScope.admit", "mcpOAuthExchange.lifetimes", "mcpOAuthExchange.plan",
            "mcpBrowserSession.cookie", "mcpBrowserSession.coordinate", "mcpBrowserSession.snapshot", "mcpBrowserSession.subject",
            "mcpBrowserSession.portfolio", "mcpBrowserConsent.plan"],
        &BTreeSet::from(["digest.sha256", "json.stringify", "kernel.invoke", "number.calculate", "record.entries", "record.put",
            "text.matches", "value.describe", "value.sort"]),
        &mut Meter::new(METER))
}

impl Access {
    pub(crate) fn load(args: &[String]) -> Result<Self> {
        let [socket, port, database, role, schema, schema_pin, policy_file, policy_pin] = args else {
            return Err(fail("Expected the database socket and pinned MCP contract"));
        };
        let contract = mcp_authorization::load(Path::new(schema), schema_pin, Path::new(policy_file), policy_pin, None)?;
        Ok(Self { socket:socket.into(), port:port.parse()?, database:database.clone(), role:role.clone(),
            contract, programme:policy()? })
    }

    pub(crate) fn portfolio_ready(&self) -> Result<()> {
        let empty_digest = "0".repeat(64);
        for selection in [Snapshot::Portfolio, Snapshot::Credential] {
            let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
            let projection = connection.snapshot(&empty_digest, selection)?;
            if !projection["tokens"].is_array() || !projection["candidates"].is_array() {
                return Err(fail("Hosted MCP portfolio projection is unavailable"));
            }
            self.programme.run("mcpWorkspaceAccess.snapshot", projection, &mut Meter::new(METER))?;
        }
        let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
        let browser = connection.document(BROWSER_SESSION_QUERY, &[&empty_digest], 16 * 1024)?;
        self.programme.run("mcpBrowserSession.snapshot", browser, &mut Meter::new(METER))?;
        let browser = connection.document(BROWSER_PORTFOLIO_QUERY, &[&empty_digest], 4 * 1024 * 1024)?;
        self.programme.run("mcpBrowserSession.portfolio", json!({"snapshot":browser,"nowMs":now_ms()}), &mut Meter::new(METER))?;
        if connection.document(BROWSER_CONSENT_READY, &[], 1024)?["available"] != true {
            return Err(fail("Hosted browser consent projection is unavailable"));
        }
        let projection = connection.snapshot(&empty_digest, Snapshot::OAuthScope(&["revoke".to_owned()]))?;
        self.programme.run("mcpOAuthScope.snapshot", projection, &mut Meter::new(METER))?;
        if connection.document(OAUTH_REVOKE_READY, &[], 1024)?["available"] != true {
            return Err(fail("Public OAuth revocation capability is unavailable"));
        }
        if connection.document(OAUTH_EXCHANGE_READY, &[], 1024)?["available"] != true
            || connection.document(OAUTH_EXCHANGE_SNAPSHOT, &[&empty_digest, "refresh_token", "", "", "", ""], 32768)?
                ["exchangeProtocol"] != "encounter/public-mcp-oauth-exchange/1" {
            return Err(fail("Public OAuth exchange capability is unavailable"));
        }
        self.programme.run("mcpOAuthExchange.lifetimes", self.contract.clone(), &mut Meter::new(METER))?;
        Ok(())
    }

    pub(crate) fn browser_coordinate(&self, cookie: &str) -> Result<Option<String>> {
        if cookie.len() > 16 * 1024 { return Ok(None); }
        let fields: Vec<_> = http::cookie_fields(cookie).collect();
        let selected = self.programme.run("mcpBrowserSession.cookie", json!(fields), &mut Meter::new(METER))?;
        let Some(encoded) = selected.as_str() else { return Ok(None); };
        let Ok(token) = http::decode_cookie(encoded) else { return Ok(None); };
        let coordinate = self.programme.run("mcpBrowserSession.coordinate", json!(Zeroizing::new(token).as_str()),
            &mut Meter::new(METER))?;
        Ok(coordinate.as_str().map(str::to_owned))
    }

    pub(crate) fn browser_lookup(&self, cookie: &str, lookup: BrowserLookup) -> Result<Value> {
        let Some(digest) = self.browser_coordinate(cookie)? else { return Ok(Value::Null); };
        Ok(self.browser_lookup_with_revision(&digest, lookup)?.1)
    }

    pub(crate) fn browser_portfolio_evidence(&self, cookie: &str) -> Result<Option<(String, u64, Value)>> {
        let Some(digest) = self.browser_coordinate(cookie)? else { return Ok(None); };
        let (revision, browser) = self.browser_lookup_with_revision(&digest, BrowserLookup::Portfolio)?;
        Ok(Some((digest, revision, browser)))
    }

    fn browser_lookup_with_revision(&self, digest: &str, lookup: BrowserLookup) -> Result<(u64, Value)> {
        let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
        let (query, limit, entry) = match lookup {
            BrowserLookup::Session => (BROWSER_SESSION_QUERY, 16 * 1024, "mcpBrowserSession.subject"),
            BrowserLookup::Portfolio => (BROWSER_PORTFOLIO_QUERY, 4 * 1024 * 1024, "mcpBrowserSession.portfolio"),
        };
        let snapshot = connection.document(query, &[digest], limit)?;
        let revision = snapshot["controlRevision"].as_u64().ok_or_else(|| fail("Missing browser control-plane revision"))?;
        let expires = expiration_ms(&snapshot["sessions"][0]["expiresAt"]);
        let response = self.programme.run(entry, json!({"snapshot":snapshot,"expiresMs":expires,"nowMs":now_ms()}),
            &mut Meter::new(METER))?;
        Ok((revision, response))
    }

    pub(crate) fn browser_consent_plan(&self, cookie: &str, claims: &Value, decision: &str) -> Result<Value> {
        let Some(digest) = self.browser_coordinate(cookie)? else { return Ok(json!({"error":"session"})); };
        let request = claims["requestId"].as_str().ok_or_else(|| fail("Missing browser consent request coordinate"))?;
        let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
        let snapshot = connection.document(BROWSER_CONSENT_QUERY, &[&digest, request, decision], 4 * 1024 * 1024)?;
        let expires = expiration_ms(&snapshot["sessions"][0]["expiresAt"]);
        let pending_expires = expiration_ms(&snapshot["requests"][0]["expiresAt"]);
        self.programme.run("mcpBrowserConsent.plan", json!({"snapshot":snapshot,"expiresMs":expires,
            "requestExpiresMs":pending_expires,"nowMs":now_ms(),"requestId":request,"userId":claims["userId"],
            "csrfExpiresAt":claims["expiresAt"],"decision":decision,"resource":self.contract["resource"]}), &mut Meter::new(METER))
    }

    pub(crate) fn browser_consent_ready(&self, proof: &str) -> Result<()> {
        let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
        if self.contract["lifetimes"]["authorizationCodeSeconds"] != 300
            || connection.document(BROWSER_CONSENT_WRITE_READY, &[proof], 1024)?["available"] != true {
            return Err(fail("Hosted browser consent commit capability or key is unavailable"));
        }
        Ok(())
    }

    pub(crate) fn browser_authorize_ready(&self) -> Result<()> {
        let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
        if connection.document(BROWSER_AUTHORIZE_READY, &[], 1024)?["available"] != true {
            return Err(fail("Hosted browser authorization commit capability is unavailable"));
        }
        Ok(())
    }

    pub(crate) fn begin_browser_authorization(&self, digest: &str, revision: &str, deadline: &str, record: &str, proof: &str) -> Result<Value> {
        Connection::open_write(&self.socket, self.port, &self.database, &self.role)?
            .transaction(BROWSER_AUTHORIZE_WRITE, &[digest,revision,deadline,record,proof], "encounter/hosted-mcp-browser-authorize/1",
                &["committed", "stale", "refused"])
    }

    pub(crate) fn browser_resource(&self) -> &str {
        self.contract["resource"].as_str().unwrap_or_default()
    }

    pub(crate) fn commit_browser_consent(&self, fields: [&str; 8], proof: &str) -> Result<Value> {
        let parameters: Vec<_> = fields.into_iter().chain(std::iter::once(proof)).collect();
        Connection::open_write(&self.socket, self.port, &self.database, &self.role)?
            .transaction(BROWSER_CONSENT_WRITE, &parameters, "encounter/hosted-mcp-browser-consent-commit/1",
                &["committed", "stale", "refused"])
    }

    pub(crate) fn browser_issuer(&self) -> &str {
        self.contract["authorizationServers"][0].as_str().unwrap_or_default()
    }

    fn oauth_projection(&self, digest: &str, operation: &str) -> Result<Value> {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || !matches!(operation, "authorization_code" | "refresh_token" | "revoke") {
            return Err(fail("Invalid public OAuth scope coordinate"));
        }
        let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
        connection.snapshot(digest, Snapshot::OAuthScope(&[operation.to_owned()]))
    }

    fn admit_oauth_scope(&self, snapshot: &Value) -> Result<Value> {
        self.programme.run("mcpOAuthScope.admit", json!({"snapshot":snapshot,"contract":self.contract}),
            &mut Meter::new(METER))
    }

    pub(crate) fn exchange_oauth(&self, plan: &Value) -> Result<Value> {
        let names = ["digest","grant","client","resource","redirect","proof"];
        let fields = names.map(|key| plan[key].as_str().unwrap_or(""));
        let [digest, grant, client, resource, redirect, proof] = fields;
        let hash = |value: &str| value.len() == 64 && value.bytes().all(|byte|
            byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
        if !hash(digest) || !matches!(grant, "authorization_code" | "refresh_token")
            || client.is_empty() || resource.is_empty() || fields.iter().any(|value| value.len() > 2048 || value.contains('\0'))
            || grant == "authorization_code" && (!hash(proof) || redirect.is_empty())
            || grant == "refresh_token" && (!proof.is_empty() || !redirect.is_empty()) {
            return Ok(json!({"reason":"unknown"}));
        }
        let lifetimes = self.programme.run("mcpOAuthExchange.lifetimes", self.contract.clone(), &mut Meter::new(METER))?;
        for _ in 0..3 {
            let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
            let mut snapshot = connection.document(OAUTH_EXCHANGE_SNAPSHOT, &fields, 32768)?;
            if let Some(candidates) = snapshot["candidates"].as_array_mut() {
                for candidate in candidates {
                    let expires = candidate["expiresAt"].as_str().and_then(|value| DateTime::parse_from_rfc3339(value).ok());
                    candidate["expiresMs"] = json!(expires.map(|value| value.timestamp_millis()));
                }
            }
            let admission = self.programme.run("mcpOAuthExchange.plan", json!({
                "snapshot":snapshot,"contract":self.contract,"grant":grant,"resource":resource,"nowMs":now_ms()
            }), &mut Meter::new(METER))?;
            if admission != "exchange" { return Ok(json!({"reason":admission})); }
            let revision = snapshot["revision"].as_u64().ok_or_else(|| fail("Invalid public OAuth revision"))?.to_string();
            let random = || -> Result<[u8; 32]> {
                let mut bytes = [0; 32];
                getrandom::getrandom(&mut bytes).map_err(|_| fail("Public OAuth token entropy unavailable"))?;
                Ok(bytes)
            };
            let access = Zeroizing::new(format!("src_mcp_access_{}", Base64UrlUnpadded::encode_string(&Zeroizing::new(random()?)[..])));
            let refresh = Zeroizing::new(format!("src_mcp_refresh_{}", Base64UrlUnpadded::encode_string(&Zeroizing::new(random()?)[..])));
            let mint = serde_json::to_string(&json!({
                "accessId":format!("mcp_at_{}", hex::encode(&random()?[..12])),
                "refreshId":format!("mcp_rt_{}", hex::encode(&random()?[..12])),
                "familyId":format!("mcp_family_{}", hex::encode(&random()?[..12])),
                "accessDigest":rel::hash(access.as_bytes()),"refreshDigest":rel::hash(refresh.as_bytes()),
                "accessSeconds":lifetimes["accessTokenSeconds"],"refreshSeconds":lifetimes["refreshTokenSeconds"]
            }))?;
            let writer = Connection::open_write(&self.socket, self.port, &self.database, &self.role)?;
            let parameters = [digest, grant, client, resource, redirect, proof, &revision, &mint];
            let result = writer.transaction(OAUTH_EXCHANGE_QUERY, &parameters, "encounter/public-mcp-oauth-exchange/1",
                &["stale","invalid","replay","issued"])?;
            match result["status"].as_str() {
                Some("stale") => continue,
                Some("invalid") => return Ok(json!({"reason":"unknown"})),
                Some("replay") => return Ok(json!({"reason":"replay"})),
                Some("issued") => return Ok(json!({"token":{"access_token":access.as_str(),"refresh_token":refresh.as_str(),
                    "token_type":"Bearer","scope":self.contract["discoveryScope"],"expires_in":lifetimes["accessTokenSeconds"]}})),
                _ => return Err(fail("Invalid public OAuth exchange outcome")),
            }
        }
        Err(fail("Public OAuth exchange could not acquire the current authority revision"))
    }

    pub(crate) fn revoke_oauth(&self, digest: &str) -> Result<()> {
        for _ in 0..3 {
            let snapshot = self.oauth_projection(digest, "revoke")?;
            if self.admit_oauth_scope(&snapshot)? != "allow" { return Ok(()); }
            let revision = snapshot["revision"].as_u64().ok_or_else(|| fail("Invalid public OAuth revision"))?;
            let connection = Connection::open_write(&self.socket, self.port, &self.database, &self.role)?;
            if connection.revoke(digest, revision)?["status"] != "stale" { return Ok(()); }
        }
        Err(fail("Public OAuth revocation could not acquire the current authority revision"))
    }

    pub(crate) fn authorize(&self, token: &str, scope: &[String; 4]) -> Result<Value> {
        if scope.iter().any(|id| id.is_empty() || id.len() > 128 || id.chars().any(char::is_control)) {
            return Err(fail("Expected exact hosted MCP workspace identities"));
        }
        let snapshot = self.snapshot(token, Snapshot::Workspace(scope))?;
        let [tenant, app, project, workspace] = scope;
        let scope = json!({"tenantId":tenant,"appId":app,"projectId":project,"workspaceId":workspace});
        let access = self.programme.run("mcpWorkspaceAccess.admit", json!({"snapshot":snapshot,
            "contract":self.contract, "scope":scope, "nowMs":now_ms()}), &mut Meter::new(METER))?;
        if http::stopping() { return Err(fail("Hosted MCP workspace access interrupted")); }
        Ok(access)
    }

    pub(crate) fn portfolio(&self, token: &str) -> Result<std::result::Result<Portfolio, Box<dyn std::error::Error>>> {
        self.authenticate(token, Snapshot::Portfolio)
    }

    pub(crate) fn connection(&self, token: &str) -> Result<std::result::Result<Portfolio, Box<dyn std::error::Error>>> {
        self.authenticate(token, Snapshot::Credential)
    }

    fn authenticate(&self, token: &str, selection: Snapshot<'_>) -> Result<std::result::Result<Portfolio, Box<dyn std::error::Error>>> {
        let snapshot = self.snapshot(token, selection)?;
        let authenticated = self.programme.run("mcpProjectPortfolio.authenticate", json!({"snapshot":&snapshot,
            "contract":self.contract, "nowMs":now_ms()}), &mut Meter::new(METER));
        Ok(authenticated.map(|mut result| Portfolio {
            snapshot, auth:result["auth"].take(), read:result["read"] == true,
        }))
    }

    pub(crate) fn select(&self, portfolio: Portfolio, request: &Value) -> Result<Value> {
        if !portfolio.read { return Err(fail("The MCP connection requires the authored project-tool scope.")); }
        self.programme.run("mcpProjectPortfolio.select", json!({"snapshot":portfolio.snapshot,
            "auth":portfolio.auth, "request":request}), &mut Meter::new(METER))
    }

    fn snapshot(&self, token: &str, selection: Snapshot<'_>) -> Result<Value> {
        let coordinate = if oauth_token(token) { rel::hash(token) }
            else if let Some(id) = personal_credential_id(token) { format!("{id}:{}", rel::hash(token)) }
            else { return Err(fail("Expected a hosted OAuth access token or personal portfolio credential")); };
        let connection = Connection::open(&self.socket, self.port, &self.database, &self.role)?;
        let mut snapshot = connection.snapshot(&coordinate, selection)?;
        parse_expirations(&mut snapshot);
        Ok(snapshot)
    }
}

pub(crate) fn now_ms() -> i64 { DateTime::<Utc>::from(SystemTime::now()).timestamp_millis() }

pub(crate) fn run(args: &[String]) -> Result<()> {
    let [configuration @ .., tenant, app, project, workspace] = args else {
        return Err(fail("Expected the database socket, pinned MCP contract and exact tenant, app, project, workspace scope"));
    };
    http::install_stop_signals()?;
    let access = Access::load(configuration)?;
    let mut bearer = Zeroizing::new(String::new());
    io::stdin().lock().take(2049).read_to_string(&mut bearer)?;
    let token = bearer.strip_suffix('\n').unwrap_or(&bearer);
    let grant = access.authorize(token, &[tenant.clone(), app.clone(), project.clone(), workspace.clone()])?;
    writeln!(io::stdout().lock(), "{grant}")?;
    Ok(())
}

#[cfg(test)]
#[test]
fn browser_session_requires_one_cookie_and_one_current_subject() -> Result<()> {
    let programme = policy()?;
    let run = |entry, input| programme.run(entry, input, &mut Meter::new(METER));
    let name = "__Host-sourcery_session";
    let token = "src_session_fixture";
    assert_eq!(run("mcpBrowserSession.cookie", json!([[name, token], ["other", "value"]]))?, token);
    assert!(run("mcpBrowserSession.cookie", json!([[name, token], [name, token]]))?.is_null());
    assert_eq!(run("mcpBrowserSession.coordinate", json!(token))?, rel::hash(token));
    assert!(run("mcpBrowserSession.coordinate", json!("src_mcp_access_fixture"))?.is_null());
    let mut snapshot = json!({
        "projectionProtocol":"encounter/hosted-mcp-browser-session/1",
        "controlSchemaVersion":2,"controlRevision":3,"controlDocumentRevision":3,
        "sessions":[{"id":"ses_example","userId":"user","identityCount":1,"revokedAt":null}]
    });
    let check = |snapshot: &Value, now| run("mcpBrowserSession.subject", json!({
        "snapshot":snapshot,"nowMs":now,"expiresMs":2000
    }));
    assert_eq!(check(&snapshot, 1999)?, json!({"kind":"user","userId":"user","sessionId":"ses_example"}));
    assert!(check(&snapshot, 2000)?.is_null());
    snapshot["sessions"][0]["identityCount"] = json!(2);
    assert!(check(&snapshot, 1999)?.is_null());
    snapshot["controlRevision"] = json!(4);
    assert!(check(&snapshot, 1999).is_err());
    Ok(())
}

#[cfg(test)]
#[test]
fn browser_portfolios_share_current_workspace_admission() -> Result<()> {
    let programme = policy()?;
    let row = |app: &str, key: &str, project_role: &str| json!({
        "tenantId":"tenant","appId":app,"lineageMatches":true,"deleted":false,
        "tenantRoles":["developer"],"projectRoles":if project_role.is_empty() { vec![] } else { vec![project_role] },
        "labels":{"tenant":"Tenant","app":app,"sortKey":key}
    });
    let mut snapshot = json!({
        "projectionProtocol":"encounter/hosted-mcp-browser-session/1",
        "portfolioProtocol":"encounter/hosted-mcp-browser-portfolio/1",
        "controlSchemaVersion":2,"controlRevision":3,"controlDocumentRevision":3,
        "sessions":[{"id":"ses_example","userId":"user","identityCount":1,"revokedAt":null}],
        "candidates":[row("Zulu","tenant/zulu/one","viewer"), row("Missing","tenant/missing/one",""),
            row("Alpha","tenant/alpha/one","author"), row("Alpha","tenant/alpha/two","viewer")]
    });
    let check = |snapshot: &Value| programme.run("mcpBrowserSession.portfolio", json!({
        "snapshot":snapshot,"nowMs":1999,"expiresMs":2000
    }), &mut Meter::new(METER));
    let result = check(&snapshot)?;
    assert_eq!(result["portfolios"], json!([
        {"id":rel::hash(r#"{"tenantId":"tenant","appId":"Alpha"}"#),"scope":{"tenantId":"tenant","appId":"Alpha"},
            "summary":{"tenant":"Tenant","application":"Alpha"}},
        {"id":rel::hash(r#"{"tenantId":"tenant","appId":"Zulu"}"#),"scope":{"tenantId":"tenant","appId":"Zulu"},
            "summary":{"tenant":"Tenant","application":"Zulu"}}
    ]));
    snapshot["candidates"][2]["lineageMatches"] = json!(false);
    assert!(check(&snapshot).is_err());
    snapshot["sessions"][0]["revokedAt"] = json!("revoked");
    assert_eq!(check(&snapshot)?, json!({"subject":null,"portfolios":[]}));
    Ok(())
}

#[cfg(test)]
#[test]
fn personal_portfolio_checks_current_authority_and_the_scope_ceiling() -> Result<()> {
    let programme = policy()?;
    let contract = json!({
        "toolScopes":{"sourcery_project":"authoring.read"},
        "scopesSupported":["authoring.read","operations.execute"],
        "scopeImplications":{"authoring.read":[],"operations.execute":[]}
    });
    let snapshot = json!({
        "projectionProtocol":"encounter/hosted-mcp-access/2","oauthSchemaVersion":1,
        "oauthRevision":1,"oauthDocumentRevision":1,
        "controlSchemaVersion":2,"controlRevision":1,"controlDocumentRevision":1,
        "identityCount":1,"applicationCount":1,"tenantRoles":["viewer"],
        "tokens":[{"credentialKind":"personal","familyId":format!("dvc_{}", "a".repeat(24)),
            "userId":"user","tenantId":"tenant","appId":"app","projectId":null,"workspaceId":null,
            "scopeMode":"application-portfolio-v1","expiresMs":1001,"revokedAt":null,"scopes":["authoring.read"]}]
    });
    let check = |snapshot| programme.run("mcpProjectPortfolio.authenticate",
        json!({"snapshot":snapshot,"contract":contract,"nowMs":1000}), &mut Meter::new(METER));
    let admitted = check(snapshot.clone())?;
    assert_eq!(admitted["read"], true);
    assert_eq!(admitted["auth"]["token"]["clientId"], "urn:sourcery:personal-mcp-connection");
    let mut widened = snapshot.clone();
    widened["tokens"][0]["scopes"] = json!(["authoring.read","operations.execute"]);
    assert!(check(widened).is_err());
    let mut missing = snapshot;
    missing["tenantRoles"] = json!([]);
    assert!(check(missing).is_err());
    Ok(())
}
