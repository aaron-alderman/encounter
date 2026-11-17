// Loopback transport for a declared gateway. The programme supplies route and
// page policy. This adapter owns sockets, hosted sessions and upstream credentials.
use crate::workspace_sign_in::{self, CompletionClient, Presentation, Screen};
use crate::{Result, appdev_reload::ReleaseSlot, application::Application, fail, http, nonce::nonce, process::{Meter, Programme, SharedProgramme}, rel::Facts};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell, collections::{BTreeMap, BTreeSet}, fs,
    io::{BufReader, Read, Write}, net::{Ipv4Addr, TcpStream},
    os::{fd::AsRawFd, unix::fs::PermissionsExt}, path::Path,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, thread, time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const HOSTED: &str = "__Host-sourcery_session";
const STATE: &str = "__Host-encounter_pilot_state";
const SESSION: &str = "__Host-encounter_pilot";
const STATE_LIFETIME: u64 = 600;
const WORKSPACE_SESSION_LIFETIME: u64 = 24 * 60 * 60;
const STATE_PATH_LIMIT: usize = 1024;
const STATE_HEADER: usize = 8 + 4 + 24;
const STATE_TAG: usize = 32;
const TIMEOUT: Duration = Duration::from_secs(3);
const HTML_LIMIT: usize = 4 * 1024 * 1024;
const ASSET_DOWNLOAD_LIMIT: usize = 16 * 1024 * 1024;
const REVIEW_VIDEO_LIMIT: usize = 16 * 1024 * 1024;

struct Target {
    mode: String,
    origin: String,
    port: u16,
    authorization: String,
}

struct Mount {
    upstream: Target,
    return_path: String,
    label: String,
    collection: Option<(String, String)>,
}

struct Config {
    port: u16,
    prefix: String,
    broker: String,
    owner: Option<String>,
    forward_principal: bool,
    workspace_control: bool,
    workspace_consumer: Option<WorkspaceConsumer>,
    workspace_observer: Option<(String, String)>,
    session_cookie: String,
    state_cookie: String,
    identity_port: u16,
    identity_path: String,
    targets: Vec<Target>,
    mounts: BTreeMap<String, Mount>,
}

pub(crate) fn origin(value: &str) -> Result<String> {
    if let Some(authority) = value.strip_prefix("https://") {
        if authority.is_empty() || !authority.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b)) {
            return Err(fail("invalid HTTPS origin"));
        }
        return Ok(value.to_owned());
    }
    let authority = value.strip_prefix("http://").ok_or_else(|| fail("expected HTTPS or loopback origin"))?;
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| fail("loopback origin requires a port"))?;
    let valid_host = host == "127.0.0.1" || host == "localhost" ||
        host.strip_suffix(".localhost").is_some_and(|prefix| !prefix.is_empty() && prefix.split('.').all(|label|
            !label.is_empty() && !label.starts_with('-') && !label.ends_with('-') &&
            label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')));
    if !valid_host || port.starts_with('0') || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
        return Err(fail("HTTP gateway origins must use loopback hosts and a canonical port"));
    }
    Ok(value.to_owned())
}

fn safe_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
}

const WORKSPACE_PREFIX: &str = "/identity-management";
const APP_SESSION: &str = "/identity-management/app-session";

pub(crate) fn workspace_return(policy: &IdentityPolicy, destination: &str) -> Result<bool> {
    if !safe_path(destination) || destination.len() > STATE_PATH_LIMIT || destination.contains('#') {
        return Ok(false);
    }
    let (path, query) = destination.split_once('?').unwrap_or((destination, ""));
    if !path[1..].split('/').all(|part| part != "." && part != ".."
        && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))) {
        return Ok(false);
    }
    let mount = path[1..].split_once('/').map_or("", |(mount, _)| mount);
    let vm_query = query.is_empty() || query.strip_prefix("vm=")
        .map(|value| value.strip_suffix("&view=display").unwrap_or(value))
        .is_some_and(|id| !id.is_empty() && id.len() <= 80
            && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)));
    Ok(policy.evaluate("gatewayIdentity.workspaceReturn", json!({
        "path": path, "mount": mount, "noQuery": query.is_empty(), "vmQuery": vm_query
    }))? == true)
}

fn workspace_link(destination: &str) -> String {
    format!("{WORKSPACE_PREFIX}/?{}", form_urlencoded::Serializer::new(String::new())
        .append_pair("workspace-return", destination).finish())
}

fn browser_navigation(request: &http::Request) -> bool {
    request.method == "GET" && !request.headers.contains_key("upgrade")
        && !request.headers.get("sec-fetch-dest").is_some_and(|kind|
            !matches!(kind.as_str(), "document" | "iframe" | "frame"))
        && request.headers.get("accept").is_some_and(|accept| accept.split(',').any(|kind|
            kind.split(';').next().is_some_and(|media| media.trim().eq_ignore_ascii_case("text/html"))))
}

pub(crate) fn cookie(request: &http::Request, key: &str) -> Option<String> {
    let mut values = request.headers.get("cookie")?.split(';').filter_map(|item| item.trim().split_once('='))
        .filter_map(|(name, value)| (name == key).then_some(value));
    let value = values.next()?;
    values.next().is_none().then(|| value.to_owned())
}

fn cookie_names(prefix: &str) -> (String, String) {
    if prefix == "/encounter-pilot" {
        (SESSION.to_owned(), STATE.to_owned())
    } else {
        let namespace = hex::encode(Sha256::digest(prefix.as_bytes()));
        (format!("__Host-encounter_{namespace}"), format!("__Host-encounter_{namespace}_state"))
    }
}

fn scoped_cookie(name: &str, origin: &str) -> String {
    if origin.starts_with("http://") {
        format!("{name}_{:x}", Sha256::digest(origin.as_bytes()))
    } else {
        name.to_owned()
    }
}

pub(crate) fn session_cookie(prefix: &str, origin: &str) -> String {
    scoped_cookie(&cookie_names(prefix).0, origin)
}

pub(crate) fn state_cookie(prefix: &str, origin: &str) -> String {
    scoped_cookie(&cookie_names(prefix).1, origin)
}

fn cookie_header(name: &str, value: &str, max_age: u64) -> String {
    format!("Set-Cookie: {name}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax\r\n")
}

fn redirect(client: &mut TcpStream, location: &str, cookies: &str) -> Result<()> {
    http::send_headers(client, "303 See Other", "text/plain",
        &format!("Location: {location}\r\nReferrer-Policy: no-referrer\r\n{cookies}"), "")
}

struct Tickets<T>(BTreeMap<String, (Instant, T)>);

impl<T> Default for Tickets<T> {
    fn default() -> Self { Self(BTreeMap::new()) }
}

impl<T> Tickets<T> {
    fn issue(&mut self, value: T, limit: usize, seconds: u64) -> Result<Option<String>> {
        let now = Instant::now();
        self.0.retain(|_, (expires, _)| *expires > now);
        if self.0.len() >= limit { return Ok(None); }
        let key = nonce()?;
        self.0.insert(key.clone(), (now + Duration::from_secs(seconds), value));
        Ok(Some(key))
    }

    fn get(&self, key: &str) -> Option<&T> {
        self.0.get(key).filter(|(expires, _)| *expires > Instant::now()).map(|(_, value)| value)
    }
}

#[derive(Clone)]
struct Session { target: usize, token: String, workspace: Option<WorkspaceConsumer>, user: Principal, actor_session: String, expires: Instant, revoked: Arc<AtomicBool> }
#[derive(Clone)]
struct Principal { id: String, email: String }
struct State { target: usize, path: String, expires: u64 }
struct Code { state: String, path: String, session: Session }

struct LoginStates {
    key: [u8; 32],
    started: Instant,
    used: BTreeMap<String, u64>,
}

impl LoginStates {
    fn new() -> Result<Self> {
        let mut key = [0; 32];
        getrandom::getrandom(&mut key).map_err(|error| fail(error.to_string()))?;
        Ok(Self { key, started: Instant::now(), used: BTreeMap::new() })
    }

    fn tag(&self, message: &[u8]) -> [u8; STATE_TAG] {
        // HMAC-SHA-256 with a fixed 32-byte key and a 64-byte block.
        let mut inner = [0x36; 64];
        let mut outer = [0x5c; 64];
        for (index, byte) in self.key.iter().enumerate() {
            inner[index] ^= byte;
            outer[index] ^= byte;
        }
        let mut hash = Sha256::new();
        hash.update(inner);
        hash.update(message);
        let digest = hash.finalize_reset();
        hash.update(outer);
        hash.update(digest);
        hash.finalize().into()
    }

    fn issue(&self, target: usize, path: &str) -> Result<String> {
        let expires = self.started.elapsed().as_secs() + u64::from(STATE_LIFETIME);
        let mut nonce = [0; 24];
        getrandom::getrandom(&mut nonce).map_err(|error| fail(error.to_string()))?;
        let mut bytes = Vec::with_capacity(STATE_HEADER + path.len() + STATE_TAG);
        bytes.extend(expires.to_be_bytes());
        bytes.extend(u32::try_from(target)?.to_be_bytes());
        bytes.extend(nonce);
        bytes.extend(path.as_bytes());
        bytes.extend(self.tag(&bytes));
        Ok(Base64UrlUnpadded::encode_string(&bytes))
    }

    fn open(&self, key: &str) -> Option<State> {
        if key.len() > (STATE_HEADER + STATE_PATH_LIMIT + STATE_TAG).div_ceil(3) * 4 { return None; }
        let bytes = Base64UrlUnpadded::decode_vec(key).ok()?;
        let (message, tag) = bytes.split_at_checked(bytes.len().checked_sub(STATE_TAG)?)?;
        if message.len() <= STATE_HEADER || message.len() > STATE_HEADER + STATE_PATH_LIMIT
            || !bool::from(self.tag(message).as_slice().ct_eq(tag)) { return None; }
        let expires = u64::from_be_bytes(message[..8].try_into().ok()?);
        if expires <= self.started.elapsed().as_secs() { return None; }
        let target = u32::from_be_bytes(message[8..12].try_into().ok()?) as usize;
        let path = std::str::from_utf8(&message[STATE_HEADER..]).ok()?;
        safe_path(path).then(|| State { target, path: path.to_owned(), expires })
    }

    fn has_room(&mut self) -> bool {
        let now = self.started.elapsed().as_secs();
        self.used.retain(|_, expires| *expires > now);
        self.used.len() < 128
    }
}

#[cfg(test)]
mod login_state_tests {
    use super::*;

    #[test]
    fn state_hmac_matches_rfc_4231() {
        let mut states = LoginStates::new().unwrap();
        states.key = [0; 32];
        states.key[..20].fill(0x0b);
        assert_eq!(hex::encode(states.tag(b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    #[test]
    fn initial_states_do_not_fill_the_pool_and_are_bound_to_the_signed_path() {
        let mut states = LoginStates::new().unwrap();
        let path = "/encounter-pilot/task?task=primary&work=1";
        let first = states.issue(0, path).unwrap();
        for _ in 0..256 {
            assert!(states.open(&states.issue(1, "/encounter-pilot/approval").unwrap()).is_some());
        }
        assert!(states.used.is_empty());
        let state = states.open(&first).unwrap();
        assert_eq!((state.target, state.path.as_str()), (0, path));
        let mut bytes = Base64UrlUnpadded::decode_vec(&first).unwrap();
        bytes[STATE_HEADER + path.len() - 1] ^= 1;
        assert!(states.open(&Base64UrlUnpadded::encode_string(&bytes)).is_none());
        states.started -= Duration::from_secs(u64::from(STATE_LIFETIME));
        assert!(states.open(&first).is_none());
    }
}

struct Auth {
    states: LoginStates,
    codes: Tickets<Code>,
    sessions: Tickets<Session>,
}

pub(crate) struct IdentityPolicy(Programme);

impl IdentityPolicy {
    pub(crate) fn load() -> Result<Self> {
        let source = include_str!("gateway_identity.encounter").to_owned();
        Ok(Self(Programme::admit_entries(&[source],
            &["gatewayIdentity.configure", "gatewayIdentity.admit", "gatewayIdentity.workspaceControl", "gatewayIdentity.workspaceReturn"],
            &BTreeSet::new(), &mut Meter::new(100_000))?))
    }

    fn evaluate(&self, entry: &str, input: Value) -> Result<Value> {
        self.0.run(entry, input, &mut Meter::new(100_000))
    }
}

#[cfg(test)]
#[test]
fn identity_policy_checks_gateway_binding_and_session_identity() -> Result<()> {
    let policy = IdentityPolicy::load()?;
    let configure = |mode, prefix| policy.evaluate("gatewayIdentity.configure", json!({"mode":mode,"prefix":prefix}));
    assert_eq!(configure(Some("appdev-office"), "/identity-management")?["workspaceControl"], true);
    assert_eq!(configure(Some("appdev-office"), "/shop")?["admit"], false);
    assert_eq!(configure(Some("appdev-shop"), "/shop")?["forwardPrincipal"], true);
    assert_eq!(configure(None, "/shop")?["forwardPrincipal"], false);

    let mut request = json!({"kind":"user","issuer":"accounts.google.com","id":"same-id","email":"owner@example.test",
        "owner":"owner@example.test","recheck":true,"expectedId":"same-id","expectedEmail":"owner@example.test"});
    let admit = |request: &Value| policy.evaluate("gatewayIdentity.admit", request.clone());
    assert_eq!(admit(&request)?, true);
    request["expectedEmail"] = json!("revoked@example.test");
    assert_eq!(admit(&request)?, false);
    request["recheck"] = json!(false);
    request["issuer"] = json!("other.example.test");
    assert_eq!(admit(&request)?, false);
    request["issuer"] = json!("https://accounts.google.com");
    request["owner"] = json!("other@example.test");
    assert_eq!(admit(&request)?, false);

    let mut control = json!({"enabled":true,"path":"/workspace-sign-out","method":"POST",
        "hasQuery":false,"hasBody":false,"authorized":true});
    let dispatch = |control: &Value| policy.evaluate("gatewayIdentity.workspaceControl", control.clone());
    assert_eq!(dispatch(&control)?, "sign-out");
    control["hasBody"] = json!(true);
    assert_eq!(dispatch(&control)?, "refuse");
    control["hasBody"] = json!(false);
    control["authorized"] = json!(false);
    assert_eq!(dispatch(&control)?, "refuse");
    Ok(())
}

struct IdentityReply {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for IdentityReply {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(std::io::ErrorKind::TimedOut.into()); }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}

fn observe_identity(port: u16, path: &str, token: &str) -> Result<Option<Value>> {
    if !token.strip_prefix("src_session_").is_some_and(|value|
        value.len() == 43 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))) {
        return Ok(None);
    }
    let deadline = Instant::now() + TIMEOUT;
    let mut stream = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), TIMEOUT)?;
    stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: {HOSTED}={token}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = BufReader::new(IdentityReply { stream, deadline });
    let (start, headers) = http::read_head(&mut response)?;
    let mut status_line = start.splitn(3, ' ');
    if !matches!(status_line.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(fail("invalid identity response version"));
    }
    match status_line.next().and_then(|code| code.parse::<u16>().ok()) {
        Some(400..=599) => return Ok(None),
        Some(200) => {}
        _ => return Err(fail("invalid identity response status")),
    }
    if headers.contains_key("transfer-encoding") {
        return Err(fail("unsupported identity response framing"));
    }
    let length = headers.get("content-length").filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length <= 64 * 1024).ok_or_else(|| fail("invalid identity response length"))?;
    let mut body = vec![0; length];
    response.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body).ok())
}

#[cfg(test)]
#[test]
fn identity_transport_refuses_unbounded_or_truncated_replies() -> Result<()> {
    let query = |response: &'static [u8]| -> Result<Option<Value>> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let fixture = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let (line, _) = http::read_head(&mut reader).unwrap();
            assert_eq!(line, "GET /v1/me HTTP/1.1");
            reader.get_mut().write_all(response).unwrap();
        });
        let result = observe_identity(port, "/v1/me", &format!("src_session_{}", "A".repeat(43)));
        fixture.join().expect("identity fixture");
        result
    };
    assert_eq!(query(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}")?, Some(json!({})));
    assert!(query(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")?.is_none());
    assert!(query(b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n").is_err());
    assert!(query(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}").is_err());
    assert!(query(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").is_err());
    Ok(())
}

fn principal(policy: &IdentityPolicy, port: u16, path: &str, owner: Option<&str>, token: &str,
    expected: Option<&Principal>) -> Result<Option<Principal>> {
    let Some(reply) = observe_identity(port, path, token)? else { return Ok(None); };
    let identity = &reply["identity"];
    let safe_field = |value: &str| !value.is_empty() && value.len() <= 320
        && value.bytes().all(|byte| byte.is_ascii_graphic());
    let Some(id) = identity["id"].as_str().filter(|value| safe_field(value)) else { return Ok(None) };
    let Some(email) = identity["email"].as_str().filter(|value| safe_field(value)) else { return Ok(None) };
    let admitted = policy.evaluate("gatewayIdentity.admit", json!({
        "kind":reply["kind"], "issuer":identity["issuer"], "id":id, "email":email, "owner":owner,
        "recheck":expected.is_some(), "expectedId":expected.map(|user| user.id.as_str()),
        "expectedEmail":expected.map(|user| user.email.as_str()),
    }))?;
    Ok((admitted == true).then(|| Principal { id: id.to_owned(), email: email.to_owned() }))
}

#[derive(Clone)]
struct WorkspaceConsumer {
    origin: String,
    port: u16,
    authorization: String,
}

struct WorkspaceObservation {
    user: Principal,
    actor_session: String,
    remaining: Duration,
}

impl WorkspaceConsumer {
    fn observe(&self, token: &str) -> Result<Option<WorkspaceObservation>> {
        if token.is_empty() || token.len() > 128
            || !token.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)) {
            return Ok(None);
        }
        let host = self.origin.split_once("://").expect("validated workspace origin").1;
        let name = session_cookie(WORKSPACE_PREFIX, &self.origin);
        let url = format!("http://127.0.0.1:{}{APP_SESSION}", self.port);
        let cookie = format!("{name}={token}");
        let reply = crate::http_client::send(crate::http_client::Request {
            url: &url, method: "GET",
            headers: &[("Host", host), ("Authorization", &self.authorization), ("Cookie", &cookie)],
            body: None, timeout: TIMEOUT, connect_timeout: TIMEOUT, limit: 4096,
            resolve: None, trust_anchor: None, restoring: false,
        })?;
        match reply.status {
            401 => return Ok(None),
            200 => {}
            _ => return Err(fail("Workspace session inspection is unavailable")),
        }
        let value: Value = serde_json::from_slice(&reply.body)?;
        let field = |key: &str| value[key].as_str().filter(|value| !value.is_empty() && value.len() <= 320
            && value.bytes().all(|byte| byte.is_ascii_graphic()))
            .map(str::to_owned).ok_or_else(|| fail("Invalid Workspace session identity"));
        let remaining = value["remainingSeconds"].as_u64().filter(|seconds| *seconds <= WORKSPACE_SESSION_LIFETIME)
            .ok_or_else(|| fail("Invalid Workspace session expiry"))?;
        Ok(Some(WorkspaceObservation {
            user: Principal { id: field("id")?, email: field("email")? },
            actor_session: field("actorSession")?,
            remaining: Duration::from_secs(remaining),
        }))
    }
}

impl Config {
    fn cookies(&self, target: usize) -> (String, String) {
        let origin = &self.targets[target].origin;
        (scoped_cookie(&self.session_cookie, origin), scoped_cookie(&self.state_cookie, origin))
    }

}

impl GatewayRequest<'_> {
    fn principal(&self, token: &str, expected: Option<&Principal>) -> Result<Option<Principal>> {
        let config = &self.config;
        principal(&self.identity_policy, config.identity_port, &config.identity_path, config.owner.as_deref(), token, expected)
    }

    fn broker(&self, auth: &mut Auth, client: &mut TcpStream, request: &http::Request, query: &str) -> Result<()> {
        let config = &self.config;
        let fields = http::form(query.as_bytes())?;
        let key = fields.get("state").map(String::as_str).unwrap_or_default();
        let Some(state) = auth.states.open(key)
            .filter(|state| state.target < config.targets.len() && !auth.states.used.contains_key(key)) else {
            return self.notice(client, request, "400 Bad Request", "Sign in again", "Open the workspace again to sign in.");
        };
        if config.workspace_consumer.as_ref()
            .is_some_and(|consumer| consumer.origin == config.targets[state.target].origin) {
            return refused(client);
        }
        let token = cookie(request, HOSTED).unwrap_or_default();
        let Some(user) = self.principal(&token, None)? else {
            if fields.get("returned").is_some_and(|value| value == "1") {
                return self.notice(client, request, "403 Forbidden", "Access required", "This Google account does not have access to the workspace.");
            }
            // The prefix and state are validated at creation. Encode the query delimiter characters.
            let back = format!("{}%2Fidentity%3Freturned%3D1%26state%3D{key}", config.prefix.replace('/', "%2F"));
            return redirect(client, &format!("/identity/login?return={back}"), "");
        };
        let target = state.target;
        if !auth.states.has_room() { return self.notice(client, request, "503 Service Unavailable", "Sign-in busy", "Sign-in capacity reached. Try again shortly."); }
        let value = Code { state: key.to_owned(), path: state.path, session: Session { target, token, workspace: None, user, actor_session: nonce()?,
            expires: Instant::now(), revoked: Arc::new(AtomicBool::new(false)) } };
        let Some(code) = auth.codes.issue(value, 128, 60)? else { return self.notice(client, request, "503 Service Unavailable", "Sign-in busy", "Sign-in capacity reached. Try again shortly.") };
        auth.states.used.insert(key.to_owned(), state.expires);
        redirect(client, &format!("{}{}/finish?code={code}", config.targets[target].origin, config.prefix), "")
    }

    fn finish(&self, auth: &mut Auth, client: &mut TcpStream, request: &http::Request, target: usize, query: &str) -> Result<()> {
        let config = &self.config;
        if config.workspace_consumer.as_ref()
            .is_some_and(|consumer| consumer.origin == config.targets[target].origin) {
            return refused(client);
        }
        let fields = http::form(query.as_bytes())?;
        let key = fields.get("code").map(String::as_str).unwrap_or_default();
        let (session_name, state_name) = config.cookies(target);
        let state_cookie = cookie(request, &state_name).unwrap_or_default();
        let valid = auth.codes.get(key).is_some_and(|code| code.state == state_cookie
            && code.session.target == target && auth.states.open(&state_cookie).is_some_and(|state| state.target == target));
        if !valid { return self.notice(client, request, "400 Bad Request", "Sign-in link expired", "Sign-in link expired. Open the workspace again."); }
        let mut code = auth.codes.0.remove(key).expect("code checked above").1;
        if self.principal(&code.session.token, Some(&code.session.user))?.is_none() {
            return self.notice(client, request, "403 Forbidden", "Access required", "Sign-in refused.");
        }
        let workspace = config.workspace_control && config.prefix == "/identity-management";
        let lifetime = if workspace { WORKSPACE_SESSION_LIFETIME } else { 3600 };
        code.session.expires = Instant::now() + Duration::from_secs(lifetime);
        let Some(id) = auth.sessions.issue(code.session, 32, lifetime)? else { return self.notice(client, request, "503 Service Unavailable", "Sign-in busy", "Sign-in capacity reached. Try again shortly.") };
        println!("Encounter gateway: {} sign-in completed", config.targets[target].mode);
        let cookies = cookie_header(&session_name, &id, lifetime) + &cookie_header(&state_name, "", 0);
        if workspace && workspace_return(&self.identity_policy, &code.path)? {
            let rendered = self.completion.as_ref().and_then(|renderer| renderer.page(&code.path).ok())
                .or_else(|| self.sign_in.page(Screen::Complete, &code.path).ok());
            if let Some(html) = rendered {
                return workspace_sign_in_response(client, "200 OK", &cookies, &html, "'none'");
            }
        }
        redirect(client, &code.path, &cookies)
    }
}

fn relay(client: &mut TcpStream, upstream: &mut BufReader<TcpStream>, config: &Config, session: Session) -> Result<()> {
    let mut outside = client.try_clone()?;
    let mut inside = upstream.get_ref().try_clone()?;
    let initial = upstream.buffer().to_vec();
    let (port, path, owner) = (config.identity_port, config.identity_path.clone(), config.owner.clone());
    thread::spawn(move || {
        let Ok(policy) = IdentityPolicy::load() else { return; };
        let _ = outside.write_all(&initial);
        let mut checked = Instant::now();
        let mut buffer = [0; 8192];
        while !session.revoked.load(Ordering::Relaxed) && Instant::now() < session.expires {
            if checked.elapsed() >= Duration::from_secs(30) {
                let authorized = if let Some(consumer) = &session.workspace {
                    matches!(consumer.observe(&session.token), Ok(Some(observed)) if
                        observed.user.id == session.user.id && observed.user.email == session.user.email
                            && observed.actor_session == session.actor_session)
                } else {
                    matches!(principal(&policy, port, &path, owner.as_deref(), &session.token, Some(&session.user)), Ok(Some(_)))
                };
                if !authorized { break; }
                checked = Instant::now();
            }
            let mut sockets = [libc::pollfd { fd: outside.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: inside.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
            if unsafe { libc::poll(sockets.as_mut_ptr(), 2, 1000) } < 0 { break; }
            let copy = |reader: &mut TcpStream, writer: &mut TcpStream, data: &mut [u8]| -> std::io::Result<bool> {
                let n = reader.read(data)?;
                if n == 0 { return Ok(false); }
                writer.write_all(&data[..n])?;
                Ok(true)
            };
            if sockets[0].revents != 0 && !matches!(copy(&mut outside, &mut inside, &mut buffer), Ok(true)) { break; }
            if sockets[1].revents != 0 && !matches!(copy(&mut inside, &mut outside, &mut buffer), Ok(true)) { break; }
        }
        let _ = outside.shutdown(std::net::Shutdown::Both);
        let _ = inside.shutdown(std::net::Shutdown::Both);
    });
    Ok(())
}

fn mount_links(body: &str, prefix: &str, task: Option<&str>, home: Option<&str>, read_only: bool, query_form: Option<&str>) -> String {
    let mut out = String::with_capacity(body.len());
    let mut start = 0;
    while let Some(offset) = body[start..].find("=\"/") {
        let at = start + offset;
        let value = at + 2;
        let Some(end) = body[value..].find('"').map(|n| value + n) else { break };
        let url = &body[value..end];
        out.push_str(&body[start..value]);
        let attribute = body[..at].rsplit_once([' ', '<']).map(|(_, name)| name);
        let navigable = matches!(attribute, Some("href" | "src" | "data-encounter-events"))
            || (attribute == Some("action") && (!read_only || query_form == Some(url)));
        let workspace_link = prefix == "/life-board" && attribute == Some("href")
            && (matches!(url, "/workspace/home" | "/workspace/work" | "/workspace/mobile" | "/workspace/platform" | "/shop/")
                || url.starts_with("/life-board/") || url.starts_with("/game/"));
        if navigable && !url.starts_with("//") && !workspace_link {
            out.push_str(prefix);
            if let Some(task) = task.filter(|_| url == "/" || url.starts_with("/?")) {
                out.push_str(task);
                out.push_str(&url[1..]);
            } else if attribute == Some("href") && home == Some(url) {
                out.push('/');
            } else { out.push_str(url); }
        } else { out.push_str(url); }
        start = end;
    }
    out.push_str(&body[start..]);
    out
}

struct Gateway {
    config: Config,
    identity_policy: IdentityPolicy,
    preview_client: Option<(String, String)>,
    auth: RefCell<Auth>,
    sign_in: Presentation,
    completion: Option<CompletionClient>,
}

struct GatewayModule {
    programme: SharedProgramme,
    meter: usize,
    styles: String,
    own_chrome: bool,
    notice_style_hash: Option<String>,
}

struct GatewayRequest<'a> {
    runtime: &'a Gateway,
    module: &'a GatewayModule,
}

impl std::ops::Deref for GatewayRequest<'_> {
    type Target = Gateway;
    fn deref(&self) -> &Gateway { self.runtime }
}

impl GatewayRequest<'_> {
    fn proxy(&self, client: &mut TcpStream, request: &http::Request, session: Session, route: &Value,
        query: &str, mount: Option<(&str, &Mount)>) -> Result<()> {
        let audience = &self.config.targets[session.target];
        let comment_pane = route["commentPane"] == true;
        let target = if comment_pane {
            self.config.targets.iter().find(|target| target.mode == "run")
                .ok_or_else(|| fail("preview comments require a live workspace"))?
        } else {
            mount.map_or(audience, |(_, mount)| &mount.upstream)
        };
        let prefix = if comment_pane {
            format!("{}/preview-comments", self.config.prefix)
        } else {
            mount.map_or_else(|| self.config.prefix.clone(), |(name, _)| format!("{}/{name}", self.config.prefix))
        };
        let path = route["path"].as_str().filter(|path| safe_path(path) && !path.contains('?'))
            .ok_or_else(|| fail("invalid declared upstream path"))?;
        let upgrade = route["upgrade"] == true;
        let review_media = route["reviewMedia"] == true;
        let host = format!("127.0.0.1:{}", target.port);
        let mut server = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, target.port).into(), TIMEOUT)?;
        if upgrade {
            // Encounter effects exchange small messages serially in both directions.
            client.set_nodelay(true)?;
            server.set_nodelay(true)?;
        }
        server.set_read_timeout(Some(Duration::from_secs(25)))?;
        server.set_write_timeout(Some(TIMEOUT))?;
        write!(server, "{} {path}{query} HTTP/1.1\r\nHost: {host}\r\nAuthorization: {}\r\n", request.method, target.authorization)?;
        if self.config.forward_principal {
            write!(server, "X-Temple-Principal: {}\r\nX-Temple-Email: {}\r\nX-Temple-Actor-Session: {}\r\n",
                session.user.id, session.user.email, session.actor_session)?;
        }
        let name = format!("encounter_{}", target.port);
        let browser_name = if audience.origin.starts_with("http://") {
            format!("{name}_{}", hex::encode(Sha256::digest(audience.origin.as_bytes())))
        } else { name.clone() };
        if let Some(value) = cookie(request, &browser_name).filter(|v| v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))) {
            write!(server, "Cookie: {name}={value}\r\n")?;
        }
        if request.headers.get("origin") == Some(&audience.origin) { write!(server, "Origin: http://{host}\r\n")?; }
        if review_media && let Some(range) = request.headers.get("range").filter(|value| {
            value.len() <= 80 && value.bytes().all(|byte| byte.is_ascii_digit() || b"bytes=-,".contains(&byte))
        }) {
            write!(server, "Range: {range}\r\n")?;
        }
        if upgrade {
            let key = request.headers.get("sec-websocket-key").ok_or_else(|| fail("missing WebSocket key"))?;
            write!(server, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")?;
        } else {
            write!(server, "Connection: close\r\n")?;
            if request.method == "POST" {
                write!(server, "Content-Length: {}\r\nContent-Type: {}\r\n", request.body.len(),
                    request.headers.get("content-type").map(String::as_str).unwrap_or(""))?;
            }
        }
        write!(server, "\r\n")?;
        server.write_all(&request.body)?;
        let mut upstream = BufReader::new(server);
        let (status, lines) = http::read_header_lines(&mut upstream)?;
        let mut headers = BTreeMap::<String, String>::new();
        for (name, value) in lines {
            if name == "content-security-policy" && let Some(policy) = headers.get_mut(&name) {
                // A CSP list enforces every upstream policy.
                policy.push_str(", ");
                policy.push_str(&value);
            } else if headers.insert(name, value).is_some() {
                return Err(fail("duplicate upstream HTTP header"));
            }
        }
        let status = status.strip_prefix("HTTP/1.1 ").filter(|s| s.len() >= 4 && s.bytes().take(3).all(|b| b.is_ascii_digit()))
            .ok_or_else(|| fail("invalid upstream response status"))?;
        if upgrade {
            if !status.starts_with("101 ") { return refused(client); }
            let accept = headers.get("sec-websocket-accept").ok_or_else(|| fail("missing WebSocket accept"))?;
            upstream.get_ref().set_read_timeout(Some(TIMEOUT))?;
            write!(client, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n")?;
            println!("Encounter gateway: {} WebSocket connected", target.mode);
            return relay(client, &mut upstream, &self.config, session);
        }
        let length: usize = headers.get("content-length").ok_or_else(|| fail("missing upstream body length"))?.parse()?;
        let content_type = headers.get("content-type").map(String::as_str).unwrap_or("text/plain");
        let stream_video = review_media && route["reviewVideo"] == true && content_type == "video/mp4"
            && (status.starts_with("200 ") || status.starts_with("206 "));
        let asset_download = route["assetDownload"] == true && request.method == "GET"
            && content_type == "application/octet-stream" && status.starts_with("200 ");
        let stream_body = stream_video || asset_download;
        let limit = if asset_download { ASSET_DOWNLOAD_LIMIT } else if stream_video { REVIEW_VIDEO_LIMIT } else { HTML_LIMIT };
        if length > limit { return Err(fail("upstream response exceeds the configured bound")); }
        let mut body = Vec::new();
        if !stream_body {
            body.resize(length, 0);
            upstream.read_exact(&mut body)?;
        }
        let read_only = route["readOnly"] == true;
        let query_form = route["queryForm"].as_str().filter(|form| *form == path);
        if content_type.starts_with("text/html") {
            let mounted = mount_links(std::str::from_utf8(&body)?, &prefix,
                route["taskLink"].as_str(), route["homeLink"].as_str(), read_only, query_form);
            let coordinates = http::form(query.trim_start_matches('?').as_bytes()).unwrap_or_default()
                .into_iter().filter(|(_, value)| !value.is_empty() && value.len() <= 80
                    && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
                .collect::<BTreeMap<_, _>>();
            let context = json!({"html": mounted, "coordinates": coordinates, "prefix": self.config.prefix, "mode":audience.mode, "path":path, "commentPane":comment_pane,
                "mount": mount.map(|(name, mount)| {
                    let group = name.rsplit_once('-').map(|(group, _)| group);
                    let siblings = self.config.mounts.iter().filter(|(key, sibling)|
                        sibling.upstream.origin == target.origin && key.rsplit_once('-').map(|(group, _)| group) == group)
                        .map(|(key, sibling)| json!({"name": key, "label": sibling.label})).collect::<Vec<_>>();
                    let collections = self.config.mounts.iter().filter_map(|(key, item)| {
                        let (title, route) = item.collection.as_ref()?;
                        (item.upstream.origin == target.origin).then(|| json!({
                            "name": key, "title": title, "route": route,
                            "current": key.rsplit_once('-').map(|(group, _)| group) == group,
                        }))
                    }).collect::<Vec<_>>();
                    json!({"name": name, "prefix": prefix, "returnPath": mount.return_path,
                        "label": mount.label, "siblings": siblings, "collections": collections})
                }),
                "origins": self.config.targets.iter().map(|t| (t.mode.clone(), t.origin.clone())).collect::<BTreeMap<_,_>>()});
            body = self.module.programme.run("gateway.page", context, &mut Meter::new(self.module.meter))?
                .as_str().ok_or_else(|| fail("gateway.page must return HTML text"))?.as_bytes().to_vec();
        } else if !self.module.own_chrome && content_type.starts_with("text/css") {
            body.extend_from_slice(self.module.styles.as_bytes());
        }
        let response_length = if stream_body { length } else { body.len() };
        let mut policy = headers.get("content-security-policy").map(String::as_str).unwrap_or("default-src 'none'")
            .replace(&format!("ws://{host}"), &audience.origin.replacen("https:", "wss:", 1));
        if content_type.starts_with("text/html") {
            let workspace_frame = route["workspaceFrame"] == true &&
                request.headers.get("sec-fetch-dest").is_some_and(|value| value == "iframe");
            if comment_pane || workspace_frame {
                policy = policy.replace("frame-ancestors 'none'", "frame-ancestors 'self'");
            } else if route["previewCommentFrame"] == true {
                policy.push_str(&format!("; frame-src {}{}/preview-comments/; script-src {}{}/preview-context.js",
                    audience.origin, self.config.prefix, audience.origin, self.config.prefix));
            }
        }
        write!(client, "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: same-origin\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {policy}\r\n", response_length)?;
        if request.method == "GET" && matches!(path, "/_encounter/browser.mjs" | "/encounter-events.js" | "/encounter-canvas.js")
            && status.starts_with("200 ") && content_type.starts_with("text/javascript")
            && let Some(pin) = headers.get("x-encounter-browser-wasm").filter(|pin| {
                pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            write!(client, "X-Encounter-Browser-Wasm: {pin}\r\n")?;
        }
        if asset_download {
            write!(client, "Content-Disposition: attachment\r\n")?;
        }
        if read_only && content_type.starts_with("text/html") {
            let destination = query_form.map_or_else(|| "'none'".to_owned(), |form| format!("{}{prefix}{form}", target.origin));
            write!(client, "Content-Security-Policy: form-action {destination}\r\n")?;
        }
        if let Some(value) = headers.get("set-cookie").filter(|value| value.starts_with(&format!("{name}="))) {
            write!(client, "Set-Cookie: {}\r\n", value.replacen(&format!("{name}="), &format!("{browser_name}="), 1).replace("Path=/", &format!("Path={}/; Secure", self.config.prefix)))?;
        }
        if review_media {
            if headers.get("accept-ranges").is_some_and(|value| value == "bytes") {
                write!(client, "Accept-Ranges: bytes\r\n")?;
            }
            if let Some(range) = headers.get("content-range").filter(|value| {
                value.len() <= 80 && value.bytes().all(|byte| byte.is_ascii_digit() || b"bytes */-".contains(&byte))
            }) {
                write!(client, "Content-Range: {range}\r\n")?;
            }
        }
        write!(client, "\r\n")?;
        if stream_body {
            let copied = std::io::copy(&mut upstream.take(length as u64), client)?;
            if copied != length as u64 { return Err(fail("upstream download ended before its declared length")); }
        } else {
            client.write_all(&body)?;
        }
        Ok(())
    }

    fn notice(&self, client: &mut TcpStream, request: &http::Request, status: &str, title: &str, message: &str) -> Result<()> {
        let html_requested = request.method == "GET" && !request.headers.contains_key("upgrade")
            && request.headers.get("accept").is_some_and(|accept| accept.split(',').any(|kind|
                kind.split(';').next().is_some_and(|media| media.trim().eq_ignore_ascii_case("text/html"))));
        if let Some(hash) = self.module.notice_style_hash.as_deref().filter(|_| html_requested) {
            let config = &self.config;
            let origins = config.targets.iter().map(|target| (target.mode.as_str(), target.origin.as_str()))
                .collect::<BTreeMap<_, _>>();
            if let Ok(page) = self.module.programme.run("gateway.notice", json!({
                "title": title, "message": message, "styles": self.module.styles, "prefix": config.prefix, "origins": origins,
            }), &mut Meter::new(self.module.meter)) && let Some(html) = page.as_str() {
                return http::send_gateway_notice(client, status, html, hash);
            }
        }
        http::send(client, status, "text/plain", message)
    }

    fn observe_app_session(&self, client: &mut TcpStream, request: &http::Request, target: usize,
        session_name: &str) -> Result<()> {
        let Some((_, credential)) = self.config.workspace_observer.as_ref()
            .filter(|(origin, _)| self.config.workspace_control && self.config.targets[target].origin == *origin)
            else { return missing(client) };
        if request.method != "GET" || !request.body.is_empty()
            || !request.headers.get("authorization")
                .is_some_and(|value| bool::from(value.as_bytes().ct_eq(credential.as_bytes()))) {
            return refused(client);
        }
        let auth = self.auth.borrow();
        let session = cookie(request, session_name).and_then(|key| auth.sessions.get(&key))
            .filter(|session| session.target == target);
        if let Some(session) = session
            && self.principal(&session.token, Some(&session.user))?.is_some() {
            let body = json!({
                "id": session.user.id, "email": session.user.email, "actorSession": session.actor_session,
                "remainingSeconds": session.expires.saturating_duration_since(Instant::now()).as_secs()
            });
            return http::send_headers(client, "200 OK", "application/json", "Cache-Control: no-store\r\n", &body.to_string());
        }
        sign_in_required(client)
    }

    fn request(&self, client: &mut TcpStream, request: &http::Request) -> Result<()> {
        let config = &self.config;
        let host = request.headers.get("host").map(String::as_str).unwrap_or_default();
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        if !safe_path(&request.path) { return refused(client); }
        let Some(path) = path.strip_prefix(&config.prefix).filter(|path| path.starts_with('/')) else { return missing(client) };
        if config.broker.split_once("://").is_some_and(|(_, authority)| authority == host) {
            if path != "/identity" || request.method != "GET" { return missing(client); }
            return self.broker(&mut self.auth.borrow_mut(), client, request, query);
        }
        let Some(target) = config.targets.iter().position(|item| item.origin.strip_prefix("https://").or_else(|| item.origin.strip_prefix("http://")) == Some(host)) else { return missing(client) };
        let dest = &config.targets[target];
        let (session_name, state_name) = config.cookies(target);
        if request.path == APP_SESSION {
            return self.observe_app_session(client, request, target, &session_name);
        }
        if config.workspace_control && path == "/workspace-sign-in" && request.method == "GET" && query.is_empty() {
            return requested_workspace_sign_in(&self.sign_in, &self.identity_policy, client, request);
        }
        let workspace_control = self.identity_policy.evaluate("gatewayIdentity.workspaceControl", json!({
            "enabled":config.workspace_control, "path":path, "method":request.method, "hasQuery":!query.is_empty(),
            "hasBody":!request.body.is_empty(), "authorized":request.headers.get("authorization")
                .is_some_and(|value| bool::from(value.as_bytes().ct_eq(dest.authorization.as_bytes()))),
        }))?;
        match workspace_control.as_str() {
            Some("refuse") => return refused(client),
            Some("sign-out") => {
                let mut auth = self.auth.borrow_mut();
                if let Some(key) = cookie(request, &session_name)
                    && auth.sessions.0.get(&key).is_some_and(|(_, session)| session.target == target)
                    && let Some((_, session)) = auth.sessions.0.remove(&key) {
                    session.revoked.store(true, Ordering::Relaxed);
                }
                return http::send_headers(client, "204 No Content", "text/plain", "Cache-Control: no-store\r\n", "");
            }
            Some("access") => {
                let auth = self.auth.borrow();
                let session = cookie(request, &session_name).and_then(|key| auth.sessions.get(&key))
                    .filter(|session| session.target == target && session.expires > Instant::now());
                let Some(session) = session else {
                    return http::send(client, "401 Unauthorized", "text/plain", "Sign in required.");
                };
                if self.principal(&session.token, Some(&session.user))?.is_none() {
                    return refused(client);
                }
                let identity = json!({"id": session.user.id, "email": session.user.email});
                return http::send_headers(client, "200 OK", "application/json", "Cache-Control: no-store\r\n", &identity.to_string());
            }
            Some("route") => {}
            _ => return Err(fail("invalid gateway workspace control decision")),
        }
        if path == "/finish" && request.method == "GET" {
            return self.finish(&mut self.auth.borrow_mut(), client, request, target, query);
        }
        if config.workspace_control && config.prefix == "/identity-management" && path == "/"
            && request.method == "GET" && query.starts_with("workspace-return=") {
            let fields = http::form(query.as_bytes())?;
            let Some(destination) = fields.get("workspace-return").filter(|_| fields.len() == 1) else {
                return refused(client);
            };
            if !workspace_return(&self.identity_policy, destination)? { return refused(client); }
            let auth = self.auth.borrow();
            if let Some(session) = cookie(request, &session_name).and_then(|key| auth.sessions.get(&key))
                .filter(|session| session.target == target)
                && self.principal(&session.token, Some(&session.user))?.is_some() {
                return redirect(client, destination, "");
            }
            let key = auth.states.issue(target, destination)?;
            return redirect(client, &format!("{}{}/identity?state={key}", config.broker, config.prefix),
                &cookie_header(&state_name, &key, STATE_LIFETIME));
        }
        let upgraded = request.headers.get("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        let selected = query.split('&').any(|field| field.starts_with("task="));
        let mount = path[1..].find('/').and_then(|end| {
            let (name, suffix) = path[1..].split_at(end);
            self.config.mounts.get(name).map(|mount| (name, mount, suffix))
        });
        let route = self.module.programme.run("gateway.route", json!({"mode":dest.mode,"path":path,"method":request.method,
            "task":selected,"upgrade":upgraded,"mount":mount.map(|(_, _, path)| path)}), &mut Meter::new(self.module.meter))?;
        match route["status"].as_u64() {
            Some(200) => {}
            Some(405) => return self.notice(client, request, "405 Method Not Allowed", "Method refused", "Method refused."),
            Some(403) => return self.notice(client, request, "403 Forbidden", "Request refused", "Request refused."),
            _ if route["unavailable"] == true => return self.notice(client, request, "404 Not Found", "Staged app unavailable",
                "Staged app unavailable. This scenario step or its route has no active binding."),
            _ => return self.notice(client, request, "404 Not Found", "Page not found", "Unknown route."),
        }
        if self.module.own_chrome && route["chrome"] == true && request.method == "GET" && !upgraded {
            return http::send(client, "200 OK", "text/css", &self.module.styles);
        }
        if route["previewContextScript"] == true && request.method == "GET" && !upgraded {
            if let Some((receipt, script)) = &self.preview_client {
                return http::send_headers(client, "200 OK", "text/javascript",
                    &format!("X-Encounter-Browser-Wasm: {receipt}\r\n"), script);
            }
            return http::send(client, "200 OK", "text/javascript", &crate::process::browser_wasm::preview_script(None)?);
        }
        if (request.method == "POST" || upgraded) && request.headers.get("origin") != Some(&dest.origin) {
            return refused(client);
        }
        if route["commentPane"] == true && path == "/preview-comments/" {
            let fields = if request.method == "POST" { &request.body } else { query.as_bytes() };
            let valid = http::form(fields).is_ok_and(|fields| {
                let get = |key| fields.get(key).map(String::as_str);
                get("view") == Some("preview-comments") && get("work") == Some("1")
                    && get("task").is_some_and(|id| !id.is_empty() && id.len() <= 80
                        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
                    && matches!(get("review-route"), Some("/sick-leave" | "/timesheet" | "/report"))
                    && (request.method == "GET" || get("action") == Some("stage-review-comment")
                        && request.headers.get("content-type").map(String::as_str) == Some("application/x-www-form-urlencoded"))
                    && fields.keys().all(|key| matches!(key.as_str(),
                        "view" | "work" | "task" | "review-route" | "review-entry" | "review-section" | "review-context" | "scenario" | "step" | "review-item"
                        | "_csrf" | "base" | "action" | "implementation" | "review-note"))
            });
            if !valid { return refused(client); }
        }
        if upgraded && request.headers.get("sec-websocket-version").map(String::as_str) != Some("13") {
            return refused(client);
        }
        let embedded_store = config.prefix == "/store" && path == "/"
            && query.split('&').any(|field| field == "workspace-fragment=1");
        let store_return = if config.prefix == "/store" && route["workspaceSignIn"] == true {
            Some(match query {
                "workspace=home" => "/workspace/home",
                "workspace=work" => "/workspace/work",
                _ => return refused(client),
            })
        } else {
            None
        };
        let consumer = config.workspace_consumer.as_ref().filter(|consumer| consumer.origin == dest.origin);
        let auth = self.auth.borrow();
        let session = if let Some(consumer) = consumer {
            let name = session_cookie(WORKSPACE_PREFIX, &dest.origin);
            if let Some(token) = cookie(request, &name) {
                if let Some(observed) = consumer.observe(&token)? {
                    if config.owner.as_ref().is_some_and(|owner| owner != &observed.user.email) {
                        return refused(client);
                    }
                    Some(Session { target, token, workspace: Some(consumer.clone()), user: observed.user,
                        actor_session: observed.actor_session, expires: Instant::now() + observed.remaining,
                        revoked: Arc::new(AtomicBool::new(false)) })
                } else { None }
            } else { None }
        } else {
            cookie(request, &session_name).and_then(|key| auth.sessions.get(&key).cloned())
                .filter(|item| item.target == target)
        };
        if let Some(session) = session {
            if session.workspace.is_some() || self.principal(&session.token, Some(&session.user))?.is_some() {
                drop(auth);
                if config.workspace_control && config.prefix == "/identity-management"
                    && route["workspaceTerminalApproval"] == true {
                    return redirect(client, "/workspace/terminal/approve", "");
                }
                if let Some(path) = store_return {
                    return redirect(client, path, "");
                }
                let suffix = if query.is_empty() { String::new() } else { format!("?{query}") };
                if let Some(mode) = route["redirect"].as_str() {
                    let target = config.targets.iter().find(|target| target.mode == mode)
                        .ok_or_else(|| fail("unknown gateway redirect target"))?;
                    let next = route["redirectPath"].as_str().unwrap_or(path);
                    if !safe_path(next) || next.contains(['?', '#']) {
                        return Err(fail("invalid gateway redirect path"));
                    }
                    return redirect(client, &format!("{}{}{next}{suffix}", target.origin, config.prefix), "");
                }
                let upstream = mount.filter(|(_, mount, _)| route["mounted"] == true && mount.upstream.origin == dest.origin)
                    .map(|(name, mount, _)| (name, mount));
                if route["mounted"] == true && upstream.is_none() { return missing(client); }
                return self.proxy(client, request, session, &route, &suffix, upstream);
            }
        }
        if consumer.is_some() {
            let destination = store_return.unwrap_or(&request.path);
            if !embedded_store && browser_navigation(request) && workspace_return(&self.identity_policy, destination)? {
                return workspace_sign_in_prompt(&self.sign_in, client, destination);
            }
            return sign_in_required(client);
        }
        if embedded_store {
            return http::send_headers(client, "401 Unauthorized", "text/plain", "Cache-Control: no-store\r\n", "Store sign-in required.");
        }
        if request.method != "GET" || upgraded || request.path.len() > STATE_PATH_LIMIT { return refused(client); }
        let key = auth.states.issue(target, store_return.unwrap_or(&request.path))?;
        redirect(client, &format!("{}{}/identity?state={key}", config.broker, config.prefix), &cookie_header(&state_name, &key, STATE_LIFETIME))
    }
}

pub(crate) fn serve_workspace_sign_in_presentation(port: u16, completion: Option<(&Path, u32)>) -> Result<()> {
    if std::env::var_os("APPDEV_WORKSPACE_SIGN_IN_RELEASE").is_none() {
        return Err(fail("Workspace sign-in presentation requires its release pointer"));
    }
    let policy = IdentityPolicy::load()?;
    let presentation = Arc::new(Presentation::start(true)?);
    let _completion = completion.map(|(path, authority_uid)| {
        workspace_sign_in::serve_completion(path, authority_uid, Arc::clone(&presentation), || {
            let policy = IdentityPolicy::load()?;
            Ok(move |destination: &str| workspace_return(&policy, destination))
        })
    }).transpose()?;
    http::serve(port, || {}, |_, client, request| {
        if request.path != "/identity-management/workspace-sign-in" {
            return missing(client);
        }
        if request.method != "GET" || !request.body.is_empty() || request.headers.contains_key("upgrade") {
            return refused(client);
        }
        requested_workspace_sign_in(&presentation, &policy, client, &request)
    })
}

fn requested_workspace_sign_in(presentation: &Presentation, policy: &IdentityPolicy, client: &mut TcpStream,
    request: &http::Request) -> Result<()>
{
    let Some(destination) = request.headers.get("x-workspace-return") else { return missing(client) };
    if !workspace_return(policy, destination)? { return refused(client); }
    workspace_sign_in_prompt(presentation, client, destination)
}

fn workspace_sign_in_prompt(presentation: &Presentation, client: &mut TcpStream, destination: &str) -> Result<()> {
    let page = presentation.page(Screen::Required, &workspace_link(destination))?;
    workspace_sign_in_response(client, "401 Unauthorized", "", &page, "'self'")
}

fn workspace_sign_in_response(client: &mut TcpStream, status: &str, cookies: &str, html: &str,
    frame_ancestors: &str) -> Result<()>
{
    let policy = format!("default-src 'none'; style-src 'self'; font-src 'self'; frame-ancestors {frame_ancestors}; base-uri 'none'; form-action 'none'");
    http::write_response(client, status, "text/html; charset=utf-8",
        &format!("Referrer-Policy: no-referrer\r\n{cookies}"), html.as_bytes(), &policy)
}

fn sign_in_required(client: &mut TcpStream) -> Result<()> {
    http::send_headers(client, "401 Unauthorized", "text/plain; charset=utf-8",
        "Cache-Control: no-store\r\n", "Sign in to Workspace.")
}

fn refused(client: &mut TcpStream) -> Result<()> {
    http::send(client, "403 Forbidden", "text/plain", "Request refused.")
}

fn missing(client: &mut TcpStream) -> Result<()> {
    http::send(client, "404 Not Found", "text/plain", "Unknown route.")
}

fn authorization(facts: &Facts, subject: &str) -> Result<String> {
    let value = facts.one(subject, "authorization")?;
    if !value.strip_prefix("Basic ").is_some_and(|token| !token.is_empty()
        && token.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))) {
        return Err(fail("expected a private Basic upstream credential"));
    }
    Ok(value.to_owned())
}

pub fn serve(file: &Path) -> Result<()> {
    serve_with_policy(file, None)
}

pub(crate) fn load_policy(root: &Path, declaration: &str, profile: Option<&str>) -> Result<Application> {
    crate::package::check(root)?;
    let app = Application::load(root, declaration)?;
    if profile.is_some_and(|profile| app.state_profile != profile) {
        return Err(fail("The gateway policy differs from the expected application profile"));
    }
    if !app.has_entry("gateway.route") || !app.has_entry("gateway.page") {
        return Err(fail("expected declared gateway route and page entries"));
    }
    Ok(app)
}

pub(crate) fn serve_with_policy(file: &Path, policy: Option<(&Path, &str, &str, &str)>) -> Result<()> {
    if fs::metadata(file)?.permissions().mode() & 0o077 != 0 { return Err(fail("gateway launch configuration must be private")); }
    let facts = Facts::read(file)?;
    let config_root = file.parent().ok_or_else(|| fail("missing gateway configuration directory"))?;
    let preview_pin = crate::browser_release::ClientWasmPin::from_config(&facts, config_root, "preview-client")?;
    let preview_client = if let Some(pin) = preview_pin {
        let script = crate::process::browser_wasm::preview_script(Some(&pin))?;
        Some((pin.receipt, script))
    } else { None };
    let field = |name| facts.one("gateway", name);
    if field("version")? != "encounter/gateway/1" { return Err(fail("unsupported gateway configuration")); }
    let prefix = field("prefix")?.to_owned();
    if policy.is_some_and(|(_, _, expected_prefix, _)| prefix != expected_prefix) {
        return Err(fail("The private gateway prefix differs from the packaged policy"));
    }
    let identity_path = field("identityPath")?.to_owned();
    if !safe_path(&prefix) || prefix.ends_with('/') || !prefix.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-_".contains(&b))
        || !safe_path(&identity_path) { return Err(fail("invalid gateway route coordinates")); }
    let mut targets = Vec::new();
    for mode in facts.values("gateway", "target") {
        targets.push(Target { mode: mode.to_owned(), origin: origin(facts.one(mode, "origin")?)?,
            port: facts.one(mode, "port")?.parse()?, authorization: authorization(&facts, mode)? });
    }
    let mut mounts = BTreeMap::new();
    for name in facts.values("gateway", "mount") {
        let mode = facts.one(name, "target")?;
        let target = targets.iter().find(|target| target.mode == mode).ok_or_else(|| fail("unknown mount target"))?;
        let return_path = facts.one(name, "returnPath")?;
        let label = facts.one(name, "label")?;
        let port = facts.one(name, "port")?.parse()?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || !safe_path(return_path) || !return_path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/?&=-_".contains(&b))
            || label.is_empty() || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b" -".contains(&b))
            || port == 0 || targets.iter().any(|target| target.port == port)
        {
            return Err(fail("invalid gateway mount coordinates"));
        }
        let upstream = Target { mode: mode.to_owned(), origin: target.origin.clone(), port,
            authorization: authorization(&facts, name)? };
        let collection = match facts.values(name, "collectionTitle").as_slice() {
            [] => None,
            [title] => {
                let path = facts.one(name, "collectionPath")?;
                if title.is_empty() || !title.bytes().all(|b| b.is_ascii_alphanumeric() || b" -".contains(&b))
                    || !safe_path(path) || !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-_".contains(&b)) {
                    return Err(fail("invalid gateway mount collection"));
                }
                Some((title.to_string(), path.to_owned()))
            }
            _ => return Err(fail("duplicate gateway mount collection")),
        };
        if mounts.insert(name.to_owned(), Mount { upstream, return_path: return_path.to_owned(), label: label.to_owned(), collection }).is_some() {
            return Err(fail("duplicate gateway mount"));
        }
    }
    // Independent gateways on the same HTTPS origin must not replace each other's cookies.
    let (session_cookie, state_cookie) = cookie_names(&prefix);
    let modes = facts.values("gateway", "identityAdmission");
    let mode = match modes.as_slice() {
        [] => None,
        [mode] => Some(*mode),
        _ => return Err(fail("unsupported gateway identity admission")),
    };
    let identity_policy = IdentityPolicy::load()?;
    let admission = identity_policy.evaluate("gatewayIdentity.configure", json!({"mode":mode,"prefix":prefix}))?;
    if admission["admit"] != true { return Err(fail("unsupported gateway identity admission")); }
    let forward_principal = admission["forwardPrincipal"].as_bool().ok_or_else(|| fail("invalid gateway identity configuration"))?;
    let workspace_control = admission["workspaceControl"].as_bool().ok_or_else(|| fail("invalid gateway identity configuration"))?;
    let owner = if mode.is_none() { Some(field("owner")?.to_owned()) } else { None };
    let observer = match facts.values("gateway", "workspaceObserver").as_slice() {
        [] => None,
        ["enabled"] if workspace_control => {
            let allowed_origin = origin(facts.one("workspace-observer", "origin")?)?;
            if !targets.iter().any(|target| target.origin == allowed_origin) {
                return Err(fail("Workspace observer origin does not match an identity target"));
            }
            Some((allowed_origin, authorization(&facts, "workspace-observer")?))
        }
        _ => return Err(fail("Invalid Workspace observer declaration")),
    };
    let consumer = match facts.values("gateway", "workspaceConsumer").as_slice() {
        [] => None,
        ["enabled"] if !workspace_control => {
            let workspace_origin = origin(facts.one("workspace-consumer", "origin")?)?;
            if !targets.iter().any(|target| target.origin == workspace_origin) {
                return Err(fail("Workspace consumer origin does not match an application target"));
            }
            let port = facts.one("workspace-consumer", "port")?.parse::<u16>()?;
            if port == 0 || port == field("port")?.parse::<u16>()? {
                return Err(fail("Invalid Workspace session listener port"));
            }
            Some(WorkspaceConsumer { origin: workspace_origin, port,
                authorization: authorization(&facts, "workspace-consumer")? })
        }
        _ => return Err(fail("Invalid Workspace consumer declaration")),
    };
    let config = Config { port: field("port")?.parse()?, prefix, broker: origin(field("broker")?)?,
        session_cookie, state_cookie,
        owner, forward_principal, workspace_control, workspace_consumer: consumer, workspace_observer: observer,
        identity_port: field("identityPort")?.parse()?, identity_path, targets, mounts };
    let (source, declaration, profile) = match policy {
        Some((root, declaration, _, profile)) => (root, declaration, Some(profile)),
        None => (Path::new(field("root")?), field("declaration")?, None),
    };
    let app = load_policy(source, declaration, profile)?;
    let sign_in = Presentation::start(config.workspace_control || config.workspace_consumer.is_some())?;
    let completion = if config.workspace_control { CompletionClient::configured()? } else { None };
    let policy_link = config.workspace_consumer.as_ref().and_then(|_| std::env::var_os("APPDEV_GATEWAY_POLICY_RELEASE"))
        .map(std::path::PathBuf::from);
    let contract = GatewayContract::from_app(&app);
    let declaration = declaration.to_owned();
    let prefix = config.prefix.clone();
    let shared_styles = if app.has_entry("gateway.styles") {
        String::new()
    } else {
        fs::read_to_string(field("stylesheet")?)?
    };
    let fallback_styles = shared_styles.clone();
    let modules = ReleaseSlot::start("AppDev gateway policy", policy_link,
        || GatewayModule::compile(app, &fallback_styles), move |root, _| {
            verify_module_release(root, &prefix)?;
            let candidate = load_policy(root, &declaration, Some(&contract.profile))?;
            if GatewayContract::from_app(&candidate) != contract {
                return Err(fail("gateway policy changes the declared contract or grants"));
            }
            GatewayModule::compile(candidate, &shared_styles)
        })?;
    let auth = Auth { states: LoginStates::new()?, codes: Tickets::default(), sessions: Tickets::default() };
    let runtime = Gateway { config, identity_policy, preview_client, auth: RefCell::new(auth), sign_in, completion };
    http::serve_gateway(runtime.config.port, |_, client, request| {
        let module = modules.current();
        let gateway = GatewayRequest { runtime: &runtime, module: &module };
        if gateway.request(client, &request).is_err() {
            return gateway.notice(client, &request, "502 Bad Gateway", "Workspace unavailable",
                "The workspace or sign-in service is temporarily unavailable.");
        }
        Ok(())
    })
}

#[derive(PartialEq, Eq)]
struct GatewayContract {
    profile: String,
    entries: BTreeSet<String>,
    grants: BTreeSet<String>,
}

impl GatewayContract {
    fn from_app(app: &Application) -> Self {
        Self { profile: app.state_profile.clone(),
            entries: app.declared_entries().iter().cloned().collect(), grants: app.declared_grants().clone() }
    }
}

impl GatewayModule {
    fn compile(app: Application, shared_styles: &str) -> Result<Self> {
        const LIMIT: usize = 20_000_000;
        let mut meter = Meter::new(LIMIT);
        let mut programme = app.admit(&mut meter)?;
        app.bind_data(&mut programme);
        let own_chrome = app.has_entry("gateway.styles");
        let styles = if own_chrome {
            programme.run("gateway.styles", Value::Null, &mut meter.clone())?
                .as_str().ok_or_else(|| fail("expected declared gateway stylesheet text"))?.to_owned()
        } else {
            shared_styles.to_owned()
        };
        let notice_style_hash = if app.has_entry("gateway.notice") {
            if styles.contains('\r') || styles.to_ascii_lowercase().contains("</style") {
                return Err(fail("gateway notice stylesheet must be safe to embed as HTML text"));
            }
            Some(Base64::encode_string(&Sha256::digest(styles.as_bytes())))
        } else {
            None
        };
        Ok(Self { programme: programme.into_shared()?, meter: meter.remaining(), styles, notice_style_hash, own_chrome })
    }
}

pub(crate) fn verify_module_update(previous: &Path, next: &Path, prefix: &str, declaration: &str) -> Result<()> {
    verify_module_release(previous, prefix)?;
    verify_module_release(next, prefix)?;
    let current = load_policy(previous, declaration, None)?;
    let candidate = load_policy(next, declaration, Some(&current.state_profile))?;
    if GatewayContract::from_app(&current) != GatewayContract::from_app(&candidate) {
        return Err(fail("gateway policy changes the declared contract or grants"));
    }
    GatewayModule::compile(candidate, "")?;
    Ok(())
}

fn verify_module_release(root: &Path, prefix: &str) -> Result<()> {
    const MANIFEST: &str = "gateway-policy.rel";
    let bytes = crate::browser_release::artifact(root, MANIFEST, 64_000)?;
    let manifest = Facts::parse(std::str::from_utf8(&bytes)?)?;
    if manifest.one("release", "contract")? != "encounter/appdev-gateway-policy/1"
        || manifest.one("release", "prefix")? != prefix {
        return Err(fail("incompatible gateway policy release"));
    }
    let mut directories = vec![root.to_owned()];
    let mut artifacts = 0;
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                directories.push(path);
            } else if kind.is_file() {
                let name = path.strip_prefix(root)?.to_str().ok_or_else(|| fail("invalid gateway artifact path"))?;
                if name == MANIFEST { continue; }
                if !matches!(path.extension().and_then(|value| value.to_str()), Some("rel" | "encounter")) {
                    return Err(fail("unexpected artifact in gateway policy"));
                }
                let data = crate::browser_release::artifact(root, name, 1_000_000)?;
                if manifest.one("artifact", name)? != crate::rel::hash(&data) {
                    return Err(fail("gateway policy artifact failed its digest check"));
                }
                artifacts += 1;
            } else {
                return Err(fail("gateway policy package entries must be plain files or directories"));
            }
        }
    }
    if artifacts == 0 || manifest.0.len() != artifacts + 2 {
        return Err(fail("gateway policy artifact inventory differs from its manifest"));
    }
    Ok(())
}
