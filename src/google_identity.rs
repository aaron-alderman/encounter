use crate::{Result, fail, google_identity_custody, http::{self, Request}, http_client,
    process::{Meter, Programme}, workspace::transport::{Response, encode, token}};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, VecDeque}, env, io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    sync::Mutex, time::{Duration, Instant},
};
use zeroize::Zeroizing;

const AUTHORIZATION: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const ADMISSION_PATH: &str = "/v1/auth/oidc";
const PROTOCOL: &str = "sourcery.hosted/google-identity.v1";
const RESPONSE_LIMIT: usize = 64 * 1024;
const ATTEMPT_LIMIT: usize = 1024;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("google_identity.encounter").to_owned()],
        &["google.settings", "google.origin", "google.route", "google.login", "google.callback", "google.admission", "google.session"],
        &BTreeSet::from(["text.matches", "number.calculate"]), &mut Meter::new(20_000_000))
}

fn evaluate(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(20_000_000))
}

thread_local! {
    static WORKER_POLICY: std::result::Result<Programme, String> = policy().map_err(|error| error.to_string());
}

fn decide(entry: &str, input: Value) -> Result<Value> {
    WORKER_POLICY.with(|policy| evaluate(policy.as_ref().map_err(|error| fail(error.clone()))?, entry, input))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| fail(format!("Invalid Google identity field {key}")))
}

pub(super) fn required(name: &str) -> Result<String> {
    env::var(name).ok().map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
        .ok_or_else(|| fail(format!("{name} is required")))
}

pub(super) fn integer(name: &str, default: u32) -> Result<u32> {
    let Some(source) = env::var_os(name) else { return Ok(default); };
    source.to_str().filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse().ok()).ok_or_else(|| fail(format!("{name} must be an integer")))
}

pub(super) fn loopback(host: &str) -> Option<IpAddr> {
    match host {
        "127.0.0.1" | "localhost" => Some(Ipv4Addr::LOCALHOST.into()),
        "::1" | "[::1]" => Some(Ipv6Addr::LOCALHOST.into()),
        _ => None,
    }
}

pub(super) fn admission_url(value: &str) -> Result<String> {
    let invalid = || fail("The identity control plane must use the loopback /v1/auth/oidc URL");
    let authority = value.strip_prefix("http://").and_then(|value| value.strip_suffix(ADMISSION_PATH)).ok_or_else(invalid)?;
    let (address, port) = if let Some(address) = loopback(authority) {
        (address, 80)
    } else {
        let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
        let address = loopback(host).ok_or_else(invalid)?;
        let port: u16 = port.parse().ok().filter(|port| *port != 0).ok_or_else(invalid)?;
        (address, port)
    };
    Ok(format!("http://{}{ADMISSION_PATH}", SocketAddr::new(address, port)))
}

struct Config {
    bind: SocketAddr,
    callback: String,
    client: String,
    secret: Zeroizing<String>,
    admission_url: String,
    timeout: Duration,
    ttl: Duration,
    session_age: u32,
}

impl Config {
    fn load(policy: &Programme) -> Result<Self> {
        let bind = env::var("SOURCERY_GOOGLE_BIND_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
        let address = loopback(bind.trim()).ok_or_else(|| fail("Google identity must bind to loopback"))?;
        let port = integer("SOURCERY_GOOGLE_PORT", 8132)?;
        let timeout = integer("SOURCERY_GOOGLE_REQUEST_TIMEOUT_MS", 5000)?;
        let ttl = integer("SOURCERY_GOOGLE_STATE_TTL_MS", 300_000)?;
        let session_age = integer("SOURCERY_GOOGLE_SESSION_MAXIMUM_AGE_SECONDS", 28_800)?;
        evaluate(policy, "google.settings", json!({"port":port,"timeout":timeout,"ttl":ttl,"sessionAge":session_age}))?;
        let origin = required("SOURCERY_GOOGLE_PUBLIC_ORIGIN")?;
        evaluate(policy, "google.origin", json!(&origin))?;
        let origin = origin.trim_end_matches('/').to_ascii_lowercase();
        let origin = origin.strip_suffix(":443").unwrap_or(&origin);
        let client = required("SOURCERY_GOOGLE_CLIENT_ID")?;
        let admission_url = admission_url(&required("SOURCERY_GOOGLE_CONTROL_PLANE_URL")?)?;
        if required("SOURCERY_GOOGLE_CLIENT_SECRET_FILE")? != google_identity_custody::SECRET_PATH {
            return Err(fail("Google identity environment drifted from the canonical custody path"));
        }
        let mut source = Zeroizing::new(String::new());
        google_identity_custody::open_verified_secret()?.take(4097).read_to_string(&mut source)?;
        if source.len() > 4096 || source.trim().is_empty() { return Err(fail("Google client secret size is invalid")); }
        Ok(Self { bind: SocketAddr::new(address, u16::try_from(port)?), callback: format!("{origin}/identity/google/callback"), client,
            secret: Zeroizing::new(source.trim().to_owned()), admission_url, timeout: Duration::from_millis(timeout.into()),
            ttl: Duration::from_millis(ttl.into()), session_age })
    }
}

struct Attempt {
    state: String,
    nonce: String,
    verifier: Zeroizing<String>,
    return_path: String,
    expires: Instant,
}

struct Broker {
    config: Config,
    pending: Mutex<VecDeque<Attempt>>,
}

fn upstream(url: &str, media_type: &str, body: &[u8], timeout: Duration) -> Result<http_client::Response> {
    http_client::send(http_client::Request { url, method: "POST", headers: &[("Content-Type", media_type)], body: Some(body),
        timeout, connect_timeout: timeout, limit: RESPONSE_LIMIT, resolve: None, trust_anchor: None, restoring: false })
}

fn response_json(reply: http_client::Response, stage: &'static str) -> Result<Value> {
    if !(200..300).contains(&reply.status) {
        eprintln!("[sourcery-google-identity] request failed at {stage} (upstream HTTP {})", reply.status);
        return Err(fail(stage));
    }
    let value: Value = serde_json::from_slice(&reply.body)?;
    if !value.is_object() { return Err(fail("Invalid Google identity upstream response")); }
    Ok(value)
}

fn claims(token: &str) -> Result<Value> {
    let mut parts = token.split('.');
    let invalid = || fail("Google did not return a valid ID token");
    parts.next().filter(|part| !part.is_empty()).ok_or_else(invalid)?;
    let payload = parts.next().filter(|part| !part.is_empty()).ok_or_else(invalid)?;
    parts.next().filter(|part| !part.is_empty()).ok_or_else(invalid)?;
    if parts.next().is_some() { return Err(invalid()); }
    let value: Value = serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload)?)?;
    if !value.is_object() { return Err(invalid()); }
    Ok(value)
}

impl Broker {
    fn login(&self, return_path: &str) -> Result<Response> {
        let state = token::<32>()?;
        let nonce = token::<32>()?;
        let verifier = Zeroizing::new(token::<48>()?);
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        let login = decide("google.login", json!({"state":state,"nonce":nonce,"challenge":challenge,
            "client":self.config.client,"callback":self.config.callback,"ttl":self.config.ttl.as_millis() as u64,"returnPath":return_path}))?;
        let location = format!("{AUTHORIZATION}?{}", encode(&login["fields"])?);
        let now = Instant::now();
        let mut pending = self.pending.lock().map_err(|_| fail("Google identity pending state is unavailable"))?;
        pending.retain(|attempt| attempt.expires > now);
        if pending.len() == ATTEMPT_LIMIT { pending.pop_front(); }
        pending.push_back(Attempt { state, nonce, verifier, return_path: field(&login, "returnPath")?.to_owned(), expires: now + self.config.ttl });
        Ok(Response::empty(303).with("Location", location).with("Set-Cookie", field(&login, "cookie")?))
    }

    fn consume(&self, state: &str) -> Result<Option<Attempt>> {
        let mut pending = self.pending.lock().map_err(|_| fail("Google identity pending state is unavailable"))?;
        Ok(pending.iter().position(|attempt| attempt.state == state).and_then(|index| pending.remove(index)))
    }

    fn callback(&self, state: &str, code: &str, has_error: bool, cookies: &[String],
        post: impl Fn(&str, &str, &[u8], Duration) -> Result<http_client::Response>) -> Result<Response> {
        let attempt = self.consume(state)?;
        let request = decide("google.callback", json!({"pending":attempt.is_some(),
            "active":attempt.as_ref().is_some_and(|attempt| attempt.expires > Instant::now()),
            "cookies":cookies,"state":state,"error":has_error,"code":code,"client":self.config.client,
            "callback":self.config.callback,"verifier":attempt.as_ref().map(|attempt| attempt.verifier.as_str())}))?;
        if request.is_null() { return Ok(Response::text(401, "Google sign-in was not accepted.\n")); }
        let attempt = attempt.ok_or_else(|| fail("Google identity policy selected a missing attempt"))?;
        let mut form = Zeroizing::new(encode(&request)?);
        form.push('&');
        form.push_str(&Zeroizing::new(form_urlencoded::Serializer::new(String::new())
            .append_pair("client_secret", &self.config.secret).finish()));
        let google = response_json(post(GOOGLE_TOKEN, "application/x-www-form-urlencoded", form.as_bytes(), self.config.timeout)?,
            "google-token-exchange")?;
        let id_token = field(&google, "id_token")?;
        let payload = decide("google.admission", json!({"idToken":id_token,"claims":claims(id_token)?,"expectedNonce":attempt.nonce}))?;
        let session = response_json(post(&self.config.admission_url, "application/json", &serde_json::to_vec(&payload)?, self.config.timeout)?,
            "control-plane-admission")?;
        let cookies = decide("google.session", json!({"token":field(&session,"token")?,"age":self.config.session_age}))?;
        Ok(Response::empty(303).with("Location", attempt.return_path)
            .with("Set-Cookie", field(&cookies, "sessionCookie")?).with("Set-Cookie", field(&cookies, "clearCookie")?))
    }

    fn handle(&self, request: Request) -> Result<Response> {
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        let fields: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();
        let param = |name| fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_ref());
        let route = decide("google.route", json!({"method":request.method,"path":path}))?;
        match route.as_str() {
            Some("health") => Ok(Response::text(200, format!("{}\n", json!({"status":"ok","protocol":PROTOCOL})))),
            Some("login") => self.login(param("return").unwrap_or_default()),
            Some("callback") => {
                let cookies: Vec<_> = request.headers.get("cookie").into_iter().flat_map(|header| header.split(';'))
                    .filter_map(|item| item.trim().strip_prefix("__Host-sourcery_google="))
                    .map(|value| {
                        let encoded = format!("value={}", value.replace('&', "%26").replace('+', "%2B"));
                        form_urlencoded::parse(encoded.as_bytes()).next().map(|(_, value)| value.into_owned()).unwrap_or_default()
                    }).collect();
                self.callback(param("state").unwrap_or_default(), param("code").unwrap_or_default(), param("error").is_some(), &cookies, upstream)
            }
            Some("missing") => Ok(Response::text(404, "Not found.\n")),
            _ => Err(fail("Unknown Google identity route")),
        }
    }
}

pub(crate) fn serve() -> Result<()> {
    let policy = policy()?;
    let config = Config::load(&policy)?;
    let listener = TcpListener::bind(config.bind)?;
    let broker = Broker { config, pending: Mutex::new(VecDeque::new()) };
    http::serve_bound_workers(listener, 8, 0, || Ok(()), move |stream, request| {
        let response = broker.handle(request).unwrap_or_else(|_| {
            eprintln!("[sourcery-google-identity] request failed");
            Response::text(503, "Identity service is temporarily unavailable.\n")
        });
        let _ = response.with("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'").send(stream, false);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, io::{BufRead, BufReader, Write}, net::TcpStream, thread};

    fn wire(response: Response) -> Result<String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let mut client = TcpStream::connect(listener.local_addr()?)?;
        let (mut server, _) = listener.accept()?;
        response.send(&mut server, false)?;
        drop(server);
        let mut reply = String::new();
        client.read_to_string(&mut reply)?;
        Ok(reply)
    }

    fn fixture_upstream(admission_body: String, token_body: String) -> Result<(SocketAddr, thread::JoinHandle<std::result::Result<Vec<String>, String>>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let worker = thread::spawn(move || (|| -> Result<_> {
            let mut observed = Vec::new();
            for body in [token_body, admission_body] {
                let (mut stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                let mut reader = BufReader::new(&mut stream);
                let mut head = String::new();
                reader.read_line(&mut head)?;
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line)? == 0 || line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("Content-Length") { length = value.trim().parse()?; }
                    }
                }
                let mut received = vec![0; length];
                reader.read_exact(&mut received)?;
                observed.push(format!("{head}{}", String::from_utf8(received)?));
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
            }
            Ok(observed)
        })().map_err(|error| error.to_string()));
        Ok((address, worker))
    }

    #[test]
    fn oauth_broker_checks_state_nonce_and_admission_before_setting_session() -> Result<()> {
        let broker = Broker { config: Config { bind: (Ipv4Addr::LOCALHOST, 0).into(),
            callback: "https://mcp.example/identity/google/callback".to_owned(), client: "google-client".to_owned(),
            secret: Zeroizing::new("fixture-secret+&".to_owned()), admission_url: "http://127.0.0.1:8130/v1/auth/oidc".to_owned(),
            timeout: Duration::from_secs(2), ttl: Duration::from_secs(300), session_age: 28_800 }, pending: Mutex::default() };
        let health = Request { method: "GET".to_owned(), path: "/identity/healthz".to_owned(), headers: Default::default(), body: vec![] };
        assert!(wire(broker.handle(health)?)?.contains(PROTOCOL));
        let login = wire(broker.login("//outside.example")?)?;
        assert!(login.starts_with("HTTP/1.1 303"));
        let location = login.lines().find_map(|line| line.strip_prefix("Location: ")).unwrap();
        let query = location.strip_prefix(AUTHORIZATION).unwrap().strip_prefix('?').unwrap();
        let fields: std::collections::BTreeMap<_, _> = form_urlencoded::parse(query.as_bytes()).collect();
        assert_eq!(fields["response_type"], "code");
        assert_eq!(fields["scope"], "openid email profile");
        assert_eq!(fields["code_challenge_method"], "S256");
        assert_eq!(fields["prompt"], "select_account");
        let state = fields["state"].to_string();
        let nonce = fields["nonce"].to_string();
        assert!(login.contains(&format!("__Host-sourcery_google={state}; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax")));
        assert!(decide("google.admission", json!({"claims":{"nonce":"different"},"expectedNonce":nonce})).is_err());
        assert!(decide("google.session", json!({"token":"external-token","age":28800})).is_err());
        let id_token = format!("header.{}.signature", Base64UrlUnpadded::encode_string(json!({"nonce":nonce}).to_string().as_bytes()));
        let session = format!("src_session_{}", "a".repeat(43));
        let (address, worker) = fixture_upstream(json!({"token":session}).to_string(),
            json!({"id_token":id_token,"access_token":"must-not-be-forwarded"}).to_string())?;
        let destinations = RefCell::new(Vec::new());
        let callback = wire(broker.callback(&state, "google-code", false, std::slice::from_ref(&state), |url, media, body, timeout| {
            destinations.borrow_mut().push(url.to_owned());
            let path = if url == GOOGLE_TOKEN { "/token" } else { ADMISSION_PATH };
            upstream(&format!("http://{address}{path}"), media, body, timeout)
        })?)?;
        assert_eq!(destinations.into_inner(), [GOOGLE_TOKEN, &broker.config.admission_url]);
        let observed = worker.join().expect("fixture HTTP worker")?;
        let form: std::collections::BTreeMap<_, _> = form_urlencoded::parse(observed[0].split_once("\r\n").unwrap().1.as_bytes()).collect();
        assert_eq!(form["code"], "google-code");
        assert_eq!(form["client_secret"], "fixture-secret+&");
        assert_eq!(fields["code_challenge"], Base64UrlUnpadded::encode_string(&Sha256::digest(form["code_verifier"].as_bytes())));
        assert_eq!(serde_json::from_str::<Value>(observed[1].split_once("\r\n").unwrap().1)?, json!({"idToken":id_token}));
        assert!(callback.starts_with("HTTP/1.1 303"));
        assert!(callback.contains("Location: /portal\r\n"));
        assert!(callback.contains(&format!("Set-Cookie: __Host-sourcery_session={session}; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Lax")));
        assert!(callback.contains("Set-Cookie: __Host-sourcery_google=; Path=/; Max-Age=0"));
        let denied = |_: &str, _: &str, _: &[u8], _: Duration| panic!("invalid callback attempted upstream access");
        assert!(wire(broker.callback(&state, "replay", false, std::slice::from_ref(&state), denied)?)?.starts_with("HTTP/1.1 401"));
        broker.login("/portal")?;
        let state = broker.pending.lock().unwrap().back().unwrap().state.clone();
        assert!(wire(broker.callback(&state, "wrong-cookie", false, &["other".to_owned()], denied)?)?.starts_with("HTTP/1.1 401"));
        assert!(wire(broker.callback(&state, "second-try", false, std::slice::from_ref(&state), denied)?)?.starts_with("HTTP/1.1 401"));
        assert!(admission_url("http://127.0.0.1.example/v1/auth/oidc").is_err());
        assert!(admission_url("http://127.0.0.1:8130/other").is_err());
        Ok(())
    }
}
