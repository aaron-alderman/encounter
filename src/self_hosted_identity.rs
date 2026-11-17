use crate::{Result, fail, google_identity::{admission_url, integer, loopback, required}, http::{self, Request}, http_client,
    process::{CSS_RENDERER, HTML_PORTS, HTML_RENDERER, Meter, Programme}, self_hosted_identity_crypto::{PasswordRecord, SigningKey}, workspace::transport::{Response, token}};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque}, env, fs::OpenOptions, io::Read,
    net::{IpAddr, SocketAddr, TcpListener}, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::Path,
    sync::Mutex, time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const PROTOCOL: &str = "sourcery.self-hosted/identity.v1";
const POLICY_METER: usize = 20_000_000;
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const LOGIN_WINDOW: Duration = Duration::from_secs(300);
const MAX_CRYPTO_MEMORY: u64 = 192 * 1024 * 1024;
const BODY_LIMIT: usize = 8192;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("self_hosted_identity.encounter").to_owned()],
        &["identity.settings", "identity.passwordRecord", "identity.provision", "identity.productionCustody", "identity.route", "identity.returnPath", "identity.admitRequest", "identity.rate",
            "identity.checkChallenge", "identity.credential", "identity.assertion", "identity.session"],
        &BTreeSet::from(["text.matches", "number.calculate", "record.put"]), &mut Meter::new(POLICY_METER))
}

thread_local! {
    static POLICY: std::result::Result<Programme, String> = policy().map_err(|error| error.to_string());
}

pub(super) fn decide(entry: &str, input: Value) -> Result<Value> {
    POLICY.with(|policy| policy.as_ref().map_err(|error| fail(error.clone()))?.run(entry, input, &mut Meter::new(POLICY_METER)))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or_else(|| fail(format!("Invalid operator identity field {name}")))
}

fn credential(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = required(name)?;
    if !Path::new(&path).is_absolute() { return Err(fail(format!("{name} must be absolute"))); }
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || (metadata.uid() != 0 && metadata.uid() != uid) || metadata.mode() & 0o027 != 0 || metadata.len() > 16_384 {
        return Err(fail(format!("{name} must be a protected regular credential file")));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(16_385).read_to_end(&mut bytes)?;
    if bytes.len() > 16_384 { return Err(fail(format!("{name} exceeds its byte limit"))); }
    Ok(bytes)
}

fn load_key(key_id: &str) -> Result<(SigningKey, Value)> {
    let source = credential("SOURCERY_IDENTITY_PRIVATE_JWK_FILE")?;
    let mut jwk: Value = serde_json::from_slice(&source).map_err(|_| fail("Invalid private JWK JSON"))?;
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" { return Err(fail("Expected an EC P-256 private JWK")); }
    let mut scalar = Zeroizing::new([0; 32]);
    let raw = jwk.as_object_mut().and_then(|fields| fields.remove("d")).ok_or_else(|| fail("Missing private JWK scalar"))?;
    let Value::String(raw) = raw else { return Err(fail("Invalid private JWK scalar")); };
    let raw = Zeroizing::new(raw);
    if Base64UrlUnpadded::decode(&raw, scalar.as_mut())?.len() != 32 { return Err(fail("Invalid private JWK scalar width")); }
    let coordinate = |key| -> Result<[u8; 32]> {
        Base64UrlUnpadded::decode_vec(field(&jwk, key)?)?.try_into().map_err(|_| fail("Invalid P-256 coordinate width"))
    };
    let signer = SigningKey::new(scalar, coordinate("x")?, coordinate("y")?)?;
    let keys = json!({"keys":[{"kty":"EC","crv":"P-256","x":jwk["x"],"y":jwk["y"],"kid":key_id,
        "alg":"ES256","use":"sig","key_ops":["verify"]}]});
    Ok((signer, keys))
}

fn load_password() -> Result<(PasswordRecord, u64)> {
    let source = credential("SOURCERY_IDENTITY_PASSWORD_RECORD_FILE")?;
    let mut record: Value = serde_json::from_slice(&source).map_err(|_| fail("Invalid password record JSON"))?;
    let raw = record.as_object_mut().and_then(|fields| fields.remove("digest")).ok_or_else(|| fail("Missing password digest"))?;
    let Value::String(raw) = raw else { return Err(fail("Invalid password digest")); };
    let digest = Zeroizing::new(Base64::decode_vec(&Zeroizing::new(raw))?);
    let salt = Base64::decode_vec(field(&record, "salt")?)?;
    let integer = |name| record[name].as_u64().and_then(|value| u32::try_from(value).ok()).map(u64::from)
        .ok_or_else(|| fail("Invalid password record parameter"));
    let cost = integer("cost")?;
    let block_size = integer("blockSize")?;
    let parallelization = integer("parallelization")?;
    let memory = 128_u64.checked_mul(cost + parallelization + 2).and_then(|value| value.checked_mul(block_size))
        .ok_or_else(|| fail("Invalid password memory requirement"))?;
    decide("identity.passwordRecord", json!({"algorithm":record["algorithm"],"cost":cost,"powerOfTwo":cost.is_power_of_two(),
        "blockSize":block_size,"parallelization":parallelization,"keyLength":integer("keyLength")?,"memoryBytes":memory,
        "digestBytes":digest.len(),"saltBytes":salt.len()}))?;
    Ok((PasswordRecord { salt, digest, cost, block_size, parallelization }, memory))
}

struct Config {
    bind: SocketAddr,
    origin: String,
    issuer: String,
    audience: String,
    subject: String,
    email: String,
    key_id: String,
    signer: SigningKey,
    keys: Value,
    password: PasswordRecord,
    password_memory: u64,
    control: String,
    timeout: Duration,
    session_age: u32,
    token_ttl: u32,
}

fn https(value: String) -> Result<String> {
    let address = value.strip_prefix("https://").ok_or_else(|| fail("Expected an HTTPS identity URL"))?;
    let (host, path) = address.split_once('/').map_or((address, ""), |(host, _)| (host, &address[host.len()..]));
    let host = host.strip_suffix(":443").unwrap_or(host);
    Ok(format!("https://{}{path}", host.to_ascii_lowercase()).trim_end_matches('/').to_owned())
}

impl Config {
    fn load() -> Result<Self> {
        let host = env::var("SOURCERY_IDENTITY_BIND_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let address = loopback(host.trim()).ok_or_else(|| fail("Self-hosted identity must bind to loopback"))?;
        let port = integer("SOURCERY_IDENTITY_PORT", 8131)?;
        let origin = https(required("SOURCERY_IDENTITY_PUBLIC_ORIGIN")?)?;
        let issuer = https(required("SOURCERY_IDENTITY_ISSUER")?)?;
        let audience = required("SOURCERY_IDENTITY_AUDIENCE")?;
        let subject = required("SOURCERY_IDENTITY_SUBJECT")?;
        let email = required("SOURCERY_IDENTITY_EMAIL")?.to_lowercase();
        let key_id = required("SOURCERY_IDENTITY_KEY_ID")?;
        let timeout = integer("SOURCERY_IDENTITY_CONTROL_PLANE_TIMEOUT_MS", 5000)?;
        let session_age = integer("SOURCERY_IDENTITY_SESSION_MAXIMUM_AGE_SECONDS", 28_800)?;
        let token_ttl = integer("SOURCERY_IDENTITY_TOKEN_TTL_SECONDS", 60)?;
        decide("identity.settings", json!({"origin":origin,"issuer":issuer,"issuerBelowOrigin":issuer.starts_with(&format!("{origin}/")),
            "keyId":key_id,"email":email,"emailLength":email.encode_utf16().count(),"audienceLength":audience.encode_utf16().count(),
            "subjectLength":subject.encode_utf16().count(),"port":port,"timeout":timeout,"sessionAge":session_age,"tokenTtl":token_ttl}))?;
        let control = admission_url(&required("SOURCERY_IDENTITY_CONTROL_PLANE_URL")?)?;
        let (signer, keys) = load_key(&key_id)?;
        let (password, password_memory) = load_password()?;
        Ok(Self { bind: SocketAddr::new(address, u16::try_from(port)?), origin, issuer, audience, subject, email, key_id,
            signer, keys, password, password_memory, control, timeout: Duration::from_millis(timeout.into()), session_age, token_ttl })
    }

    fn assertion(&self) -> Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let parts = decide("identity.assertion", json!({"issuer":self.issuer,"subject":self.subject,"audience":self.audience,
            "keyId":self.key_id,"email":self.email,"now":now,"ttl":self.token_ttl,"nonce":token::<16>()?}))?;
        let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&parts["header"])?);
        let claims = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&parts["claims"])?);
        let mut assertion = format!("{header}.{claims}");
        let signature = self.signer.sign(assertion.as_bytes())?;
        assertion.push('.');
        assertion.push_str(&Base64UrlUnpadded::encode_string(&signature));
        Ok(assertion)
    }

    fn exchange(&self, client: IpAddr) -> Result<Value> {
        let body = Zeroizing::new(serde_json::to_vec(&json!({"idToken":self.assertion()?}))?);
        let response = http_client::send(http_client::Request { url: &self.control, method: "POST", headers: &[
            ("Content-Type", "application/json"), ("X-Forwarded-Proto", "https"), ("X-Forwarded-For", &client.to_string())],
            body: Some(&body), timeout: self.timeout, connect_timeout: self.timeout, limit: 65_536,
            resolve: None, trust_anchor: None, restoring: false })?;
        if !(200..300).contains(&response.status) { return Err(fail("Control plane rejected the operator assertion")); }
        Ok(serde_json::from_slice(&response.body)?)
    }
}

struct Challenge { token: String, return_path: String, expires: Instant }
struct Attempt { client: IpAddr, count: u32, expires: Instant }

#[derive(Default)]
struct State { challenges: VecDeque<Challenge>, attempts: VecDeque<Attempt>, derivations: usize, memory: u64 }

struct Derivation<'a> { state: &'a Mutex<State>, memory: u64 }

impl Drop for Derivation<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() { state.derivations -= 1; state.memory -= self.memory; }
    }
}

struct Broker { config: Config, state: Mutex<State> }

fn login_page(csrf: &str, return_path: &str, failed: bool) -> Result<String> {
    let mut meter = Meter::new(100_000);
    let sources = HTML_RENDERER.into_iter().chain([
        CSS_RENDERER, include_str!("self_hosted_identity_login.encounter"),
    ]).map(str::to_owned).collect::<Vec<_>>();
    let program = Programme::admit_entries(&sources, &["operatorLogin.page"],
        &BTreeSet::from(HTML_PORTS), &mut meter)?;
    let page = program.run("operatorLogin.page", json!({
        "csrf": csrf, "returnPath": return_path, "failed": failed,
    }), &mut meter)?;
    page.as_str().map(str::to_owned).ok_or_else(|| fail("Expected operator sign-in document"))
}

fn refused(status: u16) -> Response { Response::text(status, "Sign-in was not accepted.\n") }

impl Broker {
    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| fail("Operator identity state is unavailable"))
    }

    fn challenge(&self, return_path: &str, failed: bool) -> Result<Response> {
        let csrf = token::<32>()?;
        let now = Instant::now();
        let mut state = self.state()?;
        state.challenges.retain(|challenge| challenge.expires > now);
        if state.challenges.len() == 1024 { state.challenges.pop_front(); }
        state.challenges.push_back(Challenge { token: csrf.clone(), return_path: return_path.to_owned(), expires: now + LOGIN_WINDOW });
        drop(state);
        let page = login_page(&csrf, return_path, failed)?;
        Ok(Response::html_body(if failed { 401 } else { 200 }, page)
            .with("Set-Cookie", format!("__Host-sourcery_login={csrf}; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Strict")))
    }

    fn count_attempt(&self, client: IpAddr) -> Result<u32> {
        let now = Instant::now();
        let mut state = self.state()?;
        state.attempts.retain(|attempt| attempt.expires > now);
        if let Some(attempt) = state.attempts.iter_mut().find(|attempt| attempt.client == client) {
            attempt.count = attempt.count.saturating_add(1);
            return Ok(attempt.count);
        }
        if state.attempts.len() == 4096 { state.attempts.pop_front(); }
        state.attempts.push_back(Attempt { client, count: 1, expires: now + LOGIN_WINDOW });
        Ok(1)
    }

    fn reserve_derivation(&self) -> Result<Derivation<'_>> {
        let mut state = self.state()?;
        let memory = self.config.password_memory;
        if state.derivations >= 2 || state.memory + memory > MAX_CRYPTO_MEMORY { return Err(fail("Operator verification is saturated")); }
        state.derivations += 1;
        state.memory += memory;
        Ok(Derivation { state: &self.state, memory })
    }

    fn submit(&self, mut request: Request, peer: IpAddr) -> Result<Response> {
        let headers = &request.headers;
        if decide("identity.admitRequest", json!({"loopback":peer.is_loopback(),"origin":headers.get("origin"),
            "publicOrigin":self.config.origin}))? != true { return Ok(refused(403)); }
        let client = headers.get("x-forwarded-for").and_then(|line| line.split(',').next()).and_then(|value| value.trim().parse().ok()).unwrap_or(peer);
        if decide("identity.rate", json!(self.count_attempt(client)?))? != true {
            return Ok(refused(429).with("Retry-After", "300"));
        }
        let media = headers.get("content-type").and_then(|line| line.split(';').next()).unwrap_or_default();
        if !media.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded") { return Ok(refused(415)); }
        let body = Zeroizing::new(std::mem::take(&mut request.body));
        let mut secret = None;
        let mut csrf = None;
        let mut return_to = None;
        for (name, value) in form_urlencoded::parse(&body) {
            match name.as_ref() {
                "secret" if secret.is_none() => secret = Some(Zeroizing::new(value.into_owned())),
                "csrf" if csrf.is_none() => csrf = Some(value.into_owned()),
                "return" if return_to.is_none() => return_to = Some(value.into_owned()),
                _ => {}
            }
        }
        let secret = secret.unwrap_or_default();
        let csrf = csrf.unwrap_or_default();
        let return_path = decide("identity.returnPath", json!(return_to.unwrap_or_default()))?;
        let return_path = return_path.as_str().ok_or_else(|| fail("Invalid operator return path"))?;
        let cookies: Vec<_> = headers.get("cookie").into_iter().flat_map(|header| header.split(';'))
            .filter_map(|cookie| cookie.trim().strip_prefix("__Host-sourcery_login=")).collect();
        let retained = {
            let mut state = self.state()?;
            state.challenges.iter().position(|challenge| challenge.token == csrf).and_then(|index| state.challenges.remove(index))
        };
        let valid = decide("identity.checkChallenge", json!({"challenge":csrf,"cookies":cookies,
            "active":retained.as_ref().is_some_and(|challenge| challenge.expires > Instant::now()),
            "retainedPath":retained.as_ref().map(|challenge| &challenge.return_path),"returnPath":return_path,
            "secretLength":secret.encode_utf16().count()}))?;
        if valid != true { return self.challenge(return_path, true); }
        let matched = {
            let _permit = self.reserve_derivation()?;
            self.config.password.matches(secret.as_bytes())?
        };
        if decide("identity.credential", json!(matched))? != "assert" { return self.challenge(return_path, true); }
        let result = self.config.exchange(client)?;
        let cookies = decide("identity.session", json!({"token":field(&result,"token")?,"age":self.config.session_age}))?;
        self.state()?.attempts.retain(|attempt| attempt.client != client);
        Ok(Response::empty(303).with("Location", return_path).with("Set-Cookie", field(&cookies, "session")?)
            .with("Set-Cookie", field(&cookies, "clear")?))
    }

    fn handle(&self, request: Request, peer: IpAddr) -> Result<Response> {
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        let route = decide("identity.route", json!({"method":request.method,"path":path}))?;
        let response = match route.as_str() {
            Some("challenge") => {
                let value = form_urlencoded::parse(query.as_bytes()).find(|(name, _)| name == "return").map(|(_, value)| value.into_owned());
                let path = decide("identity.returnPath", json!(value.unwrap_or_default()))?;
                return self.challenge(path.as_str().ok_or_else(|| fail("Invalid operator return path"))?, false);
            }
            Some("submit") => return self.submit(request, peer),
            Some("health") => Response::json(200, &json!({"status":"ok","protocol":PROTOCOL})),
            Some("keys") => Response::json(200, &self.config.keys),
            Some("missing") => Response::text(404, "Not found.\n"),
            _ => return Err(fail("Unknown self-hosted identity route")),
        };
        Ok(response)
    }
}

pub(crate) fn serve() -> Result<()> {
    let config = Config::load()?;
    let listener = TcpListener::bind(config.bind)?;
    let broker = Broker { config, state: Mutex::default() };
    http::serve_bound_form_workers(listener, 8, BODY_LIMIT, move |stream, request| {
        let response = stream.peer_addr().map_err(Into::into).and_then(|peer| broker.handle(request, peer.ip())).unwrap_or_else(|_| {
            eprintln!("[sourcery-identity] operator sign-in request failed");
            Response::text(503, "Identity service is temporarily unavailable.\n")
        });
        let _ = response.with("X-Frame-Options", "DENY").with("Content-Security-Policy", CSP).send(stream, false);
    })
}
