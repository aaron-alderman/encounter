use crate::{Result, fail, http, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::DateTime;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet, env, fs::{self, OpenOptions}, io::{self, Read, Write},
    os::unix::{fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt}, net::{UnixListener, UnixStream}},
    path::{Path, PathBuf}, thread, time::{Duration, Instant},
};
use zeroize::Zeroizing;

const REQUEST_LIMIT: usize = 16_384;
const PAYLOAD_LIMIT: usize = 8192;
const NIL_ID: &str = "request.00000000-0000-0000-0000-000000000000";
const INVALID: &str = "self-hosted-runtime-authority-invalid";
const TOO_LARGE: &str = "self-hosted-runtime-authority-request-large";

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("runtime_authority.encounter").to_owned()],
        &["authority.protocol", "authority.registry", "authority.dispatch"],
        &BTreeSet::from(["kernel.invoke", "record.entries", "digest.sha256", "json.canonical",
            "number.calculate", "text.matches", "value.describe"]),
        &mut Meter::new(20_000_000))
}

fn evaluate(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(20_000_000))
}

fn required(name: &str) -> Result<String> {
    env::var(name).ok().map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
        .ok_or_else(|| fail(format!("{name} is required")))
}

fn integer(name: &str, fallback: u64, minimum: u64, maximum: u64) -> Result<u64> {
    let Some(value) = env::var_os(name) else { return Ok(fallback); };
    let value = value.to_str().and_then(|value| {
        let value = value.trim();
        for (prefix, base) in [("0o", 8), ("0x", 16), ("0b", 2)] {
            if let Some(digits) = value.strip_prefix(prefix) { return u64::from_str_radix(digits, base).ok(); }
        }
        value.parse::<u64>().ok()
    }).filter(|value| (minimum..=maximum).contains(value));
    value.ok_or_else(|| fail(format!("{name} must be between {minimum} and {maximum}")))
}

fn read_config(path: &Path, limit: u64, key: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    let disallowed = if key { 0o077 } else { 0o022 };
    if !metadata.is_file() || metadata.mode() & disallowed != 0 || metadata.len() > limit {
        return Err(fail("Expected bounded runtime authority configuration with protected permissions"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Runtime authority configuration exceeds its byte limit")); }
    Ok(bytes)
}

fn signing_key(path: &Path) -> Result<SigningKey> {
    let pem = Zeroizing::new(read_config(path, 4096, true)?);
    crate::signature::signing_key_from_pem(&pem)
}

pub(crate) struct Socket {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Socket {
    pub(crate) fn bind(path: PathBuf, mode: u32) -> Result<(Self, UnixListener)> {
        let parent = path.parent().filter(|path| path.is_absolute())
            .ok_or_else(|| fail("Expected an absolute runtime authority socket path"))?;
        let metadata = fs::metadata(parent)?;
        if !metadata.is_dir() || parent.canonicalize()? != parent
            || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(fail("Expected a protected, service-owned runtime authority socket directory"));
        }
        if mode & 0o007 != 0 { return Err(fail("Runtime authority socket cannot grant access to other users")); }
        // Bind before granting the configured group access.
        let previous = unsafe { libc::umask(0o077) };
        let listener = UnixListener::bind(&path);
        unsafe { libc::umask(previous); }
        let listener = listener?;
        let metadata = fs::symlink_metadata(&path)?;
        let socket = Self { path, device:metadata.dev(), inode:metadata.ino() };
        fs::set_permissions(&socket.path, fs::Permissions::from_mode(mode))?;
        listener.set_nonblocking(true)?;
        Ok((socket, listener))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata|
            metadata.file_type().is_socket() && metadata.dev() == self.device && metadata.ino() == self.inode) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct SigningInput {
    bytes: Vec<u8>,
    evidence: Value,
}

impl SigningInput {
    fn parse(input: &Value, key_id: &str) -> Option<Self> {
        let encoded = input.as_str().filter(|encoded| !encoded.is_empty() && encoded.len() <= 12_000)?;
        let bytes = Base64UrlUnpadded::decode_vec(encoded).ok()?;
        if bytes.is_empty() || bytes.len() > PAYLOAD_LIMIT { return None; }
        let wire = std::str::from_utf8(&bytes).ok()?;
        let claims: Value = serde_json::from_str(wire).ok()?;
        let timestamp = |name| DateTime::parse_from_rfc3339(claims[name].as_str()?).ok().map(|date| date.timestamp_millis());
        let (issued, expires) = (timestamp("issuedAt"), timestamp("expiresAt"));
        let evidence = json!({"wire":wire,"claims":claims,"keyId":key_id,
            "fieldCount":claims.as_object().map(|fields| fields.len()),
            "timestamps":issued.is_some() && expires.is_some(),"issuedAt":issued,"expiresAt":expires});
        Some(Self { bytes, evidence })
    }
}

struct Authority {
    protocol: String,
    key_id: String,
    key: SigningKey,
    registry: Value,
    timeout: Duration,
}

impl Authority {
    fn dispatch(&self, policy: &Programme, message: Value) -> Result<Value> {
        let signing = if message["operation"] == "sign-runtime-grant" && message["keyId"] == self.key_id {
            SigningInput::parse(&message["payload"], &self.key_id)
        } else { None };
        let decision = evaluate(policy, "authority.dispatch", json!({
            "keyId":self.key_id,"registry":self.registry,"message":message,
            "hasConsumer":message.get("presentedConsumerId").is_some(),
            "hasSigning":signing.is_some(),
            "signing":signing.as_ref().map(|input| &input.evidence),
        })).unwrap_or_else(|_| json!({"code":"self-hosted-runtime-authority-denied"}));
        let id = message["requestId"].as_str().filter(|id| id.len() <= NIL_ID.len()).unwrap_or(NIL_ID);
        let envelope = |body: Value| -> Value {
            let mut response = json!({"protocol":self.protocol,"requestId":id});
            response.as_object_mut().expect("runtime authority envelope")
                .extend(body.as_object().expect("runtime authority response").clone());
            response
        };
        let response = match decision["kind"].as_str() {
            Some("ready") => json!({"status":"ok","keyId":decision["keyId"],"workloadCount":decision["workloadCount"]}),
            Some("identity") => json!({"status":"ok","consumerId":decision["consumerId"],"evidenceHash":decision["evidenceHash"]}),
            Some("sign") => {
                if http::stopping() { return Err(fail("Runtime authority is stopping")); }
                let input = signing.ok_or_else(|| fail("Expected a verified runtime grant payload"))?;
                let signature = self.key.sign(&input.bytes);
                json!({"status":"ok","signature":Base64UrlUnpadded::encode_string(&signature.to_bytes())})
            }
            _ => json!({"status":"denied","code":decision["code"].as_str().unwrap_or("self-hosted-runtime-authority-denied")}),
        };
        Ok(envelope(response))
    }

    fn deny(&self, code: &str) -> Value {
        json!({"protocol":self.protocol,"requestId":NIL_ID,"status":"denied","code":code})
    }

    fn connection(&self, mut stream: UnixStream) -> Result<()> {
        let deadline = Instant::now() + self.timeout;
        let mut frame = Vec::new();
        let mut buffer = [0; 4096];
        let response = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if http::stopping() || remaining.is_zero() { return Ok(()); }
            stream.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
            match stream.read(&mut buffer) {
                Ok(0) => break self.deny(INVALID),
                Ok(count) => {
                    frame.extend_from_slice(&buffer[..count]);
                    if frame.len() > REQUEST_LIMIT { break self.deny(TOO_LARGE); }
                    if let Some(newline) = frame.iter().position(|byte| *byte == b'\n') {
                        if frame[newline + 1..].iter().any(|byte| !byte.is_ascii_whitespace()) {
                            break self.deny(INVALID);
                        }
                        let Ok(message) = serde_json::from_slice(&frame[..newline]) else { break self.deny(INVALID); };
                        break self.dispatch(&policy()?, message).unwrap_or_else(|_| self.deny(INVALID));
                    }
                }
                Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                Err(error) => return Err(error.into()),
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if http::stopping() || remaining.is_zero() { return Ok(()); }
        stream.set_write_timeout(Some(remaining.min(Duration::from_millis(200))))?;
        let mut output = serde_json::to_vec(&response)?;
        if output.len() >= REQUEST_LIMIT { return Err(fail("Runtime authority response exceeds its byte limit")); }
        output.push(b'\n');
        stream.write_all(&output)?;
        Ok(())
    }
}

pub fn serve() -> Result<()> {
    let path = required("SOURCERY_RUNTIME_AUTHORITY_SOCKET")?.into();
    let key_id = required("SOURCERY_RUNTIME_AUTHORITY_KEY_ID")?;
    let key_path = required("SOURCERY_RUNTIME_AUTHORITY_PRIVATE_KEY_FILE")?;
    let registry_path = required("SOURCERY_RUNTIME_AUTHORITY_WORKLOAD_REGISTRY_FILE")?;
    let mode = integer("SOURCERY_RUNTIME_AUTHORITY_SOCKET_MODE", 0o660, 0o600, 0o770)? as u32;
    let timeout = Duration::from_millis(integer("SOURCERY_RUNTIME_AUTHORITY_CONNECTION_TIMEOUT_MS", 5_000, 100, 30_000)?);
    let maximum = integer("SOURCERY_RUNTIME_AUTHORITY_MAXIMUM_CONNECTIONS", 32, 1, 256)? as usize;
    let policy = policy()?;
    let protocol = evaluate(&policy, "authority.protocol", Value::Null)?.as_str().ok_or_else(|| fail("Expected runtime authority protocol"))?.to_owned();
    let registry: Value = serde_json::from_slice(&read_config(Path::new(&registry_path), 1_048_576, false)?)?;
    let registry = evaluate(&policy, "authority.registry", json!({"registry":registry,"keyId":key_id}))?;
    let count = registry.as_array().ok_or_else(|| fail("Expected admitted runtime authority registry"))?.len();
    let key = signing_key(Path::new(&key_path))?;
    let authority = Authority { protocol, key_id, key, registry, timeout };
    http::install_stop_signals()?;
    let (_socket, listener) = Socket::bind(path, mode)?;
    println!("{}", json!({"protocol":authority.protocol,"status":"ready","keyId":authority.key_id,"workloadCount":count}));
    thread::scope(|scope| -> Result<()> {
        let mut workers = Vec::<thread::ScopedJoinHandle<'_, ()>>::new();
        while !http::stopping() {
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    workers.swap_remove(index).join().map_err(|_| fail("Runtime authority worker failed"))?;
                } else { index += 1; }
            }
            match listener.accept() {
                Ok((stream, _)) if workers.len() < maximum => {
                    let authority = &authority;
                    workers.push(thread::Builder::new().spawn_scoped(scope, move || {
                        let _ = authority.connection(stream);
                    })?);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    })
}
