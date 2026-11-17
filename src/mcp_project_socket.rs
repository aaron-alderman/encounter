use crate::{Result, fail, http, image, mcp_client_socket, mcp_project_context::Tool, mcp_workspace_access::BrowserLookup, rel, runtime_authority::Socket};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs, io::{self, Read, Write}, net::Shutdown,
    os::{fd::AsRawFd, unix::{fs::{FileTypeExt, MetadataExt}, net::UnixStream}},
    path::{Path, PathBuf}, thread, time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PROTOCOL: &str = "encounter/hosted-mcp-project/1";
const REQUEST_LIMIT: usize = 80 * 1024;
const REPLY_LIMIT: usize = 1024 * 1024;

fn release(schema: &str, policy: &str) -> Result<String> {
    Ok(rel::hash(format!("{}:{schema}:{policy}", image::runtime_pin()?)))
}

pub(crate) fn peer(stream: &UnixStream, uid: u32) -> Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    let status = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
        (&mut credentials as *mut libc::ucred).cast(), &mut length) };
    if status != 0 || length as usize != std::mem::size_of_val(&credentials) || credentials.uid != uid {
        return Err(fail("Hosted project socket peer identity differs from its configured owner"));
    }
    Ok(())
}

pub(crate) fn receive(stream: &mut UnixStream, limit: usize, timeout: Duration) -> Result<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + timeout;
    let mut frame = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0; 4096]);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if http::stopping() || remaining.is_zero() { return Err(fail("Hosted project socket read interrupted or timed out")); }
        stream.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
        match stream.read(&mut *buffer) {
            Ok(0) if !frame.is_empty() => return Ok(frame),
            Ok(0) => return Err(fail("Empty hosted project socket frame")),
            Ok(count) => {
                if frame.len() + count > limit { return Err(fail("Hosted project socket frame exceeds its size limit")); }
                frame.extend_from_slice(&buffer[..count]);
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn send(stream: &mut UnixStream, frame: Value, limit: usize) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(&frame)?);
    if bytes.len() > limit { return Err(fail("Hosted project socket frame exceeds its size limit")); }
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    stream.write_all(&bytes)?;
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

pub(crate) fn socket_parent(path: &Path, uid: u32) -> Result<()> {
    let parent = path.parent().filter(|_| path.is_absolute())
        .ok_or_else(|| fail("Expected an absolute hosted project socket path"))?;
    let metadata = fs::metadata(parent)?;
    if parent.canonicalize()? != parent || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(fail("Expected a protected hosted project socket directory"));
    }
    Ok(())
}

pub(crate) fn connect(path: &Path, uid: u32) -> Result<UnixStream> {
    let metadata = path.symlink_metadata()?;
    if !metadata.file_type().is_socket() || metadata.uid() != uid || metadata.mode() & 0o007 != 0 {
        return Err(fail("Hosted project socket is outside its configured authority"));
    }
    let stream = UnixStream::connect(path)?;
    peer(&stream, uid)?;
    Ok(stream)
}

pub(crate) struct Client {
    path: PathBuf,
    uid: u32,
    release: String,
}

impl Client {
    pub(crate) fn load(path: &Path, uid: u32, schema: &str, policy: &str) -> Result<Self> {
        socket_parent(path, uid)?;
        let client = Self { path:path.to_owned(), uid, release:release(schema, policy)? };
        let ready = client.exchange(json!({"operation":"ready"}))?;
        if ready["ready"] != true { return Err(fail("Matched hosted project authority is unavailable")); }
        Ok(client)
    }

    fn exchange(&self, request: Value) -> Result<Value> {
        self.exchange_with_timeout(request, Duration::from_secs(8))
    }

    fn exchange_with_timeout(&self, request: Value, timeout: Duration) -> Result<Value> {
        let mut stream = connect(&self.path, self.uid)?;
        send(&mut stream, json!({"protocol":PROTOCOL,"release":self.release,"request":request}), REQUEST_LIMIT)?;
        let mut result: Value = serde_json::from_slice(&receive(&mut stream, REPLY_LIMIT, timeout)?)?;
        if result["protocol"] != PROTOCOL || result["release"] != self.release {
            return Err(fail("Hosted project socket did not use the matched release"));
        }
        Ok(result["response"].take())
    }

    pub(crate) fn authorize_browser(&self, cookie: &str, href: &str) -> Result<Value> {
        self.exchange_with_timeout(json!({"operation":"authorize-browser","cookie":cookie,"href":href}), Duration::from_secs(15))
    }

    pub(crate) fn call(&self, bearer: &str, message: Value, headers: Value) -> Result<Value> {
        self.exchange(json!({"operation":"mcp","bearer":bearer,"message":message,"headers":headers}))
    }

    pub(crate) fn browser_form(&self, cookie: &str, form: Value, consent: bool) -> Result<Value> {
        let operation = if consent { "commit-browser-consent" } else { "select-browser-portfolio" };
        self.exchange(json!({"operation":operation,"cookie":cookie,"form":form}))
    }

    pub(crate) fn exchange_oauth(&self, mut plan: Value) -> Result<Value> {
        let Value::String(verifier) = plan.as_object_mut().and_then(|fields| fields.shift_remove("verifier")).unwrap_or_default()
            else { return Err(fail("Missing public OAuth verifier field")); };
        let verifier = Zeroizing::new(verifier);
        plan["proof"] = json!(if verifier.is_empty() { String::new() } else {
            rel::hash(Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes())))
        });
        self.exchange(json!({"operation":"oauth-exchange","plan":plan}))
    }

    pub(crate) fn revoke_oauth(&self, digest: &str) -> Result<()> {
        if self.exchange(json!({"operation":"oauth-revoke","digest":digest}))?["revoked"] != true {
            return Err(fail("Missing public OAuth revocation receipt"));
        }
        Ok(())
    }
}

fn connection(mut stream: UnixStream, uid: u32, release: &str, tool: &Tool, resolver: &mcp_client_socket::Client) -> Result<()> {
    peer(&stream, uid)?;
    let mut frame: Value = serde_json::from_slice(&receive(&mut stream, REQUEST_LIMIT, Duration::from_secs(1))?)
        .map_err(|_| fail("Invalid hosted project socket frame"))?;
    if frame["protocol"] != PROTOCOL || frame["release"] != release {
        return Err(fail("Hosted project socket request uses a different release"));
    }
    let mut request = frame["request"].take();
    let response = match request["operation"].as_str() {
        Some("ready") => json!({"ready":true}),
        Some("authorize-browser") => {
            let Value::String(cookie) = request["cookie"].take() else { return Err(fail("Missing hosted browser cookie header")); };
            let href = request["href"].as_str().ok_or_else(|| fail("Missing hosted browser authorization request"))?;
            tool.authorize_browser(&Zeroizing::new(cookie), href, resolver)?
        }
        Some("select-browser-portfolio") => {
            let Value::String(cookie) = request["cookie"].take() else {
                return Err(fail("Missing hosted browser cookie header"));
            };
            tool.select_browser_portfolio(&Zeroizing::new(cookie), request["form"].take())?
        }
        Some("commit-browser-consent") => {
            let Value::String(cookie) = request["cookie"].take() else {
                return Err(fail("Missing hosted browser cookie header"));
            };
            tool.commit_browser_consent(&Zeroizing::new(cookie), request["form"].take())?
        }
        Some(operation @ ("browser-session" | "browser-portfolios")) => {
            let session_only = operation == "browser-session";
            let Value::String(cookie) = request["cookie"].take() else {
                return Err(fail("Missing hosted browser cookie header"));
            };
            let cookie = Zeroizing::new(cookie);
            if session_only {
                json!({"subject":tool.browser_lookup(&cookie, BrowserLookup::Session)?})
            } else {
                let result = tool.browser_lookup(&cookie, BrowserLookup::Portfolio)?;
                if result.is_null() { json!({"subject":null,"portfolios":[]}) } else { result }
            }
        }
        Some("oauth-exchange") => tool.exchange_oauth(&request["plan"])?,
        Some("oauth-revoke") => {
            let digest = request["digest"].as_str().ok_or_else(|| fail("Missing public OAuth revocation digest"))?;
            tool.revoke_oauth(digest)?;
            json!({"revoked":true})
        }
        Some("mcp") => {
            let Value::String(token) = request["bearer"].take() else { return Err(fail("Missing hosted project bearer")); };
            let token = Zeroizing::new(token);
            let message = request["message"].take();
            crate::compat_value::external(&message)?;
            tool.http_call(&token, message, &request["headers"])?
        }
        _ => return Err(fail("Unsupported hosted project socket operation")),
    };
    if http::stopping() { return Ok(()); }
    send(&mut stream, json!({"protocol":PROTOCOL,"release":release,"response":response}), REPLY_LIMIT)
}

pub(crate) fn serve(args: &[String]) -> Result<()> {
    let [path, uid, key, consent_key, commit_key, configuration @ .., client_socket, client_uid, clients_pin, hosts_pin] = args else {
        return Err(fail("Expected hosted project socket, gateway UID, project and consent keys, database and client resolver configuration"));
    };
    let uid = uid.parse()?;
    http::install_stop_signals()?;
    let tool = Tool::load(Path::new(key), configuration)?.with_consent_keys(Path::new(consent_key), Path::new(commit_key))?;
    tool.ready()?;
    let runtime = image::runtime_pin()?;
    let resolver = mcp_client_socket::Client::load_with_runtime(Path::new(client_socket), client_uid.parse()?,
        &[clients_pin, hosts_pin, &configuration[5], &configuration[7]], &runtime)?;
    let release = rel::hash(format!("{runtime}:{}:{}", configuration[5], configuration[7]));
    let (_socket, listener) = Socket::bind(path.into(), 0o660)?;
    println!("Encounter hosted MCP project authority ready");
    while !http::stopping() {
        match listener.accept() {
            Ok((stream, _)) => { let _ = connection(stream, uid, &release, &tool, &resolver); }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
