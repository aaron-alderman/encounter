use crate::{Result, appdev_host_process::Supervisor, command_sources::Sources, compat_value, fail, http,
    mcp_project_socket::peer, nonce, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::{self, Read, Write}, mem::offset_of,
    os::{fd::{AsRawFd, FromRawFd}, unix::{fs::{FileTypeExt, MetadataExt}, net::UnixStream}},
    path::Path, time::{Duration, Instant}};

const LIMIT: usize = 16_384;
const TIMEOUT: &str = "self-hosted-runtime-authority-timeout";
const RESPONSE: &str = "self-hosted-runtime-authority-response";

#[derive(Clone, Copy)]
pub(crate) enum Operation { Readiness, SignGrant, Workload }

impl Operation {
    fn wire(self) -> &'static str {
        match self {
            Self::Readiness => "inspect-readiness",
            Self::SignGrant => "sign-runtime-grant",
            Self::Workload => "authenticate-workload",
        }
    }
}

fn fault(code: &str, message: &str) -> Box<dyn std::error::Error> {
    fail(json!({"code":code,"message":message}).to_string())
}

fn remaining(deadline: Instant) -> Result<Duration> {
    http::check_interruption(false)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() { return Err(fault(TIMEOUT, "Runtime authority timed out.")); }
    Ok(remaining)
}

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("runtime_authority.encounter").to_owned(),
        include_str!("runtime_authority_client.encounter").to_owned()],
        &["authorityClient.request", "authorityClient.response"], &BTreeSet::from([
            "kernel.invoke", "number.isNatural", "number.calculate", "value.describe", "text.matches", "record.put",
        ]), &mut Meter::new(200_000))
}

pub(crate) fn connect(path: &Path, deadline: Instant) -> Result<UnixStream> {
    let root = Path::new("/");
    let parent = path.parent().ok_or_else(|| fail("Expected a runtime authority socket directory"))?;
    let directory = parent.strip_prefix(root)?.to_str().ok_or_else(|| fail("Expected an absolute runtime authority socket path"))?;
    let name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| fail("Expected a runtime authority socket name"))?;
    let sources = Sources::open_physical(root)?.open_directory_relative(directory)?;
    let directory = sources.root()?.metadata()?;
    let observed = sources.observe_relative(name)?;
    let socket = observed.metadata()?;
    if !socket.file_type().is_socket() || socket.uid() != directory.uid() || socket.mode() & 0o007 != 0
        || directory.mode() & 0o022 != 0 {
        return Err(fault("self-hosted-runtime-authority-socket", "Runtime authority requires a protected socket and directory."));
    }

    // Connect to the inode opened above. A rename cannot redirect the request.
    let path = format!("/proc/self/fd/{}", observed.as_raw_fd());
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, byte) in address.sun_path.iter_mut().zip(path.bytes()) {
        *destination = byte as libc::c_char;
    }
    let length = (offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 { return Err(io::Error::last_os_error().into()); }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    let connected = unsafe { libc::connect(fd, (&address as *const libc::sockaddr_un).cast(), length) };
    if connected != 0 {
        let error = io::Error::last_os_error();
        remaining(deadline)?;
        if matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINPROGRESS | libc::ETIMEDOUT)) {
            return Err(fault(TIMEOUT, "Runtime authority timed out."));
        }
        return Err(error.into());
    }
    peer(&stream, socket.uid())?;
    Ok(stream)
}

fn exchange(path: &Path, request: &Value, deadline: Instant) -> Result<Value> {
    let mut wire = serde_json::to_vec(request)?;
    if wire.len() >= LIMIT {
        return Err(fault("self-hosted-runtime-authority-request-large", "Runtime authority request exceeds its byte bound."));
    }
    wire.push(b'\n');
    let mut stream = connect(path, deadline)?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(&wire)?;
    let mut response = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?.min(Duration::from_millis(100))))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) if response.len() + count <= LIMIT => response.extend_from_slice(&chunk[..count]),
            Ok(_) => return Err(fault("self-hosted-runtime-authority-response-large", "Runtime authority response exceeds its byte bound.")),
            Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
            Err(error) => return Err(error.into()),
        }
    }
    remaining(deadline)?;
    let response: Value = serde_json::from_slice(&response)
        .map_err(|_| fault(RESPONSE, "Runtime authority returned malformed JSON."))?;
    compat_value::external(&response).map_err(|_| fault(RESPONSE, "Runtime authority returned invalid response fields."))?;
    Ok(response)
}

pub(crate) fn run(operation: Operation, socket: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    let mut bytes = Vec::new();
    io::stdin().lock().take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(fault("self-hosted-runtime-authority-request-large", "Runtime authority request exceeds its byte bound."));
    }
    let input: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&input)?;
    println!("{}", request(operation, socket, &input["body"], &input["timeoutMs"], None)?);
    Ok(())
}

pub(super) fn probe_readiness(socket: &Path, key_id: &str, startup_deadline: Instant) -> Result<()> {
    request(Operation::Readiness, socket, &json!({"keyId": key_id}), &json!(5_000), Some(startup_deadline))?;
    Ok(())
}

pub(super) fn sign_grant(socket: &Path, key_id: &str, payload: &str) -> Result<Value> {
    request(Operation::SignGrant, socket, &json!({"keyId": key_id, "payload": payload}), &json!(5_000), None)
}

pub(super) fn authenticate_workload(socket: &Path, operation: &str, scope: &Value, consumer: &Value) -> Result<Value> {
    request(Operation::Workload, socket, &json!({
        "grantOperation": operation, "scope": scope, "presentedConsumerId": consumer,
    }), &json!(5_000), None)
}

fn request(operation: Operation, socket: &Path, body: &Value, timeout: &Value, startup_deadline: Option<Instant>) -> Result<Value> {
    let payload_valid = matches!(operation, Operation::SignGrant) && body["payload"].as_str()
        .and_then(|text| Base64UrlUnpadded::decode_vec(text).ok())
        .is_some_and(|payload| (1..=8192).contains(&payload.len()));
    let policy = policy()?;
    let request = policy.run("authorityClient.request", json!({
        "operation": operation.wire(), "requestId": format!("request.{}", nonce::uuid_v4()?),
        "timeoutMs": timeout, "body": body, "payloadValid": payload_valid,
    }), &mut Meter::new(300_000)).map_err(|error| fault("self-hosted-runtime-authority-invalid", &error.to_string()))?;
    let timeout_ms = timeout.as_u64().ok_or_else(|| fail("Expected the admitted runtime authority timeout"))?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let response = exchange(socket, &request, startup_deadline.map_or(deadline, |startup| startup.min(deadline)))?;
    let signature_valid = matches!(operation, Operation::SignGrant) && response["signature"].as_str()
        .and_then(|text| Base64UrlUnpadded::decode_vec(text).ok()).is_some_and(|signature| signature.len() == 64);
    let mut result = policy.run("authorityClient.response", json!({
        "request": request, "response": response, "signatureValid": signature_valid,
    }), &mut Meter::new(300_000))?;
    if let Some(code) = result["error"].as_str() {
        return Err(fault(code, result["message"].as_str().unwrap_or("Runtime authority denied the request.")));
    }
    http::check_interruption(false)?;
    result.as_object_mut().and_then(|result| result.remove("value"))
        .ok_or_else(|| fault(RESPONSE, "Runtime authority returned no verified value."))
}
