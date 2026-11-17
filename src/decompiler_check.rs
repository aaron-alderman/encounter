use crate::{Result, appdev_host_process::Supervisor, command::Evaluator, fail, http, rel::Facts};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};
use subtle::ConstantTimeEq;

const WORKFLOW: &str = "release/workflow.rel";
const CONFIG_LIMIT: u64 = 128_000;
const BODY_LIMIT: u64 = 2 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(8);

fn credential(path: &Path) -> Result<String> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() > CONFIG_LIMIT {
        return Err(fail("Expected a private Decompiler gateway configuration"));
    }
    let mut text = String::new();
    file.take(CONFIG_LIMIT + 1).read_to_string(&mut text)?;
    if text.len() as u64 > CONFIG_LIMIT {
        return Err(fail("Decompiler gateway configuration exceeded its size limit"));
    }
    let facts = Facts::parse(&text).map_err(|_| fail("Invalid Decompiler gateway REL configuration"))?;
    let authorization = facts.one("decompiler", "authorization")
        .map_err(|_| fail("Expected exactly one Decompiler mount credential"))?;
    if !authorization.strip_prefix("Basic ").is_some_and(|value| !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))) {
        return Err(fail("Invalid Decompiler mount credential"));
    }
    Ok(authorization.to_owned())
}

fn request(port: u16, authorization: &str) -> Result<(u16, String)> {
    let request = format!("GET /decompiler HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n");
    let mut response = http::LoopbackReply::open(port, request.as_bytes(), TIMEOUT)?;
    let (start, headers) = http::read_head(&mut response)?;
    let mut status = start.splitn(3, ' ');
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(fail("Invalid Decompiler response version"));
    }
    let status = status.next().and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| fail("Invalid Decompiler response status"))?;
    if status != 200 { return Ok((status, String::new())); }
    if headers.contains_key("transfer-encoding") {
        return Err(fail("Unsupported Decompiler response framing"));
    }
    let length = headers.get("content-length").map(|value| value.parse::<u64>()).transpose()?;
    if length.is_some_and(|length| length > BODY_LIMIT) {
        return Err(fail("Decompiler response exceeded its size limit"));
    }
    let mut body = Vec::new();
    response.take(length.unwrap_or(BODY_LIMIT + 1)).read_to_end(&mut body)?;
    if body.len() as u64 > BODY_LIMIT || length.is_some_and(|length| length != body.len() as u64) {
        return Err(fail("Incomplete or oversized Decompiler response"));
    }
    Ok((status, String::from_utf8(body)?))
}

fn port(value: &str) -> Result<u16> {
    let port = value.parse::<u16>()?;
    if port < 1024 { return Err(fail("Expected an unprivileged Decompiler loopback port")); }
    Ok(port)
}

pub(crate) fn admit(workflow: &Evaluator, entry: &str, evidence: Value) -> Result<()> {
    if workflow.run(entry, evidence)? != true {
        return Err(fail("Encounter did not admit the Decompiler observation"));
    }
    Ok(())
}

fn active_credential(workflow: &Evaluator, config: &Path, revoked_pin: &str) -> Result<String> {
    let authorization = credential(config)?;
    let digest = hex::encode(Sha256::digest(authorization.as_bytes()));
    let revoked = bool::from(digest.as_bytes().ct_eq(revoked_pin.as_bytes()));
    admit(workflow, "decompiler.mountPin", json!({"revokedPin":revoked_pin,"revoked":revoked}))?;
    Ok(authorization)
}

fn mount_page(workflow: &Evaluator, port: u16, authorization: &str) -> Result<String> {
    let (status, body) = request(port, authorization)?;
    admit(workflow, "decompiler.mountPage", json!({"status":status,"body":body}))?;
    Ok(body)
}

fn mount(workflow: &Evaluator, port: u16, config: &Path, revoked_pin: &str) -> Result<()> {
    let authorization = active_credential(workflow, config, revoked_pin)?;
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| fail("Decompiler check entropy unavailable"))?;
    let rejected = format!("Basic {}", Base64::encode_string(format!("mount:{}", hex::encode(nonce)).as_bytes()));
    let (status, _) = request(port, &rejected)?;
    admit(workflow, "decompiler.mountDenied", json!({"status":status}))?;
    mount_page(workflow, port, &authorization)?;
    println!("PASS: the revoked mount fingerprint is inactive, invalid authorization is rejected, and the active mount works.");
    Ok(())
}

fn mount_plan(workflow: &Evaluator) -> Result<(u16, std::path::PathBuf, String)> {
    let plan = workflow.run("decompiler.mountPlan", Value::Null)?;
    let [Some(listener), Some(config), Some(pin)] = ["port", "config", "revokedPin"].map(|field| plan[field].as_str()) else {
        return Err(fail("Invalid Decompiler mount check plan"));
    };
    Ok((port(listener)?, config.into(), pin.into()))
}

pub fn release_mount(workflow: &Evaluator) -> Result<()> {
    let (port, config, pin) = mount_plan(workflow)?;
    mount(workflow, port, &config, &pin)
}

pub fn mount_document(app: &Path) -> Result<()> {
    let _supervisor = Supervisor::new();
    let workflow = Evaluator::load(&app.canonicalize()?, WORKFLOW)?;
    let (port, config, pin) = mount_plan(&workflow)?;
    let authorization = active_credential(&workflow, &config, &pin)?;
    let document = mount_page(&workflow, port, &authorization)?;
    io::stdout().lock().write_all(document.as_bytes())?;
    Ok(())
}

pub fn check_mount(app: &Path, listener: &str, config: &Path, pin: &str) -> Result<()> {
    let _supervisor = Supervisor::new();
    mount(&Evaluator::load(&app.canonicalize()?, WORKFLOW)?, port(listener)?, config, pin)
}

pub fn release_paging(app: &Path, workflow: &Evaluator) -> Result<()> {
    let plan = workflow.run("decompiler.pagingPlan", Value::Null)?;
    let listener = plan["port"].as_str().ok_or_else(|| fail("Expected a Decompiler paging port"))?;
    crate::browser_check::decompiler_paging(app, workflow, &plan, port(listener)?)
}

pub fn check_paging(app: &Path, listener: &str) -> Result<()> {
    let _supervisor = Supervisor::new();
    let app = app.canonicalize()?;
    let workflow = Evaluator::load(&app, WORKFLOW)?;
    let plan = workflow.run("decompiler.pagingPlan", Value::Null)?;
    crate::browser_check::decompiler_paging(&app, &workflow, &plan, port(listener)?)
}
