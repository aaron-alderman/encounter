use crate::{Result, browser_release, command::Evaluator, evaluation_replay, fail, http, rel};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use std::{
    cell::OnceCell,
    collections::BTreeMap,
    io::Write,
    net::TcpStream,
    path::Path,
    sync::{Mutex, TryLockError},
};

const DOCUMENT_POLICY: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; ";
const MAX_PUBLICATION: u64 = 160_000_000;
const MAX_ASSET: u64 = 32_000_000;
const MAX_INDEX: u64 = 1_000_000;

thread_local! {
    static EVALUATOR: OnceCell<Evaluator> = const { OnceCell::new() };
}

struct Publication {
    assets: BTreeMap<String, Vec<u8>>,
    cases: Value,
    replay: Mutex<()>,
}

impl Publication {
    fn open(root: &Path, specification: Value) -> Result<Self> {
        let index = browser_release::artifact(root, "publication.rel", MAX_INDEX)?;
        if specification["index"] != rel::hash(&index) {
            return Err(fail("Evaluation publication index differs from its reviewed pin"));
        }
        let facts = rel::Facts::parse(std::str::from_utf8(&index)?)?;
        if facts.one("publication", "version")? != "encounter/evaluation-publication/1" {
            return Err(fail("Unsupported evaluation publication"));
        }
        let mut assets = BTreeMap::new();
        let mut remaining = MAX_PUBLICATION;
        let directory = root.join("assets").canonicalize()?;
        for [subject, name, pin] in facts.0 {
            if subject == "publication" && name == "version" { continue; }
            if subject != "asset" || assets.contains_key(&name) {
                return Err(fail("Unexpected evaluation publication index fact"));
            }
            let bytes = browser_release::artifact(&directory, &name, remaining.min(MAX_ASSET))?;
            if rel::hash(&bytes) != pin {
                return Err(fail(format!("Evaluation asset {name} differs from its reviewed pin")));
            }
            remaining -= bytes.len() as u64;
            assets.insert(name, bytes);
        }
        let cases = specification["cases"].as_object().ok_or_else(|| fail("Expected evaluation case pins"))?;
        for (case, pin) in cases {
            let name = format!("case/{case}/manifest.rel");
            if assets.get(&name).is_none_or(|bytes| *pin != rel::hash(bytes)) {
                return Err(fail(format!("Evaluation case {case} differs from its reviewed manifest")));
            }
        }
        if assets.get("identity.rel").is_none_or(|bytes| specification["identity"] != rel::hash(bytes)) {
            return Err(fail("Identity evidence differs from its reviewed pin"));
        }
        Ok(Self { assets, cases: specification["cases"].clone(), replay: Mutex::new(()) })
    }

    fn replay(&self, app: &Evaluator, case: &str, manifest: &str) -> Result<String> {
        let mut report = evaluation_replay::verify(app, manifest, |name| {
            self.assets.get(&format!("case/{case}/{name}")).map(Vec::as_slice)
                .ok_or_else(|| fail("Expected pinned replay artifact"))
        })?;
        report["caseId"] = json!(case);
        app.run("decompiler.verification", report)?.as_str().map(str::to_owned)
            .ok_or_else(|| fail("Expected an Encounter verification page"))
    }

    fn handle(&self, root: &Path, stream: &mut TcpStream, request: http::Request) -> Result<()> {
        EVALUATOR.with(|slot| {
            if slot.get().is_none() {
                let _ = slot.set(Evaluator::load(root, "native.rel")?);
            }
            let app = slot.get().expect("initialized evaluation programme");
            let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
            let mut parameters = Map::new();
            let query = query.split('?').next().unwrap_or("");
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                if matches!(key.as_ref(), "case" | "download" | "phase" | "site" | "differences" | "pin" | "platform" | "action") {
                    parameters.entry(key.into_owned()).or_insert_with(|| json!(value));
                }
            }
            let route = app.run("evaluation.route", json!({
                "path": path, "method": request.method, "parameters": parameters, "cases": self.cases,
                "host": request.headers.get("host").map_or("", String::as_str),
                "origin": request.headers.get("origin").map_or("", String::as_str)
            }))?;
            let head = request.method == "HEAD";
            if let Some(case) = route["replay"].as_str() {
                let _guard = match self.replay.try_lock() {
                    Ok(guard) => guard,
                    Err(TryLockError::WouldBlock) => return send(stream,
                        &json!({"status":409}), false, b"Offline replay is already running."),
                    Err(error) => return Err(fail(error.to_string())),
                };
                let manifest = route["manifest"].as_str().ok_or_else(|| fail("Expected a reviewed replay pin"))?;
                match self.replay(app, case, manifest) {
                    Ok(page) => return send(stream, &route, false, page.as_bytes()),
                    Err(error) => {
                        eprintln!("Offline evaluation replay: {error}");
                        return send(stream, &json!({"status":500}), false, b"Offline replay could not be verified.");
                    }
                }
            }
            if let Some(asset) = route["asset"].as_str() {
                return match self.assets.get(asset) {
                    Some(bytes) => send(stream, &route, head, bytes),
                    None => send(stream, &json!({"status":404}), head, b""),
                };
            }
            if let Some(message) = route["message"].as_str() {
                return send(stream, &route, head, &serde_json::to_vec(&json!({"message":message}))?);
            }
            send(stream, &route, head, route["body"].as_str().unwrap_or("").as_bytes())
        })
    }
}

fn send(stream: &mut TcpStream, route: &Value, head: bool, body: &[u8]) -> Result<()> {
    let status = match route["status"].as_u64() {
        Some(200) => "200 OK",
        Some(400) => "400 Bad Request",
        Some(403) => "403 Forbidden",
        Some(404) => "404 Not Found",
        Some(405) => "405 Method Not Allowed",
        Some(409) => "409 Conflict",
        Some(500) => "500 Internal Server Error",
        Some(503) => "503 Service Unavailable",
        _ => return Err(fail("Invalid evaluation response status")),
    };
    let mut policy = DOCUMENT_POLICY.to_owned();
    if route["desk"] == true {
        policy.push_str("script-src 'self'; connect-src 'self'; ");
    }
    policy.push_str("frame-ancestors ");
    policy.push_str(if route["desk"] == true && route["platform"] == true {
        "https://appdev.sourcerytech.com.au"
    } else { "'none'" });
    write!(stream, "HTTP/1.1 {status}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {policy}\r\n")?;
    for (key, header) in [("type", "Content-Type"), ("allow", "Allow")] {
        if let Some(value) = route[key].as_str() { write!(stream, "{header}: {value}\r\n")?; }
    }
    if let Some(filename) = route["filename"].as_str() {
        write!(stream, "Content-Disposition: attachment; filename=\"{filename}\"\r\n")?;
    }
    if route["omitLength"] != true { write!(stream, "Content-Length: {}\r\n", body.len())?; }
    stream.write_all(b"\r\n")?;
    if !head { stream.write_all(body)?; }
    Ok(())
}

pub fn serve(root: &Path, port: u16, mount_pin: Option<&str>) -> Result<()> {
    let mount_pin = mount_pin.map(|pin| -> Result<[u8; 32]> {
        let mut digest = [0; 32];
        hex::decode_to_slice(pin, &mut digest).map_err(|_| fail("Invalid evaluation mount pin"))?;
        Ok(digest)
    }).transpose()?;
    if port < 1024 { return Err(fail("Expected an unprivileged evaluation port")); }
    let root = root.canonicalize()?;
    crate::package::check(&root)?;
    let app = Evaluator::load(&root, "native.rel")?;
    let publication = Publication::open(&root, app.run("evaluation.publication", Value::Null)?)?;
    http::serve_workers(port, 8, 16_384, move |stream, request| {
        let head = request.method == "HEAD";
        // The local Life Board bridge sends no authorization. A hosted gateway
        // request supplies Basic authorization, which must match the active pin.
        if let (Some(pin), Some(authorization)) = (&mount_pin, request.headers.get("authorization")) {
            let digest = Sha256::digest(authorization.as_bytes());
            if !bool::from(pin.as_slice().ct_eq(&digest)) {
                let _ = send(stream, &json!({"status":403}), head, b"Invalid mount authorization.");
                return;
            }
        }
        if let Err(error) = publication.handle(&root, stream, request) {
            if error.downcast_ref::<std::io::Error>().is_none() {
                eprintln!("Evaluation listener: {error}");
                let _ = send(stream, &json!({"status":500}), head, b"");
            }
        }
    })
}
