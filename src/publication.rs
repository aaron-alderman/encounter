// File delivery for a built publication. Application execution stays with its declared host.
use crate::{Result, browser_release, fail, http, rel::{self, Facts}, websocket};
use std::{collections::BTreeMap, fs::File, io::{self, Read, Write}, net::TcpStream, path::{Component, Path},
    sync::{Arc, atomic::{AtomicUsize, Ordering}}, thread};

fn send(stream: &mut TcpStream, status: &str, kind: &str, length: u64, extra: &str) -> Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: {kind}\r\nContent-Length: {length}\r\n\
        Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
        Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'\r\n{extra}\r\n")?;
    Ok(())
}

fn asset_name(target: &str) -> Option<String> {
    let pathname = target.split('?').next()?;
    let path = http::decode_path(pathname).ok()?;
    let relative = Path::new(path.strip_prefix('/')?);
    if path.contains('\\') || path.chars().any(char::is_control)
        || !relative.components().all(|component| matches!(component, Component::Normal(_))) {
        return None;
    }
    Some(if path == "/" { "index.html".to_owned() } else { path[1..].to_owned() })
}

fn asset(root: &Path, target: &str) -> Option<std::path::PathBuf> {
    let name = asset_name(target)?;
    crate::package::check_path(Path::new(&name)).ok()?;
    let path = root.join(name).canonicalize().ok()?;
    crate::package::check_path(&path).ok()?;
    (path.starts_with(root) && path.is_file()).then_some(path)
}

pub fn serve(root: &Path, port: u16) -> Result<()> {
    let root = root.canonicalize()?;
    crate::package::check(&root)?;
    if asset(&root, "/").is_none() { return Err(fail("expected publication index.html")); }
    http::serve_gateway(port, |origin, stream, request| {
        let authority = origin.trim_start_matches("http://");
        let local = authority.replacen("127.0.0.1:", "localhost:", 1);
        let host = request.headers.get("host").map(String::as_str);
        if host != Some(authority) && host != Some(&local) {
            return send(stream, "421 Misdirected Request", "text/plain", 0, "");
        }
        respond(&root, stream, &request, "")
    })
}

pub fn serve_pinned(root: &Path, manifest: &Path, pin: &str, port: u16) -> Result<()> {
    let root = root.canonicalize()?;
    crate::package::check(&root)?;
    let mut receipt = Vec::new();
    File::open(manifest)?.take(256_001).read_to_end(&mut receipt)?;
    if receipt.len() > 256_000 || rel::hash(&receipt) != pin {
        return Err(fail("publication manifest exceeds its limit or differs from its pin"));
    }
    let facts = Facts::parse(std::str::from_utf8(&receipt)?)?;
    let projected = match facts.one("publication", "version")? {
        "encounter/pinned-publication/1" => false,
        "encounter/pinned-publication/2" => true,
        _ => return Err(fail("unsupported pinned publication contract")),
    };
    let socket_asset = match facts.values("publication", "socketAsset").as_slice() {
        [] if projected => None,
        [name] => Some((*name).to_owned()),
        _ => return Err(fail("expected one publication socket asset")),
    };
    let mut assets = BTreeMap::new();
    let mut remaining = 160_000_000_u64;
    for [subject, name, digest] in &facts.0 {
        if subject == "publication" && matches!(name.as_str(), "version" | "socketAsset") { continue; }
        if projected && matches!(subject.as_str(), "projection" | "projectionSha256") { continue; }
        if subject != "artifact" || assets.contains_key(name) {
            return Err(fail("invalid or duplicate pinned publication artifact"));
        }
        let bytes = browser_release::artifact(&root, name, remaining.min(96_000_000))?;
        if rel::hash(&bytes) != *digest {
            return Err(fail(format!("publication artifact hash differs from manifest: {name}")));
        }
        remaining -= bytes.len() as u64;
        assets.insert(name.clone(), bytes);
    }
    if projected {
        for [subject, route, source] in &facts.0 {
            if subject != "projection" { continue; }
            if !route.ends_with(".json") || asset_name(&format!("/{route}")).as_ref() != Some(route)
                || route.contains('?') || route.contains('%') || !source.ends_with(".rel.gz")
                || assets.contains_key(route) {
                return Err(fail("invalid or duplicate publication data projection"));
            }
            let encoded = assets.remove(source).ok_or_else(|| fail("missing pinned projection REL"))?;
            let bytes = crate::publication_data::project(&encoded)?;
            if bytes.len() as u64 > remaining || rel::hash(&bytes) != facts.one("projectionSha256", route)? {
                return Err(fail(format!("publication projection differs from its pin: {route}")));
            }
            remaining -= bytes.len() as u64;
            assets.insert(route.clone(), bytes);
        }
        for [subject, route, _] in &facts.0 {
            if subject == "projectionSha256" && !assets.contains_key(route) {
                return Err(fail("unbound publication projection pin"));
            }
        }
    }
    if let Some(name) = &socket_asset {
        let snapshot = assets.get(name).filter(|bytes| bytes.len() <= 2_000_000)
            .ok_or_else(|| fail("expected a bounded pinned publication socket asset"))?;
        std::str::from_utf8(snapshot)?;
    }
    if !assets.contains_key("index.html") { return Err(fail("missing pinned publication index.html")); }
    let assets = Arc::new(assets);
    let active = Arc::new(AtomicUsize::new(0));
    http::serve_gateway(port, |origin, stream, request| {
        let authority = origin.trim_start_matches("http://");
        let host = request.headers.get("host").map(String::as_str);
        let local = authority.replacen("127.0.0.1:", "localhost:", 1);
        if host != Some(authority) && !(projected && host == Some(&local)) {
            return send(stream, "421 Misdirected Request", "text/plain", 0, "");
        }
        if request.path == "/_encounter/browser" && let Some(name) = &socket_asset {
            if !request.body.is_empty() || request.headers.get("origin").map(String::as_str) != Some(origin) {
                return send(stream, "403 Forbidden", "text/plain", 0, "");
            }
            websocket::handshake(stream, &request)?;
            websocket::frame(stream, 1, &assets[name])?;
            return websocket::frame(stream, 8, &1000_u16.to_be_bytes());
        }
        if socket_asset.as_deref().is_some_and(|name| asset_name(&request.path).as_deref() == Some(name)) {
            return send(stream, "404 Not Found", "text/plain", 0, "");
        }
        if active.load(Ordering::Relaxed) >= 16 {
            return send(stream, "503 Service Unavailable", "text/plain", 0, "");
        }
        let mut socket = stream.try_clone()?;
        let assets = assets.clone();
        let in_flight = active.clone();
        active.fetch_add(1, Ordering::Relaxed);
        let worker = thread::Builder::new().name("encounter-publication-read".to_owned()).spawn(move || {
            let mut request = request;
            if let Some(path) = request.path.split('?').next().filter(|path| *path != "/" && path.ends_with('/')) {
                request.path = format!("{path}index.html");
            }
            let _ = respond_verified(&assets, &mut socket, &request, "");
            in_flight.fetch_sub(1, Ordering::Relaxed);
        });
        if worker.is_err() {
            active.fetch_sub(1, Ordering::Relaxed);
            return send(stream, "503 Service Unavailable", "text/plain", 0, "");
        }
        Ok(())
    })
}

pub fn respond(root: &Path, stream: &mut TcpStream, request: &http::Request, headers: &str) -> Result<()> {
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        return send(stream, "405 Method Not Allowed", "text/plain", 0, "Allow: GET, HEAD\r\n");
    }
    let Some(path) = asset(root, &request.path) else {
        return send(stream, "404 Not Found", "text/plain", 0, "");
    };
    let mut file = File::open(&path)?;
    send(stream, "200 OK", kind(&path), file.metadata()?.len(), headers)?;
    if request.method == "GET" { io::copy(&mut file, stream)?; }
    Ok(())
}

fn kind(path: &Path) -> &'static str {
    match path.extension().and_then(|suffix| suffix.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

pub fn respond_verified(
    assets: &std::collections::BTreeMap<String, Vec<u8>>,
    stream: &mut TcpStream, request: &http::Request, headers: &str,
) -> Result<()> {
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        return send(stream, "405 Method Not Allowed", "text/plain", 0, "Allow: GET, HEAD\r\n");
    }
    let Some(name) = asset_name(&request.path) else {
        return send(stream, "404 Not Found", "text/plain", 0, "");
    };
    let Some(bytes) = assets.get(&name) else {
        return send(stream, "404 Not Found", "text/plain", 0, "");
    };
    send(stream, "200 OK", kind(Path::new(&name)), bytes.len() as u64, headers)?;
    if request.method == "GET" { stream.write_all(bytes)?; }
    Ok(())
}
