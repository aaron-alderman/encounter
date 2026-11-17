// Host adapter for a loopback service directory and its registered previews.
use crate::{Result, application::Application, fail, http, process::Meter};
use crate::http::{copy_exact, single_header as single};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io::{self, BufReader, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::Path,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    thread,
    time::Duration,
};

type Headers = [(String, String)];
const CONNECT: Duration = Duration::from_millis(800);
const TRANSFER: Duration = Duration::from_secs(120);

fn connection(headers: &Headers) -> BTreeSet<String> {
    headers.iter().filter(|(name, _)| name == "connection")
        .flat_map(|(_, value)| value.split(',')).map(|value| value.trim().to_ascii_lowercase()).collect()
}

fn hop(name: &str, connection: &BTreeSet<String>) -> bool {
    connection.contains(name) || matches!(name, "connection" | "keep-alive" | "proxy-authenticate"
        | "proxy-authorization" | "proxy-connection" | "te" | "trailer" | "transfer-encoding" | "upgrade")
}

fn translate<'a>(value: &'a str, from: &str, to: &str) -> std::borrow::Cow<'a, str> {
    if let Some(suffix) = value.strip_prefix(from)
        && (suffix.is_empty() || suffix.starts_with(['/', '?', '#'])) {
        return format!("{to}{suffix}").into();
    }
    value.into()
}

fn scoped_cookie(value: &str) -> Option<String> {
    let mut fields = value.split(';');
    let mut cookie = fields.next()?.to_owned();
    for field in fields {
        if let Some((key, domain)) = field.split_once('=') && key.trim().eq_ignore_ascii_case("domain") {
            if domain.trim().trim_start_matches('.') != "127.0.0.1" { return None; }
        } else {
            cookie.push(';');
            cookie.push_str(field);
        }
    }
    Some(cookie)
}

enum Body { Empty, Sized(u64), Chunked }

fn request_body(headers: &Headers) -> Result<Body> {
    match (single(headers, "content-length")?, single(headers, "transfer-encoding")?) {
        (None, None) => Ok(Body::Empty),
        (Some(length), None) if !length.is_empty() && length.bytes().all(|b| b.is_ascii_digit()) =>
            Ok(Body::Sized(length.parse()?)),
        (None, Some(value)) if value.eq_ignore_ascii_case("chunked") => Ok(Body::Chunked),
        _ => Err(fail("invalid request framing")),
    }
}

fn send(client: &mut TcpStream, head: bool, status: &str, content_type: &str, headers: &str, body: &[u8]) -> Result<()> {
    write!(client, "HTTP/1.1 {status}\r\nConnection: close\r\n")?;
    if !content_type.is_empty() { write!(client, "Content-Type: {content_type}\r\n")?; }
    write!(client, "Content-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'\r\n{headers}\r\n", body.len())?;
    if !head { client.write_all(body)?; }
    Ok(())
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    authority: &'a str,
    headers: &'a Headers,
    credential_free_alias: bool,
}

fn proxy(client: &mut BufReader<TcpStream>, request: Request, port: u16) -> Result<()> {
    let Request { method, path, authority, headers, credential_free_alias } = request;
    let browser = format!("http://{authority}");
    let host = format!("127.0.0.1:{port}");
    let origin = format!("http://{host}");
    let head = method == "HEAD";
    let supplied_origin = single(headers, "origin")?;
    let fetch_site = single(headers, "sec-fetch-site")?;
    if supplied_origin.is_some_and(|value| !value.is_empty() && value != browser)
        || (!matches!(method, "GET" | "HEAD") && fetch_site.is_some_and(|value| !matches!(value, "" | "same-origin" | "none"))) {
        return send(client.get_mut(), head, "403 Forbidden", "text/plain", "", b"This app only accepts requests from its own Front Gate address.");
    }
    let body = match request_body(headers) {
        Ok(body) => body,
        Err(_) => return send(client.get_mut(), head, "400 Bad Request", "text/plain", "", b"Invalid request framing."),
    };
    let expect = single(headers, "expect")?;
    if expect.is_some_and(|value| !value.eq_ignore_ascii_case("100-continue")) {
        return send(client.get_mut(), head, "417 Expectation Failed", "text/plain", "", b"Unsupported request expectation.");
    }
    let Ok(mut upstream) = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), CONNECT) else {
        return unavailable(client.get_mut(), head);
    };
    upstream.set_read_timeout(Some(TRANSFER))?;
    upstream.set_write_timeout(Some(TRANSFER))?;
    client.get_mut().set_read_timeout(Some(TRANSFER))?;
    client.get_mut().set_write_timeout(Some(TRANSFER))?;
    let request_connection = connection(headers);
    write!(upstream, "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n")?;
    for (name, value) in headers {
        if hop(name, &request_connection) || matches!(name.as_str(), "host" | "content-length" | "forwarded" | "expect") || name.starts_with("x-forwarded-") { continue; }
        if credential_free_alias && matches!(name.as_str(), "cookie" | "authorization") { continue; }
        let value = if name == "origin" && value == &browser { origin.as_str().into() }
            else if name == "referer" { translate(value, &browser, &origin) }
            else { value.as_str().into() };
        write!(upstream, "{name}: {value}\r\n")?;
    }
    match body {
        Body::Sized(length) => write!(upstream, "Content-Length: {length}\r\n")?,
        Body::Chunked => write!(upstream, "Transfer-Encoding: chunked\r\n")?,
        Body::Empty => {}
    }
    write!(upstream, "\r\n")?;
    if expect.is_some() {
        client.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    match body {
        Body::Sized(length) => copy_exact(client, &mut upstream, length)?,
        Body::Chunked => http::copy_chunked(client, &mut upstream, u64::MAX, true)?,
        Body::Empty => {}
    }

    let mut upstream = BufReader::new(upstream);
    let Ok((status, headers)) = http::read_header_lines(&mut upstream) else {
        return unavailable(client.get_mut(), head);
    };
    let code = status.split_ascii_whitespace().nth(1).and_then(|code| code.parse::<u16>().ok());
    let Some(code @ 200..=599) = code.filter(|_| status.starts_with("HTTP/1.") && !status.bytes().any(|b| b.is_ascii_control())) else {
        return unavailable(client.get_mut(), head);
    };
    let response_connection = connection(&headers);
    let transfer = single(&headers, "transfer-encoding")?;
    let length = single(&headers, "content-length")?;
    if transfer.is_some_and(|value| !value.eq_ignore_ascii_case("chunked")) || (transfer.is_some() && length.is_some()) {
        return unavailable(client.get_mut(), head);
    }
    let client = client.get_mut();
    write!(client, "{status}\r\nConnection: close\r\n")?;
    // Preserve framing while streaming the body bytes without decoding them.
    if transfer.is_some() { write!(client, "Transfer-Encoding: chunked\r\n")?; }
    for (name, value) in &headers {
        if hop(name, &response_connection) { continue; }
        if name == "set-cookie" {
            if credential_free_alias { continue; }
            if let Some(value) = scoped_cookie(value) { write!(client, "{name}: {value}\r\n")?; }
        } else if name == "location" {
            let value = translate(value, &origin, &browser);
            let value = translate(&value, &format!("//{host}"), &browser);
            write!(client, "{name}: {value}\r\n")?;
        } else {
            write!(client, "{name}: {value}\r\n")?;
        }
    }
    write!(client, "\r\n")?;
    if !head && !matches!(code, 204 | 304) {
        if transfer.is_some() {
            http::copy_chunked(&mut upstream, client, u64::MAX, true)?;
        } else if let Some(length) = length {
            copy_exact(&mut upstream, client, length.parse()?)?;
        } else {
            io::copy(&mut upstream, client)?;
        }
    }
    Ok(())
}

fn unavailable(client: &mut TcpStream, head: bool) -> Result<()> {
    send(client, head, "502 Bad Gateway", "text/plain", "", b"This app is unavailable. Return to Front Gate and refresh its status.")
}

fn running_units(user: bool) -> Value {
    let names = crate::systemd_user_service::running_service_names(user).ok();
    json!({"scope": if user {"user"} else {"system"}, "names": names})
}

pub(crate) fn perth_time(micros: Option<i64>) -> String {
    micros.filter(|time| *time > 0).and_then(chrono::DateTime::from_timestamp_micros)
        .and_then(|time| time.checked_add_signed(chrono::TimeDelta::hours(8)))
        .map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "—".into())
}

pub(crate) fn observed_unit(name: &str, suffix: &str) -> bool {
    name.ends_with(suffix) && name.len() <= 255
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".:@_-".contains(&byte))
}

pub(crate) fn valid_invocation_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && id.bytes().any(|byte| byte != b'0')
}

fn timer_runs(user: bool, units: &BTreeSet<&str>) -> Vec<Value> {
    if units.is_empty() { return Vec::new(); }
    let Ok(rows) = crate::systemd_user_service::directory_runs(user, units.iter()) else { return Vec::new(); };
    let mut recent = rows.into_iter().filter_map(|row| {
        let start = i64::try_from(row.start_us / 1_000_000).ok().filter(|start| *start > 0)?;
        let end = i64::try_from(row.end_us / 1_000_000).ok().filter(|end| *end > 0)?;
        let duration = end.checked_sub(start).filter(|seconds| *seconds >= 0)?;
        if row.result.is_empty() || !row.result.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'-') { return None; }
        let started = perth_time(start.checked_mul(1_000_000));
        let mut run = json!({"name":row.name,"started":started,"duration":duration,"result":row.result});
        if valid_invocation_id(&row.invocation) { run["invocationId"] = json!(row.invocation); }
        Some((start, run))
    }).collect::<Vec<_>>();
    recent.sort_by_key(|(started, _)| std::cmp::Reverse(*started));
    recent.into_iter().map(|(_, run)| run).collect()
}

fn observed_timers(user: bool) -> Value {
    let scope = if user { "user" } else { "system" };
    let timers = crate::systemd_user_service::directory_timers(user).ok().map(|rows| rows.into_iter().map(|row| {
        let service = observed_unit(&row.service, ".service").then_some(row.service);
        json!({"name":row.name,"next":perth_time(i64::try_from(row.next_us).ok()),
            "last":perth_time(i64::try_from(row.last_us).ok()),"service":service})
    }).collect::<Vec<_>>());
    let units = timers.iter().flatten().filter_map(|timer| timer["service"].as_str()).collect::<BTreeSet<_>>();
    json!({"scope":scope,"runs":timer_runs(user,&units),"timers":timers})
}

struct Directory {
    app: Application,
    services: Vec<(Value, u16)>,
    routes: BTreeMap<String, u16>,
    read_only_paths: BTreeMap<String, u16>,
    post_paths: BTreeMap<String, u16>,
    css: Vec<u8>,
    script: Vec<u8>,
}

impl Directory {
    fn page(&self, port: u16) -> Result<String> {
        let (services, units, timers) = thread::scope(|scope| {
            let system = scope.spawn(|| running_units(false));
            let user = scope.spawn(|| running_units(true));
            let system_timers = scope.spawn(|| observed_timers(false));
            let user_timers = scope.spawn(|| observed_timers(true));
            let checks = self.services.iter().map(|(service, port)| scope.spawn(move || {
                let mut entry = service.clone();
                entry["online"] = json!(TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, *port).into(), CONNECT).is_ok());
                entry
            })).collect::<Vec<_>>();
            (checks.into_iter().map(|check| check.join().expect("service probe")).collect::<Vec<_>>(),
                [system.join().expect("system units"), user.join().expect("user units")],
                [system_timers.join().expect("system timers"), user_timers.join().expect("user timers")])
        });
        let now = chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now());
        let time = (now + chrono::TimeDelta::hours(8)).format("%H:%M:%S").to_string();
        let mut meter = Meter::new(20_000_000);
        let programme = self.app.admit(&mut meter)?;
        programme.run("gate.page", json!({"port":port,"services":services,"units":units,"timers":timers,"time":time}), &mut meter)?
            .as_str().map(str::to_owned).ok_or_else(|| fail("gate.page must return HTML text"))
    }

    fn request(&self, stream: TcpStream) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut client = BufReader::new(stream);
        let Ok((start, headers)) = http::read_header_lines(&mut client) else {
            return send(client.get_mut(), false, "400 Bad Request", "text/plain", "", b"Invalid HTTP request.");
        };
        let fields = start.split(' ').collect::<Vec<_>>();
        let [method, path, "HTTP/1.1" | "HTTP/1.0"] = fields.as_slice() else {
            return send(client.get_mut(), false, "400 Bad Request", "text/plain", "", b"Invalid HTTP request line.");
        };
        let head = *method == "HEAD";
        if !method.bytes().all(|byte| byte.is_ascii_uppercase()) || !path.starts_with('/') || path.starts_with("//")
            || !path.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'\\') {
            return send(client.get_mut(), head, "400 Bad Request", "text/plain", "", b"Invalid request path.");
        }
        let authority = single(&headers, "host")?.unwrap_or_default();
        let (host, port) = authority.split_once(':').unwrap_or((authority, "80"));
        let port = (!port.starts_with('0') && port.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| port.parse::<u16>().ok()).flatten();
        if let Some(port) = port {
            if let Some(app) = self.routes.get(host) {
                return proxy(&mut client, Request { method, path, authority, headers: &headers, credential_free_alias: false }, *app);
            }
            if matches!(host, "localhost" | "127.0.0.1") {
                let request_path = path.split_once('?').map_or(*path, |(path, _)| path);
                if let Some(app) = self.post_paths.get(request_path) {
                    if *method != "POST" {
                        return send(client.get_mut(), head, "405 Method Not Allowed", "text/plain", "Allow: POST\r\n", b"Method not allowed.");
                    }
                    if single(&headers, "origin")? != Some(format!("http://{authority}").as_str()) {
                        return send(client.get_mut(), head, "403 Forbidden", "text/plain", "", b"Wrong origin.");
                    }
                    return proxy(&mut client, Request { method, path, authority, headers: &headers, credential_free_alias: true }, *app);
                }
                if !matches!(*method, "GET" | "HEAD") {
                    return send(client.get_mut(), head, "405 Method Not Allowed", "text/plain", "Allow: GET, HEAD\r\n", b"Method not allowed.");
                }
                if let Some(app) = self.read_only_paths.get(request_path) {
                    return proxy(&mut client, Request { method, path, authority, headers: &headers, credential_free_alias: true }, *app);
                }
                let client = client.get_mut();
                return match *path {
                    "/front-gate.css" => send(client, head, "200 OK", "text/css; charset=utf-8", "", &self.css),
                    "/front-gate.js" => send(client, head, "200 OK", "text/javascript; charset=utf-8", "", &self.script),
                    "/encounter-front-gate.conf" => send(client, head, "303 See Other", "", "Location: /\r\n", b""),
                    "/" => match self.page(port) {
                        Ok(page) => send(client, head, "200 OK", "text/html; charset=utf-8", "", page.as_bytes()),
                        Err(_) => send(client, head, "503 Service Unavailable", "text/plain", "", b"The service directory could not be loaded."),
                    },
                    _ => send(client, head, "404 Not Found", "text/plain", "", b"Page not found."),
                };
            }
        }
        send(client.get_mut(), head, "421 Misdirected Request", "text/plain", "", b"Open Front Gate through its loopback address.")
    }
}

pub fn serve(root: &Path, declaration: &str, port: u16) -> Result<()> {
    crate::package::check(root)?;
    let app = Application::load(root, declaration)?;
    if !app.has_entry("gate.apps") || !app.has_entry("gate.page") { return Err(fail("missing directory entries")); }
    let mut meter = Meter::new(20_000_000);
    let programme = app.admit(&mut meter)?;
    let apps = programme.run("gate.apps", Value::Null, &mut meter)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    let mut ports = BTreeSet::from([listener.local_addr()?.port()]);
    let mut routes = BTreeMap::new();
    let mut read_only_paths = BTreeMap::new();
    let mut post_paths = BTreeMap::new();
    let mut services = Vec::new();
    for entry in apps.as_array().ok_or_else(|| fail("expected a service registry"))? {
        let id = entry["id"].as_str().filter(|id| id.starts_with(|c: char| c.is_ascii_lowercase())
            && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
            .ok_or_else(|| fail("invalid service id"))?;
        let port = entry["port"].as_u64().and_then(|port| u16::try_from(port).ok()).filter(|port| *port != 0)
            .ok_or_else(|| fail("invalid service port"))?;
        if !ports.insert(port) || routes.insert(format!("{id}.localhost"), port).is_some() {
            return Err(fail("duplicate service id or port"));
        }
        for (field, table) in [("readOnlyPaths", &mut read_only_paths), ("postPaths", &mut post_paths)] {
            let Some(paths) = entry.get(field) else { continue; };
            for value in paths.as_array().ok_or_else(|| fail("expected directory path list"))? {
                let path = value.as_str().filter(|path| {
                    path.starts_with('/') && path.len() <= 200
                        && path[1..].split('/').all(|part| !matches!(part, "" | "." | ".."))
                        && path.bytes().all(|c| c.is_ascii_alphanumeric() || b"/-._".contains(&c))
                        && !matches!(*path, "/front-gate.css" | "/front-gate.js" | "/encounter-front-gate.conf")
                }).ok_or_else(|| fail("invalid directory path"))?;
                if table.insert(path.to_owned(), port).is_some() {
                    return Err(fail("duplicate directory path"));
                }
            }
        }
        services.push((entry.clone(), port));
    }
    if post_paths.keys().any(|path| read_only_paths.contains_key(path)) {
        return Err(fail("overlapping directory paths"));
    }
    let directory = Arc::new(Directory { app, routes, read_only_paths, post_paths, services, css: fs::read(root.join("front-gate.css"))?,
        script: fs::read(root.join("front-gate.js"))? });
    let active = Arc::new(AtomicUsize::new(0));
    println!("Encounter http://{}", listener.local_addr()?);
    for stream in listener.incoming() {
        let stream = stream?;
        if active.load(Ordering::Relaxed) >= 64 { continue; }
        active.fetch_add(1, Ordering::Relaxed);
        let active = active.clone();
        let directory = directory.clone();
        thread::spawn(move || {
            let _ = directory.request(stream);
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}
