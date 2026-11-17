use crate::{Result, appdev_host_process::{Supervisor, interruption}, appdev_performance, command::Evaluator, fail, http};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::{
    fs, io::{self, BufReader, Read, Write},
    os::unix::{fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt}, net::{UnixListener, UnixStream}},
    path::{Path, PathBuf}, thread, time::{Duration, SystemTime, UNIX_EPOCH},
};

const RENDER: &str = "applications/appdev-projects/dev-jobs/performance-mailbox.rel";
const COOKIE: &str = "encounter_performance_seen";

struct Mailbox { policy: Evaluator, renderer: Evaluator }

impl Mailbox {
    fn load(app: &Path) -> Result<Self> {
        let projects = app.ancestors().nth(2).ok_or_else(|| fail("Expected the Encounter project source root"))?;
        Ok(Self { policy: appdev_performance::evaluator(app)?, renderer: Evaluator::load(projects, RENDER)? })
    }

    fn render(&self, data: &Value) -> Result<String> {
        let output = self.renderer.run("cli.main", json!([data.to_string()]))?;
        output.as_str().map(str::to_owned).ok_or_else(|| fail("Invalid Performance Mailbox markup"))
    }

    fn delta(&self, data: &Value, known: &str, unread: &str) -> Result<Option<String>> {
        let delta = self.policy.run("mailbox.delta", json!({"data":data,"known":known,"unread":unread}))?;
        if delta["unchanged"] == true { return Ok(None); }
        let changed = delta["changed"].as_array().ok_or_else(|| fail("Invalid Performance Mailbox delta"))?;
        let mut rows = Map::new();
        for row in changed {
            let key = row["key"].as_str().ok_or_else(|| fail("Invalid warning key"))?;
            let mut input = data.clone();
            input["groups"] = json!([row["group"]]);
            input["rowsOnly"] = json!(true);
            let markup = self.render(&input)?;
            let inner = markup.strip_prefix("<li>").and_then(|html| html.strip_suffix("</li>"))
                .ok_or_else(|| fail("Unexpected Encounter warning markup"))?;
            rows.insert(key.to_owned(), json!(inner));
        }
        Ok(Some(json!({"order":delta["order"],"rows":rows,"unread":delta["unread"],
            "openLimit":delta["openLimit"],"exchangeLimit":delta["exchangeLimit"]}).to_string()))
    }

    fn handle(&self, stream: &mut UnixStream, history: impl FnOnce() -> Result<Vec<Value>>) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let request = http::read_head(&mut BufReader::new(&mut *stream));
        let Ok((start, headers)) = request else { return respond(stream, 400, false, false, None, "Invalid request"); };
        let mut parts = start.split(' ');
        let (Some(method), Some(target), Some("HTTP/1.0" | "HTTP/1.1"), None) =
            (parts.next(), parts.next(), parts.next(), parts.next()) else {
                return respond(stream, 400, false, false, None, "Invalid request");
            };
        if headers.contains_key("transfer-encoding") || headers.get("content-length").is_some_and(|value| value != "0") {
            return respond(stream, 400, false, false, None, "Invalid request");
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let Ok(query) = http::form(query.as_bytes()) else { return respond(stream, 400, false, false, None, "Invalid query"); };
        let field = |key| query.get(key).map(String::as_str);
        let route = self.policy.run("mailbox.route", json!({"method":method,"path":path,"updates":field("updates")==Some("1")}))?;
        let (badge, delta) = match route.as_str() {
            Some("mailbox") => (false, false),
            Some("badge") => (true, false),
            Some("delta") => (true, true),
            Some("missing") => return respond(stream, 404, false, false, None, "Not found"),
            Some("method") => return respond(stream, 501, false, false, None, "Unsupported method"),
            _ => return Err(fail("Invalid Encounter mailbox route")),
        };
        let seen = seen_cursor(headers.get("cookie").map(String::as_str).unwrap_or_default());
        let runs = match history() {
            Ok(runs) => runs,
            Err(_) if badge && !delta => Vec::new(),
            Err(error) => {
                eprintln!("Performance Mailbox history: {error}");
                return respond(stream, 503, badge, delta, None, "Sweep journal unavailable");
            }
        };
        let content = (|| -> Result<(Option<String>, Option<u64>)> {
            let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
            let runs = dated_runs(runs, now)?;
            let data = self.policy.run("mailbox.model", json!({"runs":runs,"seen":seen,"badge":badge}))?;
            let cursor = data["messages"][0]["cursor"].as_u64().filter(|cursor| *cursor > seen);
            let body = if delta { self.delta(&data, field("known").unwrap_or(""), field("unread").unwrap_or("0"))? }
                else { Some(self.render(&data)?) };
            Ok((body, cursor))
        })();
        match content {
            Ok((Some(body), cursor)) => respond(stream, 200, badge, delta, cursor, &body),
            Ok((None, cursor)) => respond(stream, 204, badge, delta, cursor, ""),
            Err(error) => {
                eprintln!("Performance Mailbox: {error}");
                respond(stream, 503, badge, delta, None, "Encounter renderer unavailable")
            }
        }
    }
}

fn seen_cursor(cookie: &str) -> u64 {
    cookie.split(';').filter_map(|field| field.trim().split_once('=')).filter(|(key, _)| *key == COOKIE)
        .last().and_then(|(_, value)| {
            let value = value.strip_prefix('"').and_then(|value| value.strip_suffix('"')).unwrap_or(value);
            (value.len() <= 20 && !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| value.parse::<u64>().unwrap_or(u64::MAX).min(9_007_199_254_740_991))
        }).unwrap_or(0)
}

fn dated_runs(mut runs: Vec<Value>, now: u64) -> Result<Vec<Value>> {
    let perth = FixedOffset::east_opt(8 * 3600).ok_or_else(|| fail("Invalid Perth offset"))?;
    for run in &mut runs {
        let stamp = run["stamp"].as_u64().ok_or_else(|| fail("Invalid sweep timestamp"))?;
        let date = DateTime::<Utc>::from_timestamp_micros(i64::try_from(stamp)?).ok_or_else(|| fail("Invalid sweep date"))?;
        let local = date.with_timezone(&perth);
        run["when"] = json!(date.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        run["recordedAt"] = json!(local.to_rfc3339_opts(SecondsFormat::Secs, false));
        run["recordedLabel"] = json!(local.format("%d %b, %H:%M AWST").to_string());
        run["elapsedMinutes"] = json!(now.saturating_sub(stamp) / 60_000_000);
    }
    Ok(runs)
}

fn respond(stream: &mut UnixStream, status: u16, badge: bool, delta: bool, cursor: Option<u64>, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK", 204 => "No Content", 400 => "Bad Request", 404 => "Not Found",
        501 => "Not Implemented", 503 => "Service Unavailable", _ => return Err(fail("Invalid mailbox status")),
    };
    let content_type = if status >= 400 { "text/plain; charset=utf-8" }
        else if delta { "application/json" } else { "text/html; charset=utf-8" };
    let ancestors = if badge { "'self'" } else { "'none'" };
    write!(stream, "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
        Cache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors {ancestors}\r\n", body.len())?;
    if let Some(cursor) = cursor {
        write!(stream, "Set-Cookie: {COOKIE}={cursor}; Path=/workspace/platform; Max-Age=86400; Secure; HttpOnly; SameSite=Lax\r\n")?;
    }
    write!(stream, "\r\n{body}")?;
    Ok(())
}

struct SocketFile(PathBuf, u64, u64);

impl Drop for SocketFile {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.0).is_ok_and(|meta| meta.dev() == self.1 && meta.ino() == self.2) {
            let _ = fs::remove_file(&self.0);
        }
    }
}

pub fn serve(app: &Path, socket: &Path) -> Result<()> {
    serve_with_history(app, socket, |mailbox| appdev_performance::mailbox_history(&mailbox.policy))
}

pub(crate) fn serve_fixture(app: &Path, socket: &Path, scenario: &str) -> Result<()> {
    if socket.file_name().and_then(|name| name.to_str()) != Some("performance.sock") {
        return Err(fail("Expected the performance fixture socket name"));
    }
    if !matches!(scenario, "startup" | "badge") {
        return Err(fail("Unknown performance mailbox fixture scenario"));
    }
    let phase = socket.with_file_name("assurance-phase");
    serve_with_history(app, socket, |mailbox| {
        let file = fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&phase)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.len() > 16 {
            return Err(fail("Expected a bounded private mailbox fixture phase"));
        }
        let mut phase = String::new();
        file.take(17).read_to_string(&mut phase)?;
        let mut runs = mailbox.policy.run("mailbox.fixtureHistory", json!({"phase":phase,"scenario":scenario}))?;
        runs.as_array_mut().map(std::mem::take).ok_or_else(|| fail("Invalid mailbox fixture history"))
    })
}

fn serve_with_history(app: &Path, socket: &Path, history: impl Fn(&Mailbox) -> Result<Vec<Value>>) -> Result<()> {
    let _signals = Supervisor::new();
    let app = app.canonicalize()?;
    let mailbox = Mailbox::load(&app)?;
    let parent = socket.parent().filter(|path| path.is_absolute()).ok_or_else(|| fail("Expected an absolute mailbox socket path"))?;
    let uid = unsafe { libc::geteuid() };
    let meta = fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o027 != 0 {
        return Err(fail("Expected a private mailbox socket directory"));
    }
    match fs::symlink_metadata(socket) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == uid => {
            match UnixStream::connect(socket) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(socket)?,
                _ => return Err(fail("Mailbox socket is already in use")),
            }
        }
        Ok(_) => return Err(fail("Refusing to replace mailbox socket path")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(socket)?;
    let meta = fs::symlink_metadata(socket)?;
    let _socket = SocketFile(socket.to_owned(), meta.dev(), meta.ino());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    listener.set_nonblocking(true)?;
    while interruption().is_none() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(error) = mailbox.handle(&mut stream, || history(&mailbox)) {
                    eprintln!("Performance Mailbox: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(25)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn native_mailbox_preserves_warning_delta_and_read_marker() -> Result<()> {
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../applications/appdev-projects").canonicalize()?;
    let mailbox = Mailbox::load(&app)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let run = |stamp, open| json!({"stamp":stamp,"capacity":false,"release":"fixture","confirmation":null,
        "reports":{"encounter-work-startup":{"samples":[{"delayMs":200,"openMs":open,"exchanges":2}]}}});
    let confirmed = now - 120_000_000;
    let warning = vec![run(now - 180_000_000, 1000), run(confirmed, 1000)];
    let query = |target: &str, cookie: &str, history: Vec<Value>| -> Result<(String, String)> {
        use std::io::Read;
        let (mut client, mut server) = UnixStream::pair()?;
        write!(client, "GET {target} HTTP/1.0\r\nCookie: {cookie}\r\n\r\n")?;
        mailbox.handle(&mut server, || Ok(history))?;
        drop(server);
        let mut reply = String::new();
        client.read_to_string(&mut reply)?;
        let (headers, body) = reply.split_once("\r\n\r\n").ok_or_else(|| fail("Missing mailbox response"))?;
        Ok((headers.to_owned(), body.to_owned()))
    };
    let (headers, body) = query("/", "", warning.clone())?;
    assert!(headers.starts_with("HTTP/1.1 200 "));
    assert!(headers.contains(&format!("Set-Cookie: {COOKIE}={confirmed};")));
    assert!(body.contains("WARNING: Performance Regression"));
    let (headers, body) = query("/badge?updates=1", "", warning.clone())?;
    assert!(headers.contains("Content-Type: application/json"));
    let update: Value = serde_json::from_str(&body)?;
    assert_eq!(update["unread"], 1);
    let key = update["order"][0].as_str().ok_or_else(|| fail("Missing warning key"))?;
    assert!(update["rows"][key].as_str().unwrap_or_default().contains("active-regression"));
    let (headers, body) = query(&format!("/badge?updates=1&known={key}&unread=1"), "", warning.clone())?;
    assert!(headers.starts_with("HTTP/1.1 204 "));
    assert!(body.is_empty());
    let (headers, body) = query("/badge?updates=1", &format!("{COOKIE}={confirmed}"), warning.clone())?;
    assert!(headers.starts_with("HTTP/1.1 204 "));
    assert!(body.is_empty());
    let mut recovery = warning;
    recovery.push(run(now - 60_000_000, 900));
    let (_, body) = query(&format!("/badge?updates=1&known={key}&unread=1"), "", recovery)?;
    let update: Value = serde_json::from_str(&body)?;
    let recovered = update["order"][0].as_str().ok_or_else(|| fail("Missing recovered warning"))?;
    assert_ne!(recovered, key);
    assert!(update["rows"][recovered].as_str().unwrap_or_default().contains("Recovered"));
    Ok(())
}
