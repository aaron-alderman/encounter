use crate::{Result, fail, http, process::{Meter, Programme}};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::{
    cell::OnceCell,
    collections::BTreeSet,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::TcpStream,
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const LIMIT: u64 = 8 * 1024 * 1024;

thread_local! {
    static POLICY: OnceCell<Programme> = const { OnceCell::new() };
}

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("assurance_view.encounter").to_owned()],
        &["assuranceView.route"], &BTreeSet::from(["text.matches", "text.slice"]), &mut Meter::new(100_000))
}

fn report(directory: &File, name: &str) -> Result<Option<File>> {
    if Path::new(name).file_name().and_then(|name| name.to_str()) != Some(name) {
        return Err(fail("Expected one assurance report filename"));
    }
    let name = CString::new(name)?;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ELOOP | libc::EACCES) => Ok(None),
            _ => Err(error.into()),
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    Ok(file.metadata()?.is_file().then_some(file))
}

fn http_date(date: DateTime<Utc>) -> String { date.format("%a, %d %b %Y %H:%M:%S GMT").to_string() }

fn response(stream: &mut TcpStream, status: &str, mime: &str, modified: Option<DateTime<Utc>>, length: usize, body: &[u8]) -> Result<()> {
    let date = http_date(DateTime::<Utc>::from(SystemTime::now()));
    write!(stream, "HTTP/1.1 {status}\r\nDate: {date}\r\nConnection: close\r\n")?;
    if status != "304 Not Modified" {
        write!(stream, "Content-Type: {mime}\r\nContent-Length: {length}\r\nX-Content-Type-Options: nosniff\r\n")?;
        if let Some(modified) = modified { write!(stream, "Last-Modified: {}\r\n", http_date(modified))?; }
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    Ok(())
}

fn missing(stream: &mut TcpStream, status: &str, head: bool) -> Result<()> {
    let body = if status == "501 Not Implemented" { b"Unsupported method.\n".as_slice() } else { b"Assurance report unavailable.\n" };
    response(stream, status, "text/plain; charset=utf-8", None, body.len(), if head { b"" } else { body })
}

fn handle(directory: &File, programme: &Programme, stream: &mut TcpStream, request: http::Request) -> Result<()> {
    let raw = request.path.split('?').next().unwrap_or_default();
    let path = http::decode_path(raw).unwrap_or_default();
    let route = programme.run("assuranceView.route", json!({"method":request.method,"path":path}), &mut Meter::new(100_000))?;
    let head = request.method == "HEAD";
    let status = route["status"].as_str().ok_or_else(|| fail("Expected assurance route status"))?;
    let name = match status {
        "200 OK" => route["file"].as_str().ok_or_else(|| fail("Expected assurance report filename"))?,
        "404 Not Found" | "501 Not Implemented" => return missing(stream, status, head),
        _ => return Err(fail("Unexpected assurance route status")),
    };
    let Some(file) = report(directory, name)? else { return missing(stream, "404 Not Found", head); };
    let metadata = file.metadata()?;
    if metadata.len() > LIMIT { return missing(stream, "404 Not Found", head); }
    let modified = metadata.modified()?.duration_since(UNIX_EPOCH).ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok()).and_then(|time| DateTime::from_timestamp(time, 0));
    if !request.headers.contains_key("if-none-match")
        && let Some((value, modified)) = request.headers.get("if-modified-since").zip(modified)
        && let Ok(since) = DateTime::parse_from_rfc2822(value)
        && since.offset().local_minus_utc() == 0 && since >= modified {
        return response(stream, "304 Not Modified", "", None, 0, b"");
    }
    let mime = route["mime"].as_str().ok_or_else(|| fail("Expected assurance report media type"))?;
    if head { return response(stream, "200 OK", mime, modified, metadata.len() as usize, b""); }
    let mut body = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut body)?;
    if body.len() as u64 > LIMIT { return missing(stream, "404 Not Found", false); }
    response(stream, "200 OK", mime, modified, body.len(), &body)
}

pub fn serve(root: &Path, port: u16) -> Result<()> {
    if !root.is_absolute() || port < 1024 {
        return Err(fail("Expected an absolute assurance directory and an unprivileged loopback port"));
    }
    let directory = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(root)?;
    policy()?;
    http::serve_workers(port, 4, 64 * 1024, move |stream, request| {
        let result = POLICY.with(|slot| {
            if slot.get().is_none() { let _ = slot.set(policy()?); }
            handle(&directory, slot.get().expect("admitted assurance view policy"), stream, request)
        });
        if let Err(error) = result {
            if error.downcast_ref::<io::Error>().is_none() { eprintln!("Assurance view: {error}"); }
        }
    })
}

#[cfg(test)]
#[test]
fn viewer_admits_only_report_routes_and_regular_files_in_the_pinned_directory() -> Result<()> {
    use crate::appdev_host_process::Scratch;
    use std::{env, fs, os::unix::fs::symlink};
    let programme = policy()?;
    let route = |method, path| programme.run("assuranceView.route", json!({"method":method,"path":path}),
        &mut Meter::new(100_000));
    assert_eq!(route("GET", "/")?["file"], "index.html");
    assert_eq!(route("HEAD", "/assessment.identity")?["mime"], "application/octet-stream");
    assert_eq!(route("POST", "/assessment.json")?["status"], "501 Not Implemented");
    for path in ["/private.json", "/a1-hidden/assessment.json", "/../assessment.json"] {
        assert_eq!(route("GET", path)?["status"], "404 Not Found");
    }
    let scratch = Scratch::create(&env::temp_dir(), "assurance-view-test-")?;
    let root = scratch.path().join("reports");
    fs::create_dir(&root)?;
    let directory = File::open(&root)?;
    fs::write(scratch.path().join("outside"), "outside")?;
    symlink(scratch.path().join("outside"), root.join("a1-escape.html"))?;
    fs::create_dir(root.join("a1-directory.html"))?;
    assert!(report(&directory, "a1-escape.html")?.is_none());
    assert!(report(&directory, "a1-directory.html")?.is_none());
    assert!(report(&directory, "../outside").is_err());
    fs::write(root.join("index.html"), "report")?;
    fs::rename(&root, scratch.path().join("previous"))?;
    fs::create_dir(&root)?;
    fs::write(root.join("index.html"), "different directory")?;
    let mut file = report(&directory, "index.html")?.ok_or_else(|| fail("Pinned assurance report unavailable"))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    assert_eq!(contents, "report");
    Ok(())
}
