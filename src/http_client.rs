// The native transport accepts requests only from scoped Rust adapters.
use crate::{Result, fail, http};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_long, c_void},
    ptr::{self, NonNull}, sync::OnceLock, time::Duration,
};

#[link(name = "libcurl.so.4", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn curl_global_init(flags: c_long) -> c_int;
    fn curl_easy_init() -> *mut c_void;
    fn curl_easy_cleanup(handle: *mut c_void);
    fn curl_easy_setopt(handle: *mut c_void, option: c_int, ...) -> c_int;
    fn curl_easy_perform(handle: *mut c_void) -> c_int;
    fn curl_easy_getinfo(handle: *mut c_void, info: c_int, ...) -> c_int;
    fn curl_slist_append(list: *mut c_void, item: *const c_char) -> *mut c_void;
    fn curl_slist_free_all(list: *mut c_void);
}

struct Easy(NonNull<c_void>);
impl Drop for Easy {
    fn drop(&mut self) { unsafe { curl_easy_cleanup(self.0.as_ptr()) } }
}

#[derive(Default)]
struct List(*mut c_void);
impl List {
    fn append(&mut self, value: &str) -> Result<()> {
        let value = CString::new(value)?;
        let next = unsafe { curl_slist_append(self.0, value.as_ptr()) };
        if next.is_null() { return Err(fail("Cannot configure native HTTP list")); }
        self.0 = next;
        Ok(())
    }
}
impl Drop for List {
    fn drop(&mut self) { unsafe { curl_slist_free_all(self.0) } }
}

pub(crate) struct Request<'a> {
    pub url: &'a str,
    pub method: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub limit: usize,
    pub resolve: Option<&'a str>,
    pub trust_anchor: Option<&'a CStr>,
    pub restoring: bool,
}

pub(crate) struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    headers: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct BodyLimitExceeded;

impl std::fmt::Display for BodyLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Native HTTP response exceeded its body limit")
    }
}

impl std::error::Error for BodyLimitExceeded {}

impl Response {
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers.split(|byte| *byte == b'\n').filter_map(move |line| {
            let (key, value) = std::str::from_utf8(line).ok()?.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

struct Transfer {
    body: Vec<u8>,
    headers: Vec<u8>,
    header_bytes: usize,
    header_complete: bool,
    limit: usize,
    body_limit_exceeded: bool,
    restoring: bool,
}

unsafe extern "C" fn write_body(bytes: *const u8, size: usize, count: usize, data: *mut c_void) -> usize {
    let Some(size) = size.checked_mul(count).filter(|size| *size != 0) else { return 0; };
    let transfer = unsafe { &mut *data.cast::<Transfer>() };
    if http::check_interruption(transfer.restoring).is_err() { return 0; }
    if size > transfer.limit - transfer.body.len() {
        transfer.body_limit_exceeded = true;
        return 0;
    }
    transfer.body.extend_from_slice(unsafe { std::slice::from_raw_parts(bytes, size) });
    size
}

unsafe extern "C" fn write_header(bytes: *const u8, size: usize, count: usize, data: *mut c_void) -> usize {
    let Some(size) = size.checked_mul(count).filter(|size| *size != 0) else { return 0; };
    let transfer = unsafe { &mut *data.cast::<Transfer>() };
    if http::check_interruption(transfer.restoring).is_err() || size > 65_536 - transfer.header_bytes { return 0; }
    transfer.header_bytes += size;
    let line = unsafe { std::slice::from_raw_parts(bytes, size) };
    if line.starts_with(b"HTTP/") {
        transfer.headers.clear();
        transfer.header_complete = false;
    }
    if matches!(line, b"\r\n" | b"\n") { transfer.header_complete = true; }
    if !transfer.header_complete { transfer.headers.extend_from_slice(line); }
    size
}

unsafe extern "C" fn progress(data: *mut c_void, _: i64, _: i64, _: i64, _: i64) -> c_int {
    let transfer = unsafe { &*data.cast::<Transfer>() };
    http::check_interruption(transfer.restoring).is_err().into()
}

pub(crate) fn send(request: Request<'_>) -> Result<Response> {
    exchange(request, None)
}

pub(super) fn send_unix(request: Request<'_>, socket: &CStr) -> Result<Response> {
    exchange(request, Some(socket))
}

fn exchange(request: Request<'_>, socket: Option<&CStr>) -> Result<Response> {
    let protocol = if request.url.starts_with("https://") { c"https" }
        else if request.url.starts_with("http://") { c"http" }
        else { return Err(fail("Expected an HTTP or HTTPS endpoint")); };
    if !matches!(request.method, "GET" | "POST" | "PUT" | "DELETE") || request.url.contains(['#', '\\'])
        || !request.url.bytes().all(|byte| byte.is_ascii_graphic())
        || request.body.is_some_and(|body| body.len() > 2_097_152) || !(1..=8 * 1024 * 1024).contains(&request.limit) {
        return Err(fail("Invalid native HTTP request"));
    }
    http::check_interruption(request.restoring)?;
    let millis = |duration: Duration| -> Result<c_long> {
        let value = c_long::try_from(duration.as_millis())?;
        if value == 0 { return Err(fail("Native HTTP deadline elapsed")); }
        Ok(value)
    };
    let timeout = millis(request.timeout)?;
    let connect = millis(request.connect_timeout.min(request.timeout))?;
    static INITIALIZED: OnceLock<c_int> = OnceLock::new();
    if *INITIALIZED.get_or_init(|| unsafe { curl_global_init(3) }) != 0 {
        return Err(fail("Cannot initialize the native HTTP library"));
    }
    let mut headers = List::default();
    for (name, value) in request.headers {
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.contains(['\r', '\n', '\0']) {
            return Err(fail("Invalid native HTTP request header"));
        }
        headers.append(&format!("{name}: {value}"))?;
    }
    let mut resolution = List::default();
    if let Some(value) = request.resolve { resolution.append(value)?; }
    let url = CString::new(request.url)?;
    let method = CString::new(request.method)?;
    let mut transfer = Transfer { body: Vec::new(), headers: Vec::new(), header_bytes: 0, header_complete: true,
        limit: request.limit, body_limit_exceeded: false, restoring: request.restoring };
    let data = (&mut transfer as *mut Transfer).cast::<c_void>();
    let handle = Easy(NonNull::new(unsafe { curl_easy_init() }).ok_or_else(|| fail("Cannot allocate native HTTP request"))?);
    let easy = handle.0.as_ptr();
    let check = |status| if status == 0 { Ok(()) } else { Err(fail("Native HTTP exchange did not complete")) };
    let (mut status, mut content_type): (c_long, *const c_char) = (0, ptr::null());
    let content_type = unsafe {
        // Stable libcurl option numbers, with C variadic argument types.
        for (option, value) in [(10002, url.as_ptr()), (10036, method.as_ptr()), (10004, c"".as_ptr()),
            (10318, protocol.as_ptr()), (10018, c"Encounter".as_ptr())] {
            check(curl_easy_setopt(easy, option, value))?; // URL, CUSTOMREQUEST, PROXY, PROTOCOLS_STR, USERAGENT
        }
        if protocol == c"https" {
            let trust = request.trust_anchor.unwrap_or(c"/etc/ssl/certs/ca-certificates.crt");
            check(curl_easy_setopt(easy, 10065, trust.as_ptr()))?; // CAINFO
        }
        if let Some(socket) = socket {
            check(curl_easy_setopt(easy, 10231, socket.as_ptr()))?; // UNIX_SOCKET_PATH
        }
        if !headers.0.is_null() { check(curl_easy_setopt(easy, 10023, headers.0))?; } // HTTPHEADER
        if !resolution.0.is_null() { check(curl_easy_setopt(easy, 10203, resolution.0))?; } // RESOLVE
        for (option, value) in [(52, 0), (64, 1), (81, 2), (32, 6), (99, 1), (43, 0), (234, 1),
            (155, timeout), (156, connect)] {
            check(curl_easy_setopt(easy, option, value))?; // redirects, TLS, signals, progress, path, deadlines
        }
        if let Some(body) = request.body {
            check(curl_easy_setopt(easy, 30120, body.len() as i64))?; // POSTFIELDSIZE_LARGE
            check(curl_easy_setopt(easy, 10015, body.as_ptr()))?; // POSTFIELDS
        }
        check(curl_easy_setopt(easy, 30117, request.limit as i64))?; // MAXFILESIZE_LARGE
        check(curl_easy_setopt(easy, 10001, data))?; // WRITEDATA
        check(curl_easy_setopt(easy, 10029, data))?; // HEADERDATA
        check(curl_easy_setopt(easy, 10057, data))?; // XFERINFODATA
        let body: unsafe extern "C" fn(*const u8, usize, usize, *mut c_void) -> usize = write_body;
        let header: unsafe extern "C" fn(*const u8, usize, usize, *mut c_void) -> usize = write_header;
        let callback: unsafe extern "C" fn(*mut c_void, i64, i64, i64, i64) -> c_int = progress;
        check(curl_easy_setopt(easy, 20011, body))?; // WRITEFUNCTION
        check(curl_easy_setopt(easy, 20079, header))?; // HEADERFUNCTION
        check(curl_easy_setopt(easy, 20219, callback))?; // XFERINFOFUNCTION
        let result = curl_easy_perform(easy);
        if result == 63 || transfer.body_limit_exceeded { // CURLE_FILESIZE_EXCEEDED
            return Err(BodyLimitExceeded.into());
        }
        check(result)?;
        check(curl_easy_getinfo(easy, 0x200002, &mut status as *mut c_long))?;
        check(curl_easy_getinfo(easy, 0x100012, &mut content_type as *mut *const c_char))?;
        if content_type.is_null() { String::new() } else { CStr::from_ptr(content_type).to_str()?.to_owned() }
    };
    drop(handle);
    if !(200..=599).contains(&status) { return Err(fail("Native HTTP exchange returned no final status")); }
    Ok(Response { status: status as u16, content_type, body: transfer.body, headers: transfer.headers })
}

#[cfg(test)]
#[test]
fn native_http_keeps_paths_and_payloads_literal_and_refuses_redirects() -> Result<()> {
    use std::{io::{self, BufReader, Read, Write}, net::{Ipv4Addr, TcpListener}, thread};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let origin = format!("http://{}", listener.local_addr()?);
    let server = thread::spawn(move || -> io::Result<()> {
        let (socket, _) = listener.accept()?;
        let mut socket = BufReader::new(socket);
        let (start, headers) = http::read_head(&mut socket)
            .map_err(|error| io::Error::other(error.to_string()))?;
        assert_eq!(start, "PUT /a/../b?value=%20 HTTP/1.1");
        assert_eq!(headers["host"], "workspace.fixture");
        assert_eq!(headers["authorization"], "Bearer fixture");
        let expected = b"@/literal/nonexistent-file";
        assert_eq!(headers["content-length"], expected.len().to_string());
        let mut body = [0; 26];
        socket.read_exact(&mut body[..expected.len()])?;
        assert_eq!(&body[..expected.len()], expected);
        socket.get_mut().write_all(b"HTTP/1.1 303 See Other\r\nLocation: /must-not-follow\r\n\
            Content-Type: text/plain\r\nSet-Cookie: first=one\r\nSet-Cookie: second=two\r\n\
            Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\none\r\n0\r\nSet-Cookie: trailer=three\r\n\r\n")
    });
    let reply = send(Request {
        url: &format!("{origin}/a/../b?value=%20"), method: "PUT",
        headers: &[("Host", "workspace.fixture"), ("Authorization", "Bearer fixture")],
        body: Some(b"@/literal/nonexistent-file"), timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(1), limit: 1024, resolve: None, trust_anchor: None, restoring: false,
    });
    server.join().expect("native HTTP fixture")?;
    let reply = reply?;
    assert_eq!(reply.status, 303);
    assert_eq!(reply.content_type, "text/plain");
    assert_eq!(reply.body, b"one");
    assert_eq!(reply.header_values("set-cookie").collect::<Vec<_>>(), ["first=one", "second=two"]);
    Ok(())
}

#[cfg(test)]
#[test]
fn native_http_bounds_streamed_responses() -> Result<()> {
    use std::{io, net::{Ipv4Addr, TcpListener}, thread};
    use std::io::Write;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut socket, _) = listener.accept()?;
        http::read_bounded(&mut socket, 0, false).map_err(|error| io::Error::other(error.to_string()))?;
        socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nlongbody\r\n0\r\n\r\n")
    });
    let result = send(Request {
        url: &format!("http://{address}/"), method: "GET", headers: &[], body: None,
        timeout: Duration::from_secs(2), connect_timeout: Duration::from_secs(1),
        limit: 4, resolve: None, trust_anchor: None, restoring: false,
    });
    server.join().expect("native HTTP fixture")?;
    assert!(result.is_err());
    Ok(())
}

#[cfg(test)]
#[test]
#[ignore = "requires a disposable listener that interrupts this test process"]
fn interrupted_http_can_only_continue_for_recovery() -> Result<()> {
    let port: u16 = std::env::var("ENCOUNTER_HTTP_TEST_PORT")?.parse()?;
    let _supervisor = crate::appdev_host_process::Supervisor::new();
    let request = |path, restoring| send(Request {
        url: &format!("http://127.0.0.1:{port}/{path}"), method: "GET", headers: &[], body: None,
        timeout: Duration::from_secs(8), connect_timeout: Duration::from_secs(1),
        limit: 1024, resolve: None, trust_anchor: None, restoring,
    });
    let start = std::time::Instant::now();
    assert!(request("interrupted", false).is_err());
    assert!(crate::appdev_host_process::interruption().is_some());
    assert!(start.elapsed() < Duration::from_secs(4));
    assert!(request("forbidden", false).is_err());
    assert_eq!(request("recovery", true)?.status, 204);
    Ok(())
}
