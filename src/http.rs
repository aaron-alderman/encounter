// Loopback HTTP transport for the bounded browser profile.
use crate::{Result, fail};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    thread,
    time::{Duration, Instant},
};

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

const HEADER_LIMIT: u64 = 8192;
const BODY_LIMIT: usize = 64 * 1024;
static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

pub(crate) fn stopping() -> bool { SIGNAL_STOP.load(Ordering::Acquire) }

pub(crate) struct LoopbackReply {
    stream: TcpStream,
    deadline: Instant,
    restoring: bool,
}

impl LoopbackReply {
    pub(crate) fn open(port: u16, request: &[u8], timeout: Duration) -> Result<BufReader<Self>> {
        Self::open_addr((Ipv4Addr::LOCALHOST, port).into(), request, timeout)
    }

    pub(crate) fn open_addr(address: std::net::SocketAddr, request: &[u8], timeout: Duration) -> Result<BufReader<Self>> {
        Self::connect(address, request, timeout, false)
    }

    pub(crate) fn open_for_rollback(port: u16, request: &[u8], timeout: Duration) -> Result<BufReader<Self>> {
        Self::connect((Ipv4Addr::LOCALHOST, port).into(), request, timeout, true)
    }

    fn connect(address: std::net::SocketAddr, request: &[u8], timeout: Duration, restoring: bool) -> Result<BufReader<Self>> {
        if !address.ip().is_loopback() { return Err(fail("Expected a loopback HTTP peer")); }
        check_interruption(restoring)?;
        let deadline = Instant::now() + timeout;
        let mut stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        stream.write_all(request)?;
        Ok(BufReader::new(Self { stream, deadline, restoring }))
    }
}

impl Read for LoopbackReply {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        read_until_deadline(&mut self.stream, self.deadline, bytes, self.restoring)
    }
}

pub(crate) fn check_interruption(restoring: bool) -> io::Result<()> {
    if !restoring && (stopping() || crate::appdev_host_process::interruption().is_some()) {
        return Err(io::ErrorKind::ConnectionAborted.into());
    }
    Ok(())
}

pub(super) fn read_until_deadline(stream: &mut TcpStream, deadline: Instant, bytes: &mut [u8], restoring: bool) -> io::Result<usize> {
    loop {
        check_interruption(restoring)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(io::ErrorKind::TimedOut.into()); }
        stream.set_read_timeout(Some(remaining.min(Duration::from_millis(200))))?;
        match stream.read(bytes) {
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            result => return result,
        }
    }
}

pub(crate) fn write_temple_bytes(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        if stopping() { return Err(io::ErrorKind::Interrupted.into()); }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err(io::ErrorKind::TimedOut.into()); }
        stream.set_write_timeout(Some(remaining.min(Duration::from_millis(200))))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(size) => bytes = &bytes[size..],
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct BodyLimit;

impl std::fmt::Display for BodyLimit {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("HTTP body exceeds its size limit")
    }
}

impl std::error::Error for BodyLimit {}

extern "C" fn request_stop(_: libc::c_int) {
    SIGNAL_STOP.store(true, Ordering::Release);
}

pub(crate) fn install_stop_signals() -> io::Result<()> {
    // The handler only stores a lock-free flag. The main loop drains the
    // current request before dropping the store and listener.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = request_stop as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn line(reader: &mut impl BufRead, remaining: &mut u64) -> Result<String> {
    let mut bytes = Vec::new();
    let read = reader.take(*remaining).read_until(b'\n', &mut bytes)? as u64;
    *remaining -= read;
    if !bytes.ends_with(b"\r\n") {
        return Err(fail("invalid or oversized HTTP header"));
    }
    bytes.truncate(bytes.len() - 2);
    Ok(String::from_utf8(bytes)?)
}

pub fn read(stream: &mut TcpStream) -> Result<Request> {
    read_bounded(stream, BODY_LIMIT, false)
}

pub fn read_bounded(stream: &mut TcpStream, body_limit: usize, allow_http_10: bool) -> Result<Request> {
    read_request(stream, body_limit, allow_http_10, false)
}

fn read_request(stream: &mut TcpStream, body_limit: usize, allow_http_10: bool, allow_chunked: bool) -> Result<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    parse_request(&mut BufReader::new(stream), body_limit, allow_http_10, allow_chunked)
}

struct DeadlineReader<'a>(&'a mut TcpStream, Instant);

impl Read for DeadlineReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { read_until_deadline(self.0, self.1, bytes, false) }
}

pub(crate) fn read_temple_transit(stream: &mut TcpStream, body_limit: usize) -> Result<Request> {
    read_temple_request(stream, Some(body_limit))
}

pub(crate) fn read_temple_publication(stream: &mut TcpStream) -> Result<Request> {
    read_temple_request(stream, None)
}

fn read_temple_request(stream: &mut TcpStream, body_limit: Option<usize>) -> Result<Request> {
    let timeout = Duration::from_secs(1);
    stream.set_write_timeout(Some(timeout))?;
    let mut reader = BufReader::new(DeadlineReader(stream, Instant::now() + timeout));
    if let Some(body_limit) = body_limit {
        parse_request(&mut reader, body_limit, true, true)
    } else {
        parse_request_head(&mut reader, true)
    }
}

fn parse_request_head(reader: &mut impl BufRead, allow_http_10: bool) -> Result<Request> {
    let (start, headers) = read_head(reader)?;
    let (method, path) = match start.split(' ').collect::<Vec<_>>().as_slice() {
        [method, path, version] if *version == "HTTP/1.1" || (allow_http_10 && *version == "HTTP/1.0") =>
            (method.to_string(), path.to_string()),
        _ => return Err(fail("invalid HTTP request line")),
    };
    Ok(Request { method, path, headers, body: Vec::new() })
}

fn parse_request(reader: &mut impl BufRead, body_limit: usize, allow_http_10: bool, allow_chunked: bool) -> Result<Request> {
    let Request { method, path, headers, .. } = parse_request_head(reader, allow_http_10)?;
    if headers.contains_key("expect") {
        return Err(fail("unsupported HTTP framing"));
    }
    if let Some(transfer) = headers.get("transfer-encoding") {
        if !allow_chunked || method != "POST" || !transfer.eq_ignore_ascii_case("chunked")
            || headers.contains_key("content-length") {
            return Err(fail("unsupported HTTP framing"));
        }
        let mut body = Vec::new();
        copy_chunked(reader, &mut body, body_limit as u64, false)?;
        return Ok(Request { method, path, headers, body });
    }
    let length = match headers.get("content-length") {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => value.parse()?,
        Some(_) => return Err(fail("invalid HTTP content length")),
        None => 0,
    };
    if length > body_limit { return Err(Box::new(BodyLimit)); }
    if method != "POST" && length != 0 {
        return Err(fail("unsupported HTTP body length"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Request { method, path, headers, body })
}

pub fn serve_workers(port: u16, count: usize, body_limit: usize,
    handle: impl Fn(&mut TcpStream, Request) + Send + Sync + 'static) -> Result<()> {
    serve_bound_workers(TcpListener::bind((Ipv4Addr::LOCALHOST, port))?, count, body_limit, || Ok(()), handle)
}

pub(crate) fn serve_bound_workers(listener: TcpListener, count: usize, body_limit: usize,
    tick: impl Fn() -> Result<()>, handle: impl Fn(&mut TcpStream, Request) + Send + Sync + 'static) -> Result<()> {
    serve_request_workers(listener, count, body_limit, false, "400 Bad Request", tick, handle)
}

pub(crate) fn serve_chunked_workers(port: u16, count: usize, body_limit: usize,
    handle: impl Fn(&mut TcpStream, Request) + Send + Sync + 'static) -> Result<()> {
    serve_request_workers(TcpListener::bind((Ipv4Addr::LOCALHOST, port))?, count, body_limit, true, "400 Bad Request", || Ok(()), handle)
}

pub(crate) fn serve_bound_form_workers(listener: TcpListener, count: usize, body_limit: usize,
    handle: impl Fn(&mut TcpStream, Request) + Send + Sync + 'static) -> Result<()> {
    serve_request_workers(listener, count, body_limit, true, "413 Content Too Large", || Ok(()), handle)
}

fn serve_request_workers(listener: TcpListener, count: usize, body_limit: usize, allow_chunked: bool, oversized_status: &'static str,
    tick: impl Fn() -> Result<()>, handle: impl Fn(&mut TcpStream, Request) + Send + Sync + 'static) -> Result<()> {
    install_stop_signals()?;
    listener.set_nonblocking(true)?;
    let (send, receive) = std::sync::mpsc::sync_channel::<TcpStream>(count);
    let receive = Arc::new(std::sync::Mutex::new(receive));
    let handle = Arc::new(handle);
    let mut workers = Vec::new();
    for _ in 0..count {
        let receive = Arc::clone(&receive);
        let handle = Arc::clone(&handle);
        workers.push(thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(move || {
            loop {
                let received = receive.lock().expect("HTTP worker queue").recv();
                let Ok(mut stream) = received else { break; };
                if stopping() { break; }
                let request = if allow_chunked {
                    let timeout = Duration::from_secs(3);
                    stream.set_write_timeout(Some(timeout)).map_err(Into::into).and_then(|()| {
                        let mut reader = BufReader::new(DeadlineReader(&mut stream, Instant::now() + timeout));
                        parse_request(&mut reader, body_limit, true, true)
                    })
                } else {
                    read_request(&mut stream, body_limit, true, false)
                };
                if stopping() { break; }
                match request {
                    Ok(request) => handle(&mut stream, request),
                    Err(error) if error.is::<BodyLimit>() => { let _ = send_error(&mut stream, oversized_status); }
                    Err(_) => { let _ = send_error(&mut stream, "400 Bad Request"); }
                }
            }
        })?);
    }
    println!("Encounter workspace http://{}", listener.local_addr()?);
    let mut result = Ok(());
    while !SIGNAL_STOP.load(Ordering::Acquire) {
        if let Err(error) = tick() { result = Err(error); break; }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(std::sync::mpsc::TrySendError::Full(mut stream)) = send.try_send(stream) {
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                    let _ = send_error(&mut stream, "503 Service Unavailable");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => { result = Err(error.into()); break; }
        }
    }
    drop(send);
    for worker in workers { let _ = worker.join(); }
    result
}

fn send_error(stream: &mut TcpStream, status: &str) -> Result<()> {
    send(stream, status, "text/plain", "")
}

pub fn read_head(reader: &mut impl BufRead) -> Result<(String, BTreeMap<String, String>)> {
    let (start, lines) = read_header_lines(reader)?;
    let mut headers = BTreeMap::new();
    for (name, value) in lines {
        if headers.insert(name, value).is_some() { return Err(fail("duplicate HTTP header")); }
    }
    Ok((start, headers))
}

pub fn read_header_lines(reader: &mut impl BufRead) -> Result<(String, Vec<(String, String)>)> {
    read_header_lines_bounded(reader, HEADER_LIMIT)
}

pub(super) fn read_header_lines_bounded(reader: &mut impl BufRead, mut remaining: u64) -> Result<(String, Vec<(String, String)>)> {
    let start = line(reader, &mut remaining)?;
    let mut headers = Vec::new();
    loop {
        let header = line(reader, &mut remaining)?;
        if header.is_empty() { return Ok((start, headers)); }
        let (key, value) = header.split_once(':').ok_or_else(|| fail("invalid HTTP header"))?;
        if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.bytes().any(|byte| byte.is_ascii_control() && byte != b'\t') {
            return Err(fail("invalid HTTP header"));
        }
        headers.push((key.to_ascii_lowercase(), value.trim().to_string()));
    }
}

pub(crate) fn single_header<'a>(headers: &'a [(String, String)], name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.iter().filter(|(key, _)| key == name).map(|(_, value)| value.as_str());
    let first = values.next();
    if values.next().is_some() { return Err(fail("duplicate HTTP framing or authority header")); }
    Ok(first)
}

pub(crate) fn read_response_head(reader: &mut impl BufRead) -> Result<(u16, Vec<(String, String)>)> {
    for _ in 0..5 {
        let (start, headers) = read_header_lines(reader)?;
        let mut fields = start.splitn(3, ' ');
        if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(fail("Invalid HTTP response version"));
        }
        let status = fields.next().filter(|value| value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| fail("Invalid HTTP response status"))?.parse()?;
        match status {
            100 | 102..=199 => continue,
            200..=599 => return Ok((status, headers)),
            _ => return Err(fail("Unsupported HTTP response status")),
        }
    }
    Err(fail("Too many informational HTTP responses"))
}

pub(crate) fn copy_response_body(reader: &mut impl BufRead, headers: &[(String, String)], writer: &mut impl Write, limit: u64)
    -> Result<()> {
    match (single_header(headers, "transfer-encoding")?, single_header(headers, "content-length")?) {
        (Some(value), None) if value.eq_ignore_ascii_case("chunked") => copy_chunked(reader, writer, limit, false)?,
        (None, Some(value)) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            let length = value.parse()?;
            if length > limit { return Err(BodyLimit.into()); }
            copy_exact(reader, writer, length)?;
        }
        (None, None) => {
            if io::copy(&mut reader.take(limit + 1), writer)? > limit { return Err(BodyLimit.into()); }
        }
        _ => return Err(fail("Invalid HTTP response framing")),
    }
    Ok(())
}

pub(crate) fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, size: u64) -> Result<()> {
    if io::copy(&mut reader.take(size), writer)? != size { return Err(fail("incomplete HTTP body")); }
    Ok(())
}

pub(crate) fn copy_chunked(reader: &mut impl BufRead, writer: &mut impl Write, mut limit: u64, framed: bool) -> Result<()> {
    let mut bytes = Vec::new();
    loop {
        bytes.clear();
        reader.take(1024).read_until(b'\n', &mut bytes)?;
        let size = bytes.strip_suffix(b"\r\n").and_then(|line| line.split(|byte| *byte == b';').next())
            .filter(|size| !size.is_empty() && size.iter().all(u8::is_ascii_hexdigit))
            .ok_or_else(|| fail("invalid HTTP chunk"))?;
        let size = u64::from_str_radix(std::str::from_utf8(size)?, 16)?;
        if size == 0 {
            let mut remaining = HEADER_LIMIT;
            while !line(reader, &mut remaining)?.is_empty() {}
            if framed { writer.write_all(b"0\r\n\r\n")?; }
            return Ok(());
        }
        limit = limit.checked_sub(size).ok_or(BodyLimit)?;
        if framed { write!(writer, "{size:x}\r\n")?; }
        copy_exact(reader, writer, size)?;
        let mut end = [0; 2];
        reader.read_exact(&mut end)?;
        if &end != b"\r\n" { return Err(fail("invalid chunk terminator")); }
        if framed { writer.write_all(&end)?; }
    }
}

fn decode(input: &[u8], form: bool) -> Result<String> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut input = input.iter();
    while let Some(&byte) = input.next() {
        decoded.push(match byte {
            b'+' if form => b' ',
            b'%' => {
                let hi = input.next().and_then(|&b| char::from(b).to_digit(16));
                let lo = input.next().and_then(|&b| char::from(b).to_digit(16));
                match (hi, lo) {
                    (Some(hi), Some(lo)) => (hi * 16 + lo) as u8,
                    _ => return Err(fail("invalid percent escape")),
                }
            }
            _ => byte,
        });
    }
    Ok(String::from_utf8(decoded)?)
}

pub(crate) fn decode_cookie(value: &str) -> Result<String> { decode(value.as_bytes(), false) }

pub(crate) fn cookie_fields(header: &str) -> impl Iterator<Item = (&str, &str)> {
    header.split(';').filter_map(|pair| pair.split_once('=')).map(|(name, value)| (name.trim(), value.trim()))
}

pub fn form(body: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    if body.is_empty() { return Ok(fields); }
    for pair in body.split(|&byte| byte == b'&') {
        let equals = pair.iter().position(|&byte| byte == b'=').ok_or_else(|| fail("invalid form field"))?;
        let key = decode(&pair[..equals], true)?;
        let value = decode(&pair[equals + 1..], true)?;
        if fields.insert(key, value).is_some() {
            return Err(fail("duplicate form field"));
        }
    }
    Ok(fields)
}

pub fn decode_path(path: &str) -> Result<String> {
    decode(path.as_bytes(), false)
}

pub fn send(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> Result<()> {
    send_headers(stream, status, content_type, "", body)
}

pub fn send_headers(stream: &mut TcpStream, status: &str, content_type: &str, headers: &str, body: &str) -> Result<()> {
    send_bytes(stream, status, &format!("{content_type}; charset=utf-8"), headers, body.as_bytes())
}

pub fn send_bytes(stream: &mut TcpStream, status: &str, content_type: &str, headers: &str, body: &[u8]) -> Result<()> {
    send_policy(stream, status, content_type, headers, body, "", "", "")
}

pub(crate) fn send_raster_html(stream: &mut TcpStream, status: &str, headers: &str, html: &str) -> Result<()> {
    write_response(stream, status, "text/html; charset=utf-8", headers, html.as_bytes(), RASTER_POLICY)
}

const RASTER_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; frame-src 'self'; form-action 'self'; frame-ancestors 'self'; base-uri 'none'";

pub(crate) fn begin_raster_stream(stream: &mut TcpStream, headers: &str, html: &str) -> Result<()> {
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Accel-Buffering: no\r\nContent-Security-Policy: {RASTER_POLICY}\r\n{headers}\r\n")?;
    stream.write_all(html.as_bytes())?;
    Ok(())
}

pub fn send_live_html(stream: &mut TcpStream, headers: &str, body: &str, origin: &str, review_media: bool) -> Result<()> {
    let ws = origin.strip_prefix("http://").ok_or_else(|| fail("expected loopback HTTP origin"))?;
    let media = if review_media { "; media-src 'self'" } else { "" };
    let live = format!("; script-src 'self'; connect-src 'self' ws://{ws}{media}");
    send_policy(stream, "200 OK", "text/html; charset=utf-8", headers, body.as_bytes(), &live, "", "")
}

pub fn send_gateway_notice(stream: &mut TcpStream, status: &str, html: &str, style_hash: &str) -> Result<()> {
    let style = format!(" 'sha256-{style_hash}'");
    send_policy(stream, status, "text/html; charset=utf-8", "Referrer-Policy: no-referrer\r\n",
        html.as_bytes(), "", &style, "")
}

pub(crate) fn send_oauth_form(stream: &mut TcpStream, headers: &str, body: &[u8], origin: &str) -> Result<()> {
    send_policy(stream, "200 OK", "text/html; charset=utf-8", headers, body, "", "", &format!(" {origin}"))
}

fn send_policy(stream: &mut TcpStream, status: &str, content_type: &str, headers: &str, body: &[u8], live: &str, style: &str, form: &str) -> Result<()> {
    let policy = format!("default-src 'none'; style-src 'self'{style}; form-action 'self'{form}; frame-ancestors 'none'; base-uri 'none'{live}");
    write_response(stream, status, content_type, headers, body, &policy)
}

pub(crate) fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, headers: &str, body: &[u8], policy: &str) -> Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
        Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
        Content-Security-Policy: {policy}\r\n{headers}\r\n", body.len())?;
    stream.write_all(body)?;
    Ok(())
}

pub fn serve(port: u16, tick: impl Fn(), handle: impl Fn(&str, &mut TcpStream, Request) -> Result<()>) -> Result<()> {
    serve_loop(port, true, tick, handle)
}

pub fn serve_gateway(port: u16, handle: impl Fn(&str, &mut TcpStream, Request) -> Result<()>) -> Result<()> {
    serve_loop(port, false, || {}, handle)
}

fn serve_loop(port: u16, require_loopback_host: bool, tick: impl Fn(), handle: impl Fn(&str, &mut TcpStream, Request) -> Result<()>) -> Result<()> {
    install_stop_signals()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let closing = Arc::new(AtomicBool::new(false));
    let requested = Arc::clone(&closing);
    thread::spawn(move || {
        for line in io::stdin().lock().lines().map_while(std::result::Result::ok) {
            if line.trim() == "close" {
                requested.store(true, Ordering::Release);
                break;
            }
        }
    });
    let host = address.to_string();
    let origin = format!("http://{host}");
    println!("Encounter {origin}");
    io::stdout().flush()?;

    while !closing.load(Ordering::Acquire) && !SIGNAL_STOP.load(Ordering::Acquire) {
        tick();
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        stream.set_nonblocking(false)?;
        let result = match read(&mut stream) {
            Ok(request) if !require_loopback_host || request.headers.get("host") == Some(&host) => handle(&origin, &mut stream, request),
            Ok(_) => send(&mut stream, "403 Forbidden", "text/plain", "Wrong host."),
            Err(_) => send(&mut stream, "400 Bad Request", "text/plain", "Invalid request."),
        };
        if let Err(error) = result {
            eprintln!("{error}");
            let _ = send(&mut stream, "500 Internal Server Error", "text/plain", "Unable to load this view. Reopen the page and try again.");
        }
    }
    Ok(())
}

pub struct Upload {
    pub field: String,
    pub filename: String,
    pub text: String,
}

pub fn multipart(content_type: &str, body: &[u8]) -> Result<(BTreeMap<String, String>, Option<Upload>)> {
    let invalid = || fail("invalid multipart form");
    let boundary = content_type.strip_prefix("multipart/form-data; boundary=").ok_or_else(invalid)?;
    if boundary.is_empty() || boundary.len() > 70 || !boundary.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(invalid());
    }
    let marker = format!("--{boundary}");
    let delimiter = format!("\r\n{marker}");
    let mut remaining = std::str::from_utf8(body)?.strip_prefix(&marker).ok_or_else(invalid)?;
    let mut fields = BTreeMap::new();
    let mut upload = None;
    while remaining != "--\r\n" && remaining != "--" {
        let (headers, content) = remaining.strip_prefix("\r\n").and_then(|part| part.split_once("\r\n\r\n")).ok_or_else(invalid)?;
        let (value, rest) = content.split_once(&delimiter).ok_or_else(invalid)?;
        let mut lines = headers.split("\r\n");
        let disposition = lines.next().and_then(|line| line.strip_prefix("Content-Disposition: form-data; name=\"")).ok_or_else(invalid)?;
        let (name, suffix) = disposition.split_once('"').ok_or_else(invalid)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) {
            return Err(invalid());
        }
        if suffix.is_empty() {
            if lines.next().is_some() || fields.insert(name.to_owned(), value.to_owned()).is_some() {
                return Err(invalid());
            }
        } else {
            let filename = suffix.strip_prefix("; filename=\"").and_then(|part| part.strip_suffix('"')).ok_or_else(invalid)?;
            if upload.is_some() || filename.is_empty() || filename.len() > 240
                || filename.chars().any(|c| c.is_control() || matches!(c, '"' | '/' | '\\'))
                || lines.next().is_none_or(|line| !line.starts_with("Content-Type: "))
                || lines.next().is_some()
            {
                return Err(invalid());
            }
            upload = Some(Upload { field: name.to_owned(), filename: filename.to_owned(), text: value.to_owned() });
        }
        remaining = rest;
    }
    if upload.as_ref().is_some_and(|file| fields.contains_key(&file.field)) { return Err(invalid()); }
    Ok((fields, upload))
}
