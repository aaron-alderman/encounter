use crate::{Result, fail, http};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet}, io::{self, BufRead, BufReader, Read, Write}, net::{Shutdown, SocketAddr, TcpStream},
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}}, time::{Duration, Instant},
};

const HEADER_LIMIT: u64 = 16 * 1024;
type Headers = [(String, String)];

pub(super) struct Route {
    address: SocketAddr,
    leases: Mutex<BTreeMap<usize, Sockets>>,
    next: AtomicUsize,
    closed: AtomicBool,
}

impl Route {
    pub(super) fn new(address: SocketAddr) -> Arc<Self> {
        Arc::new(Self { address, leases: Mutex::new(BTreeMap::new()), next: AtomicUsize::new(0), closed: AtomicBool::new(false) })
    }

    pub(super) fn lease(self: &Arc<Self>, socket: &TcpStream) -> io::Result<Lease> {
        let number = self.next.fetch_add(1, Ordering::Relaxed);
        let mut leases = self.leases.lock().unwrap();
        if self.closed.load(Ordering::Acquire) { return Err(io::ErrorKind::ConnectionAborted.into()); }
        leases.insert(number, Sockets { client: socket.try_clone()?, upstream: None });
        Ok(Lease { route: Arc::clone(self), number })
    }

    pub(super) fn idle(&self) -> bool { self.leases.lock().unwrap().is_empty() }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for sockets in self.leases.lock().unwrap().values() {
            let _ = sockets.client.shutdown(Shutdown::Both);
            if let Some(upstream) = &sockets.upstream { let _ = upstream.shutdown(Shutdown::Both); }
        }
    }
}

struct Sockets { client: TcpStream, upstream: Option<TcpStream> }

pub(super) struct Lease { route: Arc<Route>, number: usize }

impl Lease {
    fn upstream(&self, socket: &TcpStream) -> io::Result<()> {
        let mut leases = self.route.leases.lock().unwrap();
        if self.route.closed.load(Ordering::Acquire) { return Err(io::ErrorKind::ConnectionAborted.into()); }
        leases.get_mut(&self.number).unwrap().upstream = Some(socket.try_clone()?);
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) { self.route.leases.lock().unwrap().remove(&self.number); }
}

pub(super) struct Forwarding {
    connection: String,
    strip: BTreeSet<String>,
    request: BTreeMap<String, String>,
    response: BTreeMap<String, String>,
}

impl Forwarding {
    pub(super) fn new(value: &Value) -> Result<Self> {
        Ok(Self {
            connection: value["connectionHeader"].as_str().ok_or_else(|| fail("Missing hosted connection header policy"))?.into(),
            strip: serde_json::from_value(value["strip"].clone())?,
            request: serde_json::from_value(value["request"].clone())?,
            response: serde_json::from_value(value["response"].clone())?,
        })
    }

    fn headers(&self, headers: &Headers, upstream: Option<SocketAddr>, output: &mut impl Write) -> Result<()> {
        let nominated: BTreeSet<String> = headers.iter().filter(|(name, _)| name == &self.connection)
            .flat_map(|(_, value)| value.split(',').map(|value| value.trim().to_ascii_lowercase())).collect();
        let fixed = if upstream.is_some() { &self.request } else { &self.response };
        for (name, value) in headers {
            if self.strip.contains(name) || nominated.contains(name) || fixed.contains_key(name)
                || matches!(name.as_str(), "content-length" | "expect") { continue; }
            write!(output, "{name}: {value}\r\n")?;
        }
        if let Some(address) = upstream
            && (nominated.contains("host") || !headers.iter().any(|(name, _)| name == "host")) {
            write!(output, "Host: {address}\r\n")?;
        }
        for (name, value) in fixed { write!(output, "{name}: {value}\r\n")?; }
        Ok(())
    }
}

enum Body { Empty, Sized(u64), Chunked }

impl Body {
    fn read(headers: &Headers) -> Result<Self> {
        Ok(match (http::single_header(headers, "content-length")?, http::single_header(headers, "transfer-encoding")?) {
            (None, None) => Self::Empty,
            (Some(length), None) if !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit()) =>
                Self::Sized(length.parse()?),
            (None, Some(value)) if value.eq_ignore_ascii_case("chunked") => Self::Chunked,
            _ => return Err(fail("Invalid hosted HTTP framing")),
        })
    }

    fn header(&self, output: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Sized(length) => write!(output, "Content-Length: {length}\r\n"),
            Self::Chunked => output.write_all(b"Transfer-Encoding: chunked\r\n"),
        }
    }

    fn copy(&self, input: &mut impl BufRead, output: &mut impl Write) -> Result<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Sized(length) => http::copy_exact(input, output, *length),
            Self::Chunked => http::copy_chunked(input, output, u64::MAX, true),
        }
    }
}

pub(super) fn unavailable(client: &mut TcpStream) -> Result<()> {
    http::send_headers(client, "503 Service Unavailable", "application/json; charset=utf-8", "Cache-Control: no-store\r\n",
        "{\"error\":{\"code\":\"generation-unavailable\",\"message\":\"The active hosted generation is unavailable.\"}}\n")
}

struct RequestStream { socket: TcpStream, deadline: Instant }

impl Read for RequestStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        http::read_until_deadline(&mut self.socket, self.deadline, bytes, true)
    }
}

pub(super) fn serve(client: TcpStream, active: impl FnOnce(&TcpStream) -> Result<Option<Lease>>,
    forwarding: &Forwarding, timeout: Duration) -> Result<()> {
    let accepted = Instant::now();
    client.set_write_timeout(Some(timeout))?;
    let mut client = BufReader::new(RequestStream { socket: client, deadline: accepted + timeout.min(Duration::from_secs(10)) });
    let request = (|| {
        let (start, headers) = http::read_header_lines_bounded(&mut client, HEADER_LIMIT)?;
        let fields: Vec<_> = start.split(' ').collect();
        let [method, path, version] = fields.as_slice() else { return Err(fail("Invalid hosted HTTP request line")); };
        if !matches!(*version, "HTTP/1.1" | "HTTP/1.0") || method.is_empty()
            || !method.bytes().all(|byte| byte.is_ascii_uppercase() || byte == b'-')
            || path.is_empty() || path.bytes().any(|byte| byte.is_ascii_control())
            || (*version == "HTTP/1.1" && http::single_header(&headers, "host")?.is_none()) {
            return Err(fail("Invalid hosted HTTP request"));
        }
        let body = Body::read(&headers)?;
        Ok((method.to_string(), path.to_string(), headers, body))
    })();
    let Ok((method, path, headers, body)) = request else {
        return http::send(&mut client.get_mut().socket, "400 Bad Request", "text/plain", "");
    };
    let expect = http::single_header(&headers, "expect")?;
    if expect.is_some_and(|value| !value.eq_ignore_ascii_case("100-continue")) {
        return http::send(&mut client.get_mut().socket, "417 Expectation Failed", "text/plain", "");
    }
    let Some(lease) = active(&client.get_ref().socket)? else { return unavailable(&mut client.get_mut().socket); };
    let Ok(mut upstream) = TcpStream::connect_timeout(&lease.route.address, timeout.min(Duration::from_secs(1))) else {
        return unavailable(&mut client.get_mut().socket);
    };
    lease.upstream(&upstream)?;
    client.get_mut().deadline = accepted + timeout;
    upstream.set_write_timeout(Some(timeout))?;
    write!(upstream, "{method} {path} HTTP/1.1\r\nConnection: close\r\n")?;
    forwarding.headers(&headers, Some(lease.route.address), &mut upstream)?;
    body.header(&mut upstream)?;
    upstream.write_all(b"\r\n")?;
    if expect.is_some() { client.get_mut().socket.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?; }
    body.copy(&mut client, &mut upstream)?;

    let mut upstream = BufReader::new(upstream);
    let response = (|| {
        for _ in 0..5 {
            let (status, headers) = http::read_header_lines_bounded(&mut upstream, HEADER_LIMIT)?;
            if status.bytes().any(|byte| byte.is_ascii_control()) { break; }
            let mut fields = status.splitn(3, ' ');
            if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) { break; }
            match fields.next().filter(|value| value.len() == 3).and_then(|value| value.parse::<u16>().ok()) {
                Some(100 | 102..=199) => continue,
                Some(code @ 200..=599) => return Ok((status, code, Body::read(&headers)?, headers)),
                _ => break,
            }
        }
        Err(fail("Invalid hosted generation response"))
    })();
    let Ok((status, code, response_body, headers)) = response else { return unavailable(&mut client.get_mut().socket); };
    let client = &mut client.get_mut().socket;
    write!(client, "{status}\r\nConnection: close\r\n")?;
    forwarding.headers(&headers, None, client)?;
    response_body.header(client)?;
    client.write_all(b"\r\n")?;
    if method != "HEAD" && !matches!(code, 204 | 304) {
        match response_body {
            Body::Empty => { io::copy(&mut upstream, client)?; }
            body => body.copy(&mut upstream, client)?,
        }
    }
    Ok(())
}
