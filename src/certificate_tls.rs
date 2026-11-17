use crate::{Result, fail, http, x509::{Certificate, PrivateKey}};
use std::{
    ffi::{CStr, c_int, c_long, c_void}, io::{self, BufReader, Read},
    net::{Ipv4Addr, TcpStream}, os::fd::AsRawFd, ptr::{self, NonNull}, time::{Duration, Instant},
};

#[link(name = "libssl.so.3", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn TLS_client_method() -> *const c_void;
    #[cfg(test)]
    fn TLS_server_method() -> *const c_void;
    fn SSL_CTX_new(method: *const c_void) -> *mut c_void;
    fn SSL_CTX_free(context: *mut c_void);
    fn SSL_CTX_ctrl(context: *mut c_void, command: c_int, argument: c_long, value: *mut c_void) -> c_long;
    fn SSL_CTX_use_certificate(context: *mut c_void, certificate: *mut c_void) -> c_int;
    fn SSL_CTX_use_PrivateKey(context: *mut c_void, key: *mut c_void) -> c_int;
    fn SSL_CTX_check_private_key(context: *const c_void) -> c_int;
    fn SSL_CTX_get_cert_store(context: *const c_void) -> *mut c_void;
    fn SSL_CTX_load_verify_locations(context: *mut c_void, ca_file: *const libc::c_char, ca_path: *const libc::c_char) -> c_int;
    fn SSL_CTX_set_verify(context: *mut c_void, mode: c_int, callback: *const c_void);
    fn SSL_new(context: *mut c_void) -> *mut c_void;
    fn SSL_free(session: *mut c_void);
    fn SSL_ctrl(session: *mut c_void, command: c_int, argument: c_long, value: *mut c_void) -> c_long;
    fn SSL_set_fd(session: *mut c_void, fd: c_int) -> c_int;
    fn SSL_set1_host(session: *mut c_void, host: *const libc::c_char) -> c_int;
    fn SSL_connect(session: *mut c_void) -> c_int;
    #[cfg(test)]
    fn SSL_accept(session: *mut c_void) -> c_int;
    fn SSL_get_error(session: *const c_void, returned: c_int) -> c_int;
    fn SSL_get1_peer_certificate(session: *const c_void) -> *mut c_void;
    fn SSL_read(session: *mut c_void, buffer: *mut c_void, length: c_int) -> c_int;
    fn SSL_write(session: *mut c_void, buffer: *const c_void, length: c_int) -> c_int;
}

#[link(name = "libcrypto.so.3", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn X509_STORE_add_cert(store: *mut c_void, cert: *mut c_void) -> c_int;
    fn ERR_clear_error();
}

struct Context(NonNull<c_void>);
impl Drop for Context { fn drop(&mut self) { unsafe { SSL_CTX_free(self.0.as_ptr()) } } }

impl Context {
    fn new() -> Result<Self> {
        let context = Self(NonNull::new(unsafe { SSL_CTX_new(TLS_client_method()) })
            .ok_or_else(|| fail("Cannot allocate TLS client context"))?);
        let ctx = context.0.as_ptr();
        unsafe {
            if SSL_CTX_ctrl(ctx, 123, 0x0303, ptr::null_mut()) != 1 { // Minimum TLS version 1.2.
                return Err(fail("Cannot set minimum TLS version"));
            }
            SSL_CTX_set_verify(ctx, 1, ptr::null()); // Require a verified server certificate.
        }
        Ok(context)
    }

    fn trust_bundle(&self, ca_file: &CStr) -> Result<()> {
        if unsafe { SSL_CTX_load_verify_locations(self.0.as_ptr(), ca_file.as_ptr(), ptr::null()) } != 1 {
            return Err(fail("Cannot load the host TLS trust bundle"));
        }
        Ok(())
    }

    fn managed_identity(&self, issuer: &Certificate, desktop: &Certificate, key: &PrivateKey) -> Result<()> {
        let ctx = self.0.as_ptr();
        if unsafe { SSL_CTX_use_certificate(ctx, desktop.as_ptr()) != 1 || SSL_CTX_use_PrivateKey(ctx, key.as_ptr()) != 1
            || SSL_CTX_check_private_key(ctx) != 1 || X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), issuer.as_ptr()) != 1 } {
            return Err(fail("Invalid managed TLS client credentials"));
        }
        Ok(())
    }
}

struct Session { ssl: NonNull<c_void>, socket: TcpStream, deadline: Instant, restoring: bool }
impl Drop for Session { fn drop(&mut self) { unsafe { SSL_free(self.ssl.as_ptr()) } } }

impl Session {
    fn connect(context: &Context, port: u16, host: &CStr, timeout: Duration, restoring: bool) -> Result<Self> {
        http::check_interruption(restoring)?;
        let deadline = Instant::now() + timeout;
        let socket = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), timeout)?;
        socket.set_nonblocking(true)?;
        let ssl = NonNull::new(unsafe { SSL_new(context.0.as_ptr()) }).ok_or_else(|| fail("Cannot allocate TLS session"))?;
        let session = Self { ssl, socket, deadline, restoring };
        let ssl = session.ssl.as_ptr();
        if unsafe { SSL_set_fd(ssl, session.socket.as_raw_fd()) != 1 || SSL_set1_host(ssl, host.as_ptr()) != 1
            || SSL_ctrl(ssl, 55, 0, host.as_ptr().cast_mut().cast()) != 1 } { // Send the same host as SNI.
            return Err(fail("Invalid TLS listener identity"));
        }
        session.perform(|ssl| unsafe { SSL_connect(ssl) }, false)?;
        Ok(session)
    }

    fn send(&self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let length = bytes.len().min(c_int::MAX as usize) as c_int;
            let sent = self.perform(|ssl| unsafe { SSL_write(ssl, bytes.as_ptr().cast(), length) }, false)?;
            bytes = &bytes[sent..];
        }
        Ok(())
    }

    fn perform(&self, mut operation: impl FnMut(*mut c_void) -> c_int, reading: bool) -> io::Result<usize> {
        loop {
            http::check_interruption(self.restoring)?;
            let left = self.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() { return Err(io::ErrorKind::TimedOut.into()); }
            let ssl = self.ssl.as_ptr();
            unsafe { ERR_clear_error(); }
            let returned = operation(ssl);
            if returned > 0 { return Ok(returned as usize); }
            let events = match unsafe { SSL_get_error(ssl, returned) } {
                2 => libc::POLLIN,
                3 => libc::POLLOUT,
                6 if reading => return Ok(0),
                _ => return Err(io::Error::other("Managed TLS handshake or transfer failed")),
            };
            let mut descriptor = libc::pollfd { fd:self.socket.as_raw_fd(), events, revents:0 };
            if unsafe { libc::poll(&mut descriptor, 1, left.as_millis().clamp(1,100) as c_int) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
            }
        }
    }
}

impl Read for Session {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() { return Ok(0); }
        let length = buffer.len().min(c_int::MAX as usize) as c_int;
        self.perform(|ssl| unsafe { SSL_read(ssl, buffer.as_mut_ptr().cast(), length) }, true)
    }
}

#[cfg(test)]
pub(crate) fn reply_fixture(socket: TcpStream, certificate: &str, key: &[u8], response: &[u8]) -> Result<()> {
    let context = Context(NonNull::new(unsafe { SSL_CTX_new(TLS_server_method()) })
        .ok_or_else(|| fail("Cannot allocate TLS fixture context"))?);
    let certificate = Certificate::from_pem(certificate)?;
    let key = PrivateKey::from_pem(key)?;
    let ctx = context.0.as_ptr();
    if unsafe { SSL_CTX_use_certificate(ctx, certificate.as_ptr()) != 1 || SSL_CTX_use_PrivateKey(ctx, key.as_ptr()) != 1 } {
        return Err(fail("Invalid TLS fixture credentials"));
    }
    socket.set_nonblocking(true)?;
    let ssl = NonNull::new(unsafe { SSL_new(ctx) }).ok_or_else(|| fail("Cannot allocate TLS fixture session"))?;
    let session = Session { ssl, socket, deadline: Instant::now() + Duration::from_secs(5), restoring: false };
    if unsafe { SSL_set_fd(ssl.as_ptr(), session.socket.as_raw_fd()) } != 1 {
        return Err(fail("Cannot attach TLS fixture socket"));
    }
    session.perform(|ssl| unsafe { SSL_accept(ssl) }, false)?;
    let mut reader = BufReader::new(session);
    let (line, headers) = http::read_head(&mut reader)?;
    assert_eq!(line, "GET /keys HTTP/1.1");
    assert_eq!(headers["accept"], "application/json");
    reader.get_ref().send(response)
}

pub(crate) fn probe(port: u16, host: &CStr, issuer: &Certificate, desktop: &Certificate, key: &PrivateKey, restoring: bool)
    -> Result<(u16, String)> {
    let context = Context::new()?;
    context.managed_identity(issuer, desktop, key)?;
    let session = Session::connect(&context, port, host, Duration::from_secs(1), restoring)?;
    let peer = unsafe { Certificate::take_peer(SSL_get1_peer_certificate(session.ssl.as_ptr()))? };
    let hostname = host.to_str()?;
    let request = format!("GET / HTTP/1.1\r\nHost: {hostname}:{port}\r\nConnection: close\r\n\r\n");
    session.send(request.as_bytes())?;
    let mut response = BufReader::new(session);
    let (status, headers) = http::read_response_head(&mut response)?;
    if status == 200 {
        http::copy_response_body(&mut response, &headers, &mut io::sink(), 1_048_576)?;
    }
    Ok((status, peer.fingerprint().to_owned()))
}

pub(crate) fn ingress_status(host: &CStr, path: &str, restoring: bool) -> Result<u16> {
    let context = Context::new()?;
    context.trust_bundle(c"/etc/ssl/certs/ca-certificates.crt")?;
    ingress_response(&context, 443, host, path, restoring)
}

fn ingress_response(context: &Context, port: u16, host: &CStr, path: &str, restoring: bool) -> Result<u16> {
    let session = Session::connect(context, port, host, Duration::from_secs(2), restoring)?;
    let hostname = host.to_str()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n");
    session.send(request.as_bytes())?;
    let mut response = BufReader::new(session);
    let (status, headers) = http::read_response_head(&mut response)?;
    if !matches!(status, 204 | 304) {
        http::copy_response_body(&mut response, &headers, &mut io::sink(), 8 * 1024 * 1024)?;
    }
    Ok(status)
}

#[cfg(test)]
#[test]
#[ignore = "requires a disposable loopback TLS listener and CA"]
fn ingress_tls_rejects_wrong_identity_and_allows_interrupted_rollback() -> Result<()> {
    use std::{env, ffi::CString, os::unix::ffi::OsStrExt};

    let port = env::var("ENCOUNTER_TEST_INGRESS_PORT")?.parse()?;
    let ca = env::var_os("ENCOUNTER_TEST_INGRESS_CA").ok_or_else(|| fail("Expected a fixture CA file"))?;
    let context = Context::new()?;
    let host = c"mcp.sourcerytech.com.au";
    let path = "/shop/identity";
    assert!(ingress_response(&context, port, host, path, false).is_err());
    context.trust_bundle(&CString::new(ca.as_bytes())?)?;
    assert!(ingress_response(&context, port, c"appdev.sourcerytech.com.au", path, false).is_err());
    assert_eq!(ingress_response(&context, port, host, path, false)?, 403);
    assert!(ingress_response(&context, port, host, path, false).is_err());

    let _supervisor = crate::appdev_host_process::Supervisor::new();
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    assert!(http::check_interruption(false).is_err());
    assert!(ingress_response(&context, port, host, path, false).is_err());
    assert_eq!(ingress_response(&context, port, host, path, true)?, 400);
    Ok(())
}
