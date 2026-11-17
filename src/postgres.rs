use crate::{Result, fail, http};
use serde_json::Value;
use std::{ffi::{CStr, CString, c_char, c_int, c_void}, io, os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path, ptr::{self, NonNull}, time::{Duration, Instant}};

#[link(name = "libpq.so.5", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn PQconnectdbParams(keys: *const *const c_char, values: *const *const c_char, expand: c_int) -> *mut c_void;
    fn PQconnectStartParams(keys: *const *const c_char, values: *const *const c_char, expand: c_int) -> *mut c_void;
    fn PQconnectPoll(connection: *mut c_void) -> c_int;
    fn PQstatus(connection: *mut c_void) -> c_int;
    fn PQerrorMessage(connection: *mut c_void) -> *const c_char;
    fn PQfinish(connection: *mut c_void);
    fn PQsocket(connection: *mut c_void) -> c_int;
    fn PQserverVersion(connection: *mut c_void) -> c_int;
    fn PQsendQueryParams(connection: *mut c_void, command: *const c_char, count: c_int, types: *const u32,
        values: *const *const c_char, lengths: *const c_int, formats: *const c_int, result_format: c_int) -> c_int;
    fn PQconsumeInput(connection: *mut c_void) -> c_int;
    fn PQisBusy(connection: *mut c_void) -> c_int;
    fn PQgetResult(connection: *mut c_void) -> *mut c_void;
    fn PQresultStatus(result: *mut c_void) -> c_int;
    fn PQcmdStatus(result: *mut c_void) -> *const c_char;
    fn PQntuples(result: *mut c_void) -> c_int;
    fn PQnfields(result: *mut c_void) -> c_int;
    fn PQgetisnull(result: *mut c_void, row: c_int, column: c_int) -> c_int;
    fn PQgetlength(result: *mut c_void, row: c_int, column: c_int) -> c_int;
    fn PQgetvalue(result: *mut c_void, row: c_int, column: c_int) -> *const c_char;
    fn PQclear(result: *mut c_void);
}

pub(crate) struct Connection(NonNull<c_void>, Option<Instant>);

#[derive(Debug)]
struct PeerRejected;

impl std::fmt::Display for PeerRejected {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("Local PostgreSQL rejected Unix peer authentication")
    }
}

impl std::error::Error for PeerRejected {}

impl Drop for Connection {
    fn drop(&mut self) { unsafe { PQfinish(self.0.as_ptr()); } }
}

struct Row(NonNull<c_void>);

impl Drop for Row {
    fn drop(&mut self) { unsafe { PQclear(self.0.as_ptr()); } }
}

impl Connection {
    pub(super) fn server_version(&self) -> i32 { unsafe { PQserverVersion(self.0.as_ptr()) } }

    pub(super) fn peer_uid(&self) -> Result<u32> {
        Ok(unix_peer(unsafe { PQsocket(self.0.as_ptr()) })?.uid)
    }

    pub(super) fn rejects_peer(socket: &Path, port: u16, database: &str, role: &str) -> Result<bool> {
        match Self::open(socket, port, database, role) {
            Ok(_) => Ok(false),
            Err(error) if error.is::<PeerRejected>() => Ok(true),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn open(socket: &Path, port: u16, database: &str, role: &str) -> Result<Self> {
        Self::connect(socket, port, database, role,
            c"-c default_transaction_read_only=on -c statement_timeout=3000 -c search_path=pg_catalog", None)
    }

    pub(super) fn open_readiness(socket: &Path, port: u16, database: &str, role: &str,
        timeout: Duration, deadline: Option<Instant>) -> Result<Self> {
        let mut connection = Self::connect(socket, port, database, role,
            c"-c default_transaction_read_only=on -c statement_timeout=3000 -c search_path=pg_catalog",
            Some(deadline.map_or(timeout, |end| end.saturating_duration_since(Instant::now()).min(timeout))))?;
        connection.1 = deadline;
        Ok(connection)
    }

    pub(crate) fn open_write(socket: &Path, port: u16, database: &str, role: &str) -> Result<Self> {
        Self::connect(socket, port, database, role,
            c"-c default_transaction_read_only=off -c statement_timeout=3000 -c search_path=pg_catalog", None)
    }

    fn connect(socket: &Path, port: u16, database: &str, role: &str, options: &CStr,
        timeout: Option<Duration>) -> Result<Self> {
        let identifier = |value: &str| !value.is_empty() && value.len() <= 63
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !socket.is_absolute() || socket.canonicalize()? != socket || !socket.is_dir()
            || socket.as_os_str().as_bytes().contains(&b',') || port == 0 || !identifier(database) || !identifier(role)
            || socket.metadata()?.mode() & 0o002 != 0
        {
            return Err(fail("Expected a canonical PostgreSQL socket directory with protected permissions and a named access role"));
        }
        if ["PGHOSTADDR", "PGSERVICE"].iter().any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty())) {
            return Err(fail("Local PostgreSQL refuses PostgreSQL address and service environment overrides"));
        }
        let socket = CString::new(socket.as_os_str().as_bytes())?;
        let port = CString::new(port.to_string())?;
        let database = CString::new(database)?;
        let role = CString::new(role)?;
        let entries = [(c"host", socket.as_c_str()), (c"port", &port), (c"dbname", &database), (c"user", &role),
            (c"sslmode", c"disable"), (c"gssencmode", c"disable"), (c"connect_timeout", c"3"),
            (c"require_auth", c"none"), (c"passfile", c"/proc/self/no-sourcery-pgpass"), (c"client_encoding", c"UTF8"),
            (c"options", options)];
        let keys: Vec<_> = entries.iter().map(|(key, _)| key.as_ptr()).chain([ptr::null()]).collect();
        let values: Vec<_> = entries.iter().map(|(_, value)| value.as_ptr()).chain([ptr::null()]).collect();
        http::check_interruption(false)?;
        let handle = unsafe {
            if timeout.is_some() { PQconnectStartParams(keys.as_ptr(), values.as_ptr(), 0) }
            else { PQconnectdbParams(keys.as_ptr(), values.as_ptr(), 0) }
        };
        let connection = Self(NonNull::new(handle)
            .ok_or_else(|| fail("Could not allocate the local PostgreSQL connection"))?, None);
        if let Some(timeout) = timeout { connection.wait_connect(timeout)?; }
        let handle = connection.0.as_ptr();
        if unsafe { PQstatus(handle) } != 0 {
            // Pre-16 servers lack SYSTEM_USER. Distinguish an explicit peer
            // rejection from an unavailable socket or a different HBA rule.
            let diagnostic = unsafe { CStr::from_ptr(PQerrorMessage(handle)) }.to_bytes();
            let message = format!("Peer authentication failed for user \"{}\"", role.to_string_lossy());
            if diagnostic.windows(message.len()).any(|bytes| bytes == message.as_bytes()) {
                return Err(Box::new(PeerRejected));
            }
            return Err(fail("Could not connect to the local PostgreSQL using its named authority role"));
        }
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
        if unsafe { libc::getpeername(PQsocket(handle), (&mut peer as *mut libc::sockaddr_storage).cast(), &mut length) } != 0
            || c_int::from(peer.ss_family) != libc::AF_UNIX
        {
            return Err(fail("Local PostgreSQL requires a PostgreSQL Unix-socket peer"));
        }
        Ok(connection)
    }

    fn wait_connect(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let handle = self.0.as_ptr();
        if unsafe { PQstatus(handle) } == 1 { return Ok(()); }
        let mut events = libc::POLLOUT;
        loop {
            let mut socket = libc::pollfd { fd: unsafe { PQsocket(handle) }, events, revents: 0 };
            if socket.fd < 0 { return Err(fail("Missing local PostgreSQL connection socket")); }
            loop {
                http::check_interruption(false)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() { return Err(fail("Local PostgreSQL connection timed out")); }
                let wait = remaining.as_millis().clamp(1, 100) as c_int;
                let result = unsafe { libc::poll(&mut socket, 1, wait) };
                if result > 0 { break; }
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return Err(fail("Could not wait for the local PostgreSQL connection"));
                }
            }
            events = match unsafe { PQconnectPoll(handle) } {
                0 | 3 => return Ok(()), // The caller checks libpq's final connection status.
                1 => libc::POLLIN,
                2 => libc::POLLOUT,
                _ => return Err(fail("Unexpected local PostgreSQL connection state")),
            };
        }
    }

    pub(crate) fn command(&self, query: &CStr, expected_tag: &CStr) -> Result<()> {
        let result = self.execute(query, &[], 1)?;
        if unsafe { CStr::from_ptr(PQcmdStatus(result.0.as_ptr())) } != expected_tag {
            return Err(fail("Local PostgreSQL command did not complete as expected"));
        }
        Ok(())
    }

    fn wait_result(&self, deadline: Instant) -> Result<()> {
        let handle = self.0.as_ptr();
        let mut socket = libc::pollfd { fd: unsafe { PQsocket(handle) }, events: libc::POLLIN, revents: 0 };
        while unsafe { PQisBusy(handle) } == 1 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if http::check_interruption(false).is_err() || remaining.is_zero() {
                return Err(fail("Local PostgreSQL operation interrupted or timed out"));
            }
            let ready = unsafe { libc::poll(&mut socket, 1, remaining.as_millis().clamp(1, 100) as c_int) };
            if ready < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                || ready > 0 && unsafe { PQconsumeInput(handle) } != 1 {
                return Err(fail("Could not read the local PostgreSQL response"));
            }
        }
        http::check_interruption(false)?;
        Ok(())
    }

    fn execute(&self, query: &CStr, parameters: &[&str], expected_status: c_int) -> Result<Row> {
        http::check_interruption(false)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let deadline = self.1.map_or(deadline, |startup| startup.min(deadline));
        if Instant::now() >= deadline { return Err(fail("Local PostgreSQL operation timed out")); }
        let parameters = parameters.iter().map(|value| CString::new(*value))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let values: Vec<_> = parameters.iter().map(|value| value.as_ptr()).collect();
        let handle = self.0.as_ptr();
        if unsafe { PQsendQueryParams(handle, query.as_ptr(), values.len() as c_int, ptr::null(),
            values.as_ptr(), ptr::null(), ptr::null(), 0) } != 1 {
            return Err(fail("Could not request the local PostgreSQL operation"));
        }
        self.wait_result(deadline)?;
        let row = Row(NonNull::new(unsafe { PQgetResult(handle) })
            .ok_or_else(|| fail("Missing local PostgreSQL result"))?);
        if unsafe { PQresultStatus(row.0.as_ptr()) } != expected_status {
            return Err(fail("Local PostgreSQL operation did not complete"));
        }
        self.wait_result(deadline)?;
        if let Some(extra) = NonNull::new(unsafe { PQgetResult(handle) }) {
            drop(Row(extra));
            return Err(fail("Local PostgreSQL operation produced an unexpected extra result"));
        }
        Ok(row)
    }

    pub(crate) fn document(&self, query: &CStr, parameters: &[&str], limit: usize) -> Result<Value> {
        let row = self.execute(query, parameters, 2)?;
        let result = row.0.as_ptr();
        if unsafe { PQntuples(result) != 1 || PQnfields(result) != 1 || PQgetisnull(result, 0, 0) != 0 } {
            return Err(fail("Expected one available local PostgreSQL document"));
        }
        let size = usize::try_from(unsafe { PQgetlength(result, 0, 0) })?;
        if size > limit { return Err(fail("Hosted MCP workspace snapshot exceeds its size limit")); }
        let bytes = unsafe { std::slice::from_raw_parts(PQgetvalue(result, 0, 0).cast(), size) };
        let value = serde_json::from_slice(bytes)?;
        crate::compat_value::external(&value)?;
        Ok(value)
    }
}

pub(super) fn unix_peer(fd: c_int) -> Result<libc::ucred> {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, peer.as_mut_ptr().cast(), &mut size) } != 0
        || size as usize != std::mem::size_of::<libc::ucred>() {
        return Err(fail("Expected a local socket peer with kernel credentials"));
    }
    Ok(unsafe { peer.assume_init() })
}
