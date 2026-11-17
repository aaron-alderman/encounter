// Revocable socket leases for an Encounter-authored device routing plan.
use crate::{Result, fail, http, rel::Facts};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    env, fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, Shutdown, TcpStream},
    os::{fd::{AsRawFd, FromRawFd, OwnedFd}, linux::net::SocketAddrExt,
        unix::{ffi::OsStrExt, fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
            net::{SocketAddr, UnixDatagram, UnixListener, UnixStream}}},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
    thread,
    time::{Duration, Instant},
};

const CHECK_INTERVAL: Duration = Duration::from_millis(250);
const CHECK_TIMEOUT: Duration = Duration::from_millis(300);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(600);
const CONNECTION_LIMIT: usize = 48;
const STATUS_FILE: &str = "state.sock";
const STATUS_LIMIT: u64 = 8192;
const STATUS_VERSION: &str = "encounter/device-edge-status/2";
const LEGACY_STATUS_VERSION: &str = "encounter/device-edge-status/1";
const RESPONSE_WINDOW: usize = 32;

struct Plan {
    policy: u16,
    apps: BTreeMap<String, u16>,
}

fn port(value: &str) -> Result<u16> {
    let port = value.parse()?;
    if port < 1024 { return Err(fail("expected an unprivileged loopback port")); }
    Ok(port)
}

fn app_slug(app: &str) -> bool {
    !app.is_empty() && app.len() <= 64
        && !matches!(app, "edge" | "state")
        && app.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl Plan {
    fn read(path: &Path) -> Result<Self> {
        let facts = Facts::read(path)?;
        if facts.one("edge", "version")? != "encounter/device-edge/1" {
            return Err(fail("unsupported device edge contract"));
        }
        let policy = port(facts.one("edge", "policyPort")?)?;
        let mut apps = BTreeMap::new();
        let mut backends = BTreeSet::from([policy]);
        for [app, field, value] in facts.0 {
            if app == "edge" && matches!(field.as_str(), "version" | "policyPort") { continue; }
            if field != "upstreamPort" || !app_slug(&app) {
                return Err(fail("invalid device edge route"));
            }
            let upstream = port(&value)?;
            if !backends.insert(upstream) || apps.insert(app, upstream).is_some() {
                return Err(fail("device edge routes must have distinct apps and upstreams"));
            }
        }
        if apps.is_empty() || apps.len() > 16 { return Err(fail("expected 1 to 16 device edge routes")); }
        Ok(Self { policy, apps })
    }
}

#[derive(PartialEq, Eq)]
enum Admission { Allowed, Refused, Unavailable }

fn admission(policy: u16, app: &str) -> Admission {
    let check = || -> Result<Admission> {
        let mut socket = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, policy).into(), CHECK_TIMEOUT)?;
        socket.set_read_timeout(Some(CHECK_TIMEOUT))?;
        socket.set_write_timeout(Some(CHECK_TIMEOUT))?;
        write!(socket, "GET /_encounter/device/check/{app} HTTP/1.1\r\nHost: 127.0.0.1:{policy}\r\nConnection: close\r\n\r\n")?;
        let (status, _) = http::read_head(&mut BufReader::new(socket))?;
        Ok(match status.as_str() {
            "HTTP/1.1 204 No Content" => Admission::Allowed,
            "HTTP/1.1 403 Forbidden" => Admission::Refused,
            _ => Admission::Unavailable,
        })
    };
    check().unwrap_or(Admission::Unavailable)
}

struct Sockets {
    ingress: UnixStream,
    upstream: TcpStream,
}

impl Sockets {
    fn close(&self) {
        let _ = self.ingress.shutdown(Shutdown::Both);
        let _ = self.upstream.shutdown(Shutdown::Both);
    }
}

type Connections = Arc<Mutex<BTreeMap<u64, Sockets>>>;

#[derive(Default)]
struct ResponseSamples(Mutex<VecDeque<u64>>);

impl ResponseSamples {
    fn observe(&self, micros: u64) {
        let mut values = self.0.lock().unwrap();
        if values.len() == RESPONSE_WINDOW { values.pop_front(); }
        values.push_back(micros);
    }

    fn snapshot(&self) -> Value {
        let values = self.0.lock().unwrap();
        let Some(latest) = values.back() else { return Value::Null; };
        let mut sorted: Vec<_> = values.iter().copied().collect();
        sorted.sort_unstable();
        let rank = (sorted.len() * 19).div_ceil(20);
        json!({"samples":sorted.len(),"p95Micros":sorted[rank - 1],"latestMicros":latest})
    }
}

struct FirstResponse<'a> {
    upstream: &'a mut TcpStream,
    observation: Option<(&'a ResponseSamples, Instant)>,
}

impl Read for FirstResponse<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = self.upstream.read(buffer)?;
        if size != 0 && let Some((samples, started)) = self.observation.take() {
            samples.observe(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
        }
        Ok(size)
    }
}

struct SocketFile(PathBuf);
impl Drop for SocketFile {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

struct Route {
    app: String,
    port: u16,
    listener: UnixListener,
    _socket: SocketFile,
    active: Connections,
    admitted: Cell<u64>,
    denied: Cell<u64>,
    revoked: Cell<u64>,
    unavailable: Cell<u64>,
    policy_unavailable: Cell<u64>,
    responses: Arc<ResponseSamples>,
}

impl Route {
    fn bind(directory: &Path, app: String, port: u16) -> Result<Self> {
        let path = directory.join(format!("{app}.sock"));
        let listener = UnixListener::bind(&path)?;
        let socket = SocketFile(path);
        listener.set_nonblocking(true)?;
        Ok(Self { app, port, listener, _socket: socket, active: Arc::default(),
            admitted: Cell::default(), denied: Cell::default(), revoked: Cell::default(), unavailable: Cell::default(),
            policy_unavailable: Cell::default(), responses: Arc::default() })
    }

    fn serve(&self, id: u64, mut ingress: UnixStream, started: Instant) -> Result<bool> {
        let Ok(mut upstream) = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, self.port).into(), CONNECT_TIMEOUT) else {
            reject(&mut ingress, "502 Bad Gateway")?;
            return Ok(false);
        };
        let mut from_client = ingress.try_clone()?;
        let mut to_backend = upstream.try_clone()?;
        let lease = Sockets { ingress: ingress.try_clone()?, upstream: upstream.try_clone()? };
        let active = Arc::clone(&self.active);
        let responses = Arc::clone(&self.responses);
        active.lock().unwrap().insert(id, lease);
        if thread::Builder::new().name("encounter-device-flow".into()).spawn(move || {
            thread::scope(|scope| {
                scope.spawn(|| {
                    let _ = io::copy(&mut from_client, &mut to_backend);
                    let _ = to_backend.shutdown(Shutdown::Write);
                });
                let mut first = FirstResponse { upstream: &mut upstream, observation: Some((&responses, started)) };
                let _ = io::copy(&mut first, &mut ingress);
                let _ = ingress.shutdown(Shutdown::Both);
                let _ = upstream.shutdown(Shutdown::Both);
            });
            active.lock().unwrap().remove(&id);
        }).is_err() {
            self.active.lock().unwrap().remove(&id);
            return Ok(false);
        }
        Ok(true)
    }

    fn revoke(&self) {
        let leases = std::mem::take(&mut *self.active.lock().unwrap());
        self.revoked.set(self.revoked.get() + leases.len() as u64);
        for lease in leases.values() { lease.close(); }
    }

    fn snapshot(&self) -> Value {
        json!({
            "app": self.app,
            "active": self.active.lock().unwrap().len(),
            "admitted": self.admitted.get(),
            "denied": self.denied.get(),
            "revoked": self.revoked.get(),
            "unavailable": self.unavailable.get(),
            "policyUnavailable": self.policy_unavailable.get(),
            "firstResponse": self.responses.snapshot(),
        })
    }
}

fn reject(stream: &mut UnixStream, status: &str) -> Result<()> {
    stream.set_write_timeout(Some(CHECK_TIMEOUT))?;
    write!(stream, "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n")?;
    Ok(())
}

pub fn private_directory(path: &Path) -> Result<PathBuf> {
    let directory = path.canonicalize()?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(fail("expected a private device edge socket directory owned by this account"));
    }
    Ok(directory)
}

fn prepare_directory(path: &Path) -> Result<(PathBuf, fs::File)> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    if !path.symlink_metadata()?.is_dir() {
        return Err(fail("expected a real device edge socket directory"));
    }
    let directory = private_directory(path)?;
    let lock = fs::File::open(&directory)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("device edge socket directory is already in use"));
    }
    Ok((directory, lock))
}

fn refuse_live_socket(path: &Path) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(fail("invalid device edge socket path"));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) { *slot = *byte as libc::c_char; }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 { return Err(io::Error::last_os_error().into()); }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    let status = unsafe { libc::connect(socket.as_raw_fd(), (&address as *const libc::sockaddr_un).cast(), length as libc::socklen_t) };
    if status == 0 { return Err(fail("device edge socket already has a listener")); }
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => Ok(()),
        _ => Err(error.into()),
    }
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    let socket = match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() } => metadata,
        Ok(_) => return Err(fail("refusing to replace a device edge socket path")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    refuse_live_socket(path)?;
    match path.symlink_metadata() {
        Ok(current) if (current.dev(), current.ino()) == (socket.dev(), socket.ino()) => fs::remove_file(path)?,
        Ok(_) => return Err(fail("device edge socket changed during preparation")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn notify_ready() -> Result<()> {
    let Some(socket) = env::var_os("NOTIFY_SOCKET") else { return Ok(()); };
    let address = if let Some(name) = socket.as_bytes().strip_prefix(b"@") {
        SocketAddr::from_abstract_name(name)?
    } else {
        SocketAddr::from_pathname(Path::new(&socket))?
    };
    UnixDatagram::unbound()?.send_to_addr(b"READY=1", &address)?;
    Ok(())
}

pub fn read_status(directory: &Path) -> Result<Value> {
    let stream = UnixStream::connect(directory.join(STATUS_FILE))?;
    stream.set_read_timeout(Some(CHECK_TIMEOUT))?;
    let mut payload = Vec::new();
    stream.take(STATUS_LIMIT + 1).read_to_end(&mut payload)?;
    if payload.len() as u64 > STATUS_LIMIT { return Err(fail("device edge status size limit")); }
    let value: Value = serde_json::from_slice(&payload)?;
    let routes = value["routes"].as_array().ok_or_else(|| fail("invalid device edge status routes"))?;
    let metrics = ["active", "admitted", "denied", "revoked", "unavailable"];
    let legacy = value["version"] == LEGACY_STATUS_VERSION;
    if (!legacy && value["version"] != STATUS_VERSION) || value["limit"].as_u64().is_none_or(|limit| limit == 0)
        || routes.is_empty() || routes.len() > 16 || routes.iter().any(|route| {
            !route["app"].as_str().is_some_and(app_slug) || metrics.iter().any(|metric| !route[*metric].is_u64())
                || (!legacy && (!route["policyUnavailable"].is_u64()
                    || !route.get("firstResponse").is_some_and(valid_response_sample)))
        })
    {
        return Err(fail("invalid device edge status"));
    }
    let routes = routes.iter().map(|route| json!({
        "app": route["app"], "active": route["active"], "admitted": route["admitted"],
        "denied": route["denied"], "revoked": route["revoked"], "unavailable": route["unavailable"],
        "policyUnavailable": if legacy { Value::Null } else { route["policyUnavailable"].clone() },
        "firstResponse": if legacy { Value::Null } else { route["firstResponse"].clone() },
    })).collect::<Vec<_>>();
    Ok(json!({"version": value["version"], "limit": value["limit"], "routes": routes}))
}

fn valid_response_sample(value: &Value) -> bool {
    value.is_null() || value["samples"].as_u64().is_some_and(|count| (1..=RESPONSE_WINDOW as u64).contains(&count))
        && value["p95Micros"].is_u64() && value["latestMicros"].is_u64()
}

pub fn serve(config: &Path, directory: &Path) -> Result<()> {
    let Plan { policy, apps } = Plan::read(config)?;
    let (directory, _lock) = prepare_directory(directory)?;
    for app in apps.keys() {
        remove_stale_socket(&directory.join(format!("{app}.sock")))?;
    }
    let state_file = directory.join(STATUS_FILE);
    remove_stale_socket(&state_file)?;
    let routes = apps.into_iter().map(|(app, port)| Route::bind(&directory, app, port)).collect::<Result<Vec<_>>>()?;
    let status_listener = UnixListener::bind(&state_file)?;
    let _status_file = SocketFile(state_file);
    status_listener.set_nonblocking(true)?;
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
    println!("Encounter device edge ready");
    io::stdout().flush()?;
    notify_ready()?;
    let mut next_check = Instant::now() + CHECK_INTERVAL;
    let mut id = 0u64;
    while !closing.load(Ordering::Acquire) {
        if let Ok((mut stream, _)) = status_listener.accept() {
            let status = json!({"version": STATUS_VERSION, "limit": CONNECTION_LIMIT,
                "routes": routes.iter().map(Route::snapshot).collect::<Vec<_>>()});
            if stream.set_write_timeout(Some(CHECK_TIMEOUT)).is_ok() {
                let _ = serde_json::to_writer(&mut stream, &status);
            }
        }
        if Instant::now() >= next_check {
            for route in &routes {
                let in_use = !route.active.lock().unwrap().is_empty();
                if in_use && admission(policy, &route.app) != Admission::Allowed { route.revoke(); }
            }
            next_check = Instant::now() + CHECK_INTERVAL;
        }
        let mut accepted = false;
        for route in &routes {
            let mut ingress = match route.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
                Err(error) => return Err(error.into()),
            };
            let started = Instant::now();
            accepted = true;
            let count: usize = routes.iter().map(|item| item.active.lock().unwrap().len()).sum();
            if count >= CONNECTION_LIMIT {
                route.unavailable.set(route.unavailable.get() + 1);
                let _ = reject(&mut ingress, "503 Service Unavailable");
            } else {
                match admission(policy, &route.app) {
                    Admission::Allowed => {
                        id += 1;
                        let counter = if matches!(route.serve(id, ingress, started), Ok(true)) { &route.admitted } else { &route.unavailable };
                        counter.set(counter.get() + 1);
                    }
                    Admission::Refused => {
                        route.denied.set(route.denied.get() + 1);
                        let _ = reject(&mut ingress, "403 Forbidden");
                    }
                    Admission::Unavailable => {
                        route.policy_unavailable.set(route.policy_unavailable.get() + 1);
                        let _ = reject(&mut ingress, "503 Service Unavailable");
                    }
                }
            }
        }
        if !accepted { thread::sleep(Duration::from_millis(10)); }
    }
    for route in &routes { route.revoke(); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, net::TcpListener};

    #[test]
    fn socket_preparation_preserves_live_and_non_socket_paths() -> Result<()> {
        let scratch = crate::appdev_host_process::Scratch::create(&env::temp_dir(), "edge-test-")?;
        let (directory, lock) = prepare_directory(scratch.path())?;
        assert!(prepare_directory(&directory).is_err());
        let path = directory.join(STATUS_FILE);
        let listener = UnixListener::bind(&path)?;
        assert!(remove_stale_socket(&path).is_err());
        assert!(path.symlink_metadata()?.file_type().is_socket());
        drop(listener);
        remove_stale_socket(&path)?;
        assert!(!path.exists());
        fs::write(&path, "keep")?;
        assert!(remove_stale_socket(&path).is_err());
        assert_eq!(fs::read_to_string(&path)?, "keep");
        drop(lock);
        assert!(prepare_directory(&directory).is_ok());
        Ok(())
    }

    #[test]
    fn first_response_percentile_uses_a_bounded_recent_window() {
        let readings = ResponseSamples::default();
        assert_eq!(readings.snapshot(), Value::Null);
        for micros in 1..=40 { readings.observe(micros); }
        assert_eq!(readings.snapshot(), json!({"samples":32,"p95Micros":39,"latestMicros":40}));
    }

    #[test]
    fn revocation_closes_an_existing_flow_on_both_ends() -> Result<()> {
        let directory = std::env::temp_dir().join(format!("edge-test-{}", crate::nonce::nonce()?));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let route = Route::bind(&directory, "test".to_owned(), upstream.local_addr()?.port())?;
        let mut client = UnixStream::connect(&route._socket.0)?;
        assert!(route.serve(1, route.listener.accept()?.0, Instant::now())?);
        let (mut backend, _) = upstream.accept()?;
        let timeout = Some(Duration::from_secs(2));
        client.set_read_timeout(timeout)?;
        backend.set_read_timeout(timeout)?;
        client.write_all(b"request")?;
        let mut bytes = [0; 7];
        backend.read_exact(&mut bytes)?;
        assert_eq!(&bytes, b"request");
        assert_eq!(route.snapshot()["firstResponse"], Value::Null);
        backend.write_all(b"upgrade")?;
        client.read_exact(&mut bytes)?;
        assert_eq!(&bytes, b"upgrade");
        assert_eq!(route.snapshot()["firstResponse"]["samples"], 1);

        route.revoke();
        assert_eq!(client.read(&mut bytes)?, 0);
        assert_eq!(backend.read(&mut bytes)?, 0);
        route.revoke();
        assert_eq!(route.snapshot()["active"], 0);
        assert_eq!(route.snapshot()["revoked"], 1);
        drop(route);
        fs::remove_dir(directory)?;
        Ok(())
    }
}
