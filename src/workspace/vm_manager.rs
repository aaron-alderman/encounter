use super::{Fields, Request, Response, Workspace, header, registry_shadow, string};
use super::steward::{DEMO, PAGE};
use crate::{Result, fail, rel::Facts, websocket};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{Read, Write},
    net::TcpStream,
    os::{fd::AsRawFd, unix::{fs::FileTypeExt, net::UnixStream}},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

// The console client treats this as an opaque selector. Colons are excluded from VM IDs.
const REGISTRY_CONSOLE_PREFIX: &str = "registry-display:";
const CONSOLE: &str = "/workspace/vm-manager/console";
const RECHECK: Duration = Duration::from_secs(15);
const RECHECK_RETRY: Duration = Duration::from_secs(2);
const RECHECK_LIMIT: Duration = Duration::from_secs(30);
const SESSION_LIMIT: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
pub(super) struct Registry {
    guests: Vec<Guest>,
    shadow: Option<PathBuf>,
}

struct Guest {
    id: String,
    title: String,
    socket: PathBuf,
    display: Option<PathBuf>,
    terminal: bool,
    operator: Mutex<()>,
}

impl Registry {
    pub(super) fn load() -> Result<Self> {
        let Some(path) = env::var_os("APPDEV_VM_REGISTRY") else { return Ok(Self::default()); };
        let facts = Facts::read(Path::new(&path))?;
        if facts.one("registry", "format")? != "encounter/vm-manager/1" {
            return Err(fail("Invalid VM Manager registry format"));
        }
        let ids = facts.values("registry", "guest");
        if ids.len() > 8 {
            return Err(fail("VM Manager supports up to eight registered guests"));
        }
        let mut guests: Vec<Guest> = Vec::new();
        for id in ids {
            let title = facts.one(id, "title")?;
            let (path, terminal) = match (
                facts.values(id, "serialSocket").as_slice(), facts.values(id, "terminalSocket").as_slice()
            ) {
                ([path], []) => (*path, false),
                ([], [path]) => (*path, true),
                _ => return Err(fail("Expected a single VM Manager console binding")),
            };
            let socket = PathBuf::from(path);
            if id.is_empty() || id.len() > 48 || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || title.trim().is_empty() || title.len() > 100 || title.chars().any(char::is_control)
                || !socket.is_absolute() || socket.as_os_str().len() > 107
                || guests.iter().any(|guest| guest.id == id || guest.socket == socket || guest.display.as_ref() == Some(&socket)) {
                return Err(fail("Invalid VM Manager guest binding"));
            }
            let display = match facts.values(id, "displaySocket").as_slice() {
                [] => None,
                [path] if !terminal && Path::new(path).is_absolute() && path.len() <= 107 && Path::new(path) != socket => {
                    Some(PathBuf::from(path))
                }
                _ => return Err(fail("Invalid VM Manager display binding")),
            };
            if display.as_ref().is_some_and(|path| guests.iter().any(|guest| &guest.socket == path || guest.display.as_ref() == Some(path))) {
                return Err(fail("Duplicate VM Manager display binding"));
            }
            guests.push(Guest { id: id.to_owned(), title: title.to_owned(), socket, display, terminal, operator: Mutex::new(()) });
        }
        Ok(Self { guests, shadow: registry_shadow::spool() })
    }

    fn find(&self, id: &str) -> Option<&Guest> {
        self.guests.iter().find(|guest| guest.id == id)
    }
}

impl Guest {
    fn public(&self) -> Value {
        json!({"id": self.id, "title": self.title, "display": self.display.is_some(), "terminal": self.terminal})
    }

    fn display_request(&self, command: &str) -> Result<Vec<u8>> {
        let path = self.display.as_ref().ok_or_else(|| fail("Display is unavailable"))?;
        let mut socket = connect_socket(path)?;
        socket.set_read_timeout(Some(Duration::from_secs(4)))?;
        socket.write_all(command.as_bytes())?;
        socket.shutdown(std::net::Shutdown::Write)?;
        let mut reply = Vec::new();
        socket.take(4 * 1024 * 1024 + 1).read_to_end(&mut reply)?;
        if reply.len() > 4 * 1024 * 1024 { return Err(fail("Guest display frame is too large")); }
        Ok(reply)
    }

    fn connect(&self) -> Result<UnixStream> {
        connect_socket(&self.socket)
    }
}

// Reset the provider before another browser can acquire the guest console.
struct GuestPointer<'a> {
    guest: &'a Guest,
    used: bool,
}

impl GuestPointer<'_> {
    fn send(&mut self, command: &str) -> bool {
        self.used = true;
        self.guest.display_request(command).is_ok_and(|reply| reply == b"ok")
    }

    fn reset(&mut self) {
        if self.used && self.guest.display_request("mouse reset").is_ok_and(|reply| reply == b"ok") {
            self.used = false;
        }
    }
}

impl Drop for GuestPointer<'_> {
    fn drop(&mut self) {
        self.reset();
    }
}

fn valid_pointer(command: &str) -> bool {
    if command == "mouse reset" {
        return true;
    }
    let Some(fields) = command.strip_prefix("mouse ") else { return false; };
    let mut fields = fields.split(' ').map(|field| {
        if field.len() > 4 || !field.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        field.parse::<u16>().ok()
    });
    matches!((fields.next(), fields.next(), fields.next(), fields.next()),
        (Some(Some(0..=8191)), Some(Some(0..=8191)), Some(Some(0..=7)), None))
}

struct ConsoleAuthorization {
    next_check: Instant,
    unavailable_since: Option<Instant>,
}

impl ConsoleAuthorization {
    fn new(started: Instant) -> Self {
        Self { next_check: started + RECHECK, unavailable_since: None }
    }

    fn check(&mut self, workspace: &Workspace, request: &Request, stream: &mut TcpStream) -> Result<bool> {
        if Instant::now() < self.next_check {
            return Ok(true);
        }
        match workspace.vm_operator(request) {
            Ok(true) => {
                self.next_check = Instant::now() + RECHECK;
                if self.unavailable_since.take().is_some() {
                    send_status(stream, "Connected", true)?;
                }
                websocket::frame(stream, 9, &[])?;
                Ok(true)
            }
            Ok(false) => {
                send_status(stream, "Console authorization ended. Sign in again to reconnect.", false)?;
                Ok(false)
            }
            Err(_) => {
                let now = Instant::now();
                if self.unavailable_since.is_none() {
                    self.unavailable_since = Some(now);
                    websocket::frame(stream, 1, &serde_json::to_vec(&json!({
                        "status": "Checking console authorization. Guest input is paused.",
                        "connected": true, "inputPaused": true
                    }))?)?;
                }
                if self.unavailable_since.is_some_and(|since| now.duration_since(since) >= RECHECK_LIMIT) {
                    send_status(stream, "Console authorization is unavailable. Reconnect to try again.", false)?;
                    return Ok(false);
                }
                self.next_check = now + RECHECK_RETRY;
                Ok(true)
            }
        }
    }

    fn paused(&self) -> bool {
        self.unavailable_since.is_some()
    }
}

impl Workspace {
    fn vm_operator(&self, request: &Request) -> Result<bool> {
        self.platform_allowed(self.observe_workspace_identity(request, true)?.as_ref())
    }

    pub(super) fn vm_manager_style(&self) -> Result<Response> {
        let extra = self.run(json!({"program":"workspace", "operation":"vm-manager-style"}))?;
        Ok(Response::css(&format!("{}\n{}", self.release.style, string(&extra)?)))
    }

    pub(super) fn vm_manager_page(&self, request: &Request, query: &Fields) -> Result<Response> {
        let start_display = query.get("view") == Some("display");
        let registry = query.get("vm") == Some(registry_shadow::GUEST);
        let launch = query.get("launch");
        let selected = match query.get("vm") {
            Some(id) if query.len() == 1 + usize::from(start_display) + usize::from(registry && launch.is_some()) => {
                match self.runtime.vms.find(id) {
                    Some(guest) if !(start_display || registry) || guest.display.is_some() => Some(guest.public()),
                    _ => return Ok(Response::text(404, "Development VM is unavailable.")),
                }
            }
            None if query.len() == 0 => None,
            _ => return Ok(Response::empty(400)),
        };
        if registry && !start_display {
            return Ok(super::environments::redirect(PAGE, DEMO));
        }
        let identity = match self.observe_workspace_identity(request, true) {
            Ok(identity) => identity,
            Err(_) => return Ok(Response::text(503, "Console authorization is unavailable. Try again shortly.")),
        };
        if identity.is_none() {
            let destination = match query.get("vm") {
                Some(_) if registry => format!("{PAGE}?{DEMO}"),
                Some(id) => format!("{PAGE}?vm={id}{}", if start_display { "&view=display" } else { "" }),
                None => PAGE.to_owned(),
            };
            return self.workspace_sign_in_page(&destination);
        }
        if !self.platform_allowed(identity.as_ref())? {
            return self.workspace_access_page(403, "Platform steward access required",
                "Your AppDev account is signed in. To open this application, sign out of Workspace and sign in with a Platform steward account.", None, None);
        }
        let steward_expiry = if registry {
            let Some(launch) = launch else { return self.registry_approval(request); };
            let Some(remaining) = self.registry_steward_remaining(request, launch) else {
                return Ok(super::environments::redirect(PAGE, DEMO));
            };
            Some(chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now() + remaining))
        } else {
            None
        };
        let style_nonce = if selected.as_ref().and_then(|guest| guest["terminal"].as_bool()) == Some(true) {
            Some(crate::nonce::nonce()?)
        } else {
            None
        };
        let terminal_style = style_nonce.as_ref().map(|nonce| format!(" 'nonce-{nonce}'")).unwrap_or_default();
        let vms = self.runtime.vms.guests.iter().map(Guest::public).collect::<Vec<_>>();
        let data = self.run(json!({"program":"workspace", "operation":"vm-manager-page",
            "vms":vms, "selected":selected, "styleNonce":style_nonce, "startDisplay":start_display,
            "stewardLaunch":launch, "stewardExpiry":steward_expiry.map(|expires| expires.format("%H:%M UTC").to_string()),
            "stewardExpiryDate":steward_expiry.map(|expires| expires.to_rfc3339()),
            "stewardConsole":launch.map(|launch| format!("{REGISTRY_CONSOLE_PREFIX}{launch}")),
            "stewardAction":format!("{PAGE}?{DEMO}")}))?;
        let socket_origin = self.runtime.origin.replacen("http", "ws", 1);
        let policy = format!(
            "default-src 'none'; img-src blob:; style-src 'self'{terminal_style}; font-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src {socket_origin}{CONSOLE}; frame-ancestors 'self'; base-uri 'none'; form-action 'self'"
        );
        Ok(Response::html(200, string(&data)?, policy).with("Referrer-Policy", "strict-origin"))
    }

    pub(super) fn vm_console(&self, stream: &mut TcpStream, request: &Request) -> Result<()> {
        if request.method != "GET" || header(request, "origin") != self.runtime.origin {
            return Response::empty(403).send(stream, false);
        }
        let identity = match self.observe_workspace_identity(request, true) {
            Ok(identity) => identity,
            Err(_) => return Response::empty(503).send(stream, false),
        };
        match self.platform_allowed(identity.as_ref()) {
            Ok(true) => {}
            Ok(false) => return Response::empty(403).send(stream, false),
            Err(_) => return Response::empty(503).send(stream, false),
        }
        let Some((CONSOLE, query)) = request.path.split_once('?') else {
            return Response::empty(404).send(stream, false);
        };
        let fields = Fields::parse(query.as_bytes());
        let Some(console) = fields.get("vm").filter(|_| fields.len() == 1) else {
            return Response::empty(404).send(stream, false);
        };
        let launch = console.strip_prefix(REGISTRY_CONSOLE_PREFIX);
        let guest_id = if launch.is_some() { registry_shadow::GUEST } else { console };
        let Some(guest) = self.runtime.vms.find(guest_id) else {
            return Response::empty(404).send(stream, false);
        };
        if guest.id == registry_shadow::GUEST
            && launch.and_then(|id| self.registry_steward_remaining(request, id)).is_none() {
            return Response::empty(403).send(stream, false);
        }
        websocket::handshake(stream, request)?;
        let Ok(_control) = guest.operator.try_lock() else {
            send_status(stream, "Another session is controlling this VM.", false)?;
            return websocket::frame(stream, 8, &[]);
        };
        let Ok(mut serial) = guest.connect() else {
            send_status(stream, "Guest console is offline.", false)?;
            return websocket::frame(stream, 8, &[]);
        };
        if guest.terminal {
            serial.set_read_timeout(Some(Duration::from_secs(6)))?;
            let mut ready = [0];
            if serial.read_exact(&mut ready).is_err() || ready != [1] {
                send_status(stream, "Guest terminal is offline.", false)?;
                return websocket::frame(stream, 8, &[]);
            }
            send_status(stream, "Connected", true)?;
            return self.relay_vm_terminal(stream, &mut serial, request);
        }
        send_status(stream, "Connected", true)?;
        let mut meter = self.runtime.vms.shadow.as_ref()
            .filter(|_| guest.id == registry_shadow::GUEST)
            .zip(identity.as_ref())
            .and_then(|(spool, user)| match registry_shadow::Session::begin(spool, &user.principal_key, Instant::now()) {
                Ok(session) => Some(session),
                Err(_) => {
                    eprintln!("Registry Demo shadow metering could not start a console sample");
                    None
                }
            });
        self.relay_vm_console(stream, &mut serial, request, guest, launch, meter.as_mut())
    }

    fn relay_vm_terminal(&self, stream: &mut TcpStream, guest: &mut UnixStream, request: &Request) -> Result<()> {
        let started = Instant::now();
        let mut authorization = ConsoleAuthorization::new(started);
        let mut bytes = [0; 8193];
        let mut terminal_keepalive = started + RECHECK;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        while started.elapsed() < SESSION_LIMIT && !crate::http::stopping() {
            if !authorization.check(self, request, stream)? { break; }
            if !authorization.paused() && Instant::now() >= terminal_keepalive {
                terminal_message(guest, 2, &[])?;
                terminal_keepalive = Instant::now() + RECHECK;
            }
            let [browser, terminal] = ready_sources(stream, guest, 1000)?;
            if browser {
                let Some((kind, body)) = websocket::read_guest_frame(stream, 8192, true)? else { return Ok(()); };
                if authorization.paused() { continue; }
                match kind {
                    2 if !body.is_empty() => terminal_message(guest, 0, &body)?,
                    1 => {
                        let size = std::str::from_utf8(&body)?
                            .split_once(' ').and_then(|(rows, cols)| {
                                Some((rows.parse::<u16>().ok()?, cols.parse::<u16>().ok()?))
                            });
                        if let Some((rows, cols)) = size.filter(|(r, c)| (1..=240).contains(r) && (1..=512).contains(c)) {
                            let [r0, r1] = rows.to_be_bytes();
                            let [c0, c1] = cols.to_be_bytes();
                            terminal_message(guest, 1, &[r0, r1, c0, c1])?;
                        }
                    }
                    _ => {}
                }
            }
            if terminal {
                let read = guest.read(&mut bytes[1..])?;
                if read == 0 {
                    send_status(stream, "Workspace Terminal exited.", false)?;
                    break;
                }
                if !authorization.paused() {
                    websocket::frame(stream, 2, &bytes[..=read])?;
                }
            }
        }
        websocket::frame(stream, 8, &[])
    }

    fn relay_vm_console(&self, stream: &mut TcpStream, serial: &mut UnixStream, request: &Request, guest: &Guest,
                        launch: Option<&str>, mut meter: Option<&mut registry_shadow::Session>) -> Result<()> {
        let started = Instant::now();
        let mut authorization = ConsoleAuthorization::new(started);
        let mut last_command = None::<Instant>;
        let mut serial_bytes = [0; 4097];
        let mut display = false;
        let mut pointer = GuestPointer { guest, used: false };
        let mut last_frame = Vec::new();
        let mut next_frame = started;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        while started.elapsed() < SESSION_LIMIT && !crate::http::stopping() {
            if launch.is_some_and(|launch| self.registry_steward_remaining(request, launch).is_none()) {
                send_status(stream, "Steward session ended. Open Registry Demo Display again for approval.", false)?;
                break;
            }
            let checked_at = Instant::now();
            let permitted = authorization.check(self, request, stream);
            if let Some(meter) = meter.as_deref_mut() {
                meter.authorization(checked_at, matches!(&permitted, Ok(true)) && !authorization.paused());
            }
            if !permitted? { break; }
            if authorization.paused() {
                pointer.reset();
            }
            if display && !authorization.paused() && Instant::now() >= next_frame {
                match guest.display_request("frame") {
                    Ok(image) if image.starts_with(b"\x89PNG\r\n\x1a\n") => {
                        if last_frame.get(1..) != Some(image.as_slice()) {
                            last_frame.clear();
                            last_frame.push(1);
                            last_frame.extend(image);
                            websocket::frame(stream, 2, &last_frame)?;
                        }
                    }
                    _ => {
                        pointer.reset();
                        display = false;
                        if launch.is_some() {
                            send_status(stream, "Registry Demo Display is offline.", false)?;
                            break;
                        }
                        send_mode(stream, "serial", "Display is offline. Serial is connected.")?;
                    }
                }
                next_frame = Instant::now() + Duration::from_millis(220);
            }
            let [browser, guest_output] = ready_sources(stream, serial, if display { 100 } else { 1000 })?;
            if browser {
                let Some(command) = websocket::read_guest_text(stream, 254)? else { return Ok(()); };
                if command.is_empty() || authorization.paused() { continue; }
                if command.starts_with('\0') {
                    match command.as_str() {
                        "\0display" if guest.display.is_some() => {
                            display = true;
                            next_frame = Instant::now();
                            last_frame.clear();
                            send_mode(stream, "display", "Connected")?;
                        }
                        "\0serial" if launch.is_none() => {
                            pointer.reset();
                            display = false;
                            send_mode(stream, "serial", "Connected")?;
                        }
                        command if display && command.starts_with("\0key ") => {
                            if !guest.display_request(&command[1..]).is_ok_and(|reply| reply == b"ok") {
                                send_mode(stream, "display", "Guest key could not be sent.")?;
                            }
                        }
                        command if display && valid_pointer(&command[1..]) => {
                            if pointer.send(&command[1..]) {
                                next_frame = next_frame.min(Instant::now() + Duration::from_millis(50));
                            } else {
                                send_status(stream, "Guest mouse input could not be sent.", true)?;
                            }
                        }
                        _ => {}
                    }
                    continue;
                }
                if display || launch.is_some() { continue; }
                if command.chars().any(char::is_control) {
                    send_status(stream, "Enter one command without control characters.", true)?;
                    continue;
                }
                if last_command.is_some_and(|last| last.elapsed() < Duration::from_millis(250)) {
                    send_status(stream, "Wait briefly before sending another command.", true)?;
                    continue;
                }
                let mut line = command.into_bytes();
                line.push(b'\r');
                serial.write_all(&line)?;
                last_command = Some(Instant::now());
            }
            if guest_output {
                let read = serial.read(&mut serial_bytes[1..])?;
                if read == 0 {
                    send_status(stream, "Guest console disconnected.", false)?;
                    break;
                }
                if launch.is_none() && !authorization.paused() {
                    websocket::frame(stream, 2, &serial_bytes[..=read])?;
                }
            }
        }
        websocket::frame(stream, 8, &[])
    }
}

fn send_status(stream: &mut TcpStream, status: &str, connected: bool) -> Result<()> {
    websocket::frame(stream, 1, &serde_json::to_vec(&json!({"status":status, "connected":connected}))?)
}

fn connect_socket(path: &Path) -> Result<UnixStream> {
    if !fs::symlink_metadata(path)?.file_type().is_socket() {
        return Err(fail("Guest socket is unavailable"));
    }
    let socket = UnixStream::connect(path)?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(socket)
}

fn send_mode(stream: &mut TcpStream, mode: &str, status: &str) -> Result<()> {
    websocket::frame(stream, 1, &serde_json::to_vec(&json!({
        "status": status, "connected": true, "mode": mode
    }))?)
}


fn ready_sources(stream: &TcpStream, guest: &UnixStream, milliseconds: i32) -> Result<[bool; 2]> {
    let mut sources = [
        libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: guest.as_raw_fd(), events: libc::POLLIN, revents: 0 },
    ];
    if unsafe { libc::poll(sources.as_mut_ptr(), sources.len() as libc::nfds_t, milliseconds) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted { return Err(error.into()); }
        return Ok([false, false]);
    }
    Ok(sources.map(|source| source.revents != 0))
}

fn terminal_message(socket: &mut UnixStream, kind: u8, body: &[u8]) -> Result<()> {
    let [high, low] = u16::try_from(body.len())?.to_be_bytes();
    socket.write_all(&[kind, high, low])?;
    socket.write_all(body)?;
    Ok(())
}
