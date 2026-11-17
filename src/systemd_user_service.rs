use crate::{Result, fail, http, postgres::unix_peer};
use serde::Serialize;
use std::{
    cell::RefCell,
    ffi::{CStr, CString, c_char, c_int, c_void},
    io,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    ptr::{self, NonNull},
    time::{Duration, Instant},
};

#[link(name = "libsystemd.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn sd_bus_new(bus: *mut *mut c_void) -> c_int;
    fn sd_bus_unref(bus: *mut c_void) -> *mut c_void;
    fn sd_bus_set_address(bus: *mut c_void, address: *const c_char) -> c_int;
    fn sd_bus_set_bus_client(bus: *mut c_void, enabled: c_int) -> c_int;
    fn sd_bus_start(bus: *mut c_void) -> c_int;
    fn sd_bus_get_fd(bus: *mut c_void) -> c_int;
    fn sd_bus_set_method_call_timeout(bus: *mut c_void, microseconds: u64) -> c_int;
    fn sd_bus_is_ready(bus: *mut c_void) -> c_int;
    fn sd_bus_process(bus: *mut c_void, message: *mut *mut c_void) -> c_int;
    fn sd_bus_wait(bus: *mut c_void, timeout: u64) -> c_int;
    fn sd_bus_negotiate_fds(bus: *mut c_void, enabled: c_int) -> c_int;
    fn sd_bus_message_new_method_call(bus: *mut c_void, message: *mut *mut c_void,
        destination: *const c_char, path: *const c_char, interface: *const c_char, member: *const c_char) -> c_int;
    fn sd_bus_message_set_auto_start(message: *mut c_void, enabled: c_int) -> c_int;
    fn sd_bus_message_append(message: *mut c_void, types: *const c_char, ...) -> c_int;
    fn sd_bus_call(bus: *mut c_void, message: *mut c_void, timeout: u64, error: *mut c_void, reply: *mut *mut c_void) -> c_int;
    fn sd_bus_message_unref(message: *mut c_void) -> *mut c_void;
    fn sd_bus_message_read_basic(message: *mut c_void, kind: c_char, value: *mut c_void) -> c_int;
    fn sd_bus_message_read_array(message: *mut c_void, kind: c_char, value: *mut *const c_void, size: *mut usize) -> c_int;
    fn sd_bus_message_enter_container(message: *mut c_void, kind: c_char, contents: *const c_char) -> c_int;
    fn sd_bus_message_exit_container(message: *mut c_void) -> c_int;
    fn sd_bus_message_skip(message: *mut c_void, types: *const c_char) -> c_int;
    fn sd_bus_message_get_sender(message: *mut c_void) -> *const c_char;
    fn sd_bus_add_match(bus: *mut c_void, slot: *mut *mut c_void, rule: *const c_char,
        handler: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int>, userdata: *mut c_void) -> c_int;
    fn sd_bus_get_property_trivial(bus: *mut c_void, destination: *const c_char, path: *const c_char,
        interface: *const c_char, member: *const c_char, error: *mut c_void, kind: c_char,
        value: *mut c_void) -> c_int;
    fn sd_bus_get_property_string(bus: *mut c_void, destination: *const c_char, path: *const c_char,
        interface: *const c_char, member: *const c_char, error: *mut c_void, value: *mut *mut c_char) -> c_int;
    fn sd_bus_get_property(bus: *mut c_void, destination: *const c_char, path: *const c_char,
        interface: *const c_char, member: *const c_char, error: *mut c_void, reply: *mut *mut c_void,
        kind: *const c_char) -> c_int;
}

struct Bus(NonNull<c_void>);
struct Message(NonNull<c_void>);

impl Drop for Bus {
    fn drop(&mut self) { unsafe { sd_bus_unref(self.0.as_ptr()); } }
}

impl Drop for Message {
    fn drop(&mut self) { unsafe { sd_bus_message_unref(self.0.as_ptr()); } }
}

fn checked(result: c_int) -> io::Result<c_int> {
    if result < 0 { Err(io::Error::from_raw_os_error(-result)) } else { Ok(result) }
}

#[derive(Clone, Copy)]
struct Deadline {
    expires: Instant,
    restoring: bool,
}

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Self { expires: Instant::now() + timeout, restoring: false }
    }
}

fn remaining(deadline: Deadline) -> io::Result<u64> {
    http::check_interruption(deadline.restoring)?;
    let remaining = deadline.expires.saturating_duration_since(Instant::now()).as_micros() as u64;
    if remaining == 0 { return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT)); }
    Ok(remaining)
}

fn wait_for_bus(bus: *mut c_void, deadline: Deadline) -> io::Result<()> {
    while checked(unsafe { sd_bus_is_ready(bus) })? == 0 {
        let timeout = remaining(deadline)?.min(100_000);
        if checked(unsafe { sd_bus_process(bus, ptr::null_mut()) })? == 0 {
            checked(unsafe { sd_bus_wait(bus, timeout) })?;
        }
    }
    Ok(())
}

pub(super) fn main_pid(unit: &str) -> Result<u32> {
    let uid = unsafe { libc::geteuid() };
    main_pid_on_bus(Path::new(&format!("/run/user/{uid}/bus")), uid, unit)
}

fn main_pid_on_bus(path: &Path, uid: u32, unit: &str) -> Result<u32> {
    let deadline = Deadline::new(Duration::from_secs(2));
    let bus = connect(path, uid, Some(uid), deadline)?;
    let unit = get_unit(&bus, unit, deadline)?;
    let mut pid = 0_u32;
    let raw = bus.0.as_ptr();
    checked(unsafe { sd_bus_set_method_call_timeout(raw, remaining(deadline)?) })?;
    checked(unsafe { sd_bus_get_property_trivial(raw, unit.sender.as_ptr(), unit.path.as_ptr(),
        c"org.freedesktop.systemd1.Service".as_ptr(), c"MainPID".as_ptr(), ptr::null_mut(),
        b'u' as c_char, (&mut pid as *mut u32).cast()) })?;
    if pid <= 1 { return Err(fail("application unit has no running main process")); }
    Ok(pid)
}

pub(super) struct FrontGateRun {
    pub invocation: String,
    pub start_us: u64,
    pub end_us: u64,
    pub timer: Option<(String, u64)>,
}

const FRONT_GATE_SERVICE: &str = "sourcery-dev-front-gate-check.service";
const FRONT_GATE_TIMER: &str = "sourcery-dev-front-gate-check.timer";

pub(super) fn front_gate_run() -> Result<FrontGateRun> {
    let uid = unsafe { libc::geteuid() };
    let deadline = Deadline::new(Duration::from_secs(5));
    let bus = connect(Path::new(&format!("/run/user/{uid}/bus")), uid, Some(uid), deadline)?;
    let service = get_unit(&bus, FRONT_GATE_SERVICE, deadline)?;
    require_unit_owner(&bus, &service, uid, deadline)?;
    let invocation = invocation_id(&bus, &service, deadline)?;
    let start_us = uint64_property(&bus, &service, c"org.freedesktop.systemd1.Service", c"ExecMainStartTimestamp", deadline)?;
    let end_us = uint64_property(&bus, &service, c"org.freedesktop.systemd1.Service", c"ExecMainExitTimestamp", deadline)?;
    let timer = match get_unit(&bus, FRONT_GATE_TIMER, deadline) {
        Ok(timer) => {
            if timer.sender != service.sender { return Err(fail("Systemd manager changed during receipt observation")); }
            let activates = string_property(&bus, &timer, c"org.freedesktop.systemd1.Timer", c"Unit", 256, deadline)?;
            let last = uint64_property(&bus, &timer, c"org.freedesktop.systemd1.Timer", c"LastTriggerUSec", deadline)?;
            Some((activates, last))
        }
        Err(error) if error.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error) == Some(libc::ENOENT) => None,
        Err(error) => return Err(error),
    };
    if invocation_id(&bus, &service, deadline)? != invocation {
        return Err(fail("Systemd invocation changed during receipt observation"));
    }
    Ok(FrontGateRun { invocation, start_us, end_us, timer })
}

fn invocation_id(bus: &Bus, unit: &Unit, deadline: Deadline) -> Result<String> {
    let raw = bus.0.as_ptr();
    checked(unsafe { sd_bus_set_method_call_timeout(raw, remaining(deadline)?) })?;
    let mut reply = ptr::null_mut();
    checked(unsafe { sd_bus_get_property(raw, unit.sender.as_ptr(), unit.path.as_ptr(),
        c"org.freedesktop.systemd1.Unit".as_ptr(), c"InvocationID".as_ptr(), ptr::null_mut(), &mut reply, c"ay".as_ptr()) })?;
    let reply = Message(NonNull::new(reply).ok_or_else(|| fail("Missing systemd invocation reply"))?);
    let mut data = ptr::null();
    let mut size = 0;
    let read = checked(unsafe { sd_bus_message_read_array(reply.0.as_ptr(), b'y' as c_char, &mut data, &mut size) })?;
    if read != 1 || size != 16 || data.is_null() { return Err(fail("Invalid systemd invocation ID")); }
    Ok(hex::encode(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) }))
}

fn uint64_property(bus: &Bus, unit: &Unit, interface: &CStr, member: &CStr, deadline: Deadline) -> Result<u64> {
    let raw = bus.0.as_ptr();
    checked(unsafe { sd_bus_set_method_call_timeout(raw, remaining(deadline)?) })?;
    let mut value = 0_u64;
    checked(unsafe { sd_bus_get_property_trivial(raw, unit.sender.as_ptr(), unit.path.as_ptr(),
        interface.as_ptr(), member.as_ptr(), ptr::null_mut(), b't' as c_char, (&mut value as *mut u64).cast()) })?;
    Ok(value)
}

fn connect(path: &Path, uid: u32, peer_uid: Option<u32>, deadline: Deadline) -> Result<Bus> {
    remaining(deadline)?;
    let parent = path.parent().ok_or_else(|| fail("missing systemd bus directory"))?.symlink_metadata()?;
    let socket = path.symlink_metadata()?;
    if !parent.is_dir() || parent.uid() != uid || parent.mode() & 0o022 != 0
        || !socket.file_type().is_socket() || socket.uid() != uid {
        return Err(fail("Expected a systemd bus socket in a protected directory"));
    }
    let address = CString::new(format!("unix:path={}", path.display()))?;
    let mut bus = ptr::null_mut();
    checked(unsafe { sd_bus_new(&mut bus) })?;
    let bus = Bus(NonNull::new(bus).ok_or_else(|| fail("missing systemd bus"))?);
    let raw = bus.0.as_ptr();
    checked(unsafe { sd_bus_set_address(raw, address.as_ptr()) })?;
    checked(unsafe { sd_bus_set_bus_client(raw, 1) })?;
    checked(unsafe { sd_bus_negotiate_fds(raw, 0) })?;
    checked(unsafe { sd_bus_start(raw) })?;
    let fd = checked(unsafe { sd_bus_get_fd(raw) })?;
    let peer = unix_peer(fd)?;
    if peer_uid.is_some_and(|uid| peer.uid != uid) {
        return Err(fail("Systemd bus peer has the wrong Unix UID"));
    }

    // Method timeouts begin after authentication. Bound the handshake with the same deadline.
    wait_for_bus(raw, deadline)?;
    let current = path.symlink_metadata()?;
    if (socket.dev(), socket.ino()) != (current.dev(), current.ino()) {
        return Err(fail("Systemd bus socket changed during authentication"));
    }
    Ok(bus)
}

struct Unit {
    path: CString,
    sender: CString,
}

pub(super) fn signal_managed_listener(unit: &str, restoring: bool) -> Result<()> {
    if !unit.strip_prefix("notes-managed-").and_then(|name| name.strip_suffix(".service"))
        .is_some_and(crate::certificate_renewal::stem) || unit.len() > 255 {
        return Err(fail("Expected a managed listener service"));
    }
    let deadline = Deadline { restoring, ..Deadline::new(Duration::from_secs(5)) };
    let (bus, uid) = directory_bus(true, deadline)?;
    let selected = get_unit(&bus, unit, deadline)?;
    require_unit_owner(&bus, &selected, uid, deadline)?;
    let raw = bus.0.as_ptr();
    let mut request = ptr::null_mut();
    checked(unsafe { sd_bus_message_new_method_call(raw, &mut request, selected.sender.as_ptr(),
        selected.path.as_ptr(), c"org.freedesktop.systemd1.Unit".as_ptr(), c"Kill".as_ptr()) })?;
    let request = Message(NonNull::new(request).ok_or_else(|| fail("Missing listener signal request"))?);
    checked(unsafe { sd_bus_message_set_auto_start(request.0.as_ptr(), 0) })?;
    checked(unsafe { sd_bus_message_append(request.0.as_ptr(), c"si".as_ptr(), c"main".as_ptr(), libc::SIGHUP) })?;
    checked(unsafe { sd_bus_call(raw, request.0.as_ptr(), remaining(deadline)?, ptr::null_mut(), ptr::null_mut()) })?;
    Ok(())
}

#[cfg(test)]
#[test]
fn managed_listener_signal_refuses_unrelated_units_before_connecting() {
    for unit in ["nginx.service", "notes-managed-.service", "notes-managed-a/b.service", "notes-managed-a.socket"] {
        assert!(signal_managed_listener(unit, true).unwrap_err().to_string().contains("Expected a managed listener service"));
    }
}

pub(super) fn reload_google_identity_definition(timeout: Duration, restoring: bool) -> Result<()> {
    let deadline = Deadline { restoring, ..Deadline::new(timeout) };
    let (bus, uid) = directory_bus(false, deadline)?;
    let owner = call_with_string(&bus, c"org.freedesktop.DBus", c"/org/freedesktop/DBus",
        c"org.freedesktop.DBus", c"GetNameOwner", c"org.freedesktop.systemd1", deadline)?;
    let owner = CString::new(reply_text(&owner, b's', 64)?)?;
    require_manager_owner(&bus, &owner, uid, deadline)?;
    let raw = bus.0.as_ptr();
    let mut request = ptr::null_mut();
    checked(unsafe { sd_bus_message_new_method_call(raw, &mut request, owner.as_ptr(),
        c"/org/freedesktop/systemd1".as_ptr(), c"org.freedesktop.systemd1.Manager".as_ptr(), c"Reload".as_ptr()) })?;
    let request = Message(NonNull::new(request).ok_or_else(|| fail("Missing systemd definition reload request"))?);
    checked(unsafe { sd_bus_message_set_auto_start(request.0.as_ptr(), 0) })?;
    checked(unsafe { sd_bus_call(raw, request.0.as_ptr(), remaining(deadline)?, ptr::null_mut(), ptr::null_mut()) })?;
    Ok(())
}

fn call_with_string(bus: &Bus, destination: &CStr, path: &CStr, interface: &CStr, member: &CStr,
    argument: &CStr, deadline: Deadline) -> Result<Message> {
    let raw = bus.0.as_ptr();
    let mut request = ptr::null_mut();
    checked(unsafe { sd_bus_message_new_method_call(raw, &mut request, destination.as_ptr(),
        path.as_ptr(), interface.as_ptr(), member.as_ptr()) })?;
    let request = Message(NonNull::new(request).ok_or_else(|| fail("missing systemd unit request"))?);
    checked(unsafe { sd_bus_message_set_auto_start(request.0.as_ptr(), 0) })?;
    checked(unsafe { sd_bus_message_append(request.0.as_ptr(), c"s".as_ptr(), argument.as_ptr()) })?;
    let mut reply = ptr::null_mut();
    checked(unsafe { sd_bus_call(raw, request.0.as_ptr(), remaining(deadline)?, ptr::null_mut(), &mut reply) })?;
    Ok(Message(NonNull::new(reply).ok_or_else(|| fail("missing systemd reply"))?))
}

struct JobCompletion<'a> {
    units: &'a [&'a str],
    jobs: Vec<(String, String, String)>,
    invalid: bool,
}

impl JobCompletion<'_> {
    fn result(&self, unit: &str, job: &str) -> Result<Option<()>> {
        if self.invalid { return Err(fail("Invalid systemd job completion signal")); }
        match self.jobs.iter().find(|(name, path, _)| name == unit && path == job) {
            Some((_, _, result)) if result == "done" => Ok(Some(())),
            Some((_, _, result)) => Err(fail(format!("Systemd job for {unit} returned {result}"))),
            None => Ok(None),
        }
    }
}

unsafe extern "C" fn job_removed(message: *mut c_void, data: *mut c_void, _: *mut c_void) -> c_int {
    let mut completion = unsafe { &*data.cast::<RefCell<JobCompletion<'_>>>() }.borrow_mut();
    let mut path: *const c_char = ptr::null();
    let mut unit: *const c_char = ptr::null();
    let mut result: *const c_char = ptr::null();
    let observed = unsafe {
        sd_bus_message_skip(message, c"u".as_ptr()) >= 0
            && sd_bus_message_read_basic(message, b'o' as c_char, (&mut path as *mut *const c_char).cast()) == 1
            && sd_bus_message_read_basic(message, b's' as c_char, (&mut unit as *mut *const c_char).cast()) == 1
            && sd_bus_message_read_basic(message, b's' as c_char, (&mut result as *mut *const c_char).cast()) == 1
    };
    if !observed || path.is_null() || unit.is_null() || result.is_null() {
        completion.invalid = true;
        return 0;
    }
    let unit = unsafe { CStr::from_ptr(unit) }.to_bytes();
    if !completion.units.iter().any(|name| name.as_bytes() == unit) { return 0; }
    let path = unsafe { CStr::from_ptr(path) }.to_bytes();
    let result = unsafe { CStr::from_ptr(result) }.to_bytes();
    if path.len() > 128 || result.len() > 64 || completion.jobs.len() >= 64 {
        completion.invalid = true;
    } else {
        completion.jobs.push((String::from_utf8_lossy(unit).into_owned(),
            String::from_utf8_lossy(path).into_owned(), String::from_utf8_lossy(result).into_owned()));
    }
    0
}

pub(super) fn reload_nginx(timeout: Duration, restoring: bool) -> Result<()> {
    change_release_units(ReleaseServiceChange::ReloadNginx, &["nginx.service"], timeout, restoring)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseServiceChange { Restart, Stop, ReloadNginx }

pub(super) fn change_release_units(change: ReleaseServiceChange, units: &[&str], timeout: Duration, restoring: bool) -> Result<()> {
    const RESTART: &[&str] = &["life-board-workgarden.service", "appdev-workspace.service", "appdev-browser.service",
        "appdev-life-board-browser.service", "appdev-life-board-gateway.service", "life-board-network.service",
        "appdev-shop.service", "appdev-shop-gateway.service"];
    let user = units == ["life-board-workgarden.service"];
    let allowed = match change {
        ReleaseServiceChange::Restart => units.iter().all(|unit| RESTART.contains(unit)
            && (user || *unit != "life-board-workgarden.service")),
        ReleaseServiceChange::Stop => units.iter().all(|unit| matches!(*unit, "appdev-shop.service" | "appdev-shop-gateway.service")),
        ReleaseServiceChange::ReloadNginx => units == ["nginx.service"],
    };
    if !allowed || units.is_empty() || units.iter().enumerate().any(|(i, unit)| units[..i].contains(unit)) {
        return Err(fail("Systemd release operation is outside its admitted unit set"));
    }
    let deadline = Deadline { restoring, ..Deadline::new(timeout) };
    let completion = RefCell::new(JobCompletion { units, jobs: Vec::new(), invalid: false });
    let (bus, uid) = release_binding_bus(user, deadline)?;
    let reply = call_with_string(&bus, c"org.freedesktop.DBus", c"/org/freedesktop/DBus",
        c"org.freedesktop.DBus", c"GetNameOwner", c"org.freedesktop.systemd1", deadline)?;
    let owner = reply_text(&reply, b's', 64)?;
    if !owner.strip_prefix(':').is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit() || b == b'.')) {
        return Err(fail("Invalid systemd manager name"));
    }
    let owner = CString::new(owner)?;
    require_manager_owner(&bus, &owner, uid, deadline)?;
    let raw = bus.0.as_ptr();
    let manager = c"org.freedesktop.systemd1.Manager";
    let manager_path = c"/org/freedesktop/systemd1";
    let rule = CString::new(format!("type='signal',sender='{}',path='/org/freedesktop/systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved'", owner.to_str()?))?;
    // The floating match belongs to the bus, which is dropped before its callback data.
    checked(unsafe { sd_bus_set_method_call_timeout(raw, remaining(deadline)?) })?;
    checked(unsafe { sd_bus_add_match(raw, ptr::null_mut(), rule.as_ptr(), Some(job_removed),
        (&completion as *const RefCell<JobCompletion<'_>>).cast_mut().cast()) })?;
    let call = |method: &CStr, unit: Option<&CStr>| -> Result<Message> {
        let mut request = ptr::null_mut();
        checked(unsafe { sd_bus_message_new_method_call(raw, &mut request, owner.as_ptr(),
            manager_path.as_ptr(), manager.as_ptr(), method.as_ptr()) })?;
        let request = Message(NonNull::new(request).ok_or_else(|| fail("Missing systemd release request"))?);
        checked(unsafe { sd_bus_message_set_auto_start(request.0.as_ptr(), 0) })?;
        if let Some(unit) = unit {
            checked(unsafe { sd_bus_message_append(request.0.as_ptr(), c"ss".as_ptr(), unit.as_ptr(), c"replace".as_ptr()) })?;
        }
        let mut reply = ptr::null_mut();
        checked(unsafe { sd_bus_call(raw, request.0.as_ptr(), remaining(deadline)?, ptr::null_mut(), &mut reply) })?;
        Ok(Message(NonNull::new(reply).ok_or_else(|| fail("Missing systemd release reply"))?))
    };
    call(c"Subscribe", None)?;
    let method = match change {
        ReleaseServiceChange::Restart => c"RestartUnit",
        ReleaseServiceChange::Stop => c"StopUnit",
        ReleaseServiceChange::ReloadNginx => c"ReloadUnit",
    };
    let mut jobs = Vec::new();
    let mut errors = Vec::new();
    for &unit in units {
        remaining(deadline)?;
        let name = CString::new(unit)?;
        match call(method, Some(&name)).and_then(|reply| reply_text(&reply, b'o', 128)) {
            Ok(job) if job.strip_prefix("/org/freedesktop/systemd1/job/")
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())) => jobs.push((unit, job)),
            Ok(_) => errors.push(format!("Invalid systemd job path for {unit}")),
            Err(error) => errors.push(format!("Could not queue the systemd job for {unit}: {error}")),
        }
    }
    while !jobs.is_empty() {
        let timeout = remaining(deadline)?.min(100_000);
        {
            let completion = completion.borrow();
            if completion.invalid { return Err(fail("Invalid systemd job completion signal")); }
            jobs.retain(|(unit, job)| match completion.result(unit, job) {
                Ok(None) => true,
                Ok(Some(())) => false,
                Err(error) => { errors.push(error.to_string()); false }
            });
        }
        if jobs.is_empty() { break; }
        if checked(unsafe { sd_bus_process(raw, ptr::null_mut()) })? == 0 {
            checked(unsafe { sd_bus_wait(raw, timeout) })?;
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(fail(errors.join(", "))) }
}

#[cfg(test)]
#[test]
fn release_service_change_requires_success_from_the_exact_job() -> Result<()> {
    let path = |id| format!("/org/freedesktop/systemd1/job/{id}");
    let unit = "nginx.service";
    let mut completion = JobCompletion { units: &[unit], jobs: vec![(unit.into(), path(2), "done".into())], invalid: false };
    assert_eq!(completion.result(unit, &path(1))?, None);
    assert_eq!(completion.result("appdev-browser.service", &path(2))?, None);
    completion.jobs.push((unit.into(), path(1), "canceled".into()));
    assert!(completion.result(unit, &path(1)).is_err());
    assert_eq!(completion.result(unit, &path(2))?, Some(()));
    completion.invalid = true;
    assert!(completion.result(unit, &path(2)).is_err());
    Ok(())
}

#[cfg(test)]
#[test]
fn release_service_change_rejects_unadmitted_units_before_connecting() {
    use ReleaseServiceChange::*;
    for (change, units) in [
        (Restart, &["sshd.service"][..]),
        (Restart, &["life-board-workgarden.service", "appdev-workspace.service"][..]),
        (Stop, &["appdev-browser.service"][..]),
        (Stop, &["appdev-shop.service", "appdev-shop.service"][..]),
        (ReloadNginx, &["appdev-shop.service"][..]),
    ] {
        let error = change_release_units(change, units, Duration::ZERO, true).unwrap_err();
        assert!(error.to_string().contains("outside its admitted unit set"));
    }
}

pub(super) fn running_service_names(user: bool) -> Result<Vec<String>> {
    let deadline = Deadline::new(Duration::from_millis(1500));
    let (bus, uid) = directory_bus(user, deadline)?;
    let (reply, _) = directory_units(&bus, uid, true, deadline)?;
    let raw = reply.0.as_ptr();
    let mut names = Vec::new();
    for _ in 0..4096 {
        remaining(deadline)?;
        if checked(unsafe { sd_bus_message_enter_container(raw, b'r' as c_char, c"ssssssouso".as_ptr()) })? == 0 {
            names.sort_unstable();
            return Ok(names);
        }
        let name = reply_text(&reply, b's', 255)?;
        if crate::directory::observed_unit(&name, ".service") { names.push(name); }
        checked(unsafe { sd_bus_message_skip(raw, c"sssssouso".as_ptr()) })?;
        checked(unsafe { sd_bus_message_exit_container(raw) })?;
    }
    Err(fail("Systemd service listing exceeded its unit bound"))
}

pub(super) struct DirectoryTimer {
    pub name: String,
    pub service: String,
    pub next_us: u64,
    pub last_us: u64,
}

pub(super) fn directory_timers(user: bool) -> Result<Vec<DirectoryTimer>> {
    let deadline = Deadline::new(Duration::from_millis(1500));
    let (bus, uid) = directory_bus(user, deadline)?;
    let (reply, sender) = directory_units(&bus, uid, false, deadline)?;
    let raw = reply.0.as_ptr();
    let mut timers = Vec::new();
    for _ in 0..4096 {
        remaining(deadline)?;
        if checked(unsafe { sd_bus_message_enter_container(raw, b'r' as c_char, c"ssssssouso".as_ptr()) })? == 0 {
            timers.sort_unstable_by_key(|timer: &DirectoryTimer| (if timer.next_us == 0 { u64::MAX } else { timer.next_us }, timer.name.clone()));
            return Ok(timers);
        }
        let name = reply_text(&reply, b's', 255)?;
        checked(unsafe { sd_bus_message_skip(raw, c"sssss".as_ptr()) })?;
        let path = reply_text(&reply, b'o', 1024)?;
        checked(unsafe { sd_bus_message_skip(raw, c"uso".as_ptr()) })?;
        checked(unsafe { sd_bus_message_exit_container(raw) })?;
        if !crate::directory::observed_unit(&name, ".timer") { continue; }
        if timers.len() == 256 { return Err(fail("Systemd timer listing exceeded its unit bound")); }
        let unit = Unit { path: CString::new(path)?, sender: sender.clone() };
        let interface = c"org.freedesktop.systemd1.Timer";
        let service = string_property(&bus, &unit, interface, c"Unit", 255, deadline)?;
        let next_real = uint64_property(&bus, &unit, interface, c"NextElapseUSecRealtime", deadline)?;
        let next_mono = uint64_property(&bus, &unit, interface, c"NextElapseUSecMonotonic", deadline)?;
        let last_us = uint64_property(&bus, &unit, interface, c"LastTriggerUSec", deadline)?;
        let next_us = next_timer_time(next_real, next_mono)?;
        timers.push(DirectoryTimer { name, service, next_us, last_us });
    }
    Err(fail("Systemd timer listing exceeded its scan bound"))
}

fn next_timer_time(realtime: u64, monotonic: u64) -> Result<u64> {
    let real = (realtime != 0 && realtime != u64::MAX).then_some(realtime);
    if monotonic == 0 || monotonic == u64::MAX { return Ok(real.unwrap_or(0)); }
    let micros = |clock| -> io::Result<i128> {
        let mut time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        if unsafe { libc::clock_gettime(clock, &mut time) } != 0 { return Err(io::Error::last_os_error()); }
        Ok(i128::from(time.tv_sec) * 1_000_000 + i128::from(time.tv_nsec) / 1000)
    };
    let converted = u64::try_from(i128::from(monotonic) + micros(libc::CLOCK_REALTIME)? - micros(libc::CLOCK_MONOTONIC)?)?;
    Ok(real.map_or(converted, |real| real.min(converted)))
}

pub(super) struct DirectoryRun {
    pub name: String,
    pub invocation: String,
    pub start_us: u64,
    pub end_us: u64,
    pub result: String,
}

pub(super) fn directory_runs(user: bool, names: impl Iterator<Item = impl AsRef<str>>) -> Result<Vec<DirectoryRun>> {
    let deadline = Deadline::new(Duration::from_millis(1500));
    let (bus, uid) = directory_bus(user, deadline)?;
    let mut rows = Vec::new();
    for name in names.take(64) {
        remaining(deadline)?;
        let name = name.as_ref();
        let observation = (|| -> Result<DirectoryRun> {
            let unit = get_unit(&bus, name, deadline)?;
            require_unit_owner(&bus, &unit, uid, deadline)?;
            let interface = c"org.freedesktop.systemd1.Service";
            let canonical = string_property(&bus, &unit, c"org.freedesktop.systemd1.Unit", c"Id", 255, deadline)?;
            if canonical != name { return Err(fail("Timer service name did not match")); }
            let invocation = invocation_id(&bus, &unit, deadline)?;
            let start_us = uint64_property(&bus, &unit, interface, c"ExecMainStartTimestamp", deadline)?;
            let end_us = uint64_property(&bus, &unit, interface, c"ExecMainExitTimestamp", deadline)?;
            let result = string_property(&bus, &unit, interface, c"Result", 64, deadline)?;
            if invocation_id(&bus, &unit, deadline)? != invocation { return Err(fail("Timer service invocation changed")); }
            Ok(DirectoryRun { name: canonical, invocation, start_us, end_us, result })
        })();
        if let Ok(row) = observation { rows.push(row); }
    }
    Ok(rows)
}

fn directory_bus(user: bool, deadline: Deadline) -> Result<(Bus, u32)> {
    if user {
        let uid = unsafe { libc::geteuid() };
        Ok((connect(Path::new(&format!("/run/user/{uid}/bus")), uid, Some(uid), deadline)?, uid))
    } else {
        Ok((connect(Path::new("/run/dbus/system_bus_socket"), 0, None, deadline)?, 0))
    }
}

fn directory_units(bus: &Bus, uid: u32, running: bool, deadline: Deadline) -> Result<(Message, CString)> {
    let raw = bus.0.as_ptr();
    let mut request = ptr::null_mut();
    let method = if running { c"ListUnitsFiltered" } else { c"ListUnits" };
    checked(unsafe { sd_bus_message_new_method_call(raw, &mut request, c"org.freedesktop.systemd1".as_ptr(),
        c"/org/freedesktop/systemd1".as_ptr(), c"org.freedesktop.systemd1.Manager".as_ptr(), method.as_ptr()) })?;
    let request = Message(NonNull::new(request).ok_or_else(|| fail("Missing systemd unit listing request"))?);
    checked(unsafe { sd_bus_message_set_auto_start(request.0.as_ptr(), 0) })?;
    if running {
        checked(unsafe { sd_bus_message_append(request.0.as_ptr(), c"as".as_ptr(), 1 as c_int, c"running".as_ptr()) })?;
    }
    let mut reply = ptr::null_mut();
    checked(unsafe { sd_bus_call(raw, request.0.as_ptr(), remaining(deadline)?, ptr::null_mut(), &mut reply) })?;
    let reply = Message(NonNull::new(reply).ok_or_else(|| fail("Missing systemd unit listing"))?);
    let sender = unsafe { sd_bus_message_get_sender(reply.0.as_ptr()) };
    if sender.is_null() { return Err(fail("Missing systemd listing sender")); }
    let sender = unsafe { CStr::from_ptr(sender) };
    if !sender.to_bytes().starts_with(b":") { return Err(fail("Invalid systemd listing sender")); }
    require_manager_owner(bus, sender, uid, deadline)?;
    if checked(unsafe { sd_bus_message_enter_container(reply.0.as_ptr(), b'a' as c_char, c"(ssssssouso)".as_ptr()) })? != 1 {
        return Err(fail("Invalid systemd unit listing"));
    }
    Ok((reply, sender.to_owned()))
}

fn reply_text(reply: &Message, kind: u8, limit: usize) -> Result<String> {
    let mut value: *const c_char = ptr::null();
    let read = checked(unsafe { sd_bus_message_read_basic(reply.0.as_ptr(), kind as c_char,
        (&mut value as *mut *const c_char).cast()) })?;
    if read != 1 || value.is_null() { return Err(fail("Missing systemd listing field")); }
    let value = unsafe { CStr::from_ptr(value) }.to_str()?;
    if value.len() > limit { return Err(fail("Systemd listing field exceeded its size bound")); }
    Ok(value.to_owned())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReleaseCommand {
    path: String,
    argv: Vec<String>,
    ignore_errors: bool,
}

pub(super) fn release_commands(name: &str, workgarden_user: bool) -> Result<Vec<ReleaseCommand>> {
    let deadline = Deadline::new(Duration::from_secs(10));
    let (bus, owner) = release_binding_bus(workgarden_user, deadline)?;
    let unit = get_unit(&bus, name, deadline)?;
    require_unit_owner(&bus, &unit, owner, deadline)?;
    let reply = release_property(&bus, &unit, c"ExecStart", c"a(sasbttttuii)", deadline)?;
    let raw = reply.0.as_ptr();
    if checked(unsafe { sd_bus_message_enter_container(raw, b'a' as c_char, c"(sasbttttuii)".as_ptr()) })? != 1 {
        return Err(fail("Invalid systemd ExecStart array"));
    }
    let mut commands = Vec::new();
    while checked(unsafe { sd_bus_message_enter_container(raw, b'r' as c_char, c"sasbttttuii".as_ptr()) })? == 1 {
        if commands.len() >= 16 { return Err(fail("Systemd ExecStart exceeded its command bound")); }
        let path = reply_text(&reply, b's', 4096)?;
        let argv = string_array(&reply)?;
        let mut ignored: c_int = 0;
        if checked(unsafe { sd_bus_message_read_basic(raw, b'b' as c_char, (&mut ignored as *mut c_int).cast()) })? != 1 {
            return Err(fail("Missing systemd ExecStart error policy"));
        }
        checked(unsafe { sd_bus_message_skip(raw, c"ttttuii".as_ptr()) })?;
        checked(unsafe { sd_bus_message_exit_container(raw) })?;
        commands.push(ReleaseCommand { path, argv, ignore_errors: ignored != 0 });
    }
    Ok(commands)
}

pub(super) fn release_nginx_pid(restoring: bool) -> Result<u32> {
    let deadline = Deadline { restoring, ..Deadline::new(Duration::from_secs(2)) };
    let (bus, owner) = release_binding_bus(false, deadline)?;
    let unit = get_unit(&bus, "nginx.service", deadline)?;
    require_unit_owner(&bus, &unit, owner, deadline)?;
    SystemServices(bus).service_pid(&unit, deadline)
}

pub(super) fn release_network_environment() -> Result<Vec<String>> {
    let deadline = Deadline::new(Duration::from_secs(10));
    let (bus, owner) = release_binding_bus(false, deadline)?;
    let unit = get_unit(&bus, "life-board-network.service", deadline)?;
    require_unit_owner(&bus, &unit, owner, deadline)?;
    string_array(&release_property(&bus, &unit, c"Environment", c"as", deadline)?)
}

fn release_binding_bus(workgarden_user: bool, deadline: Deadline) -> Result<(Bus, u32)> {
    if !workgarden_user { return directory_bus(false, deadline); }
    let mut account = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = [0_u8; 16_384];
    let mut found = ptr::null_mut();
    let code = unsafe { libc::getpwnam_r(c"ubuntu".as_ptr(), account.as_mut_ptr(),
        buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
    if code != 0 { return Err(io::Error::from_raw_os_error(code).into()); }
    if found.is_null() { return Err(fail("Missing AppDev Workgarden user")); }
    let uid = unsafe { account.assume_init() }.pw_uid;
    Ok((connect(Path::new(&format!("/run/user/{uid}/bus")), uid, Some(uid), deadline)?, uid))
}

fn release_property(bus: &Bus, unit: &Unit, name: &CStr, signature: &CStr, deadline: Deadline) -> Result<Message> {
    let raw = bus.0.as_ptr();
    checked(unsafe { sd_bus_set_method_call_timeout(raw, remaining(deadline)?) })?;
    let mut reply = ptr::null_mut();
    checked(unsafe { sd_bus_get_property(raw, unit.sender.as_ptr(), unit.path.as_ptr(),
        c"org.freedesktop.systemd1.Service".as_ptr(), name.as_ptr(), ptr::null_mut(), &mut reply, signature.as_ptr()) })?;
    Ok(Message(NonNull::new(reply).ok_or_else(|| fail("Missing systemd release binding property"))?))
}

fn string_array(reply: &Message) -> Result<Vec<String>> {
    let raw = reply.0.as_ptr();
    if checked(unsafe { sd_bus_message_enter_container(raw, b'a' as c_char, c"s".as_ptr()) })? != 1 {
        return Err(fail("Invalid systemd string array"));
    }
    let mut fields = Vec::new();
    let mut bytes = 0;
    loop {
        let mut value: *const c_char = ptr::null();
        if checked(unsafe { sd_bus_message_read_basic(raw, b's' as c_char, (&mut value as *mut *const c_char).cast()) })? == 0 { break; }
        if value.is_null() { return Err(fail("Missing systemd string array value")); }
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        bytes += value.len();
        if fields.len() >= 256 || bytes > 32 * 1024 { return Err(fail("Systemd string array exceeded its bound")); }
        fields.push(value.to_owned());
    }
    checked(unsafe { sd_bus_message_exit_container(raw) })?;
    Ok(fields)
}

fn get_unit(bus: &Bus, unit: &str, deadline: Deadline) -> Result<Unit> {
    // Resolve aliases without loading a unit or activating a D-Bus service.
    let reply = call_with_string(bus, c"org.freedesktop.systemd1", c"/org/freedesktop/systemd1",
        c"org.freedesktop.systemd1.Manager", c"GetUnit", &CString::new(unit)?, deadline)?;
    let mut path: *const c_char = ptr::null();
    let path_read = checked(unsafe { sd_bus_message_read_basic(reply.0.as_ptr(), b'o' as c_char,
        (&mut path as *mut *const c_char).cast()) })?;
    let sender = unsafe { sd_bus_message_get_sender(reply.0.as_ptr()) };
    if path_read != 1 || path.is_null() || sender.is_null() {
        return Err(fail("invalid systemd unit reply"));
    }
    let path = unsafe { CStr::from_ptr(path) };
    let sender = unsafe { CStr::from_ptr(sender) };
    if !path.to_bytes().starts_with(b"/org/freedesktop/systemd1/unit/") || !sender.to_bytes().starts_with(b":") {
        return Err(fail("invalid systemd unit reply"));
    }
    Ok(Unit { path: path.to_owned(), sender: sender.to_owned() })
}

pub(super) struct SystemServices(Bus);

pub(super) struct ServiceMeasurement {
    pub pid: u32,
    pub active_state: String,
    pub memory_current: Option<u64>,
}

impl SystemServices {
    pub(super) fn open() -> Result<Self> {
        Self::open_at(Path::new("/run/dbus/system_bus_socket"), 0, Duration::from_secs(2))
    }

    fn open_at(path: &Path, owner: u32, timeout: Duration) -> Result<Self> {
        Ok(Self(connect(path, owner, None, Deadline::new(timeout))?))
    }

    pub(super) fn working_directory(&self, unit: &str) -> Result<String> {
        self.observe(unit, c"org.freedesktop.systemd1.Service", c"WorkingDirectory", 4096)
    }

    pub(super) fn active_state(&self, unit: &str) -> Result<String> {
        self.observe(unit, c"org.freedesktop.systemd1.Unit", c"ActiveState", 64)
    }

    pub(super) fn main_pid(&self, name: &str) -> Result<u32> {
        let deadline = Deadline::new(Duration::from_secs(2));
        let unit = self.resolve(name, deadline)?;
        self.service_pid(&unit, deadline)
    }

    pub(super) fn measurement(&self, name: &str) -> Result<ServiceMeasurement> {
        let deadline = Deadline::new(Duration::from_secs(2));
        let unit = self.resolve(name, deadline)?;
        let pid = self.service_pid(&unit, deadline)?;
        let active_state = string_property(&self.0, &unit, c"org.freedesktop.systemd1.Unit", c"ActiveState", 64, deadline)?;
        let bytes = uint64_property(&self.0, &unit, c"org.freedesktop.systemd1.Service", c"MemoryCurrent", deadline)?;
        if self.service_pid(&unit, deadline)? != pid {
            return Err(fail("Systemd service changed its main process during observation"));
        }
        Ok(ServiceMeasurement { pid, active_state, memory_current: (bytes != u64::MAX).then_some(bytes) })
    }

    fn service_pid(&self, unit: &Unit, deadline: Deadline) -> Result<u32> {
        let mut pid = 0_u32;
        self.service_property(unit, c"MainPID", b'u', (&mut pid as *mut u32).cast(), deadline)?;
        if pid == 0 { return Err(fail("Expected a running sweep service")); }
        Ok(pid)
    }

    fn service_property(&self, unit: &Unit, property: &CStr, kind: u8, value: *mut c_void, deadline: Deadline) -> Result<()> {
        let raw = self.0.0.as_ptr();
        checked(unsafe { sd_bus_set_method_call_timeout(raw, remaining(deadline)?) })?;
        checked(unsafe { sd_bus_get_property_trivial(raw, unit.sender.as_ptr(), unit.path.as_ptr(),
            c"org.freedesktop.systemd1.Service".as_ptr(), property.as_ptr(), ptr::null_mut(), kind as c_char, value) })?;
        Ok(())
    }

    fn observe(&self, unit: &str, interface: &CStr, property: &CStr, limit: usize) -> Result<String> {
        let deadline = Deadline::new(Duration::from_secs(2));
        let unit = self.resolve(unit, deadline)?;
        string_property(&self.0, &unit, interface, property, limit, deadline)
    }

    fn resolve(&self, name: &str, deadline: Deadline) -> Result<Unit> {
        let unit = get_unit(&self.0, name, deadline)?;
        require_unit_owner(&self.0, &unit, 0, deadline)?;
        Ok(unit)
    }
}

fn require_unit_owner(bus: &Bus, unit: &Unit, expected: u32, deadline: Deadline) -> Result<()> {
    require_manager_owner(bus, &unit.sender, expected, deadline)
}

fn require_manager_owner(bus: &Bus, sender: &CStr, expected: u32, deadline: Deadline) -> Result<()> {
    let owner = call_with_string(bus, c"org.freedesktop.DBus", c"/org/freedesktop/DBus",
        c"org.freedesktop.DBus", c"GetConnectionUnixUser", sender, deadline)?;
    let mut uid = u32::MAX;
    let read = checked(unsafe { sd_bus_message_read_basic(owner.0.as_ptr(), b'u' as c_char,
        (&mut uid as *mut u32).cast()) })?;
    if read != 1 || uid != expected { return Err(fail("Systemd manager has the wrong Unix UID")); }
    Ok(())
}

fn string_property(bus: &Bus, unit: &Unit, interface: &CStr, property: &CStr, limit: usize, deadline: Deadline) -> Result<String> {
    let raw = bus.0.as_ptr();
    // Target the unique owner returned by GetUnit. A restarted manager must be resolved again.
    checked(unsafe { sd_bus_set_method_call_timeout(raw, remaining(deadline)?) })?;
    let mut value = ptr::null_mut();
    checked(unsafe { sd_bus_get_property_string(raw, unit.sender.as_ptr(), unit.path.as_ptr(),
        interface.as_ptr(), property.as_ptr(), ptr::null_mut(), &mut value) })?;
    if value.is_null() { return Err(fail("Missing systemd property value")); }
    let result = (|| {
        let value = unsafe { CStr::from_ptr(value) }.to_str()?;
        if value.len() > limit { return Err(fail("Systemd property exceeded its byte limit")); }
        Ok(value.to_owned())
    })();
    unsafe { libc::free(value.cast()); }
    result
}

#[cfg(test)]
#[test]
fn unresponsive_bus_cannot_hold_file_index_indefinitely() -> Result<()> {
    use crate::appdev_host_process::Scratch;
    use std::os::unix::net::UnixListener;

    let scratch = Scratch::create(&std::env::temp_dir(), "file-index-bus-")?;
    let path = scratch.path().join("bus");
    // A listening socket can complete connect while never answering the D-Bus handshake.
    let _listener = UnixListener::bind(&path)?;
    let started = Instant::now();
    let uid = unsafe { libc::geteuid() };
    let error = main_pid_on_bus(&path, uid, "file-index-fixture.service").unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(3), "{error}");
    assert_eq!(error.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error), Some(libc::ETIMEDOUT), "{error}");
    Ok(())
}

#[cfg(test)]
#[test]
fn unresponsive_bus_cannot_hold_system_service_observation_indefinitely() -> Result<()> {
    use crate::appdev_host_process::Scratch;
    use std::os::unix::net::UnixListener;

    let scratch = Scratch::create(&std::env::temp_dir(), "system-services-bus-")?;
    let path = scratch.path().join("bus");
    let _listener = UnixListener::bind(&path)?;
    let uid = unsafe { libc::geteuid() };
    let started = Instant::now();
    let result = SystemServices::open_at(&path, uid, Duration::from_millis(100));
    let error = result.err().expect("unresponsive bus must fail authentication");
    assert!(started.elapsed() < Duration::from_secs(1), "{error}");
    assert_eq!(error.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error), Some(libc::ETIMEDOUT));
    Ok(())
}
