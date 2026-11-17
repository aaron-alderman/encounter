use crate::{Result, fail};
use std::{
    ffi::CString, fs, io::{self, Read}, net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::{fd::AsRawFd, unix::{ffi::OsStrExt, fs::{DirBuilderExt, MetadataExt}, process::CommandExt}},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicI32, Ordering},
    thread,
    time::{Duration, Instant},
};

static SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn interrupted(signal: libc::c_int) {
    let _ = SIGNAL.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

pub fn interruption() -> Option<u8> {
    let signal = SIGNAL.load(Ordering::Relaxed);
    (signal != 0).then_some(128 + signal as u8)
}

pub(crate) fn handle_hangup() {
    unsafe { libc::signal(libc::SIGHUP, interrupted as *const () as libc::sighandler_t); }
}

pub(crate) enum ServiceTool { Git, Nginx }

impl ServiceTool {
    pub(crate) fn command(self) -> Result<Command> {
        let path = Path::new(match self {
            Self::Git => "/usr/bin/git",
            Self::Nginx => "/usr/sbin/nginx",
        });
        let metadata = path.symlink_metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(fail("Expected a root-owned platform service executable"));
        }
        crate::package::require_native_runtime(path)?;
        let mut command = Command::new(path);
        command.env_clear().env("LC_ALL", "C").stdin(Stdio::null());
        Ok(command)
    }
}

pub struct Supervisor {
    children: Vec<(String, Child)>,
    restoring_release: bool,
}

impl Supervisor {
    pub fn children() -> Self { Self { children: Vec::new(), restoring_release: false } }

    pub fn release_recovery() -> Self { Self { children: Vec::new(), restoring_release: true } }

    pub fn new() -> Self {
        // The CLI owns signal handling for the duration of these host commands.
        unsafe {
            libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, interrupted as *const () as libc::sighandler_t);
        }
        Self::children()
    }

    fn cancelled(&self) -> bool { !self.restoring_release && interruption().is_some() }

    pub fn start(&mut self, name: &str, command: &mut Command) -> Result<&mut Child> {
        if self.cancelled() {
            return Err(fail("AppDev command interrupted"));
        }
        let child = command.process_group(0).spawn().map_err(|error| fail(format!("{name}: {error}")))?;
        self.children.push((name.to_owned(), child));
        Ok(&mut self.children.last_mut().expect("started child").1)
    }

    pub fn run(&mut self, name: &str, command: &mut Command) -> Result<()> {
        self.run_until(name, command, None)
    }

    pub fn run_until(&mut self, name: &str, command: &mut Command, timeout: Option<Duration>) -> Result<()> {
        let deadline = timeout.map(|duration| Instant::now() + duration);
        self.start(name, command)?;
        while !self.cancelled() {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(fail(format!("{name} timed out")));
            }
            if let Some(status) = self.children.last_mut().expect("started child").1.try_wait()? {
                if status.success() {
                    self.children.pop();
                    return Ok(());
                }
                return Err(fail(format!("{name} failed ({status})")));
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(fail("AppDev command interrupted"))
    }

    pub fn capture(&mut self, name: &str, command: &mut Command, timeout: Duration, limit: usize) -> Result<Vec<u8>> {
        let (status, output) = self.capture_status(name, command, timeout, limit)?;
        if !status.success() { return Err(fail(format!("{name} failed ({status})"))); }
        Ok(output)
    }

    pub fn capture_status(&mut self, name: &str, command: &mut Command, timeout: Duration, limit: usize)
        -> Result<(ExitStatus, Vec<u8>)> {
        let deadline = Instant::now() + timeout;
        let restoring_release = self.restoring_release;
        let child = self.start(name, command.stdout(Stdio::piped()))?;
        let mut output = child.stdout.take().ok_or_else(|| fail("Missing AppDev stdout pipe"))?;
        nonblocking(output.as_raw_fd())?;
        let mut result = Vec::new();
        let mut eof = false;
        while (restoring_release || interruption().is_none()) && Instant::now() < deadline {
            if !eof {
                match (&mut output).take((limit + 1 - result.len()) as u64).read_to_end(&mut result) {
                    Ok(_) => eof = true,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
                if result.len() > limit { return Err(fail(format!("{name} exceeded its output limit"))); }
            }
            if let Some(status) = child.try_wait()? {
                if eof {
                    if status.success() { self.children.pop(); }
                    return Ok((status, result));
                }
            }
            thread::sleep(Duration::from_millis(25));
        }
        if self.cancelled() { return Err(fail("AppDev command interrupted")); }
        Err(fail(format!("{name} timed out")))
    }

    pub fn start_assurance_browser(&mut self, release: &Path) -> Result<String> {
        let runtime = release.join("encounter");
        crate::package::require_native_runtime(&runtime)?;
        let mut command = Command::new(runtime);
        command.args(["appdev-browser-host", "--allow-aster-stream"]).arg(release).arg("0")
            .stdin(Stdio::null()).stdout(Stdio::piped());
        let child = self.start("AppDev Assurance browser host", &mut command)?;
        let mut output = child.stdout.take().ok_or_else(|| fail("Missing AppDev browser startup pipe"))?;
        nonblocking(output.as_raw_fd())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut announcement = Vec::new();
        let mut buffer = [0; 128];
        while Instant::now() < deadline {
            self.check()?;
            match output.read(&mut buffer) {
                Ok(0) => return Err(fail("AppDev browser host closed its startup pipe")),
                Ok(size) => {
                    announcement.extend_from_slice(&buffer[..size]);
                    if announcement.len() > buffer.len() {
                        return Err(fail("AppDev browser host startup announcement exceeded its limit"));
                    }
                    if announcement.contains(&b'\n') { return assurance_origin(&announcement); }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            thread::sleep(Duration::from_millis(25));
        }
        Err(fail("AppDev browser host startup timed out"))
    }

    fn exited(&mut self) -> Result<Option<(String, ExitStatus)>> {
        for (name, child) in &mut self.children {
            if let Some(status) = child.try_wait()? {
                return Ok(Some((name.clone(), status)));
            }
        }
        Ok(None)
    }

    pub fn check(&mut self) -> Result<()> {
        if self.cancelled() {
            return Err(fail("AppDev command interrupted"));
        }
        if let Some((name, status)) = self.exited()? {
            return Err(fail(format!("{name} stopped ({status})")));
        }
        Ok(())
    }

    pub(crate) fn wait_for_success(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while !self.cancelled() && Instant::now() < deadline {
            let (name, child) = self.children.last_mut().ok_or_else(|| fail("Missing supervised child"))?;
            if let Some(status) = child.try_wait()? {
                if !status.success() { return Err(fail(format!("{name} failed ({status})"))); }
                self.children.pop();
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        if self.cancelled() { return Err(fail("AppDev command interrupted")); }
        Err(fail("Supervised child did not stop in time"))
    }

    pub fn listen(&mut self, port: u16) -> Result<()> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            self.check()?;
            if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(75));
        }
        Err(fail(format!("Preview listener did not start at {address}")))
    }

    pub fn supervise(&mut self) -> Result<()> {
        while interruption().is_none() {
            self.check()?;
            thread::sleep(Duration::from_millis(75));
        }
        Ok(())
    }

    fn signal_groups(&self, signal: libc::c_int) {
        for (_, child) in &self.children {
            // Each started command is the leader of its own process group.
            unsafe { libc::kill(-(child.id() as libc::pid_t), signal); }
        }
    }
}

pub(crate) fn nonblocking(descriptor: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn assurance_origin(announcement: &[u8]) -> Result<String> {
    let port = std::str::from_utf8(announcement)?.strip_prefix("Encounter http://127.0.0.1:")
        .and_then(|line| line.strip_suffix('\n'))
        .filter(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|port| port.parse::<u16>().ok()).filter(|port| *port != 0)
        .ok_or_else(|| fail("AppDev browser host did not announce a loopback address"))?;
    Ok(format!("http://127.0.0.1:{port}"))
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.signal_groups(libc::SIGTERM);
        let deadline = Instant::now() + Duration::from_millis(1500);
        while Instant::now() < deadline {
            if self.children.iter_mut().all(|(_, child)| matches!(child.try_wait(), Ok(Some(_)))) {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        self.signal_groups(libc::SIGKILL);
        for (_, child) in &mut self.children { let _ = child.wait(); }
    }
}

pub fn available(port: u16) -> Result<()> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|error| fail(format!("Preview port {port}: {error}")))?;
    Ok(())
}

pub(crate) fn rename_new_path(stage: &Path, output: &Path) -> Result<()> {
    rename_with_flags(stage, output, libc::RENAME_NOREPLACE)
}

pub(crate) fn exchange_paths(left: &Path, right: &Path) -> Result<()> {
    rename_with_flags(left, right, libc::RENAME_EXCHANGE)
}

fn rename_with_flags(stage: &Path, output: &Path, flags: libc::c_uint) -> Result<()> {
    let stage = CString::new(stage.as_os_str().as_bytes())?;
    let output = CString::new(output.as_os_str().as_bytes())?;
    // The staging directory and destination have the same parent filesystem.
    let status = unsafe { libc::renameat2(libc::AT_FDCWD, stage.as_ptr(), libc::AT_FDCWD,
        output.as_ptr(), flags) };
    if status != 0 { return Err(io::Error::last_os_error().into()); }
    Ok(())
}

pub struct Scratch(PathBuf);

impl Scratch {
    pub fn create(parent: &Path, prefix: &str) -> Result<Self> {
        for _ in 0..8 {
            let mut random = [0; 8];
            getrandom::getrandom(&mut random).map_err(|error| fail(error.to_string()))?;
            let path = parent.join(format!("{prefix}{}", hex::encode(random)));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(fail("Could not allocate a private host directory"))
    }

    pub fn path(&self) -> &Path { &self.0 }

    pub fn retain(mut self) -> PathBuf { std::mem::take(&mut self.0) }
}

impl Drop for Scratch {
    fn drop(&mut self) { if !self.0.as_os_str().is_empty() { let _ = fs::remove_dir_all(&self.0); } }
}

#[cfg(test)]
#[test]
fn assurance_startup_requires_the_exact_loopback_announcement() -> Result<()> {
    assert_eq!(assurance_origin(b"Encounter http://127.0.0.1:31962\n")?, "http://127.0.0.1:31962");
    for rejected in [
        "Encounter http://0.0.0.0:31962\n", "Encounter http://127.0.0.1:0\n",
        "Encounter http://127.0.0.1:65536\n", "Encounter http://127.0.0.1:31962/extra\n",
        "Encounter http://127.0.0.1:31962\nUnexpected output\n",
    ] {
        assert!(assurance_origin(rejected.as_bytes()).is_err());
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn capture_bounds_output_and_requires_child_success() -> Result<()> {
    let capture = |command: &mut Command, timeout, limit| {
        Supervisor::children().capture("fixture probe", command, timeout, limit)
    };
    assert_eq!(capture(Command::new("/usr/bin/printf").arg("report"), Duration::from_secs(2), 6)?, b"report");
    assert!(capture(Command::new("/usr/bin/printf").arg("oversized"), Duration::from_secs(2), 6)
        .unwrap_err().to_string().contains("output limit"));
    assert!(capture(&mut Command::new("/usr/bin/false"), Duration::from_secs(2), 6).is_err());
    assert!(capture(Command::new("/usr/bin/sleep").arg("10"), Duration::from_millis(40), 6)
        .unwrap_err().to_string().contains("timed out"));
    Ok(())
}
