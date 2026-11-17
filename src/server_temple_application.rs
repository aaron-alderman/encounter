use crate::{Result, fail, http};
use serde_json::Value;
use std::{io::{self, Read}, os::{fd::AsRawFd, unix::{fs::MetadataExt, process::CommandExt}},
    path::{Path, PathBuf}, process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant}};

pub(crate) struct Application {
    args: Vec<String>,
    port: u16,
}

impl Application {
    pub(crate) fn admit(plan: &Value) -> Result<Self> {
        let coordinate = |key| {
            plan[key].as_str().map(PathBuf::from).ok_or_else(|| fail("Expected a native Temple application coordinate"))
        };
        let image = coordinate("image")?;
        let store = coordinate("store")?;
        if image.canonicalize()? != image || store.canonicalize()? != store {
            return Err(fail("Expected canonical native Temple image and store paths"));
        }
        let metadata = store.metadata()?;
        let owner = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
            return Err(fail("Expected an owner-only native Temple application store"));
        }
        for name in ["workspace.sqlite", "workspace.sqlite-wal", "workspace.sqlite-shm", "workspace.sqlite-journal"] {
            match store.join(name).symlink_metadata() {
                Ok(file) if file.is_file() && file.uid() == owner && file.nlink() == 1 => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(fail("Expected an owner-controlled native Temple application database file")),
            }
        }
        let pin = plan["sha256"].as_str().ok_or_else(|| fail("Expected the native Temple image pin"))?;
        let port = u16::try_from(plan["port"].as_u64().ok_or_else(|| fail("Expected a Temple application port"))?)?;
        crate::image::load(&image, pin)?;
        let args = vec!["serve".into(), "--image".into(),
            image.to_str().ok_or_else(|| fail("Expected a UTF-8 Temple image path"))?.to_owned(), pin.to_owned(),
            store.to_str().ok_or_else(|| fail("Expected a UTF-8 Temple store path"))?.to_owned(), port.to_string()];
        Ok(Self { args, port })
    }

    pub(crate) fn args(&self) -> &[String] { &self.args }

    pub(crate) fn start(&self, capsule: &Path, temple: &str, manifest: &str) -> Result<Runtime> {
        if http::stopping() { return Err(fail("Native Temple application startup interrupted")); }
        let mut command = Command::new("/proc/self/exe");
        command.args(&self.args).env_clear().env("LANG", "C.UTF-8")
            .env("SOURCERY_TEMPLE_ID", temple).env("SOURCERY_TEMPLE_MANIFEST_HASH", manifest)
            .env("SOURCERY_TEMPLE_CAPSULE", capsule)
            .stdin(Stdio::null()).stdout(Stdio::piped()).process_group(0);
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent { return Err(io::ErrorKind::Interrupted.into()); }
                Ok(())
            });
        }
        let mut runtime = Runtime { child:command.spawn()?, output:None, announcement:Vec::new(), port:self.port };
        let output = runtime.child.stdout.take().ok_or_else(|| fail("Missing native Temple application startup pipe"))?;
        let fd = output.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        runtime.output = Some(output);
        Ok(runtime)
    }
}

pub(crate) struct Runtime {
    child: Child,
    output: Option<ChildStdout>,
    announcement: Vec<u8>,
    port: u16,
}

impl Runtime {
    pub(crate) fn id(&self) -> u32 { self.child.id() }

    pub(crate) fn status(&mut self) -> Result<Option<ExitStatus>> { Ok(self.child.try_wait()?) }

    pub(crate) fn origin(&mut self) -> Result<Option<String>> {
        let output = self.output.as_mut().ok_or_else(|| fail("Missing native Temple application startup pipe"))?;
        let mut bytes = [0; 128];
        match output.read(&mut bytes) {
            Ok(0) => return Err(fail("Native Temple application closed its startup pipe")),
            Ok(size) => self.announcement.extend_from_slice(&bytes[..size]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if self.announcement.len() > bytes.len() { return Err(fail("Native Temple application announcement exceeded its limit")); }
        if !self.announcement.contains(&b'\n') { return Ok(None); }
        let line = std::str::from_utf8(&self.announcement)?;
        let port = line.strip_prefix("Encounter http://127.0.0.1:").and_then(|value| value.strip_suffix('\n'))
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u16>().ok()).filter(|port| *port != 0 && (self.port == 0 || *port == self.port))
            .ok_or_else(|| fail("Native Temple application announced an unexpected listener"))?;
        Ok(Some(format!("http://127.0.0.1:{port}")))
    }

    fn signal(&self, signal: libc::c_int) -> Result<()> {
        if unsafe { libc::kill(-(self.child.id() as libc::pid_t), signal) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) { return Err(error.into()); }
        }
        Ok(())
    }

    pub(crate) fn stop(&mut self, mut maintain_lease: impl FnMut() -> Result<()>) -> Result<ExitStatus> {
        if let Some(status) = self.status()? { return Ok(status); }
        self.signal(libc::SIGTERM)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut maintenance_error = None;
        while Instant::now() < deadline {
            if let Some(status) = self.status()? { return maintenance_error.map_or(Ok(status), Err); }
            if maintenance_error.is_none() { maintenance_error = maintain_lease().err(); }
            std::thread::sleep(Duration::from_millis(25));
        }
        self.signal(libc::SIGKILL)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if self.status()?.is_some() { break; }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(fail("Native Temple application did not stop before its deadline"))
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.signal(libc::SIGKILL);
            let _ = self.child.try_wait();
        }
    }
}
