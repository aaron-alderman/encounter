use crate::{Result, fail, hosted_release_identity::{self as identity, GenerationProbe}, http,
    package::{observe_beneath, require_bounded_x64_executable}, process::Programme};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::{fs::{File, OpenOptions}, io::{self, Read, Seek, SeekFrom, Write}, net::{IpAddr, SocketAddr},
    os::{fd::AsRawFd, unix::{fs::{MetadataExt, OpenOptionsExt}, net::UnixStream, process::CommandExt}},
    path::Path, process::{Child, Command, Stdio}, thread, time::{Duration, Instant}};

const WORKER: &str = "plugins/hosted-control-plane/production-generation-worker.mjs";
const ENDPOINT: &str = "sourcery.hosted/production-child-endpoint.v1";
const PREPARED: &str = "sourcery.hosted/production-child-prepared.v1";
const LISTEN: &str = "sourcery.hosted/production-child-listen.v1";
const BOOT: &str = "sourcery.hosted/production-child-boot.v1";
const PREPARE: &str = "sourcery.hosted/production-child-prepare.v1";
const SHUTDOWN: &str = "sourcery.hosted/production-child-shutdown.v1";

pub(super) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| fail(format!("Missing admitted hosted field {key}")))
}

pub(super) struct Generation {
    child: Child,
    ipc: UnixStream,
}

impl Generation {
    pub(super) fn start(policy: &Programme, root: &Path, bind: &str, expected: &Value, platform: &Value, timeout: Duration,
        cleanup: Duration, attest: impl Fn() -> Result<()>) -> Result<(Self, SocketAddr)> {
        let launch = identity::decide(policy, "hostedRelease.childLaunch", json!({"bindHost":bind,"identity":expected}))?;
        let expected_host = text(&launch, "host")?;
        let mut generation = Self::spawn(policy, root, &launch)?;
        let result = (|| {
            let deadline = Instant::now() + timeout;
            for (request, grant) in [(BOOT, PREPARE), (PREPARED, LISTEN)] {
                let observed = generation.startup_message(request, deadline)?;
                if request == BOOT {
                    let basis = identity::decide(policy, "hostedRelease.childBasis", observed["basis"].clone())?;
                    identity::decide(policy, "hostedRelease.childIdentity", json!({"expected":expected,"observed":basis}))?;
                }
                identity::decide(policy, "hostedRelease.childPrepared", json!({
                    "expectedHash":expected["generationHash"], "platform":platform, "observed":observed,
                }))?;
                if request == PREPARED {
                    crate::hosted_launch_config::evaluate("production-readiness", observed["readiness"].clone())?;
                }
                attest()?;
                http::check_interruption(false)?;
                if Instant::now() >= deadline { return Err(fail("Hosted production startup deadline elapsed before admission")); }
                let mut message = json!({"protocol":grant,"generationHash":expected["generationHash"]});
                if grant == PREPARE {
                    message["identity"] = expected.clone();
                    message["operations"] = crate::hosted_launch_config::production_operations()?;
                    message["authority"] = crate::hosted_launch_config::production_authority()?;
                    message["claimipediaHandoff"] = crate::hosted_launch_config::production_claimipedia_handoff()?;
                    message["timesheetUrl"] = crate::hosted_launch_config::evaluate("timesheet-url",
                        observed["timesheet"].clone())?;
                    let mut environment = crate::hosted_launch_config::host_environment();
                    for (name, field) in [("DEPLOYMENT_PROFILE", "profile"), ("PORT", "port"), ("BIND_HOST", "host")] {
                        environment.insert(format!("SOURCERY_HOSTED_{name}"), launch[field].clone());
                    }
                    message["launch"] = crate::hosted_launch_config::evaluate("config",
                        json!({"cwd":root,"environment":environment,"supervisedGeneration":true}))?;
                    let manifest = crate::hosted_production_manifest::admit_supervised(root)?;
                    crate::hosted_postgres::probe_readiness(&manifest["postgres"], deadline)
                        .map_err(|error| fail(format!("Hosted production PostgreSQL readiness failed: {error}")))?;
                    let runtime = &manifest["runtime"];
                    crate::runtime_authority_client::probe_readiness(
                        Path::new(text(runtime, "socketPath")?), text(runtime, "keyId")?, deadline)
                        .map_err(|error| fail(format!("Hosted production runtime authority readiness failed: {error}")))?;
                    let socket = match std::env::var("CONTAINER_HOST") {
                        Ok(socket) => Some(socket),
                        Err(std::env::VarError::NotPresent) => None,
                        Err(error) => return Err(error.into()),
                    };
                    crate::hosted_worker_container::probe_readiness(
                        text(&manifest["worker"], "image")?, socket.as_deref(), deadline)
                        .map_err(|error| fail(format!("Hosted production Podman readiness failed: {error}")))?;
                    message["interactionSecrets"] = crate::hosted_production_manifest::interaction_secrets(
                        Path::new(text(&manifest, "interactionSecretsFile")?))?;
                    message["runtimeVerificationKeys"] = crate::hosted_production_manifest::runtime_verification_keys(
                        Path::new(text(runtime, "verificationKeysFile")?), text(runtime, "keyId")?)?;
                    message["cataloguePublication"] = crate::hosted_production_manifest::catalogue_publication(
                        Path::new(text(&manifest["capability"], "catalogPublicationFile")?))?;
                    message["storageConformanceEvidence"] = crate::hosted_production_manifest::storage_conformance(
                        Path::new(text(&manifest["capability"], "conformanceEvidenceFile")?))?;
                    message["oauthClients"] = crate::mcp_client::admit_registered_clients(
                        crate::hosted_production_manifest::release_document(Path::new(text(&manifest, "oauthClientsFile")?))?)?;
                    let operations = &manifest["operations"];
                    message["operationsReleaseProposal"] = match operations["releaseProposalFile"].as_str() {
                        Some(path) => crate::hosted_production_manifest::release_proposal(Path::new(path))?,
                        None => Value::Null,
                    };
                    message["operationsAuthority"] = if operations.is_null() { Value::Null } else {
                        crate::hosted_production_manifest::operations_roster(
                            Path::new(text(operations, "approvalAuthorityFile")?))?
                    };
                    message["infrastructureManifest"] = manifest;
                }
                generation.send_startup_grant(&message, deadline)?;
            }
            let endpoint = generation.startup_message(ENDPOINT, deadline)?;
            identity::decide(policy, "hostedRelease.childRuntime", json!({
                "expected":platform, "observed":endpoint["runtime"],
            }))?;
            let host = text(&endpoint, "host")?;
            let port = endpoint["port"].as_u64().and_then(|port| u16::try_from(port).ok()).unwrap_or(0).to_string();
            identity::probe_generation(policy, GenerationProbe {
                expected_host, observed_host: host, observed_port: &port, observed_generation: text(&endpoint, "generationHash")?,
                source: text(expected, "sourceTreeHash")?, release: text(expected, "releasePointerHash")?,
                generation: text(expected, "generationHash")?, timeout_ms: timeout.as_millis() as u64,
            }, || generation.alive())?;
            Ok(SocketAddr::new(host.parse::<IpAddr>()?, port.parse()?))
        })();
        match result {
            Ok(address) => Ok((generation, address)),
            Err(error) => {
                generation.stop(cleanup.min(Duration::from_secs(5)));
                Err(error)
            }
        }
    }

    fn spawn(policy: &Programme, root: &Path, launch: &Value) -> Result<Self> {
        http::check_interruption(false)?;
        let mut node = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open("/usr/bin/node")?;
        let metadata = node.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(fail("Hosted generation requires the protected platform Node executable"));
        }
        require_bounded_x64_executable(&mut node, 256_000_000)?;
        let pin = std::env::var("SOURCERY_HOSTED_NODE_SHA256").unwrap_or_default();
        identity::decide(policy, "hostedRelease.pin", json!(pin))?;
        node.seek(SeekFrom::Start(0))?;
        let (size, hash) = crate::archive::Work::new(Duration::from_secs(15))
            .copy(&mut node, &mut io::sink(), 256_000_000)?;
        let after = node.metadata()?;
        if size != metadata.len() || (metadata.ctime(), metadata.ctime_nsec()) != (after.ctime(), after.ctime_nsec()) {
            return Err(fail("Hosted worker executable changed while it was observed"));
        }
        identity::decide(policy, "hostedRelease.childExecutable", json!({"expected":pin,"observed":hash}))?;
        http::check_interruption(false)?;

        let worker = observe_beneath(&File::open(root)?, Path::new(WORKER))?;
        let metadata = worker.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o022 != 0 || ![0, unsafe { libc::getuid() }].contains(&metadata.uid()) {
            return Err(fail("Hosted generation requires the protected worker in the matched release"));
        }
        let worker_fd = worker.as_raw_fd();
        let (parent, channel) = UnixStream::pair()?;
        let child_fd = channel.as_raw_fd();
        parent.set_nonblocking(true)?;
        let mut token = [0_u8; 32];
        getrandom::getrandom(&mut token).map_err(|error| fail(error.to_string()))?;

        let mut command = Command::new(format!("/proc/self/fd/{}", node.as_raw_fd()));
        for name in launch["omitEnvironment"].as_array().ok_or_else(|| fail("Missing hosted worker environment policy"))? {
            command.env_remove(name.as_str().ok_or_else(|| fail("Invalid hosted worker environment field"))?);
        }
        // The fixed worker is read from its observed descriptor. Node resolves module imports from its physical release path.
        let worker_arg = format!("/proc/self/fd/{worker_fd}");
        command.arg(worker_arg).current_dir(root).process_group(0)
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
            .env("NODE_CHANNEL_FD", child_fd.to_string()).env("NODE_CHANNEL_SERIALIZATION_MODE", "json")
            .env("SOURCERY_HOSTED_DEPLOYMENT_PROFILE", text(launch, "profile")?)
            .env("SOURCERY_HOSTED_PORT", text(launch, "port")?)
            .env("SOURCERY_HOSTED_BIND_HOST", text(launch, "host")?)
            .env("SOURCERY_HOSTED_SUPERVISED_GENERATION", Base64UrlUnpadded::encode_string(&token))
            .env("SOURCERY_HOSTED_EXPECTED_SOURCE_TREE_SHA256", text(&launch["identity"], "sourceTreeHash")?)
            .env("SOURCERY_HOSTED_EXPECTED_RELEASE_POINTER_SHA256", text(&launch["identity"], "releasePointerHash")?)
            .env("SOURCERY_HOSTED_EXPECTED_GENERATION_SHA256", text(&launch["identity"], "generationHash")?);
        // Only the observed script and private channel need to survive exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(child_fd, libc::F_SETFD, 0) < 0 || libc::fcntl(worker_fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        Ok(Self { child, ipc: parent })
    }

    pub(super) fn alive(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    fn send_startup_grant(&mut self, message: &Value, deadline: Instant) -> Result<()> {
        let mut frame = serde_json::to_vec(message)?;
        if frame.len() >= 256 * 1024 { return Err(fail("Hosted production startup grant exceeds its byte bound")); }
        frame.push(b'\n');
        let mut remaining = frame.as_slice();
        while !remaining.is_empty() {
            http::check_interruption(false)?;
            if Instant::now() >= deadline { return Err(fail("Hosted production startup deadline elapsed while sending admission")); }
            match self.ipc.write(remaining) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(count) => remaining = &remaining[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(20)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn startup_message(&mut self, protocol: &str, deadline: Instant) -> Result<Value> {
        let limit = if protocol == BOOT { 65_536 } else { 8192 };
        let mut pending = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            http::check_interruption(false)?;
            if !self.alive()? { return Err(fail("Hosted production child exited before reporting its bound endpoint.")); }
            if Instant::now() >= deadline {
                return Err(fail("Hosted production child did not report its bound endpoint before the startup deadline."));
            }
            match self.ipc.read(&mut buffer) {
                Ok(0) => return Err(fail("Hosted production child closed its endpoint channel.")),
                Ok(count) => {
                    pending.extend_from_slice(&buffer[..count]);
                    if pending.len() > limit { return Err(fail("Hosted production startup message exceeds its byte bound.")); }
                    if let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                        let value: Value = serde_json::from_slice(&pending[..end])?;
                        crate::compat_value::external(&value)?;
                        if end + 1 != pending.len() || value["protocol"] != protocol {
                            return Err(fail("Hosted production child crossed its startup protocol"));
                        }
                        return Ok(value);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(20)),
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(super) fn stop(&mut self, timeout: Duration) {
        if self.alive().is_ok_and(|alive| !alive) { return; }
        let message = format!("{}\n", json!({"protocol": SHUTDOWN}));
        if self.ipc.write_all(message.as_bytes()).is_err() {
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM); }
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline && self.alive().unwrap_or(false) {
            thread::sleep(Duration::from_millis(20));
        }
        self.kill();
    }

    fn kill(&mut self) {
        if self.child.try_wait().is_ok_and(|status| status.is_none()) {
            unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL); }
            let _ = self.child.wait();
        }
    }
}

impl Drop for Generation {
    fn drop(&mut self) { self.kill(); }
}
