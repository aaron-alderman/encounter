use crate::{Result, appdev_host_process::{Supervisor, interruption}, fail,
    hosted_generation_process::{Generation, text}, hosted_generation_proxy::{self as proxy, Forwarding, Route},
    hosted_launch_config, hosted_release_identity::{self as identity, decide},
    package::observe_beneath, process::Programme};
use serde_json::{Value, json};
use std::{env, fs::{self, File}, io, net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    os::unix::fs::MetadataExt, path::{Path, PathBuf},
    sync::{Arc, RwLock, atomic::{AtomicBool, AtomicUsize, Ordering}},
    thread::{self, JoinHandle}, time::{Duration, Instant}};

struct Config {
    root: PathBuf,
    state: PathBuf,
    pointer: PathBuf,
    temple_hash: String,
    closure_store: PathBuf,
    composition_pin: String,
    paths: Vec<String>,
    host: String,
    port: u16,
    request: Duration,
    startup: Duration,
    drain: Duration,
    poll: Duration,
}

impl Config {
    fn load() -> Result<Self> {
        let cwd = env::current_dir()?;
        let setting = |name: &str| env::var(name).unwrap_or_default();
        let environment = hosted_launch_config::host_environment();
        let host = hosted_launch_config::evaluate("config", json!({"cwd": cwd, "environment": environment}))?;
        let release = identity::supervisor_settings(json!({
            "cwd":cwd, "profile":host["deploymentProfile"], "source":setting("SOURCERY_HOSTED_SOURCE_ROOT"),
            "paths":setting("SOURCERY_HOSTED_RELOAD_PATHS"), "pointer":setting("SOURCERY_HOSTED_RELEASE_POINTER"),
            "temple":setting("SOURCERY_HOSTED_TEMPLE_ROOT"), "tree":setting("SOURCERY_HOSTED_TEMPLE_TREE_SHA256"),
            "poll":setting("SOURCERY_HOSTED_RELOAD_POLL_MS"), "startup":setting("SOURCERY_HOSTED_GENERATION_STARTUP_TIMEOUT_MS"),
            "drain":setting("SOURCERY_HOSTED_GENERATION_DRAIN_TIMEOUT_MS")
        }))?;
        let dependencies = identity::supervisor_dependency_gate(json!({
            "store":setting("SOURCERY_HOSTED_DEPENDENCY_CLOSURE_ROOT"),
            "pin":setting("SOURCERY_HOSTED_DEPENDENCY_COMPOSITION_SHA256"),
        }))?;
        Ok(Self {
            root: text(&release, "sourceRoot")?.into(), state: text(&host, "stateRoot")?.into(),
            pointer: text(&release, "releasePointer")?.into(),
            temple_hash: text(&release, "expectedTempleTreeHash")?.into(),
            closure_store: text(&dependencies, "store")?.into(), composition_pin: text(&dependencies, "pin")?.into(),
            paths: serde_json::from_value(release["sourcePaths"].clone())?,
            host: text(&host, "bindHost")?.into(), port: u16::try_from(number(&host, "port")?)?,
            request: Duration::from_millis(number(&host, "requestTimeoutMs")?),
            startup: Duration::from_millis(number(&release, "startupTimeoutMs")?),
            drain: Duration::from_millis(number(&release, "drainTimeoutMs")?),
            poll: Duration::from_millis(number(&release, "pollIntervalMs")?),
        })
    }

    fn observe_release(&self) -> Result<Value> { identity::admission_identity(&self.root, &self.pointer) }

    fn attest(&self) -> Result<Value> {
        let release = self.root.canonicalize()?;
        require_matched_runtime(&release)?;
        crate::hosted_composition::audit_release(&release, &self.closure_store, Some(&self.composition_pin), Some(&self.temple_hash))
    }

    fn start(&self, policy: &Programme, release: &Value) -> Result<Worker> {
        let dependencies = self.attest()?;
        let expected = identity::observed_generation(policy, &self.root, &self.state, &self.paths, release)?;
        let (mut process, address) = Generation::start(policy, &self.root, &self.host, &expected,
            &dependencies["platform"], self.startup, self.drain, || {
                self.attest()?;
                let observed_release = self.observe_release()?;
                let observed = identity::observed_generation(policy, &self.root, &self.state, &self.paths, &observed_release)?;
                decide(policy, "hostedRelease.childIdentity", json!({"expected":expected,"observed":observed}))?;
                Ok(())
            })?;
        let confirmed = (|| {
            self.attest()?;
            let confirmed = identity::observed_generation(policy, &self.root, &self.state, &self.paths, release)?;
            decide(policy, "hostedRelease.childIdentity", json!({"expected":expected,"observed":confirmed}))
        })();
        if let Err(error) = confirmed {
            process.stop(self.drain);
            return Err(error);
        }
        Ok(Worker { process, expected, route: Route::new(address) })
    }

    fn address(&self) -> Result<SocketAddr> {
        // Match the first loopback result from the operating system for localhost.
        let address = (self.host.as_str(), self.port).to_socket_addrs()?.find(|address| address.ip().is_loopback())
            .ok_or_else(|| fail("Hosted supervisor requires a loopback listener"))?;
        Ok(address)
    }
}

fn number(input: &Value, field: &str) -> Result<u64> {
    input[field].as_u64().ok_or_else(|| fail(format!("Missing admitted hosted field {field}")))
}

pub(super) fn require_matched_runtime(root: &Path) -> Result<()> {
    let named = observe_beneath(&File::open(root)?, Path::new("encounter"))?.metadata()?;
    let executing = fs::metadata("/proc/self/exe")?;
    if !named.is_file() || named.mode() & 0o022 != 0
        || (named.dev(), named.ino()) != (executing.dev(), executing.ino()) {
        return Err(fail("Hosted supervisor must use the native executable in its exact release"));
    }
    Ok(())
}

struct Worker { process: Generation, expected: Value, route: Arc<Route> }

impl Worker {
    fn drain(mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.route.idle() && self.process.alive().unwrap_or(false) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        self.route.close();
        self.process.stop(timeout);
    }
}

fn cutover(config: &Config, policy: &Programme, candidate: &mut Worker) -> Result<Value> {
    let observed = match config.observe_release() {
        Ok(observed) => observed["pointerHash"].clone(),
        Err(error) => { eprintln!("{error}"); Value::Null }
    };
    require_matched_runtime(&config.root)?;
    decide(policy, "hostedRelease.cutover", json!({"generation":candidate.expected,"pointerHash":observed,
        "candidateAlive":candidate.process.alive()?,"closed":interruption().is_some()}))
}

type Selected = Arc<RwLock<Option<Arc<Route>>>>;

struct RequestSlot(Arc<AtomicUsize>);

impl Drop for RequestSlot {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Release); }
}

fn serve(listener: TcpListener, selected: Selected, forwarding: Arc<Forwarding>, timeout: Duration,
    stopping: Arc<AtomicBool>) -> io::Result<()> {
    let slots = Arc::new(AtomicUsize::new(0));
    while !stopping.load(Ordering::Acquire) && interruption().is_none() {
        match listener.accept() {
            Ok((mut stream, peer)) if peer.ip().is_loopback() => {
                if slots.fetch_add(1, Ordering::Acquire) >= 256 {
                    slots.fetch_sub(1, Ordering::Release);
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
                    let _ = proxy::unavailable(&mut stream);
                    continue;
                }
                let slot = RequestSlot(Arc::clone(&slots));
                let selected = Arc::clone(&selected);
                let forwarding = Arc::clone(&forwarding);
                // A failed thread start drops the socket and releases the slot.
                let _ = thread::Builder::new().name("hosted-request".into()).spawn(move || {
                    let _slot = slot;
                    let _ = proxy::serve(stream, |stream: &TcpStream| {
                        let active = selected.read().unwrap();
                        active.as_ref().map(|route| route.lease(stream)).transpose().map_err(Into::into)
                    }, &forwarding, timeout);
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(20)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn replace(config: &Config, policy: &Programme, active: &mut Worker, rejected: &mut Value) -> Result<Option<Worker>> {
    let release = config.observe_release()?;
    let decision = decide(policy, "hostedRelease.reload", json!({"active":active.process.alive()?,
        "candidate":release["pointerHash"],"accepted":active.expected["releasePointerHash"],"rejected":rejected}))?;
    if decision == "identical-release" {
        if !rejected.is_null() {
            println!("Hosted release pointer returned to the serving release; cleared candidate quarantine");
        }
        *rejected = Value::Null;
        return Ok(None);
    }
    if decision == "candidate-quarantined" { return Ok(None); }
    if decision != "replace" { return Err(fail("Unexpected hosted reload decision.")); }
    let result = (|| {
        let mut candidate = config.start(policy, &release)?;
        let transition = cutover(config, policy, &mut candidate);
        if transition.as_ref().is_ok_and(|value| value == "activate") { return Ok(Some(candidate)); }
        candidate.drain(config.drain);
        if transition? == "candidate-exited" { return Err(fail("Hosted successor exited before cutover.")); }
        Ok(None)
    })();
    if result.is_err() { *rejected = release["pointerHash"].clone(); }
    result
}

pub(crate) fn run() -> Result<()> {
    let _signals = Supervisor::new();
    let config = Config::load()?;
    require_matched_runtime(&config.root)?;
    let policy = identity::policy()?;
    let forwarding = Arc::new(Forwarding::new(&decide(&policy, "hostedRelease.proxyHeaders", Value::Null)?)?);
    let release = config.observe_release()?;
    let mut active = config.start(&policy, &release)?;
    if cutover(&config, &policy, &mut active)? != "activate" {
        active.drain(config.drain);
        return Err(fail("Hosted initial generation lost its admitted release before listening."));
    }
    let listener = TcpListener::bind(config.address()?)?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let selected: Selected = Arc::new(RwLock::new(Some(Arc::clone(&active.route))));
    let stopping = Arc::new(AtomicBool::new(false));
    let acceptor = {
        let selected = Arc::clone(&selected);
        let stopping = Arc::clone(&stopping);
        let timeout = config.request;
        thread::Builder::new().name("hosted-listener".into()).spawn(move || serve(listener, selected, forwarding, timeout, stopping))?
    };
    println!("Hosted production supervisor listening on {address}");
    let mut drains: Vec<JoinHandle<()>> = Vec::new();
    let mut rejected = Value::Null;
    let mut next = Instant::now() + config.poll;
    while interruption().is_none() && !acceptor.is_finished() {
        let remaining = next.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            thread::sleep(remaining.min(Duration::from_millis(50)));
            continue;
        }
        match replace(&config, &policy, &mut active, &mut rejected) {
            Ok(Some(candidate)) if interruption().is_none() => {
                *selected.write().unwrap() = Some(Arc::clone(&candidate.route));
                let predecessor = std::mem::replace(&mut active, candidate);
                rejected = Value::Null;
                let timeout = config.drain;
                match thread::Builder::new().name("hosted-drain".into()).spawn(move || predecessor.drain(timeout)) {
                    Ok(drain) => drains.push(drain),
                    Err(error) => eprintln!("Could not start hosted predecessor drain: {error}"),
                }
            }
            Ok(Some(candidate)) => candidate.drain(config.drain),
            Ok(None) => {}
            Err(error) if interruption().is_none() => eprintln!("{error}"),
            Err(_) => {}
        }
        drains.retain(|drain| !drain.is_finished());
        next = Instant::now() + config.poll;
    }
    stopping.store(true, Ordering::Release);
    *selected.write().unwrap() = None;
    active.drain(config.drain);
    for drain in drains { let _ = drain.join(); }
    acceptor.join().map_err(|_| fail("Hosted listener stopped unexpectedly"))??;
    Ok(())
}
