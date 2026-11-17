use crate::{Result, appdev_host_process::{Scratch, Supervisor}, command::{self, Evaluator},
    fail, http, image, network_build::{copy_file, copy_tree, local}, network_probe, package, rel};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File, OpenOptions}, io::{self, Read}, net::{Ipv4Addr, Shutdown, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf}, process::{Command, Stdio},
    sync::{Arc, RwLock, atomic::{AtomicBool, AtomicUsize, Ordering}},
    thread::{self, JoinHandle}, time::Duration};

const BOARD: &str = "applications/life-board-prototype";
const GATE: &str = "encounter-platform/applications/front-gate";

pub(crate) fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| fail("Expected network text"))
}

pub(crate) fn list(value: &Value) -> Result<&[Value]> {
    value.as_array().map(Vec::as_slice).ok_or_else(|| fail("Expected network list"))
}

pub(crate) fn port(value: &Value) -> Result<u16> {
    value.as_u64().and_then(|value| u16::try_from(value).ok()).filter(|value| *value >= 1024)
        .ok_or_else(|| fail("Expected an unprivileged network port"))
}

pub(crate) fn evaluate(app: &Evaluator, operation: &str, input: &Value) -> Result<Value> {
    let response = app.run("cli.main", json!([operation, input.to_string()]))?;
    Ok(serde_json::from_str(text(&response)?)?)
}

fn listener_identities(app: &Evaluator, routes: &[Value]) -> Result<BTreeMap<u16, Value>> {
    let ports = routes.iter().map(|route| port(&route["port"])).collect::<Result<BTreeSet<_>>>()?;
    let evidence = network_probe::listener_evidence(&ports)?;
    evidence.into_iter().map(|(port, listeners)| Ok((port, app.run("controller.listener", listeners)?))).collect()
}

fn unused(excluded: &mut BTreeSet<u16>) -> Result<u16> {
    for _ in 0..8 {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port();
        if excluded.insert(port) { return Ok(port); }
    }
    Err(fail("Could not allocate an internal listener port."))
}

fn wait_health(app: &Evaluator, children: &mut Supervisor, port: u16, probe: &Value) -> Result<()> {
    let host = text(&probe["host"])?;
    let path = text(&probe["path"])?;
    let expected = text(&probe["contains"])?;
    for _ in 0..30 {
        if http::stopping() { return Err(fail("Network controller stopping")); }
        children.check()?;
        if let Ok((status, body)) = network_probe::health(port, host, path)
            && app.run("controller.probeReady", json!({"status":status,"body":String::from_utf8_lossy(&body),"expected":expected}))? == true {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(150));
    }
    Err(fail(format!("Health check failed for {host}{path}.")))
}

fn stage_executable(app: &Evaluator, input: &Path, output: &Path, kind: &str, pin: Option<&str>, running: &str) -> Result<()> {
    let canonical = input.canonicalize()?;
    let mut source = package::open_artifact(&File::open("/")?, canonical.strip_prefix("/")?)?;
    let metadata = source.metadata()?;
    let mut target = OpenOptions::new().create_new(true).write(true).mode(0o700).open(output)?;
    const LIMIT: u64 = 64_000_000;
    if metadata.mode() & 0o111 == 0 || metadata.len() > LIMIT
        || io::copy(&mut source.by_ref().take(LIMIT+1), &mut target)? > LIMIT {
        return Err(fail("Network launch executable is missing or exceeds its size limit"));
    }
    target.sync_all()?;
    drop(target);
    package::require_native_runtime(output)?;
    let managed = canonical == Path::new("/usr/sbin/nginx") && metadata.uid() == 0 && metadata.mode() & 0o022 == 0;
    let actual = rel::hash(fs::read(output)?);
    if app.run("controller.executable", json!({"kind":kind,"actual":actual,"running":running,
        "managed":managed,"expected":pin}))? != true {
        return Err(fail(format!("Network {kind} executable requires its matching release pin")));
    }
    Ok(())
}

fn command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command.env_clear().env("LC_ALL", "C").stdin(Stdio::null());
    command
}

pub(crate) struct Settings {
    pub root: PathBuf, pub projects: PathBuf, pub runtime: PathBuf, pub gate_runtime: PathBuf,
    pub nginx: PathBuf, pub work: PathBuf, pub control: u16,
    pub runtime_pin: Option<String>, pub gate_pin: Option<String>, pub nginx_pin: Option<String>,
}

impl Settings {
    pub fn routes(&self) -> Result<Value> {
        let projection = Evaluator::load(&self.root, "projection.rel")?;
        let registry = fs::read_to_string(self.projects.join(GATE).join("services.encounter"))?;
        let routes = evaluate(&projection, "routes", &json!(registry))?;
        let routes = list(&routes)?;
        let controller = Evaluator::load(&self.root, "controller.rel")?;
        let listeners = listener_identities(&controller, routes)?;
        Ok(json!(routes.iter().map(|route| -> Result<Value> {
            let mut route = route.clone();
            route["service"] = listeners.get(&port(&route["port"])?).cloned().unwrap_or(Value::Null);
            Ok(route)
        }).collect::<Result<Vec<_>>>()?))
    }

    pub fn stage(&self, app: &Evaluator, config: &Value, changes: &Value) -> Result<Generation> {
        let projection = Evaluator::load(&self.root, "projection.rel")?;
        let declaration = format!("{BOARD}/application.rel");
        let modules = evaluate(&projection, "modules", &json!(fs::read_to_string(self.projects.join(&declaration))?))?;
        let changed = list(changes)?.iter().map(|row| row["id"].clone()).collect::<Vec<_>>();
        let plan = app.run("controller.stage", json!({"config":config,"modules":modules,"changed":changed,"controlPort":self.control}))?;
        let changed_routes = list(&plan["verify"])?;
        if changed_routes.len() != changed.len() { return Err(fail("Missing changed network route")); }
        let listeners = listener_identities(app, changed_routes)?;
        for route in changed_routes {
            let route_port = port(&route["port"])?;
            if route["service"].as_str().is_none() || listeners.get(&route_port) != Some(&route["service"]) {
                return Err(fail(format!("{} has no verified listener from its registered service on port {route_port}.", text(&route["id"])?)));
            }
        }
        let scratch = Scratch::create(&self.work, "generation-")?;
        let stage = scratch.path();
        let binaries = stage.join("bin");
        fs::create_dir(&binaries)?;
        let runtime = binaries.join("browser-runtime");
        let gate_runtime = binaries.join("gate-runtime");
        let nginx = binaries.join("nginx");
        let running = image::runtime_pin()?;
        stage_executable(app, &self.runtime, &runtime, "runtime", self.runtime_pin.as_deref(), &running)?;
        stage_executable(app, &self.gate_runtime, &gate_runtime, "gate runtime", self.gate_pin.as_deref(), &running)?;
        stage_executable(app, &self.nginx, &nginx, "nginx", self.nginx_pin.as_deref(), &running)?;
        copy_tree(&self.root.join("front-gate-ingress"), &binaries.join("front-gate-ingress"))?;
        let source = stage.join("projects");
        for path in list(&plan["copies"])? {
            let path = local(text(path)?)?;
            let input = self.projects.join(path);
            let output = source.join(path);
            if input.symlink_metadata()?.is_dir() {
                fs::create_dir_all(output.parent().ok_or_else(|| fail("Missing stage parent"))?)?;
                copy_tree(&input, &output)?;
            } else {
                copy_file(&input, &output)?;
            }
        }
        package::check(&source)?;
        let paths = [source.join(GATE).join("services.encounter"), source.join(BOARD).join("mounted-apps.encounter"),
            source.join(BOARD).join("transport.encounter")];
        let rendered = evaluate(&projection, "sources", &json!({"config":config,
            "registry":fs::read_to_string(&paths[0])?, "mounts":fs::read_to_string(&paths[1])?, "transport":fs::read_to_string(&paths[2])?}))?;
        for (path, key) in paths.iter().zip(["registry","mounts","transport"]) { fs::write(path, text(&rendered[key])?)?; }
        let mut excluded = list(&plan["exclude"])?.iter().map(port).collect::<Result<BTreeSet<_>>>()?;
        let gate = unused(&mut excluded)?;
        let browser = unused(&mut excluded)?;
        let ingress = unused(&mut excluded)?;
        let probes = app.run("controller.probes", json!({"browser":browser,"public":config["lifeBoard"]}))?;
        let mut children = Supervisor::children();
        children.start("Front Gate", command(&gate_runtime).arg("front-gate-host")
            .arg(source.join(GATE)).args(["directory.rel", &gate.to_string()]).stdin(Stdio::null()))?;
        wait_health(app, &mut children, gate, &probes["gate"])?;
        let assets = stage.join("assets");
        fs::create_dir(&assets)?;
        let applications = source.join("applications");
        let render = |operation: Option<&str>| -> Result<String> {
            let args: Vec<String> = operation.into_iter().map(str::to_owned).collect();
            Ok(format!("{}\n", command::render(&applications, "life-board-prototype/shell.rel", &args)?))
        };
        let surface = evaluate(&projection, "surface", &json!({"shell":render(None)?,"ingress":render(Some("transport"))?,
            "ingressPort":ingress,"browserPort":browser,"lifeBoard":config["lifeBoard"]}))?;
        fs::write(assets.join("index.html"), text(&surface["shell"])?)?;
        fs::write(assets.join("life-board.css"), render(Some("stylesheet"))?)?;
        fs::write(stage.join("nginx.conf"), text(&surface["ingress"])?)?;
        children.start("Life Board browser host", command(&runtime).arg("browser-host").arg(&source)
            .arg(declaration).arg(assets).arg(browser.to_string()).stdin(Stdio::null()))?;
        wait_health(app, &mut children, browser, &probes["browser"])?;
        let prefix = format!("{}/", stage.display());
        children.capture("Life Board ingress configuration", command(&nginx)
            .args(["-p", &prefix, "-c", "nginx.conf", "-t"]).stdin(Stdio::null()), Duration::from_secs(5), 4096)?;
        children.start("Life Board ingress", command(&nginx).args(["-p", &prefix, "-c", "nginx.conf"]))?;
        wait_health(app, &mut children, ingress, &probes["ingress"])?;
        Ok(Generation { children, _scratch:scratch, info:json!({"config":config,"gate":gate,"ingress":ingress}) })
    }
}

pub(crate) struct Generation {
    pub children: Supervisor,
    _scratch: Scratch,
    pub info: Value,
}

type Bindings = Arc<RwLock<BTreeMap<u16,u16>>>;

fn relay(client: TcpStream, port: u16) -> io::Result<()> {
    let upstream = TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), Duration::from_secs(2))?;
    let mut from_client = client.try_clone()?;
    let mut to_client = client;
    let mut from_upstream = upstream.try_clone()?;
    let mut to_upstream = upstream;
    thread::scope(|scope| {
        scope.spawn(|| {
            if io::copy(&mut from_client, &mut to_upstream).is_err() { let _ = from_client.shutdown(Shutdown::Both); }
            let _ = to_upstream.shutdown(Shutdown::Write);
        });
        let _ = io::copy(&mut from_upstream, &mut to_client);
        let _ = to_client.shutdown(Shutdown::Both);
        let _ = from_upstream.shutdown(Shutdown::Both);
    });
    Ok(())
}

struct Forwarder {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Forwarder {
    fn bind(port: u16, bindings: Bindings, flows: Arc<AtomicUsize>) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let running = Arc::clone(&stop);
        let thread = thread::Builder::new().name(format!("network-listener-{port}")).spawn(move || {
            while !running.load(Ordering::Acquire) {
                let (client, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10)); continue;
                    }
                    Err(_) => return,
                };
                let target = bindings.read().expect("network bindings").get(&port).copied();
                let Some(target) = target else { continue; };
                if flows.fetch_add(1, Ordering::AcqRel) >= 256 {
                    flows.fetch_sub(1, Ordering::Release);
                    continue;
                }
                let count = Arc::clone(&flows);
                if thread::Builder::new().name("network-forward".into()).spawn(move || {
                    let _ = relay(client, target);
                    count.fetch_sub(1, Ordering::Release);
                }).is_err() { flows.fetch_sub(1, Ordering::Release); }
            }
        })?;
        Ok(Self { stop, thread:Some(thread) })
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

#[derive(Default)]
pub(crate) struct Activation {
    listeners: BTreeMap<u16, Forwarder>,
    bindings: Bindings,
    flows: Arc<AtomicUsize>,
    pub active: Option<Generation>,
    previous: Option<Generation>,
}

pub(crate) struct Reserved {
    listeners: BTreeMap<u16, Forwarder>,
    bindings: BTreeMap<u16,u16>,
    retain: bool,
}

impl Activation {
    pub fn reserve(&self, app: &Evaluator, generation: &Generation) -> Result<Reserved> {
        let plan = app.run("controller.switch", json!({"next":generation.info,
            "active":self.active.as_ref().map(|g| &g.info),"previous":self.previous.as_ref().map(|g| &g.info)}))?;
        let mut listeners = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        for row in list(&plan["bindings"])? {
            let public = port(&row["port"])?;
            if !self.listeners.contains_key(&public) {
                listeners.insert(public, Forwarder::bind(public, Arc::clone(&self.bindings), Arc::clone(&self.flows))?);
            }
            bindings.insert(public, port(&row["target"])?);
        }
        Ok(Reserved { listeners, bindings, retain:plan["retain"] == true })
    }

    pub fn commit(&mut self, generation: Generation, mut reserved: Reserved) {
        self.listeners.append(&mut reserved.listeners);
        let ports = reserved.bindings.keys().copied().collect::<BTreeSet<_>>();
        let prior = self.active.replace(generation);
        *self.bindings.write().expect("network bindings") = reserved.bindings;
        if reserved.retain { self.previous = prior; }
        self.listeners.retain(|port, _| ports.contains(port));
    }
}
