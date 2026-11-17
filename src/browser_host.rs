use crate::{Result, appdev_release, application::{Application, CheckProfile}, browser_form::FormSession, browser_operator::{self, Lease, WindowOperators}, compat_value, device_edge, fail, http, operator::Operators, peer_host::{PeerHost, RETRY_ENTRY}, peer_transport, process::{Env, Meter, Programme}, store::Store, surface_image::SurfaceImage, publication, rel, websocket};
use serde_json::{Value, json};
use base64ct::{Base64, Encoding};
use std::{cell::{Cell, RefCell}, collections::{BTreeMap, BTreeSet}, fs, net::{Shutdown, TcpStream},
    os::unix::{ffi::OsStrExt, fs::{DirBuilderExt, PermissionsExt}}, path::{Path, PathBuf},
    rc::Rc, sync::{Arc, OnceLock, atomic::{AtomicUsize, Ordering}, mpsc}, thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

const LIMIT: usize = 4_000_000;
const BUDGET: usize = 20_000_000;
const SESSION_LIMIT: usize = 16;
const TRACE_EFFECT_LIMIT: usize = 48;
use appdev_release::ASTER_STREAM;
const FRONT_GATE_STATUS: &str = "browser.frontGateStatus";
const COUNTDOWN: &str = "browser.countdown";
const PREFLIGHT: &str = "browser.preflight";

pub fn supports_port(name: &str) -> bool {
    matches!(name, ASTER_STREAM | COUNTDOWN | "form.sessionOpen" | "form.sessionBegin" | "form.sessionSave" | "state.get" | "state.set" | "kernel.prepare" | "kernel.execute" | "runtime.telemetry" | "runtime.environment" | "runtime.clock" | "runtime.device" | "runtime.nonce"
        | "storage.read" | "storage.write" | "storage.readRecord" | "storage.compareAndSet" | "storage.remove" | "dom.exists"
        | "browser.on" | "browser.onMany" | "browser.batch" | "browser.activeGroup" | "browser.appDescriptions" | "browser.activate" | "browser.property" | "browser.formFields" | "browser.write" | "browser.content"
        | "browser.delay" | "browser.focus" | "browser.copyText" | "browser.fileText" | "browser.formatFileSizes" | "download.text"
        | "browser.request" | "browser.assuranceRefresh" | FRONT_GATE_STATUS | "browser.requestOnExit" | "browser.location" | "browser.performance" | "browser.startup" | "browser.navigate"
        | "browser.dialog" | "browser.popover" | "browser.attribute" | "browser.target" | "browser.guard")
}

struct Listener {
    query: String,
    input: Value,
    trace: bool,
}

struct Child {
    programme: Rc<Programme>,
    entry: String,
    source_hash: String,
    model: Option<Value>,
}

#[derive(Clone)]
enum App {
    Native(Arc<Application>),
    Surface(Arc<SurfaceImage>),
}

struct DurableHost {
    directory: PathBuf,
    operators: Option<Operators>,
    window_operators: Option<WindowOperators>,
    edge: Option<PathBuf>,
    peer: Option<Arc<PeerHost>>,
    mount: String,
}

struct DurableSession {
    directory: PathBuf,
    form: bool,
    actor: Value,
    lease: Option<Arc<Lease>>,
    peer: Option<Arc<PeerHost>>,
    mount: String,
}

fn browser_profile(durable: bool, peer: bool) -> CheckProfile {
    if peer { CheckProfile::TempleBrowser }
    else if durable { CheckProfile::DurableBrowser }
    else { CheckProfile::Browser }
}

impl App {
    fn admit(&self, profile: CheckProfile) -> Result<Programme> {
        let mut meter = Meter::new(BUDGET);
        match self {
            Self::Native(app) => app.admit_native_browser(&mut meter, profile),
            Self::Surface(image) => image.admit(&mut meter),
        }
    }

    fn boot(&self) -> &str {
        match self { Self::Native(_) => "browser.boot", Self::Surface(image) => &image.boot }
    }

    fn agent(&self) -> Option<&str> {
        match self { Self::Native(_) => None, Self::Surface(image) => image.agent.as_deref() }
    }
}

pub struct Session {
    application: App,
    form: Option<FormSession>,
    root: Env,
    socket: RefCell<TcpStream>,
    state: RefCell<BTreeMap<String, Value>>,
    listeners: RefCell<Vec<Listener>>,
    children: RefCell<BTreeMap<String, Child>>,
    telemetry: Arc<HostTelemetry>,
    timing: RefCell<Option<DispatchTiming>>,
    aster_stream: bool,
    front_gate_status: bool,
    booting: Cell<bool>,
    preflight: RefCell<Option<BootEffects>>,
}

#[derive(Default)]
struct BootEffects {
    observations: Vec<(String, Value, Value)>,
    stable_ids: BTreeSet<String>,
    defer_content: bool,
    pending: Vec<Value>,
    failure: Option<String>,
}

impl BootEffects {
    fn observed(&self, name: &str, args: &Value) -> Option<Value> {
        if name == "browser.batch" {
            let steps = args["steps"].as_array().filter(|steps| !steps.is_empty() && steps.len() <= 64)?;
            let mut result = serde_json::Map::new();
            for step in steps {
                let port = step["port"].as_str()?;
                let save = step["save"].as_str()?;
                if !matches!(port, "dom.exists" | "browser.property") || !step["unless"].is_null()
                    || save.len() > 40 || !save.as_bytes().first()?.is_ascii_lowercase()
                    || !save.bytes().all(|ch| ch.is_ascii_alphanumeric()) || result.contains_key(save) {
                    return None;
                }
                result.insert(save.to_owned(), self.observed(port, &step["args"])?);
            }
            return Some(Value::Object(result));
        }
        self.observations.iter().find(|(port, input, _)| port == name && input == args)
            .map(|(_, _, value)| value.clone())
    }
}

struct DispatchTiming {
    started: Instant,
    exchange: Duration,
    effects: Vec<Value>,
    omitted: usize,
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_micros() as f64 / 1000.0
}

struct HostTelemetry {
    edge: Option<PathBuf>,
    filesystem: PathBuf,
    started: Instant,
    sessions: AtomicUsize,
    completed: AtomicUsize,
    faults: AtomicUsize,
}

impl HostTelemetry {
    fn new(edge: Option<PathBuf>, filesystem: PathBuf) -> Self {
        Self { edge, filesystem, started: Instant::now(), sessions: AtomicUsize::new(0), completed: AtomicUsize::new(0), faults: AtomicUsize::new(0) }
    }

    fn sample(&self) -> Result<Value> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // The kernel fills the caller's rusage on success. No process selector is exposed.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let usage = unsafe { usage.assume_init() };
        let micros = |time: libc::timeval| (time.tv_sec as u64) * 1_000_000 + time.tv_usec as u64;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let peak_bytes = usage.ru_maxrss as u64;
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let peak_bytes = (usage.ru_maxrss as u64) * 1024;
        Ok(json!({
            "elapsedMs": self.started.elapsed().as_millis() as u64,
            "cpuMicros": micros(usage.ru_utime) + micros(usage.ru_stime),
            "peakResidentBytes": peak_bytes,
            "activeSessions": self.sessions.load(Ordering::Relaxed),
            "sessionLimit": SESSION_LIMIT,
            "completedDispatches": self.completed.load(Ordering::Relaxed),
            "faultedDispatches": self.faults.load(Ordering::Relaxed),
        }))
    }
}

pub(crate) fn environment_memory() -> Option<Value> {
    let info = fs::read_to_string("/proc/meminfo").ok()?;
    let bytes = |field: &str| {
        info.lines().find_map(|line| line.strip_prefix(field))?
            .split_whitespace().next()?.parse::<u64>().ok()?.checked_mul(1024)
    };
    Some(json!({"totalBytes": bytes("MemTotal:")?, "availableBytes": bytes("MemAvailable:")?}))
}

fn filesystem_capacity(path: &Path) -> Option<Value> {
    let (total, available, _) = filesystem_usage(path)?;
    Some(json!({"totalBytes":total, "availableBytes":available}))
}

pub(crate) fn filesystem_usage(path: &Path) -> Option<(u64, u64, u64)> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // The kernel initializes stat on success; the path is configured by the host.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    let bytes = |blocks| (blocks as u64).checked_mul(stat.f_frsize as u64);
    let used = u128::from(stat.f_blocks.checked_sub(stat.f_bfree)?);
    let usable = used + u128::from(stat.f_bavail);
    if usable == 0 {
        return None;
    }
    let percent = (used * 100).div_ceil(usable) as u64;
    Some((bytes(stat.f_blocks)?, bytes(stat.f_bavail)?, percent))
}

fn string<'a>(args: &'a Value, field: &str) -> Result<&'a str> {
    args[field].as_str().ok_or_else(|| fail(format!("expected browser port text field {field}")))
}

fn utc_millis() -> Result<u64> {
    Ok(u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?)
}

fn send(socket: &mut TcpStream, message: &Value) -> Result<()> {
    let mut message = message.clone();
    compat_value::browser_value(&mut message);
    let bytes = serde_json::to_vec(&message)?;
    if bytes.len() > LIMIT { return Err(fail("browser message size limit")); }
    websocket::frame(socket, 1, &bytes)
}

fn decode_message(message: Option<String>) -> Result<Option<Value>> {
    message.map(|text| {
        let value = serde_json::from_str(&text)?;
        compat_value::external(&value)?;
        Ok(value)
    }).transpose()
}

fn ticket() -> Result<String> {
    let mut random = [0u8; 24];
    getrandom::getrandom(&mut random).map_err(|_| fail("child admission entropy unavailable"))?;
    Ok(hex::encode(random))
}

impl Session {
    pub fn is_surface(&self) -> bool { matches!(self.application, App::Surface(_)) }

    pub fn root_bindings(&self) -> Env { self.root.clone() }

    pub fn require_store_write(&self) -> Result<()> {
        if self.root.get("actor").is_some_and(|actor| actor["role"] == "observer") {
            return Err(fail("Observer sessions are read-only."));
        }
        Ok(())
    }

    pub fn finish_preparation(self: &Rc<Self>, entry: &str, result: &mut Value, meter: &mut Meter) -> Result<()> {
        let App::Surface(image) = &self.application else { return Ok(()); };
        if image.preparation != entry { return Ok(()); }
        let model = result.get_mut("model").filter(|model| model.is_object())
            .ok_or_else(|| fail("EC-CHILD: Preparation returned no model."))?;
        compat_value::external(model)?;
        let hash = rel::hash(serde_json::to_vec(model)?);
        let mut children = self.children.borrow_mut();
        // Store one checked programme per distinct model. Only this successful
        // preparation path may attach its seal to a value in the evaluator.
        if let Some((key, _)) = children.iter().find(|(_, child)| child.source_hash == hash && child.model.as_ref() == Some(model)) {
            model[compat_value::ADMISSION] = json!(key);
            return Ok(());
        }
        if children.len() >= 64 { return Err(fail("child admission capacity")); }
        let grants = BTreeSet::from(["value.describe", "record.entries", "record.put", "record.get",
            "text.matches", "text.split", "kernel.invoke", "kernel.execute"]);
        let mut programme = Programme::from_surface(model, &grants, meter)?;
        programme.bind_child_browser(Rc::downgrade(self));
        let admission = ticket()?;
        children.insert(admission.clone(), Child {
            programme: Rc::new(programme), entry: String::new(), source_hash: hash, model: Some(model.clone()),
        });
        model[compat_value::ADMISSION] = json!(admission);
        Ok(())
    }

    fn execute_surface_child(&self, args: &Value, env: &Env, meter: &mut Meter, depth: usize) -> Result<Value> {
        let refusal = || fail("EC-CHILD: Child model has no preparation admission.");
        let mut model = args["model"].clone();
        let admission = model.as_object_mut().and_then(|fields| fields.shift_remove(compat_value::ADMISSION))
            .ok_or_else(refusal)?;
        if env.get("model").and_then(|owner| owner.get(compat_value::ADMISSION))
            .is_some_and(|owner| owner != &admission) { return Err(refusal()); }
        let hash = rel::hash(serde_json::to_vec(&model)?);
        let programme = {
            let children = self.children.borrow();
            let child = admission.as_str().and_then(|key| children.get(key)).ok_or_else(refusal)?;
            if child.source_hash != hash || child.model.as_ref() != Some(&model) { return Err(refusal()); }
            Rc::clone(&child.programme)
        };
        let entry = string(args, "entry")?;
        let App::Surface(image) = &self.application else { return Err(refusal()); };
        let mut locals: Env = image.child_bindings.iter().filter_map(|key| env.get(key).map(|value| (key.clone(), Rc::clone(value)))).collect();
        locals.insert("model".to_owned(), Rc::new(args["model"].clone()));
        programme.run_child(entry, args["input"].clone(), locals, meter, depth)
    }

    fn effect(&self, process: &str, name: &str, args: &Value, meter: &mut Meter) -> Result<Value> {
        let pending = {
            let mut preflight = self.preflight.borrow_mut();
            let Some(boot) = preflight.as_mut() else { return self.exchange(process, name, args, meter); };
            if let Some(error) = &boot.failure { return Err(fail(error.clone())); }
            if let Some(result) = boot.observed(name, args) {
                if name != "browser.startup" || boot.pending.len() < 64 {
                    if name == "browser.startup" {
                        boot.pending.push(json!({"effect": name, "args": args, "expected": result}));
                        boot.observations.retain(|(port, _, _)| port != "browser.startup");
                    }
                    meter.charge(serde_json::to_vec(&result)?.len())?;
                    return Ok(result);
                }
            }
            match name {
                "browser.dialog" => boot.observations.retain(
                    |(port, _, _)| port != "dom.exists" && port != "browser.property"),
                "browser.content" => boot.observations.retain(|(port, input, _)|
                    (port != "dom.exists" && port != "browser.property") ||
                    (port == "dom.exists" && input["selector"].as_str()
                        .is_some_and(|selector| boot.stable_ids.contains(selector)))),
                "browser.navigate" => boot.observations.retain(|(port, _, _)| !matches!(port.as_str(),
                    "dom.exists" | "browser.property" | "browser.startup" | "browser.location")),
                "browser.startup" => boot.observations.retain(|(port, _, _)| !matches!(port.as_str(),
                    "browser.startup" | "browser.location")),
                "browser.write" | "browser.attribute" => boot.observations.retain(
                    |(port, _, _)| port != "browser.property"),
                "storage.write" | "storage.remove" => boot.observations.retain(
                    |(port, input, _)| port != "storage.read" || input["key"] != args["key"]),
                "state.set" => boot.observations.retain(
                    |(port, input, _)| port != "state.get" || input["key"] != args["key"]),
                _ => (),
            }
            let deferrable = matches!(name, ASTER_STREAM | COUNTDOWN | "browser.on" | "browser.onMany"
                | "browser.activeGroup" | "browser.appDescriptions" | "browser.copyText" | "browser.guard"
                | "browser.write" | "browser.attribute" | "state.set") ||
                (name == "browser.content" && boot.defer_content);
            if deferrable && boot.pending.len() < 64 {
                boot.pending.push(json!({"effect": name, "args": args}));
                return Ok(json!(true));
            }
            if name == "browser.batch" {
                // A mixed batch can update properties before a later observation.
                boot.observations.retain(|(port, _, _)| port != "browser.property");
            }
            std::mem::take(&mut boot.pending)
        };
        if pending.is_empty() { return self.exchange(process, name, args, meter); }
        let reply = self.exchange(process, "browser.bootEffects",
            &json!({"steps": pending, "next": {"effect": name, "args": args}}), meter)?;
        if let Some(error) = reply["setupError"].as_str() {
            if let Some(boot) = self.preflight.borrow_mut().as_mut() {
                boot.failure = Some(error.to_owned());
            }
            return Err(fail(error));
        }
        reply.get("value").cloned().ok_or_else(|| fail("Missing browser boot effect result"))
    }

    fn finish_boot(&self, meter: &mut Meter) -> Result<()> {
        self.booting.set(false);
        if let Some(boot) = self.preflight.borrow_mut().take() {
            if let Some(error) = boot.failure { return Err(fail(error)); }
            if !boot.pending.is_empty() {
                let reply = self.exchange("browser.boot", "browser.bootEffects", &json!({"steps":boot.pending}), meter)?;
                if reply["value"] != true {
                    return Err(fail(reply["setupError"].as_str().unwrap_or("Browser boot effects were not acknowledged")));
                }
            }
        }
        Ok(())
    }

    fn start_preflight(&self, process: &str, args: &Value, meter: &mut Meter) -> Result<Value> {
        let App::Native(app) = &self.application else { return Err(fail("Expected a native boot preflight")); };
        if !self.booting.get() || self.preflight.borrow().is_some() {
            return Err(fail("Browser preflight is available once during boot"));
        }
        if !args.as_object().is_some_and(|fields| fields.keys()
            .all(|key| matches!(key.as_str(), "preflight" | "probes" | "when" | "stableIds" | "deferContent"))) {
            return Err(fail("Invalid browser preflight fields"));
        }
        let reads = args["preflight"].as_array().filter(|reads| !reads.is_empty() && reads.len() <= 64)
            .ok_or_else(|| fail("Expected 1 to 64 browser preflight reads"))?;
        let grants = app.declared_grants();
        let stable_ids = if let Some(ids) = args.get("stableIds") {
            if !grants.contains("dom.exists") { return Err(fail("Stable IDs require dom.exists")); }
            ids.as_array().filter(|ids| ids.len() <= 32).ok_or_else(|| fail("Invalid stable ID list"))?
                .iter().map(|id| {
                    let selector = id.as_str().filter(|id| id.len() <= 100 && id.strip_prefix('#')
                        .is_some_and(|id| !id.is_empty() && id.bytes().all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')))
                        .ok_or_else(|| fail("Expected a stable ID selector"))?;
                    Ok(selector.to_owned())
                }).collect::<Result<BTreeSet<_>>>()?
        } else { BTreeSet::new() };
        let defer_content = args["deferContent"] == true;
        if defer_content && !grants.contains("browser.content") {
            return Err(fail("Deferred content requires browser.content"));
        }
        for step in reads {
            let port = string(step, "port")?;
            if !matches!(port, "dom.exists" | "browser.property" | "storage.read" | "state.get"
                | "browser.startup" | "browser.location")
                || !grants.contains(port) || !step["args"].is_object()
                || (port == "state.get" && step["args"]["scope"] != "document") {
                return Err(fail("Invalid browser preflight observation"));
            }
        }
        let probes = args.get("probes");
        if probes.is_some_and(|probes| !grants.contains("dom.exists") || !probes.as_object().is_some_and(|entries|
            !entries.is_empty() && entries.len() <= 8 && entries.values().all(|value|
                value.as_str().is_some_and(|selector| !selector.is_empty() && selector.len() <= 256)))) {
            return Err(fail("Invalid browser preflight probes"));
        }
        if args.get("when").is_some_and(|guard| !grants.contains("dom.exists") || !guard.as_str()
            .is_some_and(|selector| !selector.is_empty() && selector.len() <= 256)) {
            return Err(fail("Invalid browser preflight selector"));
        }
        let observed = match self.exchange(process, PREFLIGHT,
            &json!({"reads": reads, "probes": probes, "when": args.get("when")}), meter) {
            Err(error) if probes.is_some() && error.to_string() == "Invalid browser preflight observation" => {
                // An existing tab can reconnect with the bridge from the previous release.
                let steps: Vec<Value> = probes.and_then(Value::as_object).into_iter().flatten().map(|(name, selector)|
                    json!({"port":"dom.exists", "args":{"selector":selector}, "save":name})).collect();
                return self.exchange(process, "browser.batch", &json!({"steps":steps}), meter);
            }
            result => result?,
        };
        let results = if let Some(probes) = probes.and_then(Value::as_object) {
            let values = observed["probes"].as_object().filter(|values| values.len() == probes.len()
                && probes.keys().all(|key| values.get(key).is_some_and(Value::is_boolean)))
                .ok_or_else(|| fail("Invalid browser preflight probe result"))?;
            Value::Object(values.clone())
        } else { json!(true) };
        if observed["enabled"] == false { return Ok(results); }
        let values = observed.as_array().or_else(|| observed["values"].as_array())
            .filter(|values| values.len() == reads.len())
            .ok_or_else(|| fail("Invalid browser preflight result"))?;
        let observations = reads.iter().zip(values).filter_map(|(step, answer)| {
            Some((step["port"].as_str()?.to_owned(), step["args"].clone(), answer.get("value")?.clone()))
        }).collect();
        self.preflight.replace(Some(BootEffects { observations, stable_ids, defer_content, ..BootEffects::default() }));
        Ok(results)
    }

    fn exchange(&self, process: &str, name: &str, args: &Value, meter: &mut Meter) -> Result<Value> {
        let mut socket = self.socket.borrow_mut();
        socket.set_read_timeout(Some(Duration::from_secs(8)))?;
        let traced = self.timing.borrow().is_some();
        let started = traced.then(Instant::now);
        let reply = send(&mut socket, &json!({"effect": name, "args": args}))
            .and_then(|()| websocket::read_text(&mut socket, LIMIT))
            .and_then(decode_message);
        if let Some(started) = started {
            let elapsed = started.elapsed();
            if let Some(trace) = self.timing.borrow_mut().as_mut() {
                trace.exchange += elapsed;
                if trace.effects.len() < TRACE_EFFECT_LIMIT {
                    trace.effects.push(json!({
                        "process": process,
                        "port": name,
                        "label": args["diagnosticLabel"].as_str().filter(|label| !label.is_empty() && label.len() <= 100),
                        "exchangeMs": milliseconds(elapsed),
                    }));
                } else {
                    trace.omitted += 1;
                }
            }
        }
        socket.set_read_timeout(None)?;
        let reply = match reply {
            Ok(Some(reply)) if reply["reply"] == true => reply,
            _ => {
                let _ = socket.shutdown(Shutdown::Both);
                return Err(fail("browser effect exchange interrupted"));
            }
        };
        if let Some(error) = reply["error"].as_str() { return Err(fail(error)); }
        let value = reply.get("value").ok_or_else(|| fail("missing browser effect result"))?;
        meter.charge(serde_json::to_vec(value)?.len())?;
        Ok(value.clone())
    }

    pub fn port(&self, process: &str, name: &str, args: &Value, env: &Env, meter: &mut Meter, depth: usize) -> Result<Value> {
        meter.charge(serde_json::to_vec(args)?.len())?;
        match name {
            "browser.batch" if args.get("preflight").is_some() => self.start_preflight(process, args, meter),
            "form.sessionOpen" | "form.sessionBegin" | "form.sessionSave" =>
                self.form.as_ref().ok_or_else(|| fail("form session store is not configured"))?.effect(name, args),
            "runtime.nonce" => {
                if !args.as_object().is_some_and(|fields| fields.is_empty()) {
                    return Err(fail("runtime.nonce expects an empty record"));
                }
                Ok(json!(crate::nonce::nonce()?))
            }
            "runtime.clock" => {
                if !args.as_object().is_some_and(|fields| fields.is_empty()) {
                    return Err(fail("runtime.clock expects an empty record"));
                }
                Ok(json!(utc_millis()?))
            }
            "runtime.device" => {
                if !args.as_object().is_some_and(|fields| fields.is_empty()) {
                    return Err(fail("runtime.device expects an empty record"));
                }
                let edge = self.telemetry.edge.as_deref().and_then(|directory| device_edge::read_status(directory).ok());
                Ok(json!({"os":std::env::consts::OS, "architecture":std::env::consts::ARCH,
                    "engine":env!("CARGO_PKG_VERSION"), "edgeConfigured":self.telemetry.edge.is_some(), "edge":edge}))
            }
            "runtime.environment" => {
                if !args.as_object().is_some_and(|fields| fields.is_empty()) {
                    return Err(fail("runtime.environment expects an empty record"));
                }
                Ok(json!({"memory": environment_memory(), "disk": filesystem_capacity(&self.telemetry.filesystem)}))
            }
            "runtime.telemetry" => {
                if !args.as_object().is_some_and(|fields| fields.is_empty()) {
                    return Err(fail("runtime.telemetry expects an empty record"));
                }
                self.telemetry.sample()
            }
            "state.get" | "state.set" if args["scope"] == "document" => self.effect(process, name, args, meter),
            "state.get" => Ok(self.state.borrow().get(string(args, "key")?).cloned().unwrap_or(Value::Null)),
            "state.set" => {
                let key = string(args, "key")?;
                let mut state = self.state.borrow_mut();
                if key.len() > 512 || (state.len() >= 256 && !state.contains_key(key)) {
                    return Err(fail("browser state capacity"));
                }
                let mut size = key.len() + serde_json::to_vec(&args["value"])?.len();
                for (name, value) in state.iter().filter(|(name, _)| *name != key) {
                    size += name.len() + serde_json::to_vec(value)?.len();
                    if size > LIMIT { return Err(fail("browser state size limit")); }
                }
                if size > LIMIT { return Err(fail("browser state size limit")); }
                state.insert(key.to_owned(), args["value"].clone());
                Ok(json!(true))
            }
            ASTER_STREAM | COUNTDOWN | "browser.on" | "browser.onMany" => {
                let stream = name == ASTER_STREAM;
                if stream && (!self.aster_stream || !args.as_object().is_some_and(|fields|
                    fields.keys().all(|key| matches!(key.as_str(), "query" | "input")))) {
                    return Err(fail("Ask Aster stream requires approval and accepts only a handler"));
                }
                let single = name != "browser.onMany";
                let bindings = if single { std::slice::from_ref(args) } else {
                    args["bindings"].as_array().filter(|items| !items.is_empty() && items.len() <= 32)
                        .ok_or_else(|| fail("expected 1 to 32 browser bindings"))?.as_slice()
                };
                let mut listeners = self.listeners.borrow_mut();
                if listeners.len() + bindings.len() > 256 { return Err(fail("browser listener capacity")); }
                let first = listeners.len();
                let mut pending = Vec::with_capacity(bindings.len());
                let mut effects = Vec::with_capacity(bindings.len());
                for (index, args) in bindings.iter().enumerate() {
                    if !stream && args["event"] == "stream" {
                        return Err(fail("stream events require the scoped browser.asterStream port"));
                    }
                    if args["event"] == "workspace-access" &&
                        (!self.booting.get() || name != "browser.on" || args["ref"] != "window" ||
                         !matches!(&self.application, App::Native(app) if app.declared_grants().contains("browser.request"))) {
                        return Err(fail("Workspace access requires a native boot listener with browser.request"));
                    }
                    let query = string(args, "query")?;
                    let allowed = match &self.application {
                        App::Native(app) => app.has_entry(query),
                        App::Surface(image) => image.model["queries"].get(query).is_some(),
                    };
                    if query == self.application.boot() || !allowed {
                        return Err(fail("browser event entry is not declared"));
                    }
                    let mut binding = args.as_object().cloned().ok_or_else(|| fail("expected browser binding record"))?;
                    binding.insert("binding".to_owned(), json!(first + index));
                    binding.remove("query");
                    binding.remove("input");
                    let label = args["dispatchLabel"].as_str().filter(|label| !label.is_empty() && label.len() <= 120)
                        .or_else(|| args["timing"].as_str().filter(|label| !label.is_empty() && label.len() <= 80))
                        .unwrap_or(query);
                    binding.insert("dispatchLabel".to_owned(), json!(label.chars().take(120).collect::<String>()));
                    effects.push(Value::Object(binding));
                    pending.push(Listener { query: query.to_owned(), input: args["input"].clone(), trace: !stream && args["timing"].is_string() });
                }
                let effect = if single { effects.remove(0) } else { json!({"bindings": effects}) };
                self.effect(process, name, &effect, meter)?;
                listeners.extend(pending);
                Ok(if single { json!(first) } else { json!((first..listeners.len()).collect::<Vec<_>>()) })
            }
            "kernel.prepare" => {
                let mut children = self.children.borrow_mut();
                let source = string(args, "text")?;
                let entry = string(args, "entry")?;
                if source.len() > 160_000 { return Err(fail("child source size limit")); }
                let source_hash = rel::hash(source);
                if let Some((key, _)) = children.iter().find(|(_, child)| child.source_hash == source_hash && child.entry == entry) {
                    return Ok(json!({"admission":key,"sourceHash":source_hash,"entry":entry}));
                }
                if children.len() >= 64 { return Err(fail("child admission capacity")); }
                // Children can compute and call their own linked processes. All host
                // grants, inherited locals, application data and preparation stay outside.
                let programme = Programme::admit(&[source.to_owned()], entry,
                    &BTreeSet::from(["kernel.invoke"]), meter)?;
                let admission = ticket()?;
                children.insert(admission.clone(), Child { programme: Rc::new(programme), entry: entry.to_owned(),
                    source_hash: source_hash.clone(), model: None });
                Ok(json!({"admission":admission,"sourceHash":source_hash,"entry":entry}))
            }
            "kernel.execute" if self.is_surface() => self.execute_surface_child(args, env, meter, depth),
            "kernel.execute" => {
                if !args.as_object().is_some_and(|fields| fields.keys().all(|key| matches!(key.as_str(), "admission" | "input"))) {
                    return Err(fail("EC-CHILD: Expected an admission ticket and optional input."));
                }
                let children = self.children.borrow();
                let child = args["admission"].as_str().and_then(|key| children.get(key))
                    .ok_or_else(|| fail("EC-CHILD: Child has no preparation admission in this browser session."))?;
                child.programme.run_child(&child.entry, args["input"].clone(), Env::new(), meter, depth)
            }
            FRONT_GATE_STATUS => {
                let valid = args.as_object().is_some_and(|fields| fields.is_empty()
                    || (fields.len() == 1 && fields.get("countdown").and_then(Value::as_str).is_some_and(|id|
                        id.strip_prefix('#').is_some_and(|name| !name.is_empty() && name.len() <= 80
                            && name.bytes().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == b'-')))));
                if !self.front_gate_status || !valid {
                    return Err(fail("Front Gate status requires the AppDev browser host and an optional countdown ID"));
                }
                self.effect(process, name, args, meter)
            }
            _ => self.effect(process, name, args, meter),
        }
    }
}

fn run(application: App, socket: TcpStream, durable: Option<DurableSession>, telemetry: Arc<HostTelemetry>, aster_stream: bool, front_gate_status: bool) -> Result<()> {
    let mut programme = application.admit(browser_profile(durable.is_some(), durable.as_ref().is_some_and(|session| session.peer.is_some())))?;
    let lease = durable.as_ref().and_then(|session| session.lease.clone());
    let mut form = None;
    let root = match &application {
        App::Native(app) => {
            let mut bindings = Env::new();
            if let Some(DurableSession { directory, actor, peer, mount, form: uses_form, .. }) = durable {
                let profile = if let Some(peer) = peer {
                    let profile = peer.store_profile(&app.state_profile);
                    programme.bind_peer_host(peer, true);
                    profile
                } else { app.state_profile.clone() };
                programme.bind_store(Store::open(&directory, &profile, &app.basis)?);
                if uses_form { form = Some(FormSession::open(&directory, &app.basis)?); }
                bindings.insert("actor".to_owned(), Rc::new(actor));
                bindings.insert("profile".to_owned(), Rc::new(json!(profile)));
                bindings.insert("basis".to_owned(), Rc::new(json!(app.basis)));
                bindings.insert("mount".to_owned(), Rc::new(json!(mount)));
            }
            bindings
        }
        App::Surface(image) => {
            let mut bindings: Env = image.data["bindings"].as_object().ok_or_else(|| fail("surface bindings absent"))?
                .iter().map(|(key, value)| (key.clone(), Rc::new(value.clone()))).collect();
            bindings.insert("data".to_owned(), Rc::new(image.data.clone()));
            bindings.insert("model".to_owned(), Rc::new(image.model.clone()));
            bindings
        }
    };
    programme.bind_browser_host(Session {
        application, form, root, socket: RefCell::new(socket), state: RefCell::default(),
        listeners: RefCell::default(), children: RefCell::default(), telemetry, timing: RefCell::default(), aster_stream, front_gate_status,
        booting: Cell::new(true), preflight: RefCell::default(),
    });
    let session = programme.browser_session()?;
    let mut meter = Meter::new(BUDGET);
    let boot = programme.run(session.application.boot(), json!({}), &mut meter)
        .and_then(|result| { session.finish_boot(&mut meter)?; Ok(result) });
    if let Some(form) = &session.form { form.finish(); }
    let booted = boot.is_ok();
    completion(&mut session.socket.borrow_mut(), boot, false, session.application.agent().is_some(), None)?;
    loop {
        let message = decode_message(websocket::read_browser_text(&mut session.socket.borrow_mut(), LIMIT)?)?;
        let Some(message) = message else { return Ok(()); };
        if lease.as_ref().is_some_and(|lease| !lease.active()) { return Ok(()); }
        let agent = message.get("agent");
        let result = if !booted { Err(fail("browser boot refused")) }
        else if let Some(input) = agent {
            let mut meter = Meter::new(BUDGET);
            meter.charge(serde_json::to_vec(&message)?.len())?;
            session.application.agent().ok_or_else(|| fail("browser agent entry is disabled"))
                .and_then(|entry| programme.run(entry, input.clone(), &mut meter))
        } else { dispatch(&programme, &session, &message) };
        if let Some(form) = &session.form { form.finish(); }
        let counter = if result.is_ok() { &session.telemetry.completed } else { &session.telemetry.faults };
        counter.fetch_add(1, Ordering::Relaxed);
        let timing = session.timing.borrow_mut().take().map(|trace| {
            let elapsed = trace.started.elapsed();
            json!({
                "hostMs": milliseconds(elapsed),
                "exchangeMs": milliseconds(trace.exchange),
                "effects": trace.effects,
                "omitted": trace.omitted,
            })
        });
        completion(&mut session.socket.borrow_mut(), result, agent.is_some(), false, timing)?;
    }
}

fn receive_peer(application: &App, mut stream: TcpStream, directory: &Path, peer: Arc<PeerHost>) -> Result<()> {
    let response = (|| -> Result<Value> {
        let App::Native(app) = application else { return Err(fail("Temple peers require native source")); };
        let bytes = websocket::read_text(&mut stream, peer_transport::LIMIT)?.ok_or_else(|| fail("missing peer envelope"))?;
        let envelope: Value = serde_json::from_str(&bytes)?;
        compat_value::external(&envelope)?;
        let profile = peer.store_profile(&app.state_profile);
        let mut programme = application.admit(CheckProfile::TempleBrowser)?;
        programme.bind_store(Store::open(directory, &profile, &app.basis)?);
        programme.bind_peer_host(peer, false);
        let mut meter = Meter::new(BUDGET);
        meter.charge(bytes.len())?;
        let bindings = json!({"eventInput":{"envelope":envelope},"profile":profile,"basis":app.basis});
        programme.run_bound("peer.receive", bindings.as_object().unwrap(), &mut meter)
    })().unwrap_or(Value::Null);
    let bytes = serde_json::to_vec(&response)?;
    if bytes.len() > peer_transport::LIMIT { return Err(fail("peer response size limit")); }
    websocket::frame(&mut stream, 1, &bytes)
}

fn start_peer_retry(application: Arc<Application>, directory: PathBuf, peer: Arc<PeerHost>)
    -> Result<(mpsc::Sender<()>, thread::JoinHandle<()>)>
{
    let (stop, stopped) = mpsc::channel();
    let worker = thread::Builder::new().name("encounter-temple-retry".to_owned()).stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let run = || -> Result<()> {
                let profile = peer.store_profile(&application.state_profile);
                let mut programme = application.admit_native_browser(&mut Meter::new(BUDGET), CheckProfile::TempleBrowser)?;
                programme.bind_store(Store::open(&directory, &profile, &application.basis)?);
                programme.bind_peer_host(peer, true);
                let bindings = json!({"profile":profile,"basis":application.basis});
                let bindings = bindings.as_object().unwrap();
                let interval = Duration::from_secs(2);
                let mut delay = interval;
                while stopped.recv_timeout(delay) == Err(mpsc::RecvTimeoutError::Timeout) {
                    let result = programme.run_bound(RETRY_ENTRY, bindings, &mut Meter::new(BUDGET));
                    delay = if result.is_ok_and(|state| matches!(state.as_str(), Some("idle" | "settled"))) {
                        interval
                    } else {
                        (delay * 2).min(Duration::from_secs(12))
                    };
                }
                Ok(())
            };
            if let Err(error) = run() { eprintln!("Temple retry worker could not start: {error}"); }
        })?;
    Ok((stop, worker))
}

fn dispatch(programme: &Programme, session: &Session, message: &Value) -> Result<Value> {
    let id = message["binding"].as_u64().and_then(|id| usize::try_from(id).ok())
        .ok_or_else(|| fail("expected a registered browser event"))?;
    let (query, input, trace) = {
        let listeners = session.listeners.borrow();
        let listener = listeners.get(id).ok_or_else(|| fail("unknown browser event binding"))?;
        (listener.query.clone(), listener.input.clone(), listener.trace)
    };
    let mut input = input.as_object().cloned().unwrap_or_default();
    input.insert("event".to_owned(), message["event"].clone());
    input.insert("matched".to_owned(), message["matched"].clone());
    let mut meter = Meter::new(BUDGET);
    meter.charge(serde_json::to_vec(message)?.len())?;
    if trace {
        *session.timing.borrow_mut() = Some(DispatchTiming {
            started: Instant::now(), exchange: Duration::ZERO, effects: Vec::new(), omitted: 0,
        });
    }
    programme.run(&query, Value::Object(input), &mut meter)
}

fn completion(socket: &mut TcpStream, result: Result<Value>, agent: bool, enables_agent: bool, timing: Option<Value>) -> Result<()> {
    let mut response = match result {
        Ok(value) if agent => {
            let payload = compat_value::stringify(&value, &Value::Null)?;
            json!({"done": true, "agentResult": serde_json::from_str::<Value>(&payload)?})
        }
        Ok(_) if enables_agent => json!({"done": true, "agentEnabled": true}),
        Ok(_) => json!({"done": true}),
        Err(error) => json!({"done": true, "error": error.to_string()}),
    };
    if let Some(timing) = timing { response["timing"] = timing; }
    send(socket, &response)
}

pub fn serve(root: &Path, declaration: &str, assets: &Path, port: u16, allow_aster_stream: bool) -> Result<()> {
    crate::package::check(root)?;
    if declaration == appdev_release::WORK_BROWSER_DECLARATION {
        let source = root.canonicalize()?;
        let assets = assets.canonicalize()?;
        if source.file_name().is_some_and(|name| name == "source")
            && assets.file_name().is_some_and(|name| name == "assets")
            && let Some(package) = assets.parent() && source.parent() == Some(package)
            && let Some(wasm) = appdev_release::BrowserWasm::load_work(package)?
        {
            let app = App::Native(Arc::new(Application::load(&source, declaration)?));
            if matches!(&app, App::Native(app) if app.declared_grants().contains(COUNTDOWN)
                || app.declared_grants().contains("browser.assuranceRefresh")) {
                return Err(fail("The Work Wasm catalog does not supply all granted browser policies"));
            }
            return serve_app(app, &assets, port, None, allow_aster_stream, Some(StandaloneWasm::Work(wasm)));
        }
    }
    let app = Application::load(root, declaration)?;
    if declaration == "applications/appdev-projects/aster-browser/browser.rel" && allow_aster_stream {
        let assets = assets.canonicalize()?;
        if assets.file_name().is_some_and(|name| name == "browser-assets")
            && let Some(package) = assets.parent()
            && let Some(wasm) = appdev_release::BrowserWasm::load_home(package)?
        {
            wasm.require_bundled_runtime()?;
            if app.declared_grants().contains(COUNTDOWN) || app.declared_grants().contains("browser.assuranceRefresh") {
                return Err(fail("The Aster bridge uses only the Home interaction module"));
            }
            return serve_app(App::Native(Arc::new(app)), &assets, port, None, allow_aster_stream, Some(StandaloneWasm::Aster(wasm)));
        }
    }
    serve_app(App::Native(Arc::new(app)), assets, port, None, allow_aster_stream, None)
}

pub fn serve_appdev(link: &Path, port: u16, allow_aster_stream: bool) -> Result<()> {
    let releases = appdev_release::Releases::open(link, fs::symlink_metadata(link)?.file_type().is_symlink())?;
    let initial = releases.current();
    let app = App::Native(Arc::clone(&initial.browser));
    let assets = initial.browser_assets.clone();
    drop(initial);
    host(app, port, None, allow_aster_stream, Some(releases), None, link.to_path_buf(), |stream, request, headers|
        publication::respond(&assets, stream, request, headers))
}

pub fn serve_durable(root: &Path, declaration: &str, assets: &Path, directory: &Path, operators: &Path, port: u16) -> Result<()> {
    serve_durable_profile(root, declaration, assets, directory, Some(operators), port, DurableMode::Standalone)
}

pub fn serve_temple(root: &Path, declaration: &str, assets: &Path, directory: &Path, operators: &Path, peers: &Path, port: u16, window: bool, mount: &str) -> Result<()> {
    if !mount.is_empty() && (!window || mount.len() > 40 || !mount.as_bytes()[0].is_ascii_lowercase()
        || !mount.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')) {
        return Err(fail("expected a declared Temple window mount name"));
    }
    serve_durable_profile(root, declaration, assets, directory, Some(operators), port, DurableMode::Temple { peers, window, mount })
}

pub fn serve_device(root: &Path, declaration: &str, assets: &Path, directory: &Path, operators: &Path, sockets: &Path, port: u16) -> Result<()> {
    serve_durable_profile(root, declaration, assets, directory, Some(operators), port, DurableMode::Device { sockets })
}

pub fn serve_form(root: &Path, declaration: &str, assets: &Path, directory: &Path, port: u16) -> Result<()> {
    serve_durable_profile(root, declaration, assets, directory, None, port, DurableMode::Form)
}

enum DurableMode<'a> {
    Standalone,
    Form,
    Temple { peers: &'a Path, window: bool, mount: &'a str },
    Device { sockets: &'a Path },
}

fn serve_durable_profile(root: &Path, declaration: &str, assets: &Path, directory: &Path, operators: Option<&Path>, port: u16, mode: DurableMode<'_>) -> Result<()> {
    crate::package::check(root)?;
    let app = Application::load(root, declaration)?;
    let assets = assets.canonicalize()?;
    let operators = operators.map(|file| {
        let file = file.canonicalize()?;
        if file.starts_with(&assets) { return Err(fail("operator file must be outside the served assets")); }
        Operators::read(&file)
    }).transpose()?;
    let (peer, window, edge, mount) = match mode {
        DurableMode::Standalone => (None, false, None, ""),
        DurableMode::Form => {
            if !app.has_entry("form.submit") || app.has_entry("device.check") {
                return Err(fail("expected a loopback form browser declaration"));
            }
            (None, false, None, "")
        }
        DurableMode::Temple { peers, window, mount } => (Some(Arc::new(PeerHost::read(peers, &assets, port)?)), window, None, mount),
        DurableMode::Device { sockets } => {
            let sockets = device_edge::private_directory(sockets)?;
            if sockets.starts_with(&assets) || !app.has_entry("device.check") {
                return Err(fail("expected a device policy entry and private sockets outside the served assets"));
            }
            (None, false, Some(sockets), "")
        }
    };
    if let Some(peer) = &peer {
        let roles = operators.as_ref().ok_or_else(|| fail("Temple operator file required"))?.roles();
        if roles.as_array().is_none_or(|roles| roles.len() != 1 || roles[0]["id"] != peer.actor() || roles[0]["role"] == "observer") {
            return Err(fail("Temple host requires one matching authenticated local operator"));
        }
    }
    fs::DirBuilder::new().mode(0o700).recursive(true).create(directory)?;
    let directory = directory.canonicalize()?;
    if directory.starts_with(&assets) || fs::metadata(&directory)?.permissions().mode() & 0o077 != 0 {
        return Err(fail("expected a private store directory outside the served assets"));
    }
    let window_operators = window.then(|| WindowOperators::read(&assets, &directory)).transpose()?;
    serve_app(App::Native(Arc::new(app)), &assets, port, Some(DurableHost { directory, operators, window_operators, edge, peer, mount: mount.to_owned() }), false, None)
}

pub fn serve_surface(config: &Path, assets: &Path, port: u16) -> Result<()> {
    serve_app(App::Surface(Arc::new(SurfaceImage::read(config)?)), assets, port, None, false, None)
}

pub fn serve_release(root: &Path, pin: &str, port: u16) -> Result<()> {
    let (image, assets) = crate::browser_release::read(root, pin)?;
    host(App::Surface(Arc::new(image)), port, None, false, None, None, root.to_path_buf(), |stream, request, headers|
        publication::respond_verified(&assets, stream, request, headers))
}

enum StandaloneWasm {
    Work(appdev_release::BrowserWasm),
    Aster(appdev_release::BrowserWasm),
}

fn serve_app(application: App, assets: &Path, port: u16, durable: Option<DurableHost>, allow_aster_stream: bool,
    standalone_wasm: Option<StandaloneWasm>) -> Result<()>
{
    let assets = assets.canonicalize()?;
    crate::package::check(&assets)?;
    if !assets.join("index.html").is_file() { return Err(fail("expected browser host index.html")); }
    host(application, port, durable, allow_aster_stream, None, standalone_wasm, assets.clone(), |stream, request, headers|
        publication::respond(&assets, stream, request, headers))
}

fn build_compatibility_bridge(body: &str, front_gate_status: bool, aster: Option<&appdev_release::BrowserWasm>,
    countdown: bool, assurance: bool) -> Result<String>
{
    use crate::process::browser_wasm;
    let mut bindings = match aster {
        Some(wasm) => wasm.interaction_binding.clone(),
        None => format!("const encounterInteractionWasm = '{}';\n", Base64::encode_string(&browser_wasm::interaction()?)),
    };
    let mut legacy = include_str!("browser_interaction_legacy.mjs").to_owned();
    let mut policies = String::from("interaction: encounterLegacyInteraction");
    if countdown {
        if front_gate_status {
            bindings.push_str(&format!("const encounterCountdownWasm = '{}';\n",
                Base64::encode_string(&browser_wasm::countdown()?)));
        }
        legacy.push_str("\n");
        legacy.push_str(include_str!("browser_countdown_legacy.mjs"));
        policies.push_str(", countdown: encounterLegacyCountdown");
    }
    if assurance {
        if front_gate_status {
            bindings.push_str(&format!("const encounterAssuranceWasm = '{}';\n",
                Base64::encode_string(&browser_wasm::assurance()?)));
        }
        legacy.push_str("\n");
        legacy.push_str(include_str!("browser_assurance_legacy.mjs"));
        policies.push_str(", assurance: encounterLegacyAssurance");
    }
    let selector = format!("{{ {policies} }}[name]");
    let script = browser_wasm::browser_policy_script(body, Some((&legacy, &selector)));
    Ok(format!("{bindings}{script}"))
}

fn overlay_styles() -> Result<String> {
    use crate::process::{CSS_RENDERER, Meter, Programme};
    let mut meter = Meter::new(100_000);
    let entry = "browser.overlayStyles";
    let programme = Programme::admit_entries(
        &[include_str!("browser_overlay.encounter").to_owned(), CSS_RENDERER.to_owned()],
        &[entry], &std::collections::BTreeSet::new(), &mut meter,
    )?;
    let style = programme.run(entry, serde_json::Value::Null, &mut meter)?;
    Ok(format!("const encounterOverlayCss = {};\n", serde_json::to_string(&style)?))
}

fn host(
    application: App, port: u16, durable: Option<DurableHost>, allow_aster_stream: bool,
    appdev_releases: Option<appdev_release::Releases>, standalone_wasm: Option<StandaloneWasm>, filesystem: PathBuf,
    respond: impl Fn(&mut TcpStream, &http::Request, &str) -> Result<()>,
) -> Result<()> {
    let aster_stream = matches!(&application, App::Native(app) if app.declared_grants().contains(ASTER_STREAM));
    if aster_stream && !allow_aster_stream {
        return Err(fail("browser.asterStream requires operator approval (--allow-aster-stream)"));
    }
    let front_gate_status = appdev_releases.is_some();
    let bridge_body = format!("{}{}{}{}{}",
        overlay_styles()?,
        if durable.is_some() { "const encounterReconnect = true;\n" } else { "" },
        crate::process::browser_wasm::BOOTSTRAP,
        include_str!("assurance_updates.mjs"), include_str!("browser_host.mjs"));
    let compatibility = OnceLock::new();
    let aster = match &standalone_wasm {
        Some(StandaloneWasm::Aster(wasm)) => Some(wasm),
        _ => None,
    };
    // Keep the full compatibility profile for release-following and compiled image hosts.
    let (countdown, assurance) = match &application {
        App::Native(app) if !front_gate_status => (
            app.declared_grants().contains(COUNTDOWN),
            app.declared_grants().contains("browser.assuranceRefresh"),
        ),
        _ => (true, true),
    };
    let legacy_bridge = || {
        compatibility.get_or_init(|| build_compatibility_bridge(&bridge_body, front_gate_status, aster, countdown, assurance)
            .map_err(|error| error.to_string())).as_deref().map_err(|error| fail(error.clone()))
    };
    let pinned_home = appdev_releases.as_ref().is_some_and(|releases| releases.current().workspace.browser_wasm.is_some());
    if !pinned_home && !matches!(&standalone_wasm, Some(StandaloneWasm::Work(_))) {
        // Aster still has callers on the canonical compatibility URL.
        legacy_bridge()?;
    }
    let strict_bridge = crate::process::browser_wasm::browser_policy_script(&bridge_body, None);
    if !front_gate_status && matches!(&application, App::Native(app) if app.declared_grants().contains(FRONT_GATE_STATUS)) {
        return Err(fail("browser.frontGateStatus requires the AppDev browser host"));
    }
    let mut admitted = application.admit(browser_profile(durable.is_some(), durable.as_ref().is_some_and(|host| host.peer.is_some())))?;
    let device_gate = matches!(&application, App::Native(app) if app.has_entry("device.check"));
    if device_gate {
        if durable.is_none() { return Err(fail("device.check requires a durable browser host")); }
        admitted.require_grants("device.check", &BTreeSet::from(["storage.snapshot", "kernel.invoke", "rel.decode", "number.calculate"]))?;
    }
    if let Some(host) = &durable {
        let App::Native(app) = &application else { return Err(fail("durable browser host requires a native declaration")); };
        // Fail before listening if the store cannot be opened with this profile.
        let profile = host.peer.as_ref().map_or_else(|| app.state_profile.clone(), |peer| peer.store_profile(&app.state_profile));
        let store = Store::open(&host.directory, &profile, &app.basis)?;
        if device_gate { admitted.bind_store(store); }
    }
    let telemetry = Arc::new(HostTelemetry::new(durable.as_ref().and_then(|host| host.edge.clone()), filesystem));
    let peer_sessions = Arc::new(AtomicUsize::new(0));
    // The CRM mount shares the Temple's store. Only the Temple host owns its background delivery.
    let retry = match (&application, &durable) {
        (App::Native(app), Some(host)) if host.mount.is_empty() && app.has_entry(RETRY_ENTRY) => {
            host.peer.as_ref().map(|peer| start_peer_retry(app.clone(), host.directory.clone(), peer.clone())).transpose()?
        }
        _ => None,
    };
    let served = http::serve_gateway(port, |origin, stream, request| {
        let loopback = origin.trim_start_matches("http://");
        let localhost = loopback.replacen("127.0.0.1:", "localhost:", 1);
        let host = request.headers.get("host").map(String::as_str);
        if host != Some(loopback) && host != Some(localhost.as_str()) {
            return http::send(stream, "403 Forbidden", "text/plain", "Wrong browser host.");
        }
        let expected_origin = if host == Some(loopback) { origin.to_owned() } else { format!("http://{localhost}") };
        if request.path == "/_encounter/browser" && request.headers.get("origin").map(String::as_str) != Some(expected_origin.as_str()) {
            return http::send(stream, "403 Forbidden", "text/plain", "Wrong browser origin.");
        }
        if device_gate && let Some(app_id) = request.path.strip_prefix("/_encounter/device/check/") {
            let admissible = request.method == "GET" && request.body.is_empty() && !request.headers.contains_key("origin")
                && !app_id.is_empty() && app_id.len() <= 64 && app_id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
            if !admissible { return http::send(stream, "403 Forbidden", "text/plain", ""); }
            let allowed = (|| -> Result<bool> {
                let bindings = json!({"eventInput":{"app":app_id,"now":utc_millis()?}});
                admitted.run_bound("device.check", bindings.as_object().unwrap(), &mut Meter::new(BUDGET))?
                    .as_bool().ok_or_else(|| fail("device policy must return a boolean"))
            })();
            let status = match allowed {
                Ok(true) => "204 No Content",
                Ok(false) => "403 Forbidden",
                Err(_) => "503 Service Unavailable",
            };
            return http::send(stream, status, "text/plain", "");
        }
        if request.path == peer_transport::PATH && let Some(host) = &durable && let Some(peer) = &host.peer {
            if request.headers.contains_key("origin") || !request.body.is_empty() {
                return http::send(stream, "403 Forbidden", "text/plain", "Expected a native Temple peer.");
            }
            if peer_sessions.load(Ordering::Relaxed) >= 4 {
                return http::send(stream, "503 Service Unavailable", "text/plain", "Temple peer capacity.");
            }
            let socket = stream.try_clone()?;
            websocket::handshake(stream, &request)?;
            let directory = host.directory.clone();
            let peer = Arc::clone(peer);
            let application = application.clone();
            let active = Arc::clone(&peer_sessions);
            active.fetch_add(1, Ordering::Relaxed);
            let worker = thread::Builder::new().name("encounter-temple-peer".to_owned()).stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let _ = receive_peer(&application, socket, &directory, peer);
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            if worker.is_err() { peer_sessions.fetch_sub(1, Ordering::Relaxed); }
            return Ok(());
        }
        let session = if let Some(host) = &durable {
            if host.operators.is_none() {
                Some(DurableSession { directory: host.directory.clone(), actor: json!({"id":"loopback-workspace","role":"workspace-owner"}), form: true, lease: None, peer: None, mount: String::new() })
            } else if let Some(window) = &host.window_operators {
                let operators = host.operators.as_ref().ok_or_else(|| fail("window operator file required"))?;
                if matches!(request.path.as_str(), browser_operator::PATH | browser_operator::SIGN_OUT) {
                    return window.handle(operators, stream, &request, &expected_origin);
                }
                if let Some((actor, lease)) = window.actor(operators, &request)? {
                    Some(DurableSession { directory: host.directory.clone(), actor, form: false, lease: Some(lease), peer: host.peer.clone(), mount: host.mount.clone() })
                } else {
                    return match (request.method.as_str(), request.path.as_str()) {
                        ("GET", "/" | "/index.html") => window.prompt(stream),
                        ("GET" | "HEAD", path) if path.ends_with(".css") =>
                            respond(stream, &request, "Content-Security-Policy: frame-ancestors 'none'\r\n"),
                        _ => http::send(stream, "401 Unauthorized", "text/plain", "Sign in to this application."),
                    };
                }
            } else {
                let Some(actor) = host.operators.as_ref().and_then(|operators| operators.verify(request.headers.get("authorization").map(String::as_str))) else {
                    return http::send_headers(stream, "401 Unauthorized", "text/plain",
                        "WWW-Authenticate: Basic realm=\"Encounter\", charset=\"UTF-8\"\r\n", "Operator credentials required.");
                };
                Some(DurableSession { directory: host.directory.clone(), actor, form: false, lease: None, peer: host.peer.clone(), mount: String::new() })
            }
        } else { None };
        match request.path.as_str() {
            path @ ("/_encounter/browser.mjs" | appdev_release::WASM_HOME_BRIDGE) if request.method == "GET" => {
                let strict = path == appdev_release::WASM_HOME_BRIDGE;
                let standalone = match (&standalone_wasm, strict) {
                    (Some(StandaloneWasm::Work(wasm)), false) => Some(wasm),
                    (Some(StandaloneWasm::Aster(wasm)), true) => Some(wasm),
                    _ => None,
                };
                if let Some(wasm) = standalone {
                    return http::send_headers(stream, "200 OK", "text/javascript",
                        &format!("X-Encounter-Browser-Wasm: {}\r\n", wasm.catalog_pin),
                        &format!("{}{strict_bridge}", wasm.interaction_binding));
                }
                let release = appdev_releases.as_ref().map(appdev_release::Releases::current);
                if let Some(wasm) = release.as_ref().and_then(|release| release.workspace.browser_wasm.as_ref()) {
                    return http::send_headers(stream, "200 OK", "text/javascript",
                        &format!("X-Encounter-Browser-Wasm: {}\r\n", wasm.catalog_pin),
                        &format!("{}{strict_bridge}", wasm.bindings));
                }
                if strict {
                    return http::send(stream, "404 Not Found", "text/plain", "This release has no Home Wasm catalog.");
                }
                http::send(stream, "200 OK", "text/javascript", legacy_bridge()?)
            }
            "/_encounter/browser" => {
                if telemetry.sessions.load(Ordering::Relaxed) >= SESSION_LIMIT {
                    return http::send(stream, "503 Service Unavailable", "text/plain", "Browser session capacity.");
                }
                let socket = stream.try_clone()?;
                websocket::handshake(stream, &request)?;
                socket.set_read_timeout(None)?;
                let application = match &appdev_releases {
                    Some(releases) => App::Native(Arc::clone(&releases.current().browser)),
                    None => application.clone(),
                };
                let active = Arc::clone(&telemetry);
                active.sessions.fetch_add(1, Ordering::Relaxed);
                let worker = thread::Builder::new().name("encounter-browser".to_owned()).stack_size(16 * 1024 * 1024)
                    .spawn(move || {
                        let _ = run(application, socket, session, Arc::clone(&active), aster_stream, front_gate_status);
                        active.sessions.fetch_sub(1, Ordering::Relaxed);
                    });
                if worker.is_err() { telemetry.sessions.fetch_sub(1, Ordering::Relaxed); }
                Ok(())
            }
            _ => {
                let policy = "Content-Security-Policy: frame-ancestors 'none'\r\n";
                if let Some(releases) = &appdev_releases {
                    publication::respond(&releases.current().browser_assets, stream, &request, policy)
                } else {
                    respond(stream, &request, policy)
                }
            }
        }
    });
    if let Some((stop, worker)) = retry {
        drop(stop);
        let _ = worker.join();
    }
    served
}
