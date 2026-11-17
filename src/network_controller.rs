use crate::{Result, appdev_host_process::Scratch, command::Evaluator, fail, http, rel,
    network_transport::{Activation, Settings, evaluate, list, port, text}};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, VecDeque}, env, fs, io::{self, Write}, net::{Ipv4Addr, TcpListener, TcpStream},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt}, path::{Path, PathBuf}, sync::{Arc, Mutex, RwLock, TryLockError},
    thread, time::{SystemTime, UNIX_EPOCH}};
use subtle::ConstantTimeEq;

fn milliseconds() -> Result<i64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?) }

fn timestamp() -> Result<String> {
    let date = chrono::DateTime::from_timestamp_millis(milliseconds()?).ok_or_else(|| fail("Invalid network receipt time"))?;
    Ok(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn review_id() -> Result<String> {
    let mut bytes = [0;16];
    getrandom::getrandom(&mut bytes).map_err(|error| fail(error.to_string()))?;
    bytes[6] = bytes[6] & 0x0f | 0x40;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    let hex = hex::encode(bytes);
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
}

fn fields(request: &http::Request) -> Result<Value> {
    if request.headers.get("content-type").map(String::as_str) != Some("application/x-www-form-urlencoded")
        || !request.headers.get("content-length").is_some_and(|s| (1..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())) {
        return Err(fail("Submit the Network settings form."));
    }
    if request.body.len() > 4096 { return Err(fail("The request is too large.")); }
    let mut fields = BTreeMap::new();
    for (name, value) in form_urlencoded::parse(&request.body) {
        if fields.insert(name, value).is_some() { return Err(fail("Submit each setting once.")); }
    }
    Ok(json!(fields))
}

fn respond(stream: &mut TcpStream, status: u64, content_type: &str, body: &str, location: Option<&str>) -> Result<()> {
    let status = match status {
        200 => "200 OK", 303 => "303 See Other", 400 => "400 Bad Request", 403 => "403 Forbidden",
        404 => "404 Not Found", 405 => "405 Method Not Allowed", 421 => "421 Misdirected Request", _ => "503 Service Unavailable",
    };
    if let Some(location) = location {
        write!(stream, "HTTP/1.1 {status}\r\nLocation: {location}\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")?;
        return Ok(());
    }
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}; charset=utf-8\r\nContent-Length: {}\r\n\
        Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
        Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'\r\n\
        Referrer-Policy: no-referrer\r\n\r\n", body.len())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

#[derive(Clone)]
struct View { snapshot: Value, receipts: Value }

struct Machine {
    state: Value,
    snapshot: Value,
    reviews: VecDeque<(String, Value)>,
    activation: Activation,
}

struct Controller {
    settings: Settings,
    state_dir: PathBuf,
    _lock: fs::File,
    operator: String,
    credential: String,
    machine: Mutex<Machine>,
    view: RwLock<Option<View>>,
    startup_error: Mutex<Option<String>>,
}

impl Controller {
    fn save(&self, state: &Value) -> Result<()> {
        let scratch = Scratch::create(&self.state_dir, ".state-next-")?;
        let temp = scratch.path().join("active.rel");
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&temp)?;
        file.write_all(rel::encode_ordered(state, "LifeBoardNetworkState")?.as_bytes())?;
        file.sync_all()?;
        fs::rename(temp, self.state_dir.join("active.rel"))?;
        Ok(())
    }

    fn publish_view(&self, machine: &Machine) {
        *self.view.write().expect("network view") = Some(View {
            snapshot:machine.snapshot.clone(), receipts:machine.state["receipts"].clone(),
        });
    }

    fn start(&self) -> Result<()> {
        let app = Evaluator::load(&self.settings.root, "controller.rel")?;
        let mut machine = self.machine.lock().expect("network machine");
        let mut generation = self.settings.stage(&app, &machine.state["active"], &json!([]))?;
        let reserved = machine.activation.reserve(&app, &generation)?;
        generation.children.check()?;
        self.save(&machine.state)?;
        machine.activation.commit(generation, reserved);
        self.publish_view(&machine);
        println!("Life Board network controller is ready on 127.0.0.1:{}.", self.settings.control);
        Ok(())
    }

    fn check(&self) -> Result<()> {
        if let Some(error) = self.startup_error.lock().expect("network startup").take() {
            return Err(fail(error));
        }
        if let Ok(mut machine) = self.machine.try_lock() && let Some(active) = machine.activation.active.as_mut() {
            active.children.check()?;
        }
        Ok(())
    }

    fn command(&self, app: &Evaluator, notes: &Evaluator, view: &View, request: &http::Request) -> Result<(Value, Value)> {
        let command = evaluate(notes, "command", &json!({"active":view.snapshot,"fields":fields(request)?}))?;
        let body = &command["body"];
        let action = text(&command["action"])?;
        let existing = |receipts: &Value| {
            receipts.as_array().into_iter().flatten().find(|receipt|
                receipt["reviewId"] == body["reviewId"] && receipt["digest"] == body["digest"]).cloned()
        };
        if action == "approve" && let Some(receipt) = existing(&view.receipts) {
            return Ok((Value::Null, receipt));
        }
        let mut machine = match self.machine.try_lock() {
            Ok(machine) => machine,
            Err(TryLockError::WouldBlock) => return Err(fail("A change is being applied. Refresh when it finishes.")),
            Err(TryLockError::Poisoned(_)) => return Err(fail("Network settings unavailable.")),
        };
        let policy = Evaluator::load(&self.settings.root, "review.rel")?;
        if action == "review" {
            let mut prepared = evaluate(&policy, "prepare", &json!({"snapshot":machine.snapshot,
                "active":machine.state["active"],"proposal":body,"controlPort":self.settings.control}))?;
            let now = milliseconds()?;
            machine.reviews.retain(|(_, item)| item["expires"].as_i64().is_some_and(|expiry| now < expiry));
            if machine.reviews.len() >= 64 { machine.reviews.pop_front(); }
            let id = review_id()?;
            prepared["expires"] = json!(now + 600_000);
            let mut response = prepared["reviewed"].clone();
            response["reviewId"] = json!(id);
            machine.reviews.push_back((id, prepared));
            return Ok((response, Value::Null));
        }
        if action != "approve" { return Err(fail("Unknown network command")); }
        if let Some(receipt) = existing(&machine.state["receipts"]) { return Ok((Value::Null, receipt)); }
        let id = text(&body["reviewId"])?;
        let index = machine.reviews.iter().position(|(key, _)| key == id);
        let pending = index.map(|index| machine.reviews[index].1.clone()).unwrap_or_default();
        let next = evaluate(&policy, "authorize", &json!({"pending":pending,"snapshot":machine.snapshot,
            "digest":body["digest"],"now":milliseconds()?}))?;
        if let Some(index) = index { machine.reviews.remove(index); }
        let approved_at = timestamp()?;
        let receipt = |outcome: &str, detail: &str| -> Result<Value> {
            let mut input = json!({"reviewId":id,"reviewed":pending["reviewed"],"operator":self.operator,
                "approvedAt":approved_at,"outcome":outcome,"finishedAt":timestamp()?});
            input[if outcome == "applied" { "revision" } else { "reason" }] = json!(detail);
            evaluate(&policy, "receipt", &input)
        };
        let with_receipt = |active: &Value, state: &Value, receipt: &Value| -> Result<Value> {
            let mut receipts = list(&state["receipts"])?.to_vec();
            receipts.push(receipt.clone());
            Ok(json!({"active":active,"receipts":receipts}))
        };
        let attempt = (|| -> Result<_> {
            let snapshot = evaluate(&policy, "snapshot", &next)?;
            let mut generation = self.settings.stage(app, &next, &pending["reviewed"]["plan"]["routes"])?;
            let reserved = machine.activation.reserve(app, &generation)?;
            let receipt = receipt("applied", text(&snapshot["revision"])?)?;
            let state = with_receipt(&next, &machine.state, &receipt)?;
            generation.children.check()?;
            self.save(&state)?;
            Ok((generation,reserved,snapshot,state,receipt))
        })();
        let result = match attempt {
            Ok((generation,reserved,snapshot,state,receipt)) => {
                machine.activation.commit(generation, reserved);
                machine.snapshot = snapshot;
                machine.state = state;
                receipt
            }
            Err(error) => {
                let reason = if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::AddrInUse) {
                    "A requested tunnel port is already in use.".to_owned()
                } else { error.to_string() };
                let receipt = receipt("failed", &reason)?;
                let state = with_receipt(&machine.state["active"], &machine.state, &receipt)?;
                self.save(&state)?;
                machine.state = state;
                receipt
            }
        };
        self.publish_view(&machine);
        Ok((Value::Null, result))
    }

    fn request(&self, stream: &mut TcpStream, request: http::Request) -> Result<()> {
        let app = Evaluator::load(&self.settings.root, "controller.rel")?;
        let view = self.view.read().expect("network view").clone();
        let supplied = request.headers.get("authorization").map_or("", String::as_str);
        let route = app.run("controller.route", json!({"host":request.headers.get("host").map_or("",String::as_str),
            "controlHost":format!("127.0.0.1:{}",self.settings.control),"method":request.method,"path":request.path,
            "authorized":bool::from(supplied.as_bytes().ct_eq(self.credential.as_bytes())),
            "ready":view.is_some(),"origin":request.headers.get("origin")}))?;
        let mut status = route["status"].as_u64().ok_or_else(|| fail("Invalid network response status"))?;
        if status != 200 {
            return respond(stream, status, "application/json", &json!({"error":route["error"]}).to_string(), route["location"].as_str());
        }
        let view = view.ok_or_else(|| fail("Network controller is not ready"))?;
        let notes = Evaluator::load(&self.settings.root, "notes.rel")?;
        let (mut reviewed, mut receipt, mut message) = (Value::Null, Value::Null, String::new());
        if request.method == "POST" {
            match self.command(&app, &notes, &view, &request) {
                Ok(result) => (reviewed,receipt) = result,
                Err(error) => { status = 400; message = error.to_string(); }
            }
        }
        let latest = self.view.read().expect("network view").clone().unwrap_or(view);
        let receipts = list(&latest.receipts)?.iter().rev().take(20).collect::<Vec<_>>();
        let page = notes.run("cli.main", json!(["page",json!({"active":latest.snapshot,
            "receipts":receipts,"reviewed":reviewed,"receipt":receipt,"message":message}).to_string()]))?;
        respond(stream, status, "text/html", &format!("{}\n", text(&page)?), None)
    }
}

pub fn serve(root: &Path, config: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let config = rel::decode(&fs::read_to_string(config)?, "LifeBoardNetworkSettings")?;
    let path = |key| -> Result<PathBuf> {
        let path = PathBuf::from(text(&config[key])?);
        if !path.is_absolute() { return Err(fail("Expected absolute network settings paths")); }
        Ok(path)
    };
    let pin = |key| config.get(key).map(|value| text(value).map(str::to_owned)).transpose();
    let settings = Settings { root, projects:path("projects")?, runtime:path("runtime")?, gate_runtime:path("gateRuntime")?,
        nginx:path("nginx")?, work:path("work")?, control:port(&config["controlPort"])?,
        runtime_pin:pin("runtimeSha256")?, gate_pin:pin("gateRuntimeSha256")?, nginx_pin:pin("nginxSha256")? };
    let state_dir = path("state")?;
    fs::create_dir_all(&state_dir)?;
    fs::create_dir_all(&settings.work)?;
    let lock = fs::File::open(&state_dir)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("Network state directory is already in use."));
    }
    let policy = Evaluator::load(&settings.root, "review.rel")?;
    let state = match fs::read_to_string(state_dir.join("active.rel")) {
        Ok(bytes) => rel::decode(&bytes, "LifeBoardNetworkState")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => json!({"active":{
            "target":config["target"],"frontGate":config["frontGate"],"lifeBoard":config["lifeBoard"],"routes":settings.routes()?
        },"receipts":[]}),
        Err(error) => return Err(error.into()),
    };
    evaluate(&policy, "validate", &json!({"active":state["active"],"controlPort":settings.control}))?;
    list(&state["receipts"])?;
    let snapshot = evaluate(&policy, "snapshot", &state["active"])?;
    let credentials = env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| fail("Missing network credential directory"))?;
    let credential = fs::read_to_string(Path::new(&credentials).join("identity-management-auth"))?;
    if credential.trim().is_empty() { return Err(fail("The Notes steward gateway credential is required.")); }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, settings.control))?;
    let controller = Arc::new(Controller { settings, state_dir, _lock:lock, operator:text(&config["operator"])?.to_owned(),
        credential:credential.trim().to_owned(), machine:Mutex::new(Machine { state, snapshot, reviews:VecDeque::new(), activation:Activation::default() }),
        view:RwLock::new(None), startup_error:Mutex::new(None) });
    let tick = Arc::clone(&controller);
    let handle = Arc::clone(&controller);
    thread::scope(|scope| {
        scope.spawn(|| {
            if let Err(error) = controller.start() {
                *controller.startup_error.lock().expect("network startup") = Some(error.to_string());
            }
        });
        http::serve_bound_workers(listener, 8, 64 * 1024, || tick.check(), move |stream, request| {
            if let Err(error) = handle.request(stream, request) {
                eprintln!("Network settings request failed: {error}");
                let _ = respond(stream, 400, "application/json", &json!({"error":error.to_string()}).to_string(), None);
            }
        })
    })
}
