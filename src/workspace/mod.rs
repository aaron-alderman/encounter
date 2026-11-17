mod environments;
mod files;
mod formation;
mod management;
mod resources;
mod registry_shadow;
mod registry_presentation;
mod workloads;
mod public_accounts;
mod temple;
pub(crate) mod terminal_client;
mod terminal;
mod steward;
mod vm_manager;
pub(crate) mod transport;
mod x;

use crate::{Result, application::Application, fail, http::{self, Request}, process::Meter};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, fs, path::{Path, PathBuf}, sync::{Arc, Mutex, MutexGuard}};
use transport::{Fields, Response, equal, header, read_record, string, timestamp, token};

const DECLARATION: &str = "applications/appdev-projects/versions.rel";
const CORPUS: &str = "applications/appdev-projects/claimipedia.rel";
const INSTALLER: &str = "AppDev-Temple-Connector.exe";
const ROOM_LIMIT: usize = 256;
const SESSION_COOKIE: &str = "__Host-appdev-session";
const SESSION_LIFETIME: u32 = 28_800;

enum Account {
    X(String),
    Public(String),
}

#[derive(Default)]
struct State {
    office: Value,
    roles: HashMap<String, Value>,
    active_office_operations: usize,
    credentials: Value,
    credential_revision: u64,
    inbox: Value,
    pending_mentions: Option<x::Pending>,
    registering: bool,
    changing: bool,
    logins: HashMap<String, x::Login>,
    public_logins: HashMap<String, public_accounts::Login>,
    sessions: HashMap<String, (Account, i64)>,
    rooms: HashMap<String, Value>,
}

impl State {
    fn start_local_session(&mut self, request: &Request, account: Account, now: i64) -> Result<Option<String>> {
        self.sessions.retain(|_, (_, expires)| *expires > now);
        if self.sessions.len() >= ROOM_LIMIT { return Ok(None); }
        let session = token::<32>()?;
        self.sessions.remove(cookie_value(request, SESSION_COOKIE));
        self.sessions.insert(session.clone(), (account, now + i64::from(SESSION_LIFETIME) * 1000));
        Ok(Some(session))
    }
}

pub struct Release {
    root: PathBuf,
    application: Application,
    corpus: Application,
    index: String,
    identity_assurance: Option<Value>,
    style: String,
    controller: String,
    policy: String,
    pub(crate) browser_wasm: Option<crate::appdev_release::BrowserWasm>,
    projection: Mutex<Option<(Value, Value)>>,
}

struct Runtime {
    private: PathBuf,
    origin: String,
    local_origin: String,
    temple: Option<temple::Temple>,
    network: String,
    certificate_inventory: Option<String>,
    certificate_renewal: Option<(String, String)>,
    certificate_reviews: Mutex<HashMap<String, Value>>,
    certificate_rollover: Option<Value>,
    x_origin: String,
    public_providers: public_accounts::Providers,
    identity_gateway: String,
    authorization: String,
    steward: String,
    files: files::FileIndex,
    network_state: PathBuf,
    hosted_port: u16,
    terminal_only: bool,
    resources: Mutex<resources::CpuSample>,
    workloads: Mutex<workloads::WorkloadSample>,
    vms: vm_manager::Registry,
    steward_sessions: Mutex<steward::Sessions>,
    registry_presentation: registry_presentation::Presentations,
    terminal: Mutex<terminal::Sessions>,
    state: Mutex<State>,
    versions: Mutex<()>,
    formation: Mutex<()>,
    formation_test: Mutex<Option<formation::TestSession>>,
}

struct Workspace {
    release: Arc<Release>,
    runtime: Arc<Runtime>,
}

fn origin(value: &str, require_local: bool) -> Result<String> {
    let value = value.trim_end_matches('/');
    let authority = value.strip_prefix("http://127.0.0.1:").filter(|port| port.parse::<u16>().is_ok());
    if authority.is_some() { return Ok(value.to_owned()); }
    if !require_local && value.strip_prefix("https://").is_some_and(|host| !host.is_empty() &&
        host.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))) {
        return Ok(value.to_owned());
    }
    Err(fail("invalid workspace origin"))
}

fn check_programme_sources(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            check_programme_sources(&path)?;
        } else if !matches!(path.extension().and_then(|suffix| suffix.to_str()), Some("encounter" | "rel")) {
            return Err(fail(format!("Home programme source must be Encounter or REL: {}", path.display())));
        }
    }
    Ok(())
}

impl Release {
    pub fn load(root: &Path, index_path: &Path) -> Result<Self> {
        crate::package::check(root)?;
        let index = fs::read_to_string(index_path)?;
        let style = index.split_once("<style>").and_then(|(_, tail)| tail.split_once("</style>"))
            .map(|(style, _)| style.to_owned()).ok_or_else(|| fail("missing workspace stylesheet"))?;
        let style_hash = Base64::encode_string(&Sha256::digest(&style));
        let policy = format!("default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'sha256-{style_hash}'; img-src data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
        for path in ["version-programme", "browser-programme"] {
            check_programme_sources(&root.join(path))?;
        }
        let application = Application::load(&root.join("version-programme"), DECLARATION)?;
        for html in [&index, &fs::read_to_string(root.join("browser-assets/index.html"))?] {
            if invoke(&application, &json!({"program":"workspace","operation":"admit-home","html":html}))? != true {
                return Err(fail("Home Operations launch contract was not admitted"));
            }
        }
        let corpus = Application::load(&root.join("claimipedia-programme"), CORPUS)?;
        let controller = string(&invoke(&application, &json!({"program":"pairing","operation":"controller","style":style}))?)?.to_owned();
        let identity_assurance = crate::appdev_assurance::identity_report(root)?;
        let browser_wasm = crate::appdev_release::BrowserWasm::load_home(root)?;
        Ok(Self { root: root.to_owned(), application, corpus, index, identity_assurance, style, controller, policy, browser_wasm,
            projection: Mutex::new(None) })
    }

    pub fn compatible(&self, previous: &Self) -> bool {
        self.application.state_profile == previous.application.state_profile
            && self.corpus.state_profile == previous.corpus.state_profile
    }

    pub fn validate(&self) -> Result<()> {
        self.project(Value::Null)?;
        self.corpus.admit(&mut Meter::new(20_000_000))?;
        Ok(())
    }

    pub fn validate_workspace_policy(&self) -> Result<()> {
        let environment = invoke(&self.application, &json!({"program":"workspace","operation":"environment-policy"}))?;
        if environment["destination"] != "/workspace/home" || environment["save"] != false
            || environment["platform"] != false || environment["picker"] != "" {
            return Err(fail("Home environment policy was not admitted"));
        }
        let files = invoke(&self.application, &json!({"program":"workspace","operation":"file-visibility"}))?;
        if files["platform"] != false || files["roots"] != json!([]) {
            return Err(fail("Home file visibility policy was not admitted"));
        }
        Ok(())
    }

    fn project(&self, state: Value) -> Result<Value> {
        let mut projection = self.projection.lock().expect("workspace network projection");
        if let Some((known, value)) = &*projection && *known == state { return Ok(value.clone()); }
        let next = invoke(&self.application, &json!({
            "program":"network", "index":self.index, "state":state, "identityAssurance":self.identity_assurance,
            "browserWasm":self.browser_wasm.is_some()
        }))?;
        let html = string(&next["html"])?;
        if self.browser_wasm.is_some() && !html.contains(crate::appdev_release::WASM_HOME_BRIDGE) {
            return Err(fail("Home programme did not select the catalogued Wasm bridge"));
        }
        *projection = Some((state, next.clone()));
        Ok(next)
    }
}

impl Runtime {
    fn load(release: &Release, port: u16, reload_registry_approval: bool) -> Result<Self> {
        // Use the service-visible StateDirectory path for systemd's private mount.
        let private = PathBuf::from(env::var("STATE_DIRECTORY")?);
        if !private.is_absolute() || !fs::metadata(&private)?.is_dir() {
            return Err(fail("invalid workspace state directory"));
        }
        let authorization = fs::read_to_string(PathBuf::from(env::var("CREDENTIALS_DIRECTORY")?).join("identity-management-auth"))?
            .trim().to_owned();
        if authorization.is_empty() { return Err(fail("missing workspace identity credential")); }
        let certificate_renewal = match env::var("APPDEV_CERTIFICATE_RENEWAL") {
            Ok(value) => {
                let target = origin(&value, true)?;
                let credential = fs::read_to_string(PathBuf::from(env::var("CREDENTIALS_DIRECTORY")?)
                    .join("certificate-renewal-auth"))?;
                let token = credential.trim();
                if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(fail("invalid managed certificate renewal credential"));
                }
                Some((target, format!("Bearer {token}")))
            }
            Err(_) => None,
        };
        let certificate_rollover = if env::var("APPDEV_CERTIFICATE_ROLLOVER").as_deref() == Ok("1") {
            let plan = fs::read_to_string(PathBuf::from(env::var("CREDENTIALS_DIRECTORY")?)
                .join("certificate-rollover-plan"))?;
            if plan.len() > 8192 { return Err(fail("invalid managed certificate rollover plan")); }
            let facts = crate::rel::Facts::parse(&plan)?;
            let deadline = facts.one("rollover", "deadlineMs")?.parse::<i64>()?;
            let mut rows = Vec::new();
            for (id, label) in [("server", "Replacement server issuer"), ("device", "Replacement device issuer"),
                ("listener", "Server certificate"), ("desktop", "Desktop certificate"), ("phone", "Phone certificate")] {
                let fingerprint = facts.one(id, "fingerprint")?;
                if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(fail("invalid managed certificate rollover fingerprint"));
                }
                rows.push(json!({"label":label, "fingerprint":fingerprint, "expires":facts.one(id, "expires")?}));
            }
            Some(json!({"digest":crate::rel::hash(plan), "deadline":deadline,
                "overlapEnds":facts.one("rollover", "overlapEnds")?, "rows":rows}))
        } else { None };
        let mut credentials = read_record(&private.join("x-credentials.json"))?;
        if !credentials.is_null() {
            if invoke(&release.application, &json!({"program":"identity","operation":"validate","credentials":credentials}))?["valid"] != true {
                return Err(fail("invalid saved workspace credentials"));
            }
        } else if let (Ok(client), Ok(secret)) = (env::var("APPDEV_X_CLIENT_ID"), env::var("APPDEV_X_CLIENT_SECRET"))
            && !client.is_empty() && !secret.is_empty() {
            credentials = json!({"clientId":client,"clientSecret":secret});
        }
        let office = read_record(&private.join("notes-office.json"))?;
        if !office.is_null() && invoke(&release.application, &json!({"program":"office","operation":"validate","office":office}))? != true {
            return Err(fail("invalid saved workspace office"));
        }
        let inbox = match read_record(&private.join("x-mentions.json"))? {
            Value::Null => json!({"connection":null,"posts":[]}),
            value if value["posts"].is_array() && value.get("connection").is_some() => value,
            _ => return Err(fail("invalid saved workspace inbox")),
        };
        let public_origin = origin(&env::var("APPDEV_ORIGIN")?, false)?;
        let x_origin = match env::var("APPDEV_X_FIXTURE_ORIGIN") {
            Ok(_) if !public_origin.starts_with("http://127.0.0.1:") => return Err(fail("X fixture requires a loopback workspace")),
            Ok(value) => origin(&value, true)?,
            Err(_) => transport::X_API.to_owned(),
        };
        let identity_gateway = origin(&env::var("APPDEV_IDENTITY_GATEWAY")
            .unwrap_or_else(|_| "http://127.0.0.1:24256".to_owned()), true)?;
        let temple = temple::Temple::load(&public_origin)?;
        Ok(Self { temple, private, authorization, x_origin, identity_gateway,
            public_providers: public_accounts::Providers::load()?,
            origin: public_origin,
            local_origin: format!("http://127.0.0.1:{port}"),
            network: origin(&env::var("APPDEV_NETWORK_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:24361".to_owned()), true)?,
            certificate_inventory: env::var("APPDEV_CERTIFICATE_INVENTORY").ok()
                .map(|value| origin(&value, true)).transpose()?,
            certificate_renewal,
            certificate_reviews: Mutex::new(HashMap::new()),
            certificate_rollover,
            steward: env::var("APPDEV_STEWARD_EMAIL").unwrap_or_default(),
            files: files::FileIndex::load()?,
            network_state: env::var_os("APPDEV_NETWORK_STATE").map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/life-board-network/state/active.json")),
            hosted_port: env::var("APPDEV_LIFE_BOARD_PORT").ok().map(|value| value.parse()).transpose()?.unwrap_or(24252),
            vms: vm_manager::Registry::load()?,
            steward_sessions: Mutex::default(),
            registry_presentation: registry_presentation::Presentations::start(reload_registry_approval)?,
            terminal_only: env::var("APPDEV_TERMINAL_ONLY").as_deref() == Ok("1"),
            resources: Mutex::default(),
            workloads: Mutex::default(),
            terminal: Mutex::new(terminal::Sessions::default()),
            versions: Mutex::new(()), formation: Mutex::new(()), formation_test: Mutex::new(None),
            state: Mutex::new(State { office, credentials, inbox, ..State::default() }) })
    }
}

impl Workspace {
    fn state(&self) -> MutexGuard<'_, State> { self.runtime.state.lock().expect("workspace state") }


    fn run(&self, input: Value) -> Result<Value> { invoke(&self.release.application, &input) }

    fn projected(&self) -> Result<Value> {
        self.release.project(read_record(&self.runtime.network_state)?)
    }

    fn page(&self, status: u16, body: impl Into<String>) -> Response {
        Response::html(status, body, self.release.policy.clone())
    }

    fn render(&self, status: u16, program: &str, content: &str, fragment: bool) -> Result<Response> {
        if fragment { return Ok(self.page(status, content)); }
        let shell = self.projected()?;
        let result = self.run(json!({"program":"workspace","operation":"shell","programName":program,
            "content":content,"fragment":false,"origin":self.runtime.origin,"shell":shell["html"]}))?;
        Ok(self.page(status, string(&result)?))
    }

    fn preview_font(&self, name: &str) -> Result<Response> {
        let Some(stem) = name.strip_suffix(".woff2") else { return Ok(Response::empty(404)); };
        if stem.is_empty() || !stem.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return Ok(Response::empty(404));
        }
        let path = self.release.root.join("browser-assets/fonts").join(name);
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Response::empty(404)),
            Err(error) => return Err(error.into()),
        };
        Ok(Response::stream(200, "font/woff2", file.metadata()?.len(), file)
            .with("Cache-Control", "public, max-age=3600"))
    }

    fn mobile_script(&self) -> Result<String> {
        let module = self.release.browser_wasm.as_ref().and_then(|wasm| wasm.mobile.as_deref());
        crate::process::browser_wasm::mobile_script(module)
    }

    fn wasm_script_response(&self, script: &str) -> Response {
        let response = Response::script(script);
        if let Some(wasm) = self.release.browser_wasm.as_ref().filter(|wasm| wasm.mobile.is_some()) {
            return response.with("X-Encounter-Browser-Wasm", &wasm.catalog_pin);
        }
        response
    }

    fn route(&self, request: &Request) -> Result<Response> {
        let (path, raw_query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        if !path.starts_with('/') || path.starts_with("//") || path.contains(['\\', '#']) ||
            request.path.bytes().any(|byte| byte.is_ascii_control()) {
            return Ok(Response::empty(400));
        }
        if !self.runtime.terminal_only && matches!(request.method.as_str(), "GET" | "HEAD")
            && let Some(name) = path.strip_prefix("/workspace/fonts/") {
            return self.preview_font(name);
        }
        let query = Fields::parse(raw_query.as_bytes());
        if !self.runtime.terminal_only && request.method == "GET" {
            match path {
                "/workspace/aster/frame-bridge.js" => {
                    if let Some(wasm) = &self.release.browser_wasm
                        && let Some(module) = wasm.aster_frame.as_deref() {
                        let script = crate::process::browser_wasm::aster_frame_script(module);
                        return Ok(Response::script(&script).with("X-Encounter-Browser-Wasm", &wasm.catalog_pin));
                    }
                    return Ok(Response::empty(404));
                }
                "/workspace/aster/home-startup.mjs" => {
                    let script = if self.release.browser_wasm.is_some() {
                        include_str!("aster_home_startup.mjs")
                    } else {
                        include_str!("aster_home_startup_legacy.mjs")
                    };
                    return Ok(Response::script(script));
                }
                "/workspace/temple/startup" => return self.temple_startup(),
                "/workspace/temple/startup.mjs" => {
                    let module = self.release.browser_wasm.as_ref().and_then(|wasm| wasm.temple.as_deref());
                    return Ok(self.wasm_script_response(&crate::process::browser_wasm::temple_script(module, &temple::browser_presentation()?)?));
                }
                "/workspace/temple/assurance-updates.mjs" => {
                    let module = self.release.browser_wasm.as_ref().and_then(|wasm| wasm.temple_assurance.as_deref());
                    return Ok(self.wasm_script_response(&crate::process::browser_wasm::temple_assurance_script(module)));
                }
                "/workspace/temple/startup.css" => return temple::startup_styles(),
                _ => {}
            }
        }
        let route = self.run(json!({"program":"workspace","operation":"route","path":path,
            "method":request.method,"view":query.get("view"),"fragment":query.get("fragment")==Some("1"),
            "environmentRouting":true,"item":query.get("item"),"queryCount":query.len(),
            "hasSetup":query.get("setup").is_some(),"hasSignIn":query.get("sign-in").is_some(),
            "sameOrigin":header(request,"origin")==self.runtime.origin}))?;
        let (now, _) = timestamp();
        let name = string(&route["route"])?;
        if name.starts_with("terminal-") {
            return self.terminal_route(name, request, &query, raw_query);
        }
        if self.runtime.terminal_only {
            return Ok(Response::empty(if name == "origin" { 403 } else { 404 }));
        }
        match name {
            "index" => Ok(Response::html(
                200,
                string(&self.projected()?["html"])?,
                format!("{}; frame-src {}/workspace/vm-manager http://localhost:24220/decompiler", self.release.policy, self.runtime.origin),
            )),
            "workspace-default" => self.default_workspace(request, &route, raw_query),
            "home" | "platform" => self.environment_page(request, &route, raw_query),
            "server-resources" => self.server_resources(request),
            "server-workloads" => self.server_workloads(request, &query),
            "workspace-access" => self.workspace_access(request),
            "formation-records" => self.formation_records(request),
            "formation-test-session" => self.formation_test_session(request, now),
            "file-index" => self.file_index(request, raw_query),
            "vm-manager-page" => self.vm_manager_page(request, &query),
            "vm-manager-steward" => self.registry_steward_action(request, &query),
            "vm-manager-style" => self.vm_manager_style(),
            "vm-manager-script" => Ok(Response::script(crate::process::browser_wasm::guest_console_script()?)),
            "vm-manager-xterm" => Ok(Response::script(include_str!("../../browser/vendor/xterm/lib/xterm.js"))),
            "vm-manager-xterm-css" => Ok(Response::css(include_str!("../../browser/vendor/xterm/css/xterm.css"))),
            "vm-manager-xterm-fit" => Ok(Response::script(include_str!("../../browser/vendor/xterm/lib/addon-fit.js"))),
            "file-media" => self.file_media(request, raw_query),
            "workspace-preference" => self.save_workspace_preference(request),
            "mobile-legacy" => Ok(environments::redirect("/workspace/mobile", raw_query)),
            "controller" => Ok(self.page(200, &self.release.controller)),
            "mobile" | "mobile-phone" => {
                let phone = route["route"] == "mobile-phone";
                let html = self.run(json!({"program":"mobile","style":self.release.style,"phone":phone}))?;
                let policy = if phone {
                    self.release.policy.replace("default-src 'none';", "default-src 'none'; worker-src 'self';")
                } else {
                    self.release.policy.clone()
                };
                let html = string(&html)?;
                let html = if phone { html.to_owned() } else {
                    environments::environment_markup(html, self.platform_allowed(self.workspace_identity(request)?.as_ref())?, "", true)?
                };
                Ok(Response::html(200, html, if phone { policy } else { self.workspace_frame_policy(policy, request) }))
            }
            "mobile-runtime" => Ok(self.wasm_script_response(&self.mobile_script()?)),
            "mobile-worker" => {
                let html = self.run(json!({"program":"mobile","style":self.release.style,"phone":true}))?;
                let module = self.release.browser_wasm.as_ref().and_then(|wasm| wasm.mobile.as_deref());
                let worker = crate::process::browser_wasm::mobile_worker_script(module);
                let version = crate::rel::hash(format!("{}{}{}", string(&html)?, self.mobile_script()?, worker));
                let script = format!("\"use strict\";\nconst mobileVersion = '{version}';\n{worker}");
                Ok(self.wasm_script_response(&script))
            }
            "download" => Response::download(&self.release.root.join(INSTALLER), INSTALLER),
            "webhook" => self.webhook(request, &query),
            "management" => self.management(request, &query, &route),
            "origin" => Ok(Response::empty(403)),
            "session" => {
                let temple_identity = self.workspace_identity(request)?.map(|identity| identity.email);
                let state = self.state();
                let user = state.sessions.get(cookie_value(request, SESSION_COOKIE))
                    .filter(|(_, expires)| *expires > now).map(|(user, _)| user);
                let username = if let Some(Account::X(name)) = user { Some(name) } else { None };
                let public_identity = if let Some(Account::Public(name)) = user { Some(name) } else { None };
                Ok(Response::json(200, &json!({
                    "username":username, "xAvailable":!state.credentials.is_null(), "templeIdentity":temple_identity,
                    "publicIdentity":public_identity, "gmailAvailable":self.runtime.public_providers.gmail.is_some(),
                    "microsoftAvailable":self.runtime.public_providers.microsoft.is_some(),
                })))
            }
            "sign-out" => self.workspace_sign_out(request),
            "authorize" => self.authorize(request, &query, now),
            "callback" => self.callback(request, &query, now),
            "authorize-public" => self.authorize_public(request, public_accounts::Provider::parse(string(&route["provider"])?)?, now),
            "callback-public" => self.callback_public(request, &query, public_accounts::Provider::parse(string(&route["provider"])?)?, now),
            "pair" => self.start_room(now, route["mobile"] == true),
            "room" => self.room(request, &query, &route, now),
            _ => Ok(Response::empty(404)),
        }
    }

    fn start_room(&self, now: i64, mobile: bool) -> Result<Response> {
        let id = token::<12>()?;
        let surface = token::<32>()?;
        let invite = token::<32>()?;
        let mut state = self.state();
        state.rooms.retain(|_, room| room["expires"].as_i64().is_some_and(|time| time > now));
        if state.rooms.len() >= ROOM_LIMIT { return Ok(Response::text(503, "Pairing is busy. Try again shortly.")); }
        let path = if mobile { "/workspace/mobile/phone" } else { "/workspace/controller" };
        let qr = transport::qr(&format!("{}{path}#{id}.{invite}", self.runtime.origin))?;
        state.rooms.insert(id.clone(), json!({"surface":surface,"invite":invite,"status":"waiting","revision":0,
            "commands":[],"mobile":mobile,"trip":null,"expires":now+180_000}));
        let mut response = json!({"id":id,"surface":surface,"qr":qr});
        if mobile { response["link"] = json!(format!("{}{path}#{id}.{invite}", self.runtime.origin)); }
        Ok(Response::json(201, &response))
    }

    fn room(&self, request: &Request, query: &Fields, route: &Value, now: i64) -> Result<Response> {
        let id = string(&route["id"])?;
        let bearer = header(request, "authorization").strip_prefix("Bearer ").unwrap_or_default();
        if bearer.len() != 43 || !bearer.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)) {
            return Ok(Response::empty(404));
        }
        let mut state = self.state();
        let Some(room) = state.rooms.get(id).filter(|room| room["expires"].as_i64().is_some_and(|time| time > now))
            else { return Ok(Response::empty(404)); };
        let (phone, code) = if request.method == "POST" && route["action"] == "claim" {
            (Some(token::<32>()?), Some(transport::pairing_code()?))
        } else { (None, None) };
        let after = query.get("after").unwrap_or("0").parse::<u64>().ok().filter(|value| *value <= 9_007_199_254_740_991);
        let fields = Fields::parse(&request.body);
        let challenge = if request.method == "POST" && route["action"] == "offer" { Some(token::<32>()?) } else { None };
        let result = self.run(json!({"program":"pairing","room":room,
            "mobile":route["mobile"] == true, "challenge":challenge,
            "fields":{"note":fields.get("note"),"project":fields.get("project"),"pilot":fields.get("pilot"),"digest":fields.get("digest"),"challenge":fields.get("challenge")},"bearer":bearer,"now":now,
            "method":request.method,"action":route["action"],"after":after,"phone":phone,"code":code}))?;
        if result["remove"] == true { state.rooms.remove(id); }
        if !result["room"].is_null() { state.rooms.insert(id.to_owned(), result["room"].clone()); }
        let status = response_status(&result)?;
        if result["body"].is_null() { Ok(Response::empty(status)) }
        else { Ok(Response::json(status, &result["body"])) }
    }
}

fn invoke(application: &Application, input: &Value) -> Result<Value> {
    Ok(serde_json::from_str(&invoke_text(application, input)?)?)
}

fn invoke_text(application: &Application, input: &Value) -> Result<String> {
    let mut meter = Meter::new(20_000_000);
    let mut programme = application.admit(&mut meter)?;
    application.bind_data(&mut programme);
    let result = programme.run("cli.main", json!([input.to_string()]), &mut meter)?;
    Ok(string(&result)?.to_owned())
}

fn response_status(value: &Value) -> Result<u16> {
    value["status"].as_u64().filter(|status| (100..600).contains(status)).map(|status| status as u16)
        .ok_or_else(|| fail("expected workspace response status"))
}

fn cookie(name: &str, value: &str, lifetime: u32) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={lifetime}")
}

fn cookie_value<'a>(request: &'a Request, name: &str) -> &'a str {
    header(request, "cookie").split(';').map(str::trim_start).filter_map(|field| field.split_once('='))
        .find(|(key, _)| *key == name).map(|(_, value)| value).unwrap_or_default()
}

pub fn serve(path: &Path, follow: bool) -> Result<()> {
    serve_mode(path, follow, Listener::Workspace)
}

pub(crate) fn verify_registry_presentation(root: &Path) -> Result<()> {
    registry_presentation::verify(root)
}

pub fn serve_vm_manager(path: &Path) -> Result<()> {
    serve_mode(path, false, Listener::VmManager)
}

pub fn serve_file_index(path: &Path) -> Result<()> {
    serve_mode(path, true, Listener::Files)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Listener { Workspace, VmManager, Files }

fn serve_mode(path: &Path, follow: bool, listener: Listener) -> Result<()> {
    let port = env::var("APPDEV_PORT").ok().map(|value| value.parse()).transpose()?.unwrap_or(24249);
    if port == 0 { return Err(fail("expected a workspace listen port")); }
    let releases = follow.then(|| crate::appdev_release::Releases::open(path, true)).transpose()?;
    let release = if let Some(releases) = &releases {
        Arc::clone(&releases.current().workspace)
    } else {
        let root = path.canonicalize()?;
        let index_path = env::var_os("APPDEV_INDEX").map(PathBuf::from).unwrap_or_else(|| root.join("index.html"));
        let release = Release::load(&root, &index_path)?;
        if let Some(wasm) = &release.browser_wasm { wasm.require_bundled_runtime()?; }
        release.validate_workspace_policy()?;
        Arc::new(release)
    };
    let runtime = Arc::new(Runtime::load(&release, port, listener == Listener::VmManager)?);
    if !runtime.terminal_only && listener == Listener::Workspace {
        release.project(read_record(&runtime.network_state)?)?;
    }
    let fixed_release = releases.is_none().then_some(release);
    http::serve_workers(port, 24, 128 * 1024, move |stream, request| {
        let release = if let Some(releases) = &releases {
            Arc::clone(&releases.current().workspace)
        } else {
            Arc::clone(fixed_release.as_ref().expect("fixed workspace release"))
        };
        let workspace = Workspace { release, runtime: Arc::clone(&runtime) };
        let path = request.path.split_once('?').map_or(request.path.as_str(), |(path, _)| path);
        if listener == Listener::VmManager && !matches!(path,
            "/workspace/vm-manager" | "/workspace/vm-manager/console" |
            "/workspace/vm-manager/style.css" | "/workspace/vm-manager/console.mjs" |
            "/workspace/vm-manager/xterm.js" | "/workspace/vm-manager/xterm.css" | "/workspace/vm-manager/xterm-fit.js")
        {
            let _ = Response::empty(404).send(stream, request.method == "HEAD");
            return;
        }
        if listener == Listener::Files && !matches!(path, "/workspace/files" | "/workspace/file-media") {
            let _ = Response::empty(404).send(stream, request.method == "HEAD");
            return;
        }
        if !runtime.terminal_only && request.path.starts_with("/workspace/vm-manager/console?") {
            let _ = workspace.vm_console(stream, &request);
            return;
        }
        if !runtime.terminal_only && request.path == "/workspace/temple/connection" {
            let _ = workspace.temple_connection(stream, request);
            return;
        }
        let response = match workspace.route(&request) {
            Ok(response) => response,
            Err(_) => {
                eprintln!("AppDev workspace request failed");
                Response::text(500, "AppDev could not complete the request.")
            }
        };
        let _ = response.send(stream, request.method == "HEAD");
    })
}
