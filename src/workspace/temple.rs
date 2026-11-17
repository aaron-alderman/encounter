use super::{Response, Workspace, header, origin};
use crate::{Result, fail, http::Request, process::{CSS_RENDERER, HTML_PORTS, HTML_RENDERER, Meter, Programme}, websocket};
use serde_json::{Value, json};
use std::{collections::BTreeSet, env, net::TcpStream, sync::{Arc, OnceLock, atomic::{AtomicUsize, Ordering}}, thread, time::Duration};

const LIMIT: usize = 128;
const DEMO_ORIGIN: &str = "https://appdev.sourcerytech.com.au";

fn render_styles(entry: &str) -> Result<String> {
    let mut meter = Meter::new(100_000);
    let programme = Programme::admit_entries(
        &[include_str!("temple_startup.encounter").to_owned(), CSS_RENDERER.to_owned()],
        &[entry],
        &BTreeSet::new(),
        &mut meter,
    )?;
    let result = programme.run(entry, Value::Null, &mut meter)?;
    result.as_str().map(str::to_owned).ok_or_else(|| fail("expected Temple stylesheet"))
}

pub(super) fn startup_styles() -> Result<Response> {
    static CSS: OnceLock<String> = OnceLock::new();
    if let Some(css) = CSS.get() {
        return Ok(Response::css(css));
    }
    let css = render_styles("temple.startupStyles")?;
    Ok(Response::css(CSS.get_or_init(|| css)))
}

pub(super) fn browser_presentation() -> Result<Value> {
    let mut meter = Meter::new(100_000);
    let sources = HTML_RENDERER.into_iter().chain([
        CSS_RENDERER, include_str!("temple_startup.encounter"),
    ]).map(str::to_owned).collect::<Vec<_>>();
    let entry = "temple.browserPresentation";
    let programme = Programme::admit_entries(&sources, &[entry], &BTreeSet::from(HTML_PORTS), &mut meter)?;
    programme.run(entry, Value::Null, &mut meter)
}

pub(super) struct Temple {
    pub(super) id: String,
    pub(super) client: Option<String>,
    connections: Arc<AtomicUsize>,
}

impl Temple {
    pub(super) fn load(workspace_origin: &str) -> Result<Option<Self>> {
        let id = env::var("APPDEV_TEMPLE_ID").ok().or_else(|| {
            (workspace_origin == DEMO_ORIGIN).then(|| "sourcerytech-demo".to_owned())
        });
        let Some(id) = id else { return Ok(None); };
        if id.is_empty() || id.len() > 80 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)) {
            return Err(fail("invalid APPDEV_TEMPLE_ID"));
        }
        let client = env::var("APPDEV_TEMPLE_CLIENT_ORIGIN").ok().map(|value| origin(&value, false)).transpose()?;
        Ok(Some(Self { id, client, connections: Arc::new(AtomicUsize::new(0)) }))
    }
}

struct Connection(Arc<AtomicUsize>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Workspace {
    pub(super) fn temple_startup(&self) -> Result<Response> {
        let html = self.run(json!({"program":"workspace","operation":"temple-startup"}))?;
        Ok(Response::html(200, super::string(&html)?,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' wss: ws://127.0.0.1:*; frame-src 'self' https: http://127.0.0.1:*; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".to_owned()))
    }

    pub(super) fn temple_connection(self, stream: &mut TcpStream, request: Request) -> Result<()> {
        let Some(temple) = &self.runtime.temple else {
            return Response::empty(404).send(stream, false);
        };
        let caller = header(&request, "origin");
        if request.method != "GET" || (caller != self.runtime.origin && Some(caller) != temple.client.as_deref()) {
            return Response::empty(403).send(stream, false);
        }
        if !header(&request, "upgrade").eq_ignore_ascii_case("websocket") {
            return Response::empty(400).send(stream, false);
        }
        if temple.connections.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |count| (count < LIMIT).then_some(count + 1)).is_err() {
            return Response::empty(503).send(stream, false);
        }
        let slot = Connection(Arc::clone(&temple.connections));
        let identity = self.workspace_identity(&request)?;
        let steward = self.platform_allowed(identity.as_ref())?;
        let mut workspaces = vec!["home", "work", "mobile"];
        if steward { workspaces.insert(2, "platform"); }
        let default = self.workspace_default(identity.as_ref())?;
        let hello = json!({"protocol":"sourcery/temple-connection/1","temple":temple.id,"workspaces":workspaces,
            "workspaceSubscriptions":1,"defaultWorkspace":default.trim_start_matches("/workspace/")}).to_string();
        let mut socket = stream.try_clone()?;
        websocket::handshake(stream, &request)?;
        socket.set_read_timeout(Some(Duration::from_secs(90)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        thread::Builder::new().name("temple-connection".to_owned()).spawn(move || {
            let _slot = slot;
            if websocket::frame(&mut socket, 1, hello.as_bytes()).is_err() { return; }
            while let Ok(Some(text)) = websocket::read_browser_text(&mut socket, 256) {
                let Ok(message) = serde_json::from_str::<Value>(&text) else { return; };
                let (Some(id), Some(workspace)) = (message["id"].as_u64(), message["workspace"].as_str()) else { return; };
                if message["type"] != "workspace.subscribe" || id == 0 || id > u32::MAX.into() { return; }
                let view = match &message["view"] {
                    Value::Null => None,
                    Value::String(view) => Some(view.as_str()),
                    _ => return,
                };
                let data = self.workspace_bootstrap(&request, workspace, view);
                let response = match data {
                    Ok(Some(data)) => json!({"type":"workspace.ready","id":id,"workspace":workspace,"data":data}),
                    _ => json!({"type":"workspace.unavailable","id":id,"workspace":workspace}),
                };
                if websocket::frame(&mut socket, 1, response.to_string().as_bytes()).is_err() { return; }
            }
        })?;
        Ok(())
    }

    fn workspace_bootstrap(&self, request: &Request, workspace: &str, view: Option<&str>) -> Result<Option<Value>> {
        let entry = match (workspace, view) {
            ("home", None) => "/workspace/home",
            ("work", None) => "/workspace/work",
            ("mobile", None) => "/workspace/mobile",
            ("platform", None | Some("platform-inbox" | "work-items")) => {
                if !self.platform_allowed(self.workspace_identity(request)?.as_ref())? {
                    return Ok(None);
                }
                if view.is_none() {
                    let apps = self.run(json!({"program":"workspace","operation":"platform-apps"}))?;
                    return Ok(Some(json!({"kind":"platform-launcher","apps":apps})));
                }
                "/workspace/platform"
            }
            _ => return Ok(None),
        };
        Ok(Some(json!({"kind":"frame","entry":entry})))
    }

    pub(super) fn workspace_frame_policy(&self, policy: String, request: &Request) -> String {
        if header(request, "sec-fetch-dest") != "iframe" || self.runtime.temple.is_none() {
            return policy;
        }
        let clients = self.runtime.temple.as_ref().and_then(|temple| temple.client.as_ref())
            .map_or_else(|| "'self'".to_owned(), |client| format!("'self' {client}"));
        policy.replace("frame-ancestors 'none'", &format!("frame-ancestors {clients}"))
    }
}
