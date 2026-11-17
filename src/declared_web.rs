// Shared HTTP adapter for the declared app.newSession/app.request/ui.styles ABI.
use crate::{Result, application::Application, attachment::Mount, browser_release::LiveClientPins, fail, http, image::{self, LoadedImage}, launch::Launch, live::{Live, Model, Subscriber}, websocket, operator::Operators, process::{Meter, Programme}, store::Store, nonce::nonce};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::{BTreeMap, BTreeSet}, path::Path, time::{SystemTime, UNIX_EPOCH}};

struct Session {
    csrf: String,
    state: Value,
    operator: Value,
}

pub fn serve(root: &Path, declaration: &str, directory: &Path, port: u16) -> Result<()> {
    crate::package::check(root)?;
    let app = Application::load(root, declaration)?;
    let mut meter = Meter::new(20_000_000);
    let programme = app.admit_browser(&mut meter)?;
    serve_programme(app, programme, meter, directory, port, None, None, Model::Off, false, LiveClientPins::default())
}

pub fn serve_launch(launch: Launch) -> Result<()> {
    let image = image::load(&launch.image, &launch.pin)?;
    serve_bound_image(image, &launch.store, launch.port, launch.attachment_root.as_deref(), launch.operators.as_deref(),
        launch.live_model, launch.gateway_identity, None, launch.clients)
}

pub fn serve_image(image: LoadedImage, directory: &Path, port: u16, attachment_root: Option<&Path>, operators: Option<&Path>, live_model: Model, gateway_identity: bool) -> Result<()> {
    serve_bound_image(image, directory, port, attachment_root, operators, live_model, gateway_identity, None, LiveClientPins::default())
}

pub(crate) fn serve_shop_image(image: LoadedImage, directory: &Path, port: u16, operators: &Path, principals: &[&str]) -> Result<()> {
    if image.app.state_profile != "encounter/sourcery-shop/1" {
        return Err(fail("Expected a Sourcery Shop image"));
    }
    serve_bound_image(image, directory, port, None, Some(operators), Model::Off, true, Some(principals), LiveClientPins::default())
}

fn serve_bound_image(mut image: LoadedImage, directory: &Path, port: u16, attachment_root: Option<&Path>, operators: Option<&Path>, live_model: Model, gateway_identity: bool, shop_principals: Option<&[&str]>, clients: LiveClientPins) -> Result<()> {
    image.app.bind_browser(&mut image.programme)?;
    if let Some(principals) = shop_principals {
        image.programme.bind_dataset("shop-access".to_owned(), json!(principals));
    }
    let mount = if let Some(root) = attachment_root {
        if !image.app.has_entry("app.attachment") && !image.app.has_entry("app.reviewMedia") {
            return Err(fail("an attachment mount requires the declared app.attachment entry"));
        }
        if image.app.has_entry("app.attachment") {
            image.programme.require_grants("app.attachment", &BTreeSet::from(["application.data", "kernel.invoke"]))?;
        }
        Some(Mount::open(root)?)
    } else { None };
    serve_programme(image.app, image.programme, image.meter, directory, port, mount, operators.map(Operators::read).transpose()?, live_model, gateway_identity, clients)
}

fn serve_programme(app: Application, mut programme: Programme, meter: Meter,
    directory: &Path, port: u16, mount: Option<Mount>, operators: Option<Operators>, live_model: Model, gateway_identity: bool,
    clients: LiveClientPins) -> Result<()>
{
    let live_enabled = !matches!(live_model, Model::Off);
    if live_enabled && (operators.is_none() || ["app.events", "app.agentNext", "app.agentResult"]
        .iter().any(|name| !app.has_entry(name))) {
        return Err(fail("a live model requires operators and the declared live application entries"));
    }
    if matches!(live_model, Model::Codex(_)) && !app.has_entry("app.agentProgress") {
        return Err(fail("Codex requires app.agentProgress"));
    }
    let canvas_enabled = live_enabled && app.has_entry("app.canvas");
    if (clients.events.is_some() && !live_enabled) || (clients.canvas.is_some() && !canvas_enabled) {
        return Err(fail("browser Wasm pin requires its live application capability"));
    }
    if canvas_enabled && clients.events.is_some() != clients.canvas.is_some() {
        return Err(fail("a pinned Canvas application requires both Live Events and Canvas Wasm"));
    }
    let events_script = live_enabled.then(|| crate::process::browser_wasm::live_events_script(clients.events.as_ref())).transpose()?;
    let canvas_script = canvas_enabled.then(|| crate::process::browser_wasm::canvas_script(clients.canvas.as_ref())).transpose()?;
    let styles = programme.run(app.browser_styles_entry(), Value::Null, &mut meter.clone())?;
    let styles = styles.as_str().ok_or_else(|| fail("expected stylesheet text"))?;
    programme.bind_attachment(mount.clone());
    if let Some(operators) = &operators {
        programme.bind_reflection_operators(operators.roles());
    }
    programme.bind_store(Store::open(directory, &app.state_profile, &app.basis)?);
    let review_media = mount.is_some() && operators.is_some() && app.has_entry("app.reviewMedia");
    let sessions = RefCell::new(BTreeMap::<String, Session>::new());

    let live = RefCell::new(Live::new(live_model, app.has_entry("app.agentCancel"))?);
    http::serve(port, || {
        if live_enabled && let Err(error) = live.borrow_mut().tick(&programme, &meter, &app.basis, &app.state_profile) {
            eprintln!("live delivery: {error}");
        }
    }, |origin, stream, request| {
        let header = |name| request.headers.get(name).map(String::as_str);
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        let cookie_name = format!("encounter_{}", origin.rsplit(':').next().unwrap_or_default());
        let id = header("cookie").and_then(|cookies| {
            cookies.split(';').filter_map(|cookie| cookie.trim().split_once('='))
                .find_map(|(key, value)| (key == cookie_name).then_some(value))
        });
        if path == "/encounter-events.js" && request.method == "GET" && let Some(script) = &events_script {
            if let Some(pin) = &clients.events {
                return http::send_headers(stream, "200 OK", "text/javascript",
                    &format!("X-Encounter-Browser-Wasm: {}\r\n", pin.receipt), script);
            }
            return http::send(stream, "200 OK", "text/javascript", script);
        }
        if path == "/encounter-canvas.js" && request.method == "GET" && let Some(script) = &canvas_script {
            if let Some(pin) = &clients.canvas {
                return http::send_headers(stream, "200 OK", "text/javascript",
                    &format!("X-Encounter-Browser-Wasm: {}\r\n", pin.receipt), script);
            }
            return http::send(stream, "200 OK", "text/javascript", script);
        }
        if live_enabled && path == "/encounter-events" {
            let mut hub = live.borrow_mut();
            hub.subscribers.retain(|subscriber| subscriber.peer.active());
            let sessions = sessions.borrow();
            let Some(session) = id.and_then(|id| sessions.get(id)) else {
                return http::send(stream, "403 Forbidden", "text/plain", "Open an authenticated task first.");
            };
            if header("origin") != Some(origin) || hub.subscribers.len() >= 16 {
                return http::send(stream, "403 Forbidden", "text/plain", "Subscription refused.");
            }
            let Ok(mut fields) = http::form(query.as_bytes()) else {
                return http::send(stream, "400 Bad Request", "text/plain", "Invalid subscription.");
            };
            let Some(after) = fields.remove("after").and_then(|value| value.parse::<u64>().ok()) else {
                return http::send(stream, "400 Bad Request", "text/plain", "Invalid event cursor.");
            };
            let fields = json!(fields);
            let events = Live::events(&programme, &meter, &programme.snapshot()?, &session.operator, &fields, after)?;
            if !events.is_array() {
                return http::send(stream, "403 Forbidden", "text/plain", "Subscription refused.");
            }
            let Ok(peer) = websocket::upgrade(stream, &request) else {
                return http::send(stream, "400 Bad Request", "text/plain", "Invalid WebSocket upgrade.");
            };
            let mut subscriber = Subscriber { operator: session.operator.clone(), fields, after, peer };
            if Live::publish(&mut subscriber, &events).is_ok() { hub.subscribers.push(subscriber); }
            return Ok(());
        }
        if live_enabled && path == "/events" && request.method == "GET" && app.has_entry("app.stream") {
            let mut hub = live.borrow_mut();
            hub.subscribers.retain(|subscriber| subscriber.peer.active());
            let Some(bearer) = header("authorization").and_then(|value| value.strip_prefix("Bearer "))
                .filter(|value| value.len() <= 128) else {
                return http::send(stream, "403 Forbidden", "text/plain", "Stream access refused.");
            };
            let Ok(fields) = http::form(query.as_bytes()) else {
                return http::send(stream, "400 Bad Request", "text/plain", "Invalid subscription.");
            };
            let snapshot = programme.snapshot()?;
            let granted = programme.run("app.stream", json!({"snapshot":snapshot,"bearer":bearer,"fields":fields,"now":u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?}), &mut meter.clone())?;
            if !granted.is_object() || hub.subscribers.len() >= 16 {
                return http::send(stream, "403 Forbidden", "text/plain", "Stream access refused.");
            }
            let events = Live::events(&programme, &meter, &snapshot, &granted["operator"], &granted["fields"], 0)?;
            if !events.is_array() {
                return http::send(stream, "403 Forbidden", "text/plain", "Stream access refused.");
            }
            let peer = websocket::event_stream(stream)?;
            let mut subscriber = Subscriber { operator: granted["operator"].clone(), fields: granted["fields"].clone(), after: 0, peer };
            if Live::publish(&mut subscriber, &events).is_ok() { hub.subscribers.push(subscriber); }
            return Ok(());
        }
        let mut operator = Value::Null;
        if let Some(operators) = &operators {
            let Some(identity) = operators.verify(header("authorization")) else {
                return http::send_headers(stream, "401 Unauthorized", "text/plain",
                    "WWW-Authenticate: Basic realm=\"Encounter\", charset=\"UTF-8\"\r\n", "Operator credentials required.");
            };
            operator = identity;
            if gateway_identity {
                let safe = |name| header(name).filter(|value| !value.is_empty() && value.len() <= 320
                    && value.bytes().all(|byte| byte.is_ascii_graphic()));
                let (Some(id), Some(email), Some(session)) = (safe("x-temple-principal"), safe("x-temple-email"), safe("x-temple-actor-session")) else {
                    return http::send(stream, "403 Forbidden", "text/plain", "Temple sign-in required.");
                };
                operator["id"] = json!(id);
                operator["email"] = json!(email.to_ascii_lowercase());
                operator["session"] = json!(session);
            }
        }
        if request.method == "POST" && operator["role"] == "observer" {
            return http::send(stream, "403 Forbidden", "text/plain", "Observer sessions are read-only.");
        }
        if request.method == "GET" && path == "/styles.css" {
            return http::send(stream, "200 OK", "text/css", styles);
        }
        if review_media && let Some(id) = path.strip_prefix("/review-media/") {
            if request.method != "GET" {
                return http::send(stream, "405 Method Not Allowed", "text/plain", "Expected GET.");
            }
            let descriptor = programme.run("app.reviewMedia", json!(id), &mut meter.clone())?;
            if let Some(media_type @ ("video/mp4" | "audio/mp4" | "text/vtt")) = descriptor["mediaType"].as_str()
                && let Some(root) = &mount
                && let Ok(file) = root.read(&descriptor)
            {
                return file.send_review(stream, media_type, header("range"));
            }
            return http::send(stream, "404 Not Found", "text/plain", "Review media unavailable.");
        }
        if let Some(id) = path.strip_prefix("/attachments/") {
            if request.method != "GET" {
                return http::send(stream, "405 Method Not Allowed", "text/plain", "Expected GET.");
            }
            if let Some(mount) = &mount
                && app.has_entry("app.attachment")
                && !id.is_empty() && id.len() <= 128
                && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            {
                let descriptor = programme.run("app.attachment", json!(id), &mut meter.clone())?;
                if let Ok(file) = mount.read(&descriptor) {
                    let headers = format!("Content-Disposition: {}\r\n", file.disposition);
                    return http::send_bytes(stream, "200 OK", "application/octet-stream", &headers, &file.body);
                }
            }
            return http::send(stream, "404 Not Found", "text/plain", "Attachment unavailable.");
        }
        let parsed = match request.method.as_str() {
            "GET" => http::form(query.as_bytes()).map(|fields| (fields, None)),
            "POST" => {
                if header("origin") != Some(origin) {
                    return http::send(stream, "403 Forbidden", "text/plain", "Wrong origin.");
                }
                match header("content-type") {
                    Some("application/x-www-form-urlencoded") => http::form(&request.body).map(|fields| (fields, None)),
                    Some(kind) if kind.starts_with("multipart/form-data; boundary=") => http::multipart(kind, &request.body),
                    _ => return http::send(stream, "415 Unsupported Media Type", "text/plain", "Expected a form."),
                }
            }
            _ => return http::send(stream, "405 Method Not Allowed", "text/plain", "Expected GET or POST."),
        };
        let Ok((mut fields, upload)) = parsed else {
            return http::send(stream, "400 Bad Request", "text/plain", "Invalid form.");
        };
        let mut sessions = sessions.borrow_mut();
        let mut response_headers = String::new();
        let mut meter = meter.clone();
        let session = match id.and_then(|id| sessions.get_mut(id)).filter(|session| session.operator == operator) {
            Some(session) => session,
            None => {
                if request.method == "POST" {
                    return http::send(stream, "403 Forbidden", "text/plain", "Open the workspace first.");
                }
                if sessions.len() >= 1024 {
                    return http::send(stream, "503 Service Unavailable", "text/plain", "Session capacity reached.");
                }
                let id = nonce()?;
                let csrf = nonce()?;
                let state = programme.run("app.newSession", Value::Null, &mut meter)?;
                response_headers = format!("Set-Cookie: {cookie_name}={id}; HttpOnly; SameSite=Strict; Path=/\r\n");
                sessions.entry(id).or_insert(Session { csrf, state, operator: operator.clone() })
            }
        };
        if request.method == "POST" && fields.remove("_csrf").as_deref() != Some(&session.csrf) {
            return http::send(stream, "403 Forbidden", "text/plain", "Wrong session.");
        }
        let mut input = json!({
            "method":request.method,"path":path,"fields":fields,"session":session.state,
            "snapshot":programme.snapshot()?,"csrf":session.csrf,"nonce":nonce()?,
            "basis":app.basis,"profile":app.state_profile
        });
        if gateway_identity { input["query"] = json!(http::form(query.as_bytes())?); }
        if live_enabled { input["liveModel"] = json!(true); }
        if review_media { input["reviewMedia"] = json!(true); }
        if let Some(upload) = upload {
            input["upload"] = json!({"field":upload.field,"filename":upload.filename,"text":upload.text});
        }
        if app.has_entry("app.attachment") {
            input["attachments"] = json!(mount.is_some());
        }
        if operators.is_some() {
            input["operator"] = operator;
            input["now"] = json!(u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?);
        }
        let result = programme.run("app.request", input, &mut meter)?;
        let (content_type, body) = match (result.get("html"), result.get("text")) {
            (Some(html), None) => ("text/html", html.as_str()),
            (None, Some(text)) => ("text/plain", text.as_str()),
            _ => return Err(fail("expected exactly one application response body")),
        };
        let body = body.ok_or_else(|| fail("expected a text response body"))?;
        session.state = result["session"].clone();
        if live_enabled && content_type == "text/html" && !gateway_identity {
            http::send_live_html(stream, &response_headers, body, origin, review_media)
        } else {
            let status = if gateway_identity { match result["status"].as_u64() {
                Some(400) => "400 Bad Request", Some(403) => "403 Forbidden", Some(404) => "404 Not Found",
                _ => "200 OK",
            }} else { "200 OK" };
            http::send_headers(stream, status, content_type, &response_headers, body)
        }
    })
}
