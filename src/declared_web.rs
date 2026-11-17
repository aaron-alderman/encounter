// Shared HTTP adapter for the declared app.newSession/app.request/ui.styles ABI.
use crate::{Result, application::Application, attachment::Mount, fail, http, image::LoadedImage, operator::Operators, process::{Meter, Programme}, store::Store, web::nonce};
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
    serve_programme(app, programme, meter, directory, port, None, None, None)
}

pub fn serve_image(mut image: LoadedImage, directory: &Path, port: u16, attachment_root: Option<&Path>, operators: Option<&Path>, game_kernel: Option<(std::path::PathBuf, String)>) -> Result<()> {
    image.app.bind_browser(&mut image.programme)?;
    let mount = if let Some(root) = attachment_root {
        if !image.app.has_entry("app.attachment") {
            return Err(fail("an attachment mount requires the declared app.attachment entry"));
        }
        let grants = BTreeSet::from(["application.data", "kernel.invoke"]);
        image.programme.require_grants("app.attachment", &grants)?;
        if image.app.has_entry("app.image") {
            image.programme.require_grants("app.image", &grants)?;
        }
        Some(Mount::open(root)?)
    } else { None };
    let game_kernel = game_kernel.map(|(path, pin)| crate::game_kernel::Binding::open(&path, &pin, directory)).transpose()?;
    serve_programme(image.app, image.programme, image.meter, directory, port, mount, operators.map(Operators::read).transpose()?, game_kernel)
}

fn serve_programme(app: Application, mut programme: Programme, meter: Meter,
    directory: &Path, port: u16, mount: Option<Mount>, operators: Option<Operators>, game_kernel: Option<crate::game_kernel::Binding>) -> Result<()>
{
    let styles = programme.run("ui.styles", Value::Null, &mut meter.clone())?;
    let styles = styles.as_str().ok_or_else(|| fail("expected stylesheet text"))?;
    let inline_images = mount.is_some() && app.has_entry("app.image");
    let downloads = if app.has_entry("app.download") {
        if game_kernel.is_none() { return Err(fail("app.download requires a game kernel store")); }
        programme.require_grants("app.download", &BTreeSet::from(["rel.decode", "text.slice", "number.calculate"]))?;
        let root = directory.join("game-kernel/candidates");
        std::fs::create_dir_all(&root)?;
        Some(Mount::game_downloads(&root)?)
    } else { None };
    let viewer = app.has_entry("app.viewerFile") && app.has_entry("app.previewSource");
    if viewer {
        if mount.is_none() || downloads.is_none() { return Err(fail("asset preview requires attachments and downloads")); }
        programme.require_grants("app.viewerFile", &BTreeSet::from(["application.data"]))?;
        programme.require_grants("app.previewSource", &BTreeSet::from(["game.kernel"]))?;
    }
    programme.bind_attachment(mount.clone());
    programme.bind_game_kernel(game_kernel);
    programme.bind_store(Store::open(directory, &app.state_profile, &app.basis)?);
    let sessions = RefCell::new(BTreeMap::<String, Session>::new());

    http::serve(port, |origin, stream, request| {
        let header = |name| request.headers.get(name).map(String::as_str);
        let mut operator = Value::Null;
        if let Some(operators) = &operators {
            let Some(identity) = operators.verify(header("authorization")) else {
                return http::send_headers(stream, "401 Unauthorized", "text/plain",
                    "WWW-Authenticate: Basic realm=\"Encounter\", charset=\"UTF-8\"\r\n", "Operator credentials required.");
            };
            operator = identity;
        }
        if request.method == "POST" && operator["role"] == "observer" {
            return http::send(stream, "403 Forbidden", "text/plain", "Observer sessions are read-only.");
        }
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        if request.method == "GET" && path == "/styles.css" {
            return http::send(stream, "200 OK", "text/css", styles);
        }
        if viewer && let Some(name) = path.strip_prefix("/asset-viewer/") {
            if request.method != "GET" {
                return http::send(stream, "405 Method Not Allowed", "text/plain", "Expected GET.");
            }
            let descriptor = programme.run("app.viewerFile", json!(name), &mut meter.clone())?;
            if let Some(mount) = &mount && let Ok(file) = mount.read(&descriptor) {
                let content_type = match name.rsplit('.').next() {
                    Some("wasm") => "application/wasm",
                    Some("js" | "mjs") => "text/javascript; charset=utf-8",
                    _ => "text/plain; charset=utf-8",
                };
                if name == "ktx-worker.js" {
                    return http::send_bytes_with_policy(stream, "200 OK", content_type, "", &file.body,
                        "default-src 'none'; script-src 'unsafe-eval' 'wasm-unsafe-eval'");
                }
                return http::send_bytes(stream, "200 OK", content_type, "", &file.body);
            }
            return http::send(stream, "404 Not Found", "text/plain", "Viewer file unavailable.");
        }
        if let Some(downloads) = &downloads && path == "/asset-download/" {
            if request.method != "GET" {
                return http::send(stream, "405 Method Not Allowed", "text/plain", "Expected GET.");
            }
            let Ok(fields) = http::form(query.as_bytes()) else {
                return http::send(stream, "400 Bad Request", "text/plain", "Invalid download coordinates.");
            };
            let source_preview = viewer && fields.get("level")
                .is_some_and(|level| matches!(level.as_str(), "source" | "source-repair"));
            let descriptor = if source_preview {
                let result = programme.run("app.previewSource",
                    json!({"asset":fields.get("asset"),"level":fields.get("level")}), &mut meter.clone())?;
                if let Some(error) = result["error"].as_str() {
                    return http::send(stream, "422 Unprocessable Content", "text/plain", error);
                }
                result["file"].clone()
            } else {
                programme.run("app.download", json!({"fields":fields,"snapshot":programme.snapshot()?}), &mut meter.clone())?
            };
            match downloads.read(&descriptor) {
                Ok(file) => {
                    let headers = format!("Content-Disposition: {}\r\n", file.disposition);
                    return http::send_bytes(stream, "200 OK", "application/octet-stream", &headers, &file.body);
                }
                Err(error) if source_preview && !descriptor.is_null() =>
                    return http::send(stream, "500 Internal Server Error", "text/plain",
                        &format!("Preview file verification failed. {error}")),
                Err(_) => return http::send(stream, "404 Not Found", "text/plain", "Verified asset unavailable."),
            }

        }
        let inline_image = inline_images && path.starts_with("/images/");
        let attachment_id = if inline_image { path.strip_prefix("/images/") }
            else { path.strip_prefix("/attachments/") };
        if let Some(id) = attachment_id {
            if request.method != "GET" {
                return http::send(stream, "405 Method Not Allowed", "text/plain", "Expected GET.");
            }
            if let Some(mount) = &mount
                && !id.is_empty() && id.len() <= 128
                && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            {
                let entry = if inline_image { "app.image" } else { "app.attachment" };
                let descriptor = programme.run(entry, json!(id), &mut meter.clone())?;
                if let Ok(file) = mount.read(&descriptor) {
                    if inline_image {
                        return match file.image_type() {
                            Some(mime) => http::send_bytes(stream, "200 OK", mime, "", &file.body),
                            None => http::send(stream, "404 Not Found", "text/plain", "Image unavailable."),
                        };
                    }
                    let headers = format!("Content-Disposition: {}\r\n", file.disposition);
                    return http::send_bytes(stream, "200 OK", "application/octet-stream", &headers, &file.body);
                }
            }
            return http::send(stream, "404 Not Found", "text/plain", "Attachment unavailable.");
        }
        let body = match request.method.as_str() {
            "GET" => query.as_bytes(),
            "POST" => {
                if header("origin") != Some(origin) {
                    return http::send(stream, "403 Forbidden", "text/plain", "Wrong origin.");
                }
                if header("content-type") != Some("application/x-www-form-urlencoded") {
                    return http::send(stream, "415 Unsupported Media Type", "text/plain", "Expected a form.");
                }
                request.body.as_slice()
            }
            _ => return http::send(stream, "405 Method Not Allowed", "text/plain", "Expected GET or POST."),
        };
        let Ok(mut fields) = http::form(body) else {
            return http::send(stream, "400 Bad Request", "text/plain", "Invalid form.");
        };
        let cookie_name = format!("encounter_{}", origin.rsplit(':').next().unwrap_or_default());
        let id = header("cookie").and_then(|cookies| {
            cookies.split(';').filter_map(|cookie| cookie.trim().split_once('='))
                .find_map(|(key, value)| (key == cookie_name).then_some(value))
        });
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
        if app.has_entry("app.attachment") {
            input["attachments"] = json!(mount.is_some());
        }
        if operators.is_some() {
            input["operator"] = operator;
            input["now"] = json!(u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?);
        }
        let result = programme.run("app.request", input, &mut meter)?;
        let html = result["html"].as_str().ok_or_else(|| fail("expected application HTML"))?;
        session.state = result["session"].clone();
        http::send_page(stream, "200 OK", "text/html; charset=utf-8", &response_headers, html.as_bytes(),
            inline_images, viewer && result["assetPreview"] == true)
    })
}
