use super::{Fields, Request, Response, Workspace, header, origin, transport::exchange};
use crate::{Result, fail, gateway, file_index::{FileHttpDecision, IndexPolicy, GAME_ASSETS, HOME_RELEASES, MAX_VIEW, MAX_MOVIE}};
use serde_json::{Value, json};
use std::{env, fs::File, io::{BufRead, BufReader, Read, Write}, os::unix::net::UnixStream, path::{Path, PathBuf}, thread, time::Duration};

pub(super) const GAME_IMAGE_PREFIX: &str = "/game/images/";

const POLICY_FILE: &str = "version-programme/applications/appdev-projects/workspace.encounter";
const POLICY_EXCERPT: &str = concat!("spec/catalogue-source/version-programme/applications/appdev-projects/",
    "workspace.encounter/workspace.environmentPolicy.encounter");
const POLICY_PROCESS: &str = "workspace.environmentPolicy";

fn read_source_artifact(root: &File, path: &str, limit: usize) -> Result<String> {
    let mut text = String::new();
    crate::package::open_artifact(root, Path::new(path))?
        .take((limit + 1) as u64).read_to_string(&mut text)?;
    if text.len() > limit { return Err(fail("authoring source exceeds its byte limit")); }
    Ok(text)
}

fn source_revision(root: &File) -> Result<(String, crate::rel::Facts)> {
    let receipt = read_source_artifact(root, "package-receipt.rel", 2 * 1024 * 1024)?;
    let revision = crate::rel::hash(&receipt);
    let pins = crate::rel::Facts::parse(&receipt)?;
    if pins.one("package", "contract")? != "encounter/gated-release/1" {
        return Err(fail("unrecognized source release receipt"));
    }
    Ok((revision, pins))
}

fn verify_source_pin(pins: &crate::rel::Facts, path: &str, text: &str) -> Result<()> {
    if pins.one("artifact", path)? != crate::rel::hash(text) {
        return Err(fail("authoring source does not match its release receipt"));
    }
    Ok(())
}


fn add_image_preview(policy: &IndexPolicy, collections: &mut Value, selected: Option<&str>) -> Result<()> {
    let Some(selected) = selected else { return Ok(()); };
    let Some(rows) = collections.get_mut(GAME_ASSETS).and_then(Value::as_array_mut) else { return Ok(()); };
    let Some(image) = rows.iter_mut().find(|row| row["id"] == selected && row["kind"] == "image") else { return Ok(()); };
    if let (Some(name), Some(path)) = (image["name"].as_str(), image["path"].as_str()) {
        let approved = policy.http(FileHttpDecision::Image, json!({"name":name,"path":path}))?;
        if let Some(name) = approved.as_str() {
            image["imagePreview"] = json!(format!("{GAME_IMAGE_PREFIX}{name}"));
        }
    }
    Ok(())
}

pub(super) struct FileIndex {
    socket: Option<PathBuf>,
    game: Option<GatewayProbe>,
    store: Option<GatewayProbe>,
    north: Option<GatewayProbe>,
}

struct GatewayProbe {
    endpoint: String,
    route: String,
    marker: String,
}

impl FileIndex {
    pub(super) fn load() -> Result<Self> {
        let socket = env::var_os("APPDEV_FILE_INDEX_SOCKET").map(PathBuf::from);
        if socket.as_ref().is_some_and(|path| !path.is_absolute()) {
            return Err(fail("expected an absolute workspace file index socket path"));
        }
        let policy = IndexPolicy::load()?;
        let gateway = |variable, provider| -> Result<Option<GatewayProbe>> {
            let Some(endpoint) = env::var(variable).ok().map(|value| origin(&value, true)).transpose()? else { return Ok(None); };
            let plan = policy.http(FileHttpDecision::Gateway, json!(provider))?;
            let field = |key| super::string(&plan[key]).map(str::to_owned);
            Ok(Some(GatewayProbe { endpoint, route: field("route")?, marker: field("marker")? }))
        };
        Ok(Self { socket, game: gateway("APPDEV_FILE_INDEX_GAME_GATEWAY", "game")?,
            store: gateway("APPDEV_FILE_INDEX_STORE_GATEWAY", "store")?, north: gateway("APPDEV_FILE_INDEX_NORTH_GATEWAY", "north")? })
    }

    fn read(&self, roots: &[&str], file: Option<&str>, rel_filter: Option<&str>) -> Result<Value> {
        let Some(path) = &self.socket else { return Ok(json!({})); };
        if roots.is_empty() { return Ok(json!({})); }
        let mut stream = UnixStream::connect(path)?;
        let timeout = Some(Duration::from_secs(2));
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        serde_json::to_writer(&mut stream, &json!({"roots":roots, "file":file, "relFilter":rel_filter}))?;
        stream.write_all(b"\n")?;
        let mut body = Vec::new();
        stream.take(MAX_VIEW + 1).read_to_end(&mut body)?;
        if body.len() as u64 > MAX_VIEW { return Err(fail("file index response limit")); }
        let mut view: Value = serde_json::from_slice(&body)?;
        let view = view.as_object_mut().ok_or_else(|| fail("invalid file index response"))?;
        view.retain(|root, _| roots.contains(&root.as_str()));
        Ok(json!(view))
    }

    fn media(&self, policy: &IndexPolicy, file: &str, range: &str) -> Result<Response> {
        let Some(path) = &self.socket else { return Ok(Response::empty(404)); };
        let mut stream = UnixStream::connect(path)?;
        let timeout = Some(Duration::from_secs(3));
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        writeln!(stream, "{}", json!({"media":file, "range":range}))?;
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        (&mut stream).take(512).read_line(&mut line)?;
        if !line.ends_with('\n') { return Ok(Response::empty(404)); }
        let header: Value = serde_json::from_str(&line)?;
        let total = header["total"].as_u64();
        let start = header["start"].as_u64();
        let end = header["end"].as_u64();
        let decision = policy.http(FileHttpDecision::MediaFrame, json!({
            "status":header["status"].as_u64(),"mime":header["mime"],"total":total,"start":start,"end":end,"maximum":MAX_MOVIE,
        }))?;
        let status = match decision.as_u64() {
            Some(416) => return Ok(Response::empty(416).with("Content-Range", format!("bytes */{}", total.unwrap_or_default()))),
            Some(200) => 200,
            Some(206) => 206,
            _ => return Ok(Response::empty(404)),
        };
        let (Some(start), Some(end), Some(total)) = (start, end, total) else {
            return Err(fail("invalid admitted file media frame"));
        };
        let kind = match header["mime"].as_str() {
            Some("video/mp4") => "video/mp4",
            Some("video/webm") => "video/webm",
            _ => return Err(fail("invalid admitted file media type")),
        };
        let mut response = Response::stream(status, kind, end - start + 1, stream).with("Accept-Ranges", "bytes");
        if status == 206 { response = response.with("Content-Range", format!("bytes {start}-{end}/{total}")); }
        Ok(response)
    }
}

impl Workspace {
    fn provider_access(&self, request: &Request, probe: Option<&GatewayProbe>) -> Result<bool> {
        let Some(probe) = probe else { return Ok(false); };
        let public = &self.runtime.origin;
        let name = gateway::session_cookie("/identity-management", public);
        let Some(session) = gateway::cookie(request, &name) else { return Ok(false); };
        let policy = IndexPolicy::load()?;
        if policy.http(FileHttpDecision::GatewaySession, json!(session))? != true { return Ok(false); }
        let cookie = format!("{name}={session}");
        let authority = public.split_once("://").expect("validated origin").1;
        let reply = exchange(&probe.endpoint, &probe.route, "GET", &[("Host", authority), ("Cookie", &cookie)], None, "2")?;
        let marker_present = std::str::from_utf8(&reply.body).is_ok_and(|body| body.contains(&probe.marker));
        Ok(policy.http(FileHttpDecision::GatewayResponse, json!({
            "status":reply.status, "contentType":reply.content_type, "markerPresent":marker_present,
        }))? == true)
    }

    fn file_request(&self, policy: &IndexPolicy, request: &Request, query: &str, kind: &str) -> Result<Value> {
        let fields = Fields::parse(query.as_bytes());
        policy.http(FileHttpDecision::Request, json!({
            "kind":kind, "hasQuery":!query.is_empty(), "fieldCount":fields.len(),
            "file":fields.get("file"), "relFilter":fields.get("rel-filter"), "view":fields.get("view"),
            "revision":fields.get("revision"),
            "fetchSite":header(request, "sec-fetch-site"), "origin":header(request, "origin"), "publicOrigin":self.runtime.origin,
        }))
    }

    pub(super) fn file_index(&self, request: &Request, query: &str) -> Result<Response> {
        let policy = IndexPolicy::load()?;
        let admitted = self.file_request(&policy, request, query, "index")?;
        match admitted["status"].as_u64() {
            Some(200) => (),
            Some(403) => return Ok(Response::empty(403)),
            _ => return Err(fail("invalid file index request decision")),
        }
        let file = admitted["file"].as_str();
        if admitted["authoring"] == true {
            return self.authoring_source(request, file, admitted["revision"].as_str());
        }
        let rel_filter = admitted["relFilter"].as_str();
        let selected_only = admitted["selectedOnly"] == true;
        let settings = &self.runtime.files;
        let (identity, game, store, north) = thread::scope(|scope| {
            let identity = scope.spawn(|| self.workspace_identity(request).ok().flatten());
            let game = scope.spawn(|| self.provider_access(request, settings.game.as_ref()).unwrap_or(false));
            let store = scope.spawn(|| self.provider_access(request, settings.store.as_ref()).unwrap_or(false));
            let north = scope.spawn(|| self.provider_access(request, settings.north.as_ref()).unwrap_or(false));
            (identity.join().unwrap_or(None), game.join().unwrap_or(false),
                store.join().unwrap_or(false), north.join().unwrap_or(false))
        });
        let decision = self.run(json!({
            "program":"workspace", "operation":"file-visibility",
            "email":identity.as_ref().map(|identity| identity.email.as_str()), "stewardEmail":self.runtime.steward,
            "game":game, "store":store, "north":north,
        }))?;
        let roots = decision["roots"].as_array().filter(|roots| roots.len() <= 7)
            .ok_or_else(|| fail("invalid file visibility decision"))?
            .iter().map(super::string).collect::<Result<Vec<_>>>()?;
        let platform = decision["platform"].as_bool().ok_or_else(|| fail("invalid Platform visibility decision"))?;
        let mut collections = settings.read(&roots, file, rel_filter).unwrap_or_else(|_| json!({}));
        if roots.contains(&GAME_ASSETS) { add_image_preview(&policy, &mut collections, file)?; }
        if let Some(id) = file.filter(|_| selected_only) {
            if let Some(roots) = collections.as_object_mut() {
                roots.retain(|_, value| {
                    let Some(rows) = value.as_array_mut() else { return false; };
                    rows.retain(|row| row["id"] == id);
                    !rows.is_empty()
                });
            }
        }
        let mut response = json!({"collections":collections,"platform":platform});
        if platform && selected_only
            && let Some(row) = response["collections"][HOME_RELEASES].get(0)
            && row["path"] == format!("{HOME_RELEASES}/{POLICY_EXCERPT}")
            && let Some(text) = row["text"].as_str()
            && let Ok(root) = File::open(&self.release.root)
            && let Ok((revision, pins)) = source_revision(&root)
            && verify_source_pin(&pins, POLICY_EXCERPT, text).is_ok() {
            response["authoringRevision"] = json!(revision);
        }
        Ok(Response::json(200, &response))
    }

    fn authoring_source(&self, request: &Request, file: Option<&str>, expected: Option<&str>) -> Result<Response> {
        let identity = self.workspace_identity(request)?;
        if !self.platform_allowed(identity.as_ref())? {
            return Ok(Response::empty(403));
        }
        let excerpt_id = crate::rel::hash(format!("{HOME_RELEASES}/{POLICY_EXCERPT}"));
        if file != Some(excerpt_id.as_str()) {
            return Ok(Response::empty(404));
        }
        let read = || -> Result<Response> {
            let root = File::open(&self.release.root)?;
            let (revision, pins) = source_revision(&root)?;
            if expected != Some(revision.as_str()) {
                return Ok(Response::empty(409));
            }
            pins.one("artifact", POLICY_EXCERPT)?;
            let text = read_source_artifact(&root, POLICY_FILE, 32 * 1024)?;
            verify_source_pin(&pins, POLICY_FILE, &text)?;
            let declaration = format!("process {POLICY_PROCESS}:");
            let mut matches = text.lines().enumerate().filter(|(_, line)| *line == declaration);
            let Some((line, _)) = matches.next() else { return Ok(Response::empty(404)); };
            if matches.next().is_some() { return Ok(Response::empty(404)); }
            Ok(Response::json(200, &json!({
                "revision":revision, "app":"appdev-projects", "file":"workspace.encounter",
                "process":POLICY_PROCESS, "line":line + 1, "text":text
            })))
        };
        Ok(read().unwrap_or_else(|_| Response::empty(404)))
    }

    pub(super) fn file_media(&self, request: &Request, query: &str) -> Result<Response> {
        let policy = IndexPolicy::load()?;
        let admitted = self.file_request(&policy, request, query, "media")?;
        match admitted["status"].as_u64() {
            Some(200) => (),
            Some(403) => return Ok(Response::empty(403)),
            Some(404) => return Ok(Response::empty(404)),
            _ => return Err(fail("invalid file media request decision")),
        }
        let file = super::string(&admitted["file"])?;
        let range = header(request, "range");
        let platform = self.workspace_identity(request).and_then(|identity| self.platform_allowed(identity.as_ref())).unwrap_or(false);
        match policy.http(FileHttpDecision::MediaAccess, json!({"platform":platform,"rangeBytes":range.len()}))?.as_u64() {
            Some(200) => Ok(self.runtime.files.media(&policy, file, range).unwrap_or_else(|_| Response::empty(404))),
            Some(403) => Ok(Response::empty(403)),
            Some(416) => Ok(Response::empty(416)),
            _ => Err(fail("invalid file media access decision")),
        }
    }
}

#[cfg(test)]
#[test]
fn file_policy_preserves_request_priority_and_gateway_admission() -> Result<()> {
    let policy = IndexPolicy::load()?;
    let mut request = json!({"kind":"index","hasQuery":true,"fieldCount":3,"file":"a".repeat(64),
        "relFilter":"𐐀".repeat(120),"view":"file","fetchSite":"same-origin","origin":"https://home.example",
        "publicOrigin":"https://home.example"});
    let decide = |input| policy.http(FileHttpDecision::Request, input);
    let allowed = decide(request.clone())?;
    assert_eq!(allowed["status"], 200);
    assert_eq!(allowed["relFilter"], request["relFilter"]);
    assert_eq!(allowed["selectedOnly"], true);
    request["relFilter"] = json!("field\n");
    assert_eq!(decide(request.clone())?["status"], 403);
    request["relFilter"] = json!("𐐀".repeat(121));
    assert_eq!(decide(request.clone())?["status"], 403);
    request["kind"] = json!("media");
    request["origin"] = json!("https://elsewhere.example");
    assert_eq!(decide(request.clone())?["status"], 404);
    request["fieldCount"] = json!(1);
    assert_eq!(decide(request)?["status"], 403);
    for (platform, range_bytes, expected) in [(false, 81, 403), (true, 81, 416), (true, 80, 200)] {
        assert_eq!(policy.http(FileHttpDecision::MediaAccess, json!({"platform":platform,"rangeBytes":range_bytes}))?, expected);
    }
    let frame = |status, mime, start, end, total| policy.http(FileHttpDecision::MediaFrame,
        json!({"status":status,"mime":mime,"start":start,"end":end,"total":total,"maximum":100}));
    assert_eq!(frame(200, "video/webm", 0, 3, 4)?, 200);
    assert_eq!(frame(200, "video/webm", 1, 3, 4)?, 404);
    assert_eq!(frame(206, "video/mp4", 1, 3, 4)?, 206);
    assert_eq!(frame(206, "video/mp4", 1, 4, 4)?, 404);
    assert_eq!(frame(206, "text/html", 1, 3, 4)?, 404);
    assert_eq!(frame(416, "video/mp4", 0, 0, 101)?, 404);
    assert_eq!(frame(416, "", 0, 0, 4)?, 416);
    let image = |name, path| policy.http(FileHttpDecision::Image, json!({"name":name,"path":path}));
    assert_eq!(image("cover.PNG", "Apps/Game Hub/Assets/example/cover.PNG")?, "cover.PNG");
    assert_eq!(image("cover.PNG", "Apps/Game Hub/Assets/example/nested/cover.PNG")?, Value::Null);
    assert_eq!(image("cover.svg", "Apps/Game Hub/Assets/example/cover.svg")?, Value::Null);
    assert_eq!(image("../cover.PNG", "Apps/Game Hub/Assets/example/../cover.PNG")?, Value::Null);
    let plan = policy.http(FileHttpDecision::Gateway, json!("game"))?;
    assert_eq!(plan["route"], "/game/?document=recent-folio");
    assert_eq!(plan["prefix"], "/game");
    let admits = |session: &str| policy.http(FileHttpDecision::GatewaySession, json!(session));
    assert_eq!(admits("fixture-token_1")?, true);
    for token in ["", "abc;other=1", "abc\n", &"a".repeat(129)] {
        assert_eq!(admits(token)?, false);
    }
    for (status, content_type, marker_present, expected) in [
        (200, "text/html; charset=utf-8", true, true), (302, "text/html", true, false),
        (200, "application/json", true, false), (200, "text/html", false, false),
    ] {
        let result = policy.http(FileHttpDecision::GatewayResponse, json!({
            "status":status, "contentType":content_type, "markerPresent":marker_present,
        }))?;
        assert_eq!(result.as_bool().unwrap_or(false), expected);
    }
    Ok(())
}
