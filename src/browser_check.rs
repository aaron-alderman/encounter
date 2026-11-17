use crate::{Result, appdev_host_process::{Scratch, Supervisor, interruption}, command::Evaluator, fail, http_client};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::{
    collections::VecDeque, fs, io::{BufRead, BufReader, Read, Write},
    os::{fd::{AsRawFd, FromRawFd, OwnedFd}, unix::{fs::MetadataExt, net::UnixStream, process::CommandExt}},
    path::Path, process::{Child, Command, Stdio}, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ORIGIN: &str = "https://appdev.sourcerytech.com.au";
const SESSION: &str = "/workspace/formation/test-session";
const COOKIE: &str = "__Host-appdev-formation-test";
const GRANT_HELPER: &str = "/usr/local/libexec/sourcery-appdev-test-grant";
const TIMEOUT: Duration = Duration::from_secs(12);
const MAX_MESSAGE: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
struct ProtocolError {
    method: String,
    message: String,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}: {}", self.method, self.message)
    }
}

impl std::error::Error for ProtocolError {}

impl ProtocolError {
    fn stale_node(error: &(dyn std::error::Error + 'static)) -> bool {
        error.downcast_ref::<Self>().is_some_and(|error| {
            (error.method.starts_with("DOM.") || error.method.starts_with("Accessibility."))
                && matches!(error.message.as_str(),
                    "Could not find node with given id" | "No node with given id found" |
                    "Document needs to be requested first")
        })
    }

    fn missing_box(error: &(dyn std::error::Error + 'static)) -> bool {
        error.downcast_ref::<Self>().is_some_and(|error|
            error.method == "DOM.getBoxModel" && error.message == "Could not compute box model.")
    }
}

struct Chromium {
    child: Child,
    input: UnixStream,
    output: BufReader<UnixStream>,
    id: u64,
    session: Option<String>,
    target: Option<String>,
    events: VecDeque<Value>,
    _profile: Scratch,
}

impl Chromium {
    fn launch(workspace: &Path, scratch: &Path) -> Result<Self> {
        let config: Value = serde_json::from_slice(&fs::read(workspace.join("env/chrome-profile.json"))?)?;
        let profile = Scratch::create(scratch, "encounter-browser-check-")?;
        let (input, child_input) = UnixStream::pair()?;
        let (output, child_output) = UnixStream::pair()?;
        fn high_fd(fd: &UnixStream) -> Result<OwnedFd> {
            let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
            if copy < 0 { return Err(std::io::Error::last_os_error().into()); }
            Ok(unsafe { OwnedFd::from_raw_fd(copy) })
        }
        let child_input = high_fd(&child_input)?;
        let child_output = high_fd(&child_output)?;
        output.set_read_timeout(Some(TIMEOUT))?;
        input.set_write_timeout(Some(TIMEOUT))?;
        let mut command = Command::new(string(&config["executable"])?);
        command.args(["--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--no-first-run",
            "--disable-background-networking", "--remote-debugging-pipe", "--window-size=1440,1000",
            &format!("--user-data-dir={}", profile.path().display()), "about:blank"])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(child_input.as_raw_fd(), 3) < 0 || libc::dup2(child_output.as_raw_fd(), 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        Ok(Self { child, input, output: BufReader::new(output), id: 0, session: None, target: None,
            events: VecDeque::new(), _profile: profile })
    }

    fn call(&mut self, method: &str, params: Value, page: bool) -> Result<Value> {
        self.id += 1;
        let mut command = json!({"id":self.id, "method":method, "params":params});
        if page { command["sessionId"] = json!(self.session.as_deref().ok_or_else(|| fail("No open browser page"))?); }
        serde_json::to_writer(&mut self.input, &command)?;
        self.input.write_all(&[0])?;
        loop {
            let mut bytes = Vec::new();
            if self.output.by_ref().take(MAX_MESSAGE).read_until(0, &mut bytes)? == 0 || bytes.pop() != Some(0) {
                return Err(fail("Chromium returned an incomplete or oversized debugging message"));
            }
            let value: Value = serde_json::from_slice(&bytes)?;
            if value["id"] == self.id {
                if let Some(error) = value.get("error") {
                    return Err(Box::new(ProtocolError {
                        method: method.to_owned(),
                        message: error["message"].as_str().unwrap_or("Chromium refused the command").to_owned(),
                    }));
                }
                return Ok(value["result"].clone());
            }
            if value["sessionId"].as_str() == self.session.as_deref()
                && matches!(value["method"].as_str(), Some("Network.requestWillBeSent" | "Network.responseReceived"))
            {
                if self.events.len() == 2048 { self.events.pop_front(); }
                self.events.push_back(value);
            }
        }
    }

    fn new_page(&mut self) -> Result<()> {
        if let Some(target) = self.target.take() {
            self.call("Target.closeTarget", json!({"targetId":target}), false)?;
        }
        self.session = None;
        let created = self.call("Target.createTarget", json!({"url":"about:blank"}), false)?;
        let target = string(&created["targetId"])?.to_owned();
        let attached = self.call("Target.attachToTarget", json!({"targetId":target,"flatten":true}), false)?;
        self.session = Some(string(&attached["sessionId"])?.to_owned());
        self.target = Some(target);
        for method in ["Page.enable", "Network.enable", "DOM.enable", "Accessibility.enable"] {
            self.call(method, json!({}), true)?;
        }
        Ok(())
    }

    fn response_status(&mut self, url: &str, method: &str) -> Result<Value> {
        let started = Instant::now();
        while started.elapsed() < TIMEOUT && interruption().is_none() {
            if let Some(status) = self.events.iter().find_map(|event| {
                let response = &event["params"];
                if event["method"] != "Network.responseReceived" || response["response"]["url"] != url { return None; }
                self.events.iter().any(|request| request["method"] == "Network.requestWillBeSent"
                    && request["params"]["requestId"] == response["requestId"]
                    && request["params"]["request"]["method"] == method).then(|| response["response"]["status"].clone())
            }) { return Ok(status); }
            self.call("Page.getNavigationHistory", json!({}), true)?;
            thread::sleep(Duration::from_millis(40));
        }
        Err(fail(format!("Timed out waiting for {method} response at {url}")))
    }

    fn node(&mut self, locator: &Value) -> Result<Option<u64>> {
        let document = self.call("DOM.getDocument", json!({"depth":0}), true)?;
        let result = self.call("DOM.querySelectorAll", json!({
            "nodeId":document["root"]["nodeId"], "selector":string(&locator["selector"])?
        }), true)?;
        let Some(root) = result["nodeIds"].as_array().and_then(|nodes| nodes.first()).and_then(Value::as_u64) else {
            return Ok(None);
        };
        let node = if let Some(role) = locator["role"].as_str() {
            let mut params = json!({"nodeId":root,"role":role});
            if let Some(name) = locator["name"].as_str() { params["accessibleName"] = json!(name); }
            let found = self.call("Accessibility.queryAXTree", params, true)?;
            let backend = found["nodes"].as_array().and_then(|nodes| nodes.iter()
                .find(|node| node["ignored"] != true && node["role"]["value"] == role))
                .and_then(|node| node["backendDOMNodeId"].as_u64());
            let Some(backend) = backend else { return Ok(None); };
            match self.call("DOM.pushNodesByBackendIdsToFrontend", json!({"backendNodeIds":[backend]}), true) {
                Ok(nodes) => nodes["nodeIds"][0].as_u64().filter(|id| *id != 0),
                Err(error) if error.to_string().ends_with("Document needs to be requested first") => None,
                Err(error) => return Err(error),
            }
        } else { Some(root) };
        let Some(node) = node else { return Ok(None); };
        if let Some(text) = locator["text"].as_str() {
            if self.text(node)?.trim() != text { return Ok(None); }
        }
        Ok(Some(node))
    }

    fn text(&mut self, node: u64) -> Result<String> {
        fn collect(node: &Value, out: &mut String) {
            if node["nodeType"] == 3 {
                if let Some(text) = node["nodeValue"].as_str() { out.push_str(text); }
            }
            if let Some(children) = node["children"].as_array() {
                for child in children { collect(child, out); }
            }
        }
        let result = self.call("DOM.describeNode", json!({"nodeId":node,"depth":-1}), true)?;
        let mut text = String::new();
        collect(&result["node"], &mut text);
        Ok(text)
    }

    fn with_locator<T>(
        &mut self,
        locator: &Value,
        visible: bool,
        mut observe: impl FnMut(&mut Self, u64) -> Result<T>,
    ) -> Result<T> {
        let started = Instant::now();
        let mut stale = None;
        while started.elapsed() < TIMEOUT && interruption().is_none() {
            let attempt = (|| -> Result<Option<T>> {
                let Some(node) = self.node(locator)? else { return Ok(None); };
                if visible {
                    self.call("DOM.getBoxModel", json!({"nodeId":node}), true)?;
                }
                observe(self, node).map(Some)
            })();
            match attempt {
                Ok(Some(value)) => return Ok(value),
                Ok(None) => {}
                Err(error) if ProtocolError::stale_node(error.as_ref()) => stale = Some(error),
                Err(error) if visible && ProtocolError::missing_box(error.as_ref()) => {}
                Err(error) => return Err(error),
            }
            thread::sleep(Duration::from_millis(40));
        }
        let detail = stale.map(|error| format!(" (last stale node: {error})")).unwrap_or_default();
        Err(fail(format!("Timed out waiting for browser locator {locator}{detail}")))
    }

    fn wait_node(&mut self, locator: &Value, visible: bool) -> Result<u64> {
        self.with_locator(locator, visible, |_, node| Ok(node))
    }

    fn assure_stale_locator(&mut self) -> Result<()> {
        self.new_page()?;
        let tree = self.call("Page.getFrameTree", json!({}), true)?;
        let frame = string(&tree["frameTree"]["frame"]["id"])?;
        self.call("Page.setDocumentContent", json!({
            "frameId": frame,
            "html": "<!doctype html><p class=probe>Removed</p><p class=probe>Replacement</p>",
        }), true)?;

        // Remove the first match after resolving it, just before the DOM read.
        let mut attempts = 0;
        let text = self.with_locator(&json!({"selector":".probe"}), false, |browser, node| {
            attempts += 1;
            if attempts == 1 {
                browser.call("DOM.removeNode", json!({"nodeId":node}), true)?;
            }
            browser.text(node)
        })?;
        if attempts != 2 || text.trim() != "Replacement" {
            return Err(fail("Stale locator did not resolve the replacement Chromium node"));
        }
        println!("PASS: Assurance recovered a stale Chromium node");
        Ok(())
    }

    fn read_text(&mut self, locator: &Value) -> Result<String> {
        self.with_locator(locator, true, |browser, node| {
            Ok(browser.text(node)?.trim().to_owned())
        })
    }

    fn click(&mut self, locator: &Value) -> Result<()> {
        let (x, y) = self.control_center(locator)?;
        for action in ["mousePressed", "mouseReleased"] {
            self.call("Input.dispatchMouseEvent", json!({"type":action,"x":x,"y":y,"button":"left","clickCount":1}), true)?;
        }
        Ok(())
    }

    fn control_center(&mut self, locator: &Value) -> Result<(f64, f64)> {
        self.with_locator(locator, true, |browser, node| {
            browser.call("DOM.scrollIntoViewIfNeeded", json!({"nodeId":node}), true)?;
            let model = browser.call("DOM.getBoxModel", json!({"nodeId":node}), true)?;
            let quad = model["model"]["border"].as_array().filter(|quad| quad.len() == 8)
                .ok_or_else(|| fail("Browser control has no clickable box"))?;
            let x = (quad[0].as_f64().unwrap_or(0.0) + quad[4].as_f64().unwrap_or(0.0)) / 2.0;
            let y = (quad[1].as_f64().unwrap_or(0.0) + quad[5].as_f64().unwrap_or(0.0)) / 2.0;
            Ok((x, y))
        })
    }

    fn tap(&mut self, locator: &Value) -> Result<()> {
        let (x, y) = self.control_center(locator)?;
        self.call("Input.dispatchTouchEvent", json!({"type":"touchStart","touchPoints":[{"x":x,"y":y}]}), true)?;
        self.call("Input.dispatchTouchEvent", json!({"type":"touchEnd","touchPoints":[]}), true)?;
        Ok(())
    }

    fn key(&mut self, key: &str, code: u8) -> Result<()> {
        for action in ["rawKeyDown", "keyUp"] {
            self.call("Input.dispatchKeyEvent", json!({"type":action,"key":key,"code":key,
                "windowsVirtualKeyCode":code,"nativeVirtualKeyCode":code}), true)?;
        }
        Ok(())
    }

    fn select_option(&mut self, locator: &Value, value: &str) -> Result<()> {
        let node = self.wait_node(locator, true)?;
        let result = self.call("DOM.querySelectorAll", json!({"nodeId":node,"selector":"option"}), true)?;
        let options = result["nodeIds"].as_array().filter(|nodes| nodes.len() <= 128)
            .ok_or_else(|| fail("Invalid Decompiler option list"))?;
        let mut selected = None;
        for (index, option) in options.iter().enumerate() {
            let attrs = self.call("DOM.getAttributes", json!({"nodeId":option}), true)?;
            let attrs = attrs["attributes"].as_array().ok_or_else(|| fail("Expected option attributes"))?;
            if attrs.chunks_exact(2).any(|pair| pair[0] == "value" && pair[1] == value) {
                let id = option.as_u64().ok_or_else(|| fail("Expected a Decompiler option node"))?;
                selected = Some((index, self.text(id)?));
                break;
            }
        }
        let (index, label) = selected.ok_or_else(|| fail("Missing the Decompiler document option"))?;
        self.call("DOM.focus", json!({"nodeId":node}), true)?;
        self.key("Home", 36)?;
        for _ in 0..index { self.key("ArrowDown", 40)?; }
        if self.value(locator)? != label.trim() { return Err(fail("The Decompiler document selection did not take effect")); }
        Ok(())
    }

    fn visible(&mut self, locator: &Value) -> Result<bool> {
        let Some(node) = self.node(locator)? else { return Ok(false); };
        let style = self.call("CSS.getComputedStyleForNode", json!({"nodeId":node}), true)?;
        let style = style["computedStyle"].as_array().ok_or_else(|| fail("Expected browser computed style"))?;
        if !style.iter().any(|field| field["name"] == "visibility" && field["value"] == "visible") {
            return Ok(false);
        }
        let Ok(box_model) = self.call("DOM.getBoxModel", json!({"nodeId":node}), true) else { return Ok(false); };
        Ok(["width", "height"].into_iter().all(|key| box_model["model"][key].as_f64().is_some_and(|size| size > 0.0)))
    }

    fn counter(&mut self, locator: &Value) -> Result<String> {
        self.read_text(locator)
    }

    fn fill(&mut self, locator: &Value, text: &str) -> Result<()> {
        self.with_locator(locator, true, |browser, node| {
            browser.call("DOM.focus", json!({"nodeId":node}), true)?;
            Ok(())
        })?;
        for action in ["rawKeyDown", "keyUp"] {
            self.call("Input.dispatchKeyEvent", json!({"type":action,"modifiers":2,"key":"a","code":"KeyA",
                "windowsVirtualKeyCode":65,"nativeVirtualKeyCode":65}), true)?;
        }
        self.call("Input.insertText", json!({"text":text}), true)?;
        Ok(())
    }

    fn value(&mut self, locator: &Value) -> Result<Value> {
        self.with_locator(locator, true, |browser, node| {
            let tree = browser.call("Accessibility.getPartialAXTree", json!({"nodeId":node,"fetchRelatives":false}), true)?;
            Ok(tree["nodes"][0]["value"]["value"].clone())
        })
    }
}

impl Drop for Chromium {
    fn drop(&mut self) {
        // Chromium's renderers share the private process group.
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGTERM); }
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            if matches!(self.child.try_wait(), Ok(Some(_))) { return; }
            thread::sleep(Duration::from_millis(25));
        }
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL); }
        let _ = self.child.wait();
    }
}

fn string(value: &Value) -> Result<&str> { value.as_str().ok_or_else(|| fail("Expected browser check text")) }

fn entropy<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| fail("Browser check entropy unavailable"))?;
    Ok(bytes)
}

fn endpoint(path: &str) -> Result<String> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains('\\')
        || path.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) {
        return Err(fail("Expected a same-origin browser check path"));
    }
    Ok(format!("{ORIGIN}{path}"))
}

struct Response { status: u16, body: Vec<u8>, cookie: Option<String> }

fn request(method: &str, path: &str, bearer: Option<&str>, cookie: Option<&str>, restoring: bool) -> Result<Response> {
    if !matches!(method, "GET" | "POST") { return Err(fail("Expected a GET or POST browser check request")); }
    let url = endpoint(path)?;
    let bearer = bearer.map(|token| format!("Bearer {token}"));
    let cookie_header = cookie.map(|secret| format!("{COOKIE}={secret}"));
    let mut headers = Vec::new();
    if method == "POST" { headers.push(("Origin", ORIGIN)); }
    if let Some(value) = bearer.as_deref() { headers.push(("Authorization", value)); }
    if let Some(value) = cookie_header.as_deref() { headers.push(("Cookie", value)); }
    let response = http_client::send(http_client::Request {
        url: &url, method, headers: &headers, body: None, timeout: TIMEOUT, connect_timeout: TIMEOUT,
        limit: 2_097_152, resolve: None, trust_anchor: None, restoring,
    }).map_err(|_| fail(format!("{method} {path} failed")))?;
    let cookie = response.header_values("set-cookie")
        .find_map(|value| value.split(';').next()?.strip_prefix(COOKIE)?.strip_prefix('='))
        .filter(|value| value.len() == 43 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)))
        .map(str::to_owned);
    Ok(Response { status: response.status, body: response.body, cookie })
}

fn grant(operation: &str, declaration: &str) -> Result<()> {
    let restoring = match operation {
        "issue" => false, "revoke" => true, _ => return Err(fail("Unknown test grant operation")),
    };
    if declaration.len() > 128 { return Err(fail("Invalid Formation test grant declaration")); }
    let sudo = Path::new("/usr/bin/sudo").canonicalize()?;
    if !sudo.starts_with("/usr/bin") && sudo != Path::new("/usr/lib/cargo/bin/sudo") {
        return Err(fail("Expected the system sudo executable"));
    }
    for path in [sudo.as_path(), Path::new(GRANT_HELPER)] {
        for component in path.ancestors() {
            let metadata = component.symlink_metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(fail("Expected a root-owned test grant executable and parent directories"));
            }
        }
        crate::package::require_native_runtime(path)?;
    }
    let mut supervisor = if restoring { Supervisor::release_recovery() } else { Supervisor::children() };
    let child = supervisor.start("AppDev test grant", Command::new(sudo).arg0("sudo")
        .args(["-n", "--", GRANT_HELPER, "appdev-formation-grant", operation])
        .env_clear().env("LC_ALL", "C").stdin(Stdio::piped()))?;
    child.stdin.take().ok_or_else(|| fail("Missing grant custody pipe"))?.write_all(declaration.as_bytes())?;
    supervisor.wait_for_success(TIMEOUT)
}

fn evaluate(suite: &Evaluator, input: Value) -> Result<Value> {
    let value = suite.run("cli.main", json!([input.to_string()]))?;
    Ok(serde_json::from_str(string(&value)?)?)
}

pub(crate) fn decompiler_paging(app: &Path, workflow: &Evaluator, plan: &Value, port: u16) -> Result<()> {
    use crate::decompiler_check::admit;
    let workspace = app.ancestors().nth(3).ok_or_else(|| fail("Expected the AppDev development workspace"))?;
    let scratch = crate::appdev_workflow::temporary_root(app);
    let widths = plan["widths"].as_array().ok_or_else(|| fail("Expected Decompiler touch viewports"))?;
    let height = plan["height"].as_u64().ok_or_else(|| fail("Expected a Decompiler touch viewport height"))?;
    let url = format!("http://localhost:{port}/decompiler");
    for width in widths {
        let run = (|| -> Result<()> {
            if interruption().is_some() { return Err(fail("Decompiler check interrupted")); }
            let mut browser = Chromium::launch(workspace, &scratch)?;
            browser.new_page()?;
            browser.call("CSS.enable", json!({}), true)?;
            browser.call("Emulation.setDeviceMetricsOverride", json!({"width":width,"height":height,
                "deviceScaleFactor":1,"mobile":true}), true)?;
            browser.call("Emulation.setTouchEmulationEnabled", json!({"enabled":true,"maxTouchPoints":1}), true)?;
            browser.events.clear();
            let result = browser.call("Page.navigate", json!({"url":url}), true)?;
            if result["errorText"].is_string() { return Err(fail("Chromium could not open the Decompiler")); }
            let status = browser.response_status(&url, "GET")?;
            admit(workflow, "decompiler.pagingPage", json!({"status":status}))?;
            browser.select_option(&plan["document"], string(&plan["option"])?)?;
            browser.tap(&plan["replies"])?;
            for key in ["aster", "settings"] { browser.wait_node(&plan[key], true)?; }
            let first = browser.counter(&plan["counter"])?;
            let metrics = browser.call("Page.getLayoutMetrics", json!({}), true)?;
            browser.tap(&plan["next"])?;
            let next = browser.counter(&plan["counter"])?;
            let aster = browser.visible(&plan["aster"])?;
            let settings = browser.visible(&plan["settings"])?;
            browser.tap(&plan["previous"])?;
            let previous = browser.counter(&plan["counter"])?;
            admit(workflow, "decompiler.pagingTurn", json!({"viewport":width,
                "scrollWidth":metrics["cssContentSize"]["width"],"first":first,"next":next,
                "asterVisible":aster,"settingsVisible":settings,"previous":previous}))?;
            Ok(())
        })();
        run.map_err(|error| fail(format!("Decompiler paging at {width}px: {error}")))?;
        println!("PASS: Decompiler touch paging at {width}px with Aster visible");
    }
    Ok(())
}

struct Check {
    browser: Chromium,
    token: Option<String>,
    declaration: Option<String>,
    cookie: Option<String>,
}

impl Check {
    fn step(&mut self, suite: &Evaluator, step: &Value, restoring: bool) -> Result<()> {
        let effect = string(&step["effect"])?;
        let locator = &step["locator"];
        let mut observed = Value::Null;
        let mut body = Value::Null;
        match effect {
            "issue-grant" => {
                if self.token.is_some() { return Err(fail("Expected one test grant per run")); }
                let token = Base64UrlUnpadded::encode_string(&entropy::<32>()?);
                let expires = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() + 295_000;
                let declaration = format!("{} {expires}\n", crate::rel::hash(&token));
                self.declaration = Some(declaration);
                grant("issue", self.declaration.as_deref().expect("test grant declaration"))?;
                self.token = Some(token);
            }
            "request" | "exchange-grant" => {
                let path = string(&step["path"])?;
                let exchanging = effect == "exchange-grant";
                if exchanging && path != SESSION { return Err(fail("Test grant exchange requires its dedicated endpoint")); }
                let bearer = if exchanging { Some(self.token.as_deref().ok_or_else(|| fail("Missing test grant"))?) } else { None };
                let method = if exchanging { "POST" } else { step["method"].as_str().unwrap_or("GET") };
                let reply = request(method, path, bearer, self.cookie.as_deref(), restoring)?;
                observed = json!(reply.status);
                if exchanging && reply.status == 204 {
                    self.cookie = Some(reply.cookie.ok_or_else(|| fail("The live grant did not issue a test cookie"))?);
                    self.browser.call("Storage.setCookies", json!({"cookies":[{"name":COOKIE,"value":self.cookie,
                        "url":ORIGIN,"path":"/","secure":true,"httpOnly":true,"sameSite":"Lax"}]}), false)?;
                }
                if step["verify"].is_string() && observed == step["expected"] { body = serde_json::from_slice(&reply.body)?; }
            }
            "new-page" => self.browser.new_page()?,
            "navigate" => {
                let url = endpoint(string(&step["path"])?)?;
                self.browser.events.clear();
                let result = self.browser.call("Page.navigate", json!({"url":url}), true)?;
                if result["errorText"].is_string() { return Err(fail("Chromium could not open live AppDev")); }
                observed = self.browser.response_status(url.split('#').next().unwrap_or(&url), "GET")?;
            }
            "wait" => { self.browser.wait_node(locator, step["state"] != "attached")?; }
            "click" => self.browser.click(locator)?,
            "fill" => self.browser.fill(locator, string(&step["value"])?)?,
            "submit" => {
                self.browser.events.clear();
                self.browser.click(locator)?;
                observed = self.browser.response_status(&endpoint(string(&step["path"])?)?, "POST")?;
            }
            "read-text" => observed = json!(self.browser.read_text(locator)?),
            "read-value" => observed = self.browser.value(locator)?,
            _ => return Err(fail("Unsupported Encounter browser check effect")),
        }
        if let Some(expected) = step.get("expected") {
            let label = string(&step["label"])?;
            let passed = evaluate(suite, json!({"operation":"verify","verify":step["verify"],
                "expected":expected,"actual":observed,"body":body})).map_err(|error| fail(format!("{label}: {error}")))?;
            if passed != true { return Err(fail(format!("{label}: Encounter did not admit the observation"))); }
            println!("PASS: {label}");
        }
        Ok(())
    }
}

pub(crate) fn run(app: &Path, declaration: &str, expected: &Path, active: &Path, scratch: &Path) -> Result<()> {
    let release = expected.canonicalize()?;
    if active.canonicalize()? != release { return Err(fail("The requested AppDev release is no longer active")); }
    let suite = Evaluator::load(app, declaration)?;
    let marker = hex::encode(entropy::<18>()?);
    let plan = evaluate(&suite, json!({"operation":"plan","run":marker}))?;
    if plan["capability"] != "appdev-formation" || plan["origin"] != ORIGIN {
        return Err(fail("Expected the scoped AppDev Formation browser check"));
    }
    let workspace = app.ancestors().nth(3).ok_or_else(|| fail("Expected the AppDev development workspace"))?;
    let mut check = Check { browser: Chromium::launch(workspace, scratch)?, token: None, declaration: None, cookie: None };
    check.browser.assure_stale_locator()?;
    let result = (|| -> Result<()> {
        for step in plan["steps"].as_array().ok_or_else(|| fail("Expected Encounter browser steps"))? {
            check.step(&suite, step, false).map_err(|error| {
                let effect = step["effect"].as_str().unwrap_or("step");
                let target = step["label"].as_str().or_else(|| step["locator"]["selector"].as_str()).unwrap_or("");
                fail(format!("Live browser check {effect} {target}: {error}"))
            })?;
        }
        if active.canonicalize()? != release { return Err(fail("The active AppDev release changed during the live check")); }
        Ok(())
    })();
    let cleanup = (|| -> Result<()> {
        if check.cookie.is_some() {
            for step in plan["cleanup"].as_array().ok_or_else(|| fail("Expected Encounter cleanup steps"))? {
                check.step(&suite, step, true)?;
            }
        }
        Ok(())
    })();
    let file = check.declaration.as_deref().map(|declaration| grant("revoke", declaration)).transpose();
    result?;
    cleanup?;
    file?;
    println!("{}", string(&plan["summary"])?);
    Ok(())
}
