use crate::{Result, appdev_host_process::Scratch, command::Evaluator, fail, http, rel};
use base64ct::{Base64, Encoding};
use flate2::read::GzDecoder;
use pcre2::bytes::Regex;
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 12_000_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);
const REPLAY_TIMEOUT: Duration = Duration::from_secs(15);

fn unpack(compressed: &[u8], pin: &Value, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    GzDecoder::new(compressed).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit || *pin != rel::hash(&bytes) {
        return Err(fail("Replay artifact differs from the reviewed manifest"));
    }
    Ok(bytes)
}

fn write(directory: &Path, name: &str, bytes: impl AsRef<[u8]>, mode: u32) -> Result<PathBuf> {
    let path = directory.join(name);
    fs::OpenOptions::new().create_new(true).write(true).mode(mode).open(&path)?.write_all(bytes.as_ref())?;
    Ok(path)
}

fn directory(path: &Path) -> Result<()> {
    Ok(fs::DirBuilder::new().mode(0o700).create(path)?)
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn output_lines(reader: impl Read + Send + 'static, prefixes: &'static [&'static str])
    -> Receiver<String>
{
    let (send, receive) = mpsc::sync_channel(8);
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let mut line = Vec::new();
            match reader.by_ref().take(MAX_OUTPUT as u64 + 1).read_until(b'\n', &mut line) {
                Ok(1..=MAX_OUTPUT) => {}
                _ => break,
            }
            let Ok(line) = String::from_utf8(line) else { break };
            if prefixes.iter().any(|prefix| line.starts_with(prefix)) && send.send(line).is_err() {
                break;
            }
        }
    });
    receive
}

struct ReplayHttp {
    port: u16,
    credential: String,
    cookie: Option<String>,
}

impl ReplayHttp {
    fn request(&mut self, target: &str, body: Option<&str>) -> Result<String> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let mut stream = TcpStream::connect_timeout(&addr, REQUEST_TIMEOUT)?;
        stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
        let method = if body.is_some() { "POST" } else { "GET" };
        write!(stream, "{method} {target} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nAuthorization: Basic {}\r\nConnection: close\r\n", self.credential)?;
        if let Some(cookie) = &self.cookie {
            write!(stream, "Cookie: {cookie}\r\n")?;
        }
        if let Some(body) = body {
            write!(stream, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len())?;
        } else {
            stream.write_all(b"\r\n")?;
        }
        let mut reader = BufReader::new(stream);
        let (status, headers) = http::read_header_lines(&mut reader)?;
        if status.split_ascii_whitespace().nth(1) != Some("200") {
            return Err(fail(format!("Replay request returned {status}")));
        }
        let mut length = None;
        for (name, value) in headers {
            match name.as_str() {
                "content-length" if length.is_none() => length = Some(value.parse::<usize>()?),
                "content-length" | "transfer-encoding" => return Err(fail("Unexpected replay response framing")),
                "set-cookie" => {
                    self.cookie = value.split(';').next().map(str::to_owned);
                }
                _ => {}
            }
        }
        let length = length.filter(|length| *length <= MAX_OUTPUT)
            .ok_or_else(|| fail("Replay response has an invalid length"))?;
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        Ok(String::from_utf8(bytes)?)
    }
}

struct Forms {
    forms: Regex,
    inputs: Regex,
    attributes: Regex,
    target: Regex,
}

impl Forms {
    fn new() -> Result<Self> {
        Ok(Self {
            forms: Regex::new(r"(?s)<form\b([^>]*)>(.*?)</form>")?,
            inputs: Regex::new(r"<input\b([^>]*)>")?,
            attributes: Regex::new(r#"([\w-]+)="([^"]*)""#)?,
            target: Regex::new(r"\A/(?:\?task=[A-Za-z0-9_.-]+)?\z")?,
        })
    }

    fn select(&self, html: &str, step: &Value) -> Result<(String, String)> {
        let action = text(&step["action"])?;
        for form in self.forms.captures_iter(html.as_bytes()) {
            let form = form?;
            let mut body = serde_json::Map::new();
            for input in self.inputs.captures_iter(&form[2]) {
                let input = input?;
                let attributes = self.attributes(&input[1])?;
                if attributes.get("type").map(String::as_str) == Some("hidden") {
                    let name = attributes.get("name").ok_or_else(|| fail("Expected replay form field name"))?;
                    let value = attributes.get("value").ok_or_else(|| fail("Expected replay form field value"))?;
                    body.insert(name.clone(), json!(value));
                }
            }
            if body.get("action").and_then(Value::as_str) != Some(action)
                || (step["scope"].is_string() && body.get("scope") != step.get("scope")) {
                continue;
            }
            let target = self.attributes(&form[1])?.remove("action")
                .ok_or_else(|| fail("Expected a replay form target"))?;
            if !self.target.is_match(target.as_bytes())? {
                return Err(fail("Replay form target must remain on its private listener"));
            }
            body.extend(step["fields"].as_object().ok_or_else(|| fail("Expected replay form fields"))?.clone());
            let mut encoded = form_urlencoded::Serializer::new(String::new());
            for (name, value) in &body {
                encoded.append_pair(name, text(value)?);
            }
            return Ok((target, encoded.finish()));
        }
        Err(fail(format!("Expected a North River form for {action}")))
    }

    fn attributes(&self, html: &[u8]) -> Result<std::collections::BTreeMap<String, String>> {
        self.attributes.captures_iter(html).map(|row| {
            let row = row?;
            Ok((std::str::from_utf8(&row[1])?.into(), std::str::from_utf8(&row[2])?.into()))
        }).collect()
    }
}

fn list(value: &Value) -> Result<&[Value]> {
    value.as_array().map(Vec::as_slice).ok_or_else(|| fail("Expected a recorded replay sequence"))
}

fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| fail("Expected recorded replay text"))
}

fn replay(app: &Evaluator, arm_dir: &Path, executable: &Path, image: &Path, capture: &Value,
    run: &Value) -> Result<Value>
{
    let store = arm_dir.join("store");
    directory(&store)?;
    let mut random = [0; 32];
    getrandom::getrandom(&mut random).map_err(|error| fail(error.to_string()))?;
    let credential = Base64::encode_string(format!("replay-owner:{}", hex::encode(random)).as_bytes());
    let operators = write(arm_dir, "operators.rel", format!(
        "(\"operators\", \"version\", \"encounter/operators/1\")\n(\"replay-owner\", \"role\", \"author\")\n(\"replay-owner\", \"basicSha256\", \"{}\")\n",
        rel::hash(&credential)), 0o600)?;
    let launch = [
        ("version", "encounter/launch/1"), ("mode", "image"),
        ("image", image.to_str().ok_or_else(|| fail("Expected replay image path"))?),
        ("sha256", text(&capture["image"])?),
        ("store", store.to_str().ok_or_else(|| fail("Expected replay store path"))?),
        ("port", "0"), ("operators", operators.to_str().ok_or_else(|| fail("Expected replay operator path"))?),
        ("liveModel", "ollama-loopback"),
    ].into_iter().map(|(key, value)| format!("(\"launch\", \"{key}\", {})\n", rel::quote(value))).collect::<String>();
    let launch = write(arm_dir, "launch.rel", launch, 0o600)?;
    let rejected = write(arm_dir, "rejected.rel", rel::encode_ordered(&capture["rejected"], "EncounterModelReplay")?, 0o600)?;
    let selection = write(arm_dir, "selection.rel", rel::encode_ordered(&run["selected"]["ids"], "EncounterModelContext")?, 0o600)?;
    let repair = write(arm_dir, "repair.rel", rel::encode_ordered(&json!({
        "reply":run["reply"], "promptSha256":rel::hash(text(&run["prompt"])?)
    }), "EncounterOfflineRepair")?, 0o600)?;

    let mut child = ChildGuard(Command::new(executable).arg("--config").arg(launch).arg("serve")
        .current_dir(arm_dir).env_clear().env("PATH", "/usr/bin:/bin").env("LANG", "C.UTF-8")
        .env("ENCOUNTER_TEST_MODEL_REPLAY", rejected).env("ENCOUNTER_TEST_MODEL_CONTEXT", selection)
        .env("ENCOUNTER_TEST_OFFLINE_REPAIR", repair).env("ENCOUNTER_TEST_REPAIR_TRACE", "1")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let stdout = output_lines(child.0.stdout.take().expect("piped replay stdout"), &["Encounter "]);
    let stderr = output_lines(child.0.stderr.take().expect("piped replay stderr"), &["repair-trace ", "live delivery:"]);
    let address = stdout.recv_timeout(REPLAY_TIMEOUT)?;
    let port = address.trim().strip_prefix("Encounter http://127.0.0.1:")
        .ok_or_else(|| fail("Expected private replay listener"))?.parse::<u16>()?;
    if port < 1024 { return Err(fail("Expected an unprivileged replay listener")); }
    let mut client = ReplayHttp { port, credential, cookie: None };
    let mut html = client.request("/", None)?;
    let steps = app.run("evaluation.replayPlan", capture["objective"].clone())?;
    let forms = Forms::new()?;
    for step in list(&steps)? {
        let (target, body) = forms.select(&html, step)?;
        html = client.request(&target, Some(&body))?;
    }
    let deadline = Instant::now() + REPLAY_TIMEOUT;
    let mut observed: Vec<Value> = Vec::new();
    for _ in 0..2 {
        let row = stderr.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
        if let Some(trace) = row.strip_prefix("repair-trace ") {
            observed.push(serde_json::from_str(trace)?);
        } else {
            return Err(fail(row.trim().chars().take(600).collect::<String>()));
        }
    }
    while let Ok(row) = stderr.try_recv() {
        if let Some(trace) = row.strip_prefix("repair-trace ") {
            observed.push(serde_json::from_str(trace)?);
        } else {
            return Err(fail(row.trim().chars().take(600).collect::<String>()));
        }
    }
    let html = client.request("/", None)?;
    app.run("evaluation.compareReplay", json!({"arm":run["arm"], "recorded":run["traces"], "observed":observed,
        "outcome":run["outcome"], "page":html}))
}

pub fn verify<'a>(app: &Evaluator, manifest_pin: &str, read: impl Fn(&str) -> Result<&'a [u8]>) -> Result<Value> {
    let manifest = read("manifest.rel")?;
    if rel::hash(manifest) != manifest_pin {
        return Err(fail("Replay manifest differs from its reviewed pin"));
    }
    let manifest = rel::decode(std::str::from_utf8(manifest)?, "NorthRiverTraceManifest")?;
    let image = unpack(read("image.gz")?, &manifest["image"], 64_000_000)?;
    let runtime = unpack(read("runtime.gz")?, &manifest["runtime"], 32_000_000)?;
    let raw = unpack(read("trace.gz")?, &manifest["trace"], 32_000_000)?;
    let capture = rel::decode(std::str::from_utf8(&raw)?, "NorthRiverPageRankReplay")?;
    let runs = list(&capture["runs"])?;
    let order = runs.iter().map(|run| text(&run["arm"])).collect::<Result<Vec<_>>>()?;
    let counts = runs.iter().map(|run| list(&run["traces"])?.iter()
        .map(|phase| Ok(list(&phase["trace"]["events"])?.len())).collect::<Result<Vec<_>>>())
        .collect::<Result<Vec<_>>>()?;
    if capture["image"] != manifest["image"] || capture["runtime"] != manifest["runtime"]
        || capture["order"] != json!(order) || manifest["eventCounts"] != json!(counts)
        || !matches!(order.as_slice(), ["lexical", "pagerank"] | ["pagerank", "lexical"])
    {
        return Err(fail("Replay capture differs from its reviewed manifest"));
    }
    let scratch = Scratch::create(&env::temp_dir(), "north-river-replay-")?;
    let executable = write(scratch.path(), "encounter", runtime, 0o700)?;
    let image = write(scratch.path(), "repair-image.rel", image, 0o600)?;
    let mut results = Vec::new();
    for (run, arm) in runs.iter().zip(order) {
        let arm_dir = scratch.path().join(arm);
        directory(&arm_dir)?;
        results.push(replay(app, &arm_dir, &executable, &image, &capture, run).unwrap_or_else(|error| {
            let error = error.to_string().chars().take(600).collect::<String>();
            json!({"arm":arm, "status":"error", "deliveries":[], "normalized":[], "effects":[],
                "mismatch":null, "error":error})
        }));
    }
    Ok(json!({"results":results, "manifestPin":manifest_pin}))
}
