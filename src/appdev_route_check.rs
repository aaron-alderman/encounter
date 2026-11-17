use crate::{Result, appdev_host_process::Supervisor, command::Evaluator, fail, http_client};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    port: u16,
    certificate: Option<std::path::PathBuf>,
    member: String,
    steward: String,
    work: String,
    steward_email: String,
    workspace_port: Option<u16>,
    applications: Option<ApplicationFixture>,
    identity: Option<IdentityFixture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFixture {
    port: u16,
    authorization: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplicationFixture {
    game_port: u16,
    game: String,
    store: String,
    north: String,
}

impl Fixture {
    fn headers(&self, actor: &str) -> Result<Vec<(&str, &str)>> {
        Ok(match actor {
            "anonymous" => vec![],
            "member" => vec![("Cookie", &self.member)],
            "steward" => vec![("Cookie", &self.steward)],
            "work" => vec![("Cookie", &self.work)],
            "forged-header" => vec![("X-Temple-Email", &self.steward_email)],
            "game" | "store" | "north" => {
                let apps = self.applications.as_ref().ok_or_else(|| fail("Missing application fixture sessions"))?;
                let cookie = match actor { "game" => &apps.game, "store" => &apps.store, _ => &apps.north };
                vec![("Cookie", cookie)]
            }
            _ => return Err(fail("Unknown workspace fixture identity")),
        })
    }
}

pub(crate) fn run(app: &Path, phase: &str) -> Result<()> {
    let mut supervisor = Supervisor::new();
    let fixture: Fixture = serde_json::from_value(crate::platform_import_closure::read_bounded_observation(32_768)?)?;
    let policy = Evaluator::load(app, "release/workflow.rel")?;
    if matches!(phase, "index" | "application-files" | "north-changed" | "files-revoked") {
        return check_index(&mut supervisor, &fixture, &policy, phase);
    }
    let plan = policy.run("routeParity.plan", json!(phase))?;
    let probes = plan.as_array().ok_or_else(|| fail("Expected a workspace route probe plan"))?;
    let port = fixture.port;
    let loopback_authority = format!("127.0.0.1:{port}");
    let (origin, front, resolution) = if fixture.certificate.is_some() {
        ("https://appdev-assurance.test".to_owned(), format!("https://appdev-assurance.test:{port}"),
            Some(format!("appdev-assurance.test:{port}:127.0.0.1")))
    } else {
        let address = format!("http://{loopback_authority}");
        (address.clone(), address, None)
    };
    let anchor = fixture.certificate.as_ref().map(|path| CString::new(path.as_os_str().as_bytes())).transpose()?;
    for probe in probes {
        supervisor.check()?;
        let path = probe[0].as_str().filter(|path| path.starts_with('/') && !path.starts_with("//"))
            .ok_or_else(|| fail("Expected a fixture route path"))?;
        let mut headers = fixture.headers(probe[1].as_str().unwrap_or_default())?;
        let options = &probe[7];
        let identity_address;
        let (address, resolution, anchor) = match options["endpoint"].as_str() {
            Some("identity") if path == "/identity-management/workspace-access" => {
                let identity = fixture.identity.as_ref().ok_or_else(|| fail("Missing identity route fixture"))?;
                identity_address = format!("http://127.0.0.1:{}", identity.port);
                headers.push(("Host", &loopback_authority));
                if options["broker"] == true {
                    headers.push(("Authorization", &identity.authorization));
                }
                (identity_address.as_str(), None, None)
            }
            None => {
                if resolution.is_some() { headers.push(("Host", "appdev-assurance.test")); }
                (front.as_str(), resolution.as_deref(), anchor.as_deref())
            }
            _ => return Err(fail("Unknown workspace route verification endpoint")),
        };
        let form = match probe[4].as_str() {
            Some("/workspace/work") => Some(b"environment=%2Fworkspace%2Fwork".as_slice()),
            Some("/workspace/platform") => Some(b"environment=%2Fworkspace%2Fplatform".as_slice()),
            None => None,
            _ => return Err(fail("Unknown workspace preference fixture")),
        };
        if form.is_some() {
            headers.push(("Content-Type", "application/x-www-form-urlencoded"));
            headers.push(("Origin", probe[5].as_str().unwrap_or(&origin)));
        }
        if options["origin"] == true { headers.push(("Origin", &origin)); }
        let method = options["method"].as_str().unwrap_or(if form.is_some() { "POST" } else { "GET" });
        if !matches!(method, "GET" | "POST") { return Err(fail("Unknown workspace route probe method")); }
        if method == "POST" && form.is_none() { headers.push(("Content-Length", "0")); }
        let reply = http_client::send(http_client::Request {
            url: &format!("{address}{path}"), method, headers: &headers, body: form,
            timeout: Duration::from_secs(8), connect_timeout: Duration::from_secs(2),
            limit: 8 * 1024 * 1024, resolve: resolution, trust_anchor: anchor, restoring: false,
        })?;
        let body = if probe[6].is_array() || options["body"].is_string() {
            Some(std::str::from_utf8(&reply.body)?)
        } else { None };
        let evidence = json!({"probe":probe,"status":reply.status,
            "locations":reply.header_values("Location").collect::<Vec<_>>(),"body":body});
        if let Err(error) = policy.run("routeParity.check", evidence) {
            return Err(fail(format!("{path} returned HTTP {}: {error}", reply.status)));
        }
    }
    Ok(())
}

fn check_index(supervisor: &mut Supervisor, fixture: &Fixture, policy: &Evaluator, phase: &str) -> Result<()> {
    let port = fixture.workspace_port.ok_or_else(|| fail("Missing workspace file fixture port"))?;
    let host = format!("127.0.0.1:{}", fixture.port);
    let origin = if fixture.certificate.is_some() { "https://appdev-assurance.test".into() } else { format!("http://{host}") };
    let plan = if phase == "index" { policy.run("routeParity.indexPlan", Value::Null)? }
        else { policy.run("routeParity.applicationFiles", json!(phase))? };
    let mut state = Value::Null;
    let duplicate = format!("{}; {}", fixture.steward, fixture.steward);
    for probe in plan.as_array().ok_or_else(|| fail("Expected a workspace file probe plan"))? {
        supervisor.check()?;
        let name = probe["check"].as_str().ok_or_else(|| fail("Expected a named workspace file probe"))?;
        let apps = fixture.applications.as_ref();
        let endpoint = probe["endpoint"].as_str().unwrap_or("index");
        let (address, resolution, anchor, request_host) = match endpoint {
            "index" => (format!("http://127.0.0.1:{port}"), None, None, host.as_str()),
            "game" => {
                let port = apps.ok_or_else(|| fail("Missing Game fixture gateway"))?.game_port;
                (format!("http://127.0.0.1:{port}"), None, None, host.as_str())
            }
            "front" if fixture.certificate.is_some() => {
                let port = fixture.port;
                let anchor = fixture.certificate.as_ref().map(|path| CString::new(path.as_os_str().as_bytes())).transpose()?;
                (format!("https://appdev-assurance.test:{port}"), Some(format!("appdev-assurance.test:{port}:127.0.0.1")),
                    anchor, "appdev-assurance.test")
            }
            "front" => (format!("http://{host}"), None, None, host.as_str()),
            _ => return Err(fail("Unknown workspace verification endpoint")),
        };
        let media = probe["media"] == true;
        let mut path = probe["path"].as_str().unwrap_or(if media { "/workspace/file-media" } else { "/workspace/files" }).to_owned();
        if !path.starts_with('/') || path.starts_with("//") { return Err(fail("Invalid workspace verification path")); }
        let file_key = if media { Some("movie") } else if probe["file"] == true { Some("manifest") } else { probe["fileKey"].as_str() };
        if let Some(key) = file_key {
            let id = state[key].as_str().filter(|id| id.len() == 64
                && id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
                .ok_or_else(|| fail("Expected a workspace file fixture identifier"))?;
            path.push_str("?file=");
            path.push_str(id);
        }
        for field in ["query", "suffix"] {
            if let Some(value) = probe[field].as_str() { path.push_str(value); }
        }
        let actor = probe["actor"].as_str().unwrap_or_default();
        let combined;
        let mut headers = match actor {
            "duplicate-steward" => vec![("Cookie", duplicate.as_str())],
            "duplicate-game" | "combined" => {
                let apps = apps.ok_or_else(|| fail("Missing application fixture sessions"))?;
                combined = if actor == "duplicate-game" { format!("{}; {}", apps.game, apps.game) }
                    else { [&fixture.steward, &apps.game, &apps.store, &apps.north].map(String::as_str).join("; ") };
                vec![("Cookie", combined.as_str())]
            }
            _ => fixture.headers(actor)?,
        };
        headers.push(("Host", request_host));
        if probe["crossSite"] == true { headers.push(("Sec-Fetch-Site", "cross-site")); }
        if probe["range"] == true { headers.push(("Range", "bytes=999999999-")); }
        let post = probe["post"] == true;
        if post { headers.push(("Origin", &origin)); }
        let reply = http_client::send(http_client::Request {
            url: &format!("{address}{path}"), method: if post { "POST" } else { "GET" },
            headers: &headers, body: post.then_some(b""), timeout: Duration::from_secs(8),
            connect_timeout: Duration::from_secs(2), limit: 8 * 1024 * 1024, resolve: resolution.as_deref(),
            trust_anchor: anchor.as_deref(), restoring: false,
        })?;
        let body: Value = if probe["markup"].is_string() { json!(std::str::from_utf8(&reply.body)?) }
        else if endpoint == "index" && !media && probe["status"].as_u64().is_none_or(|status| status == 200) {
            serde_json::from_slice(&reply.body).map_err(|_| fail(format!("Invalid workspace file response for {name}")))?
        } else { Value::Null };
        state = policy.run("routeParity.indexObservation", json!({"probe":probe,"state":state,"status":reply.status,
            "cache":reply.header_values("Cache-Control").collect::<Vec<_>>(),"body":body}))
            .map_err(|error| fail(format!("Workspace file probe {name} returned HTTP {}: {error}", reply.status)))?;
    }
    Ok(())
}
