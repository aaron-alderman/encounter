use crate::{Result, fail, http, package, process::{Meter, Programme}, rel};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque}, ffi::CStr,
    fs::File, io::{self, Read, Write}, net::{IpAddr, Ipv6Addr, ToSocketAddrs},
    os::unix::fs::MetadataExt, path::Path,
    sync::mpsc, thread, time::{Duration, Instant},
};

const LIMIT: usize = 64 * 1024;
const METER: usize = 2_000_000;
const DEADLINE: Duration = Duration::from_secs(5);

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("mcp_client.encounter").to_owned()],
        &["mcpClient.registry", "mcpClient.lookup", "mcpClient.egress", "mcpClient.metadata", "mcpClient.redirect",
            "mcpClient.addresses", "mcpClient.hosts", "mcpClient.registeredClients"],
        &BTreeSet::from(["kernel.invoke", "number.calculate", "record.entries", "text.matches", "text.trim", "value.describe"]),
        &mut Meter::new(METER))
}

fn pinned(path: &Path, pin: &str) -> Result<Value> {
    let root = File::open("/")?;
    let file = package::open_artifact(&root, path.strip_prefix("/")?)?;
    let metadata = file.metadata()?;
    if metadata.mode() & 0o027 != 0 || metadata.nlink() != 1
        || ![0, unsafe { libc::geteuid() }].contains(&metadata.uid()) {
        return Err(fail("Expected a protected MCP client configuration file"));
    }
    let mut bytes = Vec::new();
    file.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT || rel::hash(&bytes) != pin {
        return Err(fail("MCP client configuration exceeded its limit or differed from its pin"));
    }
    let value = serde_json::from_slice(&bytes)?;
    crate::compat_value::external(&value)?;
    Ok(value)
}

// Only the URL components used by the OAuth registry and its HTTPS port.
fn callback(uri: &str) -> Option<(String, Option<String>)> {
    if uri.len() > 2048 || uri.contains(['#', '\\']) || !uri.bytes().all(|byte| byte.is_ascii_graphic()) { return None; }
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let at = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(at);
    let (host, port) = if authority.starts_with('[') {
        let (host, tail) = authority.split_once(']')?;
        let address: Ipv6Addr = host.strip_prefix('[')?.parse().ok()?;
        (format!("[{address}]"), if tail.is_empty() { None } else { Some(tail.strip_prefix(':')?) })
    } else {
        let (host, port) = authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.is_empty() || !host.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)) { return None; }
        (host.to_ascii_lowercase(), port)
    };
    let loopback = scheme == "http" && matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    if scheme != "https" && !loopback { return None; }
    let default = if loopback { 80 } else { 443 };
    let port = match port { Some(port) => Some(port.parse::<u16>().ok()?).filter(|port| *port != default), None => None };
    let (path, query) = suffix.split_once('?').map_or((suffix, None), |(path, query)| (path, Some(query)));
    let mut parts = Vec::new();
    let mut segments = path.strip_prefix('/').unwrap_or(path).split('/').peekable();
    while let Some(part) = segments.next() {
        let dots = part.to_ascii_lowercase().replace("%2e", ".");
        match dots.as_str() {
            ".." => { parts.pop(); if segments.peek().is_none() { parts.push(""); } }
            "." => { if segments.peek().is_none() { parts.push(""); } }
            _ => parts.push(part),
        }
    }
    let mut path = format!("/{}", parts.join("/"));
    if let Some(query) = query { path.push('?'); path.push_str(query); }
    let base = format!("{scheme}://{host}");
    let uri = match port { Some(port) => format!("{base}:{port}{path}"), None => format!("{base}{path}") };
    Some((uri, (loopback && port.is_some()).then(|| format!("{base}{path}"))))
}

fn normalize_callbacks(document: &mut Value, key: &str) -> Result<()> {
    let urls = document.get_mut(key).and_then(Value::as_array_mut).ok_or_else(|| fail("Expected registered callback URLs"))?;
    for url in urls {
        *url = json!(callback(url.as_str().unwrap_or_default()).ok_or_else(|| fail("Invalid hosted MCP callback URL"))?.0);
    }
    Ok(())
}

pub(super) fn admit_registered_clients(mut clients: Value) -> Result<Value> {
    let rows = clients.as_array_mut().filter(|rows| (1..=32).contains(&rows.len()))
        .ok_or_else(|| fail("Invalid hosted MCP client registry"))?;
    for client in rows {
        normalize_callbacks(client, "redirectUris")
            .map_err(|_| fail("OAuth redirect URI must be HTTPS or an uncredentialed HTTP loopback URI."))?;
    }
    policy()?.run("mcpClient.registeredClients", clients, &mut Meter::new(METER))
}

pub(crate) fn read_registered_clients() -> Result<()> {
    let request = crate::platform_import_closure::read_bounded_observation(8192)?;
    let owner = request["owner"].as_u64().and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| fail("Self-hosted OAuth client owner identity is invalid."))?;
    let file = request["file"].as_str().ok_or_else(|| fail("Self-hosted OAuth client file must be an absolute path."))?;
    let custody = crate::hosted_production_manifest::policy()?;
    let bytes = crate::hosted_production_manifest::read_custody(&custody, Path::new(file), owner, LIMIT as u64)?;
    println!("{}", admit_registered_clients(crate::hosted_production_manifest::parse(&bytes)?)?);
    Ok(())
}

fn first_public_address(policy: &Programme, addresses: &[IpAddr]) -> Result<IpAddr> {
    let parts = addresses.iter().map(|address| match address {
        IpAddr::V4(address) => json!({"family":4,"number":u32::from(*address)}),
        IpAddr::V6(address) => {
            let groups = address.segments();
            json!({"family":6,"first":groups[0],"second":groups[1]})
        }
    }).collect::<Vec<_>>();
    if policy.run("mcpClient.addresses", json!(parts), &mut Meter::new(METER))? != true {
        return Err(fail("MCP client DNS contained a non-public address"));
    }
    addresses.first().copied().ok_or_else(|| fail("MCP client DNS returned no address"))
}

fn resolve_host(policy: &Programme, host: &str, deadline: Instant, worker: &mut Option<thread::JoinHandle<()>>) -> Result<IpAddr> {
    if worker.as_ref().is_some_and(|task| !task.is_finished()) {
        return Err(fail("Previous MCP client DNS resolution is still pending"));
    }
    if let Some(task) = worker.take() { let _ = task.join(); }
    let host = host.to_owned();
    let (send, receive) = mpsc::sync_channel(1);
    *worker = Some(thread::Builder::new().name("mcp-client-dns".into()).spawn(move || {
        let answers = (host.as_str(), 443).to_socket_addrs().map(|answers| answers.map(|value| value.ip()).collect::<Vec<_>>());
        let _ = send.send(answers);
    })?);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if http::stopping() || left.is_zero() { return Err(fail("MCP client DNS was interrupted or timed out")); }
        match receive.recv_timeout(left.min(Duration::from_millis(100))) {
            Ok(result) => {
                if let Some(task) = worker.take() { let _ = task.join(); }
                return first_public_address(policy, &result?);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn https_document(policy: &Programme, url: &str, host: &str, worker: &mut Option<thread::JoinHandle<()>>) -> Result<(u16, String, Value)> {
    let deadline = Instant::now() + DEADLINE;
    let address = resolve_host(policy, host, deadline, worker)?;
    pinned_https_document(url, host, (address, 443).into(), deadline, None)
}

fn pinned_https_document(url: &str, host: &str, endpoint: std::net::SocketAddr, deadline: Instant,
    trust_anchor: Option<&CStr>) -> Result<(u16, String, Value)> {
    let port = endpoint.port();
    let pinned = match endpoint.ip() { IpAddr::V4(address) => format!("{host}:{port}:{address}"),
        IpAddr::V6(address) => format!("{host}:{port}:[{address}]") };
    if !url.starts_with("https://") { return Err(fail("MCP metadata requires HTTPS")); }
    let timeout = deadline.saturating_duration_since(Instant::now());
    let response = crate::http_client::send(crate::http_client::Request {
        url, method: "GET", headers: &[("Accept", "application/json")], body: None,
        timeout, connect_timeout: timeout, limit: LIMIT, resolve: Some(&pinned), trust_anchor, restoring: false,
    })?;
    if response.status != 200 { return Err(fail("MCP client metadata requires an unredirected HTTP 200")); }
    let mime = response.content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    if mime != "application/json" { return Err(fail("MCP client metadata requires application/json")); }
    let document = serde_json::from_slice(&response.body)?;
    crate::compat_value::external(&document)?;
    Ok((response.status, mime, document))
}

fn metadata_host<'a>(policy: &Programme, id: &'a str, hosts: &Value) -> Result<&'a str> {
    let host = id.strip_prefix("https://").and_then(|rest| rest.split_once('/')).map_or("", |(host, _)| host);
    if callback(id).is_none_or(|(canonical, _)| canonical != id)
        || policy.run("mcpClient.egress", json!({"clientId":id,"host":host,"hosts":hosts}), &mut Meter::new(METER))? != true {
        return Err(fail("MCP client is outside the exact metadata host list"));
    }
    Ok(host)
}

fn metadata_document(policy: &Programme, id: &str, host: &str,
    dns: &mut Option<thread::JoinHandle<()>>) -> Result<Value> {
    let (status, mime, mut document) = https_document(policy, id, host, dns)?;
    normalize_callbacks(&mut document, "redirect_uris")?;
    policy.run("mcpClient.metadata", json!({"document":document,"clientId":id,"status":status,"mime":mime}), &mut Meter::new(METER))
}

pub(crate) fn metadata_settings() -> Result<()> {
    let hosts = read_request()?;
    crate::compat_value::external(&hosts)?;
    let result = policy()?.run("mcpClient.hosts", hosts, &mut Meter::new(METER))?;
    writeln!(io::stdout().lock(), "{result}")?;
    Ok(())
}

pub(crate) fn resolve_metadata() -> Result<()> {
    http::install_stop_signals()?;
    let mut request = read_request()?;
    crate::compat_value::external(&request)?;
    if !request.is_object() || request.as_object().map_or(0, |record| record.len()) != 2 {
        return Err(fail("Expected a fixed hosted client metadata request"));
    }
    let policy = policy()?;
    let settings = policy.run("mcpClient.hosts", request["hosts"].take(), &mut Meter::new(METER))?;
    let id = request["clientId"].as_str().filter(|id| !id.is_empty() && id.len() <= 2048)
        .ok_or_else(|| fail("Missing hosted MCP client identity"))?;
    let host = metadata_host(&policy, id, &settings["hosts"])?;
    let client = metadata_document(&policy, id, host, &mut None)?;
    if !http::stopping() { writeln!(io::stdout().lock(), "{client}")?; }
    Ok(())
}

pub(crate) struct Resolver {
    policy: Programme,
    registry: Value,
    cache: VecDeque<(String, Instant, Value)>,
    capacity: usize,
    lifetime: Duration,
    dns: Option<thread::JoinHandle<()>>,
}

#[derive(Debug)]
pub(crate) struct CallbackRefused;

impl std::fmt::Display for CallbackRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MCP callback is outside the exact client registration")
    }
}

impl std::error::Error for CallbackRefused {}

impl Resolver {
    pub(crate) fn load(clients: &Path, clients_pin: &str, hosts: &Path, hosts_pin: &str, contract: Value) -> Result<Self> {
        let policy = policy()?;
        let mut clients = pinned(clients, clients_pin)?;
        for client in clients.as_array_mut().ok_or_else(|| fail("Expected a hosted client registry"))? {
            normalize_callbacks(client, "redirectUris")?;
        }
        let registry = policy.run("mcpClient.registry", json!({"clients":clients,"hosts":pinned(hosts, hosts_pin)?,"contract":contract}),
            &mut Meter::new(METER))?;
        let bound = |key| registry[key].as_u64().ok_or_else(|| fail("Missing authored client metadata cache bound"));
        Ok(Self { policy, capacity:usize::try_from(bound("cacheEntries")?)?,
            lifetime:Duration::from_millis(bound("cacheTtlMs")?), registry, cache:VecDeque::new(), dns:None })
    }

    pub(crate) fn resolve(&mut self, input: &Value) -> Result<Value> {
        crate::compat_value::external(input)?;
        let id = input["clientId"].as_str().filter(|id| !id.is_empty() && id.len() <= 2048)
            .ok_or_else(|| fail("Missing hosted MCP client identity"))?;
        let (redirect, loopback_base) = callback(input["redirectUri"].as_str().unwrap_or_default())
            .ok_or(CallbackRefused)?;
        let evaluate = |entry, input| self.policy.run(entry, input, &mut Meter::new(METER));
        let mut client = evaluate("mcpClient.lookup", json!({"clients":self.registry["clients"],"clientId":id}))?;
        if client.is_null() {
            let host = metadata_host(&self.policy, id, &self.registry["hosts"])?;
            let now = Instant::now();
            self.cache.retain(|(_, expires, _)| *expires > now);
            if let Some((_, _, cached)) = self.cache.iter().find(|(key, _, _)| key == id) {
                client = cached.clone();
            } else {
                client = metadata_document(&self.policy, id, host, &mut self.dns)?;
                if self.cache.len() >= self.capacity { self.cache.pop_front(); }
                self.cache.push_back((id.to_owned(), Instant::now() + self.lifetime, client.clone()));
            }
        }
        if evaluate("mcpClient.redirect", json!({"client":client,"redirectUri":redirect,"loopbackBase":loopback_base}))? != true {
            return Err(CallbackRefused.into());
        }
        Ok(json!({"client":client,"redirectUri":redirect}))
    }
}

pub(crate) fn read_request() -> Result<Value> {
    let mut input = Vec::new();
    io::stdin().lock().take(8193).read_to_end(&mut input)?;
    if input.len() > 8192 { return Err(fail("MCP client lookup exceeded its size limit")); }
    Ok(serde_json::from_slice(&input)?)
}

pub(crate) fn run(clients: &Path, clients_pin: &str, hosts: &Path, hosts_pin: &str, contract: Value) -> Result<()> {
    http::install_stop_signals()?;
    let mut resolver = Resolver::load(clients, clients_pin, hosts, hosts_pin, contract)?;
    writeln!(io::stdout().lock(), "{}", resolver.resolve(&read_request()?)?)?;
    Ok(())
}

#[cfg(test)]
#[test]
fn metadata_authority_checks_the_document_and_exact_callback() -> Result<()> {
    let policy = policy()?;
    let run = |entry, input| policy.run(entry, input, &mut Meter::new(METER));
    let identity = "https://agent.example/client.json";
    let mut input = json!({"clientId":identity,"status":200,"mime":"application/json","document":{
        "client_id":identity,"client_name":" Agent ","redirect_uris":["http://127.0.0.1/oauth/callback?track=1"],
        "token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"]
    }});
    let client = run("mcpClient.metadata", input.clone())?;
    assert_eq!(client["name"], "Agent");
    let check = |redirect: &str, client: &Value| {
        let (uri, base) = callback(redirect).ok_or_else(|| fail("Invalid callback fixture"))?;
        run("mcpClient.redirect", json!({"client":client,"redirectUri":uri,"loopbackBase":base}))
    };
    assert_eq!(check("http://127.0.0.1:1435/oauth/callback?track=1", &client)?, true);
    assert_eq!(check("http://127.0.0.1:1435/oauth/callback?track=2", &client)?, false);
    let mut registered = client.clone();
    registered["registrationMode"] = json!("preRegisteredClientV1");
    assert_eq!(check("http://127.0.0.1:1435/oauth/callback?track=1", &registered)?, false);
    input["document"]["client_id"] = json!("https://foreign.example/client.json");
    assert!(run("mcpClient.metadata", input.clone()).is_err());
    input["document"]["client_id"] = json!(identity);
    input["document"]["token_endpoint_auth_method"] = json!("client_secret_basic");
    assert!(run("mcpClient.metadata", input.clone()).is_err());
    input["document"]["token_endpoint_auth_method"] = json!(null);
    input["document"]["grant_types"] = json!(["client_credentials"]);
    assert!(run("mcpClient.metadata", input).is_err());
    assert_eq!(callback("HTTPS://Agent.Example:443/a/%2e%2e/callback").unwrap().0, "https://agent.example/callback");
    Ok(())
}

#[cfg(test)]
#[test]
fn metadata_dns_rejects_mixed_private_and_public_answers() {
    let policy = policy().unwrap();
    let public = "93.184.216.34".parse::<IpAddr>().unwrap();
    assert_eq!(first_public_address(&policy, &[public]).unwrap(), public);
    for blocked in ["127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254",
        "::1", "::ffff:8.8.8.8", "fc00::2", "fe80::1", "2001:db8::1", "2002:7f00:1::1"] {
        assert!(first_public_address(&policy, &[public, blocked.parse().unwrap()]).is_err(), "{blocked}");
    }
}

#[cfg(test)]
#[test]
fn client_cache_reuses_only_current_validated_metadata() -> Result<()> {
    let id = "https://localhost/client.json";
    let redirect = "https://client.example/callback";
    let client = json!({"clientId":id,"name":"Fixture","redirectUris":[redirect],
        "registrationMode":"clientIdMetadataDocumentV1"});
    let now = Instant::now();
    let mut resolver = Resolver { policy:policy()?, registry:json!({"clients":[],"hosts":["localhost"]}),
        cache:VecDeque::from([(id.to_owned(), now + Duration::from_secs(60), client.clone())]),
        capacity:256, lifetime:Duration::from_secs(300), dns:None };
    let input = json!({"clientId":id,"redirectUri":redirect});
    assert_eq!(resolver.resolve(&input)?["client"], client);
    assert!(resolver.resolve(&json!({"clientId":id,"redirectUri":"https://client.example/foreign"})).is_err());
    assert!(resolver.dns.is_none());
    resolver.cache[0].1 = now;
    assert!(resolver.resolve(&input).is_err());
    assert!(resolver.cache.is_empty());
    Ok(())
}

#[cfg(test)]
#[test]
#[ignore = "requires a disposable TLS fixture"]
fn pinned_tls_reads_bounded_metadata_and_checks_peer_identity() -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let port: u16 = std::env::var("SOURCERY_MCP_TEST_TLS_PORT")?.parse()?;
    let trust_path = std::env::var_os("SOURCERY_MCP_TEST_TLS_CA").ok_or_else(|| fail("Missing disposable TLS certificate"))?;
    let trust_anchor = CString::new(trust_path.as_os_str().as_bytes())?;
    let request = |host, path| pinned_https_document(&format!("https://{host}:{port}{path}"), host,
        (std::net::Ipv4Addr::LOCALHOST, port).into(), Instant::now() + DEADLINE, Some(&trust_anchor));
    let (status, mime, document) = request("oauth-fixture.invalid", "/client")?;
    assert_eq!(status, 200);
    assert_eq!(mime, "application/json");
    assert_eq!(document["client_name"], "Fixture TLS");
    assert!(request("wrong-fixture.invalid", "/client").is_err());
    assert!(request("oauth-fixture.invalid", "/redirect").is_err());
    assert!(request("oauth-fixture.invalid", "/overflow").is_err());
    assert!(request("oauth-fixture.invalid", "/mime").is_err());
    Ok(())
}
