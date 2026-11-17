use crate::{Result, fail, http::{self, LoopbackReply}, process::{Meter, Programme}, server_temple_capsule};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, BTreeSet}, fs, io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}}, path::Path,
    time::{Duration, Instant, SystemTime}};

struct Endpoint {
    authority: String,
    target: String,
    peers: Vec<SocketAddr>,
}

impl Endpoint {
    fn parse(url: &str) -> Result<Self> {
        let url = url.strip_prefix("http://").ok_or_else(|| fail("Expected a loopback HTTP readiness URL"))?;
        let end = url.find(['/', '?']).unwrap_or(url.len());
        let (authority, target) = url.split_at(end);
        let (host, port) = match authority.strip_prefix("[::1]") {
            Some("") => ("[::1]", None),
            Some(suffix) => ("[::1]", Some(suffix.strip_prefix(':').ok_or_else(|| fail("Invalid loopback authority"))?)),
            None => authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port))),
        };
        let ips: &[IpAddr] = match host {
            "127.0.0.1" => &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "[::1]" => &[IpAddr::V6(Ipv6Addr::LOCALHOST)],
            "localhost" => &[IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)],
            _ => return Err(fail("Expected a loopback HTTP readiness host")),
        };
        let port = port.map(|port| port.parse::<u16>()).transpose()?.unwrap_or(80);
        if port == 0 || !target.bytes().all(|byte| byte.is_ascii_graphic() && !b"\\#".contains(&byte)) {
            return Err(fail("Invalid Server Temple readiness URL"));
        }
        let authority = if port == 80 { host.to_owned() } else { format!("{host}:{port}") };
        let target = if target.starts_with('/') { target.to_owned() } else { format!("/{target}") };
        Ok(Self { authority, target, peers:ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect() })
    }

    fn observe(&self, timeout: Duration, body: bool) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", self.target, self.authority);
        let deadline = Instant::now() + timeout;
        let mut reply = None;
        let mut failure = None;
        for peer in &self.peers {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { break; }
            match LoopbackReply::open_addr(*peer, request.as_bytes(), remaining) {
                Ok(connection) => { reply = Some(connection); break; }
                Err(error) => failure = Some(error),
            }
        }
        let mut reply = reply.ok_or_else(|| failure.unwrap_or_else(|| fail("Server Temple readiness connection timed out")))?;
        let (line, headers) = http::read_header_lines(&mut reply)?;
        let mut fields = line.splitn(3, ' ');
        let version = fields.next();
        let status: u16 = fields.next().filter(|code| code.len() == 3)
            .ok_or_else(|| fail("Invalid Server Temple HTTP status"))?.parse()?;
        if !matches!(version, Some("HTTP/1.0" | "HTTP/1.1")) || !(200..=599).contains(&status)
            || (300..=399).contains(&status) && http::single_header(&headers, "location")?.is_some() {
            return Err(fail("Server Temple readiness refused the HTTP status or redirect"));
        }
        let mut bytes = Vec::new();
        if body && status == 200 {
            const LIMIT: u64 = 64 * 1024;
            let length = http::single_header(&headers, "content-length")?;
            let transfer = http::single_header(&headers, "transfer-encoding")?;
            match (length, transfer) {
                (None, Some(transfer)) if transfer.eq_ignore_ascii_case("chunked") =>
                    http::copy_chunked(&mut reply, &mut bytes, LIMIT, false)?,
                (Some(length), None) => {
                    let length: u64 = length.parse()?;
                    if length > LIMIT { return Err(fail("Server Temple transit readiness body exceeded its limit")); }
                    http::copy_exact(&mut reply, &mut bytes, length)?;
                }
                (None, None) => {
                    reply.take(LIMIT + 1).read_to_end(&mut bytes)?;
                    if bytes.len() as u64 > LIMIT { return Err(fail("Server Temple transit readiness body exceeded its limit")); }
                }
                _ => return Err(fail("Invalid Server Temple transit response framing")),
            }
        }
        Ok((status, headers, bytes))
    }
}

fn config(path: &Path) -> Result<Value> {
    const LIMIT: u64 = 64 * 1024;
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() { return Err(fail("Expected a regular Server Temple host configuration")); }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT { return Err(fail("Server Temple configuration exceeded its size limit")); }
    let config = serde_json::from_slice(&bytes)?;
    crate::compat_value::external(&config)?;
    Ok(config)
}

pub(crate) fn install(artifact: &Path, config_path: &Path, drop_in_path: &Path) -> Result<()> {
    use crate::appdev_host_process::{Scratch, exchange_paths, rename_new_path};
    let input = crate::platform_import_closure::read_bounded_observation(4096)?;
    let options = input.as_object().ok_or_else(|| fail("Expected Server Temple installer options"))?;
    if options.keys().any(|key| !matches!(key.as_str(), "endpoint" | "timeoutMs" | "intervalMs")) {
        return Err(fail("Unknown Server Temple installer option"));
    }
    let endpoint = match options.get("endpoint") {
        Some(value) => value.as_str().ok_or_else(|| fail("Expected a Server Temple readiness URL"))?,
        None => "http://127.0.0.1:8140/mcp",
    };
    for path in [artifact, config_path] {
        if path.canonicalize()? != path { return Err(fail("Expected a canonical Server Temple installation path")); }
    }
    let config_parent = config_path.parent().ok_or_else(|| fail("Expected a configuration directory"))?;
    let unit_parent = drop_in_path.parent().ok_or_else(|| fail("Expected a systemd drop-in directory"))?;
    if unit_parent.canonicalize()? != unit_parent || config_path == drop_in_path {
        return Err(fail("Expected a distinct canonical Server Temple drop-in path"));
    }
    let parents = BTreeSet::from([config_parent, unit_parent]);
    let mut locks = Vec::new();
    for parent in parents {
        let directory = fs::File::open(parent)?;
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(fail("Server Temple installation directory is busy"));
        }
        locks.push(directory);
    }
    let mut runtime = crate::package::open_artifact(&fs::File::open(artifact)?, Path::new("encounter"))?;
    crate::package::require_native_runtime_file(&mut runtime)?;
    let installed = runtime.metadata()?;
    let running = fs::metadata("/proc/self/exe")?;
    if installed.dev() != running.dev() || installed.ino() != running.ino() || installed.mode() & 0o022 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&installed.uid()) {
        return Err(fail("Run the installer using the protected Encounter executable in the artifact"));
    }
    let mut meter = Meter::new(20_000_000);
    let policy = Programme::admit_entries(&[
        include_str!("server_temple_readiness.encounter").to_owned(),
        include_str!("server_temple_application.encounter").to_owned(),
        include_str!("server_temple_checkpoint.encounter").to_owned(),
    ], &["templeReadiness.install", "templeReadiness.configure"],
        &BTreeSet::from(["kernel.invoke", "number.calculate", "number.isNatural", "number.parse", "record.entries",
            "record.put", "text.lowerCase", "text.matches", "text.startsWith", "value.describe", "value.type"]), &mut meter)?;
    let plan = policy.run("templeReadiness.install", json!({
        "artifact":artifact, "configPath":config_path, "dropInPath":drop_in_path, "config":config(config_path)?,
        "endpoint":endpoint,
        "timeoutMs":input.get("timeoutMs").cloned().unwrap_or(json!(30000)),
        "intervalMs":input.get("intervalMs").cloned().unwrap_or(json!(250)),
    }), &mut meter)?;
    let readiness = policy.run("templeReadiness.configure", plan["config"].clone(), &mut meter)?;
    Endpoint::parse(readiness["url"].as_str().ok_or_else(|| fail("Expected a Server Temple readiness URL"))?)?;
    crate::server_temple_application::Application::admit(&plan["application"])?;
    let existing_unit = match drop_in_path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
        _ => return Err(fail("Expected a regular systemd drop-in file")),
    };
    let config_stage = Scratch::create(config_parent, ".temple-config-")?;
    let unit_stage = Scratch::create(unit_parent, ".temple-unit-")?;
    let stage = |scratch: &Scratch, bytes: &[u8], mode, owner: Option<(u32, u32)>| -> Result<_> {
        let path = scratch.path().join("next");
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        file.write_all(bytes)?;
        if let Some((uid, gid)) = owner {
            let metadata = file.metadata()?;
            if (metadata.uid(), metadata.gid()) != (uid, gid)
                && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        Ok(path)
    };
    let metadata = config_path.metadata()?;
    let config_file = stage(&config_stage, format!("{}\n", serde_json::to_string_pretty(&plan["config"])?).as_bytes(),
        metadata.mode() & 0o777, Some((metadata.uid(), metadata.gid())))?;
    let unit = plan["dropIn"].as_str().ok_or_else(|| fail("Expected a Server Temple systemd drop-in"))?;
    let unit_file = stage(&unit_stage, unit.as_bytes(), 0o644, None)?;
    exchange_paths(&config_file, config_path)?;
    let published = if existing_unit { exchange_paths(&unit_file, drop_in_path) }
        else { rename_new_path(&unit_file, drop_in_path) };
    if let Err(error) = published {
        if let Err(rollback) = exchange_paths(&config_file, config_path) {
            let retained = config_stage.retain();
            return Err(fail(format!("{error}. Configuration rollback failed ({rollback}); prior file retained at {}", retained.display())));
        }
        return Err(error);
    }
    for directory in locks { directory.sync_all()?; }
    println!("{}", json!({"protocol":"sourcery/server-temple-readiness-installation.v1", "artifactRoot":artifact,
        "configFile":config_path, "dropInFile":drop_in_path, "readiness":plan["config"]["readiness"]}));
    Ok(())
}

pub(crate) fn run(path: &Path) -> Result<()> {
    http::install_stop_signals()?;
    let mut meter = Meter::new(20_000_000);
    let policy = Programme::admit_entries(&[include_str!("server_temple_readiness.encounter").to_owned()],
        &["templeReadiness.configure", "templeReadiness.capsule", "templeReadiness.endpoint",
            "templeReadiness.transit", "templeReadiness.receipt"],
        &BTreeSet::from(["number.calculate", "number.isNatural", "number.parse", "record.entries",
            "record.put", "text.lowerCase", "text.matches", "value.describe", "value.type"]), &mut meter)?;
    let mut run = |entry, input| policy.run(entry, input, &mut meter);
    let plan = run("templeReadiness.configure", config(path)?)?;
    let required = |key| plan[key].as_str().ok_or_else(|| fail("Expected Server Temple readiness text"));
    let timing = |key| plan[key].as_u64().map(Duration::from_millis)
        .ok_or_else(|| fail("Expected Server Temple readiness timing"));
    let endpoint = Endpoint::parse(required("url")?)?;
    let transit = plan["transit"].as_str().map(Endpoint::parse).transpose()?;
    let capsule = server_temple_capsule::inspect(Path::new(required("capsuleFile")?))?;
    run("templeReadiness.capsule", json!({"capsule":capsule,"templeId":required("templeId")?}))?;
    let expected_headers = plan["expectedHeaders"].as_object().ok_or_else(|| fail("Expected Server Temple readiness headers"))?;
    let timeout = timing("timeoutMs")?;
    let interval = timing("intervalMs")?;
    let started = Instant::now();
    let deadline = started + timeout;
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let mut attempts = 0;
    while !http::stopping() && !remaining().is_zero() {
        attempts += 1;
        let observation = endpoint.observe(remaining().min(Duration::from_secs(5)), false);
        if let Ok((status, headers, _)) = observation {
            let headers = expected_headers.keys().map(|name| {
                let values = headers.iter().filter(|(key, _)| key == name).map(|(_, value)| value.as_str()).collect::<Vec<_>>();
                (name, (!values.is_empty()).then(|| values.join(", ")))
            }).collect::<BTreeMap<_, _>>();
            let mut observation = json!({"status":status,"headers":headers});
            if run("templeReadiness.endpoint", json!({"plan":plan,"observation":observation}))? == true {
                let mut ready = transit.is_none();
                if let Some(transit) = &transit && !remaining().is_zero()
                    && let Ok((status, _, bytes)) = transit.observe(remaining().min(Duration::from_secs(5)), true) {
                    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    observation["transport"] = json!({"status":status,"templeId":body["templeId"],"manifestHash":body["manifestHash"]});
                    ready = run("templeReadiness.transit", json!({"capsule":capsule,"observation":observation["transport"]}))? == true;
                }
                if ready && !http::stopping() {
                    let receipt = run("templeReadiness.receipt", json!({"capsule":capsule,
                        "endpoint":format!("http://{}{}", endpoint.authority, endpoint.target), "attempts":attempts,
                        "readyAt":DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
                        "elapsedMs":started.elapsed().as_millis(),"observation":observation}))?;
                    writeln!(io::stdout().lock(), "{receipt}")?;
                    return Ok(());
                }
            }
        }
        let wait = Instant::now() + interval.min(remaining());
        while !http::stopping() && Instant::now() < wait {
            std::thread::sleep(wait.saturating_duration_since(Instant::now()).min(Duration::from_millis(25)));
        }
    }
    Err(fail(if http::stopping() { "Server Temple readiness interrupted" } else { "Server Temple readiness timed out" }))
}

#[cfg(test)]
#[test]
fn readiness_endpoints_accept_only_loopback_http() -> Result<()> {
    let endpoint = Endpoint::parse("http://localhost:8140/mcp?ready=1")?;
    assert_eq!(endpoint.target, "/mcp?ready=1");
    assert_eq!(endpoint.peers, [(Ipv4Addr::LOCALHOST, 8140).into(), (Ipv6Addr::LOCALHOST, 8140).into()]);
    assert_eq!(Endpoint::parse("http://[::1]:8141/health")?.peers, [(Ipv6Addr::LOCALHOST, 8141).into()]);
    for url in ["https://127.0.0.1/", "http://192.0.2.1/", "http://127.0.0.1:0/", "http://127.0.0.1/#fragment",
        "http://127.0.0.1/mcp\r\nX: injected", "http://someone@127.0.0.1/"] {
        assert!(Endpoint::parse(url).is_err(), "{url}");
    }
    Ok(())
}
