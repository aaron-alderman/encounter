use crate::{Result, appdev_host_process::{Scratch, ServiceTool, Supervisor}, certificate_tls, command::Evaluator,
    fail, http, rel::Facts, x509::{Certificate, LeafUse, PrivateKey}};
use serde_json::{Value, json};
use std::{env, ffi::CString, fs, io::{self, Read, Write}, os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf}, process::Stdio, sync::atomic::{AtomicBool, Ordering},
    thread, time::{Duration, SystemTime, UNIX_EPOCH}};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const LIMIT: usize = 16_384;

fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| fail("Expected managed renewal text"))
}

fn read(path: &Path, limit: usize) -> Result<String> {
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() { return Err(fail("Expected a regular managed credential")); }
    let mut result = String::new();
    file.take((limit + 1) as u64).read_to_string(&mut result)?;
    if result.len() > limit { return Err(fail("Managed credential exceeds its size limit")); }
    Ok(result)
}

fn first_pem(text: &str) -> Result<&str> {
    let start = text.find("-----BEGIN CERTIFICATE-----").ok_or_else(|| fail("Missing certificate PEM"))?;
    let (_, end) = text[start..].split_once("-----END CERTIFICATE-----")
        .ok_or_else(|| fail("Incomplete certificate PEM"))?;
    Ok(&text[start..text.len() - end.len()])
}

fn read_key(path: &Path) -> Result<PrivateKey> {
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() { return Err(fail("Expected a regular managed private key")); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(LIMIT + 1));
    file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT { return Err(fail("Managed private key exceeds its size limit")); }
    PrivateKey::from_pem(&bytes)
}

fn pem(cert: &str) -> String { format!("{}\n", cert.trim()) }

fn details(cert: &Certificate) -> Result<Value> {
    let mut data = cert.metadata()?;
    data["fingerprint"] = json!(text(&data["fingerprint"])?.replace(':', "").to_ascii_lowercase());
    data["notBefore"] = json!(cert.valid_from()?);
    data["notAfter"] = json!(cert.valid_until()?);
    Ok(data)
}

fn current_time() -> Result<i64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?) }

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?.write_all(bytes)?;
    Ok(())
}

fn restore(backup: &Path, target: &Path) -> io::Result<()> {
    let pending = backup.with_extension("restore");
    fs::copy(backup, &pending)?;
    fs::rename(pending, target)
}

pub(super) fn stem(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

struct Profile {
    leaf: PathBuf, leaf_key: PathBuf, issuer: PathBuf, issuer_key: PathBuf,
    dns: Option<CString>,
}

impl Profile {
    fn load(app: &Evaluator, directory: &Path, facts: &Facts, target: &str) -> Result<Self> {
        let leaf = facts.one(target, "leaf")?;
        let issuer = facts.one(target, "issuer")?;
        let purpose = facts.one(target, "purpose")?;
        if !stem(leaf) || !stem(issuer) {
            return Err(fail("Invalid managed certificate profile"));
        }
        let reviewed = app.run("renewal.profile", json!({"target":target,"purpose":purpose,
            "extensions":facts.one(target, "extensions")?}))?;
        let dns = match (target, reviewed["purpose"].as_str()) {
            ("desktop", Some("client")) => None,
            ("server", Some("server")) => Some(CString::new(format!("DNS:{}", text(&reviewed["dnsName"])?))?),
            _ => return Err(fail("Invalid managed certificate usage")),
        };
        Ok(Self {
            leaf: directory.join(format!("{leaf}-cert.pem")), leaf_key: directory.join(format!("{leaf}-key.pem")),
            issuer: directory.join(format!("{issuer}.pem")), issuer_key: directory.join(format!("{issuer}-key.pem")),
            dns,
        })
    }

    fn observe(&self) -> Result<Observation> {
        let leaf_pem = read(&self.leaf, LIMIT)?;
        let leaf = Certificate::from_pem(&leaf_pem)?;
        let issuer = Certificate::from_pem(&read(&self.issuer, LIMIT)?)?;
        leaf.verify_issuer(&issuer)?;
        Ok(Observation { leaf: details(&leaf)?, issuer: details(&issuer)?, leaf_pem })
    }
}

struct Observation { leaf: Value, issuer: Value, leaf_pem: String }

struct Service {
    root: PathBuf, directory: PathBuf, nginx: PathBuf, tls_port: u16, unit: String, host: String,
    server: Profile, desktop: Profile, managed_chain: bool, authorization: String, busy: AtomicBool,
}

impl Service {
    fn profile(&self, target: &str) -> Result<&Profile> {
        match target { "server" => Ok(&self.server), "desktop" => Ok(&self.desktop), _ => Err(fail("Invalid renewal target")) }
    }

    fn validate_listener_config(&self) -> Result<()> {
        let mut supervisor = Supervisor::release_recovery();
        let mut nginx = ServiceTool::Nginx.command()?;
        nginx.stdout(Stdio::null()).stderr(Stdio::null());
        let mut prefix = self.directory.as_os_str().to_owned();
        prefix.push("/");
        supervisor.run_until("Managed nginx validation", nginx.args(["-t", "-p"]).arg(prefix).arg("-c").arg(&self.nginx),
            Some(Duration::from_secs(5)))
    }

    fn reload(&self, restoring: bool) -> Result<()> {
        crate::systemd_user_service::signal_managed_listener(&self.unit, restoring)
    }

    fn verify_listener(&self, app: &Evaluator, fingerprint: &Value, desktop: &Path, restoring: bool) -> Result<()> {
        let host = CString::new(self.host.as_str())?;
        let issuer = Certificate::from_pem(&read(&self.server.issuer, LIMIT)?)?;
        let desktop = Certificate::from_pem(&read(desktop, LIMIT)?)?;
        let key = read_key(&self.desktop.leaf_key)?;
        let (status, observed) = certificate_tls::probe(self.tls_port, &host, &issuer, &desktop, &key, restoring)?;
        if app.run("renewal.listener", json!({"status":status,"expected":fingerprint,"observed":observed}))? != true {
            return Err(fail("Managed TLS listener did not verify"));
        }
        Ok(())
    }

    fn await_listener(&self, app: &Evaluator, fingerprint: &Value, required: u64, restoring: bool) -> Result<()> {
        let mut confirmed = 0;
        for attempt in 0..10 {
            if !restoring && http::stopping() { return Err(fail("Managed renewal interrupted")); }
            if self.verify_listener(app, fingerprint, &self.desktop.leaf, restoring).is_ok() {
                confirmed += 1;
                if confirmed == required { return Ok(()); }
            } else {
                confirmed = 0;
            }
            if attempt < 9 { thread::sleep(Duration::from_millis(250)); }
        }
        Err(fail("Managed TLS did not verify after reloading"))
    }

    fn review(&self, app: &Evaluator, input: &Value, current: &Observation, renewing: bool, now: i64) -> Result<Value> {
        let timestamp = input["requestedAt"].as_i64().is_some_and(|value| value.unsigned_abs() <= 9_007_199_254_740_991);
        app.run("renewal.review", json!({"input":input,"leaf":current.leaf,"issuer":current.issuer,
            "renewing":renewing,"now":now,"reviewAt":now / 1000 * 1000,"validTimestamp":timestamp}))
    }

    fn sign(&self, profile: &Profile, work: &Path, expires: i64) -> Result<PathBuf> {
        let leaf = Certificate::from_pem(&read(&profile.leaf, LIMIT)?)?;
        let issuer = Certificate::from_pem(&read(&profile.issuer, LIMIT)?)?;
        let host = CString::new(self.host.as_str())?;
        let usage = match &profile.dns {
            Some(dns) => LeafUse::Server { dns, host: &host },
            None => LeafUse::Desktop,
        };
        let renewed = leaf.renew(&issuer, &read_key(&profile.leaf_key)?, &read_key(&profile.issuer_key)?,
            usage, current_time()? - 1000, expires)?;
        let candidate = work.join("candidate.pem");
        write_private(&candidate, renewed.as_bytes())?;
        Ok(candidate)
    }

    fn install(&self, app: &Evaluator, input: &Value, current: &Observation, reviewed: &Value, now: i64) -> Result<Value> {
        let target = text(&input["target"])?;
        let profile = self.profile(target)?;
        let actions = app.run("renewal.install", json!({"target":target,"managedChain":self.managed_chain}))?;
        let reload = actions["reload"] == true;
        let listener_confirmations = actions["listenerConfirmations"].as_u64().filter(|value| (1..=3).contains(value))
            .ok_or_else(|| fail("Invalid managed listener confirmation count"))?;
        let lock = fs::File::open(&self.directory)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(fail("Managed certificate directory is busy"));
        }
        let scratch = Scratch::create(&self.directory, ".renewal-")?;
        let work = scratch.path();
        let expires = reviewed["expiry"].as_i64().ok_or_else(|| fail("Missing reviewed expiry"))?;
        let candidate = self.sign(profile, work, expires)?;
        let next_pem = read(&candidate, LIMIT)?;
        let next = details(&Certificate::from_pem(&next_pem)?)?;
        if next["subject"] != current.leaf["subject"] || next["keyFingerprint"] != current.leaf["keyFingerprint"]
            || next["expires"] != reviewed["plan"]["proposedExpiry"] {
            return Err(fail("The renewed certificate differs from the approved plan"));
        }
        if self.review(app, input, &profile.observe()?, true, now)?["digest"] != reviewed["digest"] {
            return Err(fail("The installed certificate changed"));
        }
        if actions["verifyBefore"] == true {
            self.verify_listener(app, &self.server.observe()?.leaf["fingerprint"], &candidate, false)?;
        }
        let backup = work.join("previous.pem");
        write_private(&backup, current.leaf_pem.as_bytes())?;
        let chain = self.directory.join("ingress-serving-chain.pem");
        let chain_backup = work.join("previous-chain.pem");
        let mut installed_chain = false;
        let mut installed_leaf = false;
        let mut reload_attempted = false;
        let operation = (|| -> Result<()> {
            if http::stopping() { return Err(fail("Managed renewal interrupted")); }
            if actions["replaceChain"] == true {
                let previous = read(&chain, 2 * LIMIT)?;
                if details(&Certificate::from_pem(first_pem(&previous)?)?)?["fingerprint"] != current.leaf["fingerprint"] {
                    return Err(fail("The serving chain differs from the reviewed certificate"));
                }
                let bridge = self.directory.join("ingress-server-bridge.pem");
                let mut next_chain = pem(&next_pem);
                match read(&bridge, LIMIT) {
                    Ok(bridge) => {
                        let cert = Certificate::from_pem(&bridge)?;
                        let metadata = details(&cert)?;
                        if !cert.is_ca() || metadata["keyFingerprint"] != current.issuer["keyFingerprint"]
                            || metadata["subject"] != current.issuer["subject"] {
                            return Err(fail("The overlap certificate does not match the issuer"));
                        }
                        if cert.valid_until()? > current_time()? { next_chain.push_str(&pem(&bridge)); }
                    }
                    Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
                        && previous.trim() == current.leaf_pem.trim() => (),
                    Err(error) => return Err(error),
                }
                let next_path = work.join("next-chain.pem");
                write_private(&next_path, next_chain.as_bytes())?;
                write_private(&chain_backup, previous.as_bytes())?;
                fs::rename(next_path, &chain)?;
                installed_chain = true;
            }
            fs::rename(&candidate, &profile.leaf)?;
            installed_leaf = true;
            if http::stopping() { return Err(fail("Managed renewal interrupted")); }
            if reload {
                self.validate_listener_config()?;
                if http::stopping() { return Err(fail("Managed renewal interrupted")); }
                reload_attempted = true;
                self.reload(false)?;
                self.await_listener(app, &next["fingerprint"], listener_confirmations, false)?;
            }
            Ok(())
        })();
        if let Err(error) = operation {
            if installed_leaf || installed_chain {
                let mut restored = true;
                if installed_leaf { restored &= restore(&backup, &profile.leaf).is_ok(); }
                if installed_chain { restored &= restore(&chain_backup, &chain).is_ok(); }
                if restored && reload_attempted {
                    restored = self.validate_listener_config().and_then(|()| self.reload(true))
                        .and_then(|()| self.await_listener(app, &current.leaf["fingerprint"], listener_confirmations, true)).is_ok();
                }
                if !restored {
                    let path = scratch.retain();
                    return Err(fail(format!("Managed renewal rollback incomplete; retained {}", path.display())));
                }
            }
            return Err(error);
        }
        Ok(json!({"renewed":{"target":target,"serial":next["serial"],"expires":next["expires"]}}))
    }

    fn request(&self, request: &http::Request, port: u16) -> Result<(u64, Value)> {
        let app = Evaluator::load(&self.root, "renewal.rel")?;
        let received = request.headers.get("authorization").map_or("", String::as_str);
        let route = app.run("renewal.route", json!({"host":request.headers.get("host"),"loopback":format!("127.0.0.1:{port}"),
            "method":request.method,"contentType":request.headers.get("content-type"),"path":request.path,
            "authorized":bool::from(received.as_bytes().ct_eq(self.authorization.as_bytes()))}))?;
        if route["status"] != 200 { return refusal(&route); }
        let renewing = request.path == "/renew";
        struct ReleaseBusy<'a>(&'a AtomicBool);
        impl Drop for ReleaseBusy<'_> { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }
        let _busy = if renewing {
            if self.busy.swap(true, Ordering::AcqRel) { return Ok((409, json!({"error":"A renewal is in progress"}))); }
            Some(ReleaseBusy(&self.busy))
        } else { None };
        if request.body.len() > 4096 { return Err(fail("Renewal request exceeds its limit")); }
        let mut input: Value = serde_json::from_slice(&request.body)?;
        if let Some(time) = input["requestedAt"].as_f64().filter(|value| value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0) {
            input["requestedAt"] = json!(time as i64);
        }
        let current = self.profile(text(&input["target"])?)?.observe()?;
        let now = current_time()?;
        let reviewed = self.review(&app, &input, &current, renewing, now)?;
        if reviewed["status"] != 200 { return refusal(&reviewed); }
        let value = if renewing { self.install(&app, &input, &current, &reviewed, now)? }
            else { json!({"plan":reviewed["plan"],"digest":reviewed["digest"]}) };
        Ok((200, value))
    }
}

fn refusal(result: &Value) -> Result<(u64, Value)> {
    Ok((result["status"].as_u64().ok_or_else(|| fail("Missing renewal status"))?, json!({"error":text(&result["error"])?})))
}

pub fn serve(root: &Path, directory: &Path, port: u16, nginx: &Path, tls_port: u16, unit: &str, chain: Option<&str>) -> Result<()> {
    if !directory.is_absolute() || !nginx.is_absolute() || port < 1024 || tls_port < 1024
        || !unit.strip_prefix("notes-managed-").and_then(|unit| unit.strip_suffix(".service")).is_some_and(stem)
        || !matches!(chain, None | Some("managed-chain")) {
        return Err(fail("Expected managed ingress paths, unit and loopback ports"));
    }
    unsafe { libc::umask(0o077); }
    let directory = directory.canonicalize()?;
    let credentials = env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| fail("Missing renewal credential directory"))?;
    let secret = read(&Path::new(&credentials).join("certificate-renewal-auth"), 256)?;
    let secret = secret.trim();
    if secret.len() != 64 || !secret.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')) {
        return Err(fail("Expected a dedicated renewal credential"));
    }
    let root = root.canonicalize()?;
    let app = Evaluator::load(&root, "renewal.rel")?;
    let facts = Facts::read(&root.join("profiles.rel"))?;
    let host = facts.one("listener", "name")?;
    if !host.split('.').all(stem) { return Err(fail("Invalid managed TLS hostname")); }
    let service = Service {
        root: root.clone(), server: Profile::load(&app, &directory, &facts, "server")?, desktop: Profile::load(&app, &directory, &facts, "desktop")?,
        directory, nginx: nginx.to_owned(), tls_port, unit: unit.to_owned(), host: host.to_owned(),
        managed_chain: chain.is_some(), authorization: format!("Bearer {secret}"), busy: AtomicBool::new(false),
    };
    http::serve_workers(port, 4, 64 * 1024, move |stream, request| {
        let (status, body) = service.request(&request, port).unwrap_or_else(|error| {
            eprintln!("Managed certificate renewal operation failed: {error}");
            (503, json!({"error":"The managed certificate operation could not complete."}))
        });
        let status = match status {
            200 => "200 OK", 400 => "400 Bad Request", 403 => "403 Forbidden", 404 => "404 Not Found",
            405 => "405 Method Not Allowed", 409 => "409 Conflict", _ => "503 Service Unavailable",
        };
        let _ = http::send_bytes(stream, status, "application/json", "", body.to_string().as_bytes());
    })
}
