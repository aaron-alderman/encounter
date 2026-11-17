use crate::{Result, fail, http, package, process::{Meter, Programme}, rel, server_temple_capsule,
    server_temple_application::{Application, Runtime},
    server_temple_publication::{self, Publication},
    server_temple_transit::{self, Transit}, signature, sqlite::Db};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::{self, File, Metadata}, io::{self, Read, Write},
    net::TcpStream, os::unix::{fs::MetadataExt, process::ExitStatusExt}, path::Path, time::{Duration, Instant, SystemTime}};
use zeroize::Zeroizing;

fn path<'a>(input: &'a Value, name: &str) -> Result<&'a Path> {
    let path = input[name].as_str().map(Path::new).filter(|path| path.is_absolute())
        .ok_or_else(|| fail("Expected an absolute Server Temple file path"))?;
    Ok(path)
}

fn artifact(root: &File, path: &Path) -> Result<File> {
    package::open_artifact(root, path.strip_prefix("/")?)
}

fn bounded(mut file: &File, limit: u64) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    if before.len() > limit { return Err(fail("Server Temple checkpoint file exceeded its size limit")); }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 > limit || bytes.len() as u64 != before.len()
        || before.len() != after.len() || before.modified()? != after.modified()?
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(fail("Server Temple checkpoint file changed while being read"));
    }
    Ok(bytes)
}

fn document(file: &File) -> Result<Value> {
    let metadata = file.metadata()?;
    if metadata.mode() & 0o022 != 0 || metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() } {
        return Err(fail("Expected a protected Server Temple checkpoint manifest"));
    }
    let value = serde_json::from_slice(&bounded(file, 256 * 1024)?)?;
    crate::compat_value::external(&value)?;
    Ok(value)
}

fn optional_row(db: &Db, sql: &str) -> Result<Value> {
    let mut rows = db.query(sql, &[])?;
    match rows.len() {
        0 => Ok(Value::Null),
        1 => Ok(rows.pop().expect("one capsule row")),
        _ => Err(fail("Expected a single Server Temple checkpoint row")),
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.is_file() && right.is_file() && left.dev() == right.dev() && left.ino() == right.ino()
}

fn now() -> DateTime<Utc> { SystemTime::now().into() }

fn configured(value: &Value) -> bool { !matches!(value, Value::Null | Value::Bool(false)) }

fn timestamp(time: DateTime<Utc>) -> String { time.to_rfc3339_opts(SecondsFormat::Millis, true) }

fn current_lease(db: &Db) -> Result<Value> {
    let lease = optional_row(db, "SELECT holder, acquired_at, expires_at, generation FROM writer_lease WHERE singleton = 1")?;
    if !lease.is_null() {
        for field in ["acquired_at", "expires_at"] {
            let stored = lease[field].as_str().ok_or_else(|| fail("Expected a Server Temple lease timestamp"))?;
            if !DateTime::parse_from_rfc3339(stored).is_ok_and(|time| timestamp(time.to_utc()) == stored) {
                return Err(fail("Invalid Server Temple lease timestamp"));
            }
        }
    }
    Ok(lease)
}

fn manifest_row(db: &Db) -> Result<Value> {
    optional_row(db, "SELECT manifest_json, manifest_hash FROM temple_manifest WHERE singleton = 1")
}

fn journal_tip(db: &Db) -> Result<Value> {
    let tail = optional_row(db, "SELECT sequence, event_hash FROM journal_events ORDER BY sequence DESC LIMIT 1")?;
    Ok(if tail.is_null() { json!({"eventCount":0,"headHash":"0".repeat(64)}) }
    else { json!({"eventCount":tail["sequence"],"headHash":tail["event_hash"]}) })
}

fn lease_input(current: Value, holder: &Value, token: Option<&Value>, lease: Duration) -> Result<Value> {
    let now = now();
    let expires = now.checked_add_signed(chrono::Duration::from_std(lease)?)
        .ok_or_else(|| fail("Server Temple writer lease time overflow"))?;
    Ok(json!({"current":current,"holder":holder,"token":token,"now":timestamp(now),"expires":timestamp(expires)}))
}

fn token_fields(token: &Value) -> [Value; 4] {
    ["holder", "acquired_at", "expires_at", "generation"].map(|field| token[field].clone())
}

pub(crate) fn append_event(db: &Db, record: &Value) -> Result<()> {
    let event = &record["event"];
    let inserted = db.query("INSERT INTO journal_events(event_id, kind, actor, occurred_at, payload_json, payload_hash, previous_hash, event_hash)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING sequence", &[event["event_id"].clone(), event["kind"].clone(),
        event["actor"].clone(), event["occurred_at"].clone(), record["payloadJson"].clone(),
        event["payload_hash"].clone(), event["previous_hash"].clone(), record["eventHash"].clone()])?;
    if inserted.as_slice() != [json!({"sequence":event["sequence"]})] {
        return Err(fail("Server Temple journal sequence changed"));
    }
    Ok(())
}

struct Checkpoint {
    root: File,
    config: Value,
    sources: Vec<Value>,
    policy: Programme,
    public_key: String,
    service_key: Option<SigningKey>,
    capsule: Metadata,
    protected: Vec<Metadata>,
}

impl Checkpoint {
    fn policy() -> Result<Programme> {
        Programme::admit_entries(&[include_str!("server_temple_checkpoint.encounter").to_owned(),
            include_str!("server_temple_application.encounter").to_owned(),
            server_temple_capsule::SOURCE.to_owned()], &["checkpoint.plan", "checkpoint.admit", "checkpoint.offline",
                "checkpoint.author", "checkpoint.leaseSettings", "checkpoint.acquire", "checkpoint.held", "checkpoint.renew",
                "checkpoint.fence", "templeApplication.plan", "templeApplication.event"],
            &BTreeSet::from(["json.parse", "json.canonical", "digest.sha256", "text.matches", "value.describe",
                "value.type", "number.calculate", "number.isNatural", "text.compare", "record.entries"]), &mut Meter::new(20_000_000))
    }

    fn load(config_file: &Path, hosted: bool) -> Result<Self> {
        let root = File::open("/")?;
        let config_handle = artifact(&root, config_file)?;
        let config = document(&config_handle)?;
        let mut protected = vec![config_handle.metadata()?];
        let sources = match config.get("stateSourceFile") {
            Some(value) if !value.is_null() => {
                let handle = artifact(&root, path(&config, "stateSourceFile")?)?;
                protected.push(handle.metadata()?);
                document(&handle)?
            }
            _ => json!({"protocol":"sourcery/server-temple-migration-source.v1","sources":[]}),
        };
        let policy = Self::policy()?;
        let sources = policy.run("checkpoint.plan", json!({"config":config,"configPath":config_file,
            "source":sources,"hosted":hosted}), &mut Meter::new(20_000_000))?;
        let sources = serde_json::from_value(sources)?;
        let identity_file = artifact(&root, path(&config, "identityFile")?)?;
        let identity_metadata = identity_file.metadata()?;
        if identity_metadata.mode() & 0o077 != 0 || identity_metadata.uid() != unsafe { libc::geteuid() } {
            return Err(fail("Expected an owner-only Server Temple identity key"));
        }
        protected.push(identity_metadata);
        let pem = Zeroizing::new(bounded(&identity_file, 4096)?);
        let identity = signature::signing_key_from_pem(&pem)?;
        let public_key = hex::encode(identity.verifying_key().as_bytes());
        let capsule = artifact(&root, path(&config, "capsuleFile")?)?.metadata()?;
        if capsule.mode() & 0o077 != 0 || capsule.uid() != unsafe { libc::geteuid() } {
            return Err(fail("Expected an owner-only Server Temple capsule"));
        }
        let service_key = (hosted && (configured(&config["transport"]) || configured(&config["publicPublication"]))).then_some(identity);
        Ok(Self { root, config, sources, policy, public_key, service_key, capsule, protected })
    }

    fn evaluate(&self, entry: &str, input: Value) -> Result<Value> {
        self.policy.run(entry, input, &mut Meter::new(20_000_000))
    }

    fn transaction(&self, cleanup: bool) -> Result<Db> {
        let path = path(&self.config, "capsuleFile")?;
        if !same_file(&self.capsule, &fs::symlink_metadata(path)?) {
            return Err(fail("Server Temple capsule was replaced"));
        }
        let db = Db::open_temple_for_checkpoint(path)?;
        if !cleanup { db.interrupt_on_stop()?; }
        db.exec("PRAGMA trusted_schema = OFF; PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL; BEGIN IMMEDIATE;")?;
        if !same_file(&self.capsule, &fs::symlink_metadata(path)?) {
            return Err(fail("Server Temple capsule was replaced"));
        }
        Ok(db)
    }

    fn inspect(&self, db: &Db) -> Result<Value> {
        let migration = optional_row(db, "SELECT name, checksum FROM schema_migrations WHERE version = 1")?;
        let protocol = optional_row(db, "SELECT value FROM capsule_meta WHERE key = 'protocol'")?;
        let metadata_identity = optional_row(db, "SELECT value FROM capsule_meta WHERE key = 'templeId'")?;
        let (inspection, manifest_key) = server_temple_capsule::inspect_database(db)?;
        self.evaluate("checkpoint.admit", json!({"inspection":inspection,"templeId":self.config["templeId"],
            "manifestKey":manifest_key,"identityKey":self.public_key,"migration":migration,"protocol":protocol,
            "metadataIdentity":metadata_identity}))?;
        Ok(inspection)
    }

    fn held(&self, db: &Db, token: &Value) -> Result<()> {
        self.evaluate("checkpoint.held", json!({"current":current_lease(db)?,"token":token,"now":timestamp(now())}))?;
        Ok(())
    }

    fn capture(&self, lease: Option<(&Value, &Value)>, cleanup: bool) -> Result<Value> {
        let db = self.transaction(cleanup)?;
        let journal = if let Some((token, manifest)) = lease {
            self.held(&db, token)?;
            let current = manifest_row(&db)?;
            if &current != manifest { return Err(fail("Server Temple capsule manifest changed during custody")); }
            journal_tip(&db)?
        } else {
            self.evaluate("checkpoint.offline", current_lease(&db)?)?;
            self.inspect(&db)?["journal"].clone()
        };
        let previous = optional_row(&db, "SELECT revision, content_json FROM projections WHERE name = 'server-live-state'")?;
        let timestamp = timestamp(now());
        let mut observations = Vec::new();
        for source in &self.sources {
            if !cleanup && http::stopping() { return Err(fail("Server Temple checkpoint interrupted")); }
            let source_path = path(source, "path")?;
            let file = artifact(&self.root, source_path)?;
            let retained = file.metadata()?;
            if self.protected.iter().chain([&self.capsule]).any(|metadata| same_file(metadata, &retained)) {
                return Err(fail("Server Temple checkpoint source aliases a protected artifact"));
            }
            let bytes = bounded(&file, 128 * 1024 * 1024)?;
            let current = fs::symlink_metadata(source_path)?;
            if !same_file(&current, &retained) {
                return Err(fail("Server Temple checkpoint source was replaced while being read"));
            }
            let digest = rel::hash(&bytes);
            db.retain_temple_object(&digest, &timestamp, &bytes)?;
            observations.push(json!({"source":source,"digest":digest,"bytes":bytes.len()}));
        }
        let checkpoint = self.evaluate("checkpoint.author", json!({"observations":observations,"previous":previous,
            "journal":journal,"timestamp":timestamp,"writerId":self.config["writerId"]}))?;
        if checkpoint.is_null() {
            db.exec("ROLLBACK")?;
            return Ok(json!({"status":"unchanged"}));
        }
        let projection = &checkpoint["projection"];
        db.query("INSERT INTO projections(name, revision, content_json, content_hash, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(name) DO UPDATE SET revision = excluded.revision,
            content_json = excluded.content_json, content_hash = excluded.content_hash, updated_at = excluded.updated_at",
            &[projection["name"].clone(), projection["revision"].clone(), checkpoint["contentJson"].clone(),
                projection["contentHash"].clone(), json!(timestamp)])?;
        append_event(&db, &checkpoint)?;
        if !cleanup && http::stopping() { return Err(fail("Server Temple checkpoint interrupted")); }
        if let Some((token, _)) = lease { self.held(&db, token)?; }
        db.exec("COMMIT")?;
        Ok(json!({"status":"checkpointed","projection":projection,"eventHash":checkpoint["eventHash"]}))
    }

    fn acquire(&self, duration: Duration) -> Result<(Value, Value, Value)> {
        let db = self.transaction(false)?;
        let current = current_lease(&db)?;
        let holder = &self.config["writerId"];
        self.evaluate("checkpoint.acquire", lease_input(current.clone(), holder, None, duration)?)?;
        let inspection = self.inspect(&db)?;
        let manifest = manifest_row(&db)?;
        let token = self.evaluate("checkpoint.acquire", lease_input(current, holder, None, duration)?)?;
        db.query("INSERT INTO writer_lease(singleton, holder, acquired_at, expires_at, generation)
            VALUES (1, ?1, ?2, ?3, ?4) ON CONFLICT(singleton) DO UPDATE SET holder = excluded.holder,
            acquired_at = excluded.acquired_at, expires_at = excluded.expires_at, generation = excluded.generation",
            &token_fields(&token))?;
        if http::stopping() { return Err(fail("Server Temple writer acquisition interrupted")); }
        db.exec("COMMIT")?;
        Ok((token, manifest, inspection))
    }

    fn renew(&self, token: &Value, duration: Duration, cleanup: bool) -> Result<Value> {
        let db = self.transaction(cleanup)?;
        let next = self.evaluate("checkpoint.renew",
            lease_input(current_lease(&db)?, &self.config["writerId"], Some(token), duration)?)?;
        db.query("UPDATE writer_lease SET expires_at = ?1 WHERE singleton = 1", &[next["expires_at"].clone()])?;
        if !cleanup && http::stopping() { return Err(fail("Server Temple writer renewal interrupted")); }
        db.exec("COMMIT")?;
        Ok(next)
    }

    fn application_event(&self, token: &Value, manifest: &Value, mut observation: Value, cleanup: bool) -> Result<()> {
        let db = self.transaction(cleanup)?;
        self.held(&db, token)?;
        if &manifest_row(&db)? != manifest { return Err(fail("Server Temple capsule manifest changed during launch")); }
        observation["token"] = token.clone();
        observation["journal"] = journal_tip(&db)?;
        observation["now"] = json!(timestamp(now()));
        let event = self.evaluate("templeApplication.event", observation)?;
        append_event(&db, &event)?;
        self.held(&db, token)?;
        if !cleanup && http::stopping() { return Err(fail("Server Temple application journal interrupted")); }
        db.exec("COMMIT")
    }

    fn release(&self, token: &Value) -> Result<()> {
        let db = self.transaction(true)?;
        if self.evaluate("checkpoint.fence", json!({"current":current_lease(&db)?,"token":token}))? == true {
            db.query("DELETE FROM writer_lease WHERE singleton = 1 AND holder = ?1
                AND acquired_at = ?2 AND expires_at = ?3 AND generation = ?4", &token_fields(token))?;
            db.exec("COMMIT")?;
        }
        Ok(())
    }

    fn transit(&self, transit: &Transit, stream: &mut TcpStream, token: &Value, manifest: &Value, identity: &Value) -> Result<()> {
        let request = match http::read_temple_transit(stream, transit.maximum_bytes()) {
            Ok(request) => request,
            Err(error) if error.is::<http::BodyLimit>() =>
                return server_temple_transit::respond(stream, 413, &json!({"error":"temple-transit-rejected","message":"Temple transit request exceeds its byte limit."}), false),
            Err(_) => return server_temple_transit::respond(stream, 400,
                &json!({"error":"temple-transit-rejected","message":"Invalid Temple transit HTTP request."}), false),
        };
        let head = request.method == "HEAD";
        let route = transit.route(&request)?;
        let action = route["kind"].as_str();
        if action == Some("refuse") {
            return server_temple_transit::respond(stream, route["status"].as_u64()
                .ok_or_else(|| fail("Expected a Temple transit refusal status"))?, &route["body"], head);
        }
        let result = (|| -> Result<Value> {
            let db = self.transaction(false)?;
            self.held(&db, token)?;
            if &manifest_row(&db)? != manifest { return Err(fail("Server Temple capsule manifest changed during custody")); }
            if action == Some("health") {
                return Ok(json!({"status":"ready","templeId":identity["templeId"],"manifestHash":identity["manifestHash"],
                    "writerGeneration":token["generation"]}));
            }
            if action != Some("receive") { return Err(fail("Unknown Temple transit action")); }
            let signer = self.service_key.as_ref().ok_or_else(|| fail("Missing Temple transit identity"))?;
            let response = transit.receive(&db, signer, identity, &self.config["writerId"], &request.body, now())?;
            self.held(&db, token)?;
            if http::stopping() { return Err(fail("Temple transit interrupted")); }
            db.exec("COMMIT")?;
            Ok(response)
        })();
        match result {
            Ok(body) => server_temple_transit::respond(stream, 200, &body, head),
            Err(error) => {
                let refusal = transit.refusal(&error.to_string())?;
                server_temple_transit::respond(stream, refusal["status"].as_u64()
                    .ok_or_else(|| fail("Expected a Temple transit refusal status"))?, &refusal["body"], head)
            }
        }
    }

    fn load_publication(&self, publication: &mut Publication, token: &Value, manifest: &Value) -> Result<()> {
        let signer = self.service_key.as_ref().ok_or_else(|| fail("Missing Temple publication identity"))?;
        let db = self.transaction(false)?;
        self.held(&db, token)?;
        if &manifest_row(&db)? != manifest { return Err(fail("Server Temple capsule manifest changed during custody")); }
        let projection = optional_row(&db, "SELECT revision, content_json, content_hash FROM projections
            WHERE name = 'server-plugin-publication'")?;
        publication.load(manifest, projection, signer, now().timestamp_millis())?;
        self.held(&db, token)
    }

    fn publication(&self, publication: &Publication, stream: &mut TcpStream, token: &Value, manifest: &Value) -> Result<()> {
        let request = match http::read_temple_publication(stream) {
            Ok(request) => request,
            Err(_) => return server_temple_publication::respond_json(stream, 400, &json!({"error":"invalid-publication-request"}), false),
        };
        let admitted = (|| -> Result<()> {
            let db = self.transaction(false)?;
            self.held(&db, token)?;
            if &manifest_row(&db)? != manifest { return Err(fail("Server Temple capsule manifest changed during custody")); }
            Ok(())
        })();
        if admitted.is_err() {
            return server_temple_publication::respond_json(stream, 503, &json!({"error":"publication-unavailable"}), request.method == "HEAD");
        }
        let signer = self.service_key.as_ref().ok_or_else(|| fail("Missing Temple publication identity"))?;
        publication.respond(stream, &request, signer, now().timestamp_millis())
    }
}

pub(crate) fn run(config: &Path) -> Result<()> {
    http::install_stop_signals()?;
    let receipt = match Checkpoint::load(config, false).and_then(|checkpoint| checkpoint.capture(None, false)) {
        Err(_) if http::stopping() => return Err(fail("Server Temple checkpoint interrupted")),
        result => result?,
    };
    writeln!(io::stdout().lock(), "{receipt}")?;
    Ok(())
}

pub(crate) fn hold(config: &Path) -> Result<()> {
    supervise(config, false)
}

pub(crate) fn host(config: &Path) -> Result<()> {
    supervise(config, true)
}

fn supervise(config: &Path, launch: bool) -> Result<()> {
    http::install_stop_signals()?;
    let checkpoint = Checkpoint::load(config, true)?;
    let application = launch.then(|| Application::admit(
        &checkpoint.evaluate("templeApplication.plan", checkpoint.config.clone())?)).transpose()?;
    let settings = checkpoint.evaluate("checkpoint.leaseSettings", checkpoint.config.clone())?;
    let duration = |name| settings[name].as_u64().map(Duration::from_millis)
        .ok_or_else(|| fail("Expected a Server Temple writer interval"));
    let lease = duration("leaseMs")?;
    let renew = duration("renewMs")?;
    let interval = duration("checkpointMs")?;
    let transport = if configured(&checkpoint.config["transport"]) {
        let (transit, listener) = Transit::bind(checkpoint.config["transport"].clone())?;
        listener.set_nonblocking(true)?;
        Some((transit, listener))
    } else { None };
    let mut publication = configured(&checkpoint.config["publicPublication"])
        .then(|| Publication::bind(checkpoint.config["publicPublication"].clone(), now().timestamp_millis())).transpose()?;
    let (mut token, manifest, inspection) = checkpoint.acquire(lease)?;
    let mut runtime: Option<Runtime> = None;
    let mut next_renewal = Instant::now() + renew;
    let result = (|| -> Result<()> {
        let mut application_origin = None;
        if let Some(application) = &application {
            checkpoint.application_event(&token, &manifest, json!({"phase":"boot"}), false)?;
            let temple_id = inspection["templeId"].as_str().ok_or_else(|| fail("Expected Temple ID"))?;
            let manifest_hash = inspection["manifestHash"].as_str().ok_or_else(|| fail("Expected Temple manifest hash"))?;
            runtime = Some(application.start(path(&checkpoint.config, "capsuleFile")?, temple_id, manifest_hash)?);
            let child = runtime.as_mut().expect("started Temple application");
            checkpoint.application_event(&token, &manifest,
                json!({"phase":"start","pid":child.id(),"args":application.args()}), false)?;
            let deadline = Instant::now() + Duration::from_secs(15);
            while !http::stopping() && Instant::now() < deadline {
                if let Some(status) = child.status()? { return Err(fail(format!("Native Temple application exited during startup ({status})"))); }
                if let Some(origin) = child.origin()? { application_origin = Some(origin); break; }
                if Instant::now() >= next_renewal {
                    token = checkpoint.renew(&token, lease, false)?;
                    next_renewal = Instant::now() + renew;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            if application_origin.is_none() {
                return Err(fail(if http::stopping() { "Native Temple application startup interrupted" }
                    else { "Native Temple application startup timed out" }));
            }
            if let Some((transit, _)) = &transport {
                checkpoint.application_event(&token, &manifest,
                    json!({"phase":"transit","pid":child.id(),"transport":transit.description()}), false)?;
            }
        }
        let first = if checkpoint.sources.is_empty() { Value::Null }
            else { checkpoint.capture(Some((&token, &manifest)), false)? };
        if let Some((publication, _)) = &mut publication { checkpoint.load_publication(publication, &token, &manifest)?; }
        if let Some(child) = &mut runtime {
            if http::stopping() { return Err(fail("Native Temple application startup interrupted")); }
            if let Some(status) = child.status()? {
                return Err(fail(format!("Native Temple application exited during startup ({status})")));
            }
        }
        writeln!(io::stdout().lock(), "{}", json!({"status":if launch {"started"} else {"holding"},"templeId":inspection["templeId"],
            "manifestHash":inspection["manifestHash"],"generation":token["generation"],"checkpoint":first,
            "pid":runtime.as_ref().map(Runtime::id),"applicationOrigin":application_origin,
            "transport":transport.as_ref().map(|(transit, _)| transit.description()),
            "publicPublication":publication.as_ref().map(|(publication, _)| publication.description())}))?;
        let mut next_capture = Instant::now() + interval;
        while !http::stopping() {
            if let Some(child) = &mut runtime && let Some(status) = child.status()? {
                if status.success() { return Ok(()); }
                return Err(fail(format!("Native Temple application exited ({status})")));
            }
            if Instant::now() >= next_renewal {
                token = checkpoint.renew(&token, lease, false)?;
                next_renewal = Instant::now() + renew;
            }
            if !checkpoint.sources.is_empty() && Instant::now() >= next_capture {
                let receipt = checkpoint.capture(Some((&token, &manifest)), false)?;
                if receipt["status"] == "checkpointed" { writeln!(io::stdout().lock(), "{receipt}")?; }
                next_capture = Instant::now() + interval;
            }
            let mut handled = false;
            if let Some((transit, listener)) = &transport {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Err(error) = checkpoint.transit(transit, &mut stream, &token, &manifest, &inspection)
                            && !http::stopping() {
                            eprintln!("Temple transit HTTP: {error}");
                        }
                        handled = true;
                    }
                    Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if let Some((publication, listener)) = &publication {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Err(error) = checkpoint.publication(publication, &mut stream, &token, &manifest)
                            && !http::stopping() {
                            eprintln!("Temple publication HTTP: {error}");
                        }
                        handled = true;
                    }
                    Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if handled { continue; }
            let next = if checkpoint.sources.is_empty() { next_renewal } else { next_capture.min(next_renewal) };
            std::thread::sleep(next.saturating_duration_since(Instant::now()).min(Duration::from_millis(25)));
        }
        Ok(())
    })();
    let mut failures = result.err().map(|error| vec![error.to_string()]).unwrap_or_default();
    if let Some(child) = &mut runtime {
        let status = child.stop(|| {
            if Instant::now() >= next_renewal {
                token = checkpoint.renew(&token, lease, true)?;
                next_renewal = Instant::now() + renew;
            }
            Ok(())
        });
        if let Err(error) = &status { failures.push(error.to_string()); }
        if let Ok(status) = &status && !status.success() && failures.is_empty() {
            failures.push(format!("Native Temple application exited ({status})"));
        }
        let status = status.ok();
        let checkpoint_error = if status.is_some() && !checkpoint.sources.is_empty() {
            checkpoint.capture(Some((&token, &manifest)), true).err().map(|error| error.to_string())
        } else { None };
        let signal = status.and_then(|status| status.signal()).map(|signal| match signal {
            libc::SIGTERM => "SIGTERM".to_owned(), libc::SIGINT => "SIGINT".to_owned(),
            libc::SIGKILL => "SIGKILL".to_owned(), _ => format!("signal {signal}"),
        });
        let observation = json!({"phase":"stop","pid":child.id(),"code":status.and_then(|status| status.code()),
            "signal":signal,"error":failures.first(),"checkpointError":checkpoint_error});
        if let Err(error) = checkpoint.application_event(&token, &manifest, observation, true) {
            failures.push(error.to_string());
        }
        if let Some(error) = checkpoint_error { failures.push(error); }
    }
    let released = checkpoint.release(&token);
    if let Err(error) = released { failures.push(format!("Server Temple lease cleanup failed ({error})")); }
    if failures.is_empty() { Ok(()) } else { Err(fail(failures.join("; "))) }
}

#[cfg(test)]
#[test]
fn application_plan_admits_only_the_native_image_contract() -> Result<()> {
    let policy = Checkpoint::policy()?;
    let run = |input| policy.run("templeApplication.plan", input, &mut Meter::new(20_000_000));
    let config = json!({"nativeApplication":{
        "protocol":"encounter/server-temple-application/1", "image":"/private/application.encounter-image",
        "sha256":"a".repeat(64), "store":"/private/store", "port":0
    }});
    assert_eq!(run(config.clone())?, config["nativeApplication"]);
    for (field, value) in [("executable", json!("/bin/sh")), ("args", json!([])), ("env", json!({}))] {
        let mut alternate = config.clone();
        alternate[field] = value;
        assert!(run(alternate).is_err());
    }
    let mut alternate = config.clone();
    alternate["nativeApplication"]["command"] = json!("/bin/sh");
    assert!(run(alternate).is_err());
    let mut invalid_port = config;
    invalid_port["nativeApplication"]["port"] = json!(65536);
    assert!(run(invalid_port).is_err());
    Ok(())
}

#[cfg(test)]
#[test]
fn writer_lease_cannot_be_reused_by_a_stale_session() -> Result<()> {
    let policy = Checkpoint::policy()?;
    let run = |entry, input| policy.run(entry, input, &mut Meter::new(20_000_000));
    let current = json!({"holder":"writer","generation":1,
        "acquired_at":"2026-01-01T00:00:00.000Z","expires_at":"2026-01-01T00:00:02.000Z"});
    let mut input = json!({"current":current,"holder":"writer","now":"2026-01-01T00:00:01.000Z",
        "expires":"2026-01-01T00:00:03.000Z"});
    assert!(run("checkpoint.acquire", input.clone()).is_err());
    input["now"] = json!("2026-01-01T00:00:02.000Z");
    let replacement = run("checkpoint.acquire", input.clone())?;
    assert_eq!(replacement["generation"], 2);
    input["token"] = current.clone();
    assert!(run("checkpoint.renew", input).is_err());
    let mut same_generation = replacement;
    same_generation["generation"] = json!(1);
    assert_eq!(run("checkpoint.fence", json!({"current":same_generation,"token":current}))?, false);
    Ok(())
}
