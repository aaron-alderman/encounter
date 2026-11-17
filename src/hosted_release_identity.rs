use crate::{Result, appdev_host_process::{Scratch, Supervisor, interruption, rename_new_path}, command_sources::Sources,
    archive::{self, ARCHIVE_LIMIT, Modes, Work}, compat_value, fail, http, package::require_native_runtime_file, process::{Meter, Programme}};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File, Metadata, OpenOptions}, io::{self, Read, Seek, SeekFrom, Write},
    net::{IpAddr, SocketAddr}, os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}}, path::{Component, Path},
    thread, time::{Duration, Instant}};

const SOURCE_PROTOCOL: &str = "sourcery.hosted/production-hot-swap-supervisor.v1";
const TEMPLE_PROTOCOL: &str = "sourcery.hosted/temple-freeze.v1";
const MANIFEST_LIMIT: u64 = 8 * 1024 * 1024;
const POINTER_LIMIT: u64 = 1024 * 1024;
const ADMISSION_ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;
const ADMISSION_MAGIC: &[u8] = b"SOURCERY-ADMITTED/1\n";
const FILE_LIMIT: u64 = 256 * 1024 * 1024;
const TREE_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const ENTRY_LIMIT: usize = 100_000;

pub(super) fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_release_identity.encounter").to_owned()],
        &["hostedRelease.entry", "hostedRelease.executionCandidate", "hostedRelease.freezeSchema", "hostedRelease.freezeRecord", "hostedRelease.freezeTotals",
            "hostedRelease.freezeFile", "hostedRelease.pin", "hostedRelease.freezeAttest", "hostedRelease.runtimeStage",
            "hostedRelease.archivePin", "hostedRelease.archivePath", "hostedRelease.generation", "hostedRelease.reload",
            "hostedRelease.admissionPointer", "hostedRelease.admissionArtifact", "hostedRelease.admissionParent", "hostedRelease.pointerUnchanged",
            "hostedRelease.atlasRequirement", "hostedRelease.childEndpoint", "hostedRelease.generationReady",
            "hostedRelease.proxyHeaders", "hostedRelease.childLaunch", "hostedRelease.childBasis",
            "hostedRelease.childIdentity", "hostedRelease.childRuntime", "hostedRelease.childPrepared", "hostedRelease.childExecutable", "hostedRelease.cutover"],
        &BTreeSet::from(["text.matches", "number.calculate", "text.split", "text.join", "json.stringify",
            "digest.sha256", "record.put", "kernel.invoke", "record.entries", "value.type", "record.fromEntries",
            "json.canonical"]), &mut Meter::new(4_000_000))
}

fn governance_policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_admission_governance.encounter").to_owned()],
        &["admissionGovernance.artifact", "admissionGovernance.authorizationBasis", "admissionGovernance.authorization",
            "admissionGovernance.authoringParent", "admissionGovernance.authoringParentBinding"],
        &BTreeSet::from(["kernel.invoke", "value.type", "value.string", "value.sort", "text.trim", "text.matches",
            "json.canonical", "digest.sha256", "number.calculate", "number.isNatural", "record.put"]),
        &mut Meter::new(4_000_000))
}

pub(super) fn decide(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(200_000))
}

pub(super) fn observed_generation(policy: &Programme, root: &Path, state: &Path, paths: &[String], release: &Value) -> Result<Value> {
    let source = source_identity(root, state, paths)?;
    decide(policy, "hostedRelease.generation", json!({
        "sourceTreeHash":source["treeHash"], "releasePointerHash":release["pointerHash"],
    }))
}

pub(crate) fn generation(source: &str, release: &str) -> Result<()> {
    let result = decide(&policy()?, "hostedRelease.generation", json!({
        "sourceTreeHash": source, "releasePointerHash": release
    }))?;
    println!("{result}");
    Ok(())
}

pub(crate) enum WorkerDecision { Launch, Basis, Identity, Cutover }

pub(crate) fn worker_decision(decision: WorkerDecision) -> Result<()> {
    const LIMIT: u64 = 8 * 1024;
    let mut bytes = Vec::new();
    io::stdin().lock().take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(fail("Hosted worker decision exceeds its input limit"));
    }
    let input = serde_json::from_slice(&bytes)?;
    let entry = match decision {
        WorkerDecision::Launch => "hostedRelease.childLaunch",
        WorkerDecision::Basis => "hostedRelease.childBasis",
        WorkerDecision::Identity => "hostedRelease.childIdentity",
        WorkerDecision::Cutover => "hostedRelease.cutover",
    };
    serde_json::to_writer(io::stdout().lock(), &decide(&policy()?, entry, input)?)?;
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerRelease {
    source_root: std::path::PathBuf,
    state_root: std::path::PathBuf,
    source_paths: Vec<String>,
    release_pointer: std::path::PathBuf,
    closure_store: String,
    composition_pin: String,
    temple_pin: String,
    runtime: Value,
    expected: Value,
}

pub(crate) fn worker_release() -> Result<()> {
    let _signals = Supervisor::new();
    let input = crate::platform_import_closure::read_bounded_observation(1024 * 1024)?;
    let request: WorkerRelease = serde_json::from_value(input)?;
    crate::hosted_generation_supervisor::require_matched_runtime(&request.source_root)?;
    let gate = supervisor_dependency_gate(json!({
        "store":request.closure_store, "pin":request.composition_pin,
    }))?;
    let policy = policy()?;
    decide(&policy, "hostedRelease.pin", json!(request.temple_pin))?;
    let dependencies = crate::hosted_composition::audit_release(&request.source_root.canonicalize()?,
        Path::new(crate::hosted_generation_process::text(&gate, "store")?),
        Some(crate::hosted_generation_process::text(&gate, "pin")?), Some(&request.temple_pin))?;
    decide(&policy, "hostedRelease.childRuntime", json!({
        "expected":dependencies["platform"], "observed":request.runtime,
    }))?;
    let release = admission_identity(&request.source_root, &request.release_pointer)?;
    let observed = observed_generation(&policy, &request.source_root, &request.state_root, &request.source_paths, &release)?;
    decide(&policy, "hostedRelease.childIdentity", json!({"expected":request.expected,"observed":observed}))?;
    http::check_interruption(false)?;
    serde_json::to_writer(io::stdout().lock(), &observed)?;
    Ok(())
}

pub(crate) fn supervisor_config() -> Result<()> {
    const LIMIT: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    io::stdin().lock().take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT { return Err(fail("Hosted supervisor configuration exceeds its input limit")); }
    let config: Value = serde_json::from_slice(&bytes)?;
    serde_json::to_writer(io::stdout().lock(), &supervisor_settings(config)?)?;
    Ok(())
}

pub(super) fn supervisor_settings(config: Value) -> Result<Value> {
    let policy = Programme::admit_entries(&[include_str!("hosted_supervisor_config.encounter").to_owned(),
        include_str!("hosted_launch_config.encounter").to_owned()],
        &["hostedSupervisor.config"], &BTreeSet::from(["path.resolvePosix", "kernel.invoke", "json.parse", "text.trim",
            "text.matches", "text.startsWith", "text.slice", "text.split", "number.parse", "number.isNatural",
            "number.calculate", "value.type"]), &mut Meter::new(200_000))?;
    policy.run("hostedSupervisor.config", config, &mut Meter::new(4_000_000))
}

pub(super) fn supervisor_dependency_gate(input: Value) -> Result<Value> {
    let entry = "hostedSupervisor.dependencyGate";
    let policy = Programme::admit(&[include_str!("hosted_supervisor_config.encounter").to_owned(),
        include_str!("hosted_launch_config.encounter").to_owned()], entry,
        &BTreeSet::from(["text.trim", "text.startsWith", "text.matches"]), &mut Meter::new(200_000))?;
    decide(&policy, entry, input)
}

pub(crate) struct GenerationProbe<'a> {
    pub expected_host: &'a str,
    pub observed_host: &'a str,
    pub observed_port: &'a str,
    pub observed_generation: &'a str,
    pub source: &'a str,
    pub release: &'a str,
    pub generation: &'a str,
    pub timeout_ms: u64,
}

pub(crate) fn generation_readiness(probe: GenerationProbe<'_>) -> Result<()> {
    let _signals = Supervisor::new();
    let result = probe_generation(&policy()?, probe, || Ok(true))?;
    serde_json::to_writer(io::stdout().lock(), &result)?;
    Ok(())
}

pub(super) fn probe_generation(policy: &Programme, probe: GenerationProbe<'_>,
    mut alive: impl FnMut() -> Result<bool>) -> Result<Value> {
    const LIMIT: u64 = 1024 * 1024;
    let port = probe.observed_port.parse::<u16>().unwrap_or(0);
    let endpoint = decide(policy, "hostedRelease.childEndpoint", json!({
        "host": probe.observed_host, "expectedHost": probe.expected_host, "port": port, "timeoutMs": probe.timeout_ms,
        "endpointGenerationHash": probe.observed_generation, "sourceTreeHash": probe.source,
        "releasePointerHash": probe.release, "generationHash": probe.generation
    }))?;
    if endpoint != true {
        return Err(fail(json!({"code":"hosted-production-child-endpoint-invalid",
            "message":"Hosted production child reported an invalid bound endpoint."}).to_string()));
    }
    let forwarding = decide(policy, "hostedRelease.proxyHeaders", Value::Null)?;
    let protocol = forwarding["request"]["x-forwarded-proto"].as_str()
        .ok_or_else(|| fail("Hosted forwarding policy lacks its trusted protocol"))?;
    let address = SocketAddr::new(probe.observed_host.parse::<IpAddr>()?, port);
    let request = format!("GET /readyz HTTP/1.1\r\nHost: {address}\r\nX-Forwarded-Proto: {protocol}\r\nConnection: close\r\n\r\n");
    let deadline = Instant::now() + Duration::from_millis(probe.timeout_ms);
    loop {
        http::check_interruption(false)?;
        if !alive()? { return Err(fail("Production child exited during readiness")); }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { break; }
        let observed = (|| -> Result<(u16, Value)> {
            let mut response = http::LoopbackReply::open_addr(address, request.as_bytes(), remaining.min(Duration::from_secs(1)))?;
            let (status, headers) = http::read_response_head(&mut response)?;
            let mut body = Vec::new();
            http::copy_response_body(&mut response, &headers, &mut body, LIMIT)?;
            Ok((status, serde_json::from_slice(&body)?))
        })();
        if let Ok((status, body)) = observed {
            let ready = decide(policy, "hostedRelease.generationReady", json!({
                "status": status, "body": body, "sourceTreeHash": probe.source, "releasePointerHash": probe.release,
                "generationHash": probe.generation
            }))?;
            if ready == true {
                http::check_interruption(false)?;
                return Ok(json!({"readiness":body,"forwarding":forwarding}));
            }
        }
        thread::sleep(deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(100)));
    }
    Err(fail(json!({"code":"hosted-production-generation-not-ready",
        "message":"Hosted production generation failed readiness before the startup deadline."}).to_string()))
}

pub(crate) fn reload(active: bool, candidate: &str, accepted: &str, rejected: Option<&str>) -> Result<()> {
    let result = decide(&policy()?, "hostedRelease.reload", json!({
        "active": active, "candidate": candidate, "accepted": accepted, "rejected": rejected
    }))?;
    println!("{result}");
    Ok(())
}

fn read_admission_file(work: &Work, sources: &Sources, name: &str, limit: u64) -> Result<(Vec<u8>, String)> {
    let observed = sources.observe_relative(name)?;
    let observed_metadata = observed.metadata()?;
    if !observed_metadata.is_file() || observed_metadata.len() > limit {
        return Err(fail("Hosted admission requires a bounded regular file without links."));
    }
    let mut file = File::open(format!("/proc/self/fd/{}", observed.as_raw_fd()))?;
    let metadata = file.metadata()?;
    let mut content = Vec::new();
    let (bytes, sha256) = work.copy(&mut file, &mut content, limit)?;
    let named = sources.observe_relative(name)?.metadata()?;
    if bytes != metadata.len() || identity(&named) != identity(&metadata)
        || named.ino() != metadata.ino() || named.dev() != metadata.dev() {
        return Err(fail("The hosted admission file changed during inspection."));
    }
    Ok((content, sha256))
}

fn admission_directory<'a>(root: &Path, path: &'a Path) -> Result<(Sources, &'a str)> {
    if !root.is_absolute() || !path.is_absolute() {
        return Err(fail("Expected absolute hosted release and admission pointer paths"));
    }
    let relative = path.strip_prefix(root).map_err(|_| fail("Hosted admission pointer is outside the release root"))?;
    let name = relative.file_name().and_then(|name| name.to_str()).ok_or_else(|| fail("Expected a hosted pointer name"))?;
    let directory = relative.parent().and_then(Path::to_str).ok_or_else(|| fail("Expected a hosted admission directory"))?;
    let sources = Sources::open(root)?;
    let sources = if directory.is_empty() { sources } else { sources.open_directory_relative(directory)? };
    Ok((sources, name))
}

fn admission_pointer_record(work: &Work, policy: &Programme, sources: &Sources, name: &str) -> Result<Value> {
    let (content, sha256) = read_admission_file(work, sources, name, POINTER_LIMIT)?;
    let pointer: Value = serde_json::from_slice(&content)?;
    decide(policy, "hostedRelease.admissionPointer", json!({
        "pointer": pointer, "bytes": content.len(), "sha256": sha256
    }))
}

pub(crate) fn admission_pointer(root: &Path, path: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    let (sources, name) = admission_directory(root, path)?;
    let result = admission_pointer_record(&Work::new(Duration::from_secs(2)), &policy()?, &sources, name)?;
    println!("{result}");
    Ok(())
}

fn admission_payload(artifact: &[u8]) -> Result<&[u8]> {
    artifact.strip_prefix(ADMISSION_MAGIC).ok_or_else(|| fail("Invalid hosted admission artifact header"))
}

fn verify_admission_governance(policy: &Programme, body: &Value, meter: &mut Meter) -> Result<Value> {
    policy.run("admissionGovernance.artifact", json!({
        "application": body["application"], "lineage": body["lineage"], "manifest": body["stewardshipManifest"]
    }), meter)
}

fn authoring_parent_link(policy: &Programme, body: &Value, meter: &mut Meter) -> Result<Value> {
    policy.run("admissionGovernance.authoringParent", json!({
        "parent": body["authoringSnapshot"]["authoringIntent"]["parent"], "lineageParents": body["lineage"]["parents"]
    }), meter)
}

fn verify_admission_snapshot(body: &Value) -> Result<()> {
    let Some(snapshot) = body.get("authoringSnapshot") else { return Ok(()) };
    let policy = Programme::admit_entries(&[include_str!("hosted_admission_authoring.encounter").to_owned()],
        &["admissionAuthoring.snapshot"],
        &BTreeSet::from(["kernel.invoke", "record.entries", "record.fromEntries", "record.put", "json.canonical",
            "digest.sha256", "value.type", "value.sort", "text.matches", "text.startsWith", "number.calculate", "number.isNatural"]),
        &mut Meter::new(300_000))?;
    policy.run("admissionAuthoring.snapshot", json!({
        "snapshot": snapshot, "application": body["application"]
    }), &mut Meter::new(4 * ADMISSION_ARTIFACT_LIMIT as usize))?;
    let Some(generation) = snapshot["authoringIntent"].get("generation") else { return Ok(()) };
    let evidence = Programme::admit_entries(&[include_str!("hosted_admission_evidence.encounter").to_owned(),
        include_str!("hosted_admission_handoff.encounter").to_owned()],
        &["admissionEvidence.verify", "admissionEvidence.humanPolicy"],
        &BTreeSet::from(["kernel.invoke", "record.entries", "record.fromEntries", "record.put", "json.canonical",
            "json.canonicalCompact", "json.stringify", "digest.sha256", "text.matches", "text.trim", "text.startsWith",
            "value.type", "value.sort", "number.calculate", "number.isNatural", "time.parseRfc3339", "time.formatUtc"]),
        &mut Meter::new(500_000))?;
    let mut meter = Meter::new(8 * ADMISSION_ARTIFACT_LIMIT as usize);
    if evidence.run("admissionEvidence.verify", generation.clone(), &mut meter)? == true {
        let executable = std::env::current_exe()?;
        let root = executable.parent().ok_or_else(|| fail("Expected a hosted release runtime directory"))?;
        let source = Sources::open(root)?.read_text("plugins/sourcery-app-foundation/stdlib.rel", &mut meter)?;
        let facts = crate::rel::relations(source.as_str().ok_or_else(|| fail("Expected installed human interaction authority"))?)?;
        evidence.run("admissionEvidence.humanPolicy", facts, &mut meter)?;
    }
    Ok(())
}

fn verify_admission_atlas(policy: &Programme, body: &Value) -> Result<()> {
    let facts = body["facts"].as_array().ok_or_else(|| fail("Expected admitted facts for System Atlas"))?;
    let coordinates: Vec<_> = facts.iter().map(|fact| {
        let field = |primary: &str, alias: &str| fact.get(primary).filter(|value| !value.is_null())
            .unwrap_or(&fact[alias]);
        [field("s", "subject"), field("p", "predicate"), field("o", "object"), &fact["pol"]]
    }).collect();
    let required = policy.run("hostedRelease.atlasRequirement", json!({
        "facts": coordinates, "report": body["systemAtlasConformance"]
    }), &mut Meter::new(2 * ADMISSION_ARTIFACT_LIMIT as usize))?;
    if required == true {
        let atlas = Programme::admit_entries(&[include_str!("hosted_admission_atlas.encounter").to_owned()],
            &["admissionAtlas.verify"], &BTreeSet::from(["kernel.invoke", "record.fromEntries", "value.sort",
                "value.sortJson", "value.groupTextPairs", "value.string", "text.trimFields", "text.base64url",
                "json.canonicalCompact", "digest.sha256"]), &mut Meter::new(200_000))?;
        let application = body.get("application").cloned().unwrap_or_else(|| json!("admission-candidate"));
        atlas.run("admissionAtlas.verify", json!({
            "coordinates": coordinates, "application": application, "report": body["systemAtlasConformance"]
        }), &mut Meter::new(8 * ADMISSION_ARTIFACT_LIMIT as usize))?;
    }
    Ok(())
}

struct RetainedAdmissionParent {
    stewardship: Value,
    intent_hash: Value,
}

fn read_admission_parent(work: &Work, sources: &Sources, expected: &str, policy: &Programme,
    governance: &Programme, meter: &mut Meter) -> Result<RetainedAdmissionParent>
{
    let (artifact, observed) = read_admission_file(work, sources, &format!("{expected}.sapp"), ADMISSION_ARTIFACT_LIMIT)?;
    let parent: Value = serde_json::from_slice(admission_payload(&artifact)?)?;
    policy.run("hostedRelease.admissionParent", json!({
        "observed": observed, "expected": expected, "protocol": parent["protocol"], "facts": parent["facts"].is_array()
    }), meter)?;
    verify_admission_atlas(policy, &parent)?;
    let stewardship = verify_admission_governance(governance, &parent, meter)?;
    verify_admission_snapshot(&parent)?;
    authoring_parent_link(governance, &parent, meter)?;
    let intent_hash = parent["authoringSnapshot"]["authoringIntent"]["hash"].clone();
    Ok(RetainedAdmissionParent { stewardship, intent_hash })
}

pub(crate) fn admission_artifact(root: &Path, path: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    serde_json::to_writer(io::stdout().lock(), &admission_identity(root, path)?)?;
    Ok(())
}

pub(super) fn admission_identity(root: &Path, path: &Path) -> Result<Value> {
    let work = Work::new(Duration::from_secs(15));
    let policy = policy()?;
    let (sources, name) = admission_directory(root, path)?;
    let record = admission_pointer_record(&work, &policy, &sources, name)?;
    let pointer = &record["pointer"];
    let artifact_name = pointer["artifact"].as_str().ok_or_else(|| fail("Expected an admitted artifact name"))?;
    let receipt_name = pointer["receipt"].as_str().ok_or_else(|| fail("Expected an admitted receipt name"))?;
    let (receipt, _) = read_admission_file(&work, &sources, receipt_name, POINTER_LIMIT)?;
    let (artifact, sha256) = read_admission_file(&work, &sources, artifact_name, ADMISSION_ARTIFACT_LIMIT)?;
    let payload = admission_payload(&artifact)?;
    let body: Value = serde_json::from_slice(payload)?;
    let receipt: Value = serde_json::from_slice(&receipt)?;
    let binding = json!({
        "pointer": pointer, "receipt": receipt, "artifact": {
            "sha256": sha256, "bytes": artifact.len(), "protocol": body["protocol"], "application": body["application"],
            "factCount": body["facts"].as_array().map(Vec::len),
            "snapshotHash": body["authoringSnapshot"]["hash"], "intentHash": body["authoringSnapshot"]["authoringIntent"]["hash"],
            "stewardshipHash": body["stewardshipManifest"]["hash"], "lineageHash": body["lineage"]["hash"],
            "authorizationHash": body["governanceAuthorizationReceipt"]["receiptHash"],
            "conformanceHash": body["systemAtlasConformance"]["reportHash"]
        }
    });
    let mut meter = Meter::new(8_000_000);
    policy.run("hostedRelease.admissionArtifact", binding, &mut meter)?;
    verify_admission_atlas(&policy, &body)?;
    verify_admission_snapshot(&body)?;
    let governance = governance_policy()?;
    let successor = verify_admission_governance(&governance, &body, &mut meter)?;
    let authorization = &body["governanceAuthorizationReceipt"];
    let basis = governance.run("admissionGovernance.authorizationBasis", authorization.clone(), &mut meter)?;
    let intent_parent = authoring_parent_link(&governance, &body, &mut meter)?;
    let mut parents = BTreeMap::new();
    for hash in [basis.as_str(), intent_parent["artifactHash"].as_str()].into_iter().flatten() {
        if let std::collections::btree_map::Entry::Vacant(entry) = parents.entry(hash) {
            entry.insert(read_admission_parent(&work, &sources, hash, &policy, &governance, &mut meter)?);
        }
    }
    if let Some(hash) = basis.as_str() {
        governance.run("admissionGovernance.authorization", json!({
            "application": body["application"], "parentHash": hash, "priorManifest": parents[hash].stewardship,
            "successorHash": successor["hash"], "receipt": authorization
        }), &mut meter)?;
    }
    if let Some(hash) = intent_parent["artifactHash"].as_str() {
        governance.run("admissionGovernance.authoringParentBinding", json!({
            "observed": parents[hash].intent_hash, "expected": intent_parent["intentHash"]
        }), &mut meter)?;
    }
    let (current_sources, current_name) = admission_directory(root, path)?;
    let current = admission_pointer_record(&work, &policy, &current_sources, current_name)?;
    policy.run("hostedRelease.pointerUnchanged", json!({
        "before": record["identity"]["pointerHash"], "after": current["identity"]["pointerHash"]
    }), &mut meter)?;
    work.check()?;
    Ok(record["identity"].clone())
}

struct Scan<'a> {
    root: &'a Path,
    state: Option<&'a Path>,
    sources: Sources,
    policy: Programme,
    deadline: Instant,
    visited: usize,
    inventory: bool,
}

fn missing(error: &(dyn std::error::Error + 'static), number: i32) -> bool {
    error.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error) == Some(number)
}

impl<'a> Scan<'a> {
    fn open(root: &'a Path, state: Option<&'a Path>) -> Result<Self> {
        if !root.is_absolute() { return Err(fail("Expected a physical absolute hosted release tree")); }
        Ok(Self { root, state, sources: Sources::open_physical(root)?, policy: policy()?,
            deadline: Instant::now() + Duration::from_secs(60), visited: 0, inventory: false })
    }

    fn check(&self) -> Result<()> {
        if interruption().is_some() { return Err(fail("Hosted release identity check interrupted")); }
        if Instant::now() >= self.deadline { return Err(fail("Hosted release identity check timed out")); }
        Ok(())
    }

    fn verify_root(&self) -> Result<()> {
        let opened = self.sources.root()?.metadata()?;
        let named = self.root.symlink_metadata()?;
        if !named.is_dir() || (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
            return Err(fail("Hosted release root changed during observation"));
        }
        Ok(())
    }

    fn classify(&self, path: &str, kind: &str) -> Result<Value> {
        let path_obj = Path::new(path);
        let name = path_obj.file_name().and_then(|value| value.to_str()).unwrap_or_default();
        let extension = name.rsplit_once('.').map(|(_, suffix)| suffix.to_ascii_lowercase()).unwrap_or_default();
        decide(&self.policy, "hostedRelease.entry", json!({"kind":kind,"name":name,"path":path,"extension":extension,
            "temple":self.state.is_none(),"state":self.state.is_some_and(|state| self.root.join(path).starts_with(state)),
            "inventory":self.inventory}))
    }

    fn discover(&mut self, path: &str, depth: usize, output: &mut Vec<String>) -> Result<()> {
        self.check()?;
        self.visited += 1;
        if self.visited > ENTRY_LIMIT || depth > 128 { return Err(fail("Hosted release source tree exceeds its entry or depth bound")); }
        let file = if path.is_empty() { self.sources.root()? } else { self.sources.observe_relative(path)? };
        let metadata = file.metadata()?;
        let kind = if metadata.is_dir() { "directory" } else if metadata.is_file() { "file" } else { "other" };
        let decision = self.classify(path, kind)?;
        match decision.as_str() {
            Some("skip") => {}
            Some("file") => output.push(path.to_owned()),
            Some("reject") => return Err(fail(format!("Hosted release source must be a regular file without links: {path}"))),
            Some("directory") => {
                let mut children = Vec::new();
                for (index, entry) in fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))?.enumerate() {
                    self.check()?;
                    let entry = entry?;
                    if index == ENTRY_LIMIT { return Err(fail("Hosted release directory exceeds its entry bound")); }
                    let name = entry.file_name().into_string().map_err(|_| fail("Hosted release path must be UTF-8"))?;
                    let child = if path.is_empty() { name.clone() } else { format!("{path}/{name}") };
                    let kind = entry.file_type()?;
                    let kind = if kind.is_dir() { "directory" } else if kind.is_file() { "file" } else { "other" };
                    match self.classify(&child, kind)?.as_str() {
                        Some("skip") => {}
                        Some("reject") => return Err(fail(format!("Hosted release source must be a regular file without links: {child}"))),
                        _ => children.push((name, child)),
                    }
                }
                children.sort_by(|left, right| compat_value::compare(&left.0, &right.0));
                for (_, child) in children { self.discover(&child, depth + 1, output)?; }
            }
            _ => return Err(fail("Unknown hosted release tree entry decision")),
        }
        Ok(())
    }

    fn regular(&self, path: &str) -> Result<File> {
        let observed = self.sources.observe_relative(path)?;
        if !observed.metadata()?.is_file() { return Err(fail("Hosted release source must be a regular file without links")); }
        Ok(File::open(format!("/proc/self/fd/{}", observed.as_raw_fd()))?)
    }

    fn hash(&self, files: &[String], frozen: Option<&BTreeMap<String, FrozenFile>>) -> Result<String> {
        let temple = self.state.is_none();
        let mut tree = Sha256::new();
        tree.update(if temple { TEMPLE_PROTOCOL } else { SOURCE_PROTOCOL });
        tree.update(b"\0");
        let mut total = 0_u64;
        let mut buffer = [0_u8; 65_536];
        for path in files {
            self.check()?;
            let mut file = self.regular(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > FILE_LIMIT { return Err(fail("Hosted release file is absent or exceeds its size bound")); }
            total = total.checked_add(metadata.len()).filter(|size| *size <= TREE_LIMIT).ok_or_else(|| fail("Hosted release tree exceeds its byte bound"))?;
            if !temple && path == "encounter" {
                require_native_runtime_file(&mut file)?;
                if metadata.mode() & 0o022 != 0 {
                    return Err(fail("Hosted generation requires a protected native Encounter binary"));
                }
                file.seek(SeekFrom::Start(0))?;
            }
            tree.update(path);
            tree.update(b"\0");
            if temple { tree.update(metadata.len().to_string()); tree.update(b"\0"); }
            let mut count = 0;
            let mut digest = Sha256::new();
            loop {
                self.check()?;
                let size = file.read(&mut buffer)?;
                if size == 0 { break; }
                count += size as u64;
                if count > metadata.len() { return Err(fail("Hosted release file changed during observation")); }
                tree.update(&buffer[..size]);
                if frozen.is_some() { digest.update(&buffer[..size]); }
            }
            if count != metadata.len() || identity(&file.metadata()?) != identity(&metadata) {
                return Err(fail("Hosted release file changed during observation"));
            }
            if let Some(frozen) = frozen {
                let declared = &frozen[path];
                if decide(&self.policy, "hostedRelease.freezeFile", json!({"declaredBytes":declared.bytes,"observedBytes":count,
                    "declaredSha256":declared.sha256,"observedSha256":hex::encode(digest.finalize())}))? != true {
                    return Err(fail(json!({"code":"hosted-temple-freeze-file-mismatch",
                        "message":format!("Temple frozen file failed its manifest identity: {path}")}).to_string()));
                }
            }
            tree.update(b"\0");
        }
        self.verify_root()?;
        Ok(hex::encode(tree.finalize()))
    }
}

fn identity(metadata: &Metadata) -> (u64, i64, i64, i64, i64) {
    (metadata.len(), metadata.ctime(), metadata.ctime_nsec(), metadata.mtime(), metadata.mtime_nsec())
}

#[derive(PartialEq)]
struct FrozenFile { bytes: u64, sha256: String }

struct Frozen { files: BTreeMap<String, FrozenFile>, order: Vec<String> }

fn manifest(scan: &Scan<'_>) -> Result<Option<Frozen>> {
    let file = match scan.regular("FREEZE.json") {
        Ok(file) => file,
        Err(error) if missing(error.as_ref(), libc::ENOENT) => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MANIFEST_LIMIT { return Err(fail("Temple FREEZE.json exceeds its byte bound")); }
    let mut bytes = Vec::new();
    file.take(MANIFEST_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MANIFEST_LIMIT { return Err(fail("Temple FREEZE.json exceeds its byte bound")); }
    let manifest: Value = serde_json::from_slice(&bytes)?;
    let lockfiles = manifest["platform"]["lockfiles"].as_array();
    let components = manifest["components"].as_array();
    let runtime = manifest["platformRuntimeFiles"].as_array();
    let totals = &manifest["totals"];
    decide(&scan.policy, "hostedRelease.freezeSchema", json!({"version":manifest["schemaVersion"],"package":manifest["platform"]["package"],
        "lockfiles":lockfiles.is_some(),"components":components.is_some(),"componentFiles":components.is_some_and(|items| items.iter().all(|value| value["files"].is_array())),
        "runtime":runtime.is_some(),"totals":totals.is_object()}))?;
    let lockfiles = lockfiles.ok_or_else(|| fail("Missing Temple lockfiles"))?;
    let components = components.ok_or_else(|| fail("Missing Temple components"))?;
    let runtime = runtime.ok_or_else(|| fail("Missing Temple platform runtime files"))?;
    let component_files = components.iter().flat_map(|item| item["files"].as_array().into_iter().flatten());
    let component_count = component_files.clone().count();
    let mut entries = BTreeMap::new();
    let mut order = Vec::new();
    for (index, record) in lockfiles.iter().chain(component_files).chain(runtime).enumerate() {
        scan.check()?;
        if index >= ENTRY_LIMIT { return Err(fail("Temple freeze exceeds its file count bound")); }
        let path = record["path"].as_str().unwrap_or_default();
        let bytes = record["bytes"].as_u64();
        let observed = FrozenFile { bytes: bytes.unwrap_or_default(), sha256: record["sha256"].as_str().unwrap_or_default().to_owned() };
        decide(&scan.policy, "hostedRelease.freezeRecord", json!({"path":path,"bytes":observed.bytes,"sha256":observed.sha256,
            "unsigned":bytes.is_some(),"consistent":entries.get(path).is_none_or(|retained| retained == &observed)}))?;
        if entries.insert(path.to_owned(), observed).is_none() { order.push(path.to_owned()); }
    }
    let bytes = entries.values().try_fold(0_u64, |total, record| total.checked_add(record.bytes)).ok_or_else(|| fail("Temple freeze totals exceed their bound"))?;
    let declared = |key| totals[key].as_u64();
    decide(&scan.policy, "hostedRelease.freezeTotals", json!({"declared":{"components":declared("components"),"componentFiles":declared("componentFiles"),
        "platformRuntimeFiles":declared("platformRuntimeFiles"),"files":declared("files"),"bytes":declared("bytes")},
        "observed":{"components":components.len(),"componentFiles":component_count,"platformRuntimeFiles":runtime.len(),"files":entries.len(),"bytes":bytes}}))?;
    Ok(Some(Frozen { files: entries, order }))
}

pub(super) fn temple_identity(root: &Path, expected: Option<&str>) -> Result<Value> {
    let mut scan = Scan::open(root, None)?;
    if let Some(expected) = expected { decide(&scan.policy, "hostedRelease.pin", json!(expected))?; }
    let (files, tree_hash) = if let Some(Frozen { files: frozen, order: mut files }) = manifest(&scan)? {
        files.sort_by(|left, right| compat_value::compare(left, right));
        let hash = scan.hash(&files, Some(&frozen))?;
        (files, hash)
    } else {
        let mut files = Vec::new();
        scan.discover("", 0, &mut files)?;
        let hash = scan.hash(&files, None)?;
        (files, hash)
    };
    let result = json!({"root":root,"fileCount":files.len(),"treeHash":tree_hash});
    let Some(expected) = expected else { return Ok(result); };
    let mut input = result;
    input["expected"] = json!(expected);
    let mut attestation = decide(&scan.policy, "hostedRelease.freezeAttest", input)?;
    if attestation["status"] != "frozen" {
        attestation["message"] = json!("Temple differs from the frozen production identity.");
        return Err(fail(attestation.to_string()));
    }
    Ok(attestation)
}

fn source_files<'a>(root: &'a Path, state: &'a Path, paths: &[String], inventory: bool) -> Result<(Scan<'a>, Vec<String>)> {
    if !state.is_absolute() || paths.is_empty() || paths.len() > 256 { return Err(fail("Invalid hosted source tree selection")); }
    let mut scan = Scan::open(root, Some(state))?;
    scan.inventory = inventory;
    let mut files = Vec::new();
    for path in paths {
        let relative = Path::new(path).strip_prefix(root).map_err(|_| fail("Hosted source path must stay below its release root"))?;
        if !relative.components().all(|part| matches!(part, Component::Normal(_))) {
            return Err(fail("Hosted source path has an invalid component"));
        }
        scan.discover(relative.to_str().ok_or_else(|| fail("Hosted source path must be UTF-8"))?, 0, &mut files)?;
    }
    files.sort_by(|left, right| compat_value::compare(left, right));
    let mut seen = BTreeSet::new();
    files.retain(|file| seen.insert(file.clone()));
    Ok((scan, files))
}

pub(super) fn source_identity(root: &Path, state: &Path, paths: &[String]) -> Result<Value> {
    let (scan, files) = source_files(root, state, paths, false)?;
    Ok(json!({"treeHash":scan.hash(&files, None)?,"fileCount":files.len()}))
}

pub(crate) fn execution_candidates(root: &Path, state: &Path, paths: &[String]) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", execution_inventory(root, state, paths)?);
    Ok(())
}

fn execution_inventory(root: &Path, state: &Path, paths: &[String]) -> Result<Value> {
    let (scan, files) = source_files(root, state, paths, true)?;
    let mut candidates = Vec::new();
    for path in &files {
        scan.check()?;
        let file = scan.regular(path)?;
        let mode = file.metadata()?.mode();
        let mut head = Vec::new();
        file.take(4).read_to_end(&mut head)?;
        let extension = Path::new(path).extension().and_then(|ext| ext.to_str()).unwrap_or_default().to_ascii_lowercase();
        let candidate = decide(&scan.policy, "hostedRelease.executionCandidate", json!({
            "path":path, "extension":extension, "shebang":head.starts_with(b"#!"),
            "elf":head.starts_with(b"\x7fELF"), "executable":mode & 0o111 != 0,
        }))?;
        if !candidate.is_null() { candidates.push(candidate); }
    }
    scan.verify_root()?;
    Ok(json!({"protocol":"sourcery.hosted/execution-candidates.v1",
        "fileCount":files.len(), "candidates":candidates}))
}

pub(crate) fn temple(root: &Path, expected: Option<&str>) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", temple_identity(root, expected)?);
    Ok(())
}

pub(crate) fn source(root: &Path, state: &Path, paths: &[String]) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", source_identity(root, state, paths)?);
    Ok(())
}

pub(crate) fn development_source(root: &Path, state: &Path, paths: &[String]) -> Result<()> {
    let _signals = Supervisor::new();
    let mut result = source_identity(root, state, paths)?;
    result["repositoryRevision"] = match root.join(".git").symlink_metadata() {
        Ok(metadata) if metadata.is_dir() || metadata.is_file() => {
            let mut git = crate::development_receive::git()?;
            let bytes = Supervisor::children().capture("Read development generation revision",
                git.arg("-C").arg(root).args(["rev-parse", "--verify", "HEAD^{commit}"]),
                Duration::from_secs(5), 64)?;
            json!(crate::development_receive::revision_text(&bytes)?)
        }
        Ok(_) => return Err(fail("Expected physical development Git metadata")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Value::Null,
        Err(error) => return Err(error.into()),
    };
    println!("{result}");
    Ok(())
}

fn verify_archive(work: &Work, policy: &Programme, archive: &Path, expected: &str, output: &mut impl Write) -> Result<Value> {
    decide(policy, "hostedRelease.pin", json!(expected))?;
    let (_, observed) = work.copy(&mut archive::input(archive, ARCHIVE_LIMIT)?, output, ARCHIVE_LIMIT)?;
    decide(policy, "hostedRelease.archivePin", json!({"expected":expected,"observed":observed}))
}

pub(crate) fn check_archive(archive: &Path, expected: &str) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", check_archive_identity(archive, expected)?);
    Ok(())
}

pub(super) fn check_archive_identity(archive: &Path, expected: &str) -> Result<Value> {
    verify_archive(&Work::new(Duration::from_secs(60)), &policy()?, archive, expected, &mut io::sink())
}

pub(super) fn install_archive(archive: &Path, expected: &str, tree: &str, target: &Path) -> Result<Value> {
    if !target.is_absolute() || !target.ends_with("node_modules/@temple2/platform-sdk") {
        return Err(fail("Temple must enter a scoped dependency closure"));
    }
    let parent = target.parent().ok_or_else(|| fail("Missing Temple dependency parent"))?;
    let parent_handle = Sources::open_physical(parent)?.root()?;
    if parent.canonicalize()? != parent { return Err(fail("Temple dependency parent must be physical")); }
    if target.symlink_metadata().is_ok() { return Err(fail("Temple dependency destination already exists")); }
    let work = Work::new(Duration::from_secs(120));
    let policy = policy()?;
    decide(&policy, "hostedRelease.pin", json!(tree))?;
    let scratch = Scratch::create(parent, ".temple-install-")?;
    let mut compressed = archive::create(&scratch.path().join("archive.tar.gz"))?;
    verify_archive(&work, &policy, archive, expected, &mut compressed)?;
    compressed.seek(SeekFrom::Start(0))?;
    let staged = scratch.path().join("sdk");
    fs::create_dir(&staged)?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
    archive::unpack(&work, compressed, &staged, Modes::Dependency, |path, directory| {
        let path = decide(&policy, "hostedRelease.archivePath", json!({"path":path,"directory":directory}))?;
        path.as_str().map(str::to_owned).ok_or_else(|| fail("Expected an admitted Temple archive path"))
    }, |_, _| Ok(()))?;
    let mut receipt = temple_identity(&staged, Some(tree))?;
    archive::sync_directories(&work, &staged)?;
    let named = parent.symlink_metadata()?;
    let opened = parent_handle.metadata()?;
    if (named.dev(), named.ino()) != (opened.dev(), opened.ino()) { return Err(fail("Temple dependency parent changed during installation")); }
    work.check()?;
    rename_new_path(&staged, target)?;
    if let Err(error) = parent_handle.sync_all().map_err(Into::into).and_then(|()| work.check()) {
        rename_new_path(target, &staged)?;
        parent_handle.sync_all()?;
        return Err(error);
    }
    receipt["root"] = json!(target);
    receipt["archiveSha256"] = json!(expected);
    Ok(receipt)
}

pub(crate) fn install_temple(archive: &Path, expected: &str, tree: &str, target: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", install_archive(archive, expected, tree, target)?);
    Ok(())
}

pub(crate) fn stage_runtime(root: &Path, expected: &str) -> Result<()> {
    let _signals = Supervisor::new();
    let scan = Scan::open(root, None)?;
    decide(&scan.policy, "hostedRelease.pin", json!(expected))?;
    let mut runtime = File::open("/proc/self/exe")?;
    require_native_runtime_file(&mut runtime)?;
    let metadata = runtime.metadata()?;
    runtime.seek(SeekFrom::Start(0))?;
    let scratch = Scratch::create(root, ".encounter-stage-")?;
    let staged = scratch.path().join("encounter");
    let mut destination = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&staged)?;
    let mut digest = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0; 65_536];
    loop {
        scan.check()?;
        let count = runtime.read(&mut buffer)?;
        if count == 0 { break; }
        bytes += count as u64;
        if bytes > metadata.len() { return Err(fail("Encounter executable changed while staging")); }
        digest.update(&buffer[..count]);
        destination.write_all(&buffer[..count])?;
    }
    if identity(&runtime.metadata()?) != identity(&metadata) || bytes != metadata.len() {
        return Err(fail("Encounter executable changed while staging"));
    }
    let target = root.join("encounter");
    let receipt = decide(&scan.policy, "hostedRelease.runtimeStage", json!({"expected":expected,"observed":hex::encode(digest.finalize()),"bytes":bytes,"path":target}))?;
    destination.set_permissions(fs::Permissions::from_mode(0o755))?;
    destination.sync_all()?;
    File::open(scratch.path())?.sync_all()?;
    let parent = scan.sources.root()?;
    scan.check()?;
    scan.verify_root()?;
    rename_new_path(&staged, &target)?;
    if let Err(error) = parent.sync_all().map_err(Into::into).and_then(|()| scan.check()) {
        rename_new_path(&target, &staged)?;
        parent.sync_all()?;
        return Err(error);
    }
    println!("{receipt}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rel;
    use std::os::unix::fs::symlink;

    #[test]
    fn hosted_generation_keeps_its_wire_hash_and_retries_when_no_generation_is_alive() -> Result<()> {
        let programme = policy()?;
        let source = "a".repeat(64);
        let accepted = "b".repeat(64);
        let rejected = "c".repeat(64);
        let other = "d".repeat(64);
        let identity = decide(&programme, "hostedRelease.generation", json!({
            "sourceTreeHash":source, "releasePointerHash":accepted
        }))?;
        let legacy_wire = format!(r#"{{"protocol":"sourcery.hosted/production-generation-identity.v1","releasePointerHash":"{accepted}","sourceTreeHash":"{source}"}}"#);
        assert_eq!(identity["generationHash"], rel::hash(legacy_wire));
        assert!(decide(&programme, "hostedRelease.generation", json!({
            "sourceTreeHash":"invalid", "releasePointerHash":accepted
        })).is_err());
        let reload = |active, candidate: &str| decide(&programme, "hostedRelease.reload", json!({
            "active":active, "candidate":candidate, "accepted":accepted, "rejected":rejected
        }));
        assert_eq!(reload(true, &accepted)?, "identical-release");
        assert_eq!(reload(true, &rejected)?, "candidate-quarantined");
        assert_eq!(reload(true, &other)?, "replace");
        assert_eq!(reload(false, &accepted)?, "replace");
        assert_eq!(reload(false, &rejected)?, "replace");
        assert!(reload(true, "invalid").is_err());
        Ok(())
    }

    #[test]
    fn freeze_preserves_the_exact_wire_hash_and_refuses_tampered_manifest_files() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "hosted-freeze-")?;
        let root = fixture.path();
        fs::create_dir(root.join("runtime"))?;
        let source = b"export const version = 1;\n";
        let file = root.join("runtime/main.mjs");
        fs::write(&file, source)?;
        fs::create_dir(root.join("node_modules"))?;
        fs::write(root.join("node_modules/ignored"), b"ignored")?;
        let expected = rel::hash([format!("{TEMPLE_PROTOCOL}\0runtime/main.mjs\0{}\0", source.len()).as_bytes(), source, b"\0"].concat());
        assert_eq!(temple_identity(root, None)?["treeHash"], expected);
        let attestation = temple_identity(root, Some(&expected))?;
        assert_eq!(attestation["status"], "frozen");
        assert_eq!(attestation["fileCount"], 1);
        assert!(temple_identity(root, Some(&"0".repeat(64))).unwrap_err().to_string().contains("hosted-temple-freeze-mismatch"));

        let record = json!({"path":"runtime/main.mjs","bytes":source.len(),"sha256":rel::hash(source)});
        let mut manifest = json!({"schemaVersion":2,"platform":{"package":"@temple2/platform-sdk","lockfiles":[record]},
            "components":[],"platformRuntimeFiles":[record],"totals":{"components":0,"componentFiles":0,"platformRuntimeFiles":1,"files":1,"bytes":source.len()}});
        let freeze = root.join("FREEZE.json");
        fs::write(&freeze, serde_json::to_vec(&manifest)?)?;
        assert_eq!(temple_identity(root, Some(&expected))?["treeHash"], expected);
        manifest["platformRuntimeFiles"][0]["bytes"] = json!(source.len() + 1);
        fs::write(&freeze, serde_json::to_vec(&manifest)?)?;
        assert!(temple_identity(root, None).unwrap_err().to_string().contains("conflicting file records"));
        manifest["platformRuntimeFiles"][0]["bytes"] = json!(source.len());
        fs::write(&freeze, serde_json::to_vec(&manifest)?)?;
        fs::write(&file, b"modified")?;
        assert!(temple_identity(root, None).unwrap_err().to_string().contains("hosted-temple-freeze-file-mismatch"));
        fs::remove_file(&file)?;
        let outside = root.join("replacement");
        fs::write(&outside, source)?;
        symlink(outside, &file)?;
        assert!(temple_identity(root, None).unwrap_err().to_string().contains("without links"));
        Ok(())
    }

    #[test]
    fn source_identity_excludes_state_and_dependencies_and_binds_the_runtime_bytes() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "hosted-source-tree-")?;
        let root = fixture.path();
        let state = root.join("state");
        for path in [&state, &root.join("plugins"), &root.join("node_modules")] { fs::create_dir(path)?; }
        fs::write(state.join("private.json"), b"private")?;
        fs::write(root.join("node_modules/excluded.js"), b"excluded")?;
        symlink(state.join("private.json"), root.join("plugins/link.json"))?;
        let entry = root.join("plugins/main.mjs");
        fs::write(&entry, b"public")?;
        let select = |path: &Path| path.to_str().unwrap().to_owned();
        let paths = [select(root), select(&entry)];
        assert!(source_identity(root, &state, &paths).unwrap_err().to_string().contains("without links"));
        fs::remove_file(root.join("plugins/link.json"))?;
        let first = source_identity(root, &state, &paths)?;
        assert_eq!(first["fileCount"], 1);
        assert_eq!(first["treeHash"], rel::hash(format!("{SOURCE_PROTOCOL}\0plugins/main.mjs\0public\0")));
        fs::write(root.join("plugins/entry"), b"#!/bin/sh\nexit 0\n")?;
        let inventory = execution_inventory(root, &state, &paths)?;
        assert_eq!(inventory["candidates"], json!([
            {"path":"plugins/entry","kind":"shebang","executable":false},
            {"path":"plugins/main.mjs","kind":"mjs","executable":false},
        ]));
        assert_eq!(source_identity(root, &state, &paths)?, first);
        assert!(source_identity(root, &state, &[select(root.parent().unwrap())]).is_err());
        let runtime = root.join("encounter");
        fs::write(&runtime, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755))?;
        assert!(source_identity(root, &state, &paths).is_err());
        let mut elf = [0; 21];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..20].copy_from_slice(&[3, 0, 62, 0]);
        fs::write(&runtime, elf)?;
        let staged = source_identity(root, &state, &paths)?;
        assert_eq!(staged["fileCount"], 2);
        elf[20] = 1;
        fs::write(&runtime, elf)?;
        assert_ne!(source_identity(root, &state, &paths)?["treeHash"], staged["treeHash"]);
        for extension in ["cjs", "node", "sh", "py", "wasm", "encounter"] {
            let path = root.join(format!("plugins/sidecar.{extension}"));
            let before = source_identity(root, &state, &paths)?;
            fs::write(&path, b"new source")?;
            assert_ne!(source_identity(root, &state, &paths)?["treeHash"], before["treeHash"]);
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
