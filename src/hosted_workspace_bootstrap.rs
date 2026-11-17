use crate::{
    Result, appdev_host_process::{Scratch, Supervisor, exchange_paths, rename_new_path},
    compat_value, fail, hosted_production_manifest, hosted_workspace_storage, hosted_private_fs::{make_directory, private_directory, read_private},
    http, package::{observe_beneath, open_beneath}, process::{Meter, Programme},
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet, env, fs::{self, File, OpenOptions, Metadata},
    io::{self, Read, Write}, os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt}},
    path::{Path, PathBuf}, thread, time::{Duration, Instant, SystemTime},
};

const MARKER: &str = ".sourcery-workspace.json";
const RECEIPT: &str = ".sourcery-workspace-source-bootstrap.json";
const PRIVATE_LIMIT: usize = 8192;
const SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const SOURCE_FILES: usize = 20_000;
const PREFIX: &str = "hosted-workspace-source-bootstrap";

fn error(kind: &str, message: &str) -> Box<dyn std::error::Error> {
    fail(format!("{PREFIX}-{kind}|{message}"))
}

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[
        include_str!("hosted_workspace_bootstrap.encounter").to_owned(),
        include_str!("hosted_workspace_storage.encounter").to_owned(),
        include_str!("hosted_worker_workspace.encounter").to_owned(),
    ], &["bootstrap.authorization", "bootstrap.sourceCustody", "bootstrap.input", "bootstrap.plan",
        "bootstrap.basis", "bootstrap.retained", "bootstrap.receipt"],
        &BTreeSet::from(["kernel.invoke", "value.type", "record.entries", "record.fromEntries",
            "record.put", "text.trim", "text.matches", "text.replaceAll", "text.split", "number.calculate",
            "json.stringify", "json.canonical", "digest.sha256", "time.parseRfc3339", "path.resolvePosix",
            "text.startsWith", "text.slice"]),
        &mut Meter::new(200_000))
}

fn evaluate(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(100_000_000))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| fail(format!("Missing workspace bootstrap field {key}")))
}

fn fd_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn absolute_directory(path: &Path) -> Result<File> {
    let relative = path.strip_prefix("/")?;
    let root = File::open("/")?;
    if relative.as_os_str().is_empty() { return Ok(root); }
    let observed = observe_beneath(&root, relative)?;
    if !observed.metadata()?.is_dir() { return Err(fail("Bootstrap root must be a real directory.")); }
    Ok(File::open(fd_path(&observed))?)
}

fn names(directory: &File) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for item in fs::read_dir(fd_path(directory))? {
        http::check_interruption(false)?;
        if names.len() == SOURCE_FILES { return Err(fail("Bootstrap directory exceeds its bounded envelope.")); }
        names.push(item?.file_name().into_string().map_err(|_| fail("Bootstrap entry name is not UTF-8."))?);
    }
    names.sort_by(|left, right| compat_value::compare(left, right).then_with(|| left.cmp(right)));
    Ok(names)
}

#[derive(Serialize, PartialEq, Eq)]
struct Entry { path: String, bytes: u64, sha256: String }

#[derive(Default)]
struct Manifest { entries: Vec<Entry>, directories: BTreeSet<String>, total_bytes: u64 }

fn transfer(mut source: File, mut destination: Option<&mut File>, limit: u64) -> Result<(u64, String)> {
    if source.metadata()?.len() > limit { return Err(fail("Bootstrap source exceeds its bounded envelope.")); }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0;
    loop {
        http::check_interruption(false)?;
        let length = source.read(&mut buffer)?;
        if length == 0 { break; }
        size += length as u64;
        if size > limit { return Err(fail("Bootstrap source exceeds its bounded envelope.")); }
        digest.update(&buffer[..length]);
        if let Some(file) = &mut destination { file.write_all(&buffer[..length])?; }
    }
    Ok((size, hex::encode(digest.finalize())))
}

impl Manifest {
    fn collect(root: &File) -> Result<Self> {
        let mut result = Self::default();
        result.walk(root, "")?;
        Ok(result)
    }

    fn walk(&mut self, directory: &File, prefix: &str) -> Result<()> {
        for name in names(directory)? {
            let path = format!("{prefix}{name}");
            if path.len() > 4095 { return Err(fail("Bootstrap source path exceeds its bound.")); }
            let entry = observe_beneath(directory, Path::new(&name))?;
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                if self.directories.len() == SOURCE_FILES || path.bytes().filter(|byte| *byte == b'/').count() >= 128 {
                    return Err(fail("Bootstrap directory tree exceeds its bounded envelope."));
                }
                self.directories.insert(path.clone());
                self.walk(&File::open(fd_path(&entry))?, &format!("{path}/"))?;
            } else if metadata.is_file() {
                if self.entries.len() == SOURCE_FILES { return Err(fail("Bootstrap source exceeds its bounded envelope.")); }
                let (bytes, sha256) = transfer(File::open(fd_path(&entry))?, None, SOURCE_BYTES - self.total_bytes)?;
                self.total_bytes += bytes;
                self.entries.push(Entry { path, bytes, sha256 });
            } else {
                return Err(fail(format!("Bootstrap source contains an unsupported entry: {path}.")));
            }
        }
        Ok(())
    }

    fn input(&self) -> Value {
        json!({"entries": self.entries, "fileCount": self.entries.len(), "totalBytes": self.total_bytes,
            "projectHash": self.entries.iter().find(|entry| entry.path == "project.rel").map(|entry| &entry.sha256)})
    }
}

fn lock(parent: &File, exclusive: bool) -> Result<()> {
    let mode = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        http::check_interruption(false)?;
        if unsafe { libc::flock(parent.as_raw_fd(), mode | libc::LOCK_NB) } == 0 { return Ok(()); }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock || Instant::now() >= deadline { return Err(error.into()); }
        thread::sleep(Duration::from_millis(25));
    }
}

fn receipt(workspace: &File) -> Result<Value> {
    match read_private(workspace, RECEIPT, PRIVATE_LIMIT) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).ok().filter(Value::is_object)
            .ok_or_else(|| error("receipt-corrupt", "Workspace source bootstrap receipt is corrupt.")),
        Err(cause) if missing(cause.as_ref()) => Ok(Value::Null),
        Err(cause) => Err(cause),
    }
}

fn missing(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn initial(workspace: &File, marker: &[u8]) -> Result<()> {
    if read_private(workspace, MARKER, PRIVATE_LIMIT)? != marker {
        return Err(fail("Workspace allocation marker changed during bootstrap."));
    }
    if names(workspace)? != [MARKER] {
        return Err(error("not-empty", "Workspace is not empty and has no matching source-bootstrap receipt."));
    }
    Ok(())
}

fn group(file: &File, gid: u32) -> Result<()> {
    if file.metadata()?.gid() != gid && unsafe { libc::fchown(file.as_raw_fd(), u32::MAX, gid) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn create_file(directory: &File, name: &str, gid: u32) -> Result<File> {
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(fd_path(directory).join(name))?;
    group(&file, gid)?;
    Ok(file)
}

fn write_file(directory: &File, name: &str, gid: u32, data: &[u8]) -> Result<()> {
    let mut file = create_file(directory, name, gid)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn descend(root: &File, components: &[&str], gid: u32, create: bool) -> Result<Vec<File>> {
    let mut path = vec![root.try_clone()?];
    for component in components {
        let directory = path.last().unwrap();
        let child = if create {
            let child = make_directory(directory, component)?;
            group(&child, gid)?;
            child
        } else {
            private_directory(open_beneath(directory, Path::new(component))?)?
        };
        path.push(child);
    }
    Ok(path)
}

fn sync_directories(path: &[File]) -> Result<()> {
    for directory in path.iter().rev() { directory.sync_all()?; }
    Ok(())
}

fn copy_manifest(source: &File, project: &File, manifest: &Manifest, gid: u32) -> Result<()> {
    for entry in &manifest.entries {
        let mut parts: Vec<_> = entry.path.split('/').collect();
        let name = parts.pop().unwrap();
        let directories = descend(project, &parts, gid, true)?;
        let mut file = create_file(directories.last().unwrap(), name, gid)?;
        let from = observe_beneath(source, Path::new(&entry.path))?;
        if !from.metadata()?.is_file() {
            return Err(error("source-drift", "Bootstrap source changed during staging."));
        }
        let (bytes, sha256) = transfer(File::open(fd_path(&from))?, Some(&mut file), entry.bytes)?;
        if bytes != entry.bytes || sha256 != entry.sha256 {
            return Err(error("source-drift", "Bootstrap source changed during staging."));
        }
        file.sync_all()?;
        sync_directories(&directories)?;
    }
    Ok(())
}

struct Publication<'a> {
    policy: &'a Programme,
    plan: &'a Value,
    manifest: &'a Manifest,
    marker: &'a [u8],
    identity: &'a Metadata,
    placement: Vec<&'a str>,
    backup: PathBuf,
}

impl Publication<'_> {
    fn identity(&self) -> Value {
        json!({"uid": self.identity.uid(), "gid": self.identity.gid(), "mode": 0o700})
    }

    fn stage(&self, source: &File, stage: &File) -> Result<Value> {
        let gid = self.identity.gid();
        group(stage, gid)?;
        let path = descend(stage, &self.placement, gid, true)?;
        copy_manifest(source, path.last().unwrap(), self.manifest, gid)?;
        write_file(stage, MARKER, gid, self.marker)?;
        let occurred_at = chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let receipt = evaluate(self.policy, "bootstrap.receipt", json!({"plan": self.plan,
            "identity": self.identity(), "backup": self.backup, "occurredAt": occurred_at}))?;
        let mut bytes = serde_json::to_vec_pretty(&receipt)?;
        bytes.push(b'\n');
        write_file(stage, RECEIPT, gid, &bytes)?;
        sync_directories(&path)?;
        Ok(receipt)
    }

    fn recover(&self, candidate: &File) -> Result<Value> {
        let found = receipt(candidate)?;
        evaluate(self.policy, "bootstrap.retained", json!({"plan": self.plan, "receipt": found,
            "recovery": {"identity": self.identity(), "backup": self.backup,
                "markerMatches": read_private(candidate, MARKER, PRIVATE_LIMIT)? == self.marker}}))?;
        let path = descend(candidate, &self.placement, self.identity.gid(), false)?;
        for (index, name) in self.placement.iter().enumerate() {
            let mut expected = vec![*name];
            if index == 0 { expected.extend([MARKER, RECEIPT]); }
            expected.sort();
            let mut actual = names(&path[index])?;
            actual.sort();
            if actual != expected { return Err(error("conflict", "Prepared bootstrap recovery has unexpected entries.")); }
        }
        let project = path.last().unwrap();
        let candidate = Manifest::collect(project)?;
        let expected_directories: BTreeSet<_> = self.manifest.entries.iter().flat_map(|entry| {
            entry.path.match_indices('/').map(|(index, _)| &entry.path[..index])
        }).collect();
        let observed_directories: BTreeSet<_> = candidate.directories.iter().map(String::as_str).collect();
        if candidate.entries != self.manifest.entries || observed_directories != expected_directories {
            return Err(error("conflict", "Prepared bootstrap recovery contents changed."));
        }
        Ok(found)
    }
}

fn bootstrap(policy: &Programme, root: &Path, source: &File, expected: Option<&str>, request: &Value) -> Result<Value> {
    let execute = expected.is_some();
    let namespace = Path::new(field(&request["target"], "storageNamespace")?);
    if !root.ends_with(namespace) { return Err(fail("Workspace path does not match its admitted namespace.")); }
    let workspace = field(&request["target"], "workspaceId")?;
    let parent_path = root.parent().ok_or_else(|| fail("Expected a workspace allocation parent"))?;
    let parent = private_directory(absolute_directory(parent_path)?)?;
    let anchored = fd_path(&parent);
    lock(&parent, execute)?;
    let active = private_directory(open_beneath(&parent, Path::new(workspace))?)?;
    let marker = field(request, "marker")?.as_bytes();
    if read_private(&active, MARKER, PRIVATE_LIMIT)? != marker { return Err(fail("Workspace allocation marker mismatch.")); }

    let manifest = Manifest::collect(source)?;
    let mut plan = evaluate(policy, "bootstrap.plan", json!({"request": request, "manifest": manifest.input()}))?;
    let mut retained = receipt(&active)?;
    let status = evaluate(policy, "bootstrap.retained", json!({"plan": plan, "receipt": retained}))?;
    if retained.is_null() { initial(&active, marker)?; }
    evaluate(policy, "bootstrap.basis", json!({"execute": execute, "plan": plan, "expected": expected}))?;
    if !execute {
        plan["status"] = status;
        return Ok(plan);
    }
    if !retained.is_null() {
        retained["status"] = status;
        return Ok(retained);
    }

    let identity = active.metadata()?;
    let plan_hash = field(&plan, "planHash")?;
    let backup_name = format!(".{workspace}.pre-source-{}", &plan_hash[..16]);
    let placement = field(request, "projectFile")?.rsplit_once('/')
        .ok_or_else(|| fail("Expected nested workspace source placement"))?.0.split('/').collect();
    let publication = Publication { policy, plan: &plan, manifest: &manifest, marker, identity: &identity,
        placement, backup: parent_path.join(&backup_name) };
    let backup = anchored.join(&backup_name);
    let applied = match open_beneath(&parent, Path::new(&backup_name)) {
        Ok(candidate) => publication.recover(&private_directory(candidate)?)?,
        Err(cause) if missing(cause.as_ref()) => {
            let scratch = Scratch::create(&anchored, ".source-stage-")?;
            let stage = private_directory(File::open(scratch.path())?)?;
            let applied = publication.stage(source, &stage)?;
            http::check_interruption(false)?;
            rename_new_path(scratch.path(), &backup)?;
            applied
        }
        Err(cause) => return Err(cause),
    };
    parent.sync_all()?;
    let current = private_directory(open_beneath(&parent, Path::new(workspace))?)?;
    let current_identity = current.metadata()?;
    if (current_identity.dev(), current_identity.ino()) != (identity.dev(), identity.ino()) {
        return Err(fail("Workspace directory changed during source bootstrap."));
    }
    initial(&current, marker)?;
    http::check_interruption(false)?;
    // Exchange keeps the allocated directory reachable and retains the prior root in one operation.
    exchange_paths(&backup, &anchored.join(workspace))?;
    parent.sync_all()?;
    Ok(applied)
}

fn command_path(value: &str) -> Result<PathBuf> {
    Ok(env::current_dir()?.join(value))
}

fn release_source(path: &Path) -> Result<File> {
    let release = absolute_directory(path)?;
    let runtime = observe_beneath(&release, Path::new("encounter"))?.metadata()?;
    let executing = fs::metadata("/proc/self/exe")?;
    if !runtime.is_file() || (runtime.dev(), runtime.ino()) != (executing.dev(), executing.ino()) {
        return Err(fail("Bootstrap must use the Encounter runtime from the manifest's release."));
    }
    Ok(release)
}

fn operator(manifest: &Path, evidence: &Path, expected: Option<&str>, custody_owner: u32) -> Result<Value> {
    let manifest_policy = hosted_production_manifest::policy()?;
    let manifest = hosted_production_manifest::load(&manifest_policy, manifest, custody_owner)?;
    let evidence = hosted_production_manifest::read_custody(&manifest_policy, evidence, custody_owner, 32_768)?;
    let release_root = field(&manifest, "sourceRoot")?;
    let release = release_source(Path::new(release_root))?;
    let policy = policy()?;
    let authorization = evaluate(&policy, "bootstrap.authorization", json!({
        "releaseRoot": release_root, "evidence": hosted_production_manifest::parse(&evidence)?,
        "evidenceText": std::str::from_utf8(&evidence)?
    }))?;
    let custody = authorization["custody"] == true;
    let base = if custody { absolute_directory(Path::new(field(&authorization, "base")?))? } else { release };
    let source = observe_beneath(&base, Path::new(field(&authorization, "relative")?))?;
    let metadata = source.metadata()?;
    evaluate(&policy, "bootstrap.sourceCustody", json!({"directory": metadata.is_dir(), "required": custody,
        "uid": metadata.uid(), "owner": custody_owner, "private": metadata.mode() & 0o027 == 0}))?;
    let request = evaluate(&policy, "bootstrap.input", authorization["request"].clone())?;
    let storage_root = Path::new(field(&manifest, "workspaceRoot")?);
    let allowed = storage_root.parent().ok_or_else(|| fail("Expected a private workspace state parent"))?;
    hosted_workspace_storage::prove(storage_root, allowed)?;
    let allocation = hosted_workspace_storage::resolve(storage_root, request["target"].clone())?;
    bootstrap(&policy, Path::new(field(&allocation, "root")?), &File::open(fd_path(&source))?, expected, &request)
}

pub(crate) fn run(arguments: &[String]) -> Result<()> {
    let _signals = Supervisor::new();
    let invalid = || fail("Use encounter hosted-workspace-bootstrap --authorization-evidence-file FILE [--manifest FILE] [--execute PLAN_SHA256]");
    let mut evidence = None;
    let mut manifest = None;
    let mut expected = None;
    let mut pairs = arguments.chunks_exact(2);
    for pair in &mut pairs {
        let field = match pair[0].as_str() {
            "--authorization-evidence-file" => &mut evidence,
            "--manifest" => &mut manifest,
            "--execute" => &mut expected,
            _ => return Err(invalid()),
        };
        if field.replace(pair[1].as_str()).is_some() || pair[1].is_empty() { return Err(invalid()); }
    }
    if !pairs.remainder().is_empty() { return Err(invalid()); }
    let evidence = command_path(evidence.ok_or_else(invalid)?)?;
    let default_manifest = env::var("SOURCERY_SELF_HOSTED_INFRASTRUCTURE_CONFIG").ok().filter(|path| !path.is_empty());
    let manifest = command_path(manifest.or(default_manifest.as_deref()).unwrap_or("/etc/sourcery/production-infrastructure.json"))?;
    let result = operator(&manifest, &evidence, expected, 0)?;
    http::check_interruption(false)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(test)]
#[test]
fn operator_binds_custody_release_and_recoverable_workspace_publication() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let executable = env::current_exe()?;
    let scratch = Scratch::create(executable.parent().unwrap(), ".bootstrap-fixture-")?;
    let release = scratch.path().join("release");
    fs::create_dir(&release)?;
    fs::hard_link(&executable, release.join("encounter"))?;
    let seed = release.join("seed");
    fs::create_dir(&seed)?;
    fs::create_dir(seed.join("nested"))?;
    fs::write(seed.join("project.rel"), b"// bootstrap fixture\n")?;
    fs::write(seed.join("nested/Data"), [0, 255])?;

    let state = scratch.path().join("state");
    let storage = state.join("workspaces");
    hosted_workspace_storage::prove(&storage, &state)?;
    let target = json!({"tenantId":"ten_fixture","appId":"app_fixture","projectId":"prj_fixture",
        "workspaceId":"wsp_fixture","storageNamespace":"tenants/ten_fixture/workspaces/wsp_fixture","region":"self-hosted"});
    let allocation = storage.join(field(&target, "storageNamespace")?);
    let mut current = absolute_directory(&storage)?;
    for component in Path::new(field(&target, "storageNamespace")?).iter() {
        current = make_directory(&current, component.to_str().unwrap())?;
    }
    let owner = current.metadata()?.uid();
    let gid = current.metadata()?.gid();
    let policy = policy()?;
    let admitted = evaluate(&policy, "bootstrap.input", json!({"target":target,"operationId":"fixture-bootstrap",
        "authorizationEvidenceHash":"a".repeat(64),"workspaceProjectFile":"app/project.rel"}))?;
    let marker = field(&admitted, "marker")?.as_bytes();
    write_file(&current, MARKER, gid, marker)?;

    let fixture = absolute_directory(scratch.path())?;
    let manifest_path = scratch.path().join("manifest.json");
    let manifest = json!({
        "protocol":"sourcery.hosted/self-hosted-production-infrastructure.v1",
        "postgres":{"socketDirectory":"/run/postgresql","database":"sourcery","user":"sourcery","maximumConnections":20},
        "sourceRoot":release,"workspaceRoot":storage,"capabilityRoot":"/state/capabilities",
        "oauthClientsFile":"/state/clients","oauthClientMetadataHosts":["chatgpt.com"],
        "assignmentPrivateKeyFile":"/state/assignment","interactionSecretsFile":"/state/interaction",
        "runtime":{"socketPath":"/state/runtime.sock","keyId":"key","verificationKeysFile":"/state/keys","issuer":"issuer","audience":"audience"},
        "worker":{"image":format!("sha256:{}", "a".repeat(64)),"podman":"/usr/bin/podman","imageAdmissionFile":"/state/image",
            "memoryMegabytes":1024,"cpuLimit":2,"pidLimit":256},
        "capability":{"conformanceEvidenceFile":"/state/conformance","catalogPublicationFile":"/state/catalogue",
            "maximumHistoryEntries":10000,"policyId":"policy.fixture","currency":"AUD","monthlyLimit":0,
            "maxActiveBindings":32,"reconciliationIntervalMs":30000,"reconciliationTargetLimit":128}
    });
    write_file(&fixture, "manifest.json", gid, &serde_json::to_vec(&manifest)?)?;
    let evidence_path = scratch.path().join("evidence.json");
    let evidence = json!({"protocol":"sourcery.hosted/operator-workspace-source-bootstrap-authorization.v1",
        "authorization":"Initialize fixture","operationId":"fixture-bootstrap","sourceDirectory":"seed",
        "workspaceProjectFile":"app\\project.rel","target":target});
    let mut evidence_bytes = serde_json::to_vec(&evidence)?;
    evidence_bytes.push(b'\n');
    write_file(&fixture, "evidence.json", gid, &evidence_bytes)?;

    fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o644))?;
    assert!(operator(&manifest_path, &evidence_path, None, owner).unwrap_err().to_string().contains("inaccessible publicly"));
    fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o650))?;
    assert!(operator(&manifest_path, &evidence_path, None, owner).is_err());
    fs::set_permissions(&evidence_path, fs::Permissions::from_mode(0o600))?;
    let link = scratch.path().join("linked-evidence");
    symlink(&evidence_path, &link)?;
    assert!(operator(&manifest_path, &link, None, owner).is_err());
    assert!(operator(&manifest_path, &evidence_path, None, owner ^ 1).is_err());
    let mut crossed = manifest.clone();
    crossed["sourceRoot"] = json!(scratch.path());
    fs::copy(&executable, scratch.path().join("encounter"))?;
    fs::write(&manifest_path, serde_json::to_vec(&crossed)?)?;
    assert!(operator(&manifest_path, &evidence_path, None, owner).unwrap_err().to_string().contains("manifest's release"));
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    let mut escaped = evidence.clone();
    escaped["sourceDirectory"] = json!("../outside");
    fs::write(&evidence_path, serde_json::to_vec(&escaped)?)?;
    assert!(operator(&manifest_path, &evidence_path, None, owner).unwrap_err().to_string().contains("authorized root"));
    fs::write(&evidence_path, &evidence_bytes)?;
    let plan = operator(&manifest_path, &evidence_path, None, owner)?;
    assert_eq!(plan["status"], "prepared");
    assert_eq!(plan["authorizationEvidenceHash"], hex::encode(Sha256::digest(&evidence_bytes)));
    assert_eq!(plan["placement"]["projectFile"], "app/project.rel");
    let hash = field(&plan, "planHash")?;
    let execute = || operator(&manifest_path, &evidence_path, Some(hash), owner);
    fs::write(seed.join("project.rel"), b"// changed")?;
    assert!(execute().unwrap_err().to_string().contains("plan-mismatch"));
    assert_eq!(names(&absolute_directory(&allocation)?)?, [MARKER]);
    fs::write(seed.join("project.rel"), b"// bootstrap fixture\n")?;

    let applied = execute()?;
    assert_eq!(applied["status"], "applied");
    let backup = PathBuf::from(field(&applied["recovery"], "retainedPreSourceWorkspace")?);
    assert_eq!(fs::read(backup.join(MARKER))?, marker);
    assert_eq!(fs::read(allocation.join(MARKER))?, marker);
    assert_eq!(fs::read(allocation.join("app/nested/Data"))?, [0, 255]);
    assert_eq!(execute()?["status"], "already-applied");

    exchange_paths(&allocation, &backup)?;
    fs::write(backup.join("app/nested/Data"), b"crossed")?;
    assert!(execute().unwrap_err().to_string().contains("conflict"));
    assert_eq!(names(&absolute_directory(&allocation)?)?, [MARKER]);
    fs::write(backup.join("app/nested/Data"), [0, 255])?;
    assert_eq!(execute()?, applied);
    assert_eq!(names(&absolute_directory(&backup)?)?, [MARKER]);
    Ok(())
}
