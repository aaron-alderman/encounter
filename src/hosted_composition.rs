use crate::{Result, appdev_host_process::{Scratch, Supervisor, interruption, rename_new_path}, archive, command_sources::Sources,
    compat_value::canonical_json, fail, process::{Meter, Programme}, rel};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::{self, File, OpenOptions}, io::{self, Write}, os::{fd::AsRawFd,
    unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink}}, path::{Path, PathBuf}, time::Duration};

const LIMIT: u64 = 16 * 1024 * 1024;
const COMPOSITION: &str = ".sourcery-dependency-composition.json";
const EVIDENCE: &str = ".sourcery-release-evidence.json";
const CLOSURE: &str = ".sourcery-dependency-closure.json";
const OUTPUTS: [&str; 3] = ["node_modules", COMPOSITION, EVIDENCE];

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_composition.encounter").to_owned()],
        &["composition.preflight", "composition.target", "composition.closureKey", "composition.retain", "composition.payload", "composition.seal",
            "composition.auditInputs", "composition.audit"],
        &BTreeSet::from(["text.matches", "kernel.invoke", "value.sort", "record.put", "record.entries", "record.fromEntries",
            "json.canonical", "digest.sha256"]), &mut Meter::new(5_000_000))
}

fn bytes(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() { return Err(fail("Release evidence and dependency paths must be absolute")); }
    let mut data = Vec::new();
    archive::Work::new(Duration::from_secs(30)).copy(&mut archive::input(path, LIMIT)?, &mut data, LIMIT)?;
    Ok(data)
}

fn digest(value: &Value) -> Result<String> { Ok(rel::hash(canonical_json(value)?)) }

fn name(path: &Path) -> Result<&str> {
    path.file_name().and_then(|name| name.to_str()).ok_or_else(|| fail("Expected a named release directory"))
}

fn preflight(policy: &Programme, root: &Path, evidence: &Path, archive: &str, tree: &str) -> Result<Value> {
    Sources::open_physical(root)?;
    let input: Value = serde_json::from_slice(&bytes(evidence)?)?;
    let evidence = |key| input.get(key).cloned().unwrap_or(Value::Null);
    let source = Path::new(input["sourceCapsuleManifestFile"].as_str().ok_or_else(|| fail("Expected a source capsule manifest path"))?);
    let reconstruction = Path::new(input["reconstructionProofFile"].as_str().ok_or_else(|| fail("Expected a reconstruction proof path"))?);
    let package = bytes(&root.join("package.json"))?;
    let lockfile = bytes(&root.join("package-lock.json"))?;
    let manifest: Value = serde_json::from_slice(&package)?;
    if !manifest.is_object() { return Err(fail("Expected a hosted package manifest object")); }
    let truth = |value: &Value| !value.is_null() && value != false && value != 0 && value != "";
    policy.run("composition.preflight", json!({"releaseId":name(root)?,"archive":archive,"tree":tree,
        "packageHash":rel::hash(package),"lockfileHash":rel::hash(lockfile),
        "sourceCapsuleManifestHash":rel::hash(bytes(source)?),"reconstructionProofHash":rel::hash(bytes(reconstruction)?),
        "workspaces":truth(&manifest["workspaces"]),"templeDependency":truth(&manifest["dependencies"]["@temple2/platform-sdk"]),
        "evidence":{"protocol":evidence("protocol"),"releaseId":evidence("releaseId"),"intendedActiveReleaseId":evidence("intendedActiveReleaseId"),
            "currentActiveReleaseId":evidence("currentActiveReleaseId"),"rollbackReleaseId":evidence("rollbackReleaseId"),
            "sourceCapsuleManifestHash":evidence("sourceCapsuleManifestHash"),"sourceTreeHashes":evidence("sourceTreeHashes"),
            "reconstructionProofHash":evidence("reconstructionProofHash")}}), &mut Meter::new(5_000_000))
}

fn absent(root: &Path) -> Result<()> {
    for name in OUTPUTS {
        match root.join(name).symlink_metadata() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(fail("Hosted dependency composition requires an unpublished release")),
        }
    }
    Ok(())
}

fn view_link(source: &Path, target: &Path, closure: &Path, verify: bool) -> Result<()> {
    let source = source.canonicalize()?;
    if !source.starts_with(closure) { return Err(fail("Dependency view link escapes its retained closure")); }
    if verify {
        if fs::read_link(target)? != source { return Err(fail("Dependency view differs from the retained closure")); }
    } else {
        symlink(source, target)?;
    }
    Ok(())
}

fn view(closure: &Path, stage: &Path, verify: bool) -> Result<usize> {
    let payload = closure.join("payload/node_modules");
    let staged = stage.join("node_modules");
    view_directory(&payload, &staged, verify)?;
    let mut links = 0;
    for entry in fs::read_dir(payload)? {
        let entry = entry?;
        let target = staged.join(entry.file_name());
        if entry.file_name().to_string_lossy().starts_with('@') && entry.file_type()?.is_dir() {
            view_directory(&entry.path(), &target, verify)?;
            for child in fs::read_dir(entry.path())? {
                let child = child?;
                view_link(&child.path(), &target.join(child.file_name()), closure, verify)?;
                links += 1;
            }
            if !verify { File::open(&target)?.sync_all()?; }
        } else {
            view_link(&entry.path(), &target, closure, verify)?;
            links += 1;
        }
    }
    if !verify { File::open(&staged)?.sync_all()?; }
    Ok(links)
}

fn view_directory(source: &Path, target: &Path, verify: bool) -> Result<()> {
    if !verify {
        fs::DirBuilder::new().mode(0o755).create(target)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
        return Ok(());
    }
    if !target.symlink_metadata()?.is_dir() { return Err(fail("Expected a physical dependency view directory")); }
    let names = |path| -> Result<BTreeSet<_>> {
        fs::read_dir(path)?.take(archive::MEMBER_LIMIT + 1)
            .map(|entry| Ok(entry?.file_name())).collect()
    };
    let expected = names(source)?;
    if expected.len() > archive::MEMBER_LIMIT || names(target)? != expected {
        return Err(fail("Dependency view contains missing or unadmitted entries"));
    }
    Ok(())
}

fn observe_tree(work: &archive::Work, root: &Path, directory: &Path, entries: &mut Vec<Value>, total: &mut u64, depth: usize) -> Result<()> {
    if depth > 128 || !directory.symlink_metadata()?.is_dir() { return Err(fail("Expected a bounded physical dependency directory")); }
    let mut children = Vec::new();
    for child in fs::read_dir(directory)? {
        work.check()?;
        if children.len() == archive::MEMBER_LIMIT { return Err(fail("Dependency directory has too many entries")); }
        let child = child?;
        let name = child.file_name().into_string().map_err(|_| fail("Expected a UTF-8 dependency name"))?;
        children.push((name, child));
    }
    children.sort_by(|left, right| crate::compat_value::compare(&left.0, &right.0));
    for (_, child) in children {
        work.check()?;
        if entries.len() == archive::MEMBER_LIMIT { return Err(fail("Dependency closure has too many entries")); }
        let path = child.path();
        let relative = path.strip_prefix(root)?.to_str().ok_or_else(|| fail("Expected a UTF-8 dependency path"))?;
        let kind = child.file_type()?;
        if kind.is_symlink() {
            if !path.canonicalize()?.starts_with(root) { return Err(fail("Dependency link escapes its retained payload")); }
            let link = fs::read_link(&path)?;
            entries.push(json!({"path":relative,"type":"symbolic-link","target":link.to_str().ok_or_else(|| fail("Expected a UTF-8 dependency link"))?}));
        } else if kind.is_dir() {
            entries.push(json!({"path":relative,"type":"directory"}));
            observe_tree(work, root, &path, entries, total, depth + 1)?;
        } else if kind.is_file() {
            let mut file = archive::input(&path, archive::ARCHIVE_LIMIT)?;
            let metadata = file.metadata()?;
            let (size, digest) = work.copy(&mut file, &mut io::sink(), archive::ARCHIVE_LIMIT - *total)?;
            let after = file.metadata()?;
            if metadata.len() != size || (metadata.ctime(), metadata.ctime_nsec()) != (after.ctime(), after.ctime_nsec()) {
                return Err(fail("Dependency file changed during composition"));
            }
            *total += size;
            entries.push(json!({"path":relative,"type":"file","bytes":size,"executable":metadata.mode() & 0o111 != 0,"contentHash":digest}));
        } else { return Err(fail("Unsupported dependency closure entry")); }
    }
    Ok(())
}

struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) { unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN); } }
}

fn closure_manifest(policy: &Programme, closure: &Path, install: &Value, platform: &Value, key: &str) -> Result<Value> {
    let payload = closure.join("payload");
    let mut entries = Vec::new();
    let mut size = 0;
    let work = archive::Work::new(Duration::from_secs(90));
    observe_tree(&work, &payload, &payload, &mut entries, &mut size, 0)?;
    policy.run("composition.retain", json!({"key":key,"bundle":digest(install)?,"lockfile":install["lockfileHash"],
        "platform":platform,"treeHash":digest(&json!(entries))?,"entryCount":entries.len(),"bytes":size}), &mut Meter::new(5_000_000))
}

pub(crate) struct Request<'a> {
    pub root: &'a Path,
    pub evidence: &'a Path,
    pub archive_file: &'a Path,
    pub archive: &'a str,
    pub tree: &'a str,
    pub store: &'a Path,
    pub runtime_version: &'a str,
    pub abi: &'a str,
}

fn write_new(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?;
    file.write_all(content)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn harden(path: &Path, work: &archive::Work) -> Result<()> {
    work.check()?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() { harden(&entry.path(), work)?; }
        else if kind.is_file() {
            let file = archive::input(&entry.path(), archive::ARCHIVE_LIMIT)?;
            let executable = file.metadata()?.mode() & 0o111 != 0;
            file.set_permissions(fs::Permissions::from_mode(if executable { 0o555 } else { 0o444 }))?;
            file.sync_all()?;
        } else if !kind.is_symlink() { return Err(fail("Unexpected retained dependency entry")); }
    }
    let directory = Sources::open_physical(path)?.root()?;
    directory.set_permissions(fs::Permissions::from_mode(0o555))?;
    directory.sync_all()?;
    Ok(())
}

struct ClosureStage(Scratch);

impl Drop for ClosureStage {
    fn drop(&mut self) {
        // Files in an unpublished, hardened stage are removed by Scratch.
        // Restore directory write access without following payload links.
        let mut pending = vec![self.0.path().to_owned()];
        while let Some(path) = pending.pop() {
            if !path.symlink_metadata().is_ok_and(|meta| meta.is_dir()) { continue; }
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
            if let Ok(entries) = fs::read_dir(path) {
                pending.extend(entries.flatten().filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir())).map(|entry| entry.path()));
            }
        }
    }
}

fn retain(request: &Request<'_>, policy: &Programme, install: &Value, platform: &Value, key: &str) -> Result<(PathBuf, bool)> {
    if !request.store.is_absolute() { return Err(fail("Expected an absolute dependency closure store")); }
    fs::create_dir_all(request.store)?;
    if request.store.canonicalize()? != request.store { return Err(fail("Expected a physical dependency closure store")); }
    let store = Sources::open_physical(request.store)?.root()?;
    let target = request.store.join(key);
    match target.symlink_metadata() {
        Ok(_) => return Ok((target, true)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let package = bytes(&request.root.join("package.json"))?;
    let lockfile = bytes(&request.root.join("package-lock.json"))?;
    policy.run("composition.payload", json!({"install":install,"packageManifestHash":rel::hash(&package),"lockfileHash":rel::hash(&lockfile)}), &mut Meter::new(5_000_000))?;
    let stage = ClosureStage(Scratch::create(request.store, ".hosted-closure-")?);
    let payload = stage.0.path().join("payload");
    fs::create_dir(&payload)?;
    write_new(&payload.join("package.json"), &package, 0o644)?;
    write_new(&payload.join("package-lock.json"), &lockfile, 0o644)?;
    crate::hosted_dependencies::populate_locked(&payload)?;
    let scope = payload.join("node_modules/@temple2");
    match fs::create_dir(&scope) {
        Ok(()) => fs::set_permissions(&scope, fs::Permissions::from_mode(0o755))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && scope.symlink_metadata()?.is_dir() => {},
        Err(error) => return Err(error.into()),
    }
    crate::hosted_release_identity::install_archive(request.archive_file, request.archive, request.tree, &scope.join("platform-sdk"))?;
    let work = archive::Work::new(Duration::from_secs(90));
    harden(&payload, &work)?;
    let manifest = closure_manifest(policy, stage.0.path(), install, platform, key)?;
    write_new(&stage.0.path().join(CLOSURE), canonical_json(&manifest)?.as_bytes(), 0o444)?;
    let directory = Sources::open_physical(stage.0.path())?.root()?;
    directory.set_permissions(fs::Permissions::from_mode(0o555))?;
    directory.sync_all()?;
    work.check()?;
    match rename_new_path(stage.0.path(), &target) {
        Ok(()) => { store.sync_all()?; Ok((target, false)) }
        Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) => Ok((target, true)),
        Err(error) => Err(error),
    }
}

fn seal(request: &Request<'_>, closure: &Path, reused: bool, expected_preflight: &str, platform: &Value, key: &str) -> Result<Value> {
    let root = request.root;
    let release = Sources::open_physical(root)?.root()?;
    if unsafe { libc::flock(release.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Err(fail("Hosted release is being composed")); }
    let release = Lock(release);
    absent(root)?;
    if closure.canonicalize()? != closure { return Err(fail("Expected a physical dependency closure")); }
    let policy = policy()?;
    let input = preflight(&policy, root, request.evidence, request.archive, request.tree)?;
    let bundle = digest(&input["install"])?;
    let closure_record: Value = serde_json::from_slice(&bytes(&closure.join(CLOSURE))?)?;
    let verified = closure_manifest(&policy, closure, &input["install"], platform, key)?;
    let payload = closure.join("payload");
    let work = archive::Work::new(Duration::from_secs(90));
    let (_, archive_hash) = work.copy(&mut archive::input(request.archive_file, archive::ARCHIVE_LIMIT)?, &mut io::sink(), archive::ARCHIVE_LIMIT)?;
    let freeze = crate::hosted_release_identity::temple_identity(&payload.join("node_modules/@temple2/platform-sdk"), Some(request.tree))?;
    let result = policy.run("composition.seal", json!({"release":input,"closure":verified,"bundle":bundle,
        "closureMatches":canonical_json(&closure_record)? == canonical_json(&verified)?,"directoryKey":name(closure)?,
        "archiveHash":archive_hash,"freezeHash":freeze["treeHash"],
        "expectedPreflight":expected_preflight,"preflightHash":digest(&input)?,
        "payloadManifestHash":rel::hash(bytes(&closure.join("payload/package.json"))?),
        "payloadLockfileHash":rel::hash(bytes(&closure.join("payload/package-lock.json"))?)}), &mut Meter::new(5_000_000))?;
    let stage = Scratch::create(root, ".sourcery-composition-")?;
    let links = view(closure, stage.path(), false)?;
    for (file, value) in [(COMPOSITION, &result["composition"]), (EVIDENCE, &result["releaseEvidence"])] {
        write_new(&stage.path().join(file), canonical_json(value)?.as_bytes(), 0o644)?;
    }
    File::open(stage.path())?.sync_all()?;
    let mut published = Vec::new();
    let result_publish = (|| -> Result<()> {
        for name in OUTPUTS {
            if interruption().is_some() { return Err(fail("Hosted dependency composition interrupted")); }
            rename_new_path(&stage.path().join(name), &root.join(name))?;
            published.push(name);
        }
        release.0.sync_all()?;
        if interruption().is_some() { return Err(fail("Hosted dependency composition interrupted")); }
        Ok(())
    })();
    if let Err(error) = result_publish {
        let mut failures = Vec::new();
        for name in published.into_iter().rev() {
            if let Err(restore) = rename_new_path(&root.join(name), &stage.path().join(name)) { failures.push(restore.to_string()); }
        }
        if let Err(restore) = release.0.sync_all() { failures.push(restore.to_string()); }
        if !failures.is_empty() { return Err(fail(format!("{error}. Hosted composition rollback failed ({}); retained {}",
            failures.join(", "), stage.retain().display()))); }
        return Err(error);
    }
    let mut retained = verified;
    retained["directory"] = json!(closure);
    retained["reused"] = json!(reused);
    Ok(json!({"status":"composed","closure":retained,"view":{"closureDirectory":closure,"target":root.join("node_modules"),"linkCount":links,"overlayCount":0},
        "composition":result["composition"],"releaseEvidence":result["releaseEvidence"]}))
}

pub(crate) fn compose(request: Request<'_>) -> Result<()> {
    let _signals = Supervisor::new();
    crate::hosted_release_inputs::require_idle(request.root)?;
    absent(request.root)?;
    let policy = policy()?;
    let input = preflight(&policy, request.root, request.evidence, request.archive, request.tree)?;
    let install = &input["install"];
    let platform = policy.run("composition.target", json!({"runtimeVersion":request.runtime_version,"abi":request.abi}), &mut Meter::new(5_000_000))?;
    let key = policy.run("composition.closureKey", json!({"bundle":digest(install)?,"lockfile":install["lockfileHash"],"platform":platform}), &mut Meter::new(5_000_000))?;
    let key = key.as_str().ok_or_else(|| fail("Expected a closure key"))?;
    crate::hosted_release_identity::check_archive_identity(request.archive_file, request.archive)?;
    let (closure, reused) = retain(&request, &policy, install, &platform, key)?;
    println!("{}", canonical_json(&seal(&request, &closure, reused, &digest(&input)?, &platform, key)?)?.trim_end());
    Ok(())
}

pub(crate) fn audit(root: &Path, store: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    let proof = audit_release(root, store, None, None)?;
    println!("{}", canonical_json(&proof)?.trim_end());
    Ok(())
}

pub(super) fn audit_release(root: &Path, store: &Path, pin: Option<&str>, temple_pin: Option<&str>) -> Result<Value> {
    if !root.is_absolute() || !store.is_absolute() || root.canonicalize()? != root || store.canonicalize()? != store {
        return Err(fail("Expected physical absolute release and dependency store directories"));
    }
    crate::hosted_release_inputs::require_idle(root)?;
    let release = Sources::open_physical(root)?.root()?;
    if unsafe { libc::flock(release.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(fail("Hosted release is being composed"));
    }
    Sources::open_physical(store)?;
    let policy = policy()?;
    let mut meter = Meter::new(5_000_000);
    let read = |path: &Path| -> Result<Value> {
        let value = serde_json::from_slice(&bytes(path)?)?;
        crate::compat_value::external(&value)?;
        Ok(value)
    };
    let composition = read(&root.join(COMPOSITION))?;
    let evidence = read(&root.join(EVIDENCE))?;
    let inputs = policy.run("composition.auditInputs", json!({
        "releaseId":name(root)?, "composition":composition, "evidence":evidence, "pin":pin, "templePin":temple_pin,
        "packageHash":rel::hash(bytes(&root.join("package.json"))?),
        "lockfileHash":rel::hash(bytes(&root.join("package-lock.json"))?),
    }), &mut meter)?;
    let key = inputs["key"].as_str().ok_or_else(|| fail("Expected an admitted closure key"))?;
    let closure = store.join(key);
    Sources::open_physical(&closure)?;
    let payload = closure.join("payload");
    Sources::open_physical(&payload)?;
    let retained = read(&closure.join(CLOSURE))?;
    let observed = closure_manifest(&policy, &closure, &inputs["install"], &inputs["platform"], key)?;
    let freeze = crate::hosted_release_identity::temple_identity(&payload.join("node_modules/@temple2/platform-sdk"),
        composition["templeTreeHash"].as_str())?;
    let links = view(&closure, root, true)?;
    crate::http::check_interruption(false)?;
    policy.run("composition.audit", json!({
        "composition":composition, "observed":observed, "closureMatches":canonical_json(&retained)? == canonical_json(&observed)?,
        "payloadManifestHash":rel::hash(bytes(&payload.join("package.json"))?),
        "payloadLockfileHash":rel::hash(bytes(&payload.join("package-lock.json"))?),
        "freezeHash":freeze["treeHash"], "links":links,
    }), &mut meter)
}
