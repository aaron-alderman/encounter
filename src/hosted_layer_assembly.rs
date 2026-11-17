use crate::{Result, appdev_host_process::{Scratch, Supervisor, exchange_paths, rename_new_path}, archive::Work,
    compat_value, fail, http, package::observe_beneath, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::{self, File, OpenOptions}, io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink}}, path::{Path, PathBuf}, time::Duration};

const MANIFEST: &str = ".sourcery-layer/manifest.json";
const PAYLOAD: &str = "SOURCERY-PAYLOAD.json";
const SDK: &str = "node_modules/@temple2/platform-sdk";
const LIMIT: u64 = 16 * 1024 * 1024;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_layer_assembly.encounter").to_owned(),
        include_str!("hosted_dependencies.encounter").to_owned()],
        &["layerAssembly.graph", "layerAssembly.proof", "layerAssembly.runtime", "layerAssembly.sdk",
            "layerAssembly.dependencies", "layerAssembly.payloadProof"],
        &BTreeSet::from(["number.calculate", "json.stringify", "digest.sha256", "text.matches",
            "text.split", "number.isNatural", "record.put", "kernel.invoke", "value.sort"]), &mut Meter::new(200_000))
}

fn decide(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(40_000_000))
}

fn descriptor(file: &File) -> PathBuf { format!("/proc/self/fd/{}", file.as_raw_fd()).into() }

pub(super) fn directory(path: &Path) -> Result<File> {
    let root = File::open("/")?;
    let relative = path.strip_prefix("/")?;
    let directory = if relative.as_os_str().is_empty() { root } else { observe_beneath(&root, relative)? };
    if !directory.metadata()?.is_dir() { return Err(fail("Expected a physical layer assembly directory")); }
    Ok(File::open(descriptor(&directory))?)
}

fn subdirectory(root: &File, path: &Path) -> Result<File> {
    let observed = observe_beneath(root, path)?;
    if !observed.metadata()?.is_dir() { return Err(fail("Expected a physical Platform runtime directory")); }
    Ok(File::open(descriptor(&observed))?)
}

pub(super) fn source(root: &File, name: &Path, limit: u64) -> Result<File> {
    let observed = observe_beneath(root, name)?;
    let metadata = observed.metadata()?;
    if !metadata.is_file() || metadata.len() > limit { return Err(fail("Expected a bounded regular layer object")); }
    Ok(File::open(descriptor(&observed))?)
}

fn manifest(root: &File) -> Result<Value> { read_json(root, Path::new(MANIFEST)) }

fn read_json(root: &File, path: &Path) -> Result<Value> {
    let mut bytes = Vec::new();
    source(root, path, LIMIT)?.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT { return Err(fail("Layer or runtime manifest exceeds its byte bound")); }
    let value = serde_json::from_slice(&bytes)?;
    compat_value::external(&value)?;
    Ok(value)
}

fn write_json(root: &Path, name: &str, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o644).open(root.join(name))?;
    writeln!(file, "{}", compat_value::stringify(value, &json!(2))?)?;
    file.sync_all()?;
    Ok(())
}

fn existing(target: &Path) -> Result<Option<File>> {
    match target.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() => {
            let opened = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(target)?;
            if fs::read_dir(descriptor(&opened))?.next().is_some() {
                return Err(fail("Composition target must be empty."));
            }
            Ok(Some(opened))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Ok(_) => Err(fail("Composition target must be a physical empty directory.")),
        Err(error) => Err(error.into()),
    }
}

fn inventory(work: &Work, root: &File, relative: &Path, depth: usize, paths: &mut BTreeSet<PathBuf>) -> Result<()> {
    if depth > 128 { return Err(fail("Platform runtime inventory exceeds its depth bound")); }
    for item in fs::read_dir(descriptor(root))? {
        work.check()?;
        let name = item?.file_name();
        let path = relative.join(&name);
        let observed = observe_beneath(root, Path::new(&name))?;
        let metadata = observed.metadata()?;
        if metadata.is_dir() {
            inventory(work, &File::open(descriptor(&observed))?, &path, depth + 1, paths)?;
        } else if metadata.is_file() && paths.len() < 20_001 {
            paths.insert(path);
        } else {
            return Err(fail("Platform runtime inventory contains an unsupported object or exceeds its file bound"));
        }
    }
    Ok(())
}

fn inspect_admitted(work: &Work, root: &File, base: Option<&Path>, files: &[Value], total: &mut u64) -> Result<()> {
    for file in files {
        let relative = Path::new(file["path"].as_str().ok_or_else(|| fail("Missing layer object path"))?);
        let limit = file["bytes"].as_u64().ok_or_else(|| fail("Missing layer object byte count"))?;
        *total = total.checked_add(limit).filter(|value| *value <= 4 * 1024 * 1024 * 1024)
            .ok_or_else(|| fail("Layer assembly exceeds its byte bound"))?;
        let mut input = source(root, relative, limit)?;
        let mut target = base.map(|base| -> Result<File> {
            let destination = base.join(relative);
            fs::create_dir_all(destination.parent().ok_or_else(|| fail("Missing layer object parent"))?)?;
            let mode = input.metadata()?.mode() & 0o777;
            Ok(OpenOptions::new().write(true).create_new(true).mode(mode).open(destination)?)
        }).transpose()?;
        let mut sink = io::sink();
        let mut output = target.as_mut().map_or(&mut sink as &mut dyn Write, |file| file);
        let (bytes, hash) = work.copy(&mut input, &mut output, limit)?;
        if bytes != limit || file["contentHash"] != hash {
            return Err(fail(format!("Stale or tampered layer object: {}", relative.display())));
        }
        if let Some(target) = target { target.sync_all()?; }
    }
    Ok(())
}

fn require_inventory(work: &Work, root: &File, files: &[Value], extra: Option<&str>) -> Result<()> {
    let mut expected = files.iter().map(|file| file["path"].as_str().map(PathBuf::from)
        .ok_or_else(|| fail("Missing Platform runtime path"))).collect::<Result<BTreeSet<_>>>()?;
    expected.extend(extra.map(PathBuf::from));
    let mut observed = BTreeSet::new();
    inventory(work, root, Path::new(""), 0, &mut observed)?;
    if observed != expected { return Err(fail("Platform runtime inventory is incomplete or contains unadmitted files")); }
    Ok(())
}

fn physical_runtime(policy: &Programme, work: &Work, platform: &File, stage: &Path, total: &mut u64) -> Result<()> {
    let stage_root = File::open(stage)?;
    let sdk = subdirectory(&stage_root, Path::new("sdk"))?;
    let platform_sdk = subdirectory(platform, Path::new("sdk"))?;
    let manifest = read_json(&sdk, Path::new(PAYLOAD))?;
    let source_manifest = read_json(&platform_sdk, Path::new(PAYLOAD))?;
    if source_manifest != manifest { return Err(fail("Assembled Platform SDK differs from its source payload manifest")); }
    let admitted = decide(policy, "layerAssembly.sdk", manifest)?;
    let files = admitted.as_array().ok_or_else(|| fail("Missing Platform SDK file inventory"))?;
    require_inventory(work, &platform_sdk, files, Some(PAYLOAD))?;
    require_inventory(work, &sdk, files, Some(PAYLOAD))?;
    let sdk_target = stage.join(SDK);
    inspect_admitted(work, &sdk, Some(&sdk_target), files, total)?;
    let mut manifest = source(&sdk, Path::new(PAYLOAD), LIMIT)?;
    let mut target = OpenOptions::new().write(true).create_new(true).mode(0o644).open(sdk_target.join(PAYLOAD))?;
    work.copy(&mut manifest, &mut target, LIMIT)?;
    target.sync_all()?;

    let manifest = read_json(&stage_root, Path::new("runtime-dependencies.json"))?;
    let dependencies = decide(policy, "layerAssembly.dependencies", manifest)?;
    inspect_dependencies(work, platform, Some(stage), &dependencies, total)
}

fn inspect_dependencies(work: &Work, platform: &File, stage: Option<&Path>, dependencies: &Value, total: &mut u64) -> Result<()> {
    for dependency in dependencies.as_array().ok_or_else(|| fail("Missing admitted Platform dependencies"))? {
        let name = dependency["name"].as_str().ok_or_else(|| fail("Missing Platform dependency name"))?;
        let files = dependency["files"].as_array().ok_or_else(|| fail("Missing Platform dependency files"))?;
        let relative = Path::new("node_modules").join(name);
        let root = subdirectory(platform, &relative)?;
        require_inventory(work, &root, files, None)?;
        let destination = stage.map(|stage| stage.join(relative));
        inspect_admitted(work, &root, destination.as_deref(), files, total)?;
    }
    Ok(())
}

pub(crate) fn verify_payload(root: &str, layout: &str) -> Result<()> {
    let _signals = Supervisor::new();
    let sdk_path = match layout {
        "sdk" => "sdk",
        "assembled" => SDK,
        _ => return Err(fail("Expected the sdk or assembled Platform payload layout")),
    };
    let root = directory(&std::env::current_dir()?.join(root))?;
    let sdk = subdirectory(&root, Path::new(sdk_path))?;
    let manifest = read_json(&sdk, Path::new(PAYLOAD))?;
    let payload_hash = manifest["payloadHash"].clone();
    let policy = policy()?;
    let files = decide(&policy, "layerAssembly.sdk", manifest)?;
    let dependency_manifest = read_json(&root, Path::new("runtime-dependencies.json"))?;
    let result = decide(&policy, "layerAssembly.payloadProof", json!({
        "files":files, "payloadHash":payload_hash, "dependencyManifest":dependency_manifest,
    }))?;
    let admitted = files.as_array().ok_or_else(|| fail("Missing Platform SDK file inventory"))?;
    let work = Work::new(Duration::from_secs(120));
    let mut total = 0;
    require_inventory(&work, &sdk, admitted, Some(PAYLOAD))?;
    inspect_admitted(&work, &sdk, None, admitted, &mut total)?;
    inspect_dependencies(&work, &root, None, &result["admitted"], &mut total)?;
    work.check()?;
    let evidence = json!({"proof":result["proof"],"declarations":result["declarations"],"files":files});
    println!("{}", compat_value::stringify(&evidence, &Value::Null)?);
    Ok(())
}

fn compose(paths: [&Path; 3], output: &Path, core: Option<&Path>, physical: bool) -> Result<Value> {
    let cwd = std::env::current_dir()?;
    let output = cwd.join(output);
    let name = output.file_name().ok_or_else(|| fail("Expected a named composition target"))?;
    let parent = directory(output.parent().ok_or_else(|| fail("Missing composition parent"))?)?;
    if unsafe { libc::flock(parent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let parent_path = descriptor(&parent);
    let target = parent_path.join(name);
    let prior = existing(&target)?;
    let roots = paths.map(|path| directory(&cwd.join(path))).into_iter().collect::<Result<Vec<_>>>()?;
    let manifests = roots.iter().map(manifest).collect::<Result<Vec<_>>>()?;
    let core = core.map(|path| manifest(&directory(&cwd.join(path))?)).transpose()?;
    let policy = policy()?;
    let graph = decide(&policy, "layerAssembly.graph", json!({"manifests":manifests,"withCore":core.is_some(),"core":core}))?;
    let mut proof = decide(&policy, "layerAssembly.proof", json!({"graph":graph,"manifests":manifests}))?;
    let stage = Scratch::create(&parent_path, ".layer-assembly-")?;
    let work = Work::new(Duration::from_secs(120));
    let mut total = 0_u64;
    let mut verifications = Vec::new();
    for (root, layer) in roots.iter().zip(&manifests) {
        let files = layer["files"].as_array().ok_or_else(|| fail("Missing layer files"))?;
        inspect_admitted(&work, root, Some(stage.path()), files, &mut total)?;
        verifications.push(json!({"repository":layer["repository"],"layerDigest":layer["layerDigest"],
            "verifiedObjectCount":files.len(),"valid":true}));
    }
    let runtime = decide(&policy, "layerAssembly.runtime", json!({"physical":physical}))?;
    if physical {
        physical_runtime(&policy, &work, &roots[0], stage.path(), &mut total)?;
    } else {
        if !stage.path().join("sdk").is_dir() { return Err(fail("Layer composition requires the admitted SDK tree")); }
        let link = stage.path().join("node_modules/@temple2");
        fs::create_dir_all(&link)?;
        symlink("../../sdk", link.join("platform-sdk"))?;
    }
    write_json(stage.path(), ".sourcery-runtime.json", &runtime)?;
    write_json(stage.path(), ".sourcery-composition.json", &proof)?;
    let mode = prior.as_ref().map(|directory| directory.metadata().map(|metadata| metadata.mode() & 0o777))
        .transpose()?.unwrap_or(0o755);
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(mode))?;
    crate::archive::sync_directories(&work, stage.path())?;
    http::check_interruption(false)?;
    if let Some(prior) = prior {
        let previous = prior.metadata()?;
        let named = existing(&target)?.ok_or_else(|| fail("Empty composition target disappeared"))?.metadata()?;
        if (previous.dev(), previous.ino()) != (named.dev(), named.ino()) {
            return Err(fail("Empty composition target changed"));
        }
        exchange_paths(stage.path(), &target)?;
    } else {
        rename_new_path(stage.path(), &target)?;
    }
    parent.sync_all()?;
    proof["verifications"] = json!(verifications);
    Ok(proof)
}

pub(crate) fn run(paths: &[String]) -> Result<()> {
    let _signals = Supervisor::new();
    let result = match paths {
        [flag] if flag == "--verify-manifests" => {
            let mut bytes = Vec::new();
            io::stdin().lock().take(LIMIT + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > LIMIT { return Err(fail("Layer manifests exceed their byte bound")); }
            let manifests: Value = serde_json::from_slice(&bytes)?;
            compat_value::external(&manifests)?;
            decide(&policy()?, "layerAssembly.graph", json!({"manifests":manifests,"withCore":false}))?
        }
        [flag, platform, capabilities, applications, target, core] if flag == "--source-clean" =>
            compose([Path::new(platform), Path::new(capabilities), Path::new(applications)],
                Path::new(target), Some(Path::new(core)), true)?,
        [platform, capabilities, applications, target, core @ ..] if core.len() <= 1 =>
            compose([Path::new(platform), Path::new(capabilities), Path::new(applications)], Path::new(target),
                core.first().map(Path::new), false)?,
        _ => return Err(fail("Use encounter hosted-compose-layers [--source-clean] PLATFORM CAPABILITIES APPLICATIONS TARGET [CORE]")),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
