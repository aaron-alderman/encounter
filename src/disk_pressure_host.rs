use crate::{Result, appdev_host_process::{Scratch, Supervisor, interruption}, compat_value, disk_pressure, fail, http, rel};
use crate::systemd_user_service::SystemServices;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet}, ffi::CString, fs::{self, File, OpenOptions}, io::{self, Read, Write},
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt, PermissionsExt}}},
    path::{Component, Path, PathBuf},
    rc::Rc, time::{Duration, Instant, SystemTime},
};

const DEVELOPMENT: &str = "sourcery-development-mcp.service";
const LIMIT: u64 = 8 * 1024 * 1024;

fn check() -> Result<()> {
    if interruption().is_some() { return Err(fail("Disk-pressure observation interrupted")); }
    Ok(())
}

fn read_file(path: &Path) -> Result<Option<File>> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let descriptor = unsafe { libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, path.as_ptr(),
        &how, std::mem::size_of::<libc::open_how>()) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT | libc::ELOOP) => Ok(None),
            _ => Err(error.into()),
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor as i32) };
    Ok(file.metadata()?.is_file().then_some(file))
}

fn observed_json(path: &Path) -> Result<Option<(Value, String)>> {
    let Some(file) = read_file(path)? else { return Ok(None); };
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT { return Err(fail("Disk-pressure evidence exceeds its byte limit")); }
    Ok(serde_json::from_slice::<Value>(&bytes).ok().map(|value| (value, rel::hash(bytes))))
}

fn file_hash(path: &Path, expected_size: Option<u64>) -> Result<Option<String>> {
    let Some(mut file) = read_file(path)? else { return Ok(None); };
    let before = file.metadata()?;
    if expected_size.is_some_and(|size| size != before.len()) { return Ok(None); }
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 128 * 1024];
    let mut length = 0;
    loop {
        check()?;
        let read = file.read(&mut buffer)?;
        if read == 0 { break; }
        length += read as u64;
        if length > before.len() { return Ok(None); }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    Ok((length == before.len() && before.modified()? == after.modified()?)
        .then(|| hex::encode(digest.finalize())))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| fail(format!("Expected disk-pressure field {key}")))
}

fn leaf(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !matches!(value, "." | "..")
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn pin(value: &Value) -> Option<&str> {
    value.as_str().filter(|value| value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

fn absolute(path: &Path) -> bool {
    path.is_absolute() && path.components().all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

struct Config {
    policy: Value,
    filesystem: PathBuf,
    runtime: PathBuf,
    releases: PathBuf,
    authority: PathBuf,
    capsules: PathBuf,
    records: PathBuf,
    runtime_proofs: PathBuf,
    release_proofs: PathBuf,
    closures: PathBuf,
    output: PathBuf,
}

impl Config {
    fn load(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let (policy, _) = observed_json(&path)?.ok_or_else(|| fail("Invalid disk-pressure policy file"))?;
        disk_pressure::admit(&policy)?;
        let filesystem = PathBuf::from(text(&policy, "filesystemRoot")?);
        if filesystem == Path::new("/") || !absolute(&filesystem) || filesystem.canonicalize()? != filesystem {
            return Err(fail("Expected a canonical disk-pressure filesystem root"));
        }
        let confined = |path: PathBuf| -> Result<PathBuf> {
            if !absolute(&path) || path == filesystem || !path.starts_with(&filesystem) {
                return Err(fail("Disk-pressure policy path is outside its filesystem root"));
            }
            Ok(path)
        };
        let path = |key| confined(PathBuf::from(text(&policy, key)?));
        let output = path("outputRoot")?;
        Ok(Self {
            runtime: path("runtimeRoot")?, releases: path("releaseRoot")?, authority: path("authorityStore")?,
            capsules: path("sourceCapsuleManifestRoot")?, records: path("releaseRecordRoot")?,
            runtime_proofs: path("runtimeReconstructionEvidenceRoot")?,
            release_proofs: confined(policy["applicationReconstructionEvidenceRoot"].as_str().map(PathBuf::from)
                .unwrap_or_else(|| output.join("reconstruction/releases")))?,
            closures: confined(policy["dependencyClosureRoot"].as_str().map(PathBuf::from)
                .unwrap_or_else(|| filesystem.join("dependency-closures")))?,
            output, filesystem, policy,
        })
    }
}

struct Entry { id: String, path: PathBuf, kind: &'static str, bytes: u64 }

impl Entry {
    fn observed(&self) -> Value {
        json!({"id":self.id,"path":self.path,"type":self.kind,"bytes":self.bytes})
    }
}

fn entries(root: &Path) -> Result<Vec<fs::DirEntry>> {
    check()?;
    match root.canonicalize() {
        Ok(actual) if actual == root => {}
        Ok(_) => return Err(fail("Disk-pressure inventory root resolves through a symlink")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    }
    let mut rows = match fs::read_dir(root) {
        Ok(rows) => rows.take(4097).collect::<io::Result<Vec<_>>>()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    if rows.len() > 4096 { return Err(fail("Disk-pressure inventory exceeds its entry limit")); }
    rows.sort_by(|a, b| crate::compat_value::compare(&a.file_name().to_string_lossy(), &b.file_name().to_string_lossy()));
    Ok(rows)
}

fn directory_observations(root: &Path, depth: usize, duration: Duration,
    mut observe: impl FnMut(&Path, &File, &fs::Metadata) -> Result<()>) -> Result<()> {
    let opened = crate::package::open_beneath(&File::open("/")?, root.strip_prefix("/")?)?;
    if !opened.metadata()?.is_dir() { return Err(fail("Expected a physical disk-pressure directory")); }
    let deadline = Instant::now() + duration;
    let mut remaining = 2_000_000_u64;
    let entries = |file: &File| fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()));
    observe(root, &opened, &opened.metadata()?)?;
    let mut stack = vec![(root.to_path_buf(), entries(&opened)?, opened)];
    while !stack.is_empty() {
        check()?;
        if remaining == 0 || Instant::now() >= deadline {
            return Err(fail("Disk-pressure directory observation exceeded its bounds"));
        }
        let level = stack.len();
        let (path, children, file) = stack.last_mut().expect("open directory frame");
        let Some(entry) = children.next() else { stack.pop(); continue; };
        remaining -= 1;
        let name = entry?.file_name();
        let name_c = CString::new(name.as_bytes())?;
        let fd = unsafe { libc::openat(file.as_raw_fd(), name_c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 { return Err(io::Error::last_os_error().into()); }
        let child = unsafe { File::from_raw_fd(fd) };
        let child_path = path.join(name);
        let info = child.metadata()?;
        observe(&child_path, &child, &info)?;
        if info.is_dir() && level < depth {
            if level >= 128 { return Err(fail("Disk-pressure directory observation exceeded its depth limit")); }
            stack.push((child_path, entries(&child)?, child));
        }
    }
    Ok(())
}

fn apparent_bytes(path: &Path) -> Result<u64> {
    let mut bytes = 0_u64;
    let mut hardlinks = BTreeSet::new();
    directory_observations(path, usize::MAX, Duration::from_secs(120), |_, _, metadata| {
        if (metadata.is_dir() || metadata.is_file() || metadata.is_symlink())
            && (metadata.is_dir() || metadata.nlink() <= 1 || hardlinks.insert((metadata.dev(), metadata.ino()))) {
            bytes = bytes.checked_add(metadata.len()).ok_or_else(|| fail("Disk-pressure directory size overflow"))?;
        }
        Ok(())
    })?;
    Ok(bytes)
}

fn inventory(root: &Path, select: impl Fn(&str) -> bool) -> Result<Vec<Entry>> {
    let mut inventory = Vec::new();
    for row in entries(root)? {
        let id = row.file_name().into_string().map_err(|_| fail("Invalid UTF-8 disk-pressure inventory entry"))?;
        if !select(&id) { continue; }
        let path = row.path();
        let kind = row.file_type()?;
        let (kind, bytes) = if kind.is_dir() {
            ("directory", apparent_bytes(&path)?)
        } else if kind.is_symlink() { ("symlink", 0) } else { ("other", 0) };
        inventory.push(Entry { id, path, kind, bytes });
    }
    Ok(inventory)
}

struct References {
    processes: Vec<Vec<u8>>,
    symlinks: Vec<(String, String)>,
    config: Vec<(String, Vec<u8>)>,
}

fn bounded_bytes(file: File, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Disk-pressure reference observation exceeded its byte limit")); }
    Ok(bytes)
}

fn process_references() -> Result<Vec<Vec<u8>>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut remaining = LIMIT;
    let mut by_pid = BTreeMap::new();
    for (index, entry) in fs::read_dir("/proc")?.enumerate() {
        check()?;
        if index >= 65536 || Instant::now() >= deadline {
            return Err(fail("Disk-pressure process observation exceeded its bounds"));
        }
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue; };
        let read = || -> Result<_> {
            let directory = File::open(entry.path())?;
            let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
            let stat = bounded_bytes(File::open(path.join("stat"))?, 8192)?;
            let start = stat.iter().position(|byte| *byte == b'(').ok_or_else(|| fail("Missing process name"))?;
            let end = stat.iter().rposition(|byte| *byte == b')').filter(|end| *end > start)
                .ok_or_else(|| fail("Missing process state"))?;
            let parent = std::str::from_utf8(&stat[end + 1..])?.split_ascii_whitespace().nth(1)
                .ok_or_else(|| fail("Missing process parent"))?.parse::<u32>()?;
            let mut args = bounded_bytes(File::open(path.join("cmdline"))?, remaining)?;
            if args.is_empty() { args.extend_from_slice(&stat[start + 1..end]); }
            for byte in &mut args { if *byte == 0 { *byte = b' '; } }
            Ok((parent, args))
        };
        match read() {
            Ok((parent, args)) => {
                remaining = remaining.checked_sub(args.len() as u64)
                    .ok_or_else(|| fail("Disk-pressure process observation exceeded its byte limit"))?;
                by_pid.insert(pid, (parent, args));
            }
            Err(error) if error.downcast_ref::<io::Error>()
                .is_some_and(|error| matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))) => {}
            Err(error) => return Err(error),
        }
    }
    let mut lineage = BTreeSet::new();
    let mut pid = std::process::id();
    while pid != 0 && lineage.insert(pid) { pid = by_pid.get(&pid).map_or(0, |row| row.0); }
    Ok(by_pid.into_iter().filter(|(pid, _)| !lineage.contains(pid)).map(|(_, (_, args))| args).collect())
}

fn configuration_references(roots: Vec<PathBuf>) -> Result<Vec<(String, Vec<u8>)>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut remaining = LIMIT;
    let mut files = Vec::new();
    let mut pending = roots.into_iter().map(|root| (root, Rc::new(Vec::new()))).collect::<Vec<_>>();
    let mut entries = 0_u32;
    while let Some((path, mut parents)) = pending.pop() {
        check()?;
        entries += 1;
        if entries > 65536 || Instant::now() >= deadline {
            return Err(fail("Disk-pressure configuration observation exceeded its bounds"));
        }
        if path.as_os_str().len() > 4096 { return Err(fail("Disk-pressure configuration path exceeded its byte limit")); }
        let file = OpenOptions::new().read(true).custom_flags(libc::O_PATH).open(&path)?;
        let metadata = file.metadata()?;
        if metadata.is_dir() {
            if path.file_name().is_some_and(|name| matches!(name.to_str(), Some("releases" | "person-authority"))) {
                continue;
            }
            let identity = (metadata.dev(), metadata.ino());
            if parents.contains(&identity) { continue; }
            if parents.len() >= 128 { return Err(fail("Disk-pressure configuration exceeded its depth limit")); }
            Rc::make_mut(&mut parents).push(identity);
            for child in fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))? {
                check()?;
                if pending.len() >= 65536 || Instant::now() >= deadline {
                    return Err(fail("Disk-pressure configuration observation exceeded its bounds"));
                }
                let name = child?.file_name();
                pending.push((path.join(name), Rc::clone(&parents)));
            }
        } else if metadata.is_file() {
            let name = path.file_name().expect("configuration filename").as_bytes();
            if name.windows(4).any(|part| part == b".bak") || name.windows(5).any(|part| part == b".pre-") { continue; }
            let read = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
            let bytes = bounded_bytes(read, remaining)?;
            remaining -= bytes.len() as u64;
            if !bytes.contains(&0) {
                let source = path.to_str().ok_or_else(|| fail("Expected a UTF-8 disk-pressure configuration path"))?;
                files.push((source.to_owned(), bytes));
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

impl References {
    fn collect(root: &Path, config: Vec<PathBuf>) -> Result<Self> {
        let processes = process_references()?;
        let mut symlinks = Vec::new();
        let mut bytes = 0;
        directory_observations(root, 4, Duration::from_secs(30), |path, file, metadata| {
            if !metadata.is_symlink() { return Ok(()); }
            let mut target = [0; 4096];
            let length = unsafe { libc::readlinkat(file.as_raw_fd(), c"".as_ptr(), target.as_mut_ptr().cast(), target.len()) };
            if length < 0 { return Err(io::Error::last_os_error().into()); }
            let length = length as usize;
            let path = path.to_str().ok_or_else(|| fail("Expected a UTF-8 disk-pressure symlink path"))?;
            bytes += path.len() + length + 2;
            if length == target.len() || bytes > LIMIT as usize {
                return Err(fail("Disk-pressure symlink observation exceeded its bounds"));
            }
            symlinks.push((path.to_owned(), std::str::from_utf8(&target[..length])?.to_owned()));
            Ok(())
        })?;
        symlinks.sort();
        Ok(Self { processes, symlinks, config: configuration_references(config)? })
    }

    fn for_id(&self, id: &str) -> Result<Vec<Value>> {
        check()?;
        if id.is_empty() { return Err(fail("Expected a disk-pressure reference identifier")); }
        let mut result = Vec::new();
        let needle = id.as_bytes();
        let matches = |bytes: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
        if self.processes.iter().any(|args| matches(args)) {
            result.push(json!({"kind":"process","source":"process-table"}));
        }
        for (source, bytes) in &self.config {
            check()?;
            if matches(bytes) { result.push(json!({"kind":"config","source":source})); }
        }
        result.extend(self.symlinks.iter().filter(|(_, target)| target.contains(id))
            .map(|(source, _)| json!({"kind":"symlink","source":source})));
        Ok(result)
    }
}

fn sealed_observation(path: &Path) -> Result<Value> {
    Ok(observed_json(path)?.map_or(Value::Null, |(value, hash)| json!({"path":path,"sha256":hash,"value":value})))
}

fn runtime_reconstruction(config: &Config, id: &str) -> Result<Value> {
    let path = config.runtime_proofs.join(format!("{id}.json"));
    let Some((value, digest)) = observed_json(&path)? else { return Ok(Value::Null); };
    if value["protocol"] != "sourcery/runtime-reconstruction-evidence.v1" {
        return Ok(Value::Null);
    }
    let Some(artifacts) = value["artifacts"].as_array().filter(|artifacts| artifacts.len() == 3) else {
        return Ok(Value::Null);
    };
    let mut observed = Vec::new();
    for artifact in artifacts {
        let Some(path) = artifact["path"].as_str().map(Path::new) else { return Ok(Value::Null); };
        let Some(sha) = pin(&artifact["sha256"]) else { return Ok(Value::Null); };
        if !absolute(path) || !(path.starts_with(&config.authority) || path.starts_with(config.filesystem.join("shared-assets"))) {
            return Ok(Value::Null);
        }
        observed.push(json!({"kind":artifact["kind"],"path":path,"sha256":sha,"observedSha256":file_hash(path, None)?}));
    }
    Ok(json!({"evidencePath":path,"evidenceSha256":digest,"admissionHash":value["admissionHash"],
        "coreBundleHash":value["coreBundleHash"],"dependencyBundleHash":value["dependencyBundleHash"],"artifacts":observed}))
}

fn capsule_evidence(config: &Config) -> Result<BTreeMap<String, Value>> {
    let mut manifests = entries(&config.capsules)?;
    manifests.sort_by_key(|row| row.file_name());
    let parent = config.capsules.parent().ok_or_else(|| fail("Missing source capsule directory"))?;
    let mut mapped = BTreeMap::new();
    for row in manifests {
        let path = row.path();
        if path.extension().is_none_or(|extension| extension != "json") { continue; }
        let Some((value, hash)) = observed_json(&path)? else { continue; };
        if path.file_stem().and_then(|stem| stem.to_str()) != Some(&hash)
            || value["protocol"] != "sourcery/source-capsule-retention.v1" { continue; }
        let Some(capsules) = value["capsules"].as_array().filter(|capsules| !capsules.is_empty()) else { continue; };
        let mut total = 0_u64;
        let mut valid = true;
        for capsule in capsules {
            let fields = (capsule["repository"].as_str(), pin(&capsule["sha256"]), capsule["bytes"].as_u64());
            let (Some(repository), Some(sha), Some(bytes)) = fields else { valid = false; break; };
            if !leaf(repository) || file_hash(&parent.join(repository).join(format!("{sha}.tar.gz")), Some(bytes))?.as_deref() != Some(sha) {
                valid = false;
                break;
            }
            total = total.checked_add(bytes).ok_or_else(|| fail("Source capsule size overflow"))?;
        }
        if valid && let Some(ids) = value["resolvedReleaseIds"].as_array() {
            for id in ids.iter().filter_map(Value::as_str).filter(|id| leaf(id)) {
                mapped.insert(id.to_owned(), json!({"manifestPath":path,"manifestSha256":hash,"capsuleCount":capsules.len(),
                    "capsuleBytes":total,"capsulesVerified":true}));
            }
        }
    }
    Ok(mapped)
}

fn release_evidence(config: &Config, release: &Entry) -> Result<Value> {
    let mut observation = sealed_observation(&release.path.join(".sourcery-release-evidence.json"))?;
    let (Some(capsule), Some(proof)) = (pin(&observation["value"]["sourceCapsuleManifestHash"]),
        pin(&observation["value"]["reconstructionProofHash"])) else { return Ok(Value::Null); };
    let manifest = config.capsules.join(format!("{capsule}.json"));
    let proof = config.release_proofs.join(format!("{proof}.json"));
    observation["capsuleSha256"] = json!(file_hash(&manifest, None)?);
    observation["proofSha256"] = json!(file_hash(&proof, None)?);
    observation["sourceCapsuleManifestPath"] = json!(manifest);
    observation["reconstructionProofPath"] = json!(proof);
    Ok(observation)
}

fn pressure(root: &Path) -> Result<Value> {
    let path = CString::new(root.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let stats = unsafe { stats.assume_init() };
    let used = stats.f_blocks.checked_sub(stats.f_bfree).ok_or_else(|| fail("Invalid filesystem usage"))?;
    let available = stats.f_bavail;
    let denominator = u128::from(used) + u128::from(available);
    if denominator == 0 { return Err(fail("Filesystem usage unavailable")); }
    let percent = u64::try_from((u128::from(used) * 100).div_ceil(denominator))?;
    let bytes = |blocks: u64| blocks.checked_mul(stats.f_frsize).ok_or_else(|| fail("Filesystem size overflow"));
    Ok(json!({"totalBytes":bytes(stats.f_blocks)?,"usedBytes":bytes(used)?,"availableBytes":bytes(available)?,"usedPercent":percent}))
}

fn readiness(policy: &Value) -> Result<Value> {
    let url = text(&policy["readiness"], "url")?;
    let port: u16 = url.strip_prefix("http://127.0.0.1:").and_then(|url| url.strip_suffix("/mcp"))
        .ok_or_else(|| fail("Expected a loopback MCP readiness URL"))?.parse()?;
    if port == 0 { return Err(fail("Invalid MCP readiness port")); }
    let wire = format!("GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let result = (|| -> Result<Value> {
        let mut reply = http::LoopbackReply::open(port, wire.as_bytes(), Duration::from_secs(5))?;
        let (line, headers) = http::read_head(&mut reply)?;
        let mut fields = line.split_whitespace();
        if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) { return Err(fail("Invalid MCP readiness response")); }
        let status: u16 = fields.next().ok_or_else(|| fail("Missing MCP readiness status"))?.parse()?;
        Ok(json!({"status":status,"allow":headers.get("allow")}))
    })();
    check()?;
    Ok(result.unwrap_or_else(|error| json!({"status":null,"allow":null,"error":error.to_string()})))
}

fn active_release(system: &SystemServices) -> Result<PathBuf> {
    check()?;
    let active = PathBuf::from(system.working_directory(DEVELOPMENT)?);
    if !absolute(&active) { return Err(fail("Active service has no absolute working directory")); }
    Ok(active)
}

fn service_states(system: &SystemServices, policy: &Value) -> Result<Map<String, Value>> {
    let mut states = Map::new();
    let services = policy["services"].as_array().filter(|items| !items.is_empty() && items.len() <= 64)
        .ok_or_else(|| fail("Expected bounded disk-pressure service names"))?;
    for service in services {
        check()?;
        let service = service.as_str().filter(|service| service.ends_with(".service") && leaf(service))
            .ok_or_else(|| fail("Invalid disk-pressure service name"))?;
        let state = system.active_state(service).unwrap_or_else(|_| "unknown".to_owned());
        check()?;
        states.insert(service.to_owned(), json!(state));
    }
    Ok(states)
}

fn collect(config: &Config, active: &Path, references: &References, services: Map<String, Value>) -> Result<Value> {
    let marker = config.authority.join("current.json");
    let (authority, hash) = observed_json(&marker)?.ok_or_else(|| fail("Missing current runtime authority marker"))?;
    let active_id = active.strip_prefix(&config.releases).ok().and_then(|path| path.to_str()).filter(|id| leaf(id))
        .ok_or_else(|| fail("Active service working directory is outside the release inventory"))?;
    let mut runtimes = Vec::new();
    for row in inventory(&config.runtime, |_| true)?.into_iter().filter(|row| row.kind == "directory") {
        if pin(&json!(row.id)).is_none() { return Err(fail("Invalid installed runtime reference")); }
        let mut refs = references.for_id(&row.id)?;
        refs.sort_by(|left, right| {
            let key = |row: &Value| (row["kind"].as_str().unwrap_or("").to_owned(), row["source"].as_str().unwrap_or("").to_owned());
            let (left_kind, left_source) = key(left);
            let (right_kind, right_source) = key(right);
            compat_value::compare(&left_kind, &right_kind).then_with(|| compat_value::compare(&left_source, &right_source))
        });
        let refs = refs.into_iter().map(|mut reference| {
            reference["referenceHash"] = json!(row.id);
            reference
        }).collect::<Vec<_>>();
        runtimes.push(json!({"referenceHash":row.id,"directory":row.path,"bytes":row.bytes,"liveReferences":refs,
            "reconstruction":runtime_reconstruction(config, &row.id)?,
            "releaseEvidence":sealed_observation(&row.path.join("release-evidence.json"))?}));
    }
    let capsules = capsule_evidence(config)?;
    let mut releases = Vec::new();
    for row in inventory(&config.releases, |_| true)? {
        if !leaf(&row.id) { return Err(fail("Invalid installed release identity")); }
        let mut observed = row.observed();
        observed["liveReferences"] = json!(references.for_id(&row.id)?);
        observed["releaseRecordSha256"] = json!(file_hash(&config.records.join(&row.id).join(".sourcery-release.json"), None)?);
        observed["capsuleEvidence"] = capsules.get(&row.id).cloned().unwrap_or(Value::Null);
        observed["releaseEvidence"] = if row.kind == "directory" { release_evidence(config, &row)? } else { Value::Null };
        releases.push(observed);
    }
    let mut closures = Vec::new();
    for row in inventory(&config.closures, |_| true)?.into_iter().filter(|row| row.kind == "directory") {
        let mut observed = row.observed();
        observed["manifest"] = sealed_observation(&row.path.join(".sourcery-dependency-closure.json"))?;
        closures.push(observed);
    }
    let ancillary = inventory(&config.filesystem, |name| name.starts_with("live-") || name.starts_with("failed-")
        || name.starts_with("qualification-"))?.into_iter().map(|row| row.observed()).collect::<Vec<_>>();
    Ok(json!({"protocol":"sourcery/disk-pressure-observations.v1",
        "createdAt":DateTime::<Utc>::from(SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true),
        "policy":config.policy,"activeReleaseId":active_id,"runtimes":runtimes,"releases":releases,
        "dependencyClosures":closures,"ancillary":ancillary,"pressure":pressure(&config.filesystem)?,
        "authority":{"referenceHash":authority["referenceHash"],"admissionHash":authority["admissionHash"],"markerSha256":hash},
        "health":{"services":services,"readiness":readiness(&config.policy)?}}))
}

fn private_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn publish(output: &Path, report: &Value) -> Result<()> {
    let hash = pin(&report["assessmentHash"]).ok_or_else(|| fail("Invalid disk-pressure assessment hash"))?;
    let html = disk_pressure::render(report)?;
    let wire = format!("{}\n", compat_value::stringify(report, &json!(2))?);
    let identity = format!("{hash}\n");
    let files = [("assessment.json", wire.as_bytes()), ("index.html", text(&html, "index")?.as_bytes()),
        ("approval-gate.html", text(&html, "gate")?.as_bytes()), ("assessment.identity", identity.as_bytes())];
    let current = output.join("current");
    let history = output.join("history");
    for directory in [&current, &history] {
        if directory.canonicalize()? != *directory || !directory.is_dir() {
            return Err(fail("Expected existing disk-pressure publication directories"));
        }
    }
    let lock = OpenOptions::new().write(true).create(true).truncate(false).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(current.join(".disk-pressure.lock"))?;
    if !lock.metadata()?.is_file() || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("Disk-pressure publication lock is unavailable"));
    }
    let scratch = Scratch::create(&current, ".disk-pressure-")?;
    let previous = scratch.path().join("previous");
    fs::create_dir(&previous)?;
    for (name, body) in files {
        private_write(&scratch.path().join(name), body, 0o644)?;
        let destination = current.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(meta) if meta.is_file() => fs::hard_link(&destination, previous.join(name))?,
            Ok(_) => return Err(fail("Disk-pressure report destination is not a regular file")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let history_stage = Scratch::create(&history, ".disk-pressure-")?;
    let staged_history = history_stage.path().join("assessment.json");
    let published_history = history.join(format!("{hash}.json"));
    private_write(&staged_history, wire.as_bytes(), 0o444)?;
    check()?;
    match fs::hard_link(staged_history, &published_history) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists
            && file_hash(&published_history, Some(wire.len() as u64))?.as_deref() == Some(&rel::hash(wire.as_bytes())) => {}
        Err(error) => return Err(error.into()),
    }
    File::open(&history)?.sync_all()?;
    let mut committed = Vec::new();
    for (name, _) in files {
        if let Err(error) = fs::rename(scratch.path().join(name), current.join(name)) {
            for name in committed.into_iter().rev() {
                let old = previous.join(name);
                if old.exists() { fs::rename(old, current.join(name))?; }
                else { fs::remove_file(current.join(name))?; }
            }
            return Err(error.into());
        }
        committed.push(name);
    }
    File::open(&current)?.sync_all()?;
    Ok(())
}

pub fn run(path: &Path, publish_report: bool) -> Result<()> {
    let _supervisor = Supervisor::new();
    let config = Config::load(path)?;
    let system = SystemServices::open()?;
    let active = active_release(&system)?;
    let sources = [PathBuf::from("/etc/systemd/system"), PathBuf::from("/etc/sourcery-dev")];
    let references = References::collect(&config.filesystem, sources.into())?;
    let services = service_states(&system, &config.policy)?;
    let observation = collect(&config, &active, &references, services)?;
    let report = disk_pressure::assessment(observation)?;
    if active_release(&system)? != active || file_hash(&config.authority.join("current.json"), None)?.as_deref()
        != report["authority"]["markerSha256"].as_str() {
        return Err(fail("Runtime authority or active release changed during disk-pressure observation"));
    }
    check()?;
    if !publish_report {
        println!("{}", compat_value::stringify(&report, &json!(2))?);
        return Ok(());
    }
    publish(&config.output, &report)?;
    let summary = &report["summary"];
    println!("{}", json!({"status":"completed","mode":report["mode"],"assessmentHash":report["assessmentHash"],
        "pressure":report["pressure"]["status"],"candidateCount":summary["candidateCount"],"candidateBytes":summary["candidateBytes"],
        "isolatedCount":summary["isolatedCount"],"unknownCount":summary["unknownCount"],"output":config.output.join("current")}));
    Ok(())
}

#[cfg(test)]
#[test]
fn fresh_scan_and_publication_preserve_evidence_and_report_boundary() -> Result<()> {
    use std::{net::{Ipv4Addr, TcpListener}, os::unix::fs::symlink};
    let scratch = Scratch::create(&std::env::temp_dir(), "disk-pressure-host-test-")?;
    let root = scratch.path().canonicalize()?;
    let active = root.join("releases/active");
    let old = root.join("releases/candidate");
    let referenced = root.join("releases/linked");
    let hash = "a".repeat(64);
    for directory in [&active, &old, &referenced, &root.join(format!("runtimes/{hash}")), &root.join("authority"),
        &root.join("capsules/manifests"), &root.join("capsules/source"), &root.join("records/candidate"),
        &root.join("records/linked"), &root.join("reports/current"), &root.join("reports/history"), &root.join("config")] {
        fs::create_dir_all(directory)?;
    }
    fs::write(root.join("authority/current.json"), json!({"referenceHash":hash,"admissionHash":"b".repeat(64)}).to_string())?;
    let capsule = b"retained fixture bytes";
    let pin = rel::hash(capsule);
    fs::write(root.join(format!("capsules/source/{pin}.tar.gz")), capsule)?;
    let manifest = json!({"protocol":"sourcery/source-capsule-retention.v1","resolvedReleaseIds":["candidate","linked"],
        "capsules":[{"repository":"source","sha256":pin,"bytes":capsule.len()}]}).to_string();
    fs::write(root.join(format!("capsules/manifests/{}.json", rel::hash(&manifest))), manifest)?;
    for id in ["candidate", "linked"] { fs::write(root.join(format!("records/{id}/.sourcery-release.json")), "{}")?; }
    symlink(&referenced, root.join("linked-release"))?;
    fs::write(old.join("bytes"), b"count once")?;
    fs::hard_link(old.join("bytes"), old.join("hardlink"))?;
    symlink(&referenced, old.join("symlink"))?;
    let directory_bytes = old.metadata()?.len();
    let link_bytes = old.join("symlink").symlink_metadata()?.len();
    assert_eq!(apparent_bytes(&old)?, directory_bytes + link_bytes + 10);
    fs::write(root.join("config/active.service"), format!("WorkingDirectory={}", active.display()))?;
    fs::write(root.join("config/ignored.service.bak"), "candidate")?;
    fs::write(root.join("config/ignored.service.pre-upgrade"), "candidate")?;
    fs::write(root.join("config/ignored.bin"), b"\0candidate")?;
    for name in ["releases", "person-authority"] {
        let directory = root.join("config").join(name);
        fs::create_dir(&directory)?;
        fs::write(directory.join("ignored.conf"), "candidate")?;
    }
    let outside = root.join("outside.conf");
    fs::write(&outside, "linked")?;
    symlink(&outside, root.join("config/enabled.service"))?;
    symlink(root.join("config"), root.join("config/cycle"))?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let server = std::thread::spawn(move || -> io::Result<()> {
        let (mut connection, _) = listener.accept()?;
        connection.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: POST\r\nContent-Length: 0\r\n\r\n")?;
        Ok(())
    });
    let policy_path = root.join("policy.json");
    fs::write(&policy_path, json!({
        "protocol":"sourcery/server-disk-pressure-assurance-policy.v1",
        "filesystemRoot":root,"runtimeRoot":root.join("runtimes"),"releaseRoot":root.join("releases"),
        "authorityStore":root.join("authority"),"sourceCapsuleManifestRoot":root.join("capsules/manifests"),
        "releaseRecordRoot":root.join("records"),"runtimeReconstructionEvidenceRoot":root.join("proofs"),
        "outputRoot":root.join("reports"),"rollbackReleaseIds":[],
        "safety":{"mode":"dry-run-only","automaticDeletion":false},
        "retention":{"minimumRollbackReleases":1,"quarantineDays":30,"assessmentHistoryDays":180},
        "readiness":{"url":format!("http://127.0.0.1:{port}/mcp"),"expectedStatus":405,"expectedAllow":"POST"},
        "pressure":{"warningAvailablePercent":25,"criticalAvailablePercent":15,"warningAvailableBytes":400,"criticalAvailableBytes":200}
    }).to_string())?;
    let config = Config::load(&policy_path)?;
    let mut references = References::collect(&root, vec![root.join("config")])?;
    references.processes.clear();
    assert!(references.for_id("candidate")?.is_empty());
    assert!(references.for_id("linked")?.iter().any(|reference|
        reference["kind"] == "config" && reference["source"] == root.join("config/enabled.service").to_str().unwrap()));
    let observations = collect(&config, &active, &references, Map::from_iter([(DEVELOPMENT.into(), json!("active"))]))?;
    server.join().map_err(|_| fail("MCP readiness test listener failed"))??;
    let report = disk_pressure::assessment(observations)?;
    assert_eq!(report["health"]["readiness"]["passed"], true);
    assert_eq!(report["summary"]["candidateCount"], 1, "{}", report["inventory"]["releases"]);
    assert_eq!(report["candidates"][0]["id"], "candidate");
    assert_eq!(report["inventory"]["releases"][2]["classification"], "live");
    assert!(report["inventory"]["releases"][2]["liveReferences"].as_array().unwrap()
        .iter().any(|reference| reference["kind"] == "symlink"));
    publish(&config.output, &report)?;
    publish(&config.output, &report)?;
    let current = config.output.join("current");
    let hash = report["assessmentHash"].as_str().unwrap();
    assert_eq!(fs::read_to_string(current.join("assessment.identity"))?, format!("{hash}\n"));
    assert_eq!(fs::read(current.join("assessment.json"))?, fs::read(config.output.join(format!("history/{hash}.json")))?);
    assert!(fs::read_to_string(current.join("index.html"))?.contains("Approval required"));
    assert!(fs::read_to_string(current.join("approval-gate.html"))?.contains("Retirement candidates found."));
    assert!(old.is_dir());
    fs::rename(current.join("index.html"), current.join("saved.html"))?;
    symlink(current.join("saved.html"), current.join("index.html"))?;
    assert!(publish(&config.output, &report).is_err());
    assert!(current.join("index.html").is_symlink());
    Ok(())
}
