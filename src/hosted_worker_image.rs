use crate::{Result, appdev_host_process::{Scratch, Supervisor, handle_hangup}, archive::{self, ImageArchive, Work},
    command_sources::Sources, compat_value, fail, package::require_bounded_x64_executable, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, BTreeSet}, env, fs, io::{self, Read}, os::{fd::AsRawFd, unix::{fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, process::CommandExt}},
    path::{Component, Path}, process::{Command, Stdio}, time::Duration};

const BASE_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const FILE_LIMIT: u64 = 256 * 1024 * 1024;
const STATUS_LIMIT: u64 = 8 * 1024 * 1024;
const ADMISSION_LIMIT: u64 = 16 * 1024;
const TOOL_DEADLINE: Duration = Duration::from_secs(30);
const BUILD_DEADLINE: Duration = Duration::from_secs(300);

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_worker_image.encounter").to_owned()],
        &["workerImage.digest", "workerImage.base", "workerImage.files", "workerImage.packageStatus", "workerImage.recipe"],
        &BTreeSet::from(["kernel.invoke", "text.matches", "text.join"]), &mut Meter::new(200_000))
}

fn decision(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(2_000_000))
}

fn admission_policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_worker_image.encounter").to_owned()],
        &["workerImage.digest", "workerImage.admission", "workerImage.admissionCustody"],
        &BTreeSet::from(["kernel.invoke", "text.matches", "record.entries", "value.type",
            "number.calculate", "time.parseRfc3339"]), &mut Meter::new(200_000))
}

fn read_evidence(mut reader: impl Read) -> Result<Value> {
    let mut bytes = Vec::new();
    reader.by_ref().take(ADMISSION_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > ADMISSION_LIMIT { return Err(fail("Worker image admission exceeds its byte bound")); }
    let value = serde_json::from_slice(&bytes).map_err(|_| fail("Worker image admission must contain valid JSON"))?;
    compat_value::external(&value)?;
    Ok(value)
}

pub(crate) fn validate_digest() -> Result<()> {
    let result = decision(&admission_policy()?, "workerImage.digest", read_evidence(io::stdin().lock())?)?;
    println!("{result}");
    Ok(())
}

pub(crate) fn validate_admission() -> Result<()> {
    let request = read_evidence(io::stdin().lock())?;
    let result = decision(&admission_policy()?, "workerImage.admission", request)?;
    println!("{result}");
    Ok(())
}

pub(super) fn read_admission_file(path: &Path, image: &str, owner: u32) -> Result<Value> {
    let policy = &admission_policy()?;
    let root = Path::new("/");
    let relative = path.strip_prefix(root)?.to_str().ok_or_else(|| fail("Worker image admission path must be UTF-8"))?;
    let evidence = Sources::open_physical(root)?.observe_relative(relative)?;
    let observed = evidence.metadata()?;
    let mode = observed.mode();
    decision(policy, "workerImage.admissionCustody", json!({
        "regular": observed.is_file(), "bytes": observed.len(), "uid": observed.uid(), "expectedUid": owner,
        "groupWritable": mode & 0o020 != 0, "groupExecutable": mode & 0o010 != 0, "public": mode & 0o007 != 0,
    }))?;
    let opened = fs::File::open(format!("/proc/self/fd/{}", evidence.as_raw_fd()))?;
    decision(policy, "workerImage.admission", json!({"image": image, "evidence": read_evidence(opened)?}))
}

pub(crate) fn read_admission(path: &Path, image: &str, owner: u32) -> Result<()> {
    let evidence = read_admission_file(path, image, owner)?;
    println!("{evidence}");
    Ok(())
}

pub(super) struct Podman(fs::File);

impl Podman {
    pub(super) fn open() -> Result<Self> {
        let mut file = fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open("/usr/bin/podman")?;
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(fail("Expected a protected platform Podman executable"));
        }
        require_bounded_x64_executable(&mut file, 64_000_000)?;
        Ok(Self(file))
    }

    pub(super) fn command(&self) -> Command {
        let mut command = Command::new(format!("/proc/self/fd/{}", self.0.as_raw_fd()));
        command.arg0("/usr/bin/podman").env_clear().env("LC_ALL", "C").env("PATH", "/usr/sbin:/usr/bin").stdin(Stdio::null());
        for name in ["HOME", "XDG_RUNTIME_DIR"] {
            if let Some(value) = env::var_os(name) { command.env(name, value); }
        }
        command
    }
}

fn inspect_base(policy: &Programme, podman: &Podman, digest: &str) -> Result<()> {
    let output = Supervisor::new().capture("Inspect local worker base",
        podman.command().args(["image", "inspect", "--format", "{{.Id}} {{.Os}} {{.Architecture}}", digest]),
        TOOL_DEADLINE, 1024)?;
    let fields = std::str::from_utf8(&output)?.split_whitespace().collect::<Vec<_>>();
    let [observed, os, arch] = fields.as_slice() else { return Err(fail("Malformed worker base inspection")); };
    let observed = if observed.starts_with("sha256:") { (*observed).to_owned() } else { format!("sha256:{observed}") };
    decision(policy, "workerImage.base", json!({"expected": digest, "observed": observed, "os": os, "arch": arch}))?;
    Ok(())
}

fn export_base(podman: &Podman, digest: &str, scratch: &Path, export: &Path) -> Result<()> {
    let name = scratch.file_name().and_then(|value| value.to_str()).ok_or_else(|| fail("Invalid worker build directory"))?;
    let result = (|| {
        Supervisor::new().capture("Create stopped worker base container",
            podman.command().args(["create", "--pull=never", "--network=none", "--image-volume=ignore", "--no-healthcheck",
                "--name", name, "--entrypoint=/usr/local/bin/node", digest, "--version"]),
            TOOL_DEADLINE, 1024)?;
        let mut command = podman.command();
        // Cap the export on disk even if Podman never returns.
        unsafe { command.pre_exec(|| {
            let size = libc::rlimit { rlim_cur: BASE_LIMIT, rlim_max: BASE_LIMIT };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &size) != 0 { return Err(io::Error::last_os_error()); }
            Ok(())
        }); }
        Supervisor::new().run_until("Export stopped worker base",
            command.args(["export", "--output"]).arg(export).arg(name), Some(BUILD_DEADLINE))
    })();
    let cleanup = Supervisor::release_recovery().capture("Remove stopped worker base container",
        podman.command().args(["rm", "--ignore", name]), TOOL_DEADLINE, 1024);
    match (result, cleanup) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(fail(format!("{error}; worker base cleanup failed: {cleanup}"))),
    }
}

fn status_records(source: &str) -> Result<Vec<BTreeMap<&str, &str>>> {
    let mut records = Vec::new();
    for paragraph in source.split("\n\n") {
        let mut record = BTreeMap::new();
        let mut scalar = false;
        for line in paragraph.lines() {
            if line.is_empty() { continue; }
            if line.starts_with([' ', '\t']) {
                if scalar { return Err(fail("Unexpected continuation of Debian status scalar")); }
                continue;
            }
            let (field, value) = line.split_once(':').ok_or_else(|| fail("Malformed Debian status field"))?;
            scalar = matches!(field, "Package" | "Status" | "Architecture" | "Version");
            if scalar && record.insert(field, value.trim()).is_some() {
                return Err(fail("Duplicate Debian status field"));
            }
        }
        if !record.is_empty() { records.push(record); }
        if records.len() > 10_000 { return Err(fail("Too many Debian status records")); }
    }
    Ok(records)
}

fn stage(policy: &Programme, work: &Work, archive: &mut ImageArchive, context: &Path) -> Result<()> {
    let root = context.join("rootfs");
    let files = decision(policy, "workerImage.files", Value::Null)?;
    for relative in files.as_array().ok_or_else(|| fail("Expected worker image file list"))? {
        let relative = relative.as_str().ok_or_else(|| fail("Expected worker image file path"))?;
        let path = Path::new(relative);
        if !path.components().all(|part| matches!(part, Component::Normal(_))) {
            return Err(fail("Expected a normalized worker image file path"));
        }
        let destination = root.join(path);
        fs::create_dir_all(destination.parent().ok_or_else(|| fail("Missing worker image file parent"))?)?;
        let mut file = archive::create(&destination)?;
        let mode = archive.copy(work, relative, &mut file, FILE_LIMIT)?;
        file.set_permissions(fs::Permissions::from_mode(0o644 | (mode & 0o111)))?;
    }
    for path in ["usr/local/bin/node", "lib64/ld-linux-x86-64.so.2"] {
        require_bounded_x64_executable(&mut archive::input(&root.join(path), FILE_LIMIT)?, FILE_LIMIT)?;
    }
    let mut bytes = Vec::new();
    archive.copy(work, "var/lib/dpkg/status", &mut bytes, STATUS_LIMIT)?;
    let records = status_records(std::str::from_utf8(&bytes)?)?;
    let status = decision(policy, "workerImage.packageStatus", json!(records))?;
    let destination = root.join("var/lib/dpkg");
    fs::create_dir_all(&destination)?;
    fs::write(destination.join("status"), status.as_str().ok_or_else(|| fail("Expected Debian status text"))?)?;
    let recipe = decision(policy, "workerImage.recipe", Value::Null)?;
    fs::write(context.join("Containerfile"), recipe.as_str().ok_or_else(|| fail("Expected worker build recipe"))?)?;
    Ok(())
}

pub(crate) fn run(digest: &str) -> Result<()> {
    let policy = policy()?;
    decision(&policy, "workerImage.digest", json!(digest))?;
    let mut supervisor = Supervisor::new();
    handle_hangup();
    let podman = Podman::open()?;
    inspect_base(&policy, &podman, digest)?;
    let scratch = Scratch::create(&env::temp_dir(), "sourcery-worker-image-")?;
    let export = scratch.path().join("base.tar");
    export_base(&podman, digest, scratch.path(), &export)?;
    let work = Work::new(BUILD_DEADLINE);
    let context = scratch.path().join("context");
    let mut archive = ImageArchive::open(&work, archive::input(&export, BASE_LIMIT)?)?;
    stage(&policy, &work, &mut archive, &context)?;
    drop(archive);
    fs::remove_file(export)?;

    let iid = scratch.path().join("image.id");
    supervisor.run_until("Build offline worker image",
        podman.command().args(["build", "--pull=never", "--network=none", "--layers=false", "--platform=linux/amd64", "--iidfile"])
            .arg(&iid).arg("--file").arg(context.join("Containerfile")).arg(&context).stdout(Stdio::null()),
        Some(BUILD_DEADLINE))?;
    let mut output = String::new();
    archive::input(&iid, 1024)?.read_to_string(&mut output)?;
    let digest = output.trim_end_matches(['\r', '\n']);
    decision(&policy, "workerImage.digest", json!(digest))?;
    supervisor.check()?;
    println!("{digest}");
    Ok(())
}

#[cfg(test)]
#[test]
fn worker_image_admits_only_the_pinned_base_and_required_installed_packages() -> Result<()> {
    let policy = policy()?;
    let digest = format!("sha256:{}", "a".repeat(64));
    let expected = json!({"expected": digest, "observed": digest, "os": "linux", "arch": "amd64"});
    assert_eq!(decision(&policy, "workerImage.base", expected.clone())?, true);
    for (field, value) in [("observed", "latest"), ("os", "windows"), ("arch", "arm64")] {
        let mut crossed = expected.clone();
        crossed[field] = json!(value);
        assert!(decision(&policy, "workerImage.base", crossed).is_err());
    }
    let paragraph = |name: &str| format!(
        "Package: {name}\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:2.3-4+deb12u1\n\n");
    let required = ["libc6", "libstdc++6", "libgcc-s1"].map(paragraph).concat();
    let projected = format!("{}{required}", paragraph("unlisted"));
    let records = status_records(&projected)?;
    assert_eq!(decision(&policy, "workerImage.packageStatus", json!(records))?, required);
    for invalid in [required.replace("install ok installed", "deinstall ok config-files"),
        required.replace("amd64", "arm64"), format!("{required}{}", paragraph("libc6")),
        required.replace("1:2.3-4+deb12u1", "1 2")] {
        assert!(decision(&policy, "workerImage.packageStatus", json!(status_records(&invalid)?)).is_err());
    }
    assert!(status_records("Version: 1\n Version: 2").is_err());
    assert!(status_records("Version: 1\nVersion: 2").is_err());
    Ok(())
}
