use crate::{Result, appdev_host_process::{Scratch, Supervisor, exchange_paths, rename_new_path},
    compat_value, fail, hosted_dependencies, http, package::observe_beneath, process::{Meter, Programme}, rel};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::{self, File, OpenOptions}, io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt}}, path::{Path, PathBuf}};

const PACKAGE: &str = "package.json";
const LOCK: &str = "package-lock.json";
const PROOF: &str = ".sourcery-production-input.json";
pub(super) const STAGE_PREFIX: &str = ".production-input-";
const LIMIT: usize = 2 * 1024 * 1024;

fn descriptor(file: &File) -> PathBuf { format!("/proc/self/fd/{}", file.as_raw_fd()).into() }

fn read(root: &File, path: &Path) -> Result<(Vec<u8>, Value)> {
    let observed = observe_beneath(root, path)?;
    let metadata = observed.metadata()?;
    if !metadata.is_file() || metadata.len() > LIMIT as u64 {
        return Err(fail("Expected bounded regular production release input"));
    }
    let mut bytes = Vec::new();
    File::open(descriptor(&observed))?.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT { return Err(fail("Production release input exceeds its byte bound")); }
    let value: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&value)?;
    Ok((bytes, value))
}

fn field<'a>(record: &'a Value, key: &str) -> Result<&'a str> {
    record[key].as_str().ok_or_else(|| fail(format!("Missing production release field {key}")))
}

fn absent(root: &Path, name: &str) -> Result<()> {
    match root.join(name).symlink_metadata() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(fail("Production release input outputs already exist")),
    }
}

pub(super) fn require_idle(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        http::check_interruption(false)?;
        if entry?.file_name().as_encoded_bytes().starts_with(STAGE_PREFIX.as_bytes()) {
            return Err(fail("Hosted release has an unfinished production input preparation"));
        }
    }
    Ok(())
}

fn stage(stage: &Path, name: &str, bytes: &str, mode: u32) -> Result<()> {
    if bytes.len() > LIMIT { return Err(fail("Production release output exceeds its byte bound")); }
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(stage.join(name))?;
    file.write_all(bytes.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn prepare(path: &Path) -> Result<Value> {
    let root = observe_beneath(&File::open("/")?, path.strip_prefix("/")?)?;
    if !root.metadata()?.is_dir() { return Err(fail("Production release root must be a physical directory")); }
    let root = File::open(descriptor(&root))?;
    if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let parent = descriptor(&root);
    require_idle(&parent)?;
    absent(&parent, LOCK)?;
    absent(&parent, PROOF)?;
    let (source_bytes, source) = read(&root, Path::new(PACKAGE))?;
    let (_, manifest) = read(&root, Path::new("runtime-dependencies.json"))?;
    let policy = Programme::admit_entries(&[include_str!("hosted_dependencies.encounter").to_owned()],
        &["dependency.releasePlan", "dependency.releaseInputs"],
        &BTreeSet::from(["text.matches", "value.sort", "record.fromEntries", "record.put",
            "json.stringify", "digest.sha256", "number.calculate"]), &mut Meter::new(300_000))?;
    let plan = policy.run("dependency.releasePlan", manifest, &mut Meter::new(2_000_000))?;
    let mut entries = plan.as_array().ok_or_else(|| fail("Missing planned production dependencies"))?.clone();
    for entry in &mut entries {
        http::check_interruption(false)?;
        let name = field(entry, "name")?;
        let (_, installed) = read(&root, &Path::new("node_modules").join(name).join(PACKAGE))?;
        let integrity = format!("sha512-{}", Base64::encode_string(&hex::decode(field(entry, "archiveSha512")?)?));
        entry["installed"] = installed;
        entry["integrity"] = json!(integrity);
    }
    let output = policy.run("dependency.releaseInputs", json!({
        "source":source,"sourcePackageSha256":rel::hash(&source_bytes),"entries":entries
    }), &mut Meter::new(16_000_000))?;
    let package = field(&output, "package")?;
    let lock = field(&output, "lockfile")?;
    let proof = field(&output, "proof")?;
    hosted_dependencies::validate_lock(serde_json::from_str(package)?, serde_json::from_str(lock)?)?;
    let scratch = Scratch::create(&parent, STAGE_PREFIX)?;
    let staged = scratch.path();
    let package_mode = observe_beneath(&root, Path::new(PACKAGE))?.metadata()?.mode() & 0o666;
    stage(staged, PACKAGE, package, package_mode)?;
    stage(staged, LOCK, lock, 0o644)?;
    stage(staged, PROOF, proof, 0o644)?;
    File::open(staged)?.sync_all()?;
    if read(&root, Path::new(PACKAGE))?.0 != source_bytes {
        return Err(fail("Production source package changed during preparation"));
    }
    http::check_interruption(false)?;
    rename_new_path(&staged.join(LOCK), &parent.join(LOCK))?;
    if let Err(error) = exchange_paths(&staged.join(PACKAGE), &parent.join(PACKAGE)) {
        fs::remove_file(parent.join(LOCK))?;
        root.sync_all()?;
        return Err(error);
    }
    if let Err(error) = rename_new_path(&staged.join(PROOF), &parent.join(PROOF)) {
        exchange_paths(&staged.join(PACKAGE), &parent.join(PACKAGE))?;
        fs::remove_file(parent.join(LOCK))?;
        root.sync_all()?;
        return Err(error);
    }
    root.sync_all()?;
    drop(scratch);
    root.sync_all()?;
    Ok(serde_json::from_str(proof)?)
}

pub(crate) fn run(path: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    let root = std::env::current_dir()?.join(path);
    println!("{}", serde_json::to_string_pretty(&prepare(&root)?)?);
    Ok(())
}
