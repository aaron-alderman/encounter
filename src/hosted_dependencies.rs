use crate::{Result, appdev_host_process::{Scratch, Supervisor, rename_new_path}, archive::{self, Modes, Work},
    command_sources::Sources, fail, http_client, process::{Meter, Programme}};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use std::{collections::BTreeSet, fs::{self, File}, io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{PermissionsExt, symlink}, path::{Component, Path, PathBuf}, time::Duration};

const DOWNLOAD_LIMIT: usize = 8 * 1024 * 1024;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_dependencies.encounter").to_owned(), include_str!("hosted_release_identity.encounter").to_owned()],
        &["dependency.lock", "dependency.archive", "dependency.member", "dependency.package"],
        &BTreeSet::from(["kernel.invoke", "text.matches", "text.replace", "text.split", "text.join"]), &mut Meter::new(5_000_000))
}

fn decide(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(5_000_000))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| fail(format!("Missing locked dependency field {key}")))
}

fn metadata(path: &Path) -> Result<Value> {
    let mut bytes = Vec::new();
    archive::input(path, 2_097_152)?.take(2_097_153).read_to_end(&mut bytes)?;
    if bytes.len() > 2_097_152 { return Err(fail("Locked dependency metadata exceeded its byte limit")); }
    let value: Value = serde_json::from_slice(&bytes)?;
    if !value.is_object() { return Err(fail("Expected a locked dependency metadata object")); }
    Ok(value)
}

fn leaf(name: &str) -> &str { name.rsplit('/').next().unwrap_or_default() }

pub(super) fn validate_lock(manifest: Value, lock: Value) -> Result<Value> {
    plan_documents(&policy()?, manifest, lock)
}

fn plan(policy: &Programme, root: &Path) -> Result<Value> {
    plan_documents(policy, metadata(&root.join("package.json"))?, metadata(&root.join("package-lock.json"))?)
}

fn plan_documents(policy: &Programme, manifest: Value, lock: Value) -> Result<Value> {
    let empty = json!({});
    let declared = manifest.get("dependencies").unwrap_or(&empty);
    let packages = lock["packages"].as_object().ok_or_else(|| fail("Expected production lockfile packages"))?;
    let base = packages.get("").ok_or_else(|| fail("Expected the production lockfile root package"))?;
    let dependencies = declared.as_object().ok_or_else(|| fail("Expected exact production dependencies"))?;
    if dependencies.len() > 128 { return Err(fail("Production dependency count exceeded its limit")); }
    let mut records = Vec::new();
    for (name, version) in dependencies {
        let entry = &lock["packages"][format!("node_modules/{name}")];
        records.push(json!({"name":name,"leaf":leaf(name),"version":version.as_str().unwrap_or_default(),
            "lockedVersion":entry["version"],"resolved":entry["resolved"],"integrity":entry["integrity"].as_str().unwrap_or_default(),
            "bin":entry["bin"],"fields":entry.as_object().is_some_and(|fields| fields.keys().all(|key|
                matches!(key.as_str(), "version"|"resolved"|"integrity"|"license"|"bin"|"engines")))}));
    }
    let matches = base.get("dependencies").unwrap_or(&empty) == declared && base["name"] == manifest["name"] && base["version"] == manifest["version"];
    let flat = ["devDependencies", "optionalDependencies", "peerDependencies", "workspaces"].iter().all(|key| manifest.get(key).is_none() && base.get(key).is_none());
    decide(policy, "dependency.lock", json!({"version":lock["lockfileVersion"],"matches":matches,"lockedCount":packages.len()-1,
        "flat":flat,"dependencies":records}))
}

fn download(url: &str) -> Result<Vec<u8>> {
    if !url.starts_with("https://registry.npmjs.org/") { return Err(fail("Expected the admitted npm registry endpoint")); }
    let response = http_client::send(http_client::Request { url, method:"GET", headers:&[], body:None,
        timeout:Duration::from_secs(20), connect_timeout:Duration::from_secs(5), limit:DOWNLOAD_LIMIT,
        resolve:None, trust_anchor:None, restoring:false })?;
    if response.status != 200 { return Err(fail("Production dependency registry did not return the locked archive")); }
    Ok(response.body)
}

fn directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn link_bin(modules: &Path, package: &str, bin: &str, target: &str) -> Result<()> {
    let path = Path::new(target);
    let mut parts = path.components();
    if bin.is_empty() || !bin.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)) || matches!(bin, "." | "..")
        || path.is_absolute() || !parts.clone().all(|part| matches!(part, Component::Normal(_) | Component::CurDir)) || parts.next().is_none() {
        return Err(fail("Production dependency binary has an unsafe path"));
    }
    let full = modules.join(package).join(path);
    let metadata = full.symlink_metadata()?;
    if !metadata.is_file() { return Err(fail("Production dependency binary must be a regular file")); }
    fs::set_permissions(&full, fs::Permissions::from_mode(metadata.permissions().mode() | 0o111))?;
    let binaries = modules.join(".bin");
    if !binaries.exists() { directory(&binaries)?; }
    let mut relative = PathBuf::from("..").join(package);
    relative.extend(path.components().filter(|component| matches!(component, Component::Normal(_))));
    symlink(relative, binaries.join(bin))?;
    Ok(())
}

fn populate(root: &Path, mut fetch: impl FnMut(&str) -> Result<Vec<u8>>) -> Result<usize> {
    if !root.is_absolute() || root.canonicalize()? != root { return Err(fail("Expected a physical production dependency stage")); }
    let parent = Sources::open_physical(root)?.root()?;
    let target = root.join("node_modules");
    if target.symlink_metadata().is_ok() { return Err(fail("Production dependency destination already exists")); }
    let policy = policy()?;
    let plan = plan(&policy, root)?;
    let entries = plan.as_array().ok_or_else(|| fail("Expected admitted production dependencies"))?;
    let stage = Scratch::create(root, ".locked-dependencies-")?;
    let modules = stage.path().join("node_modules");
    directory(&modules)?;
    let work = Work::new(Duration::from_secs(120));
    for (index, entry) in entries.iter().enumerate() {
        work.check()?;
        let name = field(entry,"name")?;
        let bytes = fetch(field(entry,"url")?)?;
        if bytes.len() > DOWNLOAD_LIMIT { return Err(fail("Production dependency archive exceeded its byte limit")); }
        let integrity = format!("sha512-{}", Base64::encode_string(&Sha512::digest(&bytes)));
        decide(&policy, "dependency.archive", json!({"expected":entry["integrity"],"observed":integrity}))?;
        let mut file = archive::create(&stage.path().join(format!("{index}.tar.gz")))?;
        file.write_all(&bytes)?;
        file.seek(SeekFrom::Start(0))?;
        if let Some((scope, _)) = name.split_once('/') {
            let scope = modules.join(scope);
            if !scope.exists() { directory(&scope)?; }
        }
        let installed = modules.join(name);
        directory(&installed)?;
        archive::unpack(&work, file, &installed, Modes::Dependency, |name, directory| {
            let path = decide(&policy, "dependency.member", json!({"path":name,"directory":directory}))?;
            path.as_str().map(str::to_owned).ok_or_else(|| fail("Expected an admitted dependency member"))
        }, |_, _| Ok(()))?;
        let info = metadata(&installed.join("package.json"))?;
        let flat = ["dependencies", "optionalDependencies", "peerDependencies", "bundledDependencies", "bundleDependencies"]
            .iter().all(|key| info.get(key).is_none_or(|value| value.as_object().is_some_and(|fields| fields.is_empty())
                || value.as_array().is_some_and(|items| items.is_empty())));
        decide(&policy,"dependency.package",json!({"name":info["name"],"version":info["version"],"bin":info["bin"],"flat":flat,
            "expectedName":name,"expectedVersion":entry["version"],"expectedBin":entry["bin"]}))?;
        match &info["bin"] {
            Value::Null => {}
            Value::String(path) => link_bin(&modules, name, leaf(name), path)?,
            Value::Object(bins) => for (bin, path) in bins {
                link_bin(&modules, name, bin, path.as_str().ok_or_else(|| fail("Expected a dependency binary path"))?)?;
            },
            _ => return Err(fail("Expected production dependency binary metadata")),
        }
    }
    archive::sync_directories(&work, &modules)?;
    File::open(stage.path())?.sync_all()?;
    work.check()?;
    rename_new_path(&modules, &target)?;
    if let Err(error) = parent.sync_all().map_err(Into::into).and_then(|()| work.check()) {
        rename_new_path(&target, &modules)?;
        parent.sync_all()?;
        return Err(error);
    }
    Ok(entries.len())
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", json!({"status":"populated","packageCount":populate_locked(root)?}));
    Ok(())
}

pub(super) fn populate_locked(root: &Path) -> Result<usize> { populate(root, download) }

#[cfg(test)]
#[test]
fn locked_population_checks_registry_archive_and_binary_links_before_publication() -> Result<()> {
    use flate2::{Compression, write::GzEncoder};
    let fixture = Scratch::create(&std::env::temp_dir(), "locked-dependencies-test-")?;
    let root = fixture.path();
    let name = "sample";
    let version = "1.2.3";
    let bin = json!({"sample":"bin/sample"});
    let package = serde_json::to_vec(&json!({"name":name,"version":version,"bin":bin,
        "scripts":{"postinstall":"exit 4"}}))?;
    let mut archive = GzEncoder::new(Vec::new(), Compression::default());
    for (name, body) in [("package/package.json", package.as_slice()), ("package/bin/sample", b"#!/usr/bin/env node\n")] {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000644");
        header[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
        header[154] = 0;
        archive.write_all(&header)?;
        archive.write_all(body)?;
        archive.write_all(&[0;512][..(512-body.len()%512)%512])?;
    }
    archive.write_all(&[0;1024])?;
    let archive = archive.finish()?;
    let integrity = format!("sha512-{}", Base64::encode_string(&Sha512::digest(&archive)));
    let root_package = json!({"name":"fixture","version":"1.0.0","dependencies":{"sample":version}});
    fs::write(root.join("package.json"), serde_json::to_vec(&root_package)?)?;
    let registry = "https://registry.npmjs.org/sample/-/sample-1.2.3.tgz";
    let write_lock = |url| -> Result<()> {
        fs::write(root.join("package-lock.json"), serde_json::to_vec(&json!({"lockfileVersion":3,
            "packages":{"":root_package,"node_modules/sample":{"version":version,"resolved":url,"integrity":integrity,"bin":bin}}}))?)?;
        Ok(())
    };
    write_lock("https://example.invalid/sample.tgz")?;
    assert!(populate(root, |_| panic!("unadmitted URL reached transport")).unwrap_err().to_string().contains("registry"));
    write_lock(registry)?;
    assert!(populate(root, |_| Ok(b"changed".to_vec())).unwrap_err().to_string().contains("SHA-512"));
    assert!(!root.join("node_modules").exists());
    assert_eq!(populate(root, |url| { assert_eq!(url, registry); Ok(archive.clone()) })?, 1);
    assert_eq!(fs::read_link(root.join("node_modules/.bin/sample"))?, Path::new("../sample/bin/sample"));
    assert_eq!(fs::metadata(root.join("node_modules/sample/bin/sample"))?.permissions().mode() & 0o111, 0o111);
    assert!(populate(root, |_| panic!("existing view reached transport")).is_err());
    Ok(())
}
