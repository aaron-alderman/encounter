use crate::{Result, appdev_host_process::Supervisor, compat_value, fail, http,
    hosted_private_fs::{PendingFile, make_directory, make_directory_entry, private_directory, read_private},
    package::open_beneath, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, io::{self, Read}, os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path}};

const MARKER: &str = ".sourcery-workspace.json";
const MARKER_LIMIT: usize = 8 * 1024;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_workspace_storage.encounter").to_owned()],
        &["workspaceStorage.rootPlan", "workspaceStorage.fileSystem", "workspaceStorage.durability",
            "workspaceStorage.allocation", "workspaceStorage.retained", "workspaceStorage.namespace",
            "workspaceStorage.namespacePath", "workspaceStorage.invalidNamespace"],
        &BTreeSet::from(["kernel.invoke", "value.type", "value.string", "text.matches", "text.startsWith", "text.slice",
            "path.resolvePosix", "digest.sha256", "json.stringify", "number.calculate"]), &mut Meter::new(100_000))
}

fn evaluate(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(200_000))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field].as_str().ok_or_else(|| fail("Invalid hosted workspace input or policy result"))
}

fn allowed_directory(path: &Path) -> Result<File> {
    let mut current = File::open("/")?;
    for part in path.strip_prefix("/")?.components() {
        http::check_interruption(false)?;
        let Component::Normal(name) = part else { return Err(fail("Invalid private state root path")); };
        let next = match open_beneath(&current, Path::new(name)) {
            Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => {
                make_directory_entry(&current, name.to_str().ok_or_else(|| fail("Expected a UTF-8 private state root"))?)?;
                open_beneath(&current, Path::new(name))
            }
            result => result,
        }.map_err(|_| fail("Self-hosted workspace allowed root must be a real directory."))?;
        if !next.metadata()?.is_dir() { return Err(fail("Self-hosted workspace allowed root must be a real directory.")); }
        current = next;
    }
    Ok(current)
}

fn durability(policy: &Programme, input: Value) -> Result<Value> {
    let plan = evaluate(policy, "workspaceStorage.rootPlan", input)?;
    let allowed = allowed_directory(Path::new(text(&plan, "allowedRoot")?))?;
    let child = text(&plan, "child")?;
    make_directory_entry(&allowed, child)?;
    let root = private_directory(open_beneath(&allowed, Path::new(child))
        .map_err(|_| fail("Self-hosted workspace root must be a real directory."))?)?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(root.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let kind = unsafe { stats.assume_init() }.f_type;
    evaluate(policy, "workspaceStorage.fileSystem", json!(kind))?;
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| fail(error.to_string()))?;
    let probe = PendingFile::write(&root, ".durability-probe", &bytes)?;
    root.sync_all()?;
    let reopened = probe.read(bytes.len())? == bytes;
    probe.remove()?;
    root.sync_all()?;
    allowed.sync_all()?;
    evaluate(policy, "workspaceStorage.durability", json!({"root":plan["root"],
        "fileSystemType":kind,"device":root.metadata()?.dev().to_string(),"reopened":reopened}))
}

fn allocation(policy: &Programme, mut input: Value, provision: bool, create_root: bool) -> Result<Value> {
    let root_path = input["root"].take();
    let root_path = Path::new(root_path.as_str().ok_or_else(|| fail("Expected an absolute hosted workspace root"))?);
    let operation = if provision { "provision" } else { "resolve" };
    input["operation"] = json!(operation);
    let mut plan = evaluate(policy, "workspaceStorage.allocation", input)?;
    let mut identity = plan["identity"].take();
    let namespace = text(&identity, "storageNamespace")?.to_owned();
    let expected = text(&plan, "marker")?;
    if expected.len() > MARKER_LIMIT { return Err(fail("Workspace marker exceeds its byte bound")); }
    let root = private_directory(if create_root {
        if root_path == Path::new("/") || root_path.components().collect::<std::path::PathBuf>().as_os_str() != root_path.as_os_str() {
            return Err(fail("Expected a canonical development workspace root"));
        }
        allowed_directory(root_path)?
    } else {
        open_beneath(&File::open("/")?, root_path.strip_prefix("/")?)?
    })?;
    let mut directories = vec![root];
    for component in Path::new(&namespace).components() {
        http::check_interruption(false)?;
        let Component::Normal(name) = component else { return Err(fail("Invalid workspace path component")); };
        let parent = directories.last().ok_or_else(|| fail("Missing private workspace directory"))?;
        let directory = if provision {
            make_directory(parent, name.to_str().ok_or_else(|| fail("Expected a UTF-8 workspace component"))?)?
        } else {
            private_directory(open_beneath(parent, Path::new(name))?)?
        };
        directories.push(directory);
    }
    let target = directories.last().ok_or_else(|| fail("Missing workspace allocation target"))?;
    if !provision || !PendingFile::write(target, MARKER, expected.as_bytes())?.publish(MARKER, false)? {
        let observed = read_private(target, MARKER, MARKER_LIMIT)?;
        evaluate(policy, "workspaceStorage.retained", json!({"operation":operation,"expected":expected,
            "observed":std::str::from_utf8(&observed)?}))?;
    }
    if provision {
        for directory in directories.iter().rev() { directory.sync_all()?; }
    }
    identity["root"] = json!(root_path.join(namespace));
    Ok(identity)
}

pub(super) fn prove(root: &Path, allowed_root: &Path) -> Result<Value> {
    durability(&policy()?, json!({"root": root, "allowedRoot": allowed_root}))
}

pub(super) fn resolve(root: &Path, mut target: Value) -> Result<Value> {
    target["root"] = json!(root);
    allocation(&policy()?, target, false, false)
}

pub(crate) fn run(operation: &str) -> Result<()> {
    let _signals = Supervisor::new();
    let mut bytes = Vec::new();
    let limit = if operation == "invalid-namespace" { 1024 * 1024 } else { 16384 };
    io::stdin().lock().take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Hosted workspace input exceeds its byte bound")); }
    let input: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&input)?;
    if !input.is_object() { return Err(fail("Expected a hosted workspace request record")); }
    let policy = policy()?;
    let result = match operation {
        "durability" => durability(&policy, input)?,
        "provision" => allocation(&policy, input, true, false)?,
        "provision-development" => allocation(&policy, input, true, true)?,
        "resolve" => allocation(&policy, input, false, false)?,
        "namespace" => evaluate(&policy, "workspaceStorage.namespacePath", input)?,
        "check-namespace" => evaluate(&policy, "workspaceStorage.namespace", input)?,
        "invalid-namespace" => policy.run("workspaceStorage.invalidNamespace", input["workspaces"].clone(),
            &mut Meter::new(4_000_000))?,
        _ => return Err(fail("Unsupported hosted workspace storage operation")),
    };
    http::check_interruption(false)?;
    println!("{result}");
    Ok(())
}

#[cfg(test)]
#[test]
fn workspace_durability_policy_refuses_memory_filesystems() -> Result<()> {
    let policy = policy()?;
    for kind in [0x01021994_u64, 0x858458f6] {
        assert!(evaluate(&policy, "workspaceStorage.fileSystem", json!(kind)).unwrap_err()
            .to_string().contains("non-memory filesystem"));
    }
    assert_eq!(evaluate(&policy, "workspaceStorage.fileSystem", json!(0xef53))?, true);
    Ok(())
}
