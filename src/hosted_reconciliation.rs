use crate::{Result, appdev_host_process::Supervisor, compat_value, fail, http,
    hosted_private_fs::{PendingFile, make_directory, private_directory, read_private}, package::open_beneath,
    process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::{self, File}, io::{self, Read}, os::fd::AsRawFd, path::Path};

const MARKER: &str = ".sourcery-capability-resource.json";
const DATA: &str = "data";
const MARKER_LIMIT: usize = 65_536;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_reconciliation.encounter").to_owned()],
        &["reconcile.options", "reconcile.limit", "reconcile.targets", "reconcile.summary", "reconcile.retry", "reconcile.outcome",
            "storage.target", "storage.activatePlan", "storage.locatePlan", "storage.replay", "storage.access",
            "storage.grantBinding", "storage.tombstone", "storage.effect", "storage.observation", "storage.grant"],
        &BTreeSet::from(["kernel.invoke", "number.isNatural", "number.calculate", "value.describe", "text.matches", "text.match", "text.startsWith",
            "record.entries", "record.put", "json.canonical", "text.utf8Length", "digest.sha256"]),
        &mut Meter::new(100_000))
}

pub(crate) fn decision(operation: &str) -> Result<()> {
    let entry = match operation {
        "options" => "reconcile.options",
        "targets" => "reconcile.targets",
        "summary" => "reconcile.summary",
        "retry" => "reconcile.retry",
        "outcome" => "reconcile.outcome",
        _ => return Err(fail("Unsupported hosted reconciliation decision")),
    };
    println!("{}", evaluate(&policy()?, entry, request(8 * 1024)?)?);
    Ok(())
}

fn request(limit: usize) -> Result<Value> {
    let mut bytes = Vec::new();
    io::stdin().lock().take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err(fail("Hosted reconciliation input exceeded its bound")); }
    let input = serde_json::from_slice(&bytes)?;
    compat_value::external(&input)?;
    Ok(input)
}

fn evaluate(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(200_000))
}

fn directory(path: &Path) -> Result<File> {
    let root = File::open("/")?;
    private_directory(open_beneath(&root, path.strip_prefix("/")?)?)
}

fn read_marker(directory: &File) -> Result<Value> {
    let value = serde_json::from_slice(&read_private(directory, MARKER, MARKER_LIMIT)?)?;
    compat_value::external(&value)?;
    Ok(value)
}

fn child_directories(directory: &File) -> Result<fs::ReadDir> {
    Ok(fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?)
}

fn content_key(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn inventory(policy: &Programme, input: &Value) -> Result<Value> {
    let limit = evaluate(policy, "reconcile.limit", input["limit"].clone())?.as_u64()
        .ok_or_else(|| fail("Missing inventory target bound"))? as usize;
    let root = directory(Path::new(input["root"].as_str().ok_or_else(|| fail("Missing private inventory root"))?))?;
    let mut targets = Vec::new();
    for scope_entry in child_directories(&root)? {
        http::check_interruption(false)?;
        let scope_entry = scope_entry?;
        let scope_name = scope_entry.file_name();
        let Some(scope_hash) = scope_name.to_str().filter(|name| content_key(name)) else { continue; };
        if !scope_entry.file_type()?.is_dir() { continue; }
        let scope = private_directory(open_beneath(&root, Path::new(scope_hash))?)?;
        for resource_entry in child_directories(&scope)? {
            http::check_interruption(false)?;
            let resource_entry = resource_entry?;
            let resource_name = resource_entry.file_name();
            let Some(activation_hash) = resource_name.to_str().filter(|name| content_key(name)) else { continue; };
            if !resource_entry.file_type()?.is_dir() { continue; }
            let resource = private_directory(open_beneath(&scope, Path::new(activation_hash))?)?;
            let target = evaluate(policy, "storage.target", json!({"marker":read_marker(&resource)?,
                "scopeHash":scope_hash,"activationHash":activation_hash,"resourceRef":null}))?;
            if !target.is_null() { targets.push(target); }
            if targets.len() == limit { return Ok(json!(targets)); }
        }
    }
    Ok(json!(targets))
}

fn publish_marker(directory: &File, marker: &Value, replace: bool) -> Result<bool> {
    let mut bytes = compat_value::canonical_json(marker)?.into_bytes();
    bytes.push(b'\n');
    if bytes.len() > MARKER_LIMIT { return Err(fail("Self-hosted storage resource marker exceeds its byte bound")); }
    PendingFile::write(directory, MARKER, &bytes)?.publish(MARKER, replace)
}

fn key(plan: &Value, field: &str) -> Result<String> {
    plan[field].as_str().filter(|value| content_key(value)).map(str::to_owned)
        .ok_or_else(|| fail("Invalid native storage path component"))
}

fn root_path(input: &Value) -> Result<&Path> {
    input["root"].as_str().map(Path::new).ok_or_else(|| fail("Missing private storage root"))
}

fn activate(policy: &Programme, input: Value) -> Result<Value> {
    let path = root_path(&input)?.to_owned();
    let mut plan = evaluate(policy, "storage.activatePlan", input)?;
    let root = directory(&path)?;
    let scope_hash = key(&plan, "scopeHash")?;
    let activation_hash = key(&plan, "activationHash")?;
    let marker = plan["marker"].take();
    http::check_interruption(false)?;
    let scope = make_directory(&root, &scope_hash)?;
    let resource = make_directory(&scope, &activation_hash)?;
    let data = make_directory(&resource, DATA)?;
    data.sync_all()?;
    if !publish_marker(&resource, &marker, false)? {
        let retained = read_marker(&resource)?;
        evaluate(policy, "storage.replay", json!({"expected":marker,"retained":retained}))?;
    }
    resource.sync_all()?;
    scope.sync_all()?;
    root.sync_all()?;
    evaluate(policy, "storage.effect", marker)
}

fn retained(policy: &Programme, input: &Value, operation: &str) -> Result<(File, Value, std::path::PathBuf)> {
    let path = root_path(input)?;
    let plan = evaluate(policy, "storage.locatePlan", json!({"scope":input["scope"],"resourceRef":input["resourceRef"]}))?;
    let scope_hash = key(&plan, "scopeHash")?;
    let activation_hash = key(&plan, "activationHash")?;
    let root = directory(path)?;
    let scope = private_directory(open_beneath(&root, Path::new(&scope_hash))?)?;
    let resource = private_directory(open_beneath(&scope, Path::new(&activation_hash))?)?;
    let marker = evaluate(policy, "storage.access", json!({"operation":operation,"marker":read_marker(&resource)?,
        "scopeHash":scope_hash,"activationHash":activation_hash,"resourceRef":input["resourceRef"],"bindingKey":input["bindingKey"]}))?;
    private_directory(open_beneath(&resource, Path::new(DATA))?)?;
    Ok((resource, marker, path.join(scope_hash).join(activation_hash).join(DATA)))
}

pub(crate) fn storage(operation: &str) -> Result<()> {
    let _signals = Supervisor::new();
    let input = request(MARKER_LIMIT + 4096)?;
    let policy = policy()?;
    let result = match operation {
        "activate" => activate(&policy, input)?,
        "observe" => {
            let available = retained(&policy, &input, "observe").is_ok();
            evaluate(&policy, "storage.observation", json!(available))?
        }
        "unbind" => {
            let (resource, marker, _) = retained(&policy, &input, "unbind")?;
            let tombstone = evaluate(&policy, "storage.tombstone", marker)?;
            if !tombstone.is_null() { publish_marker(&resource, &tombstone, true)?; }
            resource.sync_all()?;
            evaluate(&policy, "storage.effect", json!({"resourceRef":input["resourceRef"],"status":"unbound"}))?
        }
        "resolve" => resolve_storage_grant(&policy, &input)?,
        "inventory" => inventory(&policy, &input)?,
        _ => return Err(fail("Unsupported hosted storage operation")),
    };
    http::check_interruption(false)?;
    println!("{result}");
    Ok(())
}

fn resolve_storage_grant(policy: &Programme, input: &Value) -> Result<Value> {
    evaluate(policy, "storage.grantBinding", input.clone())?;
    let (_, _, data) = retained(policy, input, "resolve")?;
    evaluate(policy, "storage.grant", json!({"resourceRef":input["resourceRef"],"root":data}))
}

pub(super) fn resolve_current_grant(root: &Value, scope: &Value, claims: &Value, binding: &Value) -> Result<Value> {
    resolve_storage_grant(&policy()?, &json!({
        "root":root, "scope":scope, "resourceRef":claims["resourceRef"], "boundResourceRef":binding["resourceRef"],
        "bindingKey":binding["bindingKey"], "status":binding["status"], "provider":binding["offer"]["provider"],
    }))
}
