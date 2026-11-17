use crate::{Result, compat_value, fail, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, io::{self, Read}, os::unix::fs::MetadataExt, path::Path};

pub(crate) fn run(operation: &str) -> Result<()> {
    let mut bytes = Vec::new();
    io::stdin().lock().take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 { return Err(fail("Hosted launch configuration exceeds its input limit")); }
    let request: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&request)?;
    let response = if operation == "claimipedia-handoff" { claimipedia_handoff(request)? }
        else if operation == "local-ssh-mcp" { local_ssh_mcp(request)? }
        else { evaluate(operation, request)? };
    println!("{response}");
    Ok(())
}

fn local_ssh_mcp(request: Value) -> Result<Value> {
    let path = Path::new(request["file"].as_str().ok_or_else(|| fail("Expected an SSH MCP verifier file path"))?);
    let file = crate::package::open_artifact(&File::open("/")?, path.strip_prefix("/")?)?;
    let metadata = file.metadata()?;
    if ![0, unsafe { libc::geteuid() }].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(fail("SSH MCP verifier file is outside service custody"));
    }
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 { return Err(fail("SSH MCP verifier file exceeds its byte bound")); }
    let config: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&config)?;
    evaluate("local-ssh-mcp", json!({"config":config, "port":request["port"]}))
}

fn claimipedia_handoff(request: Value) -> Result<Value> {
    let policy = Programme::admit_entries(&[include_str!("hosted_launch_config.encounter").to_owned()],
        &["hostedLaunch.claimipediaHandoff", "hostedLaunch.claimipediaSecret"],
        &BTreeSet::from(["text.trim", "text.replace", "text.matches", "text.startsWith", "number.calculate"]),
        &mut Meter::new(200_000))?;
    let mut meter = Meter::new(800_000);
    let plan = policy.run("hostedLaunch.claimipediaHandoff", request, &mut meter)?;
    if plan.is_null() { return Ok(plan); }
    let path = Path::new(plan["secretFile"].as_str().ok_or_else(|| fail("Missing handoff secret path"))?);
    let relative = path.strip_prefix("/")?;
    let file = crate::package::open_artifact(&File::open("/")?, relative)
        .map_err(|_| fail("Cannot open the protected Claimipedia handoff secret file"))?;
    let metadata = file.metadata()?;
    if ![0, unsafe { libc::getuid() }].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(fail("Claimipedia handoff secret file is outside service custody"));
    }
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 { return Err(fail("Claimipedia handoff secret exceeds its byte bound")); }
    let secret = String::from_utf8(bytes).map_err(|_| fail("Claimipedia handoff secret must be UTF-8"))?;
    policy.run("hostedLaunch.claimipediaSecret", json!({"plan":plan,"secret":secret}), &mut meter)
}

pub(super) fn production_claimipedia_handoff() -> Result<Value> {
    let request = json!({
        "endpoint": std::env::var("SOURCERY_HOSTED_CLAIMIPEDIA_HANDOFF_URL").unwrap_or_default(),
        "publicOrigin": std::env::var("SOURCERY_HOSTED_CLAIMIPEDIA_PUBLIC_ORIGIN").unwrap_or_default(),
        "secretFile": std::env::var("SOURCERY_HOSTED_CLAIMIPEDIA_HANDOFF_SECRET_FILE").unwrap_or_default(),
    });
    if serde_json::to_vec(&request)?.len() > 65_536 {
        return Err(fail("Hosted launch configuration exceeds its input limit"));
    }
    compat_value::external(&request)?;
    claimipedia_handoff(request)
}

pub(super) fn production_operations() -> Result<Value> {
    let settings = [
        "SOURCERY_OPERATIONS_SHADOW_ENABLED",
        "SOURCERY_TIMESHEET_REVISION_SHA256",
        "SOURCERY_OPERATIONS_SHADOW_INTERVAL_MS",
        "SOURCERY_OPERATIONS_MCP_ENABLED",
    ].into_iter().map(|key| (key.to_owned(), json!(std::env::var(key).unwrap_or_default())));
    evaluate("operations", Value::Object(settings.collect()))
}

pub(super) fn production_authority() -> Result<Value> {
    let settings = [
        "OIDC_PROVIDERS", "MANAGED_DOMAIN_ADMISSIONS", "MASTER_KEY_BASE64",
        "BASE_DOMAIN", "OIDC_AUDIENCE", "BROWSER_LOGIN_PATH",
    ].into_iter().map(|suffix| {
        let key = format!("SOURCERY_HOSTED_{suffix}");
        let value = json!(std::env::var(&key).unwrap_or_default());
        (key, value)
    });
    let request = Value::Object(settings.collect());
    if serde_json::to_vec(&request)?.len() > 65_536 {
        return Err(fail("Hosted launch configuration exceeds its input limit"));
    }
    compat_value::external(&request)?;
    evaluate("authority", request)
}

pub(super) fn host_environment() -> serde_json::Map<String, Value> {
    [
        "STATE_ROOT", "BIND_HOST", "TRUST_PROXY", "ALLOW_INSECURE_HTTP", "DEPLOYMENT_PROFILE",
        "AUTHORING_REQUEST_JOURNAL_STORAGE", "PRODUCTION_MODULE", "SOURCE_ROOT", "PORT", "REQUEST_TIMEOUT_MS",
        "AUTHORING_WORKER_TIMEOUT_MS", "AUTHORING_WORKER_MAXIMUM_RESPONSE_BYTES", "ENVIRONMENT_WORKER_INTERVAL_MS",
        "ENVIRONMENT_WORKER_SWEEP_LIMIT",
    ].into_iter().map(|name| {
        let key = format!("SOURCERY_HOSTED_{name}");
        let value = json!(std::env::var(&key).unwrap_or_default());
        (key, value)
    }).collect()
}

pub(super) fn evaluate(operation: &str, request: Value) -> Result<Value> {
    let entry = match operation {
        "config" => "hostedLaunch.config",
        "operations" => "hostedLaunch.operations",
        "operations-shadow" => "hostedLaunch.operationsShadow",
        "operations-mcp" => "hostedLaunch.operationsMcp",
        "startup-readiness" => "hostedLaunch.startupReadiness",
        "production-readiness" => "hostedLaunch.productionReadiness",
        "authority" => "hostedLaunch.authorityConfig",
        "oidc" => "hostedOidc.configuration",
        "environment-sweep" => "hostedLaunch.environmentSweep",
        "environment-worker-config" => "hostedLaunch.environmentWorkerConfig",
        "local-mcp-port" => "hostedLaunch.localMcpPort",
        "local-ssh-mcp" => "hostedLaunch.localSshMcp",
        "timesheet-url" => "hostedLaunch.timesheetUrl",
        _ => return Err(fail("Unsupported hosted launch configuration operation")),
    };
    let mut sources = vec![include_str!("hosted_launch_config.encounter").to_owned()];
    if matches!(operation, "authority" | "oidc") {
        sources.push(include_str!("hosted_oidc.encounter").to_owned());
    }
    let policy = Programme::admit(
        &sources, entry,
        &BTreeSet::from(["kernel.invoke", "path.resolvePosix", "text.trim", "text.matches", "text.startsWith",
            "number.parse", "number.isNatural", "number.calculate", "record.put", "json.parse", "value.type",
            "text.lowerCase", "text.slice", "value.describe", "record.entries"]), &mut Meter::new(200_000))?;
    policy.run(entry, request, &mut Meter::new(800_000))
}
