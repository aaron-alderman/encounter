use crate::{Result, appdev_host_process::Supervisor, compat_value, fail, hosted_private_fs::{PendingFile,
    missing, optional_json, owned_file_parent}, http, platform_import_closure::{observation_policy,
    read_bounded_observation}, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{fs::File, io, os::fd::AsRawFd, path::Path,
    thread, time::{Duration, Instant}};

pub(super) const FRAME_LIMIT: u64 = 8 * 1024 * 1024 + 512 * 1024;
// The retained JSON is indented, whereas the policy limits compact UTF-8.
const FILE_LIMIT: usize = 32 * 1024 * 1024;

fn lock(directory: &File, wait: bool) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        http::check_interruption(false)?;
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 { return Ok(()); }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock { return Err(error.into()); }
        if !wait || Instant::now() >= deadline {
            return Err(fail("Concurrent observation ledger write is already in progress."));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn observed_time(value: &Value) -> Result<i64> {
    use chrono::{DateTime, NaiveDate};
    let text = value.as_str().ok_or_else(|| fail("Expected a retained observation timestamp"))?;
    if let Ok(time) = DateTime::parse_from_rfc3339(text).or_else(|_| DateTime::parse_from_rfc2822(text)) {
        return Ok(time.timestamp_millis());
    }
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        if let Some(time) = date.and_hms_opt(0, 0, 0) { return Ok(time.and_utc().timestamp_millis()); }
    }
    Err(fail("Unsupported observation timestamp; explicit archive or migration is required"))
}

fn check(policy: &Programme, meter: &mut Meter, request: &Value, ledger: &Value) -> Result<()> {
    let observations = ledger["observations"].as_array().ok_or_else(|| fail("Expected retained observation entries"))?;
    let times = observations.iter().map(|item| observed_time(&item["observedAt"])).collect::<Result<Vec<_>>>()?;
    policy.run("mcpObservation.checkRetention", json!({
        "ledger": ledger, "catalogueHash":request["catalogueHash"], "policy":request["policy"], "times":times,
    }), meter)?;
    Ok(())
}

fn transaction(operation: &str, file: &Path, request: &Value) -> Result<Value> {
    let name = file.file_name().and_then(|name| name.to_str()).ok_or_else(|| fail("Expected a named observation ledger"))?;
    let directory = match owned_file_parent(file, operation != "load") {
        Ok(directory) => directory,
        Err(error) if operation == "load" && missing(error.as_ref()) => return Ok(Value::Null),
        Err(error) => return Err(error),
    };
    if operation != "load" { lock(&directory, operation == "initialize")?; }
    let current = optional_json(&directory, name, FILE_LIMIT)?;
    let policy = observation_policy(&["mcpObservation.checkRetention", "mcpObservation.empty", "mcpObservation.compareAndSwap"])?;
    let mut meter = Meter::new(120_000_000);
    if let Some(ledger) = &current {
        check(&policy, &mut meter, request, ledger)?;
    }
    let ledger = match operation {
        "load" => return Ok(current.unwrap_or(Value::Null)),
        "initialize" => {
            if let Some(ledger) = &current { return Ok(ledger.clone()); }
            policy.run("mcpObservation.empty", json!({
                "catalogueHash":request["catalogueHash"], "retainedAt":request["retainedAt"],
            }), &mut meter)?
        }
        "retain" => {
            policy.run("mcpObservation.compareAndSwap", json!({
                "expected":request["expectedLedgerHash"], "current":current.as_ref().map(|ledger| &ledger["ledgerHash"]),
            }), &mut meter)?;
            request["ledger"].clone()
        }
        _ => return Err(fail("Unsupported observation ledger storage operation")),
    };
    check(&policy, &mut meter, request, &ledger)?;
    let bytes = compat_value::stringify(&ledger, &json!(2))? + "\n";
    if bytes.len() > FILE_LIMIT { return Err(fail("Observation ledger file exceeds its byte bound")); }
    if !PendingFile::write(&directory, ".mcp-observation", bytes.as_bytes())?.publish(name, current.is_some())? {
        return Err(fail("Observation ledger appeared during initialization; reload before retrying."));
    }
    Ok(ledger)
}

pub(crate) fn run(operation: &str, file: &Path) -> Result<()> {
    if !matches!(operation, "load" | "initialize" | "retain") || !file.is_absolute() {
        return Err(fail("Expected a fixed observation storage operation and absolute ledger path"));
    }
    let _signals = Supervisor::new();
    let request = read_bounded_observation(FRAME_LIMIT)?;
    let result = transaction(operation, file, &request)?;
    println!("{}", compat_value::stringify(&result, &Value::Null)?);
    Ok(())
}
