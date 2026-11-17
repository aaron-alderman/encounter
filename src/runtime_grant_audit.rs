use crate::{Result, appdev_host_process::Supervisor, compat_value, fail, hosted_postgres::{JOURNAL_LIMIT, Journal, JournalTransaction}, http, nonce,
    process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::{self, Read}};

const INPUT_LIMIT: usize = 16 * 1024;

#[derive(Clone, Copy)]
pub(crate) enum Operation { Validate, Snapshot, Append }

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("runtime_grant_audit.encounter").to_owned()],
        &["grantAudit.state", "grantAudit.snapshot", "grantAudit.append", "grantAudit.retention"],
        &BTreeSet::from(["kernel.invoke", "json.canonical", "digest.sha256", "text.matches", "time.parseRfc3339",
            "record.entries", "record.fromEntries", "record.put", "number.isNatural", "number.calculate", "value.type"]),
        &mut Meter::new(200_000))
}

fn input(limit: usize) -> Result<Value> {
    let mut bytes = Vec::new();
    io::stdin().lock().take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err(fail("Runtime grant audit request exceeds its byte bound")); }
    let request = serde_json::from_slice(&bytes)?;
    compat_value::external(&request)?;
    Ok(request)
}

fn evaluate(operation: Operation, request: Value, state: Value, revision: Value) -> Result<Value> {
    let (entry, basis) = match operation {
        Operation::Validate => ("grantAudit.state", json!({"state":state,"rowRevision":revision})),
        Operation::Snapshot => ("grantAudit.snapshot", json!({"state":state,"rowRevision":revision})),
        Operation::Append => ("grantAudit.append", json!({"state":state,"rowRevision":revision,
            "event":request["event"],"maximumEvents":request["maximumEvents"],"occurredAt":request["occurredAt"],
            "eventId":format!("runtime-grant-audit.{}", nonce::uuid_v4()?)})),
    };
    policy()?.run(entry, basis, &mut Meter::new(250_000_000))
}

pub(crate) fn memory(operation: Operation) -> Result<()> {
    let mut request = input(JOURNAL_LIMIT)?;
    let state = request["state"].take();
    let revision = state["revision"].clone();
    let result = evaluate(operation, request, state, revision)?;
    if matches!(operation, Operation::Validate) { println!("true"); }
    else { println!("{result}"); }
    Ok(())
}

pub(crate) fn retention() -> Result<()> {
    policy()?.run("grantAudit.retention", input(INPUT_LIMIT)?, &mut Meter::new(10_000))?;
    println!("true");
    Ok(())
}

pub(crate) fn postgres(operation: Operation) -> Result<()> {
    let _signals = Supervisor::new();
    let result = postgres_transaction(operation, input(INPUT_LIMIT)?)?;
    http::check_interruption(false)?;
    println!("{result}");
    Ok(())
}

pub(crate) fn postgres_transaction(operation: Operation, mut request: Value) -> Result<Value> {
    let (journal, state) = JournalTransaction::begin(Journal::RuntimeGrantAudit, request["postgres"].take())?;
    let mut result = evaluate(operation, request, state, journal.revision())?;
    if matches!(operation, Operation::Append) {
        journal.write_successor(&result["state"])?;
        result = result["event"].take();
    }
    journal.commit()?;
    Ok(result)
}

pub(super) fn retain_grant_success(postgres: Value, operation: &str, outcome: &str, claims: &Value) -> Result<()> {
    retain_grant_event(postgres, json!({
        "operation": operation, "outcome": outcome, "consumerId": claims["consumerId"],
        "bindingKey": claims["bindingKey"], "grantId": claims["grantId"], "provider": claims["provider"],
        "denialCode": "none",
    }))
}

pub(super) fn retain_grant_event(postgres: Value, event: Value) -> Result<()> {
    postgres_transaction(Operation::Append, json!({
        "postgres": postgres, "maximumEvents": 10_000,
        "occurredAt": chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now())
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "event": event,
    })).map_err(|_| fail("runtime-resource-grant-audit-unavailable"))?;
    http::check_interruption(false)?;
    Ok(())
}
