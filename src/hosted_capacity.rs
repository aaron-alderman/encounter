use crate::{Result, appdev_host_process::Supervisor, compat_value, fail, hosted_postgres::{JOURNAL_LIMIT, Journal, JournalTransaction}, http,
    process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::{self, Read}};

const INPUT_LIMIT: usize = 256 * 1024;

fn request(limit: usize) -> Result<Value> {
    let mut bytes = Vec::new();
    io::stdin().lock().take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err(fail("Hosted capacity request exceeds its byte bound")); }
    let input = serde_json::from_slice(&bytes)?;
    compat_value::external(&input)?;
    if !input.is_object() { return Err(fail("Hosted capacity requires a request record")); }
    Ok(input)
}

fn evaluate(entry: &str, input: Value) -> Result<Value> {
    let policy = Programme::admit_entries(&[include_str!("hosted_capacity.encounter").to_owned()], &[entry],
        &BTreeSet::from(["kernel.invoke", "json.canonical", "digest.sha256", "text.matches", "text.startsWith",
            "record.entries", "record.fromEntries", "record.put", "list.take", "number.isNatural", "number.calculate",
            "value.type", "value.describe", "value.string", "value.groupTextPairs", "time.parseRfc3339", "time.formatUtc"]),
        &mut Meter::new(200_000))?;
    policy.run(entry, input, &mut Meter::new(200_000_000))
}

fn reply(result: Result<Value>) -> Result<()> {
    match result {
        Ok(value) => println!("{}", json!({"value":value})),
        Err(error) => {
            let message = error.to_string();
            let (code, message) = message.split_once('|').filter(|(code, _)| {
                *code == "type" || code.starts_with("hosted-capacity-")
            }).ok_or(error)?;
            println!("{}", json!({"code":code, "message":message}));
        }
    }
    Ok(())
}

pub(crate) fn decision(operation: &str) -> Result<()> {
    let entry = match operation {
        "options" => "capacity.options",
        "plan" => "capacity.plan",
        _ => return Err(fail("Unsupported hosted capacity decision")),
    };
    reply(evaluate(entry, request(INPUT_LIMIT)?))
}

fn journal_entry(operation: &str) -> Result<&'static str> {
    match operation {
        "read" => Ok("capacity.state"),
        "snapshot" => Ok("capacity.snapshot"),
        "reserve" => Ok("capacity.reserve"),
        "settle" => Ok("capacity.settle"),
        "reconcile" => Ok("capacity.reconcile"),
        _ => Err(fail("Unsupported hosted capacity journal operation")),
    }
}

pub(crate) fn memory(operation: &str) -> Result<()> {
    let mut input = request(JOURNAL_LIMIT)?;
    if input["state"].is_null() {
        input["state"] = serde_json::from_str(Journal::Capacity.initial())?;
    }
    input["rowRevision"] = input["state"]["revision"].clone();
    if operation == "validate" {
        return reply(evaluate("capacity.state", input).map(|_| json!(true)));
    }
    reply(evaluate(journal_entry(operation)?, input))
}

pub(crate) fn postgres(operation: &str) -> Result<()> {
    let entry = journal_entry(operation)?;
    let _signals = Supervisor::new();
    let result = postgres_transaction(entry, request(INPUT_LIMIT)?);
    http::check_interruption(false)?;
    reply(result)
}

fn postgres_transaction(entry: &str, mut input: Value) -> Result<Value> {
    let (journal, state) = JournalTransaction::begin(Journal::Capacity, input["postgres"].take())?;
    input["rowRevision"] = journal.revision();
    input["state"] = state;
    let mut result = evaluate(entry, input)?;
    if matches!(entry, "capacity.reserve" | "capacity.settle" | "capacity.reconcile") {
        if let Some(state) = result.get("state") {
            journal.write_successor(state)?;
        } else {
            journal.rollback()?;
            return Ok(result["value"].take());
        }
        result = result["value"].take();
    }
    journal.commit()?;
    Ok(result)
}


#[cfg(test)]
pub(super) fn verify_postgres_journal(postgres: Value) -> Result<()> {
    let scope = json!({"tenantId":"test-capacity"});
    let scope_hash = crate::rel::hash(&compat_value::canonical_json(&scope)?);
    let plan = json!({"action":"bind","planHash":"a".repeat(64),"activationId":"test.capacity",
        "bindingKey":"test.binding","scopeHash":scope_hash,"consequences":{"currency":"AUD","monthlyCost":20}});
    let reserve = || postgres_transaction("capacity.reserve", json!({"postgres":postgres,"plan":plan,"scope":scope,
        "policy":{"policyId":"test.capacity","currency":"AUD","monthlyLimit":50,"maxActiveBindings":2},
        "now":0,"reservationTtlMs":30000,"maximumSettledReservations":100}));
    let snapshot = || postgres_transaction("capacity.snapshot", json!({"postgres":postgres}));
    let first = reserve()?;
    assert_eq!(first["reservedIncrement"], 20);
    assert_eq!(reserve()?, first);
    assert_eq!(snapshot()?["revision"], 1);
    let settled = postgres_transaction("capacity.settle", json!({"postgres":postgres,"reservation":first,
        "plan":plan,"scope":scope,"resourceRef":"test.resource","now":1}))?;
    assert_eq!(settled["status"], "settled");
    assert_eq!(snapshot()?["activeAllocations"], 1);
    assert_eq!(snapshot()?["revision"], 2);
    Ok(())
}
