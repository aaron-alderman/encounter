use crate::{Result, compat_value, fail, process::{Meter, Programme}};
use serde_json::Value;
use std::{collections::BTreeSet, io::{self, Read}};

pub(crate) fn run() -> Result<()> {
    let input = read_observation()?;
    let entry = "platformImports.verify";
    let policy = Programme::admit(&[include_str!("platform_import_closure.encounter").into()], entry,
        &BTreeSet::from(["kernel.invoke", "text.startsWith", "text.slice", "text.split", "path.resolvePosix",
            "record.fromEntries", "record.entries", "number.calculate", "value.sort", "value.type",
            "value.describe"]), &mut Meter::new(200_000))?;
    println!("{}", policy.run(entry, input, &mut Meter::new(40_000_000))?);
    Ok(())
}

pub(crate) fn audit_programme() -> Result<()> {
    let input = read_observation()?;
    let entry = "programmeCompletion.audit";
    let policy = Programme::admit(&[include_str!("programme_completion.encounter").into(),
        include_str!("knowledge_catalogue.encounter").into()], entry,
        &BTreeSet::from(["kernel.invoke", "value.type", "value.describe", "value.string", "text.trim",
            "text.join", "text.matches", "digest.sha256", "record.entries", "record.fromEntries",
            "record.put", "json.canonicalCompact", "value.sort"]), &mut Meter::new(200_000))?;
    let report = policy.run(entry, input, &mut Meter::new(40_000_000))?;
    println!("{}", compat_value::stringify(&report, &Value::Null)?);
    Ok(())
}

pub(crate) fn read_catalogue() -> Result<()> {
    let input = read_observation()?;
    let entry = "knowledgeCatalogue.read";
    let policy = Programme::admit(&[include_str!("knowledge_catalogue.encounter").into()], entry,
        &BTreeSet::from(["kernel.invoke", "json.canonicalCompact", "digest.sha256",
            "record.entries", "record.fromEntries", "record.put", "value.sort", "value.type",
            "number.calculate", "number.isNatural", "text.join", "text.lowerCase", "text.split"]),
        &mut Meter::new(200_000))?;
    let response = policy.run(entry, input, &mut Meter::new(40_000_000))?;
    println!("{}", compat_value::stringify(&response, &Value::Null)?);
    Ok(())
}

pub(crate) fn build_catalogue(operation: &str) -> Result<()> {
    let entry = match operation {
        "entry" => "catalogueBuild.entry",
        "create" => "catalogueBuild.create",
        "programme-entries" => "programmeCatalogue.entries",
        "coverage" => "catalogueBuild.coverage",
        _ => return Err(fail("Unsupported catalogue construction operation.")),
    };
    let input = read_observation()?;
    let policy = Programme::admit(&[include_str!("knowledge_catalogue.encounter").into(),
        include_str!("knowledge_catalogue_build.encounter").into(), include_str!("programme_catalogue.encounter").into()], entry,
        &BTreeSet::from(["kernel.invoke", "json.canonicalCompact", "digest.sha256", "record.entries",
            "record.fromEntries", "record.put", "value.sort", "value.type", "value.describe",
            "number.calculate", "text.trim", "text.matches"]), &mut Meter::new(200_000))?;
    let response = policy.run(entry, input, &mut Meter::new(80_000_000))?;
    println!("{}", compat_value::stringify(&response, &Value::Null)?);
    Ok(())
}

pub(crate) fn observation_ledger(operation: &str) -> Result<()> {
    let entry = match operation {
        "empty" => "mcpObservation.empty",
        "verify" => "mcpObservation.verify",
        "append" => "mcpObservation.append",
        "summarize" => "mcpObservation.summarize",
        "retention-policy" => "mcpObservation.retentionPolicy",
        _ => return Err(fail("Unsupported MCP observation ledger operation.")),
    };
    let input = read_bounded_observation(crate::mcp_observation_store::FRAME_LIMIT)?;
    let policy = observation_policy(&[entry])?;
    let response = policy.run(entry, input, &mut Meter::new(80_000_000))?;
    println!("{}", compat_value::stringify(&response, &Value::Null)?);
    Ok(())
}

pub(crate) fn catalogue_integration(operation: &str) -> Result<()> {
    let entry = match operation {
        "contract" => "catalogueIntegration.contract",
        "readiness" => "catalogueIntegration.readiness",
        "hook-evidence" => "catalogueIntegration.hookEvidence",
        "production" => "catalogueIntegration.production",
        _ => return Err(fail("Unsupported catalogue integration operation.")),
    };
    let input = read_bounded_observation(128 * 1024)?;
    let policy = Programme::admit(&[include_str!("knowledge_catalogue.encounter").into(),
        include_str!("knowledge_catalogue_integration.encounter").into()], entry,
        &BTreeSet::from(["kernel.invoke", "record.entries", "record.fromEntries", "record.put",
            "json.canonicalCompact", "digest.sha256", "value.describe", "value.type", "value.sort",
            "text.trim", "text.matches", "number.calculate"]), &mut Meter::new(200_000))?;
    let result = policy.run(entry, input, &mut Meter::new(5_000_000))?;
    println!("{}", compat_value::stringify(&result, &Value::Null)?);
    Ok(())
}

pub(super) fn observation_policy(entries: &[&str]) -> Result<Programme> {
    Programme::admit_entries(&[include_str!("knowledge_catalogue.encounter").into(),
        include_str!("mcp_observation.encounter").into()], entries,
        &BTreeSet::from(["kernel.invoke", "json.canonicalCompact", "digest.sha256",
            "record.entries", "record.fromEntries", "record.put", "value.sort", "value.type",
            "value.string", "value.describe", "number.calculate", "text.trim", "text.matches",
            "json.stringify", "text.utf8Length"]), &mut Meter::new(200_000))
}

fn read_observation() -> Result<Value> {
    read_bounded_observation(8 * 1024 * 1024)
}

pub(super) fn read_bounded_observation(limit: u64) -> Result<Value> {
    let mut bytes = Vec::new();
    io::stdin().lock().take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Platform observation exceeds its byte bound")); }
    let input: Value = serde_json::from_slice(&bytes)?;
    compat_value::external(&input)?;
    Ok(input)
}
