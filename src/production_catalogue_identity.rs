use crate::{Result, appdev_host_process::Supervisor, compat_value, fail,
    hosted_private_fs::{PendingFile, missing, optional_json, owned_file_parent},
    platform_import_closure::read_bounded_observation, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

pub(crate) fn run(file: &Path) -> Result<()> {
    let name = file.file_name().and_then(|name| name.to_str())
        .ok_or_else(|| fail("Expected a named catalogue identity file"))?;
    let _signals = Supervisor::new();
    let request = read_bounded_observation(1024 * 1024)?;
    let policy = Programme::admit_entries(&[include_str!("knowledge_catalogue.encounter").into(),
        include_str!("production_catalogue_identity.encounter").into()],
        &["productionCatalogue.revision", "productionCatalogue.identity", "productionCatalogue.reopen"],
        &BTreeSet::from(["kernel.invoke", "json.canonicalCompact", "digest.sha256", "record.put",
            "record.entries", "value.sort"]), &mut Meter::new(200_000))?;
    let mut meter = Meter::new(10_000_000);
    let mut result = policy.run("productionCatalogue.revision", request.clone(), &mut meter)?;
    let source_revision = &result["sourceRevision"];
    let proposed = request["retainedAt"].as_str();
    let directory = match owned_file_parent(file, proposed.is_some()) {
        Ok(directory) => directory,
        Err(error) if proposed.is_none() && missing(error.as_ref()) => {
            println!("null");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let reopen = |retained: Value, meter: &mut Meter| -> Result<Value> {
        let timestamp = retained["retainedAt"].as_str().is_some_and(valid_time);
        policy.run("productionCatalogue.reopen", json!({
            "sourceRevision":source_revision, "retained":retained, "timestamp":timestamp,
        }), meter)
    };
    let identity = match optional_json(&directory, name, 16 * 1024)? {
        Some(retained) => reopen(retained, &mut meter)?,
        None => {
            let Some(proposed) = proposed else {
                println!("null");
                return Ok(());
            };
            if !valid_time(proposed) { return Err(fail("Expected an explicit catalogue identity timestamp")); }
            let candidate = policy.run("productionCatalogue.identity", json!({
                "sourceRevision":source_revision, "retainedAt":proposed,
            }), &mut meter)?;
            let bytes = compat_value::stringify(&candidate, &json!(2))? + "\n";
            if PendingFile::write(&directory, ".catalogue-identity", bytes.as_bytes())?.publish(name, false)? {
                candidate
            } else {
                let retained = optional_json(&directory, name, 16 * 1024)?
                    .ok_or_else(|| fail("Catalogue identity disappeared during initialization"))?;
                reopen(retained, &mut meter)?
            }
        }
    };
    result["retainedAt"] = identity["retainedAt"].clone();
    println!("{}", compat_value::stringify(&result, &Value::Null)?);
    Ok(())
}

fn valid_time(text: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(text).is_ok()
        || chrono::DateTime::parse_from_rfc2822(text).is_ok()
        || chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").is_ok()
}
