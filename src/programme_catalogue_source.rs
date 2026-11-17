use crate::{Result, appdev_host_process::Supervisor, archive::Work, compat_value, fail,
    hosted_layer_assembly::{directory, source}, platform_import_closure::read_bounded_observation,
    process::{Meter, Programme}};
use serde_json::{Map, Value, json};
use std::{collections::BTreeSet, fs::File, path::Path, time::Duration};

const PROFILE: &str = "plugins/programme-completeness-audit/completion-profile.json";
const LIMIT: u64 = 6 * 1024 * 1024;

fn content(work: &Work, root: &File, path: &str, remaining: &mut u64) -> Result<String> {
    let mut bytes = Vec::new();
    let mut file = source(root, Path::new(path), *remaining)?;
    let (size, _) = work.copy(&mut file, &mut bytes, *remaining)?;
    *remaining -= size;
    Ok(String::from_utf8(bytes)?)
}

pub(crate) fn run(operation: &str, root: &Path) -> Result<()> {
    let entry = match operation {
        "production" => "programmeCatalogue.productionEvidence",
        "integrated" => "programmeCatalogue.integrated",
        _ => return Err(fail("Unsupported catalogue source operation")),
    };
    let _signals = Supervisor::new();
    let request = if operation == "integrated" { read_bounded_observation(64 * 1024)? } else { Value::Null };
    let policy = Programme::admit_entries(&[include_str!("knowledge_catalogue.encounter").into(),
        include_str!("knowledge_catalogue_build.encounter").into(), include_str!("programme_catalogue.encounter").into(),
        include_str!("programme_completion.encounter").into()], &["programmeCatalogue.sourcePlan", entry],
        &BTreeSet::from(["kernel.invoke", "value.type", "value.describe", "value.string", "text.trim",
            "text.join", "text.matches", "text.split", "digest.sha256", "record.entries", "record.fromEntries",
            "record.put", "json.canonicalCompact", "json.stringify", "value.sort", "number.calculate",
            "number.isNatural", "text.lowerCase"]), &mut Meter::new(200_000))?;
    let root = directory(root)?;
    let work = Work::new(Duration::from_secs(15));
    let mut remaining = LIMIT;
    let profile_content = content(&work, &root, PROFILE, &mut remaining)?;
    let profile: Value = serde_json::from_str(&profile_content)?;
    compat_value::external(&profile)?;
    let mut meter = Meter::new(120_000_000);
    let plan = policy.run("programmeCatalogue.sourcePlan", json!({
        "profile":profile, "production":operation == "production",
    }), &mut meter)?;
    let mut contents = Map::new();
    for path in plan["paths"].as_array().ok_or_else(|| fail("Missing catalogue source plan"))? {
        let path = path.as_str().ok_or_else(|| fail("Expected an admitted catalogue source path"))?;
        let observed = content(&work, &root, path, &mut remaining)
            .map_err(|cause| fail(format!("Cannot observe catalogue source {path}: {cause}")))?;
        contents.insert(path.to_owned(), observed.into());
    }
    let result = policy.run(entry, json!({
        "profile":profile, "profileContent":profile_content, "plan":plan, "contents":contents,
        "runtime":request["assemblyRuntime"], "observedAt":request["observedAt"],
    }), &mut meter)?;
    work.check()?;
    println!("{}", compat_value::stringify(&result, &Value::Null)?);
    Ok(())
}
