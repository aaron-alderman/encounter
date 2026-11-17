use crate::{Result, appdev_host_process::{Scratch, Supervisor, exchange_paths, rename_new_path},
    fail, hosted_layer_assembly::{directory, source}, process::{Meter, Programme}};
use serde::Deserialize;
use serde_json::json;
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File}, io::{self, Read, Write},
    path::{Component, Path}};

const OUTPUT: &str = "spec/catalogue-source";
const HTML_LIMIT: u64 = 4 * 1024 * 1024;
const SOURCE_LIMIT: u64 = 512 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Excerpt {
    source: String,
    process: String,
}

fn read(root: &File, path: &Path, limit: u64) -> Result<String> {
    let mut bytes = Vec::new();
    source(root, path, limit)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Catalogue input exceeded its byte bound")); }
    Ok(String::from_utf8(bytes)?)
}

fn optional_directory(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(fail("Catalogue output must be a physical directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn require_unpinned(package: &Path) -> Result<()> {
    match package.join("package-receipt.rel").symlink_metadata() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(fail("Publish Catalogue excerpts before pinning the staged package")),
    }
}

fn check_previous(supervisor: &mut Supervisor, path: &Path, depth: usize) -> Result<()> {
    if depth > 32 { return Err(fail("Catalogue output exceeded its directory depth bound")); }
    for item in fs::read_dir(path)? {
        supervisor.check()?;
        let item = item?;
        let kind = item.file_type()?;
        if kind.is_dir() {
            check_previous(supervisor, &item.path(), depth + 1)?;
        } else if !kind.is_file() || item.path().extension().is_none_or(|suffix| suffix != "encounter") {
            return Err(fail("Catalogue output contains an object outside the excerpt inventory"));
        }
    }
    Ok(())
}

pub(crate) fn run(package: &Path) -> Result<()> {
    let mut supervisor = Supervisor::new();
    let package = std::path::absolute(package)?;
    let root = directory(&package)?;
    require_unpinned(&package)?;
    let mut meter = Meter::new(40_000_000);
    let policy = Programme::admit_entries(&[include_str!("appdev_catalogue_excerpts.encounter").to_owned()],
        &["catalogueExcerpts.plan", "catalogueExcerpts.render"],
        &BTreeSet::from(["text.matchAll", "text.matches", "text.match", "text.replace", "text.split",
            "text.join", "text.utf8Length", "number.calculate", "record.fromEntries", "record.entries",
            "record.put"]), &mut meter)?;
    let html = read(&root, Path::new("index.html"), HTML_LIMIT)?;
    let plan: BTreeMap<String, Excerpt> = serde_json::from_value(
        policy.run("catalogueExcerpts.plan", json!(html), &mut meter)?)?;
    let stage = Scratch::create(&package, ".catalogue-excerpts-")?;
    let staged = stage.path().join("catalogue-source");
    fs::create_dir(&staged)?;
    let mut sources = BTreeMap::new();
    for (target, excerpt) in &plan {
        supervisor.check()?;
        let target = Path::new(target);
        if !target.components().all(|part| matches!(part, Component::Normal(_))) {
            return Err(fail("Expected a Catalogue excerpt path beneath the output directory"));
        }
        if !sources.contains_key(&excerpt.source) {
            let contents = read(&root, Path::new(&excerpt.source), SOURCE_LIMIT)?;
            sources.insert(excerpt.source.clone(), contents);
        }
        let rendered = policy.run("catalogueExcerpts.render",
            json!({"source": sources[&excerpt.source], "process": excerpt.process}), &mut meter)
            .map_err(|error| fail(format!("{}: {error}", target.display())))?;
        let text = rendered.as_str().ok_or_else(|| fail("Expected a Catalogue excerpt"))?;
        let path = staged.join(target);
        fs::create_dir_all(path.parent().ok_or_else(|| fail("Missing Catalogue excerpt directory"))?)?;
        let mut file = File::create_new(path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    let spec = package.join("spec");
    if !optional_directory(&spec)? {
        fs::create_dir(&spec)?;
    }
    let output = package.join(OUTPUT);
    let replace = optional_directory(&output)?;
    if replace { check_previous(&mut supervisor, &output, 0)?; }
    require_unpinned(&package)?;
    supervisor.check()?;
    if replace { exchange_paths(&staged, &output)?; } else { rename_new_path(&staged, &output)?; }
    File::open(spec)?.sync_all()?;
    println!("Published {} bounded Catalogue source excerpts", plan.len());
    Ok(())
}
