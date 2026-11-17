use crate::{Result, command_sources::Sources, fail, process::{Meter, Programme}, rel};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, io::{self, Read}, os::fd::AsRawFd, path::Path};

const RECEIPT: &str = ".sourcery-workspace-source-bootstrap.json";
const RECEIPT_LIMIT: u64 = 64 * 1024;
const PROJECT_LIMIT: u64 = 2_000_000;

fn read_observed(observed: &File, limit: u64) -> Result<Vec<u8>> {
    let metadata = observed.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(fail("Expected a bounded regular workspace file"));
    }
    let file = File::open(format!("/proc/self/fd/{}", observed.as_raw_fd()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Workspace file exceeds its byte bound")); }
    Ok(bytes)
}

fn invalid(message: &str) -> Box<dyn std::error::Error> {
    fail(json!({"code": "hosted-workspace-project-invalid", "message": message}).to_string())
}

fn missing(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn bootstrap_receipt(sources: &Sources) -> Result<Option<Value>> {
    let observed = match sources.observe_relative(RECEIPT) {
        Ok(file) => file,
        Err(error) if missing(error.as_ref()) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(serde_json::from_slice(&read_observed(&observed, RECEIPT_LIMIT)?)?))
}

pub(super) fn admit(root: &Path, target: Value) -> Result<(Value, File)> {
    let filesystem = Path::new("/");
    let relative = root.strip_prefix(filesystem)?.to_str().ok_or_else(|| fail("Workspace root must be UTF-8"))?;
    let sources = Sources::open_physical(filesystem)?.open_directory_relative(relative)
        .map_err(|_| invalid("The assigned workspace root is not a physical directory."))?;
    let receipt = bootstrap_receipt(&sources)
        .map_err(|_| invalid("The hosted workspace source-bootstrap receipt is invalid."))?;
    let policy = Programme::admit_entries(&[include_str!("hosted_worker_workspace.encounter").to_owned()],
        &["workerWorkspace.admit"], &BTreeSet::from(["kernel.invoke", "json.canonical", "digest.sha256", "text.slice",
            "value.type", "text.matches", "text.split"]),
        &mut Meter::new(100_000))?;
    let admission = policy.run("workerWorkspace.admit",
        json!({"hasReceipt": receipt.is_some(), "receipt": receipt, "target": target}), &mut Meter::new(200_000))
        .map_err(|error| invalid(&error.to_string()))?;
    let selected = admission["projectFile"].as_str().ok_or_else(|| fail("Expected a hosted workspace project path"))?;
    let invalid_project = || invalid("The hosted workspace project source is not a regular workspace-owned file.");
    let project = match sources.observe_relative(selected) {
        Ok(file) => file,
        Err(error) if missing(error.as_ref()) => return Err(fail(json!({
            "code": "hosted-workspace-project-uninitialized",
            "message": "The hosted workspace has no initialized project source. Complete the evidence-bound workspace source bootstrap before authoring."
        }).to_string())),
        Err(_) => return Err(invalid_project()),
    };
    if !project.metadata()?.is_file() { return Err(invalid_project()); }
    Ok((admission, project))
}

pub(super) fn application(project: &File) -> Result<Value> {
    let bytes = read_observed(project, PROJECT_LIMIT)?;
    application_for_source(std::str::from_utf8(&bytes)?)
}

fn application_for_source(source: &str) -> Result<Value> {
    let facts = rel::project_relations(source)?;
    let policy = Programme::admit_entries(&[include_str!("hosted_worker_workspace.encounter").to_owned()],
        &["workerWorkspace.application"], &BTreeSet::from(["text.replace", "text.matches", "text.split",
            "text.slice", "text.upperCase", "text.join", "digest.sha256"]), &mut Meter::new(100_000))?;
    policy.run("workerWorkspace.application", json!({"source":source, "facts":facts}), &mut Meter::new(8_000_000))
}

pub(crate) fn run(root: &Path, target: Value) -> Result<()> {
    if !root.is_absolute() { return Err(fail("Workspace root must be absolute")); }
    let (admission, _) = admit(root, target)?;
    println!("{admission}");
    Ok(())
}

#[cfg(test)]
#[test]
fn projects_bind_the_exact_positive_application_and_source_bytes() -> Result<()> {
    let source = r#"// ("project", "app", "app.comment")
("project", "app", "app.negative", "is-not")
("project", "app", "app.crew", "is", "{\"evidence\":\"declared\"}")
("project", "app", "app.crew")
("app.crew", "name", "not-this", "is-not")
("app.crew", "name", "élite_🛠crew\u00a0deck")
("app.crew", "name", "later")
"#;
    assert_eq!(application_for_source(source)?, json!({
        "projectSha256": rel::hash(source),
        "application": {"id":"app.crew", "instance":"crew", "name":"élite_🛠crew\u{a0}deck",
            "title":"Élite 🛠crew Deck", "targetDirectory":"."}
    }));
    let default = r#"("project","app","app.service_port")"#;
    let projection = application_for_source(default)?;
    assert_eq!(projection["application"]["name"], "service_port");
    assert_eq!(projection["application"]["title"], "Service Port");
    assert_ne!(application_for_source(&format!("{default}\n"))?["projectSha256"], projection["projectSha256"]);
    for invalid in [
        r#"("project","app","app.negative","is-not")"#,
        r#"("project","app","app.first") ("project","app","app.second")"#,
        r#"("project","app","app.safe","is","{\"o\":\"app.crossed\"}")"#,
        r#"("project","app","app.first") malformed"#,
    ] {
        assert!(application_for_source(invalid).is_err(), "{invalid}");
    }
    Ok(())
}
