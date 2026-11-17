use crate::{Result, command_sources::Sources, compat_value, fail, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use std::{collections::BTreeSet, env, fs::File, io::{self, Read}, os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path, time::{SystemTime, UNIX_EPOCH}};

const MAXIMUM: u64 = 65_536;
const DEFAULT_MANIFEST: &str = "/etc/sourcery/production-infrastructure.json";

pub(super) fn policy() -> Result<Programme> {
    Programme::admit_entries(&[
        include_str!("hosted_production_manifest.encounter").to_owned(),
        include_str!("hosted_postgres.encounter").to_owned(),
        include_str!("hosted_worker_image.encounter").to_owned(),
        include_str!("hosted_reconciliation.encounter").to_owned(),
        include_str!("mcp_client.encounter").to_owned(),
        include_str!("hosted_release_identity.encounter").to_owned(),
    ], &["productionManifest.admit", "productionManifest.custody", "productionManifest.path",
        "productionManifest.source", "productionManifest.interactionSecrets", "productionManifest.operationsRoster",
        "productionManifest.operationsApprover", "productionManifest.cataloguePublication",
        "productionManifest.catalogueAuthorize", "productionManifest.runtimeVerificationKeys",
        "productionManifest.storageConformance", "productionManifest.releaseProposal", "productionManifest.coordinateRelease",
        "productionManifest.assessRelease", "productionManifest.createReleaseArtifact",
        "productionManifest.retainedArtifact", "productionManifest.retainedAssessment", "productionManifest.releaseBindings",
        "productionManifest.promotionCommand", "productionManifest.promotionArtifacts", "productionManifest.promotionAssessment",
        "productionManifest.promotionEffect"],
        &BTreeSet::from(["value.describe", "value.type", "kernel.invoke", "record.entries",
            "record.put", "text.matches", "text.replace", "path.resolvePosix", "number.isNatural",
            "number.calculate", "time.parseRfc3339", "time.formatUtc", "record.fromEntries",
            "json.canonical", "json.stringify", "digest.sha256", "text.trim"]), &mut Meter::new(200_000))
}

fn normalize_path(policy: &Programme, path: &Path) -> Result<std::path::PathBuf> {
    let path = path.to_str().ok_or_else(|| fail("Custody file path must be UTF-8"))?;
    let normalized = policy.run("productionManifest.path", json!(path), &mut Meter::new(100_000))?;
    normalized.as_str().map(Into::into).ok_or_else(|| fail("Missing admitted custody file path"))
}

pub(super) fn read_custody(policy: &Programme, path: &Path, owner: u32, maximum: u64) -> Result<Vec<u8>> {
    let path = normalize_path(policy, path)?;
    let relative = path.strip_prefix("/")?.to_str().ok_or_else(|| fail("Custody file path must be UTF-8"))?;
    let observed = Sources::open_physical(Path::new("/"))?.observe_relative(relative)?;
    let metadata = observed.metadata()?;
    policy.run("productionManifest.custody", json!({"regular": metadata.is_file(), "bytes": metadata.len(),
        "maximum": maximum, "uid": metadata.uid(), "owner": owner, "private": metadata.mode() & 0o037 == 0}),
        &mut Meter::new(100_000))?;
    read_bounded(File::open(format!("/proc/self/fd/{}", observed.as_raw_fd()))?, maximum)
}

fn read_bounded(reader: impl Read, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(fail("Self-hosted custody file must be a bounded regular file."));
    }
    Ok(bytes)
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    let value = serde_json::from_slice(bytes).map_err(|_| fail("Self-hosted custody file must contain valid JSON."))?;
    compat_value::external(&value)?;
    Ok(value)
}

pub(super) fn interaction_secrets(path: &Path) -> Result<Value> {
    let policy = policy()?;
    let bytes = zeroize::Zeroizing::new(read_custody(&policy, path, 0, 4096)?);
    policy.run("productionManifest.interactionSecrets", parse(&bytes)?, &mut Meter::new(200_000))
}

pub(super) fn operations_roster(path: &Path) -> Result<Value> {
    let policy = policy()?;
    let bytes = read_custody(&policy, path, 0, 16_384)?;
    policy.run("productionManifest.operationsRoster", parse(&bytes)?, &mut Meter::new(200_000))
}

pub(super) fn catalogue_publication(path: &Path) -> Result<Value> {
    let policy = policy()?;
    let bytes = read_custody(&policy, path, 0, 16_384)?;
    policy.run("productionManifest.cataloguePublication", parse(&bytes)?, &mut Meter::new(200_000))
}

pub(super) fn release_document(path: &Path) -> Result<Value> {
    parse(&read_custody(&policy()?, path, 0, MAXIMUM)?)
}

pub(super) fn release_proposal(path: &Path) -> Result<Value> {
    let policy = policy()?;
    let bytes = read_custody(&policy, path, 0, MAXIMUM)?;
    policy.run("productionManifest.releaseProposal", parse(&bytes)?, &mut Meter::new(2_000_000))
}

pub(crate) fn check_release_proposal() -> Result<()> {
    let proposal = parse(&read_bounded(io::stdin().lock(), MAXIMUM)?)?;
    println!("{}", policy()?.run("productionManifest.releaseProposal", proposal, &mut Meter::new(2_000_000))?);
    Ok(())
}

pub(crate) fn coordinate_release() -> Result<()> {
    let input = parse(&read_bounded(io::stdin().lock(), 128 * 1024)?)?;
    println!("{}", policy()?.run("productionManifest.coordinateRelease", input, &mut Meter::new(2_000_000))?);
    Ok(())
}

pub(crate) fn assess_release() -> Result<()> {
    let input = parse(&read_bounded(io::stdin().lock(), MAXIMUM)?)?;
    println!("{}", policy()?.run("productionManifest.assessRelease", input, &mut Meter::new(2_000_000))?);
    Ok(())
}

pub(crate) fn create_release_artifact() -> Result<()> {
    let input = parse(&read_bounded(io::stdin().lock(), MAXIMUM)?)?;
    println!("{}", policy()?.run("productionManifest.createReleaseArtifact", input, &mut Meter::new(2_000_000))?);
    Ok(())
}

pub(crate) fn check_retained_release(operation: &str) -> Result<()> {
    let entry = match operation {
        "artifact" => "productionManifest.retainedArtifact",
        "assessment" => "productionManifest.retainedAssessment",
        "bindings" => "productionManifest.releaseBindings",
        "promotion-command" => "productionManifest.promotionCommand",
        "promotion-artifacts" => "productionManifest.promotionArtifacts",
        "promotion-assessment" => "productionManifest.promotionAssessment",
        "promotion-effect" => "productionManifest.promotionEffect",
        _ => return Err(fail("Unsupported retained release decision")),
    };
    let input = parse(&read_bounded(io::stdin().lock(), MAXIMUM)?)?;
    println!("{}", policy()?.run(entry, input, &mut Meter::new(2_000_000))?);
    Ok(())
}

pub(super) fn storage_conformance(path: &Path) -> Result<Value> {
    let policy = policy()?;
    let bytes = read_custody(&policy, path, 0, MAXIMUM)?;
    policy.run("productionManifest.storageConformance", parse(&bytes)?, &mut Meter::new(500_000))
}

pub(super) fn runtime_verification_keys(path: &Path, active_key_id: &str) -> Result<Value> {
    let policy = policy()?;
    let bytes = read_custody(&policy, path, 0, 32_768)?;
    let keys = policy.run("productionManifest.runtimeVerificationKeys", json!({
        "keys": parse(&bytes)?, "activeKeyId": active_key_id,
    }), &mut Meter::new(200_000))?;
    let keyring = keys.as_object().ok_or_else(|| fail("Expected admitted runtime verification keyring"))?;
    for key in keyring.values() {
        let encoded = key["x"].as_str().ok_or_else(|| fail("Expected admitted runtime verification key"))?;
        let mut public = [0; 32];
        Base64UrlUnpadded::decode(encoded, &mut public).map_err(|_| fail("Invalid runtime verification key encoding"))?;
        VerifyingKey::from_bytes(&public).map_err(|_| fail("Invalid Ed25519 runtime verification key"))?;
    }
    Ok(keys)
}

pub(crate) fn catalogue_authorize() -> Result<()> {
    let input = parse(&read_bounded(io::stdin().lock(), 32_768)?)?;
    let result = policy()?.run("productionManifest.catalogueAuthorize", input, &mut Meter::new(200_000))?;
    println!("{result}");
    Ok(())
}

pub(crate) fn operations_approver() -> Result<()> {
    let input = parse(&read_bounded(io::stdin().lock(), 32_768)?)?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let decision = policy()?.run("productionManifest.operationsApprover", json!({
        "roster": input["roster"], "actor": input["actor"], "nowMs": now,
    }), &mut Meter::new(200_000))?;
    println!("{decision}");
    Ok(())
}

pub(super) fn load(policy: &Programme, path: &Path, owner: u32) -> Result<Value> {
    let bytes = read_custody(policy, path, owner, MAXIMUM)?;
    let value = parse(&bytes)?;
    // Use the JSON number representation already consumed by the JavaScript caller.
    let compatible = compat_value::stringify(&value, &Value::Null)?;
    policy.run("productionManifest.admit", serde_json::from_str(&compatible)?, &mut Meter::new(2_000_000))
}

pub(super) fn admit_supervised(source: &Path) -> Result<Value> {
    let configured = env::var("SOURCERY_SELF_HOSTED_INFRASTRUCTURE_CONFIG");
    let path = match &configured {
        Ok(path) if !path.is_empty() => path,
        Ok(_) | Err(env::VarError::NotPresent) => DEFAULT_MANIFEST,
        Err(error) => return Err(fail(error.to_string())),
    };
    let source = source.to_str().ok_or_else(|| fail("Supervised source root must be UTF-8"))?;
    admit_infrastructure(Path::new(path), 0, &json!(source))
}

fn admit_infrastructure(path: &Path, owner: u32, supervised: &Value) -> Result<Value> {
    let policy = policy()?;
    let manifest = load(&policy, path, owner)?;
    let source = policy.run("productionManifest.source", json!({
        "sourceRoot": manifest["sourceRoot"], "supervised": supervised,
    }), &mut Meter::new(100_000))?;
    let source = source.as_str().ok_or_else(|| fail("Missing admitted source root"))?;
    let root = Sources::open_physical(Path::new("/"))?;
    if source != "/" {
        root.open_directory_relative(source.trim_start_matches('/'))
            .map_err(|_| fail("Self-hosted source root must be a real, non-linked directory."))?;
    }
    let worker = &manifest["worker"];
    let file = worker["imageAdmissionFile"].as_str().ok_or_else(|| fail("Missing admitted image evidence path"))?;
    let image = worker["image"].as_str().ok_or_else(|| fail("Missing admitted worker image"))?;
    crate::hosted_worker_image::read_admission_file(Path::new(file), image, owner)?;
    Ok(manifest)
}

pub(crate) fn run() -> Result<()> {
    let request = parse(&read_bounded(io::stdin().lock(), 8192)?)?;
    let owner = request["owner"].as_u64().and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| fail("Self-hosted custody owner is invalid."))?;
    let path = request["file"].as_str().ok_or_else(|| fail("Self-hosted custody file must be an absolute path."))?;
    let manifest = load(&policy()?, Path::new(path), owner)?;
    println!("{manifest}");
    Ok(())
}
