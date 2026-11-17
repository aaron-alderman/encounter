use crate::{Result, fail, package, process::{Meter, Programme}, rel::Facts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{cell::OnceCell, collections::BTreeSet, fs, io::{self, Read}, os::unix::fs::OpenOptionsExt, path::Path};

pub(crate) const RECEIPT: &str = "interaction-assurance.rel";
pub(crate) const SYSTEM_POLICY: &str = "performance-policy.rel";

pub(crate) const POLICY_SOURCES: [&str; 2] = [
    include_str!("appdev_assurance.encounter"), include_str!("appdev_system_performance.encounter"),
];

thread_local! {
    static POLICY: OnceCell<Programme> = const { OnceCell::new() };
}

fn evaluate(entry: &str, input: Value) -> Result<Value> {
    POLICY.with(|slot| {
        let mut meter = Meter::new(20_000_000);
        if slot.get().is_none() {
            let programme = Programme::admit_entries(&POLICY_SOURCES.map(str::to_owned),
                &["assurance.author", "assurance.require", "assurance.identityReport", "assurance.verificationBinding",
                    "assurance.assemble", "performance.author"],
                &BTreeSet::from(["json.parse", "json.stringify", "number.parse",
                    "number.calculate", "record.entries", "record.put", "text.matches", "value.sort"]), &mut meter)?;
            let _ = slot.set(programme);
        }
        slot.get().expect("initialized AppDev Assurance policy").run(entry, input, &mut meter)
    })
}

pub(crate) fn interaction_rows(digest: &str, observations: Value) -> Result<Vec<[String; 3]>> {
    let rows = evaluate("assurance.author", json!({"releaseSha256":digest, "observations":observations}))?;
    Ok(serde_json::from_value(rows)?)
}

pub(crate) fn performance_rows(input: Value) -> Result<Vec<[String; 3]>> {
    let rows = evaluate("performance.author", input)?;
    Ok(serde_json::from_value(rows)?)
}

pub(crate) fn receipt_with_metadata(rows: Vec<[String; 3]>, verification: Option<(&str, &str)>,
    identity: Option<Value>) -> Result<Vec<[String; 3]>> {
    let verification = verification.map(|(source, digest)| json!({"source":source,"sha256":digest}));
    let rows = evaluate("assurance.assemble", json!({"rows":rows,"verification":verification,"identity":identity}))?;
    Ok(serde_json::from_value(rows)?)
}

pub(crate) fn verification_binding(receipt: &Facts, observed: Option<(&str, &str)>) -> Result<Value> {
    let observed = observed.map(|(source, digest)| json!({"source":source,"sha256":digest}));
    evaluate("assurance.verificationBinding", json!({"receipt":receipt.0,"observed":observed}))
}

pub(crate) fn read_facts(path: &Path) -> Result<Facts> {
    const LIMIT: usize = 1_000_000;
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() { return Err(fail("Expected a regular AppDev Assurance artifact")); }
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT { return Err(fail("AppDev Assurance artifact exceeded its size limit")); }
    Facts::parse(std::str::from_utf8(&bytes)?)
}

pub fn fingerprint(root: &Path) -> Result<String> {
    fingerprint_package(root, Some(RECEIPT))
}

pub(crate) fn fingerprint_package(root: &Path, excluded: Option<&str>) -> Result<String> {
    hash_package(root, excluded, |_, _| {})
}

pub(crate) fn hash_package(root: &Path, excluded: Option<&str>,
    mut observe: impl FnMut(&str, &[u8])) -> Result<String> {
    let directory = fs::File::open(root)?;
    package::check(root)?;
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for item in fs::read_dir(directory)? {
            let item = item?;
            let path = item.path();
            let kind = item.file_type()?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                if !excluded.is_some_and(|name| path == root.join(name)) { files.push(path); }
            } else {
                return Err(fail("invalid AppDev assurance artifact"));
            }
        }
    }
    files.sort_unstable();
    let mut release = Sha256::new();
    for path in files {
        let relative_path = path.strip_prefix(root)?;
        let relative = relative_path.to_str()
            .ok_or_else(|| fail("AppDev assurance requires UTF-8 artifact paths"))?;
        let mut file = Sha256::new();
        io::copy(&mut package::open_artifact(&directory, relative_path)?, &mut file)?;
        release.update(relative);
        release.update([0]);
        let digest = file.finalize();
        release.update(digest);
        observe(relative, &digest);
    }
    Ok(hex::encode(release.finalize()))
}

pub fn system_package(root: &Path) -> bool {
    root.join(SYSTEM_POLICY).exists() || root.join("work/package-receipt.rel").is_file()
}

pub(crate) fn identity_report(root: &Path) -> Result<Option<Value>> {
    let receipt = match read_facts(&root.join(RECEIPT)) {
        Ok(facts) => facts,
        Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    // A receipt without an optional report needs no artifact digest.
    let digest = (!receipt.values("identity-management", "report").is_empty())
        .then(|| fingerprint(root)).transpose()?;
    let report = evaluate("assurance.identityReport", json!({"receipt":receipt.0, "releaseSha256":digest}))?;
    Ok((!report.is_null()).then_some(report))
}

pub fn require(root: &Path) -> Result<()> {
    require_receipt(root, &root.join(RECEIPT))
}

pub fn require_receipt(root: &Path, path: &Path) -> Result<()> {
    let receipt = read_facts(path)
        .map_err(|error| fail(format!("AppDev interaction Assurance receipt unavailable: {error}")))?;
    let system = system_package(root);
    let policy = system.then(|| read_facts(&root.join(SYSTEM_POLICY)).map(|facts| facts.0)).transpose()?;
    if evaluate("assurance.require", json!({"receipt":receipt.0,"system":system,"policy":policy,
        "releaseSha256":fingerprint(root)?}))? != true {
        return Err(fail("Encounter refused the AppDev Assurance receipt"));
    }
    Ok(())
}
