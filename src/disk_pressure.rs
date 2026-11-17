use crate::{Result, compat_value, fail, process::{CSS_RENDERER, HTML_PORTS, HTML_RENDERER, Meter, Programme}};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet, fs::OpenOptions, io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt, path::Path,
};

const LIMIT: u64 = 8 * 1024 * 1024;

fn evaluate(entry: &str, value: Value) -> Result<Value> {
    compat_value::external(&value)?;
    let mut meter = Meter::new(100_000_000);
    let policy = Programme::admit_entries(&[include_str!("disk_pressure.encounter").to_owned()],
        &["diskPressure.admit", "diskPressure.assess"],
        &BTreeSet::from(["kernel.invoke", "text.matches", "text.slice", "json.canonical", "digest.sha256", "record.entries",
            "record.fromEntries", "record.put", "number.isNatural", "number.calculate", "value.describe", "value.sort"]),
        &mut meter)?;
    policy.run(entry, value, &mut meter)
}

pub(crate) fn assessment(observations: Value) -> Result<Value> {
    evaluate("diskPressure.assess", observations)
}

pub(crate) fn admit(policy: &Value) -> Result<()> {
    if evaluate("diskPressure.admit", policy.clone())? != true { return Err(fail("Disk-pressure policy refused")); }
    Ok(())
}

pub(crate) fn render(report: &Value) -> Result<Value> {
    let mut meter = Meter::new(100_000_000);
    let sources = HTML_RENDERER.into_iter().chain([
        CSS_RENDERER,
        include_str!("disk_pressure_render.encounter"),
        include_str!("disk_pressure_index.encounter"),
        include_str!("disk_pressure_gate.encounter"),
    ]).map(str::to_owned).collect::<Vec<_>>();
    let ports = HTML_PORTS.into_iter().chain([
        "kernel.invoke", "text.slice", "number.calculate", "number.format", "number.isNatural",
    ]).collect();
    let policy = Programme::admit_entries(&sources, &["diskPressure.render"], &ports, &mut meter)?;
    policy.run("diskPressure.render", report.clone(), &mut meter)
}

pub fn run(input: &Path) -> Result<()> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(input)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > LIMIT { return Err(fail("Expected bounded disk-pressure observations")); }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT { return Err(fail("Disk-pressure observations exceeded their byte limit")); }
    let result = assessment(serde_json::from_slice(&bytes)?)?;
    writeln!(io::stdout().lock(), "{}", compat_value::stringify(&result, &json!(2))?)?;
    Ok(())
}

#[cfg(test)]
#[test]
fn assessment_preserves_active_and_rollback_assets_and_refuses_crossed_evidence() -> Result<()> {
    let hash = |digit: &str| digit.repeat(64);
    let artifact = |kind, path, pin: String| json!({"kind":kind,"path":path,"sha256":pin,"observedSha256":pin});
    let runtime = |digit, reconstructible: bool, path| {
        let id = hash(digit);
        let evidence = reconstructible.then(|| json!({
            "admissionHash":hash("a"),"coreBundleHash":hash("b"),"dependencyBundleHash":hash("c"),
            "evidenceSha256":hash("e"),"evidencePath":format!("/fixture/reconstruction/{id}.json"),
            "artifacts":[artifact("admission","/fixture/authority/admission.rel",hash("e")),
                artifact("core-bundle",path,hash("b")),artifact("dependency-bundle","/fixture/shared-assets/deps.tar",hash("c"))]
        }));
        json!({"referenceHash":id,"directory":format!("/fixture/runtimes/{id}"),"bytes":12,
            "liveReferences":[],"releaseEvidence":null,"reconstruction":evidence})
    };
    let release = |id, capsule: bool| {
        let manifest = hash("d");
        let evidence = capsule.then(|| json!({
            "manifestPath":format!("/fixture/manifests/{manifest}.json"),"manifestSha256":manifest,
            "capsuleCount":1,"capsuleBytes":20,"capsulesVerified":true,
        }));
        json!({"id":id,"path":format!("/fixture/releases/{id}"),"bytes":10,"type":"directory",
            "liveReferences":[],"releaseEvidence":null,"releaseRecordSha256":capsule.then(|| hash("f")),
            "capsuleEvidence":evidence})
    };
    let mut input = json!({
        "protocol":"sourcery/disk-pressure-observations.v1","createdAt":"2026-10-06T00:00:00.000Z",
        "policy":{"protocol":"sourcery/server-disk-pressure-assurance-policy.v1",
            "safety":{"mode":"dry-run-only","automaticDeletion":false},"runtimeRoot":"/fixture/runtimes",
            "releaseRoot":"/fixture/releases","releaseRecordRoot":"/fixture/records",
            "sourceCapsuleManifestRoot":"/fixture/manifests","runtimeReconstructionEvidenceRoot":"/fixture/reconstruction",
            "filesystemRoot":"/fixture","authorityStore":"/fixture/authority",
            "rollbackRuntimeReferenceHashes":[hash("c")],"rollbackReleaseIds":["rollback"],
            "retention":{"minimumRollbackReleases":1},"readiness":{"expectedStatus":405,"expectedAllow":"POST"},
            "pressure":{"warningAvailablePercent":25,"criticalAvailablePercent":15,"warningAvailableBytes":40,"criticalAvailableBytes":20}},
        "authority":{"referenceHash":hash("a"),"admissionHash":hash("b"),"markerSha256":hash("c")},
        "pressure":{"totalBytes":100,"usedBytes":80,"availableBytes":20,"usedPercent":80},
        "health":{"services":{},"readiness":{"status":405,"allow":"POST"}},"activeReleaseId":"current",
        "runtimes":[runtime("a",false,""),runtime("b",true,"/fixture/shared-assets/core.tar"),
            runtime("c",true,"/fixture/shared-assets/core.tar"),runtime("d",true,"/fixture/shared-assets/../core.tar")],
        "releases":[release("current",false),release("rollback",true),release("old",true)],
        "dependencyClosures":[],"ancillary":[]
    });
    let report = assessment(input.clone())?;
    assert_eq!(report["summary"]["candidateCount"], 2);
    assert_eq!(report["summary"]["candidateBytes"], 22);
    assert_eq!(report["candidates"][0]["id"], hash("b"));
    assert_eq!(report["candidates"][1]["id"], "old");
    assert_eq!(report["inventory"]["runtimes"][2]["reason"], "policy-retained-rollback");
    assert_eq!(report["inventory"]["runtimes"][3]["status"], "isolated");
    assert_eq!(report["inventory"]["releases"][1]["classification"], "rollback");
    assert_eq!(report["pressure"]["status"], "warning");
    assert_eq!(report["health"]["readiness"]["passed"], true);
    assert_eq!(report["safety"]["automaticDeletion"], false);
    input["policy"]["safety"]["automaticDeletion"] = json!(true);
    assert!(assessment(input).is_err());
    Ok(())
}
