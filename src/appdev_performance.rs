use crate::{Result, appdev_host_process::Supervisor, appdev_workflow::{profile, strings}, command::Evaluator, fail};
use crate::systemd_user_service::SystemServices;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File}, io::Read, path::{Component, Path, PathBuf},
    process::{Command, Stdio}, time::{Duration, SystemTime, UNIX_EPOCH}};

const POLICY: &str = "applications/appdev-projects/verification/performance/measurements.rel";
const OUTPUT_LIMIT: usize = 256 * 1024;
const CAPACITY_SCOPE: &str = "encounter-capacity-performance";
const CONTEXT_SCOPE: &str = "encounter-sweep-context";
const ACTIVE: &str = "/var/www/appdev-projects/workspace";

pub(crate) fn evaluator(app: &Path) -> Result<Evaluator> {
    let projects = app.ancestors().nth(2).ok_or_else(|| fail("Expected the Encounter project source root"))?;
    Evaluator::load(projects, POLICY)
}

fn observation_command(app: &Path, home: &Path, mode: &str) -> Command {
    let mut command = Command::new("/usr/bin/python3");
    command.arg(app.join("verification/workspace-routes/verify.py"))
        .arg("--candidate").arg(home).arg(mode)
        .env("APPDEV_RELEASE_RUNTIME", home.join("encounter"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env_remove("APPDEV_SYSTEM_MEASUREMENTS")
        .stdin(Stdio::null());
    profile(&mut command, app);
    command
}

fn json_observations(output: &[u8]) -> Result<Vec<Value>> {
    Ok(std::str::from_utf8(output)?.lines().filter(|line| line.starts_with(['{', '[']))
        .map(serde_json::from_str).collect::<std::result::Result<_, _>>()?)
}

pub fn verify(supervisor: &mut Supervisor, app: &Path, home: &Path, evidence: &Path) -> Result<()> {
    let policy = evaluator(app)?;
    let mut probes = Map::new();
    for probe in strings(&policy.run("measurements.probes", Value::Null)?)? {
        let mode = match probe {
            "startup-idle" => "--idle-bridge",
            "assurance-bytes" => "--assurance-bytes",
            "badge-bytes" => "--badge-bytes",
            _ => return Err(fail("Unknown Encounter release performance probe")),
        };
        let mut command = observation_command(app, home, mode);
        command.env("ENCOUNTER_RELEASE_PERFORMANCE_GATE", "1");
        let output = supervisor.capture(probe, &mut command, Duration::from_secs(120), OUTPUT_LIMIT)?;
        let rows = json_observations(&output)?;
        if probes.insert(probe.to_owned(), json!(rows)).is_some() {
            return Err(fail("Duplicate Encounter release performance probe"));
        }
    }
    let mut work = Vec::new();
    File::open(evidence.join("work.json"))?.take(OUTPUT_LIMIT as u64 + 1).read_to_end(&mut work)?;
    if work.len() > OUTPUT_LIMIT { return Err(fail("Work performance evidence exceeded its size limit")); }
    let work: Value = serde_json::from_slice(&work)?;
    let verdict = policy.run("measurements.releaseEvidence", json!({"probes":probes,"work":work}))?;
    if verdict["admitted"] != true {
        let failures = verdict["failures"].as_array().ok_or_else(|| fail("Invalid Encounter performance verdict"))?;
        let failures = failures.iter().map(|row| format!("{}: {}",
            row["check"].as_str().unwrap_or("Unknown check"), row["status"].as_str().unwrap_or("Unavailable")))
            .collect::<Vec<_>>();
        return Err(fail(format!("Encounter registry release gate: {}", failures.join("; "))));
    }
    let checks = verdict["checks"].as_array().ok_or_else(|| fail("Invalid Encounter performance check list"))?;
    println!("PASS: Encounter release meets {} registry checks", checks.len());
    Ok(())
}

fn own_cgroup() -> Result<PathBuf> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let group = membership.lines().find_map(|line| line.strip_prefix("0::"))
        .map(Path::new).filter(|path| path.is_absolute()
            && path.components().all(|component| matches!(component, Component::RootDir | Component::Normal(_))))
        .ok_or_else(|| fail("Expected the current cgroup v2 membership"))?;
    Ok(Path::new("/sys/fs/cgroup").join(group.strip_prefix("/")?))
}

fn cpu_usage(group: &Path) -> Result<u64> {
    let stats = fs::read_to_string(group.join("cpu.stat"))?;
    let usage = stats.lines().find_map(|line| line.strip_prefix("usage_usec "))
        .ok_or_else(|| fail("Missing cgroup CPU usage"))?;
    Ok(usage.parse()?)
}

fn receipt_pin(release: &Path) -> Result<[u8; 32]> {
    let mut manifest = Vec::new();
    File::open(release.join("package-receipt.rel"))?.take(OUTPUT_LIMIT as u64 + 1).read_to_end(&mut manifest)?;
    if manifest.len() > OUTPUT_LIMIT { return Err(fail("Capacity sweep release receipt exceeded its size limit")); }
    Ok(Sha256::digest(manifest).into())
}

fn project_sweep_history(policy: &Evaluator, entries: Vec<Value>, channel: Option<bool>) -> Result<Vec<Value>> {
    let mut history = policy.run("mailbox.journalHistory", json!({"entries":entries,"channel":channel}))?;
    history.as_array_mut().map(std::mem::take).ok_or_else(|| fail("Invalid Encounter sweep journal history"))
}

#[cfg(test)]
#[test]
fn sweep_journal_projects_channels_in_invocation_order() -> Result<()> {
    let line = |invocation, stamp: Option<u64>, report: Value| json!({
        "invocation":invocation,"stamp":stamp,"report":report
    });
    let context = json!({"scope":CONTEXT_SCOPE,"channel":"capacity","release":"expected"});
    let older = json!({"scope":CAPACITY_SCOPE,"samples":[{"check":"mixed-cpu","value":1}]});
    let latest = json!({"scope":CAPACITY_SCOPE,"samples":[{"check":"mixed-cpu","value":2}]});
    let launch = json!({"scope":CONTEXT_SCOPE,"release":"other"});
    let partial = json!({"scope":CAPACITY_SCOPE,"samples":[]});
    let entries = [
        line("unknown", None, json!({"scope":"ignore"})),
        line("capacity", Some(20), older),
        line("different", Some(21), launch.clone()),
        line("capacity", Some(22), context.clone()),
        line("capacity", Some(23), latest.clone()),
        line("incomplete", Some(24), partial.clone()),
    ].into_iter().enumerate().map(|(index, mut entry)| {
        entry["index"] = json!(index);
        entry
    }).collect::<Vec<_>>();
    let app = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects");
    let policy = evaluator(&app.canonicalize()?)?;
    assert_eq!(project_sweep_history(&policy, entries.clone(), Some(true))?, [json!({"stamp":20,"release":"expected",
        "confirmation":null,"samples":latest["samples"]})]);
    let launch_history = [
        json!({"stamp":21,"release":"other","confirmation":null,"reports":{(CONTEXT_SCOPE):launch}}),
        json!({"stamp":24,"release":null,"confirmation":null,"reports":{(CAPACITY_SCOPE):partial}}),
    ];
    assert_eq!(project_sweep_history(&policy, vec![json!({"invocation":"different","stamp":21,"report":launch,"index":0}),
        json!({"invocation":"wrong-scope","stamp":24,"report":partial,"index":1})], Some(false))?, launch_history[..1]);
    let combined = project_sweep_history(&policy, entries, None)?;
    assert_eq!(combined[0], json!({"stamp":20,"release":"expected","confirmation":null,
        "reports":{(CONTEXT_SCOPE):context,(CAPACITY_SCOPE):latest},"capacity":true}));
    assert_eq!(combined[1..], launch_history.map(|mut row| { row["capacity"] = json!(false); row }));
    let malformed = line("malformed", None, json!({"scope":CONTEXT_SCOPE}));
    assert!(project_sweep_history(&policy, vec![malformed], None).is_err());
    Ok(())
}

pub fn capacity_sweep(app: &Path, candidate: Option<&Path>) -> Result<()> {
    let mut supervisor = Supervisor::new();
    let app = app.canonicalize()?;
    let policy = evaluator(&app)?;
    let candidate = candidate.map(Path::canonicalize).transpose()?;
    let group = own_cgroup()?;
    let release_path = candidate.as_deref().unwrap_or_else(|| Path::new(ACTIVE));
    let verdict = capacity_decision(&mut supervisor, release_path, &policy,
        |release| {
            if candidate.is_some() {
                crate::appdev_workflow::check_system_candidate_pins(&app, release)?;
            }
            capacity_observation(&app, release, &group)
        },
        || if candidate.is_some() { Ok(Vec::new()) } else { journal_history(&policy, true) })?;
    println!("{}\n{}", verdict["report"], verdict["context"]);
    if verdict["completed"] != true { return Err(fail("Capacity evidence was incomplete")); }
    Ok(())
}

struct CapacityObservation {
    cpu_before: u64,
    cpu_after: u64,
    memory_peak: u64,
    samples: Option<Value>,
}

fn capacity_observation(app: &Path, release: &Path, group: &Path) -> Result<CapacityObservation> {
    let cpu_before = cpu_usage(group)?;
    let mut command = observation_command(app, release, "--capacity");
    let output = Supervisor::children().capture("capacity browser probe", &mut command, Duration::from_secs(105), OUTPUT_LIMIT);
    let cpu_after = cpu_usage(group)?;
    let memory_peak = fs::read_to_string(group.join("memory.peak"))?.trim().parse()?;
    let samples = match output {
        Ok(output) => match json_observations(&output)?.as_slice() {
            [samples] if samples.is_array() => Some(samples.clone()),
            _ => return Err(fail("Unexpected capacity browser evidence")),
        },
        Err(error) => {
            if crate::appdev_host_process::interruption().is_some() { return Err(error); }
            eprintln!("{error}");
            None
        }
    };
    Ok(CapacityObservation { cpu_before, cpu_after, memory_peak, samples })
}

fn capacity_decision(supervisor: &mut Supervisor, active: &Path, policy: &Evaluator,
    observe: impl FnOnce(&Path) -> Result<CapacityObservation>,
    history: impl FnOnce() -> Result<Vec<Value>>) -> Result<Value>
{
    let release = active.canonicalize()?;
    let pin = receipt_pin(&release)?;
    let release_name = release_name(&release, &pin)?;
    let observation = observe(&release)?;
    if active.canonicalize()? != release { return Err(fail("Active AppDev release changed during the capacity probe")); }
    let passed = observation.samples.is_some();
    let samples = observation.samples.unwrap_or_else(|| json!([]));
    let history = history()?;
    let stamp = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let verdict = policy.run("measurements.capacitySweep", json!({
        "release":release_name,"stamp":stamp,"history":history,"samples":samples,"probePassed":passed,
        "cpuBefore":observation.cpu_before,"cpuAfter":observation.cpu_after,"memoryPeak":observation.memory_peak
    }))?;
    supervisor.check()?;
    if active.canonicalize()? != release || receipt_pin(&release)? != pin {
        return Err(fail("Active AppDev release changed before capacity reporting"));
    }
    if verdict["report"]["scope"] != CAPACITY_SCOPE || verdict["context"]["scope"] != CONTEXT_SCOPE {
        return Err(fail("Invalid Encounter capacity report"));
    }
    Ok(verdict)
}

#[cfg(test)]
#[test]
fn capacity_sweep_binds_browser_and_resource_evidence_to_the_release() -> Result<()> {
    use crate::appdev_host_process::Scratch;
    use std::os::unix::fs::symlink;

    let fixture = Scratch::create(&std::env::temp_dir(), "appdev-capacity-plan-")?;
    let app = fixture.path().join("projects/applications/appdev-projects");
    let routes = app.join("verification/workspace-routes");
    fs::create_dir_all(&routes)?;
    let group = fixture.path().join("cgroup");
    let release = fixture.path().join("candidate");
    let active = fixture.path().join("active");
    fs::create_dir(&group)?;
    fs::create_dir(&release)?;
    symlink(&release, &active)?;
    let receipt = release.join("package-receipt.rel");
    fs::write(&receipt, "candidate receipt")?;
    let cpu = group.join("cpu.stat");
    fs::write(&cpu, "usage_usec 200\n")?;
    fs::write(group.join("memory.peak"), "1024\n")?;
    let probe = routes.join("verify.py");
    fs::write(&probe, format!(r#"
import os, sys
from pathlib import Path
assert sys.argv[1:] == ["--candidate", {}, "--capacity"]
assert os.environ["APPDEV_RELEASE_RUNTIME"] == {}
Path({}).write_text("usage_usec 1201\n")
print("[]")
"#, json!(release), json!(release.join("encounter")), json!(cpu)))?;

    let source = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects").canonicalize()?;
    let policy = evaluator(&source)?;
    let mut supervisor = Supervisor::new();
    let run_probe = |release: &Path| capacity_observation(&app, release, &group);
    let verified = capacity_decision(&mut supervisor, &active, &policy, run_probe, || Ok(vec![]))?;
    assert_eq!(verified["report"]["summary"]["mixed-cpu"], 2);
    assert_eq!(verified["report"]["summary"]["mixed-ram"], 1024);
    assert_eq!(verified["completed"], false); // The browser fixture omitted the three latency series.
    assert!(verified["context"]["release"].as_str().is_some_and(|id| id.starts_with("candidate / ")));

    fs::write(&probe, "print('[]')\nraise SystemExit(1)\n")?;
    let failed = capacity_decision(&mut supervisor, &active, &policy, run_probe, || Ok(vec![]))?;
    assert_eq!(failed["report"]["samples"], json!([]));
    assert_eq!(failed["completed"], false);

    let stale = capacity_decision(&mut supervisor, &active, &policy, run_probe, || {
        fs::write(&receipt, "replacement receipt")?;
        Ok(vec![])
    }).expect_err("A replaced receipt must invalidate the capacity report");
    assert_eq!(stale.to_string(), "Active AppDev release changed before capacity reporting");
    Ok(())
}

fn release_name(release: &Path, pin: &[u8; 32]) -> Result<String> {
    let name = if release.ends_with("system") { release.parent().and_then(Path::file_name) } else { release.file_name() };
    let name = name.and_then(|name| name.to_str()).ok_or_else(|| fail("Expected a release name"))?;
    Ok(format!("{name} / {}", hex::encode(&pin[..6])))
}

fn journal_history(policy: &Evaluator, capacity: bool) -> Result<Vec<Value>> {
    match crate::appdev_sweep_journal::entries(Some(capacity)) {
        Ok(entries) => project_sweep_history(policy, entries, Some(capacity)),
        Err(error) if crate::appdev_host_process::interruption().is_some() => Err(error),
        Err(_) => Ok(Vec::new()),
    }
}

pub(crate) fn mailbox_history(policy: &Evaluator) -> Result<Vec<Value>> {
    let entries = crate::appdev_sweep_journal::entries(None)?;
    let history = project_sweep_history(policy, entries, None)?;
    if history.is_empty() { return Err(fail("No admitted sweep journal history")); }
    Ok(history)
}

fn running_executable(unit: &str) -> Result<PathBuf> {
    let services = SystemServices::open()?;
    let pid = services.main_pid(unit)?;
    let executable = PathBuf::from(format!("/proc/{pid}/exe")).canonicalize()?;
    if services.main_pid(unit)? != pid { return Err(fail("Sweep service changed its main process")); }
    Ok(executable)
}

fn index_memory() -> Vec<Value> {
    let mut samples = Vec::new();
    let Ok(services) = SystemServices::open() else { return samples; };
    for sample in 0..3 {
        if sample != 0 { std::thread::sleep(Duration::from_secs(2)); }
        let watcher = services.measurement("sourcery-home-file-index-watch.service");
        let reader = services.measurement("sourcery-home-file-index-view.service");
        let (Ok(watcher), Ok(reader)) = (watcher, reader) else { break; };
        samples.push(json!({"pids":[watcher.pid,reader.pid],"bytes":[watcher.memory_current,reader.memory_current],
            "states":[watcher.active_state,reader.active_state]}));
    }
    samples
}

#[cfg(test)]
#[test]
fn launch_memory_samples_require_active_stable_services() -> Result<()> {
    let app = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects").canonicalize()?;
    let policy = evaluator(&app)?;
    let sample = |reader_state: &str| json!({"pids":[10,20],"bytes":[100,200],"states":["active",reader_state]});
    let report = |samples| -> Result<Value> {
        let result = policy.run("launch.finish", json!({
            "release":"fixture","stamp":1000,"history":[],
            "probes":{"indexMemory":samples,"cold":[],"idle":[],"hosted":null,"fixture":null,
                "startup":null,"work":null,"workFailure":null,"assurance":null,"badge":null,
                "hostedPassed":false,"fixturePassed":false}
        }))?;
        result["reports"].as_array().and_then(|reports| reports.iter()
            .find(|report| report["scope"] == "encounter-resource-performance")).cloned()
            .ok_or_else(|| fail("Missing resource performance report"))
    };
    let active = sample("active");
    let measured = report(vec![active.clone(),active.clone(),active.clone()])?;
    assert_eq!(measured["samples"].as_array().unwrap().len(), 3);
    assert_eq!(measured["summary"]["fileIndexMedianBytes"], 300);
    assert_eq!(report(vec![active.clone(),sample("inactive"),active])?["samples"], json!([]));
    Ok(())
}

fn launch_probe(app: &Path, release: &Path, policy: &Evaluator, plan: &Value, observations: &mut Value) -> Result<()> {
    let field = |name: &str| plan[name].as_str().ok_or_else(|| fail(format!("Invalid Encounter launch probe {name}")));
    let probe = field("probe")?;
    let mut command = match field("runner")? {
        "node" => {
            let script = Path::new(field("script")?);
            if !script.starts_with("verification") || script.extension().is_none_or(|suffix| suffix != "mjs")
                || !script.components().all(|part| matches!(part, Component::Normal(_))) {
                return Err(fail("Expected an AppDev verification module"));
            }
            let mut command = Command::new("/usr/bin/node");
            command.arg(app.join(script)).args(strings(&plan["args"])?);
            if plan["appendRelease"] == true { command.arg(release); }
            if plan["indexRuntime"] == true {
                let Ok(runtime) = running_executable("sourcery-home-file-index-watch.service") else { return Ok(()); };
                command.env("ENCOUNTER_INDEX_RUNTIME", runtime);
            }
            command
        }
        "work" => {
            let browser = running_executable("appdev-life-board-browser.service").ok();
            let gateway = running_executable("appdev-life-board-gateway.service").ok();
            let decision = policy.run("launch.work", json!({"browser":browser,"gateway":gateway,
                "release":release,"bundled":release.join("work/package-receipt.rel").is_file()}))?;
            let mut command = match decision["mode"].as_str() {
                Some("unavailable") => {
                    observations["workFailure"] = decision["reason"].clone();
                    return Ok(());
                }
                Some("system") => observation_command(app, release, "--system-work-performance"),
                Some("standalone") => {
                    let work = browser.as_deref().and_then(Path::parent).ok_or_else(|| fail("Missing Work browser package"))?;
                    let standalone = match crate::appdev_workflow::configured_standalone_work_policy(app) {
                        Ok(policy) => policy,
                        Err(error) if crate::appdev_host_process::interruption().is_some() => return Err(error),
                        Err(error) => {
                            observations["workFailure"] = json!(error.to_string());
                            return Ok(());
                        }
                    };
                    let mut command = observation_command(app, release, "--work-performance");
                    command.arg(work).arg("--work-gateway-policy").arg(standalone)
                        .arg("--enforce-work-budget");
                    command
                }
                _ => return Err(fail("Invalid Encounter Work probe decision")),
            };
            command.env("APPDEV_RELEASE_RUNTIME", gateway.ok_or_else(|| fail("Missing Work gateway executable"))?);
            command
        }
        "workspace" => {
            let mut command = observation_command(app, release, field("mode")?);
            command.env_remove("ENCOUNTER_RELEASE_PERFORMANCE_GATE");
            command
        }
        "index-memory" => {
            observations["indexMemory"] = json!(index_memory());
            return Ok(());
        }
        _ => return Err(fail("Unknown Encounter launch probe runner")),
    };
    let expected = field("scope")?;
    profile(&mut command, app);
    command.stdin(Stdio::null());
    let captured = Supervisor::children().capture_status(probe, &mut command, Duration::from_secs(115), OUTPUT_LIMIT);
    let (passed, rows) = match captured {
        Ok((status, output)) => (status.success(), json_observations(&output).unwrap_or_default()),
        Err(error) if crate::appdev_host_process::interruption().is_some() => return Err(error),
        Err(error) => { eprintln!("{error}"); (false, Vec::new()) }
    };
    let report = match rows.as_slice() {
        [row] if expected.is_empty() && row.is_array() => Some(row),
        [row] if !expected.is_empty() && row["scope"] == expected => Some(row),
        _ => None,
    };
    if let Some(row) = report {
        observations[probe] = row.clone();
    }
    if let Some(status) = plan["status"].as_str() {
        observations[status] = json!(passed && report.is_some_and(|row| row["passed"] == true));
    }
    Ok(())
}

pub fn launch_sweep(app: &Path) -> Result<()> {
    let mut supervisor = Supervisor::new();
    let app = app.canonicalize()?;
    let policy = evaluator(&app)?;
    let verdict = launch_decision(&mut supervisor, Path::new(ACTIVE), &policy,
        |release, probe, observations| launch_probe(&app, release, &policy, probe, observations),
        || journal_history(&policy, false))?;
    for report in verdict["reports"].as_array().ok_or_else(|| fail("Invalid Encounter launch sweep reports"))? {
        println!("{report}");
    }
    if verdict["completed"] != true { return Err(fail("Launch sweep evidence was incomplete or a launcher failed")); }
    Ok(())
}

fn launch_decision(supervisor: &mut Supervisor, active: &Path, policy: &Evaluator,
    mut observe: impl FnMut(&Path, &Value, &mut Value) -> Result<()>,
    mut history: impl FnMut() -> Result<Vec<Value>>) -> Result<Value> {
    let probes = policy.run("launch.probes", Value::Null)?;
    let probes = probes.as_array().ok_or_else(|| fail("Invalid Encounter launch sweep plan"))?;
    'attempt: for _ in 0..2 {
        let release = active.canonicalize()?;
        let pin = receipt_pin(&release)?;
        let matches = || Ok::<_, Box<dyn std::error::Error>>(
            active.canonicalize().is_ok_and(|target| target == release) && receipt_pin(&release)? == pin);
        let mut observations = json!({"hosted":null,"fixture":null,"startup":null,"work":null,"assurance":null,
            "badge":null,"workFailure":null,"cold":[],"idle":[],"indexMemory":[],"hostedPassed":false,"fixturePassed":false});
        for entry in probes {
            supervisor.check()?;
            observe(&release, entry, &mut observations)?;
            if entry["recheck"] == true && !matches()? { continue 'attempt; }
        }
        let stamp = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
        let history = history()?;
        let verdict = policy.run("launch.finish", json!({"release":release_name(&release,&pin)?,
            "stamp":stamp,"history":history,"probes":observations}))?;
        supervisor.check()?;
        if !matches()? { continue; }
        return Ok(verdict);
    }
    Err(fail("Encounter release changed during both sweep attempts"))
}

#[cfg(test)]
#[test]
fn launch_sweep_discards_observations_on_release_switch() -> Result<()> {
    use crate::appdev_host_process::Scratch;
    use std::os::unix::fs::symlink;

    let fixture = Scratch::create(&std::env::temp_dir(), "appdev-launch-sweep-")?;
    let active = fixture.path().join("active");
    let previous = fixture.path().join("previous");
    let current = fixture.path().join("current");
    for release in [&previous, &current] {
        fs::create_dir(release)?;
        fs::write(release.join("package-receipt.rel"), release.as_os_str().as_encoded_bytes())?;
    }
    symlink(&previous, &active)?;
    let switch = |release: &Path| -> Result<()> {
        let link = fixture.path().join("pending");
        symlink(release, &link)?;
        Ok(fs::rename(link, &active)?)
    };
    let app = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects").canonicalize()?;
    let policy = evaluator(&app)?;
    let driver = "/usr/local/libexec/sourcery-appdev-activate-system";
    let work = |bundled, browser, gateway| policy.run("launch.work", json!({
        "bundled":bundled,"release":"/srv/encounter-apps/system","browser":browser,"gateway":gateway
    }));
    assert_eq!(work(true, "/srv/encounter-apps/system/work/encounter", driver)?["mode"], "system");
    assert_eq!(work(false, "/srv/encounter-apps/previous-work/encounter", driver)?["mode"], "standalone");
    assert_eq!(work(false, "/srv/encounter-apps/previous-work/encounter", "/srv/encounter-apps/previous-gateway/encounter")?["mode"],
        "unavailable");
    let verdict = launch_decision(&mut Supervisor::children(), &active, &policy, |release, probe, observed| {
        if probe["probe"] == "hosted" { observed["hosted"] = json!({"scope":"hosted","release":release}); }
        if probe["probe"] == "fixture" && release == previous { switch(&current)?; }
        Ok(())
    }, || Ok(Vec::new()))?;
    assert_eq!(verdict["reports"][0]["release"], json!(current));
    assert!(launch_decision(&mut Supervisor::children(), &active, &policy, |release, probe, _| {
        if probe["probe"] == "fixture" { switch(if release == current { &previous } else { &current })?; }
        Ok(())
    }, || Ok(Vec::new())).unwrap_err().to_string().contains("both sweep attempts"));
    Ok(())
}

#[cfg(test)]
#[test]
fn launch_probe_runs_declared_fixture_and_admits_only_its_report() -> Result<()> {
    use crate::appdev_host_process::Scratch;

    let staged = Scratch::create(&std::env::temp_dir(), "appdev-launch-plan-")?;
    let app = staged.path().join("projects/applications/appdev-projects");
    let scripts = app.join("verification/sourcery-home");
    fs::create_dir_all(&scripts)?;
    let release = staged.path().join("system");
    fs::create_dir(&release)?;
    fs::write(scripts.join("launch-sweep.mjs"), format!(r#"
import assert from 'node:assert/strict';
assert.deepEqual(process.argv.slice(2), ['--summary', {}]);
console.log(JSON.stringify({{scope:'fixture', passed:true}}));
"#, json!(release)))?;

    let source = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects").canonicalize()?;
    let policy = evaluator(&source)?;
    let plan = policy.run("launch.probes", Value::Null)?;
    let fixture = plan.as_array().and_then(|probes| probes.iter().find(|probe| probe["probe"] == "fixture"))
        .ok_or_else(|| fail("The launch plan has no fixture probe"))?;
    let mut observed = json!({});
    launch_probe(&app, &release, &policy, fixture, &mut observed)?;
    assert_eq!(observed, json!({"fixture":{"scope":"fixture","passed":true},"fixturePassed":true}));

    fs::write(scripts.join("launch-sweep.mjs"), "console.log(JSON.stringify({scope:'hosted',passed:true}));")?;
    let mut observed = json!({});
    launch_probe(&app, &release, &policy, fixture, &mut observed)?;
    assert_eq!(observed, json!({"fixturePassed":false}));

    fs::write(scripts.join("launch-sweep.mjs"), "console.log(JSON.stringify({scope:'fixture',passed:false}));")?;
    let mut observed = json!({});
    launch_probe(&app, &release, &policy, fixture, &mut observed)?;
    assert_eq!(observed, json!({"fixture":{"scope":"fixture","passed":false},"fixturePassed":false}));

    let routes = app.join("verification/workspace-routes");
    fs::create_dir_all(&routes)?;
    fs::write(routes.join("verify.py"), format!(r#"
import os, sys
assert sys.argv[1:] == ["--candidate", {}, "--idle-bridge"]
assert os.environ["APPDEV_RELEASE_RUNTIME"] == {}
assert "ENCOUNTER_RELEASE_PERFORMANCE_GATE" not in os.environ
print('[{{"check":"work-idle-bridge","value":0}}]')
"#, json!(release), json!(release.join("encounter"))))?;
    let idle = plan.as_array().and_then(|probes| probes.iter().find(|probe| probe["probe"] == "idle"))
        .ok_or_else(|| fail("The launch plan has no idle probe"))?;
    let mut observed = json!({});
    launch_probe(&app, &release, &policy, idle, &mut observed)?;
    assert_eq!(observed, json!({"idle":[{"check":"work-idle-bridge","value":0}]}));
    Ok(())
}

#[cfg(test)]
#[test]
fn registry_gate_binds_probe_output_to_work_evidence() -> Result<()> {
    use crate::{appdev_host_process::Scratch, rel::Facts};
    use std::{env, fs};

    let fixture = Scratch::create(&env::temp_dir(), "appdev-measurements-")?;
    let projects = fixture.path().join("projects");
    let app = projects.join("applications/appdev-projects");
    let verification = app.join("verification");
    let performance = verification.join("performance");
    let routes = verification.join("workspace-routes");
    fs::create_dir_all(&performance)?;
    fs::create_dir_all(&routes)?;
    let source = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects/verification/performance");
    for name in ["measurements.rel", "measurements.encounter", "capacity-sweep.encounter", "launch-sweep.encounter",
        "mailbox-model.encounter", "performance-checks.rel"] {
        fs::copy(source.join(name), performance.join(name))?;
    }
    let registry = Facts::read(&performance.join("performance-checks.rel"))?;
    let resource_prefix = "encounter-resource-performance/";
    let idle = registry.0.iter().filter_map(|[subject, field, value]| {
        (field == "releaseGate" && value == "true").then(|| subject.strip_prefix(resource_prefix)).flatten()
    }).map(|id| json!({"check":id,"value":0})).collect::<Vec<_>>();
    let bytes = |scope: &str| -> Result<Value> {
        let fields = registry.one(scope, "fields")?;
        let samples = registry.0.iter().filter_map(|[subject, field, _]| {
            (field == "budget").then(|| subject.strip_prefix(scope)?.strip_prefix('/')).flatten()
        }).map(|check| {
            let mut row = json!({"check":check,"contentMismatch":0});
            for field in fields.split(',') { row[field] = json!(0); }
            row
        }).collect::<Vec<_>>();
        Ok(json!({"scope":scope,"samples":samples}))
    };
    let home = json!({"scope":"hosted-startup","samples":[
        {"bridgeDelayMs":100,"openMs":999,"exchanges":2},{"bridgeDelayMs":200,"openMs":999,"exchanges":2}
    ]});
    let mut work = json!({"scope":"encounter-work-startup","samples":[
        {"delayMs":100,"openMs":999,"exchanges":2},{"delayMs":200,"openMs":999,"exchanges":2}
    ]});
    let reports = json!({"--idle-bridge":[home,idle],
        "--assurance-bytes":[bytes("encounter-mobile-assurance-bytes")?],
        "--badge-bytes":[bytes("encounter-performance-badge-bytes")?]});
    fs::write(routes.join("verify.py"), format!(
        "import json, sys\nfor report in json.loads({encoded})[sys.argv[-1]]:\n    print(json.dumps(report))\n",
        encoded = json!(reports.to_string())))?;
    let evidence = fixture.path();
    fs::write(evidence.join("work.json"), work.to_string())?;
    verify(&mut Supervisor::children(), &app, fixture.path(), evidence)?;
    work["samples"][0]["openMs"] = json!(1000);
    fs::write(evidence.join("work.json"), work.to_string())?;
    assert!(verify(&mut Supervisor::children(), &app, fixture.path(), evidence)
        .unwrap_err().to_string().contains("Work at 100 ms: Regression"));
    Ok(())
}
