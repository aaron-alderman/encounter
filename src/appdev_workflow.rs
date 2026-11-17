use crate::{
    Result, appdev_assurance::{self, RECEIPT, SYSTEM_POLICY, fingerprint, fingerprint_package, system_package},
    appdev_host_process::{Scratch, ServiceTool, Supervisor, rename_new_path}, appdev_release, command, fail, rel::Facts,
};
use serde_json::{Value, json};
use crate::systemd_user_service::{self, ReleaseServiceChange};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, ffi::CStr, fs, io,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::{fs::{MetadataExt, OpenOptionsExt, symlink}, process::CommandExt}},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const ACTIVE: &str = "/var/www/appdev-projects/workspace";
const INSTALLED: &str = "/srv/encounter-apps";
const SYSTEM_DRIVER: &str = "/usr/local/libexec/sourcery-appdev-activate-system";
const LEGACY_SYSTEM_DRIVER: &str = "/usr/local/libexec/sourcery-appdev-activate-system-legacy";
const RELEASE_LOCK: &str = "/run/lock/sourcery-home-release.lock";
const LIVE_FORMATION_CHECK: &str = "verification/sourcery-home/live-formation.rel";
const MAILBOX_FIXTURE_FILES: [&str; 3] = ["dev-jobs/performance-mailbox.rel",
    "dev-jobs/performance-mailbox.encounter", "dev-jobs/performance-mailbox.nginx.conf"];
const BROWSER_PROFILE: &str = "env/chrome-profile.json";
const FRONTEND_VERIFICATION_FILES: &[&str] = &[
    "bin/browser-profile.mjs",
    "projects/encounter-core/tests/browser-clients-wasm.mjs",
    "projects/encounter-platform/applications/front-gate/pilot.rel",
    "projects/encounter-platform/applications/front-gate/pilot.encounter",
    "projects/encounter-platform/applications/front-gate/pilot-presentation.encounter",
    "projects/applications/encounter-libraries/workflows/sourcery-presentation.encounter",
    "projects/release-rollouts/pilot-review-trips.v95v7AoI/pilot/live.rel",
    "projects/release-rollouts/pilot-review-trips.v95v7AoI/pilot/live.image.rel",
    "builds/encounter-releases/pilot-windows-presentation.dhQVpV/encounter",
];
const CO_BUILD_DECLARATION: &str = "encounter-co-build/application.rel";
const BROWSER_DECLARATION: &str = "browser-programme/applications/appdev-projects/browser.rel";
const ASSURANCE_DESCRIPTOR: &str = "browser-programme/applications/appdev-projects/assurance-catalogue-version.rel";
const WORK_GATEWAY_DECLARATION: &str = "gateway.rel";
const WORK_GATEWAY_PROFILE: &str = "encounter/life-board-gateway/1";

fn plan(workflow: &command::Evaluator, facts: &Facts, operation: &str, preview_check: bool) -> Result<Value> {
    workflow.run("release.plan", json!({
        "facts":facts.0, "operation":operation, "previewCheck":preview_check
    }))
}

pub(crate) fn strings(value: &Value) -> Result<Vec<&str>> {
    value.as_array().ok_or_else(|| fail("Expected an Encounter list"))?.iter()
        .map(|value| value.as_str().ok_or_else(|| fail("Expected Encounter text"))).collect()
}

pub fn temporary_root(app: &Path) -> PathBuf {
    if let Some(root) = env::var_os("TMPDIR") { return PathBuf::from(root); }
    let short = app.ancestors().nth(3).and_then(Path::file_name).and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("dev-"));
    if let (Some(home), Some(name)) = (env::var_os("HOME"), short) {
        let path = PathBuf::from(home).join(format!(".aaron-dev-tmp-{name}"));
        if path.is_dir() { return path; }
    }
    env::temp_dir()
}

pub fn profile(command: &mut Command, app: &Path) {
    if let Some(root) = app.ancestors().nth(3) {
        command.env("DEV_ROOT", root)
            .env("PLAYWRIGHT_BROWSERS_PATH", root.join("env/browsers"))
            .env("ENCOUNTER_PLAYWRIGHT", root.join("bin/browser-profile.cjs"));
    }
    command.env("TMPDIR", temporary_root(app));
}

fn package(path: &Path) -> Result<PathBuf> {
    let path = path.canonicalize()?;
    if !path.join("package-receipt.rel").is_file() {
        return Err(fail("Expected a staged AppDev package with its runtime and receipt"));
    }
    crate::package::require_native_runtime(&path.join("encounter"))?;
    Ok(path)
}

fn verification_digest(app: &Path) -> Result<String> {
    if !app.join(LIVE_FORMATION_CHECK).is_file() {
        return Err(fail("The AppDev verification suite is missing the live Temple Manager check"));
    }
    let mut directories = ["release", "preview", "verification"].map(|name| app.join(name)).to_vec();
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                if entry.file_name() != "__pycache__" { directories.push(entry.path()); }
            } else if kind.is_file() {
                files.push(entry.path());
            } else {
                return Err(fail("AppDev verification artifacts must be regular files or directories"));
            }
        }
    }
    files.sort_unstable();
    let mut suite = Sha256::new();
    for file in files {
        let name = file.strip_prefix(app)?.to_str().ok_or_else(|| fail("Expected a UTF-8 verification path"))?;
        suite.update(name.as_bytes());
        suite.update([0]);
        suite.update(Sha256::digest(fs::read(file)?));
    }
    let workspace = app.ancestors().nth(3).ok_or_else(|| fail("Expected the AppDev development workspace"))?;
    suite.update(b"encounter/native-browser-check/1\0");
    suite.update(Sha256::digest(include_bytes!("browser_check.rs")));
    suite.update(b"encounter/native-decompiler-check/1\0");
    suite.update(Sha256::digest(include_bytes!("decompiler_check.rs")));
    suite.update(Sha256::digest(include_bytes!("http.rs")));
    suite.update(b"encounter/native-workspace-route-check/1\0");
    suite.update(Sha256::digest(include_bytes!("appdev_route_check.rs")));
    suite.update(Sha256::digest(include_bytes!("http_client.rs")));
    suite.update(b"encounter/native-performance-mailbox-fixture/1\0");
    suite.update(Sha256::digest(include_bytes!("appdev_mailbox.rs")));
    for file in MAILBOX_FIXTURE_FILES {
        suite.update(Sha256::digest(fs::read(app.join(file))?));
    }
    suite.update(b"encounter/appdev-assurance-policy/1\0");
    for source in appdev_assurance::POLICY_SOURCES { suite.update(Sha256::digest(source)); }
    suite.update(Sha256::digest(include_bytes!("appdev_assurance.rs")));
    suite.update(Sha256::digest(fs::read(workspace.join(BROWSER_PROFILE))?));
    let mut frontend_files: Vec<_> = FRONTEND_VERIFICATION_FILES.iter().map(PathBuf::from).collect();
    let applications = Path::new("projects/applications");
    let co_build = applications.join(CO_BUILD_DECLARATION);
    let declaration = Facts::read(&workspace.join(&co_build))?;
    frontend_files.push(co_build);
    for [subject, property, source] in &declaration.0 {
        let extension = match (subject.as_str(), property.as_str()) {
            ("application", "module") => "encounter",
            ("application", "dataSource") => "rel",
            (subject, "source") if subject.starts_with("data.") => "rel",
            _ => continue,
        };
        crate::application::validate_path(source, extension)?;
        frontend_files.push(applications.join(source));
    }
    frontend_files.sort_unstable();
    frontend_files.dedup();
    for file in frontend_files {
        let name = file.to_str().ok_or_else(|| fail("Expected a UTF-8 verification path"))?;
        suite.update(name.as_bytes());
        suite.update([0]);
        suite.update(Sha256::digest(fs::read(workspace.join(file))?));
    }
    Ok(hex::encode(suite.finalize()))
}

fn system_performance(home: &Path, evidence: &Path, fingerprint: &str) -> Result<Vec<[String; 3]>> {
    let read = |name| -> Result<Value> {
        const LIMIT: usize = 256 * 1024;
        let mut bytes = Vec::new();
        fs::File::open(evidence.join(name))?.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > LIMIT { return Err(fail("AppDev performance evidence exceeded its size limit")); }
        Ok(serde_json::from_slice(&bytes)?)
    };
    appdev_assurance::performance_rows(json!({
        "releaseSha256":fingerprint, "policy":appdev_assurance::read_facts(&home.join(SYSTEM_POLICY))?.0,
        "home":read("home.json")?, "work":read("work.json")?, "journeys":read("journeys.json")?
    }))
}

fn verify_package_pins(workflow: &command::Evaluator, home: &Path, system: bool,
    artifacts: &BTreeMap<String, String>) -> Result<()> {
    let directory = fs::File::open(home)?;
    let read = |name: &str| -> Result<String> {
        const LIMIT: usize = 1_000_000;
        let mut bytes = Vec::new();
        crate::package::open_artifact(&directory, Path::new(name))?
            .take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > LIMIT { return Err(fail("AppDev release metadata exceeded its size limit")); }
        if artifacts.get(name) != Some(&crate::rel::hash(&bytes)) {
            return Err(fail(format!("AppDev release metadata changed while reading {name}")));
        }
        Ok(String::from_utf8(bytes)?)
    };
    let package = Facts::parse(&read("package-receipt.rel")?)?;
    let browser = Facts::parse(&read(BROWSER_DECLARATION)?)?;
    let work = system.then(|| -> Result<_> {
        Ok(Facts::parse(&read("work/package-receipt.rel")?)?.0)
    }).transpose()?;
    let descriptor = artifacts.contains_key(ASSURANCE_DESCRIPTOR).then(|| read(ASSURANCE_DESCRIPTOR)).transpose()?;
    if workflow.run("release.packagePins", json!({
        "artifacts":artifacts, "system":system, "package":package.0, "browser":browser.0,
        "work":work, "descriptor":descriptor, "descriptorPath":ASSURANCE_DESCRIPTOR
    }))? != true {
        return Err(fail("Encounter did not admit the AppDev package pins"));
    }
    Ok(())
}

fn require_verification(app: &Path, receipt: &Facts) -> Result<()> {
    let source = app.to_str().ok_or_else(|| fail("Expected a UTF-8 verification root"))?;
    appdev_assurance::verification_binding(receipt, Some((source, &verification_digest(app)?)))?;
    Ok(())
}

pub fn deploy_verified(requested: &Path) -> Result<()> {
    let requested = package(requested)?;
    let receipt = appdev_assurance::read_facts(&requested.join(RECEIPT))?;
    let binding = appdev_assurance::verification_binding(&receipt, None)?;
    let app = binding["source"].as_str().ok_or_else(|| fail("Expected the verification source path"))?;
    release(Path::new(app), "deploy-system", &requested)
}

const WORKSPACE_REQUEST_ZONE: &str = "appdev_workspace_requests";
const INGRESS_RATE: &str = "/etc/nginx/conf.d/appdev-workspace-limits.conf";
const INGRESS_BURSTS: &[&str] = &[
    "/etc/nginx/sites-enabled/temple2-sourcery",
    "/etc/nginx/snippets/appdev-workspace.conf",
    "/etc/nginx/snippets/appdev-temple-startup.conf",
    "/etc/nginx/snippets/performance-mailbox.conf",
    "/etc/nginx/snippets/sourcery-aster-kernel-origin.conf",
    "/etc/nginx/snippets/sourcery-aster-kernel-assets.conf",
];

fn ingress_directives(config: &str) -> Vec<Vec<&str>> {
    let mut directives = Vec::new();
    let mut words = Vec::new();
    for line in config.lines() {
        let line = line.split_once('#').map_or(line, |(prefix, _)| prefix);
        for part in line.split_inclusive([';', '{', '}']) {
            if let Some(statement) = part.strip_suffix([';', '{', '}']) {
                words.extend(statement.split_whitespace());
                directives.push(std::mem::take(&mut words));
            } else {
                words.extend(part.split_whitespace());
            }
        }
    }
    directives
}

fn ingress_cooldown(rate_config: &str, burst_configs: &[String]) -> Result<std::time::Duration> {
    let zone = format!("zone={WORKSPACE_REQUEST_ZONE}");
    let rate_zone = format!("{zone}:");
    let mut rates = ingress_directives(rate_config).into_iter().filter(|words| {
        words.first() == Some(&"limit_req_zone") && words.iter().any(|word| word.starts_with(&rate_zone))
    });
    let rate = rates.next().filter(|_| rates.next().is_none())
        .and_then(|words| words.into_iter().find_map(|word| word.strip_prefix("rate=")))
        .ok_or_else(|| fail("Expected one AppDev workspace ingress rate"))?;
    let (rate, seconds) = rate.strip_suffix("r/s").map(|value| (value, 1))
        .or_else(|| rate.strip_suffix("r/m").map(|value| (value, 60)))
        .ok_or_else(|| fail("Expected an AppDev ingress rate in r/s or r/m"))?;
    // Nginx stores the rate in thousandths of a request per second.
    let rate = rate.parse::<u64>()?.checked_mul(1000).map(|value| value / seconds)
        .filter(|value| *value > 0).ok_or_else(|| fail("Invalid AppDev ingress rate"))?;

    let burst = burst_configs.iter().flat_map(|config| ingress_directives(config))
        .filter(|words| words.first() == Some(&"limit_req") && words.contains(&zone.as_str()))
        .map(|words| words.into_iter().find_map(|word| word.strip_prefix("burst="))
            .unwrap_or("0").parse::<u64>())
        .try_fold(None::<u64>, |maximum, burst| burst.map(|burst| Some(maximum.unwrap_or(0).max(burst))))?
        .ok_or_else(|| fail("Expected an AppDev workspace ingress burst directive"))?;
    let drain = burst.checked_add(1).and_then(|value| value.checked_mul(1_000_000))
        .ok_or_else(|| fail("Invalid AppDev ingress burst"))?;
    Ok(std::time::Duration::from_millis(drain.div_ceil(rate)))
}

fn live_ingress_cooldown(release: &Path) -> Result<std::time::Duration> {
    let rate = fs::read_to_string(INGRESS_RATE)?;
    let mut bursts = INGRESS_BURSTS.iter().map(fs::read_to_string).collect::<io::Result<Vec<_>>>()?;
    for file in ["formation/records.nginx.conf", "shop/appdev.nginx.conf"] {
        bursts.push(fs::read_to_string(release.join(file))?);
    }
    ingress_cooldown(&rate, &bursts)
}

fn live_formation(app: &Path, expected: &Path) -> Result<()> {
    let lock = fs::File::open(RELEASE_LOCK)?;
    let started = std::time::Instant::now();
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 { break; }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock { return Err(error.into()); }
        if crate::appdev_host_process::interruption().is_some() || started.elapsed().as_secs() >= 30 {
            return Err(fail("Could not acquire the AppDev release lock for the live check"));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let cooldown = live_ingress_cooldown(expected)?;
    let result = crate::browser_check::run(app, LIVE_FORMATION_CHECK, expected, Path::new(ACTIVE), &temporary_root(app));
    // Keep the lock while the shared ingress burst drains, including after a failed run.
    println!("Home smoke ingress cooldown: {} ms", cooldown.as_millis());
    std::thread::sleep(cooldown);
    drop(lock);
    result
}

pub fn check_live_formation(app: &Path, expected: &Path) -> Result<()> {
    let _supervisor = Supervisor::new();
    live_formation(&app.canonicalize()?, expected)
}

fn gates(supervisor: &mut Supervisor, app: &Path, workflow: &command::Evaluator,
    home: &Path, work: Option<&Path>, gates: &[&str]) -> Result<()> {
    let measurements = if gates.contains(&"system-journeys") {
        Some(Scratch::create(&temporary_root(app), "appdev-system-measurements-")?)
    } else { None };
    let system = system_package(home);
    let installed = home.starts_with(INSTALLED);
    let require_receipt = installed || (system && measurements.is_none());
    let verification = if system && measurements.is_some() { Some(verification_digest(app)?) } else { None };
    if measurements.is_some() && !home.join(SYSTEM_POLICY).is_file() {
        return Err(fail("Expected a staged system package with its performance policy"));
    }
    if system && (installed || measurements.is_none()) {
        appdev_assurance::require(home)?;
    }
    let mut artifacts = BTreeMap::new();
    let home_digest = appdev_assurance::hash_package(home, Some(RECEIPT), |path, digest| {
        artifacts.insert(path.to_owned(), hex::encode(digest));
    })?;
    verify_package_pins(workflow, home, system, &artifacts)?;
    let work_digest = work.map(|path| fingerprint_package(path, None)).transpose()?;
    let previous_clients = if gates.contains(&"frontend-csp-policy") && artifacts.contains_key("browser-wasm.rel") {
        env::var_os("APPDEV_FRONTEND_PREVIOUS_CLIENTS").map(|path| package(Path::new(&path))).transpose()?
    } else { None };
    let commands = workflow.run("release.verify", json!({
        "home":home, "work":work, "gates":gates,
        "homeWasm":artifacts.contains_key("browser-wasm.rel"),
        "workWasm":artifacts.contains_key("work/browser-wasm.rel"),
        "standaloneWasm":artifacts.contains_key(appdev_release::STANDALONE_CATALOG),
        "previousClients":previous_clients
    }))?;
    let mut interaction_receipt = None;
    let mut identity_report = if !installed && !system && !gates.contains(&"identity-assurance") {
        appdev_assurance::identity_report(home)?
    } else {
        None
    };
    for gate in commands.as_array().ok_or_else(|| fail("Expected a gate command list"))? {
        let label = gate["label"].as_str().ok_or_else(|| fail("Expected a gate label"))?;
        let args = strings(&gate["args"])?;
        println!("Running AppDev gate {label}");
        if gate["tool"] == "decompiler-mount" {
            supervisor.check()?;
            if !args.is_empty() { return Err(fail("Unexpected arguments for Decompiler mount gate")); }
            crate::decompiler_check::release_mount(workflow)?;
            continue;
        }
        if gate["tool"] == "decompiler-paging" {
            supervisor.check()?;
            if !args.is_empty() { return Err(fail("Unexpected arguments for Decompiler paging gate")); }
            crate::decompiler_check::release_paging(app, workflow)?;
            continue;
        }
        if gate["tool"] == "registry-performance" {
            supervisor.check()?;
            if !args.is_empty() { return Err(fail("Unexpected arguments for registry performance gate")); }
            let evidence = measurements.as_ref().ok_or_else(|| fail("Registry performance requires system measurements"))?;
            crate::appdev_performance::verify(supervisor, app, home, evidence.path())?;
            continue;
        }
        if gate["tool"] == "identity-assurance" {
            supervisor.check()?;
            let sources = app.ancestors().nth(2).ok_or_else(|| fail("Expected the Encounter project source root"))?;
            let [declaration, mode] = args.as_slice() else { return Err(fail("Invalid Identity Assurance command")); };
            let (output, status) = command::source_report(sources, declaration, &[(*mode).to_owned()], false)?;
            println!("{output}");
            if status != 0 { return Err(fail(format!("{label} failed (exit status: {status})"))); }
            let report: Value = serde_json::from_str(&output)?;
            if report["status"] != "pass" { return Err(fail("Expected passing Identity Assurance evidence")); }
            if installed && let Some(saved) = appdev_assurance::identity_report(home)? && saved != report {
                return Err(fail("Identity Assurance evidence differs from the staged release receipt"));
            }
            identity_report = Some(report);
            continue;
        }
        if gate["tool"] == "assurance" {
            if !args.is_empty() { return Err(fail("Unexpected arguments for interaction Assurance")); }
            if require_receipt { appdev_release::check(home)?; }
            let mut browser = Supervisor::children();
            let origin = browser.start_assurance_browser(home)?;
            let mut command = Command::new("node");
            command.arg(app.join("verification/assurance/release-gate.mjs")).arg(home).arg(origin)
                .stdin(Stdio::null());
            profile(&mut command, app);
            command.env_remove("APPDEV_SYSTEM_MEASUREMENTS");
            let output = browser.capture(label, &mut command, Duration::from_secs(180), 64 * 1024)?;
            browser.check()?;
            drop(browser);
            let evidence: Value = serde_json::from_slice(&output)?;
            let mut rows = appdev_assurance::interaction_rows(&home_digest, evidence)?;
            if let Some(directory) = &measurements {
                rows.extend(system_performance(home, directory.path(), &home_digest)?);
            }
            if fingerprint(home)? != home_digest {
                return Err(fail("Candidate changed while Assurance was running"));
            }
            if require_receipt {
                appdev_release::check(home)?;
                println!("PASS: AppDev release interaction Assurance {home_digest}");
            } else {
                interaction_receipt = Some(rows);
            }
            continue;
        }
        let runtime = env::current_exe()?;
        let mut command = match gate["tool"].as_str() {
            Some("routes") => {
                let mut command = Command::new("python3");
                command.arg(app.join("verification/workspace-routes/verify.py"));
                command
            }
            _ => return Err(fail("Unknown AppDev gate tool")),
        };
        command.args(args);
        profile(&mut command, app);
        command.env("APPDEV_RELEASE_RUNTIME", &runtime);
        if gate["enforceFrontendCsp"] == true {
            command.env("ENCOUNTER_VERIFY_BROWSER_WASM", "1");
            command.env("ENCOUNTER_ENFORCE_BROWSER_CSP", "1");
        }
        command.env_remove("APPDEV_SYSTEM_MEASUREMENTS");
        if let Some(directory) = &measurements {
            command.env("APPDEV_SYSTEM_MEASUREMENTS", directory.path());
        }
        supervisor.run(label, &mut command)?;
    }
    let active = work.map(|_| Path::new(ACTIVE).canonicalize()).transpose()?;
    let after = work.map(|path| fingerprint_package(path, None)).transpose()?;
    let finished = workflow.run("release.finish", json!({
        "homeBefore":home_digest, "homeAfter":fingerprint(home)?, "work":work.is_some(),
        "workBefore":work_digest, "workAfter":after, "activeBefore":home, "activeAfter":active
    }))?;
    if finished != true { return Err(fail("Encounter did not admit the AppDev verification result")); }
    supervisor.check()?;
    if let Some(digest) = &verification && verification_digest(app)? != *digest {
        return Err(fail("The AppDev verification suite changed while its gates were running"));
    }
    if !installed && (interaction_receipt.is_some() || identity_report.is_some()) {
        let rows = match interaction_receipt {
            Some(rows) => rows,
            None => appdev_assurance::read_facts(&home.join(RECEIPT))?.0,
        };
        if fingerprint(home)? != home_digest {
            return Err(fail("The AppDev package changed before assurance publication"));
        }
        let parent = home.parent().ok_or_else(|| fail("Expected the package parent directory"))?;
        let publication = Scratch::create(parent, ".interaction-assurance-")?;
        let staged = publication.path().join(RECEIPT);
        let binding = if let Some(digest) = &verification {
            let source = app.to_str().ok_or_else(|| fail("Expected a UTF-8 verification root"))?;
            Some((source, digest.as_str()))
        } else { None };
        let rows = appdev_assurance::receipt_with_metadata(rows, binding, identity_report)?;
        let mut file = fs::File::create(&staged)?;
        for [subject, property, value] in rows {
            writeln!(file, "({}, {}, {})", json!(subject), json!(property), json!(value))?;
        }
        drop(file);
        appdev_release::check_staged_receipt(home, &staged)?;
        if fingerprint(home)? != home_digest {
            return Err(fail("The AppDev package changed during assurance publication"));
        }
        supervisor.check()?;
        fs::rename(staged, home.join(RECEIPT))?;
        if measurements.is_some() {
            println!("PASS: AppDev system release interaction Assurance {home_digest}");
        } else if !require_receipt {
            println!("PASS: AppDev release interaction Assurance {home_digest}");
        }
    }
    Ok(())
}

pub fn check_preview(supervisor: &mut Supervisor, app: &Path, workflow: &command::Evaluator,
    facts: &Facts, release: &Path) -> Result<()> {
    let plan = plan(workflow, facts, "check", true)?;
    if plan["candidate"] != "home" || plan["finish"] != "return" {
        return Err(fail("Invalid AppDev preview gate plan"));
    }
    gates(supervisor, app, workflow, &package(release)?, None, &strings(&plan["gates"])?)
}

fn work_system(work: &Path) -> Result<PathBuf> {
    let home = work.parent().filter(|parent| parent.join(SYSTEM_POLICY).is_file())
        .ok_or_else(|| fail("Expected Work inside a coordinated AppDev system package"))?;
    let home = package(home)?;
    if system_work(&home)? != work {
        return Err(fail("Expected the coordinated AppDev system's bundled Work package"));
    }
    Ok(home)
}

pub(crate) fn check_system_candidate_pins(app: &Path, home: &Path) -> Result<()> {
    package(home)?;
    system_work(home)?;
    let workflow = command::Evaluator::load(app, "release/workflow.rel")?;
    let mut artifacts = BTreeMap::new();
    appdev_assurance::hash_package(home, Some(RECEIPT), |path, digest| {
        artifacts.insert(path.to_owned(), hex::encode(digest));
    })?;
    verify_package_pins(&workflow, home, true, &artifacts)
}

pub fn stage_browser_wasm(app: &Path, sources: &Path, input: &Path, output: &Path, refresh_runtime: bool) -> Result<()> {
    const CATALOG: &str = "browser-wasm.rel";
    const PACKAGE_RECEIPT: &str = "package-receipt.rel";
    let app = app.canonicalize()?;
    let sources = sources.canonicalize()?;
    let input = package(input)?;
    let name = output.file_name().ok_or_else(|| fail("Choose a new AppDev candidate directory"))?;
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new(".")).canonicalize()?;
    let output = parent.join(name);
    if parent.starts_with(&input) || output.symlink_metadata().is_ok() {
        return Err(fail("Choose a new candidate directory outside the input package"));
    }
    system_work(&input)?;
    let workflow = command::Evaluator::load(&app, "release/workflow.rel")?;
    let mut artifacts = BTreeMap::new();
    let before = appdev_assurance::hash_package(&input, Some(RECEIPT), |path, digest| {
        artifacts.insert(path.to_owned(), hex::encode(digest));
    })?;
    verify_package_pins(&workflow, &input, true, &artifacts)?;
    let runtime_pin = crate::rel::hash(fs::read("/proc/self/exe")?);
    let rebuild = ["encounter", "work/encounter"].iter().any(|path| artifacts.get(*path) != Some(&runtime_pin));
    if rebuild && !refresh_runtime {
        return Err(fail("Stage browser Wasm with the Encounter runtime bundled in both packages"));
    }

    let scratch = Scratch::create(&parent, ".appdev-browser-wasm-")?;
    let staged = scratch.path().join("candidate");
    crate::network_build::copy_tree(&input, &staged)?;
    if fingerprint(&staged)? != before || fingerprint(&input)? != before {
        return Err(fail("Input AppDev package changed while copying"));
    }
    if rebuild {
        appdev_release::check_rebuild_input(&staged)?;
    } else if artifacts.contains_key(CATALOG) || artifacts.contains_key("work/browser-wasm.rel") {
        appdev_release::check_candidate(&staged)?;
    }
    let old_assurance = staged.join(RECEIPT);
    if old_assurance.is_file() { fs::remove_file(old_assurance)?; }
    let work = staged.join("work");
    let mut supervisor = Supervisor::new();
    let mut rebuilt_home = BTreeMap::new();
    let mut rebuilt_work = BTreeMap::new();
    let runtime = if rebuild {
        for package in [&staged, &work] {
            let executable = scratch.path().join("encounter");
            fs::copy("/proc/self/exe", &executable)?;
            fs::rename(executable, package.join("encounter"))?;
        }
        rebuilt_home.insert("encounter".to_owned(), runtime_pin.clone());
        rebuilt_home.insert("work/encounter".to_owned(), runtime_pin.clone());
        rebuilt_work.insert("encounter".to_owned(), runtime_pin.clone());
        let runtime = staged.join("encounter");
        let images: Vec<[String; 2]> = serde_json::from_value(workflow.run("release.runtimeBoundImages", json!(null))?)?;
        for [artifact, declaration] in images {
            crate::application::validate_path(&artifact, "rel")?;
            crate::application::validate_path(&declaration, "rel")?;
            let destination = staged.join(&artifact);
            let source = destination.parent().ok_or_else(|| fail("Missing packaged image source directory"))?.join("source");
            let image = scratch.path().join("runtime-bound-image.rel");
            let mut command = Command::new(&runtime);
            command.arg("build").arg(source).arg(declaration).arg(&image);
            let pin = supervisor.capture("AppDev runtime-bound image build", &mut command, Duration::from_secs(60), 256)?;
            let observed = crate::rel::hash(fs::read(&image)?);
            if std::str::from_utf8(&pin)?.trim() != observed {
                return Err(fail("Compiler output differs from the rebuilt AppDev image"));
            }
            fs::set_permissions(&image, fs::metadata(&destination)?.permissions())?;
            fs::rename(&image, destination)?;
            rebuilt_home.insert(artifact, observed);
        }
        runtime
    } else {
        env::current_exe()?
    };
    let mut catalog_pins = Vec::new();
    for (package, declaration, catalogue_name, module_directory) in [
        (&staged, "appdev.rel", CATALOG, "browser-wasm"),
        (&work, "work.rel", CATALOG, "browser-wasm"),
        (&staged, "standalone.rel", appdev_release::STANDALONE_CATALOG, appdev_release::STANDALONE_DIRECTORY),
    ] {
        let bundle = scratch.path().join(declaration);
        let mut command = Command::new(&runtime);
        command.args(["build", "--browser"]).arg(&sources).arg(declaration).arg(&sources).arg(&bundle);
        let pin = supervisor.capture("AppDev browser Wasm build", &mut command, Duration::from_secs(60), 256)?;
        let catalog = bundle.join(CATALOG);
        let observed = crate::rel::hash(fs::read(&catalog)?);
        if std::str::from_utf8(&pin)?.trim() != observed {
            return Err(fail("Compiler output differs from the browser Wasm catalog"));
        }
        if package.join(catalogue_name).is_file() { fs::remove_file(package.join(catalogue_name))?; }
        if package.join(module_directory).is_dir() { fs::remove_dir_all(package.join(module_directory))?; }
        fs::rename(catalog, package.join(catalogue_name))?;
        fs::rename(bundle.join("browser-wasm"), package.join(module_directory))?;
        catalog_pins.push(observed);
    }

    let write_receipt = |package: &Path, catalog_pin: &str, bundled: Option<(&str, &str)>,
        rebuilt: &BTreeMap<String, String>| -> Result<String>
    {
        let path = package.join(PACKAGE_RECEIPT);
        let receipt = appdev_assurance::read_facts(&path)?;
        let rows = workflow.run("release.browserWasmReceipt", json!({
            "receipt":receipt.0, "catalogPin":catalog_pin,
            "workCatalogPin":bundled.map(|(catalog, _)| catalog),
            "workReceiptPin":bundled.map(|(_, receipt)| receipt),
            "standalonePin":bundled.map(|_| &catalog_pins[2]),
            "newRuntimePin":rebuild.then_some(&runtime_pin), "rebuilt":rebuilt
        }))?;
        let rows: Vec<[String; 3]> = serde_json::from_value(rows)?;
        let mut rendered = String::new();
        for [subject, property, value] in rows {
            rendered.push_str(&format!("({}, {}, {})\n", serde_json::to_string(&subject)?,
                serde_json::to_string(&property)?, serde_json::to_string(&value)?));
        }
        fs::write(path, &rendered)?;
        Ok(crate::rel::hash(rendered))
    };
    let work_receipt = write_receipt(&work, &catalog_pins[1], None, &rebuilt_work)?;
    write_receipt(&staged, &catalog_pins[0], Some((&catalog_pins[1], &work_receipt)), &rebuilt_home)?;
    appdev_release::check_candidate(&staged)?;
    artifacts.clear();
    appdev_assurance::hash_package(&staged, Some(RECEIPT), |path, digest| {
        artifacts.insert(path.to_owned(), hex::encode(digest));
    })?;
    verify_package_pins(&workflow, &staged, true, &artifacts)?;
    supervisor.check()?;
    rename_new_path(&staged, &output)?;
    println!("{}", output.display());
    Ok(())
}

pub fn release(app: &Path, operation: &str, requested: &Path) -> Result<()> {
    let app = app.canonicalize()?;
    let workflow = command::Evaluator::load(&app, "release/workflow.rel")?;
    let facts = Facts::read(&app.join("release/plan.rel"))?;
    let plan = plan(&workflow, &facts, operation, false)?;
    let candidate = plan["candidate"].as_str().ok_or_else(|| fail("Expected an AppDev candidate type"))?;
    if candidate == "preview-declaration" {
        return crate::appdev_preview::serve(&app, &workflow, &facts, requested, &strings(&plan["launch"])?);
    }
    let requested = package(requested)?;
    let (home, work) = match candidate {
        "home" => (requested, None),
        "work-with-active-home" => (package(Path::new(ACTIVE))?, Some(requested)),
        "system" => {
            system_work(&requested)?;
            (requested, None)
        }
        "bundled-work-system" => (work_system(&requested)?, None),
        _ => return Err(fail("Unknown AppDev candidate type")),
    };
    if workflow.run("release.admit", json!({
        "system":system_package(&home), "operation":operation
    }))? != true { return Err(fail("Encounter did not admit the AppDev release")); }
    let finish = plan["finish"].as_str().ok_or_else(|| fail("Expected an AppDev release action"))?;
    let deployment_receipt = (finish == "activate-system").then(|| appdev_assurance::read_facts(&home.join(RECEIPT))).transpose()?;
    if let Some(receipt) = &deployment_receipt { require_verification(&app, receipt)?; }
    let previous = if matches!(finish, "activate-home" | "activate-system") {
        if !home.starts_with(INSTALLED) { return Err(fail("Install the staged package under /srv/encounter-apps before deploying")); }
        Some(Path::new(ACTIVE).canonicalize()?)
    } else { None };
    let mut supervisor = Supervisor::new();
    gates(&mut supervisor, &app, &workflow, &home, work.as_deref(), &strings(&plan["gates"])?)?;
    supervisor.check()?;
    match finish {
        "return" => Ok(()),
        "activate-home" => {
            let mut command = Command::new("/usr/bin/sudo");
            command.arg("--").arg("/usr/local/libexec/sourcery-appdev-activate-home")
                .arg("appdev-activate-home").arg(home).arg(previous.ok_or_else(|| fail("Expected activation baseline"))?);
            // The operator may need to enter a sudo password.
            Err(command.exec().into())
        }
        "activate-system" => {
            if let Some(receipt) = &deployment_receipt { require_verification(&app, receipt)?; }
            let status = Command::new("/usr/bin/sudo").arg("--")
                .arg(SYSTEM_DRIVER).arg("appdev-activate-system")
                .arg(&home).arg(previous.ok_or_else(|| fail("Expected activation baseline"))?).status()?;
            if !status.success() { return Err(fail(format!("AppDev system activation failed ({status})"))); }
            live_formation(&app, &home)
                .map_err(|error| fail(format!("AppDev was activated, but its post-deployment check failed: {error}")))
        }
        _ => Err(fail("Invalid AppDev release action")),
    }
}

pub(crate) fn immutable(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path)?;
    if info.uid() != 0 || info.mode() & 0o022 != 0 || (!info.is_file() && !info.is_dir()) {
        return Err(fail("Install a root-owned release with regular files and no group or other write access"));
    }
    if info.is_dir() {
        for entry in fs::read_dir(path)? { immutable(&entry?.path())?; }
    }
    Ok(())
}

fn locked_switch(active: &Path, lock: &Path, release: &Path, previous: &Path, admit: impl FnOnce() -> Result<()>) -> Result<()> {
    coordinated_switch(active, lock, release, previous, interrupted, admit, |_, _| Ok(()))
}

fn interrupted() -> bool { crate::appdev_host_process::interruption().is_some() }

pub(crate) fn coordinated_switch(active: &Path, lock: &Path, release: &Path, previous: &Path,
    cancelled: impl Fn() -> bool, admit: impl FnOnce() -> Result<()>,
    mut reconcile: impl FnMut(&Path, bool) -> Result<()>) -> Result<()> {
    let check = || -> Result<()> {
        if cancelled() { return Err(fail("AppDev activation interrupted")); }
        Ok(())
    };
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .mode(0o644).custom_flags(libc::O_NOFOLLOW).open(lock)?;
    loop {
        check()?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 { break; }
        let error = io::Error::last_os_error();
        if !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) { return Err(error.into()); }
        std::thread::sleep(Duration::from_millis(50));
    }
    if active.canonicalize()? != previous {
        return Err(fail("AppDev changed while the release was being tested. Rebase and rerun the release command."));
    }
    admit()?;
    let parent = active.parent().ok_or_else(|| fail("Expected AppDev release link parent"))?;
    let pending = Scratch::create(parent, ".workspace-release.")?;
    let next_link = pending.path().join("next");
    let previous_link = pending.path().join("previous");
    symlink(release, &next_link)?;
    symlink(previous, &previous_link)?;
    check()?;
    fs::rename(next_link, active)?;
    if let Err(error) = check().and_then(|_| reconcile(release, false)).and_then(|_| check()) {
        let recovery = (|| -> Result<()> {
            fs::rename(previous_link, active)?;
            reconcile(previous, true)
        })();
        if let Err(rollback) = recovery {
            return Err(fail(format!("AppDev activation failed ({error}); recovery failed ({rollback})")));
        }
        return Err(fail(format!("AppDev activation failed ({error}); restored {}", previous.display())));
    }
    Ok(())
}

pub fn activate(release: &Path, previous: &Path) -> Result<()> {
    let _supervisor = Supervisor::new();
    if !release.starts_with(INSTALLED) || release.canonicalize()? != release {
        return Err(fail("Expected an installed release"));
    }
    locked_switch(Path::new(ACTIVE), Path::new(RELEASE_LOCK), release, previous, || {
        if system_package(release) || system_package(previous) {
            return Err(fail("Use coordinated system activation to switch to or from a system package"));
        }
        immutable(release)?;
        if fs::read(previous.join("encounter"))? != fs::read(release.join("encounter"))? {
            return Err(fail("The native runtime changed. Use the coordinated runtime rollout."));
        }
        appdev_release::check(release)
    })?;
    println!("Activated {}", release.display());
    Ok(())
}

struct SystemActivation {
    actions: Vec<ActivationAction>,
    probes: Vec<ReadinessProbe>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ActivationUnit(&'static str);

impl ActivationUnit {
    fn from_policy(name: &str) -> Result<Self> {
        const UNITS: [&str; 10] = ["life-board-workgarden.service", "appdev-workspace.service",
            "appdev-browser.service", "appdev-life-board-browser.service", "appdev-life-board-gateway.service",
            "life-board-network.service", "appdev-shop.service", "appdev-shop-gateway.service", "appdev-file-viewer.service", "nginx.service"];
        UNITS.into_iter().find(|unit| *unit == name).map(Self)
            .ok_or_else(|| fail("Unknown AppDev activation unit"))
    }

    fn user_scope(self) -> bool { self.0 == "life-board-workgarden.service" }

    fn shop(self) -> bool { matches!(self.0, "appdev-shop.service" | "appdev-shop-gateway.service") }

}

enum ActivationAction {
    ValidateIngress,
    ReloadIngress,
    Systemd { change: ReleaseServiceChange, units: Vec<ActivationUnit> },
}

impl ActivationAction {
    fn from_policy(row: &Value) -> Result<Self> {
        let units = strings(&row["units"])?.into_iter().map(ActivationUnit::from_policy).collect::<Result<Vec<_>>>()?;
        let first = units.first().copied();
        if row["kind"] == "validate-ingress" && first.is_none() { return Ok(Self::ValidateIngress); }
        let first = first.ok_or_else(|| fail("AppDev service action requires units"))?;
        if units.iter().enumerate().any(|(index, unit)| units[..index].contains(unit) || unit.user_scope() != first.user_scope()) {
            return Err(fail("AppDev service action requires distinct units in one service manager"));
        }
        let change = match row["kind"].as_str() {
            Some("restart") if units.iter().all(|unit| unit.0 != "nginx.service") => ReleaseServiceChange::Restart,
            Some("stop") if units.iter().all(|unit| unit.shop()) => ReleaseServiceChange::Stop,
            Some("reload") if units.len() == 1 && first.0 == "nginx.service"
                && row["requiresValidatedIngress"] == true => return Ok(Self::ReloadIngress),
            _ => return Err(fail("Unknown or inadmissible AppDev service action")),
        };
        Ok(Self::Systemd { change, units })
    }

    fn run(&self, restoring: bool) -> Result<()> {
        let mut children = if restoring { Supervisor::release_recovery() } else { Supervisor::children() };
        match self {
            Self::ValidateIngress => children.run_until("AppDev validate ingress",
                ServiceTool::Nginx.command()?.arg("-t"), Some(Duration::from_secs(30))),
            Self::ReloadIngress => systemd_user_service::reload_nginx(Duration::from_secs(120), restoring),
            Self::Systemd { change, units } => {
                let names = units.iter().map(|unit| unit.0).collect::<Vec<_>>();
                systemd_user_service::change_release_units(*change, &names, Duration::from_secs(120), restoring)
            }
        }
    }
}

enum ReadinessTarget { Appdev, Mcp, FrontGate }

impl ReadinessTarget {
    fn name(&self) -> &'static str {
        match self { Self::Appdev => "appdev", Self::Mcp => "mcp", Self::FrontGate => "front-gate" }
    }

    fn tls_host(&self) -> Option<&'static CStr> {
        match self {
            Self::Appdev => Some(c"appdev.sourcerytech.com.au"),
            Self::Mcp => Some(c"mcp.sourcerytech.com.au"),
            Self::FrontGate => None,
        }
    }
}

fn front_gate_readiness(port: u16, path: &str, restoring: bool) -> Result<(u16, String)> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: front-gate-readiness\r\nConnection: close\r\n\r\n");
    let timeout = Duration::from_secs(2);
    let mut reply = if restoring {
        crate::http::LoopbackReply::open_for_rollback(port, request.as_bytes(), timeout)?
    } else {
        crate::http::LoopbackReply::open(port, request.as_bytes(), timeout)?
    };
    let (status, headers) = crate::http::read_response_head(&mut reply)?;
    let mut body = Vec::new();
    if (200..400).contains(&status) && !matches!(status, 204 | 304) {
        crate::http::copy_response_body(&mut reply, &headers, &mut body, 256)?;
    }
    Ok((status, String::from_utf8(body)?))
}

struct ReadinessProbe {
    target: ReadinessTarget,
    path: String,
    expected: Vec<String>,
    attempts: u8,
    delay_ms: u64,
}

impl ReadinessProbe {
    fn from_policy(row: &Value) -> Result<Self> {
        let target = match row["target"].as_str() {
            Some("appdev") => ReadinessTarget::Appdev,
            Some("mcp") => ReadinessTarget::Mcp,
            Some("front-gate") => ReadinessTarget::FrontGate,
            _ => return Err(fail("Unknown AppDev readiness target")),
        };
        let probe = Self {
            target,
            path: row["path"].as_str().ok_or_else(|| fail("Expected AppDev readiness path"))?.into(),
            expected: serde_json::from_value(row["expected"].clone())?,
            attempts: serde_json::from_value(row["attempts"].clone())?,
            delay_ms: serde_json::from_value(row["delayMs"].clone())?,
        };
        if !(1..=20).contains(&probe.attempts) || !(1..=1_000).contains(&probe.delay_ms)
            || probe.expected.is_empty() || !probe.path.starts_with('/') || probe.path.starts_with("//")
            || !probe.path.bytes().all(|byte| byte.is_ascii_graphic() && !b"\\#?".contains(&byte))
        {
            return Err(fail("Invalid AppDev readiness probe"));
        }
        Ok(probe)
    }

    fn observe(&self, restoring: bool) -> Result<(u16, String)> {
        if let Some(host) = self.target.tls_host() {
            let status = crate::certificate_tls::ingress_status(host, &self.path, restoring)?;
            Ok((status, String::new()))
        } else {
            front_gate_readiness(24220, &self.path, restoring)
        }
    }

    fn ready(&self, policy: &command::Evaluator, observation: Option<&(u16, String)>) -> Result<bool> {
        Ok(policy.run("release.ready", json!({
            "transportSucceeded":observation.is_some(),
            "status":observation.map(|(status, _)| status.to_string()),
            "body":observation.map(|(_, body)| body),
            "probe":{"target":self.target.name(),"expected":self.expected}
        }))? == true)
    }
}

fn system_steps(policy: &command::Evaluator, system: bool) -> Result<SystemActivation> {
    let plan = policy.run("release.activation", json!({"system":system}))?;
    let actions = plan["actions"].as_array().ok_or_else(|| fail("Expected AppDev activation actions"))?
        .iter().map(ActivationAction::from_policy).collect::<Result<Vec<_>>>()?;
    let probes = plan["probes"].as_array().ok_or_else(|| fail("Expected AppDev readiness probes"))?
        .iter().map(ReadinessProbe::from_policy).collect::<Result<Vec<_>>>()?;
    if actions.is_empty() || probes.is_empty() { return Err(fail("Incomplete AppDev activation policy")); }
    Ok(SystemActivation { actions, probes })
}

fn system_readiness(policy: &command::Evaluator, probes: &[ReadinessProbe], restoring: bool) -> Result<()> {
    for probe in probes {
        let mut ready = false;
        let mut failure = None;
        for attempt in 1..=probe.attempts {
            crate::http::check_interruption(restoring)?;
            let observation = probe.observe(restoring);
            crate::http::check_interruption(restoring)?;
            if probe.ready(policy, observation.as_ref().ok())? {
                ready = true;
                break;
            }
            failure = observation.err();
            if attempt < probe.attempts { std::thread::sleep(Duration::from_millis(probe.delay_ms)); }
        }
        if !ready {
            let detail = failure.map(|error| format!(" ({error})")).unwrap_or_default();
            return Err(fail(format!("AppDev readiness failed for {}{detail}", probe.path)));
        }
    }
    Ok(())
}

fn observed_release_binding(policy: &command::Evaluator, binding: &Value, needs_standalone: bool) -> Result<Option<PathBuf>> {
    let unit = ActivationUnit::from_policy(binding["unit"].as_str().ok_or_else(|| fail("Expected release unit"))?)?;
    let observed = match binding["property"].as_str() {
        Some("ExecStart") => serde_json::to_value(crate::systemd_user_service::release_commands(unit.0, unit.user_scope())?)?,
        Some("Environment") if unit.0 == "life-board-network.service" =>
            json!(crate::systemd_user_service::release_network_environment()?),
        _ => return Err(fail("Unknown or inadmissible AppDev unit property")),
    };
    let result = policy.run("release.unitFollows", json!({
        "binding":binding, "active":ACTIVE, "launcher":SYSTEM_DRIVER, "observed":observed,
        "needsStandalone":needs_standalone
    }))?;
    if result["follows"] != true {
        return Err(fail(format!("{} must be configured to follow the shared AppDev release link", unit.0)));
    }
    let standalone = result["standalonePolicy"].as_str().map(|path| standalone_work_gateway(Path::new(path), true)).transpose()?;
    if let Some(root) = &standalone { check_work_gateway_policy(root)?; }
    Ok(standalone)
}

fn system_units_follow_release(policy: &command::Evaluator, needs_standalone: bool) -> Result<()> {
    let launcher = Path::new(SYSTEM_DRIVER);
    immutable(launcher)?;
    crate::package::require_native_runtime(launcher)?;
    let bindings = policy.run("release.unitBindings", Value::Null)?;
    let bindings = bindings.as_array().filter(|rows| !rows.is_empty())
        .ok_or_else(|| fail("Expected AppDev release unit bindings"))?;
    for binding in bindings { observed_release_binding(policy, binding, needs_standalone)?; }
    Ok(())
}

pub(crate) fn configured_standalone_work_policy(app: &Path) -> Result<PathBuf> {
    let policy = command::Evaluator::load(app, "release/activation.rel")?;
    let bindings = policy.run("release.unitBindings", Value::Null)?;
    let binding = bindings.as_array().and_then(|rows| rows.iter().find(|binding| binding["operation"] == "appdev-work-gateway"))
        .ok_or_else(|| fail("Missing the managed Work gateway binding"))?;
    observed_release_binding(&policy, binding, true)?.ok_or_else(|| fail("Missing the standalone Work gateway policy"))
}

pub fn dispatch_installed_system_activation(arguments: &[String]) -> Result<()> {
    match arguments {
        [operation, release, previous] if operation == "appdev-activate-system" => {
            activate_system_lifecycle(Path::new(release), Path::new(previous))
        }
        [operation, ..] if operation == "appdev-activate-system" => {
            Err(fail("Expected appdev-activate-system RELEASE PREVIOUS"))
        }
        // Work and Shop bind this launcher in their service units.
        _ => Err(Command::new(LEGACY_SYSTEM_DRIVER).args(arguments).exec().into()),
    }
}

pub fn activate_system(release: &Path, previous: &Path) -> Result<()> {
    let _supervisor = Supervisor::new();
    let policy_root = Path::new("/etc/sourcery/appdev-system");
    immutable(policy_root)?;
    for path in [release, previous] {
        if !path.starts_with(INSTALLED) || path.canonicalize()? != path {
            return Err(fail("Expected canonical installed AppDev release paths"));
        }
    }
    if release == previous || !(system_package(release) || system_package(previous)) {
        return Err(fail("Expected a switch to or from a distinct system release"));
    }
    let policy = command::Evaluator::load(policy_root, "activation.rel")?;
    if policy.run("release.ready", json!({
        "transportSucceeded": false, "status": null, "body": null, "probe": {"target":"appdev","expected": []}
    }))? != false {
        return Err(fail("AppDev activation policy admitted a failed transport"));
    }
    let steps = [system_steps(&policy, false)?, system_steps(&policy, true)?];
    coordinated_switch(Path::new(ACTIVE), Path::new(RELEASE_LOCK), release, previous, interrupted, || {
        validate_activation_releases(release, previous)?;
        system_units_follow_release(&policy, !system_package(release) || !system_package(previous))?;
        let inventory = policy_root.join("lifecycle-inventory.rel");
        match inventory.symlink_metadata() {
            Ok(_) => {
                let report = crate::appdev_lifecycle::report(policy_root, &inventory, previous, release)?;
                eprintln!("AppDev lifecycle report {report}");
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ActivationAction::ValidateIngress.run(false)
    }, |active, restoring| {
        let system = system_package(active);
        let plan = &steps[usize::from(system)];
        let mut failures = Vec::new();
        let mut ingress_valid = false;
        for action in &plan.actions {
            if !restoring && interrupted() { return Err(fail("AppDev activation interrupted")); }
            if matches!(action, ActivationAction::ReloadIngress) && !ingress_valid { continue; }
            match action.run(restoring) {
                Ok(()) if matches!(action, ActivationAction::ValidateIngress) => ingress_valid = true,
                Ok(()) => {}
                Err(error) if restoring => failures.push(error.to_string()),
                Err(error) => return Err(error),
            }
        }
        if !failures.is_empty() {
            return Err(fail(failures.join(", ")));
        }
        system_readiness(&policy, &plan.probes, restoring)
    })?;
    println!("Activated {}", release.display());
    Ok(())
}


fn validate_activation_releases(release: &Path, previous: &Path) -> Result<()> {
    for path in [release, previous] {
        immutable(path)?;
        crate::package::require_native_runtime(&path.join("encounter"))?;
        appdev_release::check(path)?;
        if system_package(path) {
            check_work_gateway_policy(&system_work(path)?.join("gateway-programme"))?;
            if ["formation/records.nginx.conf", "shop/appdev.nginx.conf", "shop/broker.nginx.conf"]
                .iter().any(|name| !path.join(name).is_file()) {
                return Err(fail("The system release must include Formation and both Shop ingress files"));
            }
        }
    }
    Ok(())
}

const LIFECYCLE_POLICY_ROOT: &str = "/etc/sourcery/appdev-system-lifecycle";

struct FollowingHost {
    unit: ActivationUnit,
    pid: u32,
}

impl FollowingHost {
    fn pid(unit: ActivationUnit) -> Result<u32> {
        let result = Command::new("/usr/bin/systemctl").args(["show", "-p", "MainPID", "--value", unit.0]).output()?;
        if !result.status.success() { return Err(fail("unable to inspect AppDev follower service")); }
        let pid = std::str::from_utf8(&result.stdout)?.trim().parse()?;
        if pid == 0 { return Err(fail("AppDev follower service is stopped")); }
        Ok(pid)
    }

    fn observe(unit: ActivationUnit, previous: &Path, next: &Path) -> Result<Self> {
        if !matches!(unit.0, "appdev-workspace.service" | "appdev-browser.service" | "appdev-file-viewer.service") {
            return Err(fail("service does not have a verified release-following protocol"));
        }
        let pid = Self::pid(unit)?;
        let process = PathBuf::from(format!("/proc/{pid}"));
        let command = fs::read(process.join("cmdline"))?;
        let args = command.strip_suffix(&[0]).unwrap_or(&command).split(|byte| *byte == 0).collect::<Vec<_>>();
        let correct_operation = match unit.0 {
            "appdev-workspace.service" => matches!(args.as_slice(), [_, b"workspace-host", b"--follow-release", path] if *path == ACTIVE.as_bytes()),
            "appdev-browser.service" => matches!(args.as_slice(), [_, b"appdev-browser-host", b"--allow-aster-stream", path, b"24257"] if *path == ACTIVE.as_bytes()),
            _ => matches!(args.as_slice(), [_, b"appdev-file-viewer", path] if *path == ACTIVE.as_bytes()),
        };
        let previous_runtime = fs::read(previous.join("encounter"))?;
        let correct_runtime = if unit.0 == "appdev-file-viewer.service" {
            let executable = fs::read_link(process.join("exe"))?;
            if !executable.starts_with(INSTALLED) { return Err(fail("AppDev File Viewer must use an installed runtime")); }
            immutable(&executable)?;
            args.first().is_some_and(|arg| *arg == executable.as_os_str().as_encoded_bytes())
        } else {
            fs::read(process.join("exe"))? == previous_runtime
        };
        if !correct_operation || !correct_runtime || fs::read(next.join("encounter"))? != previous_runtime {
            return Err(fail("AppDev follower is not serving the required runtime and release link"));
        }
        let host = Self { unit, pid };
        host.acknowledge(previous, false)?;
        Ok(host)
    }

    fn acknowledge(&self, release: &Path, restoring: bool) -> Result<()> {
        // The older hosts check the release pointer when serving requests.
        let warmup = match self.unit.0 {
            "appdev-browser.service" => Some("http://127.0.0.1:24257/"),
            "appdev-file-viewer.service" => Some("https://appdev.sourcerytech.com.au/workspace/files"),
            _ => None,
        };
        if let Some(url) = warmup {
            let response = crate::http_client::send(crate::http_client::Request {
                url, method: "GET", headers: &[], body: None,
                timeout: Duration::from_secs(5), connect_timeout: Duration::from_secs(2), limit: 4_000_000,
                resolve: None, trust_anchor: None, restoring,
            })?;
            if response.status != 200 { return Err(fail("AppDev follower did not answer readiness")); }
        }
        let current = format!("AppDev release activated: {}", release.display());
        let legacy = format!("AppDev loaded release {}", release.display());
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            crate::http::check_interruption(restoring)?;
            if Self::pid(self.unit)? != self.pid {
                return Err(fail("AppDev follower restarted during coordinated activation"));
            }
            let result = Command::new("/usr/bin/journalctl").args(["-b", "-n", "1", "--no-pager", "-o", "cat",
                "--grep", "^AppDev (release activated: |loaded release )"])
                .arg(format!("_SYSTEMD_UNIT={}", self.unit.0)).arg(format!("_PID={}", self.pid)).output()?;
            if result.status.success() && std::str::from_utf8(&result.stdout)?.lines().any(|line| line == current || line == legacy) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(fail(format!("{} did not acknowledge the selected release", self.unit.0)));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn nginx_workers(master: u32) -> Result<BTreeSet<u32>> {
    let children = fs::read_to_string(format!("/proc/{master}/task/{master}/children"))?;
    let mut workers = BTreeSet::new();
    for child in children.split_ascii_whitespace() {
        let pid: u32 = child.parse()?;
        let command = match fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(command) => command,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if command.split(|byte| *byte == 0).next() == Some(b"nginx: worker process") {
            workers.insert(pid);
        }
    }
    Ok(workers)
}

fn run_lifecycle_action(action: &ActivationAction, restoring: bool) -> Result<()> {
    if !matches!(action, ActivationAction::ReloadIngress) { return action.run(restoring); }

    // systemd acknowledges delivery of the reload signal before Nginx starts workers.
    let master = systemd_user_service::release_nginx_pid(restoring)?;
    let previous = nginx_workers(master)?;
    if previous.is_empty() && !restoring { return Err(fail("Nginx has no accepting workers before reload")); }
    action.run(restoring)?;

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        crate::http::check_interruption(restoring)?;
        if systemd_user_service::release_nginx_pid(restoring)? != master {
            return Err(fail("Nginx master restarted during graceful reload"));
        }
        let workers = nginx_workers(master)?;
        if !workers.is_empty() && workers.is_disjoint(&previous) {
            println!("AppDev Nginx master {master} acknowledged reload with {} accepting workers", workers.len());
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(fail("Nginx did not start a new accepting worker generation"));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

struct SelectedLifecycle {
    policy: command::Evaluator,
    actions: Vec<ActivationAction>,
    probes: Vec<ReadinessProbe>,
    followers: Vec<FollowingHost>,
    attempted: Vec<usize>,
}

impl SelectedLifecycle {
    fn reconcile(&mut self, release: &Path, restoring: bool) -> Result<()> {
        let mut errors = Vec::new();
        if restoring {
            let ingress_attempted = self.attempted.iter().any(|index| matches!(self.actions[*index], ActivationAction::ReloadIngress));
            let mut ingress_valid = false;
            if ingress_attempted {
                match ActivationAction::ValidateIngress.run(true) {
                    Ok(()) => ingress_valid = true,
                    Err(error) => errors.push(error.to_string()),
                }
            }
            for index in self.attempted.iter().copied() {
                let action = &self.actions[index];
                if matches!(action, ActivationAction::ReloadIngress) && !ingress_valid { continue; }
                if let Err(error) = run_lifecycle_action(action, true) { errors.push(error.to_string()); }
            }
        } else {
            for (index, action) in self.actions.iter().enumerate() {
                crate::http::check_interruption(false)?;
                if !matches!(action, ActivationAction::ValidateIngress) { self.attempted.push(index); }
                run_lifecycle_action(action, false)?;
            }
        }
        if let Err(error) = system_readiness(&self.policy, &self.probes, restoring) {
            errors.push(error.to_string());
        }
        for follower in &self.followers {
            if let Err(error) = follower.acknowledge(release, restoring) { errors.push(error.to_string()); }
        }
        if errors.is_empty() { Ok(()) } else { Err(fail(errors.join(", "))) }
    }
}

pub fn activate_system_lifecycle(release: &Path, previous: &Path) -> Result<()> {
    let _supervisor = Supervisor::new();
    let policy_root = Path::new(LIFECYCLE_POLICY_ROOT);
    immutable(policy_root)?;
    for path in [release, previous] {
        if !path.starts_with(INSTALLED) || path.canonicalize()? != path {
            return Err(fail("Expected canonical installed AppDev release paths"));
        }
    }
    if release == previous || !system_package(release) || !system_package(previous) {
        return Err(fail("Dependency-aware activation requires distinct AppDev system releases"));
    }
    let selected = std::cell::RefCell::<Option<SelectedLifecycle>>::new(None);
    coordinated_switch(Path::new(ACTIVE), Path::new(RELEASE_LOCK), release, previous, interrupted, || {
        immutable(policy_root)?;
        let policy = command::Evaluator::load(policy_root, "activation.rel")?;
        let plan = crate::appdev_system_lifecycle::plan(policy_root, previous, release)?;
        if plan["requiresReview"] != false {
            return Err(fail(format!("AppDev release requires lifecycle review: {plan}")));
        }
        validate_activation_releases(release, previous)?;
        for package in [release, previous] { appdev_assurance::require(package)?; }
        let actions = plan["nativeActions"].as_array().ok_or_else(|| fail("expected executable lifecycle actions"))?
            .iter().map(ActivationAction::from_policy).collect::<Result<Vec<_>>>()?;
        let required = policy.run("release.unitBindings", Value::Null)?;
        let bindings = required.as_array().ok_or_else(|| fail("expected release unit bindings"))?;
        for action in &actions {
            if let ActivationAction::Systemd { units, .. } = action {
                for unit in units {
                    let binding = bindings.iter().find(|row| row["unit"] == unit.0)
                        .ok_or_else(|| fail("selected restart has no verified release binding"))?;
                    observed_release_binding(&policy, binding, false)?;
                }
            }
        }
        let followers = strings(&plan["followUnits"])?.iter().map(|unit| {
            FollowingHost::observe(ActivationUnit::from_policy(unit)?, previous, release)
        }).collect::<Result<Vec<_>>>()?;
        let legacy_probes = system_steps(&policy, true)?.probes;
        system_readiness(&policy, &legacy_probes, false)?;
        println!("AppDev coordinated lifecycle {plan}");
        *selected.borrow_mut() = Some(SelectedLifecycle {
            policy, actions, probes: legacy_probes, followers, attempted: Vec::new(),
        });
        Ok(())
    }, |active, restoring| {
        let mut selection = selected.borrow_mut();
        let selection = selection.as_mut().ok_or_else(|| fail("missing selected lifecycle plan"))?;
        selection.reconcile(active, restoring)
    })?;
    println!("Activated {} through the AppDev lifecycle policy", release.display());
    Ok(())
}

fn selected_system(active: &Path) -> Result<Option<PathBuf>> {
    if !active.is_absolute() {
        return Err(fail("Expected an absolute AppDev release link"));
    }
    let current = active.canonicalize()?;
    let present = |name: &str| -> Result<bool> {
        match current.join(name).symlink_metadata() {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    };
    if present(SYSTEM_POLICY)? || present("work")? {
        if active == Path::new(ACTIVE) || current.starts_with(INSTALLED) {
            appdev_assurance::require(&current)?;
        }
        Ok(Some(current))
    } else {
        Ok(None)
    }
}

fn bundled_work(active: &Path) -> Result<Option<PathBuf>> {
    let Some(current) = selected_system(active)? else { return Ok(None); };
    Ok(Some(system_work(&current)?))
}

fn system_work(home: &Path) -> Result<PathBuf> {
    let bundled = home.join("work");
    let work = package(&bundled)?;
    if work != bundled {
        return Err(fail("The AppDev Work package must belong to the selected system release"));
    }
    crate::package::check(&work)?;
    Ok(work)
}

pub fn serve_work(active: &Path, legacy: &Path, port: u16) -> Result<()> {
    if !legacy.is_absolute() {
        return Err(fail("Expected an absolute legacy Work release path"));
    }
    let work = match bundled_work(active)? {
        Some(work) => work,
        None => {
            let work = package(legacy)?;
            crate::package::check(&work)?;
            work
        }
    };
    let mut runtime = Command::new(work.join("encounter"));
    runtime.current_dir(&work).arg("browser-host").arg(work.join("source"))
        .arg("applications/life-board-prototype/hosting/application.rel")
        .arg(work.join("assets")).arg(port.to_string());
    Err(runtime.exec().into())
}

fn standalone_work_gateway(path: &Path, installed: bool) -> Result<PathBuf> {
    if !path.is_absolute() || path.canonicalize()? != path || !path.is_dir() {
        return Err(fail("Expected a canonical standalone Work gateway policy directory"));
    }
    if installed {
        if !path.starts_with(INSTALLED) {
            return Err(fail("Install the standalone Work gateway policy under /srv/encounter-apps"));
        }
        for parent in path.ancestors().skip(1) {
            let metadata = parent.symlink_metadata()?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(fail("The standalone Work gateway policy must have immutable parents"));
            }
        }
        immutable(path)?;
    }
    Ok(path.to_owned())
}

fn check_work_gateway_policy(root: &Path) -> Result<()> {
    crate::gateway::load_policy(root, WORK_GATEWAY_DECLARATION, Some(WORK_GATEWAY_PROFILE))?
        .admit(&mut crate::process::Meter::new(20_000_000))?;
    Ok(())
}

pub fn serve_work_gateway(active: &Path, config: &Path, standalone: Option<&Path>) -> Result<()> {
    if !config.is_absolute() {
        return Err(fail("Expected an absolute AppDev gateway configuration path"));
    }
    let root = match bundled_work(active)? {
        Some(work) => work.join("gateway-programme"),
        None => {
            let root = standalone.ok_or_else(|| fail("Standalone Home requires an explicit Work gateway policy"))?;
            standalone_work_gateway(root, active == Path::new(ACTIVE))?
        }
    };
    crate::gateway::serve_with_policy(config, Some((&root, WORK_GATEWAY_DECLARATION, "/life-board", WORK_GATEWAY_PROFILE)))
}

pub fn serve_shop(active: &Path, config: &Path, gateway: bool) -> Result<()> {
    let root = selected_system(active)?.ok_or_else(|| fail("Shop requires an active AppDev system release"))?;
    let config = config.canonicalize()?;
    if gateway {
        return crate::gateway::serve_with_policy(&config,
            Some((&root.join("shop/source"), "sourcery-shop/gateway.rel", "/shop", "encounter/sourcery-shop-gateway/1")));
    }
    let runtime = root.join("encounter");
    crate::package::require_native_runtime(&runtime)?;
    Err(Command::new(runtime).arg("appdev-shop-image").arg(root)
        .arg(config).exec().into())
}

pub fn serve_shop_image(root: &Path, config: &Path) -> Result<()> {
    let metadata = fs::metadata(config)?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() > 32_768 {
        return Err(fail("Expected a private Shop launch configuration of at most 32768 bytes"));
    }
    let settings = Facts::read(config)?;
    let field = |key| settings.one("shop", key);
    if field("contract")? != "encounter/appdev-shop/1" {
        return Err(fail("Unsupported AppDev Shop launch contract"));
    }
    if settings.0.iter().any(|[subject, key, _]| subject != "shop"
        || !matches!(key.as_str(), "contract" | "store" | "operators" | "port" | "operatorPrincipal")) {
        return Err(fail("Unknown Shop launch setting"));
    }
    let store = Path::new(field("store")?);
    let operators = Path::new(field("operators")?);
    let port = field("port")?.parse::<u16>()?;
    let principals = settings.values("shop", "operatorPrincipal");
    if !store.is_absolute() || !store.is_dir() || !operators.is_absolute() || port == 0
        || principals.iter().any(|id| id.is_empty() || id.len() > 320 || !id.bytes().all(|byte| byte.is_ascii_graphic()))
    {
        return Err(fail("Invalid Shop store, operators, port or principal"));
    }
    let relative = "shop/shop.rel";
    let receipt = Facts::read(&root.join("package-receipt.rel"))?;
    let image = crate::image::load(&root.join(relative), receipt.one("artifact", relative)?)?;
    crate::declared_web::serve_shop_image(image, store, port, operators, &principals)
}

pub fn serve_workgarden(active: &Path, config: &Path) -> Result<()> {
    let settings = Facts::read(config)?;
    let setting = |key| settings.one("workgarden", key);
    if setting("contract")? != "encounter/appdev-workgarden/1" {
        return Err(fail("Unsupported AppDev Workgarden launch contract"));
    }
    let store = Path::new(setting("store")?);
    let port = setting("port")?.parse::<u16>()?;
    if !store.is_absolute() || !store.is_dir() || port == 0 {
        return Err(fail("Expected an existing absolute Workgarden store and a fixed port"));
    }
    let (runtime, image, pin) = match selected_system(active)? {
        Some(root) => {
            let relative = "workgarden/board.rel";
            let receipt = Facts::read(&root.join("package-receipt.rel"))?;
            (root.join("encounter"), root.join(relative), receipt.one("artifact", relative)?.to_owned())
        }
        None => (PathBuf::from(setting("legacyRuntime")?), PathBuf::from(setting("legacyImage")?),
            setting("legacySha256")?.to_owned()),
    };
    if !runtime.is_absolute() || !image.is_absolute() {
        return Err(fail("Expected absolute Workgarden executable and image paths"));
    }
    crate::package::require_native_runtime(&runtime)?;
    Err(Command::new(runtime).args(["serve", "--image"]).arg(image).arg(pin)
        .arg(store).arg(port.to_string()).exec().into())
}

pub fn stage_aster(source: &Path, seed: &Path, destination: &Path) -> Result<()> {
    let facts = Facts::read(&source.join("application.rel"))?;
    let plan = command::evaluate(source, "stage.rel", "aster.stage", json!(facts.0))?;
    let files = strings(&plan["files"])?;
    let target = plan["privateSeed"].as_str().ok_or_else(|| fail("Expected an Aster seed name"))?;
    for name in files.iter().copied().chain(std::iter::once(target)) {
        if Path::new(name).file_name().and_then(|part| part.to_str()) != Some(name) || name.contains('\\') {
            return Err(fail("Expected a single staging file name"));
        }
    }
    let mut seed = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(seed)
        .map_err(|_| fail("Supply a readable deployment seed file"))?;
    if !seed.metadata()?.is_file() { return Err(fail("Supply a readable deployment seed file")); }
    fs::create_dir(destination)?;
    let result = (|| -> Result<()> {
        let renderers = ["html.escape.encounter", "html.cssText.encounter", "html.serialize.encounter"];
        for name in files {
            if let Some(index) = renderers.iter().position(|module| *module == name) {
                fs::write(destination.join(name), crate::process::HTML_RENDERER[index])?;
            } else {
                fs::copy(source.join(name), destination.join(name))?;
            }
        }
        let mut copy = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(destination.join(target))?;
        io::copy(&mut seed, &mut copy)?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_dir_all(destination); }
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke_cooldown_uses_workspace_rate_and_largest_burst() {
        let rate = "limit_req_zone $binary_remote_addr zone=appdev_workspace_requests:1m rate=12r/s;";
        let bursts = vec![
            "location = /first { limit_req zone=appdev_workspace_requests burst=8 nodelay; }".to_owned(),
            "# limit_req zone=appdev_workspace_requests burst=300;\nlimit_req zone=other burst=99;\nlimit_req\n zone=appdev_workspace_requests burst=20 nodelay;".to_owned(),
        ];
        assert_eq!(ingress_cooldown(rate, &bursts).unwrap().as_millis(), 1750);
        assert_eq!(ingress_cooldown(&rate.replace("12r/s", "600r/m"), &bursts).unwrap().as_millis(), 2100);
        assert!(ingress_cooldown(&rate.replace("12r/s", "0r/s"), &bursts).is_err());
        assert!(ingress_cooldown(rate, &[]).is_err());
    }

    use super::*;

    #[test]
    fn activation_readiness_uses_the_selected_release_plan() -> Result<()> {
        let root = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects/release");
        let policy = command::Evaluator::load(&root, "activation.rel")?;
        let home = system_steps(&policy, false)?;
        let system = system_steps(&policy, true)?;
        assert!(matches!(&home.actions[0], ActivationAction::Systemd { change: ReleaseServiceChange::Stop, units }
            if units.iter().map(|unit| unit.0).collect::<Vec<_>>() == ["appdev-shop-gateway.service", "appdev-shop.service"]));
        assert!(matches!(&system.actions[3], ActivationAction::Systemd { change: ReleaseServiceChange::Restart, units }
            if units.iter().map(|unit| unit.0).collect::<Vec<_>>() == ["appdev-shop.service", "appdev-shop-gateway.service"]));
        assert!(matches!(&system.actions[4..], [ActivationAction::ValidateIngress,
            ActivationAction::ReloadIngress]));
        assert_eq!(home.probes.iter().map(|probe| probe.path.as_str()).collect::<Vec<_>>(),
            ["/workspace/home", "/workspace/work", "/front-gate/ready"]);
        assert_eq!(system.probes.iter().map(|probe| probe.path.as_str()).collect::<Vec<_>>(),
            ["/workspace/home", "/workspace/work", "/workspace/formation/records", "/shop/", "/shop/identity", "/front-gate/ready"]);
        let shop = &system.probes[4];
        assert!(shop.ready(&policy, Some(&(400, String::new())))?);
        assert!(shop.ready(&policy, Some(&(403, String::new())))?);
        assert!(!shop.ready(&policy, Some(&(200, "403".to_owned())))?);
        assert!(!shop.ready(&policy, None)?);
        assert_eq!(shop.target.tls_host(), Some(c"mcp.sourcerytech.com.au"));
        let front_gate = &home.probes[2];
        assert!(front_gate.ready(&policy, Some(&(200, "encounter/front-gate-ready/1".to_owned())))?);
        assert!(!front_gate.ready(&policy, Some(&(200, "encounter/front-gate-ready/1\n".to_owned())))?);
        assert!(!front_gate.ready(&policy, Some(&(503, "encounter/front-gate-ready/1".to_owned())))?);
        Ok(())
    }

    #[test]
    fn front_gate_readiness_checks_response_framing_and_bound() -> Result<()> {
        use std::net::{Ipv4Addr, TcpListener};
        let observe = |response: &'static [u8]| -> Result<(u16, String)> {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            let server = std::thread::spawn(move || -> io::Result<()> {
                let (mut socket, _) = listener.accept()?;
                let request = crate::http::read_bounded(&mut socket, 0, false)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                assert_eq!(request.path, "/front-gate/ready");
                assert_eq!(request.headers["host"], "front-gate-readiness");
                socket.write_all(response)?;
                Ok(())
            });
            let result = front_gate_readiness(port, "/front-gate/ready", false);
            server.join().expect("readiness fixture")?;
            result
        };
        assert_eq!(observe(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")?,
            (200, "ok".to_owned()));
        assert!(observe(b"HTTP/1.1 200 OK\r\nContent-Length: 257\r\n\r\n").is_err());
        assert!(observe(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx").is_err());
        assert!(observe(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok").is_err());
        Ok(())
    }

    #[test]
    fn activation_binds_services_to_the_shared_native_launcher() -> Result<()> {
        let root = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects/release");
        let policy = command::Evaluator::load(&root, "activation.rel")?;
        let bindings = policy.run("release.unitBindings", Value::Null)?;
        let unit = |binding: &Value, observed: Value, needs_standalone: bool| policy.run("release.unitFollows", json!({
            "binding":binding, "active":ACTIVE, "launcher":SYSTEM_DRIVER, "observed":observed,
            "needsStandalone":needs_standalone
        }));
        let follows = |binding: &Value, observed: Value| -> Result<Value> {
            Ok(unit(binding, observed, false)?["follows"].clone())
        };
        let command = |operation, arguments: &[&str]| {
            let mut argv = vec![SYSTEM_DRIVER, operation, ACTIVE];
            argv.extend_from_slice(arguments);
            json!([{"path":SYSTEM_DRIVER,"argv":argv,"ignoreErrors":false}])
        };
        let exec = command("appdev-work-host", &["/srv/work", "24252"]);
        assert_eq!(follows(&bindings[0], exec.clone())?, true);
        for (field, invalid) in [("path", json!("/usr/bin/bash")), ("ignoreErrors", json!(true)),
            ("argv", json!([SYSTEM_DRIVER, "appdev-work-host", "/srv/encounter-apps/old", "/srv/work", "24252"]))] {
            let mut crossed = exec.clone();
            crossed[0][field] = invalid;
            assert_eq!(follows(&bindings[0], crossed)?, false);
        }
        assert_eq!(follows(&bindings[0], json!([exec[0], exec[0]]))?, false);
        let gateway = |arguments: &[&str]| command("appdev-work-gateway", arguments);
        assert_eq!(unit(&bindings[1], gateway(&["/etc/work.rel"]), false)?["follows"], true);
        assert_eq!(unit(&bindings[1], gateway(&["/etc/work.rel"]), true)?["follows"], false);
        assert_eq!(unit(&bindings[1], gateway(&["/usr/local/bin/legacy", "/etc/work.rel"]), false)?["follows"], false);
        assert_eq!(unit(&bindings[1], gateway(&["/etc/work.rel", "--standalone-policy", "/srv/encounter-apps/work-policy"]), true)?,
            json!({"follows":true,"standalonePolicy":"/srv/encounter-apps/work-policy"}));
        let var = format!("APPDEV_FRONT_GATE_ACTIVE_RELEASE={ACTIVE}");
        assert_eq!(follows(&bindings[5], json!(["OTHER=one", var]))?, true);
        assert_eq!(follows(&bindings[5], json!([format!("OTHER=value {var} suffix")]))?, false);
        assert_eq!(follows(&bindings[5], json!([var, "APPDEV_FRONT_GATE_ACTIVE_RELEASE=/srv/old"]))?, false);
        assert!(ActivationAction::from_policy(&json!({"kind":"stop","units":["nginx.service"]})).is_err());
        assert!(ActivationAction::from_policy(&json!({"kind":"restart","units":["ssh.service"]})).is_err());
        assert!(ActivationAction::from_policy(&json!({"kind":"restart","units":["life-board-workgarden.service",
            "appdev-browser.service"]})).is_err());
        assert!(ActivationAction::from_policy(&json!({"kind":"reload","units":["nginx.service"]})).is_err());
        Ok(())
    }

    #[test]
    fn package_pins_require_the_exact_bundled_work_and_catalogue() -> Result<()> {
        let app = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects");
        let workflow = command::Evaluator::load(&app, "release/workflow.rel")?;
        let candidate = Scratch::create(&env::temp_dir(), "appdev-package-pins-")?;
        let home = candidate.path();
        let write = |name: &str, bytes: &str| -> Result<String> {
            let file = home.join(name);
            fs::create_dir_all(file.parent().unwrap())?;
            fs::write(file, bytes)?;
            Ok(crate::rel::hash(bytes))
        };
        let home_runtime = write("encounter", "Home runtime")?;
        let work_runtime = write("work/encounter", "Work runtime")?;
        let work_asset = write("work/asset.rel", "Work asset")?;
        let work_receipt = write("work/package-receipt.rel", &format!(
            "(\"package\", \"runtimeSha256\", \"{work_runtime}\")\n(\"artifact\", \"asset.rel\", \"{work_asset}\")\n"
        ))?;
        let catalogue = "Mobile Assurance catalogue";
        let catalogue_digest = crate::rel::hash(catalogue);
        let catalogue_path = format!("browser-assets/assurance-catalogue/{catalogue_digest}.html");
        write(&catalogue_path, catalogue)?;
        let descriptor = write(ASSURANCE_DESCRIPTOR,
            &crate::rel::encode(&json!(catalogue_digest), "ApplicationData")?)?;
        write(BROWSER_DECLARATION, "(\"application\", \"dataset\", \"assurance-catalogue\")\n")?;
        let package_receipt = |work_path: &str, asset_digest: &str| format!(
            "(\"package\", \"runtimeSha256\", \"{home_runtime}\")\n\
             (\"artifact\", \"work/encounter\", \"{work_runtime}\")\n\
             (\"artifact\", \"work/package-receipt.rel\", \"{work_receipt}\")\n\
             (\"artifact\", \"{work_path}\", \"{asset_digest}\")\n\
             (\"artifact\", \"{ASSURANCE_DESCRIPTOR}\", \"{descriptor}\")\n\
             (\"artifact\", \"{catalogue_path}\", \"{catalogue_digest}\")\n"
        );
        let verify = |system| {
            let mut artifacts = BTreeMap::new();
            let digest = appdev_assurance::hash_package(home, Some(RECEIPT), |path, digest| {
                artifacts.insert(path.to_owned(), hex::encode(digest));
            })?;
            assert_eq!(digest, fingerprint(home)?);
            verify_package_pins(&workflow, home, system, &artifacts)
        };
        let intact = package_receipt("work/asset.rel", &work_asset);
        write("package-receipt.rel", &intact)?;
        verify(true)?;
        verify(false)?;
        let standalone = appdev_release::STANDALONE_CATALOG;
        let standalone_pin = write(standalone, "Standalone catalog")?;
        assert!(verify(true).unwrap_err().to_string().contains("Missing standalone browser Wasm catalog pin"));
        let standalone_row = format!("(\"artifact\", \"{standalone}\", \"{standalone_pin}\")\n");
        write("package-receipt.rel", &format!("{intact}{standalone_row}"))?;
        verify(true)?;
        write(standalone, "Changed standalone catalog")?;
        assert!(verify(true).unwrap_err().to_string().contains("Package artifact pin is duplicate, missing, or changed"));
        fs::remove_file(home.join(standalone))?;
        write("package-receipt.rel", &intact)?;
        let home_catalog = write("browser-wasm.rel", "Home catalog")?;
        assert!(verify(true).unwrap_err().to_string().contains("Missing Home browser Wasm catalog pin"));
        let home_pinned = format!("{intact}(\"artifact\", \"browser-wasm.rel\", \"{home_catalog}\")\n");
        write("package-receipt.rel", &home_pinned)?;
        verify(true)?;
        let work_catalog = write("work/browser-wasm.rel", "Work catalog")?;
        assert!(verify(true).unwrap_err().to_string().contains("Missing Work browser Wasm catalog pin"));
        let nested = home.join("work/package-receipt.rel");
        let original_work_receipt = fs::read_to_string(&nested)?;
        let updated_work_receipt = write("work/package-receipt.rel", &format!(
            "{original_work_receipt}(\"artifact\", \"browser-wasm.rel\", \"{work_catalog}\")\n"))?;
        assert!(verify(true).is_err());
        let work_pinned = home_pinned.replace(&work_receipt, &updated_work_receipt);
        write("package-receipt.rel", &work_pinned)?;
        assert!(verify(true).unwrap_err().to_string().contains("Missing bundled Work artifact pin"));
        write("package-receipt.rel", &format!(
            "{work_pinned}(\"artifact\", \"work/browser-wasm.rel\", \"{work_catalog}\")\n"))?;
        verify(true)?;
        fs::remove_file(home.join("browser-wasm.rel"))?;
        fs::remove_file(home.join("work/browser-wasm.rel"))?;
        fs::write(nested, original_work_receipt)?;
        write("package-receipt.rel", &package_receipt("work/../work/asset.rel", &work_asset))?;
        assert!(verify(true).is_err());
        write("package-receipt.rel", &package_receipt("work/asset.rel", &home_runtime))?;
        assert!(verify(true).is_err());
        write("package-receipt.rel", &intact.replace(
            &format!("(\"artifact\", \"work/asset.rel\", \"{work_asset}\")\n"), ""))?;
        assert!(verify(true).is_err());
        write("package-receipt.rel", &intact)?;
        write(&catalogue_path, "Changed catalogue")?;
        assert!(verify(false).is_err());
        let directory = fs::File::open(home)?;
        symlink("work", home.join("alternate"))?;
        assert!(crate::package::open_artifact(&directory, Path::new("alternate/asset.rel")).is_err());
        Ok(())
    }

    fn browser_observations() -> Value {
        json!({
                "desktop-switch-mutations": 2, "desktop-repeat-mutations": 0,
                "desktop-activation-dispatches": 0, "system-catalogue-sections": 5,
                "front-gate-between-dispatches": 0, "front-gate-due-dispatches": 1,
                "front-gate-minimized-dispatches": 0, "front-gate-restore-dispatches": 1,
                "front-gate-paused-dispatches": 0, "front-gate-identical-mutations": 0,
                "front-gate-timestamp-mutations": 1, "front-gate-filtered-mutations": 0,
                "front-gate-visible-mutations": 1
        })
    }

    #[test]
    fn interaction_receipt_is_authored_only_for_complete_browser_observations() -> Result<()> {
        let digest = "a".repeat(64);
        let mut observations = browser_observations();
        let rows = appdev_assurance::interaction_rows(&digest, observations.clone())?;
        assert_eq!(rows.len(), 15);
        assert_eq!(rows[1], ["assurance", "releaseSha256", digest.as_str()]);
        assert_eq!(rows[5], ["system-catalogue-sections", "observed", "5"]);
        observations["system-catalogue-sections"] = json!(4);
        assert!(appdev_assurance::interaction_rows(&digest, observations.clone()).is_err());
        observations.as_object_mut().unwrap().remove("system-catalogue-sections");
        assert!(appdev_assurance::interaction_rows(&digest, observations.clone()).is_err());
        observations["system-catalogue-sections"] = json!(5);
        observations["unexpected"] = json!(0);
        assert!(appdev_assurance::interaction_rows(&digest, observations).is_err());
        Ok(())
    }

    #[test]
    fn system_performance_receipt_checks_current_and_saved_measurements() -> Result<()> {
        let package = Scratch::create(&env::temp_dir(), "appdev-system-assurance-test-")?;
        let home = package.path();
        let write = |file: &str, rows: &[[String; 3]]| -> Result<()> {
            let mut file = fs::File::create(home.join(file))?;
            for [subject, property, value] in rows {
                writeln!(file, "({}, {}, {})", json!(subject), json!(property), json!(value))?;
            }
            Ok(())
        };
        let metrics = [
            "home.desktop.launch", "home.mobile.launch", "work.startup", "shop.homeToShopMs",
            "shop.requestMs", "shop.reopenMs", "formation.importMs", "formation.workReopenMs",
            "formation.offlineReopenMs", "formation.receiptMs",
        ];
        let mut policy = vec![
            ["policy", "contract", "encounter/appdev-system-performance/1"],
            ["policy", "journeySamples", "3"],
            ["work.startup", "maximumExchanges", "2"],
        ];
        policy.extend(metrics.map(|name| [name, "maximumMs", "100"]));
        let home_sample = |width| json!({"viewport":{"width":width},"tested":200,"failures":0,
            "revealMs":{"count":200,"p50":5,"p95":10,"max":15}});
        let journey = |ms| json!({
            "shop":{"homeToShopMs":ms,"requestMs":ms,"reopenMs":ms},
            "formation":{"importMs":ms,"workReopenMs":ms,"offlineReopenMs":ms,"receiptMs":ms}
        });
        write(SYSTEM_POLICY, &policy.iter().map(|row| row.map(str::to_owned)).collect::<Vec<_>>())?;
        let digest = fingerprint(home)?;
        let input = json!({
            "policy":policy,"releaseSha256":digest,
            "home":{"scope":"fixture","passed":true,"results":[home_sample(1440),home_sample(390)]},
            "work":{"scope":"encounter-work-startup","passed":true,"samples":[
                {"delayMs":100,"openMs":40,"exchanges":2},{"delayMs":200,"openMs":20,"exchanges":1}]},
            "journeys":[journey(30),journey(10),journey(20)]
        });
        let facts = Facts(appdev_assurance::performance_rows(input.clone())?);
        assert_eq!(facts.0.len(), 80);
        assert_eq!(facts.one("performance.work.startup", "p50Ms")?, "20");
        assert_eq!(facts.one("performance.work.startup", "p95Ms")?, "40");
        assert_eq!(facts.one("performance.work.startup", "sample1Exchanges")?, "2");
        assert_eq!(facts.one("performance.shop.requestMs", "sample1Ms")?, "30");
        assert_eq!(facts.one("performance.shop.requestMs", "p50Ms")?, "20");
        let mut over_budget = input.clone();
        over_budget["work"]["samples"][0]["openMs"] = json!(101);
        assert!(appdev_assurance::performance_rows(over_budget).is_err());
        let mut malformed = input.clone();
        malformed["journeys"][0]["shop"]["requestMs"] = json!("30");
        assert!(appdev_assurance::performance_rows(malformed).is_err());
        let mut receipt = appdev_assurance::interaction_rows(&digest, browser_observations())?;
        write(RECEIPT, &receipt)?;
        assert!(appdev_assurance::require(home).is_err());
        receipt.extend(facts.0);
        write(RECEIPT, &receipt)?;
        appdev_assurance::require(home)?;
        let catalogue = receipt.iter().position(|row| row[0] == "system-catalogue-sections").unwrap();
        receipt[catalogue][2] = "4".into();
        write(RECEIPT, &receipt)?;
        assert!(appdev_assurance::require(home).is_err());
        receipt.remove(catalogue);
        write(RECEIPT, &receipt)?;
        appdev_assurance::require(home)?;
        let sample = receipt.iter().position(|row| row[0] == "performance.shop.requestMs" && row[1] == "sample1Ms").unwrap();
        receipt[sample][2] = "31".into();
        write(RECEIPT, &receipt)?;
        assert!(appdev_assurance::require(home).is_err());
        receipt[sample][2] = "30".into();
        write(RECEIPT, &receipt)?;
        fs::write(home.join("new-artifact.rel"), "")?;
        assert!(appdev_assurance::require(home).is_err());
        Ok(())
    }

    #[test]
    fn system_plan_requires_registry_performance_as_final_gate() -> Result<()> {
        let app = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects");
        let workflow = command::Evaluator::load(&app, "release/workflow.rel")?;
        let mut facts = Facts::read(&app.join("release/plan.rel"))?;
        let selected = plan(&workflow, &facts, "check-system", false)?;
        let gates = strings(&selected["gates"])?;
        let deployment = plan(&workflow, &facts, "deploy-system", false)?;
        let work_deployment = plan(&workflow, &facts, "deploy-work", false)?;
        assert_eq!(work_deployment["candidate"], "bundled-work-system");
        assert_eq!(work_deployment["finish"], "activate-system");
        assert_eq!(work_deployment["gates"], deployment["gates"]);
        assert_eq!(work_deployment["gates"], selected["gates"]);
        let work_check = plan(&workflow, &facts, "check-work", false)?;
        assert_eq!(work_check["candidate"], "work-with-active-home");
        assert_eq!(work_check["finish"], "return");
        assert!(strings(&work_check["gates"])?.contains(&"work-browser"));
        assert!(plan(&workflow, &facts, "preview", false).is_err());
        assert_eq!(gates.last(), Some(&"registry-performance"));
        let commands = workflow.run("release.verify", json!({"home":"/fixture/home","work":null,"gates":gates}))?;
        assert_eq!(commands.as_array().unwrap().last().unwrap(),
            &json!({"label":"registry-performance","tool":"registry-performance","args":[]}));
        let policy_gate = json!({"label":"frontend-csp-policy","tool":"routes",
            "args":["--candidate","/fixture/home","--frontend-wasm-journeys"]});
        assert!(!commands.as_array().unwrap().contains(&policy_gate));
        let browser_plan = |home_wasm, work_wasm, standalone_wasm| workflow.run("release.verify",
            json!({"home":"/fixture/home","work":null,"gates":gates,"homeWasm":home_wasm,
                "workWasm":work_wasm,"standaloneWasm":standalone_wasm}));
        let pinned = browser_plan(true, true, true)?;
        assert_eq!(pinned.as_array().unwrap().first(), Some(&policy_gate));
        let retained = workflow.run("release.verify", json!({
            "home":"/fixture/home","work":null,"gates":gates,
            "homeWasm":true,"workWasm":true,"standaloneWasm":true,"previousClients":"/fixture/previous"
        }))?;
        let mut expected = pinned.clone();
        expected[0]["args"] = json!(["--candidate", "/fixture/home", "--frontend-wasm-journeys",
            "--frontend-previous-clients", "/fixture/previous"]);
        assert_eq!(retained, expected);
        assert_eq!(browser_plan(false, false, false)?, commands);
        for mask in 1..7 {
            assert!(browser_plan(mask & 1 != 0, mask & 2 != 0, mask & 4 != 0)
                .unwrap_err().to_string().contains("requires Home, Work, and standalone browser catalogs together"));
        }
        let home_browser = |plan: &Value| -> Result<Value> {
            plan.as_array().and_then(|gates| gates.iter().find(|gate| gate["label"] == "home-browser"))
                .cloned().ok_or_else(|| fail("Expected the Home browser gate"))
        };
        assert_eq!(home_browser(&pinned)?["enforceFrontendCsp"], true);
        assert!(home_browser(&commands)?["enforceFrontendCsp"].is_null());
        let mut missing_csp = Facts(facts.0.clone());
        missing_csp.0.retain(|row| row[2] != "frontend-csp-policy");
        assert!(plan(&workflow, &missing_csp, "check-system", false).is_err());
        for gate in ["decompiler-paging", "decompiler-mount"] {
            assert!(commands.as_array().unwrap().contains(&json!({"label":gate,"tool":gate,"args":[]})));
            let mut incomplete = Facts(facts.0.clone());
            incomplete.0.retain(|row| row[2] != gate);
            assert!(plan(&workflow, &incomplete, "check-system", false).is_err());
        }
        facts.0.retain(|row| row[2] != "registry-performance");
        for operation in ["check-system", "deploy-system", "deploy-work"] {
            assert!(plan(&workflow, &facts, operation, false).is_err());
        }
        Ok(())
    }

    #[test]
    fn work_activation_admits_only_the_systems_own_bundled_package() -> Result<()> {
        let scratch = Scratch::create(&env::temp_dir(), "appdev-work-system-test-")?;
        let home = scratch.path().join("system");
        let work = home.join("work");
        fs::create_dir_all(&work)?;
        let setup = |root: &Path| -> Result<()> {
            fs::write(root.join("package-receipt.rel"), "")?;
            fs::copy("/usr/bin/true", root.join("encounter"))?;
            Ok(())
        };
        setup(&home)?;
        setup(&work)?;
        assert!(work_system(&work).is_err());
        fs::write(home.join(SYSTEM_POLICY), "")?;
        assert_eq!(work_system(&work)?, home);
        let other = home.join("other");
        fs::rename(&work, &other)?;
        symlink(&other, &work)?;
        assert!(system_work(&home).is_err());
        assert!(work_system(&other).is_err());
        Ok(())
    }

    #[test]
    fn deployment_requires_the_bound_verification_source_and_contents() -> Result<()> {
        let scratch = Scratch::create(&env::temp_dir(), "appdev-verification-test-")?;
        let workspace = scratch.path();
        let app = workspace.join("projects/applications/appdev");
        for directory in ["release", "preview", "verification/sourcery-home", "dev-jobs"] {
            fs::create_dir_all(app.join(directory))?;
        }
        for file in MAILBOX_FIXTURE_FILES {
            fs::write(app.join(file), file)?;
        }
        fs::create_dir(workspace.join("env"))?;
        let host = workspace.join(BROWSER_PROFILE);
        fs::write(&host, "browser host")?;
        for name in FRONTEND_VERIFICATION_FILES {
            let file = workspace.join(name);
            fs::create_dir_all(file.parent().unwrap())?;
            fs::write(file, name)?;
        }
        let co_build = workspace.join("projects/applications").join(CO_BUILD_DECLARATION);
        fs::create_dir_all(co_build.parent().unwrap())?;
        fs::write(&co_build, "(\"application\", \"module\", \"encounter-co-build/fixture.encounter\")\n")?;
        let module = co_build.with_file_name("fixture.encounter");
        fs::write(&module, "fixture")?;
        fs::write(app.join("release/plan.rel"), "plan")?;
        let check = app.join(LIVE_FORMATION_CHECK);
        fs::write(&check, "check")?;
        let old_identity = ["identity-management".into(), "report".into(), "{}".into()];
        let report = json!({"status":"pass"});
        let receipt = Facts(appdev_assurance::receipt_with_metadata(vec![old_identity],
            Some((app.to_str().unwrap(), &verification_digest(&app)?)), Some(report.clone()))?);
        assert_eq!(receipt.one("identity-management", "report")?, report.to_string());
        require_verification(&app, &receipt)?;
        assert!(require_verification(&app, &Facts(Vec::new())).is_err());
        assert!(require_verification(&app.join("preview"), &receipt).is_err());
        fs::write(&host, "changed")?;
        assert!(require_verification(&app, &receipt).is_err());
        fs::write(&host, "browser host")?;
        for name in FRONTEND_VERIFICATION_FILES {
            let file = workspace.join(name);
            fs::write(&file, "changed")?;
            assert!(require_verification(&app, &receipt).is_err(), "{name}");
            fs::write(file, name)?;
        }
        require_verification(&app, &receipt)?;
        fs::write(&module, "changed Co-build module")?;
        assert!(require_verification(&app, &receipt).is_err());
        fs::write(&module, "fixture")?;
        require_verification(&app, &receipt)?;
        fs::write(&check, "changed")?;
        assert!(require_verification(&app, &receipt).is_err());
        fs::remove_file(&check)?;
        assert!(require_verification(&app, &receipt).is_err());
        Ok(())
    }

    #[test]
    fn locked_activation_and_rollback_refuse_stale_pointer() -> Result<()> {
        let scratch = Scratch::create(&env::temp_dir(), "appdev-link-test-")?;
        let first = scratch.path().join("first");
        let next = scratch.path().join("next");
        let active = scratch.path().join("workspace");
        let lock = scratch.path().join("release.lock");
        fs::create_dir(&first)?;
        fs::create_dir(&next)?;
        symlink(&first, &active)?;
        assert!(locked_switch(&active, &lock, &next, &first, || Err(fail("refused"))).is_err());
        assert_eq!(active.canonicalize()?, first);
        locked_switch(&active, &lock, &next, &first, || Ok(()))?;
        assert!(locked_switch(&active, &lock, &first, &first, || Ok(())).is_err());
        assert_eq!(active.canonicalize()?, next);
        locked_switch(&active, &lock, &first, &next, || Ok(()))?;
        assert_eq!(active.canonicalize()?, first);
        Ok(())
    }

    #[test]
    fn system_switch_restores_previous_release_on_reconcile_failure() -> Result<()> {
        let root = Path::new(env!("ENCOUNTER_APPDEV_SOURCE")).join("appdev-projects/release");
        let policy = command::Evaluator::load(&root, "activation.rel")?;
        let plans = [system_steps(&policy, false)?, system_steps(&policy, true)?];
        let scratch = Scratch::create(&env::temp_dir(), "appdev-system-switch-test-")?;
        let previous = scratch.path().join("previous");
        let next = scratch.path().join("next");
        let active = scratch.path().join("workspace");
        let lock = scratch.path().join("release.lock");
        fs::create_dir(&previous)?;
        fs::create_dir(&next)?;
        fs::write(next.join(SYSTEM_POLICY), "")?;
        symlink(&previous, &active)?;
        let mut observed = Vec::new();
        let error = coordinated_switch(&active, &lock, &next, &previous, || false, || Ok(()), |target, restoring| {
            assert_eq!(active.canonicalize()?, target);
            let contender = fs::File::open(&lock)?;
            assert_ne!(unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
            assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
            observed.push((target.to_path_buf(), restoring));
            let plan = &plans[usize::from(system_package(target))];
            for probe in &plan.probes {
                let response = match probe.path.as_str() {
                    "/workspace/home" | "/workspace/formation/records" => (200, ""),
                    "/workspace/work" => (303, ""),
                    "/front-gate/ready" => (200, "encounter/front-gate-ready/1"),
                    _ => panic!("unexpected readiness probe {}", probe.path),
                };
                if !probe.ready(&policy, Some(&(response.0, response.1.to_owned())))? {
                    return Err(fail(format!("readiness failed for {}", probe.path)));
                }
            }
            Ok(())
        }).unwrap_err();
        assert!(error.to_string().contains("readiness failed for /workspace/formation/records"));
        assert!(error.to_string().contains("restored"));
        assert_eq!(observed, [(next, false), (previous.clone(), true)]);
        assert_eq!(active.canonicalize()?, previous);
        Ok(())
    }

    #[test]
    fn interrupted_activation_restores_the_exact_previous_release_under_lock() -> Result<()> {
        use std::cell::Cell;
        let scratch = Scratch::create(&env::temp_dir(), "appdev-interrupted-switch-")?;
        let previous = scratch.path().join("previous");
        let next = scratch.path().join("next");
        let active = scratch.path().join("workspace");
        let lock = scratch.path().join("release.lock");
        fs::create_dir(&previous)?;
        fs::create_dir(&next)?;
        symlink(&previous, &active)?;
        let cancelled = Cell::new(true);
        let early = coordinated_switch(&active, &lock, &next, &previous, || cancelled.get(),
            || panic!("interrupted operation reached admission"), |_, _| panic!("interrupted operation switched"));
        assert!(early.unwrap_err().to_string().contains("interrupted"));
        assert_eq!(active.canonicalize()?, previous);
        cancelled.set(false);
        let mut observed = Vec::new();
        let error = coordinated_switch(&active, &lock, &next, &previous, || cancelled.get(), || Ok(()),
            |target, restoring| {
                assert_eq!(active.canonicalize()?, target);
                let contender = fs::File::open(&lock)?;
                assert_ne!(unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                observed.push((target.to_path_buf(), restoring));
                cancelled.set(true);
                Ok(())
            }).unwrap_err();
        assert!(error.to_string().contains("interrupted"));
        assert!(error.to_string().contains("restored"));
        assert_eq!(observed, [(next, false), (previous.clone(), true)]);
        assert_eq!(active.canonicalize()?, previous);
        Ok(())
    }

}
