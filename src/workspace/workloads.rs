use super::{Request, Response, Result, Workspace};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const STORAGE_REPORT: &str = "/var/lib/sourcery-appdev-workloads/storage.json";
const STORAGE_AREAS: &[(&str, &str)] = &[
    ("projects", "Other development projects"),
    ("apps", "Application development"),
    ("platform", "Encounter platform development"),
    ("os", "Sourcery OS development and VM images"),
    ("media", "Media and game development"),
    ("research", "Research workspaces"),
    ("rollouts", "Release staging"),
    ("builds", "Build outputs"),
    ("state", "Development run state"),
    ("evidence", "Build receipts, logs and jobs"),
    ("environment", "Development toolchains"),
    ("copies", "Preserved workspace copies"),
    ("releases", "Installed Encounter releases"),
    ("hosted", "Sourcery hosted application data"),
    ("logs", "System logs"),
];

#[derive(Clone, Copy)]
struct Counters {
    group: &'static str,
    usage: Option<u64>,
    memory: Option<u64>,
}

type Sources = BTreeMap<(String, u64), Counters>;

fn service_group(unit: &str) -> &'static str {
    match unit {
        "appdev-workspace.service" | "appdev-browser.service" => "AppDev Home and browser runtime",
        "appdev-identity-gateway.service" | "sourcery-google-identity.service" => "Identity and sign-in",
        "appdev-linux-vm.service" | "appdev-vm-manager.service" | "appdev-vm-display.service"
        | "appdev-linux-terminal-bridge.service" => "AppDev virtual machines",
        "nginx.service" | "redis-server.service" => "Shared web infrastructure",
        _ if unit.starts_with("sourcery-aster") => "Ask Aster",
        _ if unit.starts_with("appdev-life-board") => "Life Board",
        _ if unit.starts_with("appdev-shop") => "Shop",
        _ if unit.starts_with("sim-museum-") => "Sim Museum previews and jobs",
        _ if unit.starts_with("claimipedia-") => "Claimipedia",
        _ if unit.starts_with("worldwright-") || unit.starts_with("encounter-worldbox") => "Worldwright and Worldbox",
        _ if unit.starts_with("usewords-") => "Usewords",
        _ if unit.starts_with("postgresql") => "Shared databases",
        _ if unit.starts_with("encounter-") || unit.starts_with("sourcery-") || unit.starts_with("appdev-") => "Other Sourcery and Encounter services",
        _ => "Other Linux services",
    }
}

fn read_group(path: &Path, name: String, group: &'static str, sources: &mut Sources) {
    let Ok(metadata) = fs::symlink_metadata(path) else { return };
    if !metadata.is_dir() { return; }
    let memory = fs::read_to_string(path.join("memory.current")).ok()
        .and_then(|text| text.trim().parse().ok());
    let usage = fs::read_to_string(path.join("cpu.stat")).ok().and_then(|text| {
        text.lines().find_map(|line| line.strip_prefix("usage_usec "))
            .and_then(|value| value.trim().parse().ok())
    });
    if memory.is_some() || usage.is_some() {
        sources.insert((name, metadata.ino()), Counters { group, usage, memory });
    }
}

fn read_sources(root: &Path) -> Sources {
    let mut sources = Sources::new();
    let system = root.join("system.slice");
    if let Ok(entries) = fs::read_dir(system) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            read_group(&entry.path(), name.clone(), service_group(&name), &mut sources);
        }
    }
    read_group(&root.join("user.slice"), "user.slice".to_owned(), "Development sessions and user jobs", &mut sources);
    read_group(&root.join("machine.slice"), "machine.slice".to_owned(), "Other virtual machines and containers", &mut sources);
    sources
}

#[derive(Default)]
struct Workload {
    sources: usize,
    memory: Option<u64>,
    cpu_micros: Option<u64>,
}

fn total(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (current, next) {
        (Some(current), Some(next)) => Some(current.saturating_add(next)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn workload_rows(current: &Sources, last: Option<(&Sources, Duration)>, cores: u32) -> Vec<Value> {
    let mut groups = BTreeMap::<_, Workload>::new();
    for (key, counters) in current {
        let group = groups.entry(counters.group).or_default();
        group.sources += 1;
        group.memory = total(group.memory, counters.memory);
        let delta = last.and_then(|(previous, _)| {
            counters.usage?.checked_sub(previous.get(key)?.usage?)
        });
        group.cpu_micros = total(group.cpu_micros, delta);
    }

    let mut rows = groups.into_iter().map(|(label, row)| {
        let cpu = row.cpu_micros.and_then(|used| {
            let capacity = last?.1.as_micros().checked_mul(u128::from(cores))?;
            (capacity > 0).then(|| (u128::from(used) * 1000 / capacity).min(1000) as u64)
        });
        (cpu, row.memory, json!({
            "activity":label, "groups":row.sources, "cpuTenths":cpu, "memoryBytes":row.memory
        }))
    }).collect::<Vec<_>>();
    rows.sort_by(|left, right| (right.0, right.1).cmp(&(left.0, left.1)));
    rows.into_iter().map(|(_, _, row)| row).collect()
}

#[derive(Default)]
pub(super) struct WorkloadSample {
    previous: Option<(Instant, Sources)>,
    rows: Vec<Value>,
    sampled_at: String,
}

impl WorkloadSample {
    fn update(&mut self, now: Instant) {
        if self.previous.as_ref().is_some_and(|(then, _)| now.duration_since(*then) < Duration::from_secs(9)) {
            return;
        }
        let current = read_sources(Path::new("/sys/fs/cgroup"));
        let last = self.previous.as_ref().and_then(|(then, before)| {
            let elapsed = now.duration_since(*then);
            (elapsed <= Duration::from_secs(25)).then_some((before, elapsed))
        });
        let cores = fs::read_to_string("/proc/stat").ok().map(|stat| {
            stat.lines().filter(|line| line.strip_prefix("cpu")
                .is_some_and(|suffix| suffix.starts_with(|ch: char| ch.is_ascii_digit()))).count() as u32
        }).unwrap_or(0);
        self.rows = workload_rows(&current, last, cores);
        self.previous = Some((now, current));
        self.sampled_at = super::timestamp().1;
    }
}

fn storage_report() -> Option<Value> {
    let file = fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(STORAGE_REPORT).ok()?;
    if !file.metadata().ok()?.is_file() { return None; }
    let mut report = String::new();
    file.take(8192).read_to_string(&mut report).ok()?;
    let data: Value = serde_json::from_str(&report).ok()?;
    let sampled_at = chrono::DateTime::parse_from_rfc3339(data["sampledAt"].as_str()?).ok()?;
    let mut areas = STORAGE_AREAS.iter().copied().map(|(key, label)| {
        let bytes = data["areas"][key]["bytes"].as_u64();
        let partial = data["areas"][key]["partial"] == true;
        (bytes, json!({"activity":label, "bytes":bytes, "partial":partial}))
    }).collect::<Vec<_>>();
    areas.sort_by(|left, right| right.0.cmp(&left.0));
    Some(json!({
        "sampledAt": sampled_at.to_rfc3339(),
        "areas":areas.into_iter().map(|(_, area)| area).collect::<Vec<_>>(),
    }))
}

impl Workspace {
    pub(super) fn server_workloads(&self, request: &Request, query: &super::Fields) -> Result<Response> {
        let Some(identity) = self.workspace_identity(request)? else {
            return Ok(Response::empty(401));
        };
        if !self.platform_allowed(Some(&identity))? {
            return Ok(Response::empty(403));
        }
        let mut sample = self.runtime.workloads.lock().expect("workspace workload samples");
        sample.update(Instant::now());
        let mut activities = sample.rows.clone();
        if query.get("sort") == Some("memory") {
            activities.sort_by_key(|row| std::cmp::Reverse(row["memoryBytes"].as_u64()));
        }
        Ok(Response::json(200, &json!({
            "sampledAt":sample.sampled_at,
            "activities":activities,
            "storage":storage_report(),
        })))
    }
}
