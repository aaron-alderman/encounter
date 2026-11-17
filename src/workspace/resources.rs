use super::{Request, Response, Result, Workspace};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
struct CpuTicks {
    total: u64,
    busy: u64,
}

impl CpuTicks {
    fn read() -> Option<Self> {
        let stat = fs::read_to_string("/proc/stat").ok()?;
        let mut fields = stat.lines().next()?.split_whitespace();
        if fields.next()? != "cpu" {
            return None;
        }
        // Guest time is already included in user and nice. Idle and I/O wait
        // do not represent time spent executing on the CPU.
        let ticks = fields.take(8).map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>().ok()?;
        let total = ticks.iter().sum::<u64>();
        let busy = total.checked_sub(ticks.get(3)? + ticks.get(4)?)?;
        Some(Self { total, busy })
    }

    fn utilization_since(self, previous: Self) -> Option<u64> {
        let total = self.total.checked_sub(previous.total)?;
        let busy = self.busy.checked_sub(previous.busy)?;
        if total == 0 || busy > total {
            return None;
        }
        Some(((u128::from(busy) * 100 + u128::from(total / 2)) / u128::from(total)) as u64)
    }
}

#[derive(Default)]
pub(super) struct CpuSample {
    previous: Option<(Instant, CpuTicks)>,
    percent: Option<u64>,
}

impl CpuSample {
    fn update(&mut self, now: Instant) -> Option<u64> {
        if self.previous.is_some_and(|(then, _)| now.duration_since(then) < Duration::from_secs(9)) {
            return self.percent;
        }
        let current = CpuTicks::read();
        self.percent = self.previous
            .filter(|(then, _)| now.duration_since(*then) <= Duration::from_secs(25))
            .and_then(|(_, previous)| current?.utilization_since(previous));
        self.previous = current.map(|ticks| (now, ticks));
        self.percent
    }
}

impl Workspace {
    pub(super) fn server_resources(&self, request: &Request) -> Result<Response> {
        let Some(identity) = self.workspace_identity(request)? else {
            return Ok(Response::empty(401));
        };
        if !self.platform_allowed(Some(&identity))? {
            return Ok(Response::empty(403));
        }

        let data = &self.runtime.private;
        let release = &self.release.root;
        let same_volume = matches!(
            (fs::metadata(data), fs::metadata(release)),
            (Ok(data), Ok(release)) if data.dev() == release.dev()
        );
        let mut disks = Vec::new();
        for (path, label) in [(data, "AppDev data"), (release, "AppDev releases")] {
            if label == "AppDev releases" && same_volume {
                break;
            }
            let usage = crate::browser_host::filesystem_usage(path)
                .map(|(total, available, percent)| json!({
                    "totalBytes":total, "availableBytes":available, "usedPercent":percent
                }))
                .unwrap_or(Value::Null);
            disks.push(json!({"label":label, "usage":usage}));
        }
        let cpu = self.runtime.resources.lock().expect("server resource samples").update(Instant::now());
        Ok(Response::json(200, &json!({
            "sampledAt":super::timestamp().1,
            "disks":disks,
            "memory":crate::browser_host::environment_memory(),
            "cpuPercent":cpu,
        })))
    }
}
