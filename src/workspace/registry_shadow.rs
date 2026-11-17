use super::transport::write_atomic;
use crate::{Result, fail, nonce::nonce, rel};
use serde_json::json;
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) const GUEST: &str = "sourcery-registry-demo";

pub(super) fn spool() -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os("APPDEV_REGISTRY_SHADOW_SPOOL")?);
    let private = path.is_absolute() && fs::symlink_metadata(&path).is_ok_and(|meta| {
        meta.is_dir() && meta.permissions().mode() & 0o077 == 0
    });
    if private { Some(path) } else {
        eprintln!("Registry Demo shadow metering disabled because its spool is not a private directory");
        None
    }
}

struct ActiveTime {
    active: Option<Instant>,
    elapsed: Duration,
}

impl ActiveTime {
    fn new(now: Instant) -> Self {
        Self { active: Some(now), elapsed: Duration::ZERO }
    }

    fn pause(&mut self, now: Instant) {
        if let Some(from) = self.active.take() {
            self.elapsed += now.saturating_duration_since(from);
        }
    }

    fn resume(&mut self, now: Instant) {
        self.active.get_or_insert(now);
    }
}

pub(super) struct Session {
    path: PathBuf,
    id: String,
    principal: String,
    started: Instant,
    started_at: u64,
    time: ActiveTime,
}

impl Session {
    pub(super) fn begin(path: &Path, principal: &str, started: Instant) -> Result<Self> {
        if principal.len() != 64 || !principal.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(fail("Invalid verified Registry Demo principal coordinate"));
        }
        let id = format!("vm-{}", nonce()?);
        let started_at = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        Ok(Self {
            path: path.join(format!("{id}.rel")),
            id,
            principal: principal.to_owned(),
            started,
            started_at,
            time: ActiveTime::new(started),
        })
    }

    pub(super) fn authorization(&mut self, checked_at: Instant, authorized: bool) {
        if authorized { self.time.resume(Instant::now()); }
        else { self.time.pause(checked_at); }
    }

    fn save(&mut self, now: Instant) -> Result<()> {
        self.time.pause(now);
        let quantity = u64::try_from(self.time.elapsed.as_millis())?;
        if quantity == 0 { return Ok(()); }
        let ended_at = self.started_at + u64::try_from(now.saturating_duration_since(self.started).as_millis())?;
        let sample = json!({
            "id": self.id,
            "principal": self.principal,
            "app": "registry-demo",
            "meter": "vm-ms",
            "unit": "ms",
            "quantity": quantity,
            "startedAtMs": self.started_at,
            "endedAtMs": ended_at,
        });
        write_atomic(&self.path, rel::encode(&sample, "AppDevRegistryShadowUsage")?.as_bytes(), false)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.save(Instant::now()).is_err() {
            eprintln!("Registry Demo shadow metering could not persist a finished console session");
        }
    }
}

#[cfg(test)]
#[test]
fn registry_shadow_excludes_paused_time() {
    let start = Instant::now();
    let mut meter = ActiveTime::new(start);
    meter.pause(start + Duration::from_millis(400));
    meter.pause(start + Duration::from_secs(1));
    meter.resume(start + Duration::from_secs(2));
    meter.resume(start + Duration::from_millis(2100));
    meter.pause(start + Duration::from_millis(2188));
    assert_eq!(meter.elapsed.as_millis(), 588);
}

#[cfg(test)]
#[test]
fn registry_shadow_persists_an_immutable_session_observation() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let spool = env::temp_dir().join(format!("registry-shadow-test-{}", nonce()?));
    fs::DirBuilder::new().mode(0o700).create(&spool)?;
    let result = (|| {
        let start = Instant::now();
        let mut session = Session::begin(&spool, &"a".repeat(64), start)?;
        session.time.pause(start + Duration::from_millis(680));
        session.save(start + Duration::from_millis(900))?;
        let record = fs::read_to_string(&session.path)?;
        let value = rel::decode(&record, "AppDevRegistryShadowUsage")?;
        assert_eq!(value["id"], session.id);
        assert_eq!(value["principal"], "a".repeat(64));
        assert_eq!(value["quantity"], 680);
        assert_eq!(value["endedAtMs"].as_u64().unwrap() - value["startedAtMs"].as_u64().unwrap(), 900);
        assert!(session.save(start + Duration::from_millis(1000)).is_err());
        assert_eq!(fs::read_to_string(&session.path)?, record);
        Ok(())
    })();
    fs::remove_dir_all(spool)?;
    result
}
