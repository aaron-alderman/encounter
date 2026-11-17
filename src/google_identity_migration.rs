use crate::{Result, appdev_host_process::{Scratch, Supervisor, exchange_paths, interruption, rename_new_path},
    fail, google_identity_custody::{self as custody, DIRECTORY, SECRET_PATH, UNIT}, process::Meter, rel};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions}, io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt}},
    path::{Path, PathBuf}, time::Duration,
};
use zeroize::Zeroizing;

const SERVICE: &str = "sourcery-google-identity.service";
const RELEASE_UNIT: &str = "/srv/sourcery/live/deployment/hosted/sourcery-google-identity.service";
const RUNTIME: &str = "/usr/local/libexec/sourcery-google-identity";
const LEGACY: &str = "/etc/sourcery-google-identity";
const LEGACY_SECRET: &str = "/etc/sourcery-google-identity/client-secret";
const BACKUP: &str = "sourcery-google-identity.service.pre-custody-v1";
const CONFIG_LIMIT: u64 = 32 * 1024;
const SECRET_LIMIT: u64 = 4096;
const SYSTEMD_TIMEOUT: Duration = Duration::from_secs(15);

trait ServiceManager {
    fn state(&mut self) -> Result<String>;
    fn reload(&mut self, restoring: bool) -> Result<()>;
}

struct Systemd;

impl ServiceManager for Systemd {
    fn state(&mut self) -> Result<String> {
        crate::systemd_user_service::SystemServices::open()?.active_state(SERVICE)
    }

    fn reload(&mut self, restoring: bool) -> Result<()> {
        crate::systemd_user_service::reload_google_identity_definition(SYSTEMD_TIMEOUT, restoring)
    }
}

struct Locations<'a> {
    legacy: &'a Path,
    canonical: &'a Path,
    unit: &'a Path,
    release_unit: &'a Path,
}

struct Ownership {
    uid: u32,
    system_gid: u32,
    service_gid: u32,
}

struct CustodyLock(File);

impl Drop for CustodyLock {
    fn drop(&mut self) {
        // An unrelated fork can briefly inherit the open description before
        // exec closes it. Release the lock independently of descriptor lifetime.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN); }
    }
}

fn check_interruption() -> Result<()> {
    if interruption().is_some() { return Err(fail("Google identity custody migration interrupted")); }
    Ok(())
}

fn protected_directory(path: &Path, uid: u32) -> Result<File> {
    let directory = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(fail("Google identity custody directory must be owner-controlled"));
    }
    Ok(directory)
}

fn read_optional(path: &Path, uid: u32, limit: u64, private: bool) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    let disallowed = if private { 0o027 } else { 0o022 };
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & disallowed != 0 || metadata.len() > limit {
        return Err(fail("Expected a bounded and protected Google identity custody file"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("Google identity custody file exceeds its size limit")); }
    Ok(Some(bytes))
}

fn read_required(path: &Path, uid: u32, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    read_optional(path, uid, limit, private)?.ok_or_else(|| fail("A required Google identity custody file is missing"))
}

fn set_permissions(file: &File, uid: u32, gid: u32, mode: u32) -> Result<()> {
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 { return Err(io::Error::last_os_error().into()); }
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn write_stage(path: &Path, bytes: &[u8], uid: u32, gid: u32, mode: u32) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    set_permissions(&file, uid, gid, mode)
}

struct Replacement {
    stage: PathBuf,
    target: PathBuf,
    existing: bool,
}

impl Replacement {
    fn sync(&self) -> Result<()> {
        for path in [&self.stage, &self.target] {
            File::open(path.parent().ok_or_else(|| fail("Missing custody publication directory"))?)?.sync_all()?;
        }
        Ok(())
    }

    fn restore(&self) -> Result<()> {
        if self.existing { exchange_paths(&self.stage, &self.target)?; }
        else { rename_new_path(&self.target, &self.stage)?; }
        self.sync()
    }
}

fn publish(changes: &mut Vec<Replacement>, stage: &Path, target: &Path, existing: bool) -> Result<()> {
    check_interruption()?;
    if existing { exchange_paths(stage, target)?; }
    else { rename_new_path(stage, target)?; }
    changes.push(Replacement { stage: stage.to_owned(), target: target.to_owned(), existing });
    changes.last().expect("recorded Google custody replacement").sync()
}

fn migrate(paths: Locations<'_>, owner: Ownership, manager: &mut impl ServiceManager) -> Result<()> {
    let unit_parent = paths.unit.parent().ok_or_else(|| fail("Missing systemd unit directory"))?;
    let custody_parent = paths.canonical.parent().ok_or_else(|| fail("Missing canonical custody parent"))?;
    let locked = protected_directory(unit_parent, owner.uid)?;
    if unsafe { libc::flock(locked.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("Google identity custody migration is already running or cannot be locked"));
    }
    let _lock = CustodyLock(locked);
    let policy = custody::policy()?;
    policy.run("custody.inactive", json!(manager.state()?), &mut Meter::new(20_000_000))?;
    protected_directory(custody_parent, owner.uid)?;
    protected_directory(paths.legacy, owner.uid)?;
    let exists = match fs::symlink_metadata(paths.canonical) {
        Ok(_) => {
            let directory = protected_directory(paths.canonical, owner.uid)?;
            let metadata = directory.metadata()?;
            if metadata.gid() != owner.service_gid || metadata.mode() & 0o7777 != 0o750 {
                return Err(fail("Existing canonical Google identity directory must have its service group and mode 0750"));
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };

    let environment = read_required(&paths.legacy.join("google.env"), owner.uid, CONFIG_LIMIT, true)?;
    let secret = read_required(&paths.legacy.join("client-secret"), owner.uid, SECRET_LIMIT, true)?;
    let target_env = paths.canonical.join("google.env");
    let target_secret = paths.canonical.join("client-secret");
    let canonical = read_optional(&target_secret, owner.uid, SECRET_LIMIT, true)?;
    let had_env = read_optional(&target_env, owner.uid, CONFIG_LIMIT, true)?.is_some();
    let release_unit = read_required(paths.release_unit, owner.uid, CONFIG_LIMIT, false)?;
    let installed = read_required(paths.unit, owner.uid, CONFIG_LIMIT, false)?;
    let target_backup = unit_parent.join(BACKUP);
    let had_backup = read_optional(&target_backup, owner.uid, CONFIG_LIMIT, false)?.is_some();
    let input = json!({"unitDigest":rel::hash(&*release_unit),"canonicalDirectory":exists,"hasBackup":had_backup,
        "environment":std::str::from_utf8(&environment)?,"secretBytes":secret.len(),"legacySecret":LEGACY_SECRET,
        "canonicalSecret":SECRET_PATH,"canonicalPresent":canonical.is_some(),
        "canonicalMatches":canonical.as_ref().is_some_and(|existing| existing.as_slice() == secret.as_slice())});
    let plan = policy.run("custody.migration", input, &mut Meter::new(20_000_000))?;
    let rewritten = plan["environment"].as_str().ok_or_else(|| fail("Missing migrated Google identity environment"))?;
    let operations = plan["operations"].as_array().ok_or_else(|| fail("Missing Google identity custody operations"))?;
    let credentials = Scratch::create(if exists { paths.canonical } else { custody_parent }, ".google-custody-")?;
    let units = Scratch::create(unit_parent, ".google-custody-")?;
    let pending_dir = credentials.path().join("custody");
    fs::DirBuilder::new().mode(0o700).create(&pending_dir)?;
    let staged_env = pending_dir.join("google.env");
    let staged_secret = pending_dir.join("client-secret");
    let staged_unit = units.path().join(SERVICE);
    let staged_backup = units.path().join(BACKUP);
    write_stage(&staged_env, rewritten.as_bytes(), owner.uid, owner.service_gid, 0o640)?;
    write_stage(&staged_secret, &secret, owner.uid, owner.service_gid, 0o640)?;
    set_permissions(&File::open(&pending_dir)?, owner.uid, owner.service_gid, 0o750)?;
    write_stage(&staged_unit, &release_unit, owner.uid, owner.system_gid, 0o644)?;
    if !had_backup { write_stage(&staged_backup, &installed, owner.uid, owner.system_gid, 0o644)?; }
    File::open(units.path())?.sync_all()?;
    File::open(credentials.path())?.sync_all()?;

    policy.run("custody.inactive", json!(manager.state()?), &mut Meter::new(20_000_000))?;
    let mut changes = Vec::new();
    let mut reload_started = false;
    let result = (|| -> Result<()> {
        for operation in operations {
            check_interruption()?;
            match operation.as_str() {
                Some("publish-environment") => publish(&mut changes, &staged_env, &target_env, had_env)?,
                Some("publish-secret") => publish(&mut changes, &staged_secret, &target_secret, canonical.is_some())?,
                Some("publish-directory") => publish(&mut changes, &pending_dir, paths.canonical, false)?,
                Some("publish-backup") => publish(&mut changes, &staged_backup, &target_backup, false)?,
                Some("publish-unit") => publish(&mut changes, &staged_unit, paths.unit, true)?,
                Some("verify-custody") => { custody::inspect_at(paths.unit, paths.canonical, Path::new(DIRECTORY), owner.uid, libc::O_PATH)?; }
                Some("reload-unit") => { reload_started = true; manager.reload(false)?; }
                _ => return Err(fail("Unknown Google identity custody operation")),
            }
        }
        check_interruption()
    })();
    if let Err(error) = result {
        let mut failures = Vec::new();
        for change in changes.iter().rev() {
            if let Err(error) = change.restore() { failures.push(error.to_string()); }
        }
        if reload_started {
            if let Err(error) = manager.reload(true) { failures.push(error.to_string()); }
        }
        if !failures.is_empty() {
            return Err(fail(format!("{error}. Custody rollback failed ({}); retained {} and {}",
                failures.join(", "), credentials.retain().display(), units.retain().display())));
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 { return Err(fail("Google identity custody migration must run as root")); }
    let _signals = Supervisor::new();
    crate::package::require_native_runtime(Path::new(RUNTIME))?;
    let runtime = fs::symlink_metadata(RUNTIME)?;
    let current = fs::metadata("/proc/self/exe")?;
    if runtime.uid() != 0 || runtime.mode() & 0o022 != 0 || runtime.dev() != current.dev() || runtime.ino() != current.ino() {
        return Err(fail("Google identity custody migration must run from the protected installed Encounter executable"));
    }
    let group = unsafe { libc::getgrnam(c"sourcery-identity".as_ptr()).as_ref() }
        .ok_or_else(|| fail("Missing sourcery-identity service group"))?.gr_gid;
    if unsafe { libc::getpwnam(c"sourcery-identity".as_ptr()).is_null() } {
        return Err(fail("Missing sourcery-identity service user"));
    }
    migrate(Locations { legacy: Path::new(LEGACY), canonical: Path::new(DIRECTORY), unit: Path::new(UNIT),
        release_unit: Path::new(RELEASE_UNIT) }, Ownership { uid: 0, system_gid: 0, service_gid: group }, &mut Systemd)?;
    println!("Google identity custody migrated; legacy custody retained at {LEGACY}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_UNIT: &[u8] = b"[Service]\nEnvironmentFile=/etc/sourcery-google-identity/google.env\n";
    const OLD_ENV: &[u8] = b"SOURCERY_GOOGLE_CLIENT_SECRET_FILE=/etc/sourcery-google-identity/client-secret\r\nEXAMPLE=retained\r\n";
    const EXPECTED_ENV: &[u8] = b"SOURCERY_GOOGLE_CLIENT_SECRET_FILE=/etc/sourcery-google/client-secret\r\nEXAMPLE=retained\r\n";
    const SECRET: &[u8] = b"fixture-secret\n";

    struct Fixture {
        _scratch: Scratch,
        legacy: PathBuf,
        canonical: PathBuf,
        unit: PathBuf,
        release_unit: PathBuf,
        uid: u32,
        gid: u32,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let scratch = Scratch::create(&std::env::temp_dir(), "google-custody-migration-")?;
            let root = scratch.path();
            let system = root.join("systemd");
            let legacy = root.join("legacy");
            let release_unit = root.join("release-unit");
            let unit = system.join(SERVICE);
            let canonical = root.join("canonical");
            let uid = fs::metadata(root)?.uid();
            let gid = fs::metadata(root)?.gid();
            for directory in [&system, &legacy] { fs::DirBuilder::new().mode(0o700).create(directory)?; }
            write_stage(&legacy.join("google.env"), OLD_ENV, uid, gid, 0o640)?;
            write_stage(&legacy.join("client-secret"), SECRET, uid, gid, 0o640)?;
            write_stage(&unit, OLD_UNIT, uid, gid, 0o644)?;
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../game-migration/sourcery-platform/deployment/hosted/sourcery-google-identity.service");
            write_stage(&release_unit, &fs::read(source)?, uid, gid, 0o644)?;
            Ok(Self { _scratch: scratch, legacy, canonical, unit, release_unit, uid, gid })
        }

        fn migrate(&self, manager: &mut impl ServiceManager) -> Result<()> {
            migrate(Locations { legacy: &self.legacy, canonical: &self.canonical, unit: &self.unit, release_unit: &self.release_unit },
                Ownership { uid: self.uid, system_gid: self.gid, service_gid: self.gid }, manager)
        }

        fn backup(&self) -> PathBuf { self.unit.with_file_name(BACKUP) }
    }

    struct Manager {
        state: &'static str,
        failure: Option<&'static str>,
        reloads: Vec<bool>,
    }

    impl Manager {
        fn inactive() -> Self { Self { state: "inactive", failure: None, reloads: Vec::new() } }
    }

    impl ServiceManager for Manager {
        fn state(&mut self) -> Result<String> { Ok(self.state.to_owned()) }

        fn reload(&mut self, restoring: bool) -> Result<()> {
            self.reloads.push(restoring);
            match (restoring, self.failure) {
                (false, Some("reload")) => Err(fail("fixture reload failed")),
                (false, Some("interrupt")) => {
                    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    #[test]
    fn migrates_only_the_matched_native_unit_and_keeps_legacy_custody() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut manager = Manager { state: "active", ..Manager::inactive() };
        assert!(fixture.migrate(&mut manager).unwrap_err().to_string().contains("inactive"));
        assert!(!fixture.canonical.exists());
        assert!(!fixture.backup().exists());
        manager.state = "inactive";
        let matched_unit = fs::read(&fixture.release_unit)?;
        fs::write(&fixture.release_unit, [matched_unit.as_slice(), b"\n# changed"].concat())?;
        let mismatch = fixture.migrate(&mut manager).unwrap_err();
        assert!(mismatch.to_string().contains("matching native service unit"), "{mismatch}");
        assert!(!fixture.canonical.exists());
        fs::write(&fixture.release_unit, &matched_unit)?;
        fixture.migrate(&mut manager)?;
        assert_eq!(fs::read(&fixture.unit)?, matched_unit);
        assert_eq!(fs::read(fixture.backup())?, OLD_UNIT);
        assert_eq!(fs::read(fixture.legacy.join("google.env"))?, OLD_ENV);
        assert_eq!(fs::read(fixture.legacy.join("client-secret"))?, SECRET);
        assert_eq!(fs::read(fixture.canonical.join("google.env"))?, EXPECTED_ENV);
        assert_eq!(fs::read(fixture.canonical.join("client-secret"))?, SECRET);
        fixture.migrate(&mut manager)?;
        assert_eq!(fs::read(fixture.backup())?, OLD_UNIT);
        assert_eq!(manager.reloads, [false, false]);
        fs::write(fixture.canonical.join("client-secret"), b"other-protected-secret")?;
        assert!(fixture.migrate(&mut manager).unwrap_err().to_string().contains("conflicts"));
        assert_eq!(manager.reloads, [false, false]);
        Ok(())
    }

    #[test]
    fn reload_failure_restores_prior_custody_inodes_and_service() -> Result<()> {
        let fixture = Fixture::new()?;
        let directory = &fixture.canonical;
        fs::DirBuilder::new().mode(0o750).create(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
        let env = directory.join("google.env");
        let secret = directory.join("client-secret");
        write_stage(&env, b"unchanged environment", fixture.uid, fixture.gid, 0o640)?;
        write_stage(&secret, SECRET, fixture.uid, fixture.gid, 0o640)?;
        write_stage(&directory.join("unrelated"), b"unrelated", fixture.uid, fixture.gid, 0o600)?;
        let inodes = [&fixture.unit, &env, &secret].map(|path| fs::metadata(path).unwrap().ino());
        let mut manager = Manager { failure: Some("reload"), ..Manager::inactive() };
        assert_eq!(fixture.migrate(&mut manager).unwrap_err().to_string(), "fixture reload failed");
        assert_eq!(manager.reloads, [false, true]);
        assert_eq!(inodes, [&fixture.unit, &env, &secret].map(|path| fs::metadata(path).unwrap().ino()));
        assert_eq!(fs::read(&fixture.unit)?, OLD_UNIT);
        assert_eq!(fs::read(&env)?, b"unchanged environment");
        assert_eq!(fs::read(&secret)?, SECRET);
        assert_eq!(fs::read(directory.join("unrelated"))?, b"unrelated");
        assert!(!fixture.backup().exists());
        Ok(())
    }

    #[test]
    fn sigterm_restores_the_prior_service_and_removes_new_custody() -> Result<()> {
        const CHILD: &str = "ENCOUNTER_TEST_GOOGLE_CUSTODY_SIGNAL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let mut command = std::process::Command::new(std::env::current_exe()?);
            command.args(["--exact", "google_identity_migration::tests::sigterm_restores_the_prior_service_and_removes_new_custody"])
                .env(CHILD, "1");
            Supervisor::children().capture("Exercise Google custody SIGTERM rollback", &mut command, Duration::from_secs(10), 8192)?;
            return Ok(());
        }
        let _signals = Supervisor::new();
        let fixture = Fixture::new()?;
        let mut manager = Manager { failure: Some("interrupt"), ..Manager::inactive() };
        assert!(fixture.migrate(&mut manager).unwrap_err().to_string().contains("interrupted"));
        assert_eq!(interruption(), Some(143));
        assert_eq!(manager.reloads, [false, true]);
        assert_eq!(fs::read(&fixture.unit)?, OLD_UNIT);
        assert!(!fixture.canonical.exists());
        assert!(!fixture.backup().exists());
        Ok(())
    }
}
