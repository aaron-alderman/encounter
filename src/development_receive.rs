use crate::{Result, appdev_host_process::{Scratch, ServiceTool, Supervisor, interruption}, fail, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet, ffi::OsString, fs::{File, OpenOptions}, io::{self, Write},
    os::{fd::AsRawFd, unix::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt}},
    path::{Path, PathBuf}, process::{Command, Stdio}, time::{Duration, Instant},
};

pub(super) const HOOK_NAME: &str = "post-receive";
const CANONICAL: &str = "/srv/git/sourcery.git";
const CHECKOUT: &str = "/srv/sourcery/dev/sourcery";
const PACK_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const OBSERVATION: Duration = Duration::from_secs(10);
const TRANSFER: Duration = Duration::from_secs(90);

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("development_receive.encounter").to_owned()],
        &["receive.batch", "receive.configuration", "receive.admit", "receive.merge", "receive.complete"],
        &BTreeSet::from(["kernel.invoke", "number.calculate", "text.match", "text.matches"]), &mut Meter::new(1_000_000))
}

fn decide(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(1_000_000))
}

fn field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field].as_str().ok_or_else(|| fail("Expected a typed development receive decision"))
}

pub(super) fn git() -> Result<Command> {
    let mut command = ServiceTool::Git.command()?;
    command.current_dir("/").env("PATH", "/usr/bin:/bin").env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0").env("GIT_TERMINAL_PROMPT", "0").env("GIT_ALLOW_PROTOCOL", "")
        .args(["--no-pager", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "core.attributesFile=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "-c", "submodule.recurse=false"]);
    Ok(command)
}

fn observe(command: &mut Command, limit: usize) -> Result<Vec<u8>> {
    Supervisor::children().capture("Read development Git state", command, OBSERVATION, limit)
}

fn directory(path: &Path, uid: u32) -> Result<()> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o002 != 0 || path.canonicalize()? != path {
        return Err(fail("Expected an owned, canonical development Git directory"));
    }
    Ok(())
}

fn check_configuration(policy: &Programme, path: &Path, uid: u32) -> Result<()> {
    let config = path.join("config");
    let metadata = config.symlink_metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o002 != 0 || metadata.len() > 32_768 {
        return Err(fail("Expected a bounded, owned development Git configuration"));
    }
    for name in ["commondir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates"] {
        match path.join(name).symlink_metadata() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(fail("Development receive refuses alternate Git storage or worktree configuration")),
        }
    }
    let keys = observe(git()?.args(["config", "--no-includes", "--file"]).arg(config).args(["--null", "--name-only", "--list"]), 32_768)?;
    let keys = std::str::from_utf8(&keys)?.split_terminator('\0').collect::<Vec<_>>();
    decide(policy, "receive.configuration", json!(keys))?;
    Ok(())
}

pub(crate) fn inspect_checkout(root: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", checkout_status(root)?);
    Ok(())
}

fn admit_checkout(root: &Path) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    directory(root, uid)?;
    let metadata = root.join(".git");
    directory(&metadata, uid)?;
    check_configuration(&policy()?, &metadata, uid)
}

pub(crate) fn historical_source(root: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    let input = crate::platform_import_closure::read_bounded_observation(8192)?;
    io::stdout().lock().write_all(&read_historical_source(root, input)?)?;
    Ok(())
}

fn read_historical_source(root: &Path, input: Value) -> Result<Vec<u8>> {
    let entry = "receive.historicalSource";
    let policy = Programme::admit(&[include_str!("development_receive.encounter").to_owned()], entry,
        &BTreeSet::from(["text.matches"]), &mut Meter::new(100_000))?;
    let object = decide(&policy, entry, input.clone())?;
    let revision = field(&input, "revision")?;
    let path = field(&input, "path")?;
    admit_checkout(root)?;
    let git_at_root = || -> Result<Command> {
        let mut command = git()?;
        command.arg("-C").arg(root);
        Ok(command)
    };
    let committed = observe(git_at_root()?.args(["rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{revision}^{{commit}}")), 64)?;
    if revision_text(&committed)? != revision {
        return Err(fail("Expected an exact development commit"));
    }
    let listing = observe(git_at_root()?.args(["--literal-pathspecs", "ls-tree", "-z", revision, "--", path]), 8192)?;
    let listing = std::str::from_utf8(&listing)?;
    let Some((metadata, listed_path)) = listing.split_once('\t') else {
        return Err(fail("Historical source is missing from the development commit"));
    };
    if !matches!(metadata.split_once(' '), Some(("100644" | "100755", _)))
        || listed_path.strip_suffix('\0') != Some(path) {
        return Err(fail("Historical source must be a regular tracked file"));
    }
    observe(git_at_root()?.args(["cat-file", "blob"]).arg(object.as_str()
        .ok_or_else(|| fail("Missing historical source object"))?), 64 * 1024 * 1024)
}

fn checkout_status(root: &Path) -> Result<Value> {
    admit_checkout(root)?;
    let observation = Programme::admit(
        &[include_str!("development_receive.encounter").to_owned()], "receive.repositoryStatus",
        &BTreeSet::from(["kernel.invoke", "text.matches", "text.split", "text.slice", "number.calculate", "record.put"]),
        &mut Meter::new(100_000))?;
    let read = |arguments: &[&str], limit| -> Result<String> {
        Ok(String::from_utf8(observe(git()?.arg("-C").arg(root).args(arguments), limit)?)?)
    };
    let head = read(&["rev-parse", "--verify", "HEAD^{commit}"], 64)?;
    let branch = read(&["branch", "--show-current"], 4096)?;
    let state = read(&["status", "--porcelain=v2", "--branch", "--untracked-files=no", "--ignore-submodules=all"], 1024 * 1024)?;
    let paths = read(&["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all"], 1024 * 1024)?;
    let mut upstream = "";
    let mut ahead = 0_u64;
    let mut behind = 0_u64;
    for line in state.lines() {
        if let Some(value) = line.strip_prefix("# branch.upstream ") { upstream = value; }
        if let Some(value) = line.strip_prefix("# branch.ab +") {
            let (left, right) = value.split_once(" -").ok_or_else(|| fail("Malformed Git branch counts"))?;
            ahead = left.parse()?;
            behind = right.parse()?;
        }
    }
    if read(&["rev-parse", "--verify", "HEAD^{commit}"], 64)? != head {
        return Err(fail("Git HEAD changed during development repository observation"));
    }
    observation.run("receive.repositoryStatus", json!({
        "head":revision_text(head.as_bytes())?, "branch":branch.trim_end(), "upstream":upstream,
        "ahead":ahead,"behind":behind,"paths":paths.split_terminator('\0').collect::<Vec<_>>(),
    }), &mut Meter::new(12_000_000))
}

struct Repositories<'a> { canonical: &'a Path, checkout: &'a Path, local: PathBuf }

impl Repositories<'_> {
    fn bare(&self) -> Result<Command> {
        let mut argument = OsString::from("--git-dir=");
        argument.push(self.canonical);
        let mut command = git()?;
        command.arg(argument);
        Ok(command)
    }

    fn checkout(&self) -> Result<Command> {
        let mut command = git()?;
        command.arg("-C").arg(self.checkout);
        Ok(command)
    }

    fn snapshot(&self, restoring: bool) -> Result<Value> {
        let capture = |command: &mut Command, limit| {
            let mut supervisor = if restoring { Supervisor::release_recovery() } else { Supervisor::children() };
            supervisor.capture("Read development checkout", command, OBSERVATION, limit)
        };
        let branch = capture(self.checkout()?.args(["symbolic-ref", "--quiet", "HEAD"]), 4096)
            .map_err(|_| fail("Development checkout is on the wrong branch or has no symbolic HEAD"))?;
        let revision = capture(self.checkout()?.args(["rev-parse", "--verify", "HEAD^{commit}"]), 64)?;
        let dirty = capture(self.checkout()?.args(["status", "--porcelain=v1", "--untracked-files=normal"]), 64 * 1024)?;
        Ok(json!({"branch":std::str::from_utf8(&branch)?.trim_end(),"current":revision_text(&revision)?,"clean":dirty.is_empty()}))
    }

    fn canonical_revision(&self, reference: &str) -> Result<String> {
        let bytes = observe(self.bare()?.args(["rev-parse", "--verify"]).arg(format!("{reference}^{{commit}}")), 64)?;
        Ok(revision_text(&bytes)?.to_owned())
    }

    fn ancestor(&self, previous: &str, next: &str) -> Result<bool> {
        let (status, _) = Supervisor::children().capture_status("Check canonical fast-forward",
            self.bare()?.args(["merge-base", "--is-ancestor", previous, next]).stderr(Stdio::null()), OBSERVATION, 64)?;
        match status.code() {
            Some(0) => Ok(true),
            // A local-only predecessor may not be present in the canonical repository.
            Some(1 | 128) => Ok(false),
            _ => Err(fail("Could not check canonical fast-forward")),
        }
    }

    fn import(&self, current: &str, next: &str) -> Result<()> {
        let scratch = Scratch::create(&self.local, ".sourcery-receive-")?;
        let revisions = scratch.path().join("revisions");
        let mut list = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&revisions)?;
        writeln!(list, "{next}\n^{current}")?;
        drop(list);
        let mut pack = self.bare()?;
        pack.args(["pack-objects", "--quiet", "--revs"]).arg(scratch.path().join("received"))
            .stdin(Stdio::from(File::open(&revisions)?));
        limit_pack(&mut pack);
        let identity = Supervisor::children().capture("Pack canonical development objects", &mut pack, TRANSFER, 64)?;
        let identity = revision_text(&identity)?;
        let packed = File::open(scratch.path().join(format!("received-{identity}.pack")))?;
        let metadata = packed.metadata()?;
        if !metadata.is_file() || metadata.len() > PACK_LIMIT { return Err(fail("Received Git pack exceeds its bound")); }
        let mut index = self.checkout()?;
        index.args(["index-pack", "--stdin", "--strict"]).stdin(Stdio::from(packed));
        limit_pack(&mut index);
        let outcome = Supervisor::children().capture("Verify and import canonical development objects", &mut index, TRANSFER, 64)?;
        if std::str::from_utf8(&outcome)?.trim_end().strip_prefix("pack\t") != Some(identity) {
            return Err(fail("Indexed development pack differs from the canonical pack identity"));
        }
        Ok(())
    }
}

fn limit_pack(command: &mut Command) {
    // The native Git pack ports can write only bounded files.
    unsafe {
        command.pre_exec(|| {
            let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            if libc::getrlimit(libc::RLIMIT_FSIZE, limit.as_mut_ptr()) != 0 { return Err(io::Error::last_os_error()); }
            let mut limit = limit.assume_init();
            limit.rlim_cur = limit.rlim_cur.min(PACK_LIMIT);
            limit.rlim_max = limit.rlim_max.min(PACK_LIMIT);
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 { return Err(io::Error::last_os_error()); }
            Ok(())
        });
    }
}

pub(super) fn revision_text(bytes: &[u8]) -> Result<&str> {
    let revision = std::str::from_utf8(bytes)?.trim_end();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(fail("Expected a canonical Git revision"));
    }
    Ok(revision)
}

fn inspect_tree(command: &mut Command, revision: &str) -> Result<()> {
    let entries = observe(command.args(["ls-tree", "-r", "-z", "--full-tree", revision]), 8 * 1024 * 1024)?;
    if entries.split(|byte| *byte == 0).any(|entry| entry.starts_with(b"160000 ")) {
        return Err(fail("Development receive does not allow nested Git submodules"));
    }
    Ok(())
}

fn lock(path: &Path, uid: u32) -> Result<File> {
    let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path.join("sourcery-development-receive.lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
        return Err(fail("Development receive lock is not a private, owned file"));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("Another development receive hook is active"));
    }
    Ok(lock)
}

fn advance(policy: &Programme, canonical: &Path, checkout: &Path, update: &Value, uid: u32) -> Result<()> {
    let reference = field(update, "ref")?;
    let revision = field(update, "revision")?;
    let repos = Repositories { canonical, checkout, local: checkout.join(".git") };
    for path in [canonical, checkout, &repos.local] { directory(path, uid)?; }
    let _lock = lock(&repos.local, uid)?;
    for config in [canonical, &repos.local] { check_configuration(policy, config, uid)?; }
    let current = observe(repos.checkout()?.args(["rev-parse", "--verify", "HEAD^{commit}"]), 64)?;
    let current = revision_text(&current)?;
    let canonical_revision = repos.canonical_revision(reference)?;
    inspect_tree(&mut repos.checkout()?, current)?;
    inspect_tree(&mut repos.bare()?, &canonical_revision)?;
    let mut state = repos.snapshot(false)?;
    state["ref"] = json!(reference);
    state["revision"] = json!(revision);
    state["canonical"] = json!(canonical_revision);
    state["ancestor"] = json!(repos.ancestor(field(&state, "current")?, &canonical_revision)?);
    let admitted = decide(policy, "receive.admit", state.clone())?;
    match admitted.as_str() {
        Some("current") => return Ok(()),
        Some("import") => {}
        _ => return Err(fail("Unknown development receive action")),
    }
    let previous = field(&state, "current")?;
    repos.import(previous, revision)?;
    for config in [canonical, &repos.local] { check_configuration(policy, config, uid)?; }
    let mut observed = repos.snapshot(false)?;
    observed["ref"] = json!(reference);
    observed["revision"] = json!(revision);
    observed["previous"] = json!(previous);
    observed["canonical"] = json!(repos.canonical_revision(reference)?);
    observed["imported"] = json!(revision_text(&observe(repos.checkout()?.args(["rev-parse", "--verify"])
        .arg(format!("{revision}^{{commit}}")), 64)?)?);
    if decide(policy, "receive.merge", observed)? != "merge" { return Err(fail("Development fast-forward was not admitted")); }
    if interruption().is_some() { return Err(fail("Development receive interrupted before fast-forward")); }
    // Let a started fast-forward finish across a graceful interruption, then verify its state.
    Supervisor::release_recovery().run_until("Fast-forward development checkout", repos.checkout()?.args([
        "merge", "--ff-only", "--no-edit", "--no-autostash", "--no-overwrite-ignore", "--no-verify-signatures", "--no-stat", revision,
    ]).stdout(Stdio::null()), Some(TRANSFER))?;
    let mut completed = repos.snapshot(true)?;
    completed["ref"] = json!(reference);
    completed["revision"] = json!(revision);
    decide(policy, "receive.complete", completed)?;
    eprintln!("Advanced Sourcery development checkout to {revision}.");
    Ok(())
}

fn read_updates() -> Result<Vec<u8>> {
    let deadline = Instant::now() + OBSERVATION;
    let mut input = Vec::new();
    let mut bytes = [0_u8; 4096];
    loop {
        if interruption().is_some() || Instant::now() >= deadline { return Err(fail("Development receive input interrupted or timed out")); }
        let mut poll = libc::pollfd { fd: libc::STDIN_FILENO, events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, 100) };
        if ready == 0 { continue; }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        let read = unsafe { libc::read(libc::STDIN_FILENO, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read == 0 { return Ok(input); }
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        input.extend_from_slice(&bytes[..read as usize]);
        if input.len() > 65_536 { return Err(fail("Development receive records exceed their size bound")); }
    }
}

pub(crate) fn run() -> Result<()> {
    let _signals = Supervisor::new();
    let uid = unsafe { libc::geteuid() };
    let account = unsafe { libc::getpwnam(c"sourcery-dev".as_ptr()).as_ref() }
        .ok_or_else(|| fail("Missing Sourcery development account"))?;
    if uid == 0 || uid != account.pw_uid { return Err(fail("Development receive must run as sourcery-dev")); }
    let canonical = Path::new(CANONICAL);
    if std::env::current_dir()? != canonical { return Err(fail("Development receive must run in the canonical bare repository")); }
    let policy = policy()?;
    let bytes = read_updates()?;
    let lines: Vec<_> = std::str::from_utf8(&bytes)?.split_terminator('\n').collect();
    let batch = decide(&policy, "receive.batch", json!(lines))?;
    for update in batch.as_array().ok_or_else(|| fail("Expected admitted development receive updates"))? {
        match field(update, "action")? {
            "deleted" => eprintln!("Sourcery development checkout was not changed after canonical branch deletion."),
            "advance" => advance(&policy, canonical, Path::new(CHECKOUT), update, uid)?,
            _ => return Err(fail("Unknown development receive record")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, thread};

    const BRANCH: &str = "codex/self-hosted-production";
    const REFERENCE: &str = "refs/heads/codex/self-hosted-production";

    fn fixture_git(directory: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
        let mut command = git()?;
        command.env("GIT_ALLOW_PROTOCOL", "file").arg("-C").arg(directory)
            .args(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"]).args(arguments);
        observe(&mut command, 8192)
    }

    #[test]
    fn historical_source_reads_exact_commit_and_refuses_non_file_paths() -> Result<()> {
        let fixture = Fixture::new()?;
        let root = &fixture.checkout;
        fs::write(root.join("state"), b"working tree only\n")?;
        let observe = |revision: &str, path: &str| read_historical_source(root, json!({"revision":revision, "path":path}));
        assert_eq!(observe(&fixture.start, "state")?, b"before\n");
        for path in ["missing", "../state", "./state", "/state", "state\n"] {
            assert!(observe(&fixture.start, path).is_err(), "{path}");
        }
        assert!(observe("HEAD", "state").is_err());
        std::os::unix::fs::symlink("state", root.join("link"))?;
        fixture_git(root, &["add", "link"])?;
        fixture_git(root, &["commit", "--quiet", "-m", "retain symlink"])?;
        let head = fixture_git(root, &["rev-parse", "HEAD"])?;
        assert!(observe(revision_text(&head)?, "link").is_err());
        Ok(())
    }

    #[test]
    fn repository_status_reports_renames_and_refuses_unadmitted_git_configuration() -> Result<()> {
        let fixture = Fixture::new()?;
        let clean = checkout_status(&fixture.checkout)?;
        assert_eq!(clean["syncStatus"], "aligned");
        assert_eq!(clean["automaticAdvanceReady"], true);
        fixture_git(&fixture.checkout, &["mv", "state", "renamed"])?;
        fs::write(fixture.checkout.join("untracked "), b"new")?;
        let dirty = checkout_status(&fixture.checkout)?;
        assert_eq!(dirty["syncStatus"], "dirty");
        assert_eq!(dirty["changes"]["items"], json!([
            {"code":"R ","kind":"tracked","path":"renamed","originalPath":"state"},
            {"code":"??","kind":"untracked","path":"untracked "},
        ]));
        fixture_git(&fixture.checkout, &["config", "core.fsmonitor", "unadmitted"])?;
        assert!(checkout_status(&fixture.checkout).unwrap_err().to_string().contains("outside the development receive port"));
        Ok(())
    }

    struct Fixture { _scratch: Scratch, canonical: PathBuf, checkout: PathBuf, author: PathBuf, uid: u32, start: String }

    impl Fixture {
        fn new() -> Result<Self> {
            let scratch = Scratch::create(&std::env::temp_dir(), "development-receive-test-")?;
            let base = scratch.path();
            let canonical = base.join("canonical.git");
            let checkout = base.join("checkout");
            let author = base.join("author");
            let canonical_text = canonical.to_str().ok_or_else(|| fail("Invalid fixture path"))?;
            fixture_git(base, &["init", "--bare", "--quiet", "canonical.git"])?;
            fixture_git(base, &["init", "--quiet", "--initial-branch", BRANCH, "author"])?;
            fs::write(author.join("state"), b"before\n")?;
            fixture_git(&author, &["add", "state"])?;
            fixture_git(&author, &["commit", "--quiet", "-m", "initial"])?;
            fixture_git(&author, &["push", "--quiet", canonical_text, REFERENCE])?;
            fixture_git(base, &["clone", "--quiet", "--no-hardlinks", "--branch", BRANCH, canonical_text, "checkout"])?;
            let start = revision_text(&fixture_git(&checkout, &["rev-parse", "HEAD"])?)?.to_owned();
            let uid = fs::metadata(base)?.uid();
            Ok(Self { _scratch: scratch, canonical, checkout, author, uid, start })
        }

        fn push(&self, file: &str, contents: &[u8]) -> Result<String> {
            fs::write(self.author.join(file), contents)?;
            fixture_git(&self.author, &["add", file])?;
            fixture_git(&self.author, &["commit", "--quiet", "-m", "canonical update"])?;
            fixture_git(&self.author, &["push", "--quiet", self.canonical.to_str().unwrap(), REFERENCE])?;
            Ok(revision_text(&fixture_git(&self.author, &["rev-parse", "HEAD"])?)?.to_owned())
        }

        fn receive(&self, previous: &str, revision: &str) -> Result<()> {
            let policy = policy()?;
            let update = decide(&policy, "receive.update", json!(format!("{previous} {revision} {REFERENCE}")))?;
            advance(&policy, &self.canonical, &self.checkout, &update, self.uid)
        }

        fn head(&self) -> Result<String> {
            Ok(revision_text(&fixture_git(&self.checkout, &["rev-parse", "HEAD"])?)?.to_owned())
        }
    }

    #[test]
    fn receive_fast_forwards_only_the_canonical_commit_and_rejects_dirty_state() -> Result<()> {
        let fixture = Fixture::new()?;
        let next = fixture.push("state", b"after\n")?;
        fixture_git(&fixture.checkout, &["remote", "set-url", "origin", "ext::/usr/bin/false"])?;
        fs::write(fixture.checkout.join("untracked"), b"local\n")?;
        assert!(fixture.receive(&fixture.start, &next).unwrap_err().to_string().contains("dirty"));
        assert_eq!(fixture.head()?, fixture.start);
        fs::remove_file(fixture.checkout.join("untracked"))?;
        fixture_git(&fixture.checkout, &["switch", "--quiet", "-c", "other"])?;
        assert!(fixture.receive(&fixture.start, &next).unwrap_err().to_string().contains("wrong branch"));
        fixture_git(&fixture.checkout, &["switch", "--quiet", BRANCH])?;
        assert!(fixture.receive(&fixture.start, &fixture.start).unwrap_err().to_string().contains("canonical branch"));
        fixture.receive(&fixture.start, &next)?;
        assert_eq!(fixture.head()?, next);
        assert_eq!(fs::read(fixture.checkout.join("state"))?, b"after\n");
        assert!(!fixture.checkout.join(".git/FETCH_HEAD").exists());
        fixture.receive(&fixture.start, &next)?;
        Ok(())
    }

    #[test]
    fn receive_refuses_divergent_heads_command_settings_and_ignored_file_overwrites() -> Result<()> {
        let fixture = Fixture::new()?;
        let next = fixture.push("local-settings", b"upstream\n")?;
        fixture_git(&fixture.checkout, &["config", "filter.fixture.smudge", "/usr/bin/false"])?;
        assert!(fixture.receive(&fixture.start, &next).unwrap_err().to_string().contains("outside the development receive port"));
        fixture_git(&fixture.checkout, &["config", "--unset", "filter.fixture.smudge"])?;
        fs::write(fixture.checkout.join(".git/info/exclude"), b"local-settings\n")?;
        fs::write(fixture.checkout.join("local-settings"), b"private\n")?;
        assert!(fixture.receive(&fixture.start, &next).is_err());
        assert_eq!(fixture.head()?, fixture.start);
        assert_eq!(fs::read(fixture.checkout.join("local-settings"))?, b"private\n");
        fs::remove_file(fixture.checkout.join("local-settings"))?;
        fs::write(fixture.checkout.join("state"), b"local divergence\n")?;
        fixture_git(&fixture.checkout, &["add", "state"])?;
        fixture_git(&fixture.checkout, &["commit", "--quiet", "-m", "divergent"])?;
        let diverged = fixture.head()?;
        assert!(fixture.receive(&fixture.start, &next).unwrap_err().to_string().contains("not a fast-forward"));
        assert_eq!(fixture.head()?, diverged);
        assert_eq!(fs::read(fixture.checkout.join("state"))?, b"local divergence\n");
        Ok(())
    }

    #[test]
    fn receive_policy_ignores_other_branches_and_deleted_development_ref() -> Result<()> {
        let policy = policy()?;
        let zero = "0".repeat(40);
        let revision = "a".repeat(40);
        assert_eq!(decide(&policy, "receive.update", json!(format!("{zero} {revision} refs/heads/elsewhere")))?["action"], "ignore");
        assert_eq!(decide(&policy, "receive.update", json!(format!("{revision} {zero} {REFERENCE}")))?["action"], "deleted");
        assert!(decide(&policy, "receive.update", json!(format!("{zero} --exec {REFERENCE}"))).is_err());
        let update = format!("{zero} {revision} {REFERENCE}");
        assert!(decide(&policy, "receive.batch", json!([update, update])).is_err());
        assert!(decide(&policy, "receive.batch", json!([update, "invalid"])).is_err());
        Ok(())
    }

    #[test]
    fn interrupted_object_import_preserves_the_checkout_and_cleans_the_stage() -> Result<()> {
        const CHILD: &str = "ENCOUNTER_TEST_RECEIVE_INTERRUPT";
        if std::env::var_os(CHILD).is_some() {
            let _signals = Supervisor::new();
            let canonical = PathBuf::from(std::env::var("ENCOUNTER_TEST_RECEIVE_CANONICAL")?);
            let checkout = PathBuf::from(std::env::var("ENCOUNTER_TEST_RECEIVE_CHECKOUT")?);
            let update = std::env::var("ENCOUNTER_TEST_RECEIVE_UPDATE")?;
            let policy = policy()?;
            let update = decide(&policy, "receive.update", json!(update))?;
            let uid = fs::metadata(&canonical)?.uid();
            assert!(advance(&policy, &canonical, &checkout, &update, uid).is_err());
            assert_eq!(interruption(), Some(143));
            return Ok(());
        }
        let fixture = Fixture::new()?;
        let mut bytes = vec![0; 2 * 1024 * 1024];
        getrandom::getrandom(&mut bytes).map_err(|error| fail(error.to_string()))?;
        let next = fixture.push("snapshot", &bytes)?;
        let mut command = Command::new(std::env::current_exe()?);
        command.args(["--exact", "development_receive::tests::interrupted_object_import_preserves_the_checkout_and_cleans_the_stage"])
            .env(CHILD, "1").env("ENCOUNTER_TEST_RECEIVE_CANONICAL", &fixture.canonical).env("ENCOUNTER_TEST_RECEIVE_CHECKOUT", &fixture.checkout)
            .env("ENCOUNTER_TEST_RECEIVE_UPDATE", format!("{} {next} {REFERENCE}", fixture.start))
            .stdout(Stdio::null()).stdin(Stdio::null());
        let mut supervisor = Supervisor::children();
        let child = supervisor.start("Exercise development receive interruption", &mut command)?;
        let local = fixture.checkout.join(".git");
        let staged = || -> Result<bool> {
            for entry in fs::read_dir(&local)? {
                if entry?.file_name().to_string_lossy().starts_with(".sourcery-receive-") { return Ok(true); }
            }
            Ok(false)
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !staged()? {
            if child.try_wait()?.is_some() || Instant::now() >= deadline { return Err(fail("Receive fixture never started importing objects")); }
            thread::sleep(Duration::from_millis(5));
        }
        if unsafe { libc::kill(child.id() as i32, libc::SIGTERM) } != 0 { return Err(io::Error::last_os_error().into()); }
        loop {
            if let Some(status) = child.try_wait()? { assert!(status.success()); break; }
            if Instant::now() >= deadline { return Err(fail("Receive fixture did not finish interruption recovery")); }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fixture.head()?, fixture.start);
        assert!(!fixture.checkout.join("snapshot").exists());
        assert!(!staged()?);
        Ok(())
    }
}
