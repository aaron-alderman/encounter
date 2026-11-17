use crate::{Result, appdev_host_process::{Scratch, Supervisor, interruption}, directory, fail,
    process::{Meter, Programme}, rel::Facts};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet, env, fs::{self, File, OpenOptions}, io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}},
    path::Path, thread, time::Duration,
};

const HEADER: &str = "(\"publication\", \"format\", \"encounter/scheduled-run-receipts/1\")\n";
const MAX_MANIFEST: usize = 2 * 1024 * 1024;
const MAX_RECEIPT: usize = 64 * 1024;

fn policy() -> Result<Programme> {
    let source = include_str!("scheduled_receipt.encounter").to_owned();
    Programme::admit_entries(&[source], &["receipt.issue", "receipt.extend"],
        &BTreeSet::from(["text.matches", "number.calculate", "number.isNatural", "json.stringify",
            "digest.sha256", "text.replace", "text.join"]), &mut Meter::new(20_000_000))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field].as_str().ok_or_else(|| fail(format!("Invalid receipt policy field {field}")))
}

fn read_private(path: &Path, limit: usize) -> Result<Option<String>> {
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(fail("Expected an owner-only receipt file"));
    }
    let mut content = String::new();
    file.take(limit as u64 + 1).read_to_string(&mut content)?;
    if content.len() > limit { return Err(fail("Scheduled receipt data exceeded its size limit")); }
    Ok(Some(content))
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn publish(directory: &Path, programme: &Programme, issued: &Value) -> Result<bool> {
    let name = text(issued, "name")?;
    let content = text(issued, "content")?;
    let pin = text(issued, "pin")?;
    if !name.strip_suffix(".rel").is_some_and(directory::valid_invocation_id)
        || content.len() > MAX_RECEIPT || crate::rel::hash(content) != pin {
        return Err(fail("Invalid scheduled receipt artifact binding"));
    }
    fs::DirBuilder::new().recursive(true).mode(0o700).create(directory)?;
    let meta = directory.symlink_metadata()?;
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(fail("Expected an owner-only scheduled receipt directory"));
    }
    let lock = OpenOptions::new().write(true).create(true).truncate(false).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(directory.join(".publication.lock"))?;
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(fail("Invalid scheduled receipt publication lock"));
    }
    loop {
        if interruption().is_some() { return Err(fail("Scheduled receipt publication interrupted")); }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 { break; }
        let error = io::Error::last_os_error();
        if !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) { return Err(error.into()); }
        thread::sleep(Duration::from_millis(25));
    }
    let manifest = directory.join("publication.rel");
    let receipt = directory.join(name);
    let current = read_private(&manifest, MAX_MANIFEST)?.unwrap_or_else(|| HEADER.to_owned());
    let facts = Facts::parse(&current)?;
    let next = programme.run("receipt.extend", json!({"manifest":current,"facts":facts.0,"name":name,"pin":pin}),
        &mut Meter::new(20_000_000))?;
    let revised = match &next {
        Value::Null => None,
        Value::String(body) if body.len() <= MAX_MANIFEST => Some(body),
        _ => return Err(fail("Invalid scheduled receipt publication decision")),
    };
    let existing = read_private(&receipt, MAX_RECEIPT)?;
    if existing.as_ref().is_some_and(|existing| existing != content) {
        return Err(fail("Invocation receipt already exists with different content"));
    }
    if existing.is_some() && revised.is_none() { return Ok(false); }
    let temporary = Scratch::create(directory, ".receipt-publish-")?;
    if existing.is_none() {
        let pending = temporary.path().join("receipt.rel");
        write_private(&pending, content)?;
        fs::hard_link(pending, &receipt)?;
        File::open(directory)?.sync_all()?;
    }
    if let Some(revised) = revised {
        let pending = temporary.path().join("publication.rel");
        write_private(&pending, revised)?;
        if interruption().is_some() { return Err(fail("Scheduled receipt publication interrupted")); }
        fs::rename(pending, &manifest)?;
        File::open(directory)?.sync_all()?;
    }
    Ok(true)
}

pub fn front_gate(directory: &Path) -> Result<()> {
    let mut supervisor = Supervisor::new();
    let invocation = env::var("INVOCATION_ID")?;
    let run = crate::systemd_user_service::front_gate_run()?;
    let start = i64::try_from(run.start_us / 1_000_000)?;
    let end = i64::try_from(run.end_us / 1_000_000)?;
    let timers: Vec<_> = run.timer.into_iter().map(|(activates, last)|
        json!({"unit":"sourcery-dev-front-gate-check.timer","activates":activates,"last":last})).collect();
    let programme = policy()?;
    let issued = programme.run("receipt.issue", json!({"invocation":invocation,
        "observedInvocation":run.invocation,"start":start,"end":end,
        "started":directory::perth_time(start.checked_mul(1_000_000)),
        "finished":directory::perth_time(end.checked_mul(1_000_000)),
        "serviceResult":env::var("SERVICE_RESULT")?,"exitCode":env::var("EXIT_CODE").unwrap_or_default(),
        "exitStatus":env::var("EXIT_STATUS").unwrap_or_default(),"timers":timers}), &mut Meter::new(20_000_000))?;
    supervisor.check()?;
    if publish(directory, &programme, &issued)? { println!("Published {}", text(&issued, "name")?); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(invocation: &str) -> Value {
        json!({"invocation":invocation,"observedInvocation":invocation,
            "start":1800000000,"end":1800000003,"started":"2027-01-15 16:00:00","finished":"2027-01-15 16:00:03",
            "serviceResult":"success","exitCode":"exited","exitStatus":"0",
            "timers":[{"unit":"sourcery-dev-front-gate-check.timer","activates":"sourcery-dev-front-gate-check.service","last":1800000000123456_u64}]})
    }

    fn issue(programme: &Programme, input: Value) -> Result<Value> {
        programme.run("receipt.issue", input, &mut Meter::new(20_000_000))
    }

    #[test]
    fn receipt_refuses_stale_identity_and_only_attributes_the_matching_timer() -> Result<()> {
        let programme = policy()?;
        let mut input = evidence("aabbccddeeff00112233445566778899");
        let issued = issue(&programme, input.clone())?;
        let facts = Facts::parse(text(&issued,"content")?)?;
        assert_eq!(facts.one("execution", "duration-seconds")?, "3");
        assert_eq!(facts.one("execution", "last-trigger")?, "2027-01-15 16:00:00");
        input["timers"][0]["last"] = json!(1800000001123456_u64);
        assert!(Facts::parse(text(&issue(&programme, input.clone())?, "content")?)?
            .values("execution", "timer").is_empty());
        input["observedInvocation"] = json!("11223344556677889900aabbccddeeff");
        assert!(issue(&programme, input).is_err());
        Ok(())
    }

    #[test]
    fn receipt_replays_orphans_and_serializes_concurrent_publications() -> Result<()> {
        let scratch = Scratch::create(&env::temp_dir(), "receipt-test-")?;
        let directory = scratch.path().join("published");
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let programme = policy()?;
        let first = issue(&programme, evidence("aabbccddeeff00112233445566778899"))?;
        let second = issue(&programme, evidence("11223344556677889900aabbccddeeff"))?;
        write_private(&directory.join(text(&first, "name")?), text(&first, "content")?)?;
        thread::scope(|scope| {
            let attempt = |issued: &Value| -> std::result::Result<bool, String> {
                (|| publish(&directory, &policy()?, issued))().map_err(|error| error.to_string())
            };
            let (first, second) = (&first, &second);
            let first_publish = scope.spawn(move || attempt(first));
            let second_publish = scope.spawn(move || attempt(second));
            assert!(first_publish.join().unwrap().unwrap());
            assert!(second_publish.join().unwrap().unwrap());
        });
        assert!(!publish(&directory, &programme, &first)?);
        let manifest = Facts::read(&directory.join("publication.rel"))?;
        assert_eq!(manifest.values("publication", "receipt").len(), 2);
        for receipt in [&first, &second] {
            let name = text(receipt, "name")?;
            assert_eq!(manifest.one(name, "sha256")?, text(receipt, "pin")?);
            assert_eq!(fs::read_to_string(directory.join(name))?, text(receipt, "content")?);
        }
        let mut changed = evidence("aabbccddeeff00112233445566778899");
        changed["serviceResult"] = json!("exit-code");
        assert!(publish(&directory, &programme, &issue(&programme, changed)?).is_err());
        let index = scratch.path().join("sources.rel");
        fs::write(&index, format!("(\"index\", \"format\", \"encounter/file-index/1\")\n(\"index\", \"source\", \"runs\")\n(\"runs\", \"provider\", \"scheduled-receipts\")\n(\"runs\", \"location\", {})\n", json!(directory)))?;
        crate::file_index::run(&index, &scratch.path().join("index"), None)?;
        Ok(())
    }
}
