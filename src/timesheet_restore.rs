use crate::{Result, appdev_host_process::{Scratch, Supervisor, rename_new_path}, fail,
    archive::{self, ARCHIVE_LIMIT, MEMBER_LIMIT, Modes, Work, create, input}, process::{Meter, Programme}};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet}, fs::{self, File},
    io::{self, Seek, SeekFrom},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf}, time::Duration,
};

const ROOT: &str = "/srv/sourcery/restore-rehearsals";
const MANIFEST_LIMIT: u64 = 8 * 1024 * 1024;

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("timesheet_restore.encounter").to_owned()],
        &["restore.source", "restore.archive", "restore.path", "restore.manifestLine", "restore.member", "restore.receipt"],
        &BTreeSet::from(["text.matches", "text.match", "text.split", "text.join", "kernel.invoke"]), &mut Meter::new(20_000_000))
}

fn decide(policy: &Programme, name: &str, input: Value) -> Result<Value> {
    policy.run(name, input, &mut Meter::new(2_000_000))
}

fn field<'a>(record: &'a Value, name: &str) -> Result<&'a str> {
    record[name].as_str().ok_or_else(|| fail(format!("Invalid Timesheet consistency field {name}")))
}


fn mkdir(path: &Path, uid: u32) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
        return Err(fail("Timesheet restore destination requires a private, owned directory"));
    }
    Ok(())
}

fn target_parent(root: &Path, target: &Path, uid: u32) -> Result<PathBuf> {
    let relative = target.strip_prefix(root).map_err(|_| fail("Restore target must be a child of the Timesheet rehearsal directory"))?;
    let parent = relative.parent().ok_or_else(|| fail("Restore target must be a child of the Timesheet rehearsal directory"))?;
    if !relative.components().all(|part| matches!(part, Component::Normal(_))) {
        return Err(fail("Timesheet restore target has an unsafe component"));
    }
    mkdir(root, uid)?;
    let mut directory = root.to_owned();
    for part in parent.components() {
        directory.push(part);
        mkdir(&directory, uid)?;
    }
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(directory),
        Err(error) => Err(error.into()),
        Ok(_) => Err(fail("Timesheet restore target already exists")),
    }
}

fn manifest(work: &Work, policy: &Programme, bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        work.check()?;
        let entry = decide(policy, "restore.manifestLine", json!(line))?;
        if entries.len() == MEMBER_LIMIT || entries.insert(field(&entry, "path")?.to_owned(), field(&entry, "sha256")?.to_owned()).is_some() {
            return Err(fail("Timesheet consistency manifest is oversized or has duplicate paths"));
        }
    }
    Ok(entries)
}

fn extract(work: &Work, policy: &Programme, file: File, output: &Path, expected: &BTreeMap<String, String>) -> Result<(usize, usize)> {
    archive::unpack(work, file, output, Modes::Private, |path, directory| {
        let admitted = decide(policy, "restore.path", json!({"path":path,"manifest":false}))?;
        let name = admitted.as_str().ok_or_else(|| fail("Missing admitted Timesheet path"))?;
        if !directory && !expected.contains_key(name) {
            return Err(fail("Timesheet restore contains a file outside its consistency manifest"));
        }
        Ok(name.to_owned())
    }, |path, digest| {
        decide(policy, "restore.member", json!({"expected":expected[path],"observed":digest}))?;
        Ok(())
    })
}

fn rehearse(root: &Path, uid: u32, archive: &Path, digest: &str, before: &Path, after: &Path, target: &Path) -> Result<Value> {
    let work = Work::new(Duration::from_secs(600));
    let policy = policy()?;
    let mut first = Vec::new();
    let mut second = Vec::new();
    work.copy(&mut input(before, MANIFEST_LIMIT)?, &mut first, MANIFEST_LIMIT)?;
    work.copy(&mut input(after, MANIFEST_LIMIT)?, &mut second, MANIFEST_LIMIT)?;
    decide(&policy, "restore.source", json!({"expected":digest,"sameManifest":first == second}))?;
    let entries = manifest(&work, &policy, &first)?;
    let parent = target_parent(root, target, uid)?;
    let scratch = Scratch::create(&parent, ".timesheet-restore-")?;
    let mut snapshot = create(&scratch.path().join("archive.tar.gz"))?;
    let (_, observed) = work.copy(&mut input(archive, ARCHIVE_LIMIT)?, &mut snapshot, ARCHIVE_LIMIT)?;
    decide(&policy, "restore.archive", json!({"expected":digest,"observed":observed}))?;
    snapshot.seek(SeekFrom::Start(0))?;
    let output = scratch.path().join("restore");
    mkdir(&output, uid)?;
    let (members, verified) = extract(&work, &policy, snapshot, &output, &entries)?;
    let mut normalized = Sha256::new();
    let mut lines: Vec<_> = entries.iter().map(|(path, digest)| format!("{digest}  {path}\n")).collect();
    lines.sort_unstable();
    for line in lines { normalized.update(line.as_bytes()); }
    let receipt = decide(&policy, "restore.receipt", json!({"members":members,"expected":entries.len(),"verified":verified,
        "archiveSha256":observed,"manifestSha256":hex::encode(normalized.finalize())}))?;
    archive::sync_directories(&work, &output)?;
    File::open(scratch.path())?.sync_all()?;
    let parent = File::open(parent)?;
    work.check()?;
    rename_new_path(&output, target)?;
    if let Err(error) = parent.sync_all().map_err(Into::into).and_then(|()| work.check()) {
        if let Err(restore) = rename_new_path(target, &output).and_then(|()| Ok(parent.sync_all()?)) {
            return Err(fail(format!("{error}. Timesheet publication rollback failed ({restore}); retained {}", scratch.retain().display())));
        }
        return Err(error);
    }
    Ok(receipt)
}

pub(crate) fn run(archive: &Path, digest: &str, before: &Path, after: &Path, target: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 { return Err(fail("Timesheet restore rehearsal requires root")); }
    let _signals = Supervisor::new();
    println!("{}", rehearse(Path::new(ROOT), 0, archive, digest, before, after, target)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive::BLOCK, rel};
    use std::io::Write;
    use flate2::{Compression, write::GzEncoder};

    fn tar(entries: &[(&str, u8, &[u8])]) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        for (name, kind, content) in entries {
            let mut header = [0; BLOCK];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[124..135].copy_from_slice(format!("{:011o}", content.len()).as_bytes());
            header[148..156].fill(b' ');
            header[156] = *kind;
            header[257..265].copy_from_slice(b"ustar  \0");
            let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
            header[154] = 0;
            encoder.write_all(&header)?;
            encoder.write_all(content)?;
            encoder.write_all(&[0; BLOCK][..(BLOCK - content.len() % BLOCK) % BLOCK])?;
        }
        encoder.write_all(&[0; 2 * BLOCK])?;
        Ok(encoder.finish()?)
    }

    struct Fixture {
        _scratch: Scratch,
        archive: PathBuf,
        before: PathBuf,
        after: PathBuf,
        root: PathBuf,
        target: PathBuf,
        uid: u32,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let scratch = Scratch::create(&std::env::temp_dir(), "timesheet-rehearsal-fixture-")?;
            let home = scratch.path();
            let root = home.join("rehearsals");
            Ok(Self { archive: home.join("backup.tar.gz"), before: home.join("before.sha256"), after: home.join("after.sha256"),
                target: root.join("attempt"), uid: fs::metadata(home)?.uid(), root, _scratch: scratch })
        }

        fn write(&self, archive: &[u8], manifest: &str) -> Result<String> {
            fs::write(&self.archive, archive)?;
            fs::write(&self.before, manifest)?;
            fs::write(&self.after, manifest)?;
            Ok(rel::hash(archive))
        }

        fn restore(&self, hash: &str) -> Result<Value> {
            rehearse(&self.root, self.uid, &self.archive, hash, &self.before, &self.after, &self.target)
        }

        fn assert_no_publication(&self) -> Result<()> {
            assert!(!self.target.exists());
            if self.root.exists() { assert_eq!(fs::read_dir(&self.root)?.count(), 0); }
            Ok(())
        }
    }

    #[test]
    fn publishes_only_the_path_bound_tree_and_accepts_gnu_long_names() -> Result<()> {
        let fixture = Fixture::new()?;
        let long = format!("data/{}-file", "x".repeat(108));
        let bytes = b"historic timesheet data";
        let day = b"another timesheet";
        let long_metadata = format!("./{long}\0");
        let archive = tar(&[("./", b'5', b""), ("./data/", b'5', b""), ("././@LongLink", b'L', long_metadata.as_bytes()),
            ("./data/placeholder", b'0', bytes), ("./data/day 1", b'0', day)])?;
        let first = format!("{}  {long}\n", rel::hash(bytes));
        let second = format!("{}  data/day 1\n", rel::hash(day));
        let manifest = format!("{} */{long}\n{}  ./data/day 1\n", rel::hash(bytes), rel::hash(day));
        let digest = fixture.write(&archive, &manifest)?;
        let receipt = fixture.restore(&digest)?;
        let mut lines = [first, second];
        lines.sort();
        assert_eq!(receipt["fileCount"], 2);
        assert_eq!(receipt["archiveSha256"], digest);
        assert_eq!(receipt["restoredManifestSha256"], rel::hash(lines.concat()));
        assert_eq!(receipt["processStarted"], false);
        assert_eq!(receipt["liveStateAccessed"], false);
        assert_eq!(fs::read(fixture.target.join(long))?, bytes);
        assert_eq!(fs::read(fixture.target.join("data/day 1"))?, day);
        assert_eq!(fs::metadata(fixture.target.join("data/day 1"))?.mode() & 0o777, 0o600);
        assert!(fixture.restore(&digest).unwrap_err().to_string().contains("exists"));
        assert_eq!(fs::read_dir(&fixture.root)?.count(), 1);
        Ok(())
    }

    #[test]
    fn restores_pax_paths_and_rejects_invalid_gzip_checksums() -> Result<()> {
        let fixture = Fixture::new()?;
        let bytes = b"PAX timesheet";
        let path = format!("data/{}", "n".repeat(110));
        let field = format!("path={path}\n");
        let metadata = format!("{} {field}", field.len() + 4);
        let archive = tar(&[("pax", b'x', metadata.as_bytes()), ("old-header-name", b'0', bytes)])?;
        let manifest = format!("{}  {path}\n", rel::hash(bytes));
        let mut bad_crc = archive.clone();
        let crc = bad_crc.len() - 8;
        bad_crc[crc] ^= 1;
        let hash = fixture.write(&bad_crc, &manifest)?;
        assert!(fixture.restore(&hash).is_err());
        fixture.assert_no_publication()?;
        let hash = fixture.write(&archive, &manifest)?;
        assert_eq!(fixture.restore(&hash)?["fileCount"], 1);
        assert_eq!(fs::read(fixture.target.join(path))?, bytes);
        Ok(())
    }

    #[test]
    fn refuses_mismatches_traversal_links_duplicates_and_unlisted_files_without_publishing() -> Result<()> {
        let fixture = Fixture::new()?;
        let bytes = b"one timesheet";
        let manifest = format!("{}  a\n", rel::hash(bytes));
        let good = tar(&[("a", b'0', bytes)])?;
        let digest = fixture.write(&good, &manifest)?;
        fs::write(&fixture.after, b"different manifest\n")?;
        assert!(fixture.restore(&digest).unwrap_err().to_string().contains("changed"));
        fixture.write(&good, &manifest)?;
        assert!(fixture.restore(&"0".repeat(64)).unwrap_err().to_string().contains("archive digest"));
        fixture.assert_no_publication()?;
        for (name, kind, content, error) in [
            ("../outside", b'0', bytes.as_slice(), "unsafe"), ("/outside", b'0', bytes.as_slice(), "unsafe"),
            ("a", b'2', b"".as_slice(), "non-regular"), ("a", b'1', b"".as_slice(), "non-regular"),
            ("a", b'0', b"replaced".as_slice(), "path-bound digest"), ("unlisted", b'0', bytes.as_slice(), "outside its consistency manifest"),
        ] {
            let digest = fixture.write(&tar(&[(name, kind, content)])?, &manifest)?;
            assert!(fixture.restore(&digest).unwrap_err().to_string().contains(error));
            fixture.assert_no_publication()?;
        }
        let digest = fixture.write(&good, &manifest.repeat(2))?;
        assert!(fixture.restore(&digest).unwrap_err().to_string().contains("duplicate paths"));
        fixture.assert_no_publication()?;
        assert!(!fixture.root.parent().unwrap().join("outside").exists());
        Ok(())
    }
}
