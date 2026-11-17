use crate::{Result, fail, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::CStr,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::{MetadataExt, OpenOptionsExt}},
    path::Path,
};

pub(super) const UNIT: &str = "/etc/systemd/system/sourcery-google-identity.service";
pub(super) const DIRECTORY: &str = "/etc/sourcery-google";
pub(crate) const SECRET_PATH: &str = "/etc/sourcery-google/client-secret";
const CONFIGURATION_LIMIT: u64 = 32 * 1024;

fn open_child(directory: &File, name: &CStr, flags: i32) -> Result<File> {
    // Fixed basenames bind both file observations to the opened directory.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn observe(file: &File) -> Result<Value> {
    let metadata = file.metadata()?;
    Ok(json!({ "file": metadata.is_file(), "directory": metadata.is_dir(),
        "uid": metadata.uid(), "gid": metadata.gid(), "mode": metadata.mode() & 0o7777,
        "bytes": metadata.len(), "protected": metadata.mode() & 0o022 == 0 }))
}

fn observe_config(file: &File, path: &Path) -> Result<Value> {
    let mut facts = observe(file)?;
    if facts["file"] == true {
        let mut source = String::new();
        file.take(CONFIGURATION_LIMIT + 1).read_to_string(&mut source)?;
        if source.len() as u64 > CONFIGURATION_LIMIT {
            return Err(fail("Google identity custody configuration exceeds its size limit"));
        }
        facts["source"] = source.into();
    }
    facts["path"] = json!(path);
    Ok(facts)
}

pub(super) fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("google_identity_custody.encounter").to_owned()],
        &["custody.verify", "custody.inactive", "custody.migration"], &BTreeSet::from(["kernel.invoke", "text.split", "text.match", "text.trim",
            "text.replace", "number.calculate"]), &mut Meter::new(20_000_000))
}

pub(super) fn inspect(unit: &Path, directory: &Path, owner_uid: u32, secret_flags: i32) -> Result<(Value, File)> {
    inspect_at(unit, directory, directory, owner_uid, secret_flags)
}

pub(super) fn inspect_at(unit: &Path, directory: &Path, named_directory: &Path, owner_uid: u32, secret_flags: i32) -> Result<(Value, File)> {
    let policy = policy()?;
    let unit_file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(unit)?;
    let parent = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(directory)?;
    let env_file = open_child(&parent, c"google.env", libc::O_RDONLY | libc::O_NONBLOCK)?;
    let secret_file = open_child(&parent, c"client-secret", secret_flags)?;
    let mut secret = observe(&secret_file)?;
    secret["path"] = json!(named_directory.join("client-secret"));
    let receipt = policy.run("custody.verify", json!({ "ownerUid": owner_uid, "directory": observe(&parent)?,
        "unit": observe_config(&unit_file, unit)?, "environment": observe_config(&env_file, &named_directory.join("google.env"))?,
        "secret": secret }), &mut Meter::new(20_000_000))?;
    Ok((receipt, secret_file))
}

pub(crate) fn open_verified_secret() -> Result<File> {
    inspect(Path::new(UNIT), Path::new(DIRECTORY), 0, libc::O_RDONLY | libc::O_NONBLOCK).map(|(_, file)| file)
}

pub(crate) fn run() -> Result<()> {
    let (receipt, _) = inspect(Path::new(UNIT), Path::new(DIRECTORY), 0, libc::O_PATH)?;
    println!("{}", receipt);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appdev_host_process::Scratch;
    use std::{fs, os::unix::fs::{PermissionsExt, symlink}};

    fn verify(unit: &Path, directory: &Path, uid: u32) -> Result<Value> {
        inspect(unit, directory, uid, libc::O_PATH).map(|(receipt, _)| receipt)
    }

    #[test]
    fn preserves_receipt_and_rejects_custody_drift() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "google-identity-custody")?;
        let directory = fixture.path().join("custody");
        let unit = fixture.path().join("identity.service");
        let environment = directory.join("google.env");
        let secret = directory.join("client-secret");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750))?;
        let unit_source = format!("[Service]\nEnvironmentFile={}\n", environment.display());
        let env_source = format!("SOURCERY_GOOGLE_CLIENT_SECRET_FILE={}\n", secret.display());
        fs::write(&unit, &unit_source)?;
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o644))?;
        fs::write(&environment, &env_source)?;
        fs::write(&secret, "retained-test-secret\n")?;
        for file in [&environment, &secret] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o640))?;
        }
        let uid = fs::metadata(&directory)?.uid();
        let check = || verify(&unit, &directory, uid);
        let receipt = check()?;
        assert_eq!(receipt["status"], "passed");
        assert_eq!(receipt["protocol"], "sourcery.hosted/google-identity-custody.v1");
        assert_eq!(receipt["modes"], json!({"directory": "0750", "environment": "0640", "secret": "0640"}));
        assert_eq!(receipt["secretBytes"], 21);
        assert!(!receipt.to_string().contains("retained-test-secret"));

        fs::write(&unit, "[Service]\nEnvironmentFile=/etc/legacy/google.env\n")?;
        assert!(check().unwrap_err().to_string().contains("drifted"));
        fs::write(&unit, &unit_source)?;
        fs::write(&environment, "SOURCERY_GOOGLE_CLIENT_SECRET_FILE=/etc/legacy/client-secret\n")?;
        assert!(check().unwrap_err().to_string().contains("drifted"));
        fs::write(&environment, env_source.repeat(2))?;
        assert!(check().unwrap_err().to_string().contains("exactly one"));
        fs::write(&environment, &env_source)?;
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644))?;
        assert!(check().unwrap_err().to_string().contains("modes"));
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o640))?;
        fs::write(&secret, [])?;
        assert!(check().unwrap_err().to_string().contains("size"));
        fs::write(&secret, vec![b'x'; 4097])?;
        assert!(check().unwrap_err().to_string().contains("size"));
        fs::write(&secret, "retained-test-secret\n")?;
        assert!(verify(&unit, &directory, uid ^ 1).unwrap_err().to_string().contains("root owner"));
        fs::remove_file(&secret)?;
        symlink(&environment, &secret)?;
        assert!(check().unwrap_err().to_string().contains("regular files"));
        Ok(())
    }
}
