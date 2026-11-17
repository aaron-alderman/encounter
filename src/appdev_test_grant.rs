use crate::{Result, fail};
use std::{
    fs::{self, OpenOptions, Permissions},
    io::{self, ErrorKind, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const STATE_DIRECTORY: &str = "/var/lib/private/appdev-workspace";
const GRANT: &str = "formation-test-grant";
const LIMIT: u64 = 128;
const MAX_LIFETIME: u128 = 300_000;

fn expiry(declaration: &str) -> Option<u128> {
    let (digest, expires) = declaration.trim_end().split_once(' ')?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    expires.parse().ok()
}

pub fn update(operation: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(fail("Formation test grant custody requires the host operator"));
    }
    let mut declaration = String::new();
    io::stdin().lock().take(LIMIT + 1).read_to_string(&mut declaration)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    update_file(Path::new(STATE_DIRECTORY), operation, &declaration, now)
}

fn update_file(directory: &Path, operation: &str, declaration: &str, now: u128) -> Result<()> {
    if !fs::symlink_metadata(directory)?.file_type().is_dir() || declaration.len() as u64 > LIMIT {
        return Err(fail("Invalid Formation test grant input"));
    }
    let expires = expiry(declaration).ok_or_else(|| fail("Invalid Formation test grant declaration"))?;
    let path = directory.join(GRANT);
    let existing = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path) {
        Ok(file) if file.metadata()?.is_file() => {
            let mut text = String::new();
            file.take(LIMIT + 1).read_to_string(&mut text)?;
            if text.len() as u64 > LIMIT { return Err(fail("Invalid existing Formation test grant")); }
            Some(text)
        }
        Ok(_) => return Err(fail("Formation test grant must be a regular file")),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    match operation {
        "issue" => {
            if expires <= now || expires - now > MAX_LIFETIME {
                return Err(fail("Formation test grants expire within five minutes"));
            }
            if let Some(prior) = existing {
                if !expiry(&prior).is_some_and(|expiry| expiry <= now) {
                    return Err(fail("Resolve the existing Formation test grant before issuing another"));
                }
                fs::remove_file(&path)?;
            }
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o644)
                .custom_flags(libc::O_NOFOLLOW).open(&path)?;
            let written = file.set_permissions(Permissions::from_mode(0o644))
                .and_then(|_| file.write_all(declaration.as_bytes()));
            if let Err(error) = written {
                fs::remove_file(&path)?;
                return Err(error.into());
            }
        }
        "revoke" => {
            if existing.as_deref() == Some(declaration) { fs::remove_file(&path)?; }
        }
        _ => return Err(fail("Expected issue or revoke for the Formation test grant")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appdev_host_process::Scratch;

    #[test]
    fn grant_custody_refuses_overwrite_and_revokes_only_the_matching_declaration() -> Result<()> {
        let scratch = Scratch::create(&std::env::temp_dir(), "appdev-test-grant-")?;
        let folder = scratch.path();
        let first = format!("{} 2000\n", "a".repeat(64));
        let next = format!("{} 2500\n", "b".repeat(64));
        update_file(folder, "issue", &first, 1000)?;
        assert!(update_file(folder, "issue", &next, 1000).is_err());
        update_file(folder, "revoke", &next, 1000)?;
        assert_eq!(fs::read_to_string(folder.join(GRANT))?, first);
        update_file(folder, "issue", &next, 2000)?;
        update_file(folder, "revoke", &next, 2000)?;
        assert!(!folder.join(GRANT).exists());
        Ok(())
    }
}
