use crate::{Result, compat_value, fail, http, nonce::nonce, package::{open_artifact, open_beneath}};
use serde_json::Value;
use std::{ffi::CString, fs::File, io::{self, Read, Write}, os::{fd::{AsRawFd, FromRawFd},
    unix::fs::MetadataExt}, path::{Component, Path}};

pub(super) fn owned_file_parent(file: &Path, create: bool) -> Result<File> {
    let relative = file.parent().and_then(|parent| parent.strip_prefix("/").ok())
        .ok_or_else(|| fail("Expected an absolute service file path"))?;
    let mut directory = File::open("/")?;
    for component in relative.components() {
        let Component::Normal(name) = component else { return Err(fail("Expected a canonical service file path")); };
        if create { make_directory_entry(&directory, name.to_str().ok_or_else(|| fail("Expected a UTF-8 service path"))?)?; }
        directory = open_beneath(&directory, Path::new(name))?;
    }
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::getuid() } || metadata.mode() & 0o022 != 0 {
        return Err(fail("Directory is outside service custody"));
    }
    Ok(directory)
}

pub(super) fn missing(error: &(dyn std::error::Error + 'static)) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

pub(super) fn optional_json(directory: &File, name: &str, limit: usize) -> Result<Option<Value>> {
    let bytes = match read_private(directory, name, limit) {
        Ok(bytes) => bytes,
        Err(error) if missing(error.as_ref()) => return Ok(None),
        Err(error) => return Err(error),
    };
    let value = serde_json::from_slice(&bytes)?;
    compat_value::external(&value)?;
    Ok(Some(value))
}

pub(super) fn private_directory(directory: File) -> Result<File> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::getuid() } {
        return Err(fail("Directory is outside private service custody"));
    }
    Ok(directory)
}

pub(super) fn make_directory(parent: &File, name: &str) -> Result<File> {
    make_directory_entry(parent, name)?;
    private_directory(open_beneath(parent, Path::new(name))?)
}

pub(super) fn make_directory_entry(parent: &File, name: &str) -> Result<()> {
    let path = CString::new(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), path.as_ptr(), 0o700) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists { return Err(error.into()); }
    }
    Ok(())
}

pub(super) fn read_private(directory: &File, name: &str, limit: usize) -> Result<Vec<u8>> {
    let file = open_artifact(directory, Path::new(name))?;
    let metadata = file.metadata()?;
    if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::getuid() } {
        return Err(fail("File is outside private service custody"));
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit { return Err(fail("Private file exceeds its byte bound")); }
    Ok(bytes)
}

pub(super) struct PendingFile<'a> {
    directory: &'a File,
    name: CString,
}

impl Drop for PendingFile<'_> {
    fn drop(&mut self) {
        unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0); }
    }
}

impl<'a> PendingFile<'a> {
    pub(super) fn write(directory: &'a File, prefix: &str, bytes: &[u8]) -> Result<Self> {
        let name = CString::new(format!("{prefix}.{}.tmp", nonce()?))?;
        let raw = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
        if raw < 0 { return Err(io::Error::last_os_error().into()); }
        let pending = Self { directory, name };
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        file.sync_all()?;
        http::check_interruption(false)?;
        Ok(pending)
    }

    pub(super) fn read(&self, limit: usize) -> Result<Vec<u8>> {
        read_private(self.directory, self.name.to_str()?, limit)
    }

    pub(super) fn remove(self) -> Result<()> {
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub(super) fn publish(self, destination: &str, replace: bool) -> Result<bool> {
        let fd = self.directory.as_raw_fd();
        let destination = CString::new(destination)?;
        let flags = if replace { 0 } else { libc::RENAME_NOREPLACE };
        http::check_interruption(false)?;
        if unsafe { libc::renameat2(fd, self.name.as_ptr(), fd, destination.as_ptr(), flags) } != 0 {
            let error = io::Error::last_os_error();
            if !replace && error.kind() == io::ErrorKind::AlreadyExists { return Ok(false); }
            return Err(error.into());
        }
        self.directory.sync_all()?;
        Ok(true)
    }
}
