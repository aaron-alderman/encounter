use crate::{Result, fail, process::Meter};
use serde_json::{Value, json};
use std::{
    ffi::CString, fs::{self, File, OpenOptions}, io::{self, Read},
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::OpenOptionsExt}, path::Path,
};

const TEXT_LIMIT: usize = 2_000_000;
const DIRECTORY_LIMIT: usize = 16_384;

pub(crate) struct Sources(File);

impl Sources {
    pub(crate) fn open(root: &Path) -> Result<Self> {
        Self::open_physical(&root.canonicalize()?)
    }

    pub(super) fn open_physical(root: &Path) -> Result<Self> {
        Ok(Self(OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(root)?))
    }

    pub(super) fn root(&self) -> Result<File> { Ok(self.0.try_clone()?) }

    pub(super) fn open_directory_relative(&self, path: &str) -> Result<Self> {
        Ok(Self(self.open_relative(path, true)?))
    }

    pub(super) fn observe_relative(&self, path: &str) -> Result<File> {
        self.open_relative_with(path, false, libc::O_PATH)
    }

    fn open_relative(&self, path: &str, directory: bool) -> Result<File> {
        self.open_relative_with(path, directory, libc::O_RDONLY | libc::O_NONBLOCK)
    }

    fn open_relative_with(&self, path: &str, directory: bool, flags: i32) -> Result<File> {
        if path.len() > 4096 || path.contains('\\') || path.chars().any(char::is_control)
            || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
            return Err(fail("invalid local source path"));
        }
        let mut opened = self.0.try_clone()?;
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            let name = CString::new(part)?;
            let flags = if parts.peek().is_some() || directory { libc::O_RDONLY | libc::O_NONBLOCK | libc::O_DIRECTORY } else { flags };
            // Resolve each component relative to an already-open directory without following links.
            let fd = unsafe { libc::openat(opened.as_raw_fd(), name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { return Err(io::Error::last_os_error().into()); }
            opened = unsafe { File::from_raw_fd(fd) };
        }
        Ok(opened)
    }

    pub(crate) fn directory(&self, path: &str, meter: &mut Meter) -> Result<Value> {
        let opened = self.open_relative(path, true)?;
        let mut entries = Vec::new();
        // Keep the directory descriptor open throughout the listing.
        for (index, entry) in fs::read_dir(format!("/proc/self/fd/{}", opened.as_raw_fd()))?.enumerate() {
            if index >= DIRECTORY_LIMIT { return Err(fail("local source directory entry limit")); }
            let entry = entry?;
            let kind = entry.file_type()?;
            if !kind.is_file() && !kind.is_dir() { continue; }
            let name = entry.file_name().into_string().map_err(|_| fail("local source name must be UTF-8"))?;
            meter.charge(name.len() + 1)?;
            entries.push((name, kind.is_dir()));
        }
        entries.sort_unstable();
        Ok(Value::Array(entries.into_iter().map(|(name, directory)| json!({ "name":name, "directory":directory })).collect()))
    }

    pub(crate) fn read_text(&self, path: &str, meter: &mut Meter) -> Result<Value> {
        let file = self.open_relative(path, false)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > TEXT_LIMIT as u64 { return Err(fail("local source text file limit")); }
        let mut source = String::new();
        file.take((TEXT_LIMIT + 1) as u64).read_to_string(&mut source)?;
        if source.len() > TEXT_LIMIT { return Err(fail("local source text file limit")); }
        meter.charge(source.len())?;
        Ok(Value::String(source))
    }
}
