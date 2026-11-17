// Validate the application package, including files not named by a declaration.
use crate::{Result, fail};
use std::{ffi::CString, fs, io::{self, Read}, os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt}}}, path::Path};

pub(crate) fn open_beneath(directory: &fs::File, relative: &Path) -> Result<fs::File> {
    open_beneath_with(directory, relative, libc::O_RDONLY | libc::O_NONBLOCK)
}

pub(super) fn observe_beneath(directory: &fs::File, relative: &Path) -> Result<fs::File> {
    open_beneath_with(directory, relative, libc::O_PATH)
}

fn open_beneath_with(directory: &fs::File, relative: &Path, flags: i32) -> Result<fs::File> {
    let relative = CString::new(relative.as_os_str().as_bytes())?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS;
    let descriptor = unsafe { libc::syscall(libc::SYS_openat2, directory.as_raw_fd(), relative.as_ptr(),
        &how, std::mem::size_of::<libc::open_how>()) };
    if descriptor < 0 { return Err(io::Error::last_os_error().into()); }
    Ok(unsafe { fs::File::from_raw_fd(descriptor as i32) })
}

pub(crate) fn open_artifact(directory: &fs::File, relative: &Path) -> Result<fs::File> {
    let file = open_beneath(directory, relative)?;
    if !file.metadata()?.is_file() { return Err(fail("Expected a regular release artifact")); }
    Ok(file)
}

pub(crate) fn require_native_runtime(path: &Path) -> Result<()> {
    let mut file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    require_native_runtime_file(&mut file)
}

pub(crate) fn require_native_runtime_file(file: &mut fs::File) -> Result<()> {
    require_bounded_x64_executable(file, 64_000_000)
}

pub(crate) fn require_bounded_x64_executable(file: &mut fs::File, limit: u64) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.len() > limit {
        return Err(fail("Expected a bounded executable Encounter runtime"));
    }
    let mut elf = [0; 20];
    file.read_exact(&mut elf)?;
    if &elf[..7] != b"\x7fELF\x02\x01\x01" || !matches!(&elf[16..20], [2 | 3, 0, 62, 0]) {
        return Err(fail("Expected a native x86-64 ELF Encounter runtime"));
    }
    Ok(())
}

pub fn check_path(path: &Path) -> Result<()> {
    if path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext|
        ["json", "mjs", "py", "rs"].iter().any(|blocked| ext.eq_ignore_ascii_case(blocked))) {
        return Err(fail(format!("application package contains forbidden file {}", path.display())));
    }
    Ok(())
}

pub fn check(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            check_path(&path)?;
            if kind.is_dir() {
                pending.push(path);
            } else if !kind.is_file() {
                return Err(fail(format!("application package entry must be a regular file: {}", path.display())));
            }
        }
    }
    Ok(())
}
