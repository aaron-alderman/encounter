use crate::{Result, fail, package, rel::{self, Facts}};
use std::{fs::{self, File}, io::Read, path::{Path, PathBuf}, sync::{Arc, Mutex}, thread, time::Duration};

/// The publisher switches an absolute pointer between immutable generation directories.
/// Candidate admission runs outside the listener and outside the publication lock.
pub(crate) struct ReleaseSlot<T>(Arc<Mutex<Arc<T>>>);

impl<T: Send + Sync + 'static> ReleaseSlot<T> {
    pub(crate) fn start(
        name: &'static str, link: Option<PathBuf>, fallback: impl FnOnce() -> Result<T>,
        load: impl Fn(&Path, Option<&T>) -> Result<T> + Send + 'static,
    ) -> Result<Self> {
        let Some(link) = link else {
            return Ok(Self(Arc::new(Mutex::new(Arc::new(fallback()?)))));
        };
        if !link.is_absolute() { return Err(fail("expected absolute release pointer")); }
        let mut checked = link.canonicalize()?;
        let active = Arc::new(Mutex::new(Arc::new(load(&checked, None)?)));
        eprintln!("{name} activated: {}", checked.display());
        let observer = Arc::downgrade(&active);
        thread::Builder::new().name(format!("{name}-reload")).spawn(move || loop {
            thread::sleep(Duration::from_millis(250));
            let Some(active) = observer.upgrade() else { break };
            let Ok(candidate) = fs::canonicalize(&link) else { continue };
            if candidate == checked { continue }
            let previous = Arc::clone(&active.lock().unwrap_or_else(|error| error.into_inner()));
            let result = load(&candidate, Some(&previous));
            if fs::canonicalize(&link).ok().as_ref() != Some(&candidate) { continue }
            checked = candidate;
            match result {
                Ok(next) => {
                    *active.lock().unwrap_or_else(|error| error.into_inner()) = Arc::new(next);
                    eprintln!("{name} activated: {}", checked.display());
                }
                Err(error) => eprintln!("{name} rejected: {error}"),
            }
        })?;
        Ok(Self(active))
    }

    pub(crate) fn current(&self) -> Arc<T> {
        Arc::clone(&self.0.lock().unwrap_or_else(|error| error.into_inner()))
    }
}

pub(crate) fn presentation_sources<const N: usize>(
    root: &Path, contract: &str, files: [(&str, u64); N],
) -> Result<[String; N]> {
    let root = File::open(root)?;
    let read = |name: &str, limit: u64| -> Result<String> {
        let mut text = String::new();
        package::open_artifact(&root, Path::new(name))?.take(limit + 1).read_to_string(&mut text)?;
        if text.len() as u64 > limit { return Err(fail("presentation artifact exceeds limit")); }
        Ok(text)
    };
    let manifest = Facts::parse(&read("presentation.rel", 4096)?)?;
    if manifest.0.len() != N + 1 || manifest.one("presentation", "contract")? != contract {
        return Err(fail("incompatible presentation contract"));
    }
    let mut sources = Vec::with_capacity(N);
    for (name, limit) in files {
        let text = read(name, limit)?;
        if manifest.one("artifact", name)? != rel::hash(text.as_bytes()) {
            return Err(fail("presentation artifact failed its digest check"));
        }
        sources.push(text);
    }
    sources.try_into().map_err(|_| fail("incomplete presentation sources"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appdev_host_process::Scratch;
    use std::{os::unix::fs::symlink, sync::mpsc};

    #[test]
    fn appdev_slow_candidate_does_not_block_readers() -> Result<()> {
        let stage = Scratch::create(&std::env::temp_dir(), "appdev-reload-test-")?;
        let initial = stage.path().join("initial");
        let candidate = stage.path().join("candidate");
        fs::create_dir(&initial)?;
        fs::create_dir(&candidate)?;
        let link = stage.path().join("active");
        symlink(&initial, &link)?;

        let (started, admission_started) = mpsc::channel();
        let (admit, wait_for_admission) = mpsc::channel();
        let slot = Arc::new(ReleaseSlot::start("AppDev test generation", Some(link.clone()),
            || Err(fail("expected initial release")), move |_, previous| {
                if previous.is_none() { return Ok(1); }
                started.send(())?;
                wait_for_admission.recv_timeout(Duration::from_secs(5))?;
                Ok(2)
            })?);
        let pending = stage.path().join("next");
        symlink(candidate, &pending)?;
        fs::rename(pending, link)?;
        admission_started.recv_timeout(Duration::from_secs(5))?;

        let (read, reader) = mpsc::channel();
        let request = Arc::clone(&slot);
        let thread = thread::spawn(move || read.send(*request.current()));
        let result = reader.recv_timeout(Duration::from_secs(1));
        admit.send(())?;
        thread.join().expect("snapshot read thread")?;
        assert_eq!(result?, 1);
        for _ in 0..50 {
            if *slot.current() == 2 { return Ok(()); }
            thread::sleep(Duration::from_millis(20));
        }
        Err(fail("validated candidate was not installed"))
    }
}
