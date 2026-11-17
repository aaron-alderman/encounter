// Bounded bridge from a declared Encounter effect to an operator-pinned kernel.
use crate::{Result, fail, rel};
use serde_json::Value;
use std::{
    fs, io::{Read, Write}, path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub struct Binding {
    adapter: PathBuf,
    scratch: PathBuf,
}

impl Binding {
    pub fn open(adapter: &Path, pin: &str, store: &Path) -> Result<Self> {
        let adapter = adapter.canonicalize()?;
        if rel::hash(&fs::read(&adapter)?) != pin {
            return Err(fail("game kernel adapter pin differs"));
        }
        let scratch = store.join("game-kernel");
        fs::create_dir_all(&scratch)?;
        Ok(Self { adapter, scratch: scratch.canonicalize()? })
    }

    pub fn run(&self, input: &Value) -> Result<Value> {
        const LIMIT: u64 = 1_048_576;
        let request = serde_json::to_vec(input)?;
        if request.len() as u64 > LIMIT { return Err(fail("game kernel request exceeds its bound")); }
        let mut child = Command::new("/usr/bin/timeout")
            .args(["--kill-after=1s", "18s", "/usr/bin/node"])
            .arg(&self.adapter).arg(&self.scratch)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
        let mut response = Vec::new();
        let exchange = (|| -> Result<()> {
            child.stdin.take().ok_or_else(|| fail("missing game kernel input"))?.write_all(&request)?;
            child.stdout.take().ok_or_else(|| fail("missing game kernel output"))?
                .take(LIMIT + 1).read_to_end(&mut response)?;
            Ok(())
        })();
        let status = child.wait()?;
        exchange?;
        if !status.success() || response.len() as u64 > LIMIT {
            return Err(fail("Game kernel did not return a bounded result."));
        }
        Ok(serde_json::from_slice(&response)?)
    }
}
