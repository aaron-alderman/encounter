use crate::{Result, fail, package, process::{Meter, Programme}, rel};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs::File, io::{self, Read, Write}, path::Path};

const METER: usize = 20_000_000;
const MAXIMUM_INPUT: u64 = 512 * 1024;

fn pinned_facts(path: &Path, pin: &str) -> Result<Value> {
    if pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(fail("Expected an independent lowercase SHA-256 pin for the MCP authorization input"));
    }
    let root = File::open("/")?;
    let input = package::open_artifact(&root, path.strip_prefix("/")?)?;
    let mut bytes = Vec::new();
    input.take(MAXIMUM_INPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAXIMUM_INPUT || rel::hash(&bytes) != pin {
        return Err(fail("MCP authorization input exceeded its size limit or differed from its pin"));
    }
    rel::relations(std::str::from_utf8(&bytes)?)
}

fn compiler() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("mcp_authorization.encounter").to_owned()],
        &["mcpAuthorization.compile"],
        &BTreeSet::from(["kernel.invoke", "record.entries", "record.put", "number.calculate",
            "number.parse", "text.matches", "value.sort"]), &mut Meter::new(METER))
}

pub(crate) fn load(schema: &Path, schema_pin: &str, policy: &Path, policy_pin: &str, loopback_port: Option<u16>) -> Result<Value> {
    let schema = pinned_facts(schema, schema_pin)?;
    let policy = pinned_facts(policy, policy_pin)?;
    compiler()?.run("mcpAuthorization.compile",
        json!({"schema":schema, "policy":policy, "loopbackPort":loopback_port}), &mut Meter::new(METER))
}

pub(crate) fn run(schema: &Path, schema_pin: &str, policy: &Path, policy_pin: &str, loopback_port: Option<u16>) -> Result<()> {
    let contract = load(schema, schema_pin, policy, policy_pin, loopback_port)?;
    writeln!(io::stdout().lock(), "{contract}")?;
    Ok(())
}
