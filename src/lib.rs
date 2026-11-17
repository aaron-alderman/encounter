//! Portable Encounter evaluation with embedded source and data.

#![cfg(not(feature = "hosted"))]
#![allow(dead_code)]

mod compat_value;
mod csv;
mod process;
mod rel;
mod signature;

use serde_json::Value;
use std::collections::BTreeSet;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn fail(message: impl Into<String>) -> Box<dyn std::error::Error> { message.into().into() }

pub struct EmbeddedProgramme {
    programme: process::Programme,
    entry: String,
}

impl EmbeddedProgramme {
    pub fn admit(
        declaration: &str,
        entry: &str,
        source: impl Fn(&str) -> Option<&'static str>,
    ) -> Result<Self> {
        let declaration = rel::Facts::parse(declaration)?;
        let app = "application";
        if !declaration.values(app, "entry").contains(&entry)
            || declaration.one(app, "dataFormat")? != "rel-facts"
        {
            return Err(fail("Expected a declared entry and an embedded REL facts dataset"));
        }
        let read = |path: &str| source(path).ok_or_else(|| fail(format!("Missing embedded file {path}")));
        let facts = read(declaration.one(app, "dataSource")?)?;
        let facts_sha256 = declaration.one(app, "dataSha256")?;
        if rel::hash(facts) != facts_sha256 {
            return Err(fail("Embedded Encounter facts differ from their declaration"));
        }
        let sources: Vec<_> = declaration.values(app, "module").into_iter()
            .map(|path| read(path).map(str::to_owned)).collect::<Result<_>>()?;
        let grants: BTreeSet<_> = declaration.values(app, "grant").into_iter().collect();
        let mut programme = process::Programme::admit(&sources, entry, &grants, &mut process::Meter::new(20_000_000))?;
        programme.bind_dataset(String::new(), rel::relations(facts)?);
        Ok(Self { programme, entry: entry.to_owned() })
    }

    pub fn run(&self, input: Value) -> Result<Value> {
        self.programme.run(&self.entry, input, &mut process::Meter::new(20_000_000))
    }
}
