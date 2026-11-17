// HTTP Basic verification for an explicitly configured loopback instance.
use crate::{Result, fail, rel::{self, Facts}};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path};
use subtle::ConstantTimeEq;

pub struct Operators(Vec<(String, [u8; 32], String)>);

impl Operators {
    pub fn read(file: &Path) -> Result<Self> {
        let metadata = fs::metadata(file)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || metadata.len() > 32_768 {
            return Err(fail("expected a private operator file of at most 32768 bytes"));
        }
        let facts = Facts::read(file)?;
        if facts.one("operators", "version")? != "encounter/operators/1" {
            return Err(fail("unsupported operator contract"));
        }
        let mut names = BTreeMap::new();
        for [name, field, value] in facts.0 {
            if name == "operators" && field == "version" { continue; }
            if name.is_empty() || name.len() > 80 || name == "operators"
                || !name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                || !matches!(field.as_str(), "basicSha256" | "role")
            {
                return Err(fail("invalid operator coordinate"));
            }
            if names.entry(name).or_insert_with(BTreeMap::new).insert(field, value).is_some() {
                return Err(fail("duplicate operator field"));
            }
        }
        if names.is_empty() || names.len() > 32 { return Err(fail("expected between 1 and 32 operators")); }
        let mut entries = Vec::<(String, [u8; 32], String)>::new();
        for (name, fields) in names {
            let role = fields.get("role").filter(|role| matches!(role.as_str(), "proposer" | "reviewer" | "observer" | "worker" | "verifier" | "reconciler" | "curator"))
                .ok_or_else(|| fail("invalid operator role"))?;
            let pin = fields.get("basicSha256").ok_or_else(|| fail("missing operator pin"))?;
            let mut digest = [0; 32];
            hex::decode_to_slice(pin, &mut digest)?;
            if entries.iter().any(|(_, used, _)| used == &digest) {
                return Err(fail("operator pins must be distinct"));
            }
            entries.push((name, digest, role.clone()));
        }
        Ok(Self(entries))
    }

    pub fn verify(&self, authorization: Option<&str>) -> Option<Value> {
        let (scheme, token) = authorization?.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") || token.len() < 44 || token.len() > 512
            || !token.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c))
        {
            return None;
        }
        let digest = hex::decode(rel::hash(token)).ok()?;
        let mut matched = None;
        for (id, pin, role) in &self.0 {
            if bool::from(pin.as_slice().ct_eq(&digest)) {
                matched = Some(json!({"id":id,"role":role}));
            }
        }
        matched
    }
}
