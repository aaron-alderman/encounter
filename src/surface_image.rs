use crate::{Result, application::{browser_profile_port, validate_path}, compat_value, fail,
    process::{Meter, Programme}, rel};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};

pub struct SurfaceImage {
    pub model: Value,
    pub data: Value,
    pub boot: String,
    pub agent: Option<String>,
    pub preparation: String,
    pub child_bindings: Vec<String>,
    grants: BTreeSet<String>,
}

impl SurfaceImage {
    pub fn read(config: &Path) -> Result<Self> {
        let config = config.canonicalize()?;
        let root = config.parent().ok_or_else(|| fail("missing surface launch directory"))?;
        validate_path(config.file_name().and_then(|name| name.to_str()).unwrap_or_default(), "rel")?;
        crate::package::check(root)?;
        let facts = rel::Facts::read(&config)?;
        let file = facts.one("surface", "image")?;
        validate_path(file, "surface")?;
        let file = root.join(file).canonicalize()?;
        if !file.starts_with(root) || !file.is_file() || fs::metadata(&file)?.len() > 8_000_000 {
            return Err(fail("surface image outside launch directory or over size limit"));
        }
        Self::parse(&facts, &fs::read(file)?)
    }

    pub(crate) fn parse(facts: &rel::Facts, bytes: &[u8]) -> Result<Self> {
        let one = |key| facts.one("surface", key);
        if one("contract")? != "encounter/browser-surface/1" { return Err(fail("unsupported surface launch contract")); }
        for [subject, key, _] in &facts.0 {
            if subject != "surface" || !matches!(key.as_str(), "contract" | "image" | "sha256"
                | "boot" | "agent" | "preparation" | "childBinding" | "grant") {
                return Err(fail("unknown surface launch field"));
            }
        }
        if bytes.len() > 8_000_000 || rel::hash(bytes) != one("sha256")? {
            return Err(fail("surface image hash differs from its pin"));
        }
        let image: Value = serde_json::from_slice(bytes)?;
        compat_value::external(&image)?;
        let agent = match facts.values("surface", "agent").as_slice() {
            [] => None,
            [name] => Some((*name).to_owned()),
            _ => return Err(fail("expected at most one surface agent entry")),
        };
        let grants = facts.values("surface", "grant").into_iter().map(str::to_owned).collect::<BTreeSet<_>>();
        if grants.iter().any(|grant| !browser_profile_port(grant) || matches!(grant.as_str(), "kernel.prepare" | "browser.asterStream")) {
            return Err(fail("unsupported surface image grant"));
        }
        let model = image["model"].clone();
        let data = image["data"].clone();
        if !data.is_object() || !data["bindings"].is_object() { return Err(fail("expected surface image data and bindings")); }
        Ok(Self { model, data, boot: one("boot")?.to_owned(), agent, preparation: one("preparation")?.to_owned(),
            child_bindings: facts.values("surface", "childBinding").into_iter().map(str::to_owned).collect(), grants })
    }

    pub fn admit(&self, meter: &mut Meter) -> Result<Programme> {
        let grants = self.grants.iter().map(String::as_str).collect();
        let programme = Programme::from_surface(&self.model, &grants, meter)?;
        if !programme.has_process(&self.boot) || !programme.has_process(&self.preparation)
            || self.agent.as_ref().is_some_and(|entry| !programme.has_process(entry)) {
            return Err(fail("surface launch entry is absent from the admitted image"));
        }
        Ok(programme)
    }
}
