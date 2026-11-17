//! Reloads the Registry approval presentation independently of the VM runtime.
use crate::{Result, appdev_reload::{ReleaseSlot, presentation_sources}, fail, process::{CSS_RENDERER, Meter, Programme}};
use serde_json::Value;
use std::{collections::BTreeSet, env, path::{Path, PathBuf}, sync::Arc};

const FORMAT: &str = "encounter/registry-approval-presentation/1";
const VIEW: &str = "registry-approval-view.encounter";
const STYLE: &str = "registry-approval-style.encounter";
const DEFAULT_VIEW: &str = include_str!(env!("ENCOUNTER_APPROVAL_VIEW"));
const DEFAULT_STYLE: &str = include_str!(env!("ENCOUNTER_APPROVAL_STYLE"));

pub(super) struct Presentation {
    copy: Value,
    pub css: String,
}

impl Presentation {
    fn compile(view: &str, style: &str) -> Result<Self> {
        let mut meter = Meter::new(250_000);
        let programme = Programme::admit_entries(
            &[view.to_owned(), style.to_owned(), CSS_RENDERER.to_owned()],
            &["registryApproval.view", "registryApproval.style"],
            &BTreeSet::new(),
            &mut meter,
        )?;
        let copy = programme.run("registryApproval.view", Value::Null, &mut meter)?;
        if copy.as_object().map(|fields| fields.len()) != Some(4)
            || ["title", "message", "warning", "acknowledgment"].iter().any(|key| {
                !copy[*key].as_str().is_some_and(|text|
                    !text.trim().is_empty() && text.len() <= 512 && !text.chars().any(char::is_control))
            }) {
            return Err(fail("invalid Registry approval copy"));
        }
        let rendered = programme.run("registryApproval.style", Value::Null, &mut meter)?;
        let css = rendered.as_str().filter(|css| !css.is_empty() && css.len() <= 64_000
            && !css.contains(['<', '\r', '\0'])).ok_or_else(|| fail("invalid Registry approval stylesheet"))?;
        Ok(Self { copy, css: css.to_owned() })
    }

    fn load(root: &Path) -> Result<Self> {
        let [view, style] = presentation_sources(root, FORMAT, [(VIEW, 32_000), (STYLE, 64_000)])?;
        Self::compile(&view, &style)
    }

    pub fn text(&self, key: &str) -> &str {
        self.copy[key].as_str().expect("validated approval copy field")
    }
}

pub(super) struct Presentations(ReleaseSlot<Presentation>);

impl Presentations {
    pub fn start(follow: bool) -> Result<Self> {
        let link = follow.then(|| env::var_os("APPDEV_REGISTRY_APPROVAL_RELEASE")).flatten().map(PathBuf::from);
        Ok(Self(ReleaseSlot::start("Registry approval presentation", link,
            || Presentation::compile(DEFAULT_VIEW, DEFAULT_STYLE), |root, _| Presentation::load(root))?))
    }

    pub fn current(&self) -> Arc<Presentation> {
        self.0.current()
    }
}

pub(super) fn verify(root: &Path) -> Result<()> { Presentation::load(root).map(drop) }
