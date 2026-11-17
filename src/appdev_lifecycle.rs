use crate::{Result, appdev_assurance, command::Evaluator, fail, rel::{self, Facts}};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, BTreeSet}, path::{Component, Path}};

struct ComponentRule<'a> {
    id: &'a str,
    kind: &'a str,
    interface: &'a str,
    state: &'a str,
    grants: Vec<&'a str>,
    imports: Vec<Value>,
    paths: Vec<&'a str>,
    trees: Vec<&'a str>,
}

impl ComponentRule<'_> {
    fn owns(&self, path: &str) -> bool {
        self.paths.contains(&path) || self.trees.iter().any(|tree| path.starts_with(tree))
    }

    fn snapshot(&self, files: &BTreeMap<String, String>) -> Result<Value> {
        let artifacts = files.iter().filter(|(path, _)| self.owns(path)).collect::<Vec<_>>();
        let digest = rel::hash(serde_json::to_vec(&artifacts)?);
        Ok(json!({"id":self.id,"kind":self.kind,"interface":self.interface,"stateProfile":self.state,
            "grants":self.grants,"imports":self.imports,"digest":digest}))
    }
}

pub(crate) fn report(policy: &Path, inventory: &Path, current: &Path, candidate: &Path) -> Result<Value> {
    report_with_system_kind(policy, inventory, current, candidate, appdev_assurance::system_package(candidate))
}

pub(crate) fn report_with_system_kind(
    policy: &Path, inventory: &Path, current: &Path, candidate: &Path, system: bool,
) -> Result<Value> {
    let current = current.canonicalize()?;
    let candidate = candidate.canonicalize()?;
    let facts = appdev_assurance::read_facts(inventory)?;
    if facts.one("inventory", "contract")? != "encounter/appdev-component-inventory/1" {
        return Err(fail("unsupported AppDev component inventory"));
    }
    let rules = component_rules(&facts)?;
    let (before, previous_digest) = artifact_snapshot(&current)?;
    let (after, candidate_digest) = artifact_snapshot(&candidate)?;
    let mut changed = BTreeMap::new();
    let mut unclassified = Vec::new();
    for path in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        if before.get(path) == after.get(path) { continue; }
        let name = match rules.iter().filter(|rule| rule.owns(path)).collect::<Vec<_>>().as_slice() {
            [single] => single.id,
            [] => { unclassified.push(path); continue; }
            _ => return Err(fail(format!("multiple component rules own changed artifact {path}"))),
        };
        changed.entry(name).or_insert_with(Vec::new).push(path);
    }
    let model = |files| rules.iter().map(|rule| rule.snapshot(files)).collect::<Result<Vec<_>>>();
    let evaluator = Evaluator::load(policy, "lifecycle.rel")?;
    let mut result = evaluator.run("release.lifecycleReport", json!({
        "current":model(&before)?,"candidate":model(&after)?,"system":system
    }))?;
    result["currentFingerprint"] = json!(previous_digest);
    result["candidateFingerprint"] = json!(candidate_digest);
    result["changedArtifacts"] = json!(changed);
    result["unclassifiedArtifacts"] = json!(unclassified);
    if !unclassified.is_empty() {
        result["requiresReview"] = json!(true);
    }
    Ok(result)
}

fn component_rules(facts: &Facts) -> Result<Vec<ComponentRule<'_>>> {
    let ids = facts.values("inventory", "component");
    if ids.is_empty() || ids.len() != ids.iter().collect::<BTreeSet<_>>().len() || ids.contains(&"inventory") {
        return Err(fail("expected a unique AppDev component inventory"));
    }
    for [subject, field, _] in &facts.0 {
        let admitted = if subject == "inventory" {
            matches!(field.as_str(), "contract" | "component")
        } else {
            ids.contains(&subject.as_str()) && matches!(field.as_str(),
                "kind" | "interface" | "stateProfile" | "grant" | "artifact" | "tree" | "import")
        };
        if !admitted { return Err(fail("unknown AppDev component inventory fact")); }
    }
    ids.iter().map(|id| {
        let paths = facts.values(id, "artifact");
        let trees = facts.values(id, "tree");
        let portable = |name: &str| !name.is_empty() && !name.contains(['\\', '\0'])
            && name.split('/').all(|part| !matches!(part, "" | "." | "..")
                && !part.chars().any(char::is_control))
            && Path::new(name).components().all(|part| matches!(part, Component::Normal(_)));
        if paths.is_empty() && trees.is_empty()
            || !paths.iter().all(|name| portable(name))
            || !trees.iter().all(|name| name.strip_suffix('/').is_some_and(portable)) {
            return Err(fail("invalid AppDev component artifact ownership"));
        }
        let imports = facts.values(id, "import").into_iter().map(|item| {
            let (binding, action) = item.rsplit_once(';').unwrap_or((item, "none"));
            let (provider, interface) = binding.split_once(':').filter(|(provider, interface)|
                ids.contains(provider) && !interface.is_empty()).ok_or_else(|| fail("invalid component import"))?;
            if !matches!(action, "none" | "reload" | "drain" | "replace") {
                return Err(fail("invalid component import lifecycle action"));
            }
            Ok(json!({"id":provider,"interface":interface,"onChange":action}))
        }).collect::<Result<Vec<_>>>()?;
        Ok(ComponentRule { id, kind: facts.one(id, "kind")?, interface: facts.one(id, "interface")?,
            state: facts.one(id, "stateProfile")?, grants: facts.values(id, "grant"), paths, trees, imports })
    }).collect()
}

fn artifact_snapshot(root: &Path) -> Result<(BTreeMap<String, String>, String)> {
    let mut files = BTreeMap::new();
    let fingerprint = appdev_assurance::hash_package(root, Some(appdev_assurance::RECEIPT), |name, hash| {
        files.insert(name.to_owned(), hex::encode(hash));
    })?;
    Ok((files, fingerprint))
}
