use crate::{Result, appdev_assurance, appdev_lifecycle, fail, rel::{self, Facts}};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, BTreeSet}, path::Path};

const METADATA: &str = "release-guide.md";
const RECEIPT: &str = "package-receipt.rel";

pub(crate) fn plan(policy: &Path, current: &Path, candidate: &Path) -> Result<Value> {
    let both_system = appdev_assurance::system_package(current) && appdev_assurance::system_package(candidate);
    let report = appdev_lifecycle::report(policy, &policy.join("lifecycle-inventory.rel"), current, candidate)?;
    let bindings = appdev_assurance::read_facts(&policy.join("lifecycle-bindings.rel"))?;
    let mut result = select(report, &bindings)?;
    let mut review = Vec::new();
    if !both_system { review.push("switching to or from a standalone release requires a migration"); }
    if result["metadataAdmission"] == true {
        let changed = result["changedArtifacts"].as_object().ok_or_else(|| fail("expected classified AppDev artifacts"))?
            .values().filter_map(Value::as_array).flatten().filter_map(Value::as_str).collect::<BTreeSet<_>>();
        if !compatible_receipt(current, candidate, &changed)? {
            review.push("release receipt changed beyond the classified artifact pins");
        }
    }
    if !review.is_empty() {
        result["requiresReview"] = json!(true);
        result["admissionReview"] = json!(review);
    }
    Ok(result)
}

fn select(mut report: Value, bindings: &Facts) -> Result<Value> {
    if bindings.one("bindings", "contract")? != "encounter/appdev-system-lifecycle-bindings/1" {
        return Err(fail("unknown AppDev lifecycle binding contract"));
    }
    let ids = bindings.values("bindings", "binding");
    if ids.len() != ids.iter().collect::<BTreeSet<_>>().len() || ids.contains(&"bindings") {
        return Err(fail("duplicate AppDev lifecycle binding"));
    }
    for [subject, property, _] in &bindings.0 {
        let valid = if subject == "bindings" {
            matches!(property.as_str(), "binding" | "contract")
        } else {
            ids.contains(&subject.as_str()) && matches!(property.as_str(), "component" | "when" | "handler" | "unit")
        };
        if !valid { return Err(fail("unrecognized AppDev lifecycle binding field")); }
    }
    let mut mappings = BTreeMap::new();
    for id in ids {
        let component = bindings.one(id, "component")?;
        let change = bindings.one(id, "when")?;
        let handler = bindings.one(id, "handler")?;
        let units = bindings.values(id, "unit");
        if !matches!((change, handler, units.is_empty()),
            ("reload", "metadata", true) | ("reload", "follow", false) |
            ("reload" | "drain", "ingress", true) | ("replace", "restart", false)) {
            return Err(fail("incompatible AppDev lifecycle handler"));
        }
        if mappings.insert((component, change), (handler, units)).is_some() {
            return Err(fail("ambiguous AppDev lifecycle binding"));
        }
    }

    let mut restarts = Vec::new();
    let mut followers = BTreeSet::new();
    let mut ingress = false;
    let mut metadata = false;
    let mut selection = Vec::new();
    let mut review = Vec::new();
    let actions = report["actions"].as_array().ok_or_else(|| fail("expected lifecycle actions"))?;
    for row in actions {
        let component = row["component"].as_str().ok_or_else(|| fail("expected lifecycle component"))?;
        let change = row["action"].as_str().ok_or_else(|| fail("expected lifecycle action"))?;
        if change == "none" { continue; }
        let Some((handler, units)) = mappings.get(&(component, change)) else {
            review.push(component.to_owned());
            continue;
        };
        match *handler {
            "restart" => {
                for unit in units {
                    if !restarts.contains(unit) { restarts.push(*unit); }
                }
            }
            "follow" => followers.extend(units.iter().copied()),
            "ingress" => ingress = true,
            "metadata" => {
                let changed = report["changedArtifacts"][component].as_array()
                    .ok_or_else(|| fail("expected metadata artifact changes"))?;
                if changed.iter().any(|path| !matches!(path.as_str(), Some(METADATA | RECEIPT))) {
                    review.push(component.to_owned());
                    continue;
                }
                metadata = true;
            }
            _ => return Err(fail("unknown AppDev lifecycle handler")),
        }
        selection.push(json!({"component":component,"action":change,"handler":handler,"units":units}));
    }
    if followers.iter().any(|unit| restarts.contains(unit)) {
        return Err(fail("an AppDev unit cannot both follow and restart during the same activation"));
    }
    let mut native_actions = restarts.iter().map(|unit| json!({"kind":"restart","units":[unit]})).collect::<Vec<_>>();
    if ingress {
        native_actions.push(json!({"kind":"validate-ingress","units":[]}));
        native_actions.push(json!({"kind":"reload","units":["nginx.service"],"requiresValidatedIngress":true}));
    }
    if !review.is_empty() { report["requiresReview"] = json!(true); }
    report["selection"] = json!(selection);
    report["unboundComponents"] = json!(review);
    report["nativeActions"] = json!(native_actions);
    report["followUnits"] = json!(followers);
    report["metadataAdmission"] = json!(metadata);
    Ok(report)
}

fn compatible_receipt(current: &Path, candidate: &Path, changed: &BTreeSet<&str>) -> Result<bool> {
    fn read_receipt(root: &Path) -> Result<(Vec<[String; 3]>, BTreeMap<String, String>)> {
        let mut controls = Vec::new();
        let mut pins = BTreeMap::new();
        for [subject, key, value] in appdev_assurance::read_facts(&root.join(RECEIPT))?.0 {
            if subject == "artifact" {
                if pins.insert(key, value).is_some() { return Err(fail("duplicate AppDev artifact receipt")); }
            } else {
                controls.push([subject, key, value]);
            }
        }
        Ok((controls, pins))
    }
    let current = current.canonicalize()?;
    let candidate = candidate.canonicalize()?;
    let (previous_controls, previous_pins) = read_receipt(&current)?;
    let (next_controls, next_pins) = read_receipt(&candidate)?;
    if previous_controls != next_controls || !previous_pins.keys().eq(next_pins.keys()) {
        return Ok(false);
    }
    let mut changed_pins = BTreeSet::new();
    for (name, previous_pin) in &previous_pins {
        let next_pin = &next_pins[name];
        if previous_pin == next_pin { continue; }
        if !changed.contains(name.as_str()) || name == RECEIPT {
            return Ok(false);
        }
        if rel::hash(crate::browser_release::artifact(&current, name, 64_000_000)?) != *previous_pin
            || rel::hash(crate::browser_release::artifact(&candidate, name, 64_000_000)?) != *next_pin {
            return Err(fail("classified AppDev artifact differs from its receipt pin"));
        }
        changed_pins.insert(name.as_str());
    }
    Ok(!changed.contains(METADATA) || changed_pins.contains(METADATA))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings(source: &str) -> Facts {
        Facts::parse(&format!(
            "(\"bindings\",\"contract\",\"encounter/appdev-system-lifecycle-bindings/1\")\n{source}"
        )).unwrap()
    }

    #[test]
    fn appdev_system_selection_keeps_unaffected_hosts_out_of_the_plan() -> Result<()> {
        let report = json!({
            "requiresReview":false,
            "actions":[{"component":"notes","action":"reload"},{"component":"work","action":"replace"},
                {"component":"shop","action":"none"}],
            "changedArtifacts":{"notes":["release-guide.md","package-receipt.rel"]},
            "existingActions":[{"kind":"restart-all"}],
        });
        let policy = bindings(r#"
            ("bindings","binding","notes")
            ("notes","component","notes")
            ("notes","when","reload")
            ("notes","handler","metadata")
            ("bindings","binding","work")
            ("work","component","work")
            ("work","when","replace")
            ("work","handler","restart")
            ("work","unit","appdev-life-board-browser.service")
        "#);
        let selected = select(report.clone(), &policy)?;
        assert_eq!(selected["nativeActions"], json!([{"kind":"restart","units":["appdev-life-board-browser.service"]}]));
        assert_eq!(selected["metadataAdmission"], true);
        assert_eq!(selected["requiresReview"], false);
        let unbound = select(report, &bindings(""))?;
        assert_eq!(unbound["unboundComponents"], json!(["notes","work"]));
        assert_eq!(unbound["requiresReview"], true);
        assert_eq!(unbound["nativeActions"], json!([]));
        Ok(())
    }

    #[test]
    fn appdev_system_selection_rejects_conflicting_follow_and_restart() {
        let report = json!({"requiresReview":false,"actions":[
            {"component":"shell","action":"reload"},{"component":"runtime","action":"replace"}]});
        let policy = bindings(r#"
            ("bindings","binding","shell")
            ("shell","component","shell")
            ("shell","when","reload")
            ("shell","handler","follow")
            ("shell","unit","appdev-workspace.service")
            ("bindings","binding","runtime")
            ("runtime","component","runtime")
            ("runtime","when","replace")
            ("runtime","handler","restart")
            ("runtime","unit","appdev-workspace.service")
        "#);
        assert!(select(report, &policy).is_err());
    }
}
