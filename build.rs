use std::{env, path::{self, PathBuf}};

const PLATFORM_SOURCES: &[(&str, &str)] = &[
    ("ENCOUNTER_CSS_RENDERER", "encounter/algebra/css/css.renderPlan.encounter"),
    ("ENCOUNTER_HTML_ESCAPE", "encounter/algebra/html/html.escape.encounter"),
    ("ENCOUNTER_HTML_CSS_TEXT", "encounter/algebra/html/html.cssText.encounter"),
    ("ENCOUNTER_HTML_SERIALIZE", "encounter/algebra/html/html.serialize.encounter"),
    ("ENCOUNTER_APPROVAL_VIEW", "appdev-projects/registry-approval-view.encounter"),
    ("ENCOUNTER_APPROVAL_STYLE", "appdev-projects/registry-approval-style.encounter"),
];

fn main() {
    println!("cargo:rerun-if-env-changed=ENCOUNTER_PLATFORM_ROOT");
    if env::var_os("CARGO_FEATURE_HOSTED").is_none() {
        return;
    }

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"));
    let candidates = match env::var_os("ENCOUNTER_PLATFORM_ROOT") {
        Some(root) => vec![PathBuf::from(root).join("applications")],
        None => vec![
            manifest.join("../encounter-platform/applications"),
            manifest.join("../applications"),
        ],
    };
    let applications = candidates.into_iter().find(|root| {
        PLATFORM_SOURCES.iter().all(|(_, file)| root.join(file).is_file())
    }).expect("Set ENCOUNTER_PLATFORM_ROOT to an Encounter Platform checkout containing the AppDev sources");

    for (key, file) in PLATFORM_SOURCES {
        let source = path::absolute(applications.join(file)).expect("absolute Platform source path");
        let source = source.to_str().expect("UTF-8 Platform source path");
        println!("cargo:rerun-if-changed={source}");
        println!("cargo:rustc-env={key}={source}");
    }
}
