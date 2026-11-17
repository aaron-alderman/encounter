use crate::{Result, appdev_host_process::{Scratch, rename_new_path}, fail, process::{Meter, Programme, browser_wasm}, rel::{self, Facts},
    source_frontend::{BUDGET, Frontend, fields, items, json_text, merge_queries, run, string},
    surface_image::SurfaceImage};
use serde_json::{Map, Value, json};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::{Component, Path, PathBuf}};

type Artifacts = BTreeMap<String, String>;

struct Sources {
    root: PathBuf,
    library: PathBuf,
    mapping: BTreeMap<String, String>,
    files: Artifacts,
    vendor_pins: BTreeMap<String, String>,
}

fn relative(path: &str) -> Result<&Path> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() || path.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(fail("expected relative build path"));
    }
    Ok(path)
}

impl Sources {
    fn read(&mut self, logical: &str) -> Result<String> {
        if let Some(text) = self.files.get(logical) { return Ok(text.clone()); }
        let (base, name) = self.mapping.get(logical).map_or((&self.root, logical), |name| (&self.library, name.as_str()));
        let name = relative(name)?;
        if name.components().any(|part| matches!(part.as_os_str().to_str(), Some("dist" | "target" | ".git")))
            || !matches!(name.extension().and_then(|ext| ext.to_str()), Some("json" | "rel" | "encounter")) {
            return Err(fail(format!("unsupported native build input {logical}")));
        }
        let file = base.join(name).canonicalize()?;
        let resolved = file.strip_prefix(base).map_err(|_| fail(format!("build input outside its source root: {logical}")))?;
        if resolved.extension() != name.extension() || resolved.components().any(|part|
            matches!(part.as_os_str().to_str(), Some("dist" | "target" | ".git")))
            || !file.is_file() || fs::metadata(&file)?.len() > 2_000_000 {
            return Err(fail(format!("build input outside its source root or over size limit: {logical}")));
        }
        let text = fs::read_to_string(file)?;
        if text.len() > 2_000_000 { return Err(fail("build input size limit")); }
        if logical.starts_with("vendor/") && self.vendor_pins.get(logical) != Some(&rel::hash(&text)) {
            return Err(fail(format!("retained vendor input pin drift: {logical}")));
        }
        self.files.insert(logical.to_owned(), text.clone());
        Ok(text)
    }

    fn json(&mut self, name: &str) -> Result<Value> { Ok(serde_json::from_str(&self.read(name)?)?) }

    fn frontend(&mut self, name: &str) -> Result<Frontend> {
        Frontend::load(self.json(name)?, |name| self.read(name))
    }
}

fn projection(frontend: &Frontend, queries: Map<String, Value>, entry: &str, bindings: Value, grants: &[&str]) -> Result<Value> {
    let model = frontend.lower(json!({"entry":entry,"queries":queries}))?;
    let programme = Programme::from_surface_root(&model, entry, &grants.iter().copied().collect())?;
    run(&programme, entry, bindings)
}

fn owner(sources: &mut Sources, frontend: &Frontend, name: &str, bindings: Value) -> Result<(Value, Value)> {
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'-') {
        return Err(fail("invalid static owner name"));
    }
    let file = format!("source/owners/{name}.encounter");
    let result = frontend.compile(&file, &sources.read(&file)?)?;
    let queries = fields(&result["surface"]["queries"])?;
    let entry = format!("owner.{name}");
    if queries.len() != 1 || items(queries.get(&entry).ok_or_else(|| fail(format!("missing static owner {entry}")))?)?.iter().any(|step| step.get("let").is_none()) {
        return Err(fail(format!("expected one static owner in {file}")));
    }
    let value = projection(frontend, queries.clone(), &entry, bindings, &[])?;
    Ok((value, source_map(&file, &result)))
}

fn definitions(sources: &mut Sources, frontend: &Frontend, spec: &Facts, artifacts: &mut Artifacts) -> Result<Map<String, Value>> {
    let build = "build";
    match (spec.values(build, "bootstrap").as_slice(), spec.values(build, "projection").as_slice()) {
        ([name], []) => {
            let (bootstrap, _) = owner(sources, frontend, name, json!({}))?;
            for (logical, path) in fields(&bootstrap["libraries"])? {
                if sources.files.contains_key(logical) || sources.mapping.insert(logical.clone(), string(path)?.to_owned()).is_some() {
                    return Err(fail(format!("duplicate library binding {logical}")));
                }
            }
            let mut fragments = Map::new();
            let mut fragment_maps = Vec::new();
            for (binding, name) in fields(&bootstrap["fragments"])? {
                let (value, map) = owner(sources, frontend, string(name)?, json!({}))?;
                fragments.insert(binding.clone(), value);
                fragment_maps.push(map);
            }
            let mut projections = Map::new();
            for definition in items(&bootstrap["definitions"])? {
                let path = string(&definition["output"])?;
                relative(path)?;
                let bindings = if definition["fragments"] == true { json!(fragments) } else { json!({}) };
                let (value, mut map) = owner(sources, frontend, string(&definition["name"])?, bindings)?;
                if definition["fragments"] == true { map["fragments"] = json!(fragment_maps); }
                insert(artifacts, &format!("{path}.map.json"), pretty(&map)?)?;
                if projections.insert(path.to_owned(), value).is_some() { return Err(fail("duplicate static output")); }
            }
            Ok(projections)
        }
        ([], [entry]) => {
            let mut queries = Map::new();
            for path in spec.values(build, "ownerModule") {
                let result = frontend.compile(path, &sources.read(path)?)?;
                merge_queries(&mut queries, &result["surface"], None)?;
            }
            let result = projection(frontend, queries, entry, json!({"eventInput":{"input":{}}}), &["text.slice","text.join"])?;
            Ok(fields(&result)?.clone())
        }
        _ => Err(fail("expected one static build entry")),
    }
}

pub fn build(root: &Path, declaration: &str, library: &Path, output: &Path) -> Result<()> {
    // Compilers and admission can recurse through authored block structures.
    std::thread::scope(|scope| {
        let build = std::thread::Builder::new().stack_size(64 * 1024 * 1024)
            .spawn_scoped(scope, || compile(root, declaration, library, output).map_err(|error| error.to_string()))?;
        build.join().map_err(|_| fail("native build worker failed"))?.map_err(fail)
    })
}

fn compile(root: &Path, declaration: &str, library: &Path, output: &Path) -> Result<()> {
    if output.symlink_metadata().is_ok() { return Err(fail("native build output must be a new directory")); }
    crate::package::check(root)?;
    let mut sources = Sources { root: root.canonicalize()?, library: library.canonicalize()?,
        mapping: BTreeMap::new(), files: BTreeMap::new(), vendor_pins: BTreeMap::new() };
    let spec = Facts::parse(&sources.read(declaration)?)?;
    match spec.values("wasm", "contract").as_slice() {
        ["encounter/browser-wasm/1"] => return build_wasm(output, declaration, &spec, &mut sources),
        ["encounter/appdev-browser-wasm-build/1" | "encounter/appdev-browser-wasm-build/2"] =>
            return Err(fail("partial Home browser Wasm builds are retired; use appdev.rel")),
        ["encounter/appdev-browser-wasm-build/3"] => return build_appdev_wasm(output, &spec, &mut sources,
            &["assurance", "aster-frame", "countdown", "interaction", "mobile", "temple"], "encounter/appdev-browser-wasm/3"),
        ["encounter/appdev-work-browser-wasm-build/1"] => return build_appdev_wasm(output, &spec, &mut sources,
            &["interaction"], "encounter/appdev-work-browser-wasm/1"),
        ["encounter/standalone-browser-wasm-build/1"] => return build_appdev_wasm(output, &spec, &mut sources,
            &browser_wasm::STANDALONE_MODULES.map(|(name, _)| name), browser_wasm::STANDALONE_CATALOG_CONTRACT),
        _ => {}
    }
    let setting = |key| spec.one("build", key);
    if setting("contract")? != "encounter/browser-build/1" { return Err(fail("unsupported native browser build contract")); }
    for [subject, key, value] in &spec.0 {
        match (subject.as_str(), key.as_str()) {
            ("build", "contract" | "frontend" | "runtimeProtocol" | "projection" | "bootstrap" | "ownerModule" | "origin" |
                "document" | "styles" | "preparation" | "childBinding" | "dataModule" | "dataEntry") | ("data", _) | ("text", _) => {}
            (_, "library") => { sources.mapping.insert(subject.clone(), value.clone()); }
            _ => return Err(fail(format!("unknown browser build field {subject}.{key}"))),
        }
    }
    let origin = setting("origin")?;
    let provenance = sources.json(origin)?;
    sources.vendor_pins = fields(&provenance["vendor"])?.iter()
        .map(|(key, value)| Ok((key.clone(), string(value)?.to_owned())))
        .collect::<Result<_>>()?;
    let primary = setting("frontend")?;
    let frontend = sources.frontend(primary)?;
    let mut artifacts = BTreeMap::new();
    let projections = definitions(&mut sources, &frontend, &spec, &mut artifacts)?;
    let manifest = projections.get("source/runtime.json").ok_or_else(|| fail("missing runtime projection"))?.clone();
    if manifest["protocol"] != setting("runtimeProtocol")? { return Err(fail("unsupported declared runtime protocol")); }
    frontend.check_runtime_lowering(&manifest)?;
    if manifest["budget"] != BUDGET { return Err(fail("expected declared execution budget")); }
    let mut queries = Map::new();
    for selection in items(&manifest["modules"])? {
        let path = selection.as_str().map_or_else(|| string(&selection["file"]), Ok)?;
        merge_queries(&mut queries, &sources.json(path)?, selection.get("queries"))?;
    }
    let mut compiled = Vec::new();
    let mut others = BTreeMap::new();
    let mut owners = Map::new();
    for module in items(&manifest["processModules"])? {
        let path = string(&module["file"])?;
        let compiler_path = string(&module["frontend"])?;
        if compiler_path != primary && !others.contains_key(compiler_path) {
            others.insert(compiler_path.to_owned(), sources.frontend(compiler_path)?);
        }
        let compiler = others.get(compiler_path).unwrap_or(&frontend);
        let text = sources.read(path)?;
        let result = compiler.compile(path, &text)?;
        let surface = &result["surface"];
        for query in fields(&surface["queries"])?.keys() { owners.insert(query.clone(), json!(path)); }
        merge_queries(&mut queries, surface, None)?;
        let out = string(&module["output"])?;
        insert(&mut artifacts, out, pretty(surface)?)?;
        insert(&mut artifacts, &format!("{out}.map.json"), pretty(&source_map(path, &result))?)?;
        compiled.push((path.to_owned(), compiler_path.to_owned(), result));
    }
    let queries = Value::Object(queries);
    for (path, compiler, result) in &compiled {
        others.get(compiler.as_str()).unwrap_or(&frontend).link(&result["surface"], &queries)
            .map_err(|error| fail(format!("{path}: {error}")))?;
    }
    let entry = string(&manifest["entry"])?;
    let model = frontend.lower(json!({"entry":entry,"queries":queries}))?;
    let grants = &manifest["grants"];
    frontend.admit(&model, grants)?;
    let granted = items(grants)?.iter().map(string).collect::<Result<BTreeSet<_>>>()?;
    let programme = Programme::from_surface(&model, &granted, &mut Meter::new(BUDGET))?;

    let mut data = Map::new();
    for [subject, key, path] in &spec.0 {
        let value = match subject.as_str() {
            "data" => {
                if let Some(value) = projections.get(path) { value.clone() }
                else { sources.json(path)? }
            }
            "text" => json!(sources.read(path)?),
            _ => continue,
        };
        if data.insert(key.clone(), value).is_some() { return Err(fail("duplicate build data binding")); }
    }
    let data_module = setting("dataModule")?;
    let data_source = frontend.compile(data_module, &sources.read(data_module)?)?;
    let assembled = projection(&frontend, fields(&data_source["surface"]["queries"])?.clone(),
        setting("dataEntry")?, json!({"eventInput":data}),
        &["record.entries", "record.fromEntries", "record.put", "json.stringify", "digest.sha256"])?;
    let mut data = fields(&assembled)?.clone();
    let bindings = fields(data.get("bindings").ok_or_else(|| fail("build data has no bindings"))?)?.clone();
    let policy = string(&manifest["policySource"])?;
    let (_, _, result) = compiled.iter().find(|(path, _, _)| path == policy).ok_or_else(|| fail("missing selected policy source"))?;
    data.insert("policy".to_owned(), result["surface"].clone());
    data.insert("policySource".to_owned(), json!(sources.read(policy)?));
    data.insert("sourceMap".to_owned(), source_map(policy, result));
    data.insert("applicationBoundary".to_owned(), json!({"grants":grants,"owners":owners}));

    let mut identity: BTreeMap<_, _> = sources.files.iter().map(|(path, text)| (path.clone(), rel::hash(text))).collect();
    for (path, value) in projections {
        let text = pretty(&value)?;
        identity.insert(path.clone(), rel::hash(&text));
        insert(&mut artifacts, &path, text)?;
    }
    let program = rel::hash(json_text(&json!(identity))?);
    data.insert("programHash".to_owned(), json!(program));
    data.insert("identity".to_owned(), json!(identity));
    let data = Value::Object(data);
    let mut render = bindings;
    render.insert("model".to_owned(), model.clone());
    render.insert("data".to_owned(), data.clone());
    render.insert("eventInput".to_owned(), json!({}));
    let render = Value::Object(render);
    let html = run(&programme, setting("document")?, render.clone())?;
    let css = run(&programme, setting("styles")?, render)?;
    insert(&mut artifacts, "assets/index.html", native_html(string(&html)?)?)?;
    insert(&mut artifacts, "assets/style.css", string(&css)?.to_owned())?;

    let mut launch = fact("surface", "contract", "encounter/browser-surface/1");
    let surface = json_text(&json!({"model":model,"data":data}))?;
    let pin = rel::hash(&surface);
    for (key, value) in [("image", "published.surface"), ("sha256", &pin), ("boot", entry),
        ("preparation", setting("preparation")?)] {
        launch.push_str(&fact("surface", key, value));
    }
    if let Some(agent) = manifest["agentEntry"].as_str() { launch.push_str(&fact("surface", "agent", agent)); }
    for grant in &granted { launch.push_str(&fact("surface", "grant", grant)); }
    for value in spec.values("build", "childBinding") { launch.push_str(&fact("surface", "childBinding", value)); }
    insert(&mut artifacts, "launch.rel", launch)?;
    insert(&mut artifacts, "published.surface", surface)?;
    let mut receipt = fact("build", "contract", "encounter/browser-build-receipt/1");
    receipt.push_str(&fact("build", "programSha256", &program));
    receipt.push_str(&fact("build", "budget", &BUDGET.to_string()));
    receipt.push_str(&fact("build", "origin", origin));
    receipt.push_str(&fact("build", "runtimeSha256", &rel::hash(fs::read("/proc/self/exe")?)));
    for (path, digest) in &identity { receipt.push_str(&fact("source", path, digest)); }
    for (path, text) in &artifacts { receipt.push_str(&fact("artifact", path, &rel::hash(text))); }
    insert(&mut artifacts, "build-receipt.rel", receipt)?;
    publish(output, artifacts)?;
    println!("{pin}");
    Ok(())
}

type WasmArtifacts = BTreeMap<String, Vec<u8>>;

fn wasm_artifacts(declaration: &str, spec: &Facts, sources: &mut Sources, runtime_pin: &str) -> Result<WasmArtifacts> {
    let source = spec.one("wasm", "source")?;
    crate::application::validate_path(source, "encounter")?;
    let text = sources.read(source)?;
    let (module, map) = browser_wasm::compile(spec, &text)?;
    let mut artifacts = WasmArtifacts::from([
        ("browser.wasm".to_owned(), module), ("browser.wasm.map.rel".to_owned(), map.into_bytes()),
    ]);
    let mut receipt = fact("build", "contract", "encounter/browser-wasm-receipt/1");
    receipt.push_str(&fact("build", "runtimeSha256", runtime_pin));
    for (path, contents) in BTreeMap::from([(declaration, sources.read(declaration)?), (source, text)]) {
        receipt.push_str(&fact("source", path, &rel::hash(contents)));
    }
    for (path, bytes) in &artifacts {
        receipt.push_str(&fact("artifact", path, &rel::hash(bytes)));
    }
    artifacts.insert("build-receipt.rel".to_owned(), receipt.into_bytes());
    Ok(artifacts)
}

fn publish_wasm(output: &Path, artifacts: WasmArtifacts, receipt: &str) -> Result<()> {
    let pin = rel::hash(artifacts.get(receipt).ok_or_else(|| fail("missing browser Wasm receipt"))?);
    let name = output.file_name().ok_or_else(|| fail("expected a browser Wasm output directory"))?;
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new(".")).canonicalize()?;
    let scratch = Scratch::create(&parent, ".encounter-wasm-")?;
    let bundle = scratch.path().join("bundle");
    fs::create_dir(&bundle)?;
    for (path, bytes) in artifacts {
        let file = bundle.join(path);
        fs::create_dir_all(file.parent().ok_or_else(|| fail("missing browser Wasm artifact parent"))?)?;
        fs::write(file, bytes)?;
    }
    rename_new_path(&bundle, &parent.join(name))?;
    println!("{pin}");
    Ok(())
}

fn build_wasm(output: &Path, declaration: &str, spec: &Facts, sources: &mut Sources) -> Result<()> {
    let runtime_pin = rel::hash(fs::read("/proc/self/exe")?);
    publish_wasm(output, wasm_artifacts(declaration, spec, sources, &runtime_pin)?, "build-receipt.rel")
}

fn build_appdev_wasm(output: &Path, spec: &Facts, sources: &mut Sources, expected: &[&str], contract: &str) -> Result<()> {
    let mut modules = spec.values("wasm", "module");
    modules.sort_unstable();
    if spec.0.len() != expected.len() + 1 || modules != expected {
        return Err(fail("invalid AppDev browser Wasm build declaration"));
    }
    let runtime_pin = rel::hash(fs::read("/proc/self/exe")?);
    let mut catalog = fact("wasm", "contract", contract);
    let mut bundle = WasmArtifacts::new();
    for name in modules {
        let declaration = format!("{name}.rel");
        let spec = Facts::parse(&sources.read(&declaration)?)?;
        let artifacts = wasm_artifacts(&declaration, &spec, sources, &runtime_pin)?;
        let receipt = artifacts.get("build-receipt.rel").ok_or_else(|| fail("missing browser Wasm receipt"))?;
        catalog.push_str(&fact(name, "receiptSha256", &rel::hash(receipt)));
        for (path, bytes) in artifacts {
            bundle.insert(format!("browser-wasm/{name}/{path}"), bytes);
        }
    }
    bundle.insert("browser-wasm.rel".to_owned(), catalog.into_bytes());
    publish_wasm(output, bundle, "browser-wasm.rel")
}

fn insert(artifacts: &mut Artifacts, path: &str, text: String) -> Result<()> {
    relative(path)?;
    if artifacts.insert(path.to_owned(), text).is_some() { return Err(fail(format!("duplicate artifact {path}"))); }
    Ok(())
}

fn source_map(path: &str, result: &Value) -> Value {
    json!({"file":path,"sourceHash":result["sourceHash"],"basis":result["basis"],"origins":result["origins"]})
}

fn pretty(value: &Value) -> Result<String> {
    Ok(crate::compat_value::stringify(value, &json!(2))? + "\n")
}

fn fact(subject: &str, predicate: &str, object: &str) -> String {
    format!("({}, {}, {})\n", rel::quote(subject), rel::quote(predicate), rel::quote(object))
}

fn native_html(html: &str) -> Result<String> {
    let script = pcre2::bytes::Regex::new(r#"<script src="app\.js"(?: defer(?:="defer")?)?></script>"#)?;
    let mut matches = script.find_iter(html.as_bytes());
    let hit = matches.next().transpose()?.ok_or_else(|| fail("missing authored application script slot"))?;
    if matches.next().is_some() { return Err(fail("duplicate authored application script slot")); }
    Ok(format!("<!doctype html>\n{}<script type=\"module\" src=\"/_encounter/browser.mjs\"></script>{}",
        &html[..hit.start()], &html[hit.end()..]))
}

fn publish(output: &Path, artifacts: Artifacts) -> Result<()> {
    for name in artifacts.keys() {
        crate::package::check_path(Path::new(name))?;
    }
    fs::create_dir(output)?;
    let result = (|| -> Result<()> {
        for (name, text) in artifacts {
            let file = output.join(name);
            fs::create_dir_all(file.parent().ok_or_else(|| fail("missing artifact parent"))?)?;
            fs::write(file, text)?;
        }
        SurfaceImage::read(&output.join("launch.rel"))?.admit(&mut Meter::new(BUDGET))?;
        Ok(())
    })();
    if result.is_err() { fs::remove_dir_all(output)?; }
    result
}
