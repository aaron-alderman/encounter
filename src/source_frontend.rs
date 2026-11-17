// Host for the pinned, authored surface-language compiler. It runs the same
// parser, lowerer and admission algebra as the reference frontend.
use crate::{Result, compat_value, fail, process::{Meter, Programme}, rel};
use serde_json::{Map, Value, json};
use std::{cell::RefCell, collections::{BTreeMap, BTreeSet}};

pub const BUDGET: usize = 20_000_000;
const PRIMITIVES: &[&str] = &["fold", "let", "raise", "isArray", "list", "append",
    "eq", "includes", "if", "count", "at", "concat", "add", "range", "distinct"];
const PURE: &[&str] = &["digest.sha256", "json.parse", "json.stringify", "kernel.invoke", "record.entries",
    "record.fromEntries", "record.get", "record.put", "text.matches", "text.replaceAll", "text.slice",
    "text.split", "value.describe"];

pub fn string(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| fail("expected text"))
}

pub fn fields(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or_else(|| fail("expected record"))
}

pub fn items(value: &Value) -> Result<&[Value]> {
    value.as_array().map(Vec::as_slice).ok_or_else(|| fail("expected list"))
}

pub fn json_text(value: &Value) -> Result<String> {
    compat_value::stringify(value, &Value::Null)
}

pub fn merge_queries(queries: &mut Map<String, Value>, module: &Value, selection: Option<&Value>) -> Result<()> {
    let owned = fields(&module["queries"])?;
    if let Some(selection) = selection {
        for name in items(selection)? {
            let name = string(name)?;
            let body = owned.get(name).ok_or_else(|| fail(format!("missing selected query {name}")))?;
            insert_query(queries, name, body)?;
        }
    } else {
        for (name, body) in owned { insert_query(queries, name, body)?; }
    }
    Ok(())
}

fn insert_query(queries: &mut Map<String, Value>, name: &str, body: &Value) -> Result<()> {
    if queries.contains_key(name) { return Err(fail(format!("duplicate process owner {name}"))); }
    queries.insert(name.to_owned(), body.clone());
    Ok(())
}

pub fn run(programme: &Programme, entry: &str, bindings: Value) -> Result<Value> {
    programme.run_bound(entry, fields(&bindings)?, &mut Meter::new(BUDGET))
        .map_err(|error| fail(format!("{entry}: {error}")))
}

pub struct Frontend {
    manifest: Value,
    lower_model: Value,
    lowerer: Programme,
    operators: Value,
    admission: Value,
    admission_programme: Programme,
    kernel_profile: Value,
    model: Value,
    compiler: Programme,
    bindings: Map<String, Value>,
    compiled: RefCell<BTreeMap<(String, String), Value>>,
}

impl Frontend {
    pub fn load(manifest: Value, mut read: impl FnMut(&str) -> Result<String>) -> Result<Self> {
        let mut unsigned = fields(&manifest)?.clone();
        let identity = unsigned.shift_remove("identity").ok_or_else(|| fail("missing frontend identity"))?;
        if manifest["protocol"] != "temple/process-frontend/1"
            || string(&identity)? != rel::hash(json_text(&Value::Object(unsigned))?) {
            return Err(fail("process frontend identity mismatch"));
        }
        let mut files = BTreeMap::new();
        for file in items(&manifest["files"])? {
            let path = string(&file["path"])?;
            let text = read(path)?;
            if string(&file["sha256"])? != rel::hash(&text) || files.contains_key(path) {
                return Err(fail(format!("process frontend dependency drift: {path}")));
            }
            files.insert(path, serde_json::from_str::<Value>(&text)?);
        }
        let pinned = |path: &Value| {
            let path = string(path)?;
            files.get(path).cloned().ok_or_else(|| fail(format!("unmeasured frontend dependency {path}")))
        };
        let pure: BTreeSet<_> = PURE.iter().copied().collect();
        let lower_model = pinned(&manifest["lowering"])?;
        let operators = pinned(&manifest["operators"])?;
        let lowerer = Programme::from_surface(&lower_model, &pure, &mut Meter::new(BUDGET))?;
        let admission = lower(&lowerer, &lower_model, &operators, pinned(&manifest["admission"])?)?;
        let kernel_profile = pinned(&manifest["kernelProfile"])?;
        let admission_programme = Programme::from_surface(&admission, &pure, &mut Meter::new(BUDGET))?;
        let mut queries = Map::new();
        for selection in items(&manifest["modules"])? {
            merge_queries(&mut queries, &pinned(&selection["file"])?, selection.get("queries"))?;
        }
        let model = lower(&lowerer, &lower_model, &operators, json!({"entry":manifest["entry"],"queries":queries}))?;
        let grants = items(&manifest["grants"])?.iter().map(string).collect::<Result<BTreeSet<_>>>()?;
        if !grants.is_subset(&pure) { return Err(fail("nonmechanical compiler port")); }
        let compiler = Programme::from_surface(&model, &grants, &mut Meter::new(BUDGET))?;
        let mut bindings = Map::new();
        for (name, spec) in fields(&manifest["data"])? {
            let mut value = pinned(&spec["file"])?;
            if let Some(path) = spec.get("path") {
                for key in items(path)? {
                    value = value.get(string(key)?).cloned().ok_or_else(|| fail("missing frontend data member"))?;
                }
            }
            bindings.insert(name.clone(), value);
        }
        let frontend = Self { manifest, lower_model, lowerer, operators, admission, admission_programme,
            kernel_profile, model, compiler, bindings, compiled: RefCell::default() };
        frontend.admit(&frontend.model, &frontend.manifest["grants"])?;
        Ok(frontend)
    }

    pub fn compile(&self, file: &str, text: &str) -> Result<Value> {
        let key = (file.to_owned(), rel::hash(text));
        if let Some(value) = self.compiled.borrow().get(&key) { return Ok(value.clone()); }
        let basis = json!({"runtime":self.manifest["identity"]});
        let input = json!({"file":file,"text":text,"expectedTextSha256":key.1,"expectedBasis":basis});
        let mut bindings = self.bindings.clone();
        bindings.insert("model".to_owned(), self.model.clone());
        bindings.insert("lpBasis".to_owned(), basis);
        bindings.insert("eventInput".to_owned(), input);
        if std::env::var_os("ENCOUNTER_BUILD_TRACE").is_some() { eprintln!("Compiling {file}"); }
        let result = self.compiler.run_shared(string(&self.manifest["entry"])?, &bindings, &mut Meter::new(BUDGET))?;
        if result["ok"] != true || result["sourceHash"] != key.1 {
            return Err(fail(format!("{file}: {}", result["diagnostic"])));
        }
        self.compiled.borrow_mut().insert(key, result.clone());
        Ok(result)
    }

    pub fn link(&self, surface: &Value, queries: &Value) -> Result<()> {
        let mut bindings = self.bindings.clone();
        bindings.extend(fields(&json!({"model":self.model,"lpFile":"process-source-link","lpText":"",
            "lpDependencies":queries,"eventInput":{"surface":surface}}))?.clone());
        let result = run(&self.compiler, "language.process.link", Value::Object(bindings))?;
        if result["ok"] != true { return Err(fail(format!("link refused: {}", result["diagnostic"]))); }
        Ok(())
    }

    pub fn check_runtime_lowering(&self, runtime: &Value) -> Result<()> {
        for (field, frontend_field) in [("lowerer", "lowering"), ("definitions", "operators")] {
            let declared = string(&runtime[field])?;
            if self.manifest[frontend_field] != declared {
                return Err(fail(format!("runtime {field} differs from the pinned frontend")));
            }
        }
        Ok(())
    }

    pub fn lower(&self, input: Value) -> Result<Value> {
        lower(&self.lowerer, &self.lower_model, &self.operators, input)
    }

    pub fn admit(&self, model: &Value, grants: &Value) -> Result<()> {
        for entry in ["admit.model", "admit.effects"] {
            run(&self.admission_programme, entry, json!({"model":self.admission,
                "target":model,"profile":self.kernel_profile,"grants":grants}))?;
        }
        Ok(())
    }
}

fn lower(programme: &Programme, model: &Value, definitions: &Value, input: Value) -> Result<Value> {
    let result = run(programme, "lower.start", json!({"model":model,"definitions":definitions,
        "primitives":PRIMITIVES,"input":input,"mode":"model"}))?;
    result.get("value").filter(|value| value["queries"].is_object()).cloned().ok_or_else(|| fail("lowerer returned no model"))
}
