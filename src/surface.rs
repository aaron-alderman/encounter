// Reader for the Temple surface-process instruction representation. Data arriving
// at a browser event never passes through the programme reader.
use super::{Expr, Meter, Programme, Step, operator_arity};
use crate::{Result, fail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn name(value: &Value) -> Result<&str> {
    let name = value.as_str().ok_or_else(|| fail("expected surface name"))?;
    if name.is_empty() || name.contains('\0') || matches!(name, "__proto__" | "prototype" | "constructor") {
        return Err(fail("invalid surface name"));
    }
    Ok(name)
}

pub(super) fn expression(node: &Value, depth: usize) -> Result<Expr> {
    if depth > 64 { return Err(fail("surface expression depth")); }
    Ok(match node {
        Value::String(text) if text.starts_with('$') => {
            let path = text[1..].split('.').map(|key| name(&Value::String(key.to_owned())).map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            Expr::Ref(path)
        }
        Value::Object(fields) => Expr::Record(fields.iter().map(|(key, value)| {
            name(&Value::String(key.clone()))?;
            Ok((key.clone(), expression(value, depth + 1)?))
        }).collect::<Result<_>>()?),
        Value::Array(items) if items.is_empty() => Expr::Apply("list".to_owned(), Vec::new()),
        Value::Array(items) => {
            let op = name(&items[0])?;
            let args = &items[1..];
            if !operator_arity(op, args.len()) { return Err(fail(format!("unsupported surface operator {op}"))); }
            let op = match op { "eq" => "surface.eq", "at" => "surface.at", "range" => "surface.range", _ => op };
            Expr::Apply(op.to_owned(), args.iter().map(|arg| expression(arg, depth + 1)).collect::<Result<_>>()?)
        }
        other => Expr::Literal(other.clone()),
    })
}

fn body(node: &Value, depth: usize, grants: &BTreeSet<&str>, calls: &mut BTreeSet<String>) -> Result<Vec<Step>> {
    if depth > 32 { return Err(fail("surface block depth")); }
    let nodes = node.as_array().ok_or_else(|| fail("expected surface step array"))?;
    nodes.iter().map(|step| {
        let fields = step.as_object().ok_or_else(|| fail("expected surface step record"))?;
        let fields_match = |expected: &[&str]| fields.len() == expected.len() && expected.iter().all(|key| fields.contains_key(*key));
        let expr = |key| expression(&step[key], 0);
        let binding = |key| name(&step[key]).map(str::to_owned);
        Ok(if fields_match(&["let", "value"]) { Step::Let(binding("let")?, expr("value")?) }
        else if fields_match(&["assert", "message"]) {
            Step::Assert(expr("assert")?, step["message"].as_str().ok_or_else(|| fail("expected refusal message"))?.to_owned())
        } else if fields_match(&["when", "then"]) {
            Step::When(expr("when")?, body(&step["then"], depth + 1, grants, calls)?)
        } else if fields_match(&["call"]) {
            let name = binding("call")?;
            calls.insert(name.clone());
            Step::Call(name)
        } else if fields_match(&["each", "as", "steps"]) {
            Step::Each { items: expr("each")?, item: binding("as")?, body: body(&step["steps"], depth + 1, grants, calls)? }
        } else if fields_match(&["try", "error", "catch"]) {
            Step::Try { body: body(&step["try"], depth + 1, grants, calls)?,
                error: binding("error")?, catch: body(&step["catch"], depth + 1, grants, calls)? }
        } else if fields_match(&["fold", "as", "accumulator", "initial", "steps", "yield", "into"]) {
            Step::Fold { items: expr("fold")?, item: binding("as")?, accumulator: binding("accumulator")?,
                initial: expr("initial")?, body: body(&step["steps"], depth + 1, grants, calls)?,
                yielded: expr("yield")?, into: binding("into")? }
        } else if fields_match(&["port", "args", "into"]) {
            let port = binding("port")?;
            if !grants.contains(port.as_str()) || !surface_port(&port) {
                return Err(fail(format!("surface port not granted: {port}")));
            }
            if port == "kernel.invoke" {
                if let Some(query) = step["args"]["query"].as_str().filter(|query| !query.starts_with('$')) {
                    calls.insert(query.to_owned());
                }
            }
            Step::Port { name: port, args: expr("args")?, into: binding("into")? }
        } else { return Err(fail("unknown or ambiguous surface step")); })
    }).collect()
}

fn surface_port(name: &str) -> bool {
    #[cfg(feature = "hosted")]
    return crate::application::browser_profile_port(name);
    #[cfg(not(feature = "hosted"))]
    super::supports_port(name)
}

impl Programme {
    pub(crate) fn from_surface(model: &Value, grants: &BTreeSet<&str>, meter: &mut Meter) -> Result<Self> {
        meter.charge(serde_json::to_vec(model)?.len())?;
        Self::read_surface(model, grants, None)
    }

    pub(crate) fn from_surface_root(model: &Value, root: &str, grants: &BTreeSet<&str>) -> Result<Self> {
        Self::read_surface(model, grants, Some(root))
    }

    fn read_surface(model: &Value, grants: &BTreeSet<&str>, root: Option<&str>) -> Result<Self> {
        let queries = model["queries"].as_object().ok_or_else(|| fail("expected surface queries"))?;
        let mut steps = BTreeMap::new();
        let mut pending = if let Some(root) = root { vec![root.to_owned()] } else { queries.keys().cloned().collect() };
        while let Some(query) = pending.pop() {
            if steps.contains_key(&query) { continue; }
            name(&Value::String(query.clone()))?;
            let source = queries.get(&query).ok_or_else(|| fail(format!("unlinked surface call {query}")))?;
            let mut calls = BTreeSet::new();
            let instructions = body(source, 0, grants, &mut calls)
                .map_err(|error| fail(format!("{query}: {error}")))?;
            steps.insert(query, instructions);
            pending.extend(calls);
        }
        Ok(Self::from_steps(steps))
    }

    pub(crate) fn has_process(&self, name: &str) -> bool { self.steps.contains_key(name) }
}
