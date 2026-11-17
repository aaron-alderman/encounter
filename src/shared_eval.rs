// Shared evaluation values for authored compiler programmes. Keep aggregates
// immutable so recursive calls can pass token and source-map tables by reference.
use super::{Expr, Meter, Programme, RuntimeLimit, Step, absent, is_absent, js_string, value};
use crate::{Result, fail};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, rc::Rc};

type Cell = Rc<Tree>;
type Scope = BTreeMap<String, Cell>;

enum Tree {
    Scalar(Value),
    List(Vec<Cell>),
    Record(Vec<(String, Cell)>),
}

fn share(value: &Value) -> Cell {
    Rc::new(match value {
        Value::Array(values) => Tree::List(values.iter().map(share).collect()),
        Value::Object(fields) if !is_absent(value) => Tree::Record(fields.iter().map(|(key, value)| (key.clone(), share(value))).collect()),
        _ => Tree::Scalar(value.clone()),
    })
}

fn materialize(value: &Cell) -> Value {
    match value.as_ref() {
        Tree::List(values) => Value::Array(values.iter().map(materialize).collect()),
        Tree::Record(fields) => Value::Object(fields.iter().map(|(key, value)| (key.clone(), materialize(value))).collect()),
        Tree::Scalar(value) => value.clone(),
    }
}

fn scalar(value: &Cell) -> Result<&Value> {
    match value.as_ref() { Tree::Scalar(value) => Ok(value), _ => Err(fail("expected scalar")) }
}

fn text(value: &Cell) -> Result<&str> { super::text(scalar(value)?) }

fn list(value: &Cell) -> Result<&[Cell]> {
    match value.as_ref() { Tree::List(values) => Ok(values), _ => Err(fail("expected list")) }
}

fn get(value: &Cell, key: &str) -> Option<Cell> {
    match value.as_ref() {
        Tree::Record(fields) => fields.iter().find_map(|(k, v)| (k == key).then(|| Rc::clone(v))),
        Tree::List(values) => key.parse::<usize>().ok().filter(|n| n.to_string() == key)
            .and_then(|i| values.get(i)).cloned(),
        _ => None,
    }
}

fn missing() -> Cell { share(&absent()) }
fn truth(value: &Cell) -> bool { scalar(value).map(super::truth).unwrap_or(true) }

fn same(left: &Cell, right: &Cell) -> bool {
    if Rc::ptr_eq(left, right) { return true; }
    match (left.as_ref(), right.as_ref()) {
        (Tree::Scalar(a), Tree::Scalar(b)) => a == b,
        (Tree::List(a), Tree::List(b)) => a.len() == b.len() && a.iter().zip(b).all(|(a,b)| same(a,b)),
        (Tree::Record(a), Tree::Record(b)) => a.len() == b.len()
            && a.iter().all(|(key, value)| get(right, key).is_some_and(|other| same(value, &other))),
        _ => false,
    }
}

fn equal(left: &Cell, right: &Cell, surface: bool) -> Result<bool> {
    match (left.as_ref(), right.as_ref()) {
        (Tree::Scalar(a), Tree::Scalar(b)) if surface => super::surface_equal(a, b),
        (Tree::Scalar(a), Tree::Scalar(b)) if a.is_number() && b.is_number() => Ok(a.as_f64() == b.as_f64()),
        _ if surface => super::surface_equal(&materialize(left), &materialize(right)),
        _ => Ok(same(left, right)),
    }
}

impl Programme {
    pub(crate) fn run_shared(&self, name: &str, bindings: &Map<String, Value>, meter: &mut Meter) -> Result<Value> {
        let mut scope = bindings.iter().map(|(key, value)| (key.clone(), share(value))).collect();
        self.shared_block(self.steps.get(name).ok_or_else(|| fail(format!("missing process {name}")))?, &mut scope, meter, 0)?;
        scope.get("result").map(materialize).ok_or_else(|| fail(format!("{name}: missing result")))
    }

    fn shared_block(&self, steps: &[Step], scope: &mut Scope, meter: &mut Meter, depth: usize) -> Result<()> {
        if depth > 2048 { return Err(Box::new(RuntimeLimit("process depth limit"))); }
        for step in steps {
            meter.charge(1)?;
            match step {
                Step::Let(name, expr) => { scope.insert(name.clone(), eval(expr, scope, meter)?); }
                Step::Assert(expr, message) => {
                    if !truth(&eval(expr, scope, meter)?) { return Err(fail(message)); }
                }
                Step::When(expr, body) => {
                    if truth(&eval(expr, scope, meter)?) { self.shared_block(body, scope, meter, depth)?; }
                }
                Step::Call(name) => self.shared_block(self.steps.get(name).ok_or_else(|| fail("missing-process"))?, scope, meter, depth+1)?,
                Step::Each { items, item, body } => {
                    let values = eval(items, scope, meter)?;
                    for row in list(&values)? {
                        let mut local = scope.clone();
                        local.insert(item.clone(), Rc::clone(row));
                        self.shared_block(body, &mut local, meter, depth)?;
                    }
                }
                Step::Try { body, error, catch } => {
                    if let Err(fault) = self.shared_block(body, scope, meter, depth) {
                        if fault.is::<RuntimeLimit>() { return Err(fault); }
                        scope.insert(error.clone(), share(&json!({"name":"Error","message":fault.to_string()})));
                        self.shared_block(catch, scope, meter, depth)?;
                    }
                }
                Step::Fold { items, item, accumulator, initial, body, yielded, into } => {
                    let items = eval(items, scope, meter)?;
                    let mut acc = eval(initial, scope, meter)?;
                    for row in list(&items)? {
                        let mut local = scope.clone();
                        local.insert(item.clone(), Rc::clone(row));
                        local.insert(accumulator.clone(), acc);
                        self.shared_block(body, &mut local, meter, depth)?;
                        acc = eval(yielded, &local, meter)?;
                    }
                    scope.insert(into.clone(), acc);
                }
                Step::Port { name, args, into } => {
                    let args = eval(args, scope, meter)?;
                    let result = if name == "kernel.invoke" {
                        let query = get(&args, "query").ok_or_else(|| fail("missing invocation query"))?;
                        let target = self.steps.get(text(&query)?).ok_or_else(|| fail("missing-process"))?;
                        let mut local = scope.clone();
                        local.insert("eventInput".to_owned(), get(&args, "input").unwrap_or_else(|| share(&json!({}))));
                        self.shared_block(target, &mut local, meter, depth+1)?;
                        local.remove("result").ok_or_else(|| fail("missing result"))?
                    } else {
                        // Preserve the native port implementation and its budget.
                        // Argument evaluation and the port step were charged above.
                        let mut nested = super::Env::new();
                        self.execute_port("", name, materialize(&args), &mut nested, meter, depth).map(|value|share(&value))?
                    };
                    scope.insert(into.clone(), result);
                }
            }
        }
        Ok(())
    }
}

fn eval(expr: &Expr, scope: &Scope, meter: &mut Meter) -> Result<Cell> {
    meter.charge(1)?;
    Ok(match expr {
        Expr::Literal(value) => share(value),
        Expr::Ref(path) => {
            let mut current = scope.get(&path[0]).cloned().ok_or_else(|| fail(format!("unknown binding {}",path[0])))?;
            for (index,key) in path[1..].iter().enumerate() {
                if !matches!(current.as_ref(), Tree::Record(_)) { return Err(fail("invalid reference path")); }
                current = if let Some(value) = get(&current,key) { value }
                else if index+2==path.len() { missing() }
                else { return Err(fail("invalid reference path")); };
            }
            current
        }
        Expr::Record(fields) => Rc::new(Tree::Record(fields.iter().map(|(key,expr)| {
            Ok((key.clone(),eval(expr,scope,meter)?))
        }).collect::<Result<_>>()?)),
        Expr::Apply(op,args) => match op.as_str() {
            "if" => eval(&args[if truth(&eval(&args[0],scope,meter)?) {1}else{2}],scope,meter)?,
            "and" | "or" => {
                let mut result = share(&json!(true));
                if op=="or" { result = share(&Value::Null); }
                for arg in args {
                    let candidate = eval(arg,scope,meter)?;
                    if op=="and" {
                        result=candidate;
                        if !truth(&result) { break; }
                    } else if !truth(&result) && truth(&candidate) { result=candidate; }
                }
                result
            }
            "let" => {
                let key=eval(&args[0],scope,meter)?;
                let initial=eval(&args[1],scope,meter)?;
                let mut local=scope.clone();
                local.insert(text(&key)?.to_owned(),initial);
                eval(&args[2],&local,meter)?
            }
            "list" => Rc::new(Tree::List(args.iter().map(|arg|eval(arg,scope,meter)).collect::<Result<_>>()?)),
            "at" | "surface.at" => {
                let source=eval(&args[0],scope,meter)?;
                let key=eval(&args[1],scope,meter)?;
                let key=materialize(&key);
                let name=js_string(&key);
                match source.as_ref() {
                    Tree::Record(_) | Tree::List(_) if !name.contains('\0') => {
                        if op=="surface.at" && name=="length" && let Tree::List(values)=source.as_ref() {
                            share(&json!(values.len()))
                        } else { get(&source,&name).unwrap_or_else(missing) }
                    }
                    _ => eval_scalar(op, &[materialize(&source),key], meter)?,
                }
            }
            "count" => {
                let source=eval(&args[0],scope,meter)?;
                match source.as_ref() {
                    Tree::List(values) => share(&json!(values.len())),
                    Tree::Record(_) => missing(),
                    Tree::Scalar(value) => eval_scalar(op, &[value.clone()],meter)?,
                }
            }
            "isArray" => share(&json!(matches!(eval(&args[0],scope,meter)?.as_ref(),Tree::List(_)))),
            "not" => share(&json!(!truth(&eval(&args[0],scope,meter)?))),
            "eq" | "surface.eq" => {
                let left = eval(&args[0], scope, meter)?;
                let right = eval(&args[1], scope, meter)?;
                share(&json!(equal(&left, &right, op == "surface.eq")?))
            }
            "includes" => {
                let source=eval(&args[0],scope,meter)?;
                let item=eval(&args[1],scope,meter)?;
                match source.as_ref() {
                    Tree::List(values) => share(&json!(values.iter().any(|value|same(value,&item)))),
                    _ => eval_scalar(op,&[materialize(&source),materialize(&item)],meter)?,
                }
            }
            "append" => {
                let left=eval(&args[0],scope,meter)?;
                let right=eval(&args[1],scope,meter)?;
                Rc::new(Tree::List(list(&left)?.iter().chain(list(&right)?).cloned().collect()))
            }
            "fold" => {
                let source=eval(&args[0],scope,meter)?;
                let key=eval(&args[1],scope,meter)?;
                let accumulator=eval(&args[2],scope,meter)?;
                let mut result=eval(&args[3],scope,meter)?;
                let mut local=scope.clone();
                if text(&key)? == text(&accumulator)? { return Err(fail("fold bindings must differ")); }
                for row in list(&source)? {
                    local.insert(text(&key)?.to_owned(), Rc::clone(row));
                    local.insert(text(&accumulator)?.to_owned(), result);
                    result=eval(&args[4],&local,meter)?;
                }
                result
            }
            "map" | "filter" | "every" | "some" => {
                let source=eval(&args[0],scope,meter)?;
                let key=eval(&args[1],scope,meter)?;
                let key=text(&key)?.to_owned();
                let mut values=Vec::new();
                let mut local=scope.clone();
                for row in list(&source)? {
                    local.insert(key.clone(),Rc::clone(row));
                    let selected=eval(&args[2],&local,meter)?;
                    match op.as_str() {
                        "map" => values.push(selected),
                        "filter" if truth(&selected) => values.push(Rc::clone(row)),
                        "every" if !truth(&selected) => return Ok(share(&json!(false))),
                        "some" if truth(&selected) => return Ok(share(&json!(true))),
                        _ => {}
                    }
                }
                if matches!(op.as_str(),"some"|"every") { share(&json!(op=="every")) }
                else { Rc::new(Tree::List(values)) }
            }
            "distinct" => {
                let source=eval(&args[0],scope,meter)?;
                let mut values=Vec::new();
                for row in list(&source)? {
                    if !values.iter().any(|value|same(value,row)) { values.push(Rc::clone(row)); }
                }
                Rc::new(Tree::List(values))
            }
            _ => {
                let values=args.iter().map(|arg|eval(arg,scope,meter).map(|value|materialize(&value))).collect::<Result<Vec<_>>>()?;
                eval_scalar(op,&values,meter)?
            }
        },
    })
}

fn eval_scalar(op: &str, values: &[Value], meter: &mut Meter) -> Result<Cell> {
    let args=values.iter().cloned().map(Expr::Literal).collect();
    // The fallback receives already evaluated operands. Account only for any
    // additional work done by the native primitive.
    let mut fallback = meter.with_credit(1+values.len());
    let result = value(&Expr::Apply(op.to_owned(),args),&super::Env::new(),&mut fallback);
    *meter = fallback;
    result.map(|value|share(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_matches_surface_equality() {
        let model = serde_json::from_str(r#"{"queries":{"probe":[{"let":"result","value":["list",
            ["eq",{"2":0,"1":0},{"1":0,"2":0}],
            ["eq",{"a":0,"b":0},{"b":0,"a":0}],
            ["eq",{"a":["list",1]},{"a":["list",1.0]}]
        ]}]}}"#).unwrap();
        let programme = Programme::from_surface(&model, &Default::default(), &mut Meter::new(1000)).unwrap();
        let bindings = Map::new();
        let normal = programme.run_bound("probe", &bindings, &mut Meter::new(1000)).unwrap();
        let shared = programme.run_shared("probe", &bindings, &mut Meter::new(1000)).unwrap();
        assert_eq!(normal, json!([true, false, true]));
        assert_eq!(shared, normal);
    }
}
