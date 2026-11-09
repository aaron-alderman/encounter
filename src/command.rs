use crate::{Result, application::Application, fail, process::Meter};
use serde_json::{Value, json};
use std::{io::{self, Write}, path::Path};

pub fn run(root: &Path, declaration: &str, arguments: &[String]) -> Result<()> {
    let app = Application::load(root, declaration)?;
    if !app.has_entry("cli.main") {
        return Err(fail("expected a declared cli.main entry"));
    }
    let mut meter = Meter::new(20_000_000);
    let mut programme = app.admit(&mut meter)?;
    app.bind_data(&mut programme);
    let result = programme.run("cli.main", json!(arguments), &mut meter)?;
    let text = result.as_str().ok_or_else(|| fail("cli.main must return text"))?;
    writeln!(io::stdout().lock(), "{text}")?;
    Ok(())
}

pub fn test(root: &Path, declaration: &str) -> Result<()> {
    let app = Application::load(root, declaration)?;
    let mut entries = app.test_entries().peekable();
    if entries.peek().is_none() {
        return Err(fail("expected a declared test.* entry"));
    }
    let mut meter = Meter::new(20_000_000);
    let mut programme = app.admit(&mut meter)?;
    app.bind_data(&mut programme);
    for entry in entries {
        let result = programme.run(entry, Value::Null, &mut meter.clone())
            .map_err(|error| fail(format!("{entry}: {error}")))?;
        if result != Value::Bool(true) {
            return Err(fail(format!("{entry}: expected true")));
        }
        writeln!(io::stdout().lock(), "ok - {entry}")?;
    }
    Ok(())
}
