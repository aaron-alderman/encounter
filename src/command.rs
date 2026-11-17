use crate::{Result, application::Application, fail, process::{Meter, Programme}};
use serde_json::{Value, json};
use std::{io::{self, BufRead, Read, Write}, path::Path};

fn read_stdin() -> Result<String> {
    const LIMIT: usize = 2_000_000;
    let mut input = String::new();
    io::stdin().lock().take((LIMIT + 1) as u64).read_to_string(&mut input)?;
    if input.len() > LIMIT { return Err(fail("Encounter input exceeds the read limit")); }
    Ok(input)
}

pub fn run_stdin(root: &Path, declaration: &str) -> Result<()> {
    run(root, declaration, &[read_stdin()?])
}

pub fn run_lines(root: &Path, declaration: &str) -> Result<()> {
    const LIMIT: usize = 2_000_000;
    let evaluator = Evaluator::load(root, declaration)?;
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = (&mut input).take((LIMIT + 1) as u64).read_line(&mut line)?;
        if bytes == 0 { return Ok(()); }
        if bytes > LIMIT { return Err(fail("Encounter input exceeds the read limit")); }
        let reply = match evaluator.run("cli.main", json!([line.trim_end_matches(['\r', '\n'])])) {
            Ok(value) => json!({"ok": value}),
            Err(error) => json!({"error": error.to_string()}),
        };
        serde_json::to_writer(&mut output, &reply)?;
        writeln!(output)?;
        output.flush()?;
    }
}

pub fn run(root: &Path, declaration: &str, arguments: &[String]) -> Result<()> {
    let text = render(root, declaration, arguments)?;
    writeln!(io::stdout().lock(), "{text}")?;
    Ok(())
}

pub fn run_sources(root: &Path, declaration: &str, arguments: &[String], stdin: bool) -> Result<u8> {
    let (output, status) = source_report(root, declaration, arguments, stdin)?;
    writeln!(io::stdout().lock(), "{output}")?;
    Ok(status)
}

pub(crate) fn source_report(root: &Path, declaration: &str, arguments: &[String], stdin: bool) -> Result<(String, u8)> {
    let mut command = Evaluator::load(root, declaration)?;
    command.programme.bind_command_sources(crate::command_sources::Sources::open(root)?);
    let input = if stdin { Some(read_stdin()?) } else { None };
    let result = command.run("cli.sources", json!({"arguments": arguments, "stdin": input}))?;
    let output = result["text"].as_str().ok_or_else(|| fail("cli.sources must return output text"))?;
    let status = result["exitCode"].as_u64().and_then(|code| u8::try_from(code).ok())
        .ok_or_else(|| fail("cli.sources must return an exit code"))?;
    Ok((output.to_owned(), status))
}

pub fn render(root: &Path, declaration: &str, arguments: &[String]) -> Result<String> {
    let result = evaluate(root, declaration, "cli.main", json!(arguments))?;
    result.as_str().map(str::to_owned).ok_or_else(|| fail("cli.main must return text"))
}

pub(crate) fn evaluate(root: &Path, declaration: &str, entry: &str, input: Value) -> Result<Value> {
    Evaluator::load(root, declaration)?.run(entry, input)
}

pub(crate) struct Evaluator {
    app: Application,
    programme: Programme,
    meter: Meter,
}

impl Evaluator {
    pub(crate) fn load(root: &Path, declaration: &str) -> Result<Self> {
        let app = Application::load(root, declaration)?;
        let mut meter = Meter::new(20_000_000);
        let mut programme = app.admit(&mut meter)?;
        app.bind_data(&mut programme);
        Ok(Self { app, programme, meter })
    }

    pub(crate) fn run(&self, entry: &str, input: Value) -> Result<Value> {
        if !self.app.has_entry(entry) {
            return Err(fail(format!("expected a declared {entry} entry")));
        }
        self.programme.run(entry, input, &mut self.meter.clone())
    }
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
