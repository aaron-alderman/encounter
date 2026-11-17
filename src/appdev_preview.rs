use crate::{
    Result, appdev_host_process::{Scratch, Supervisor, available}, appdev_workflow,
    command, fail, rel::Facts,
};
use serde_json::{Value, json};
use std::{
    env, fs, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path, process::{Command, Stdio},
};

fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| fail("Expected preview text"))
}

fn port(value: &Value) -> Result<u16> {
    value.as_f64().filter(|value| value.fract() == 0.0 && (1024.0..=65535.0).contains(value))
        .map(|value| value as u16).ok_or_else(|| fail("Expected a loopback preview port"))
}

fn environment(command: &mut Command, values: &Value) -> Result<()> {
    for (key, value) in values.as_object().ok_or_else(|| fail("Expected preview environment"))? {
        if !matches!(key.as_str(), "APPDEV_PORT" | "APPDEV_ORIGIN" | "APPDEV_STEWARD_EMAIL"
            | "APPDEV_IDENTITY_GATEWAY" | "APPDEV_CERTIFICATE_ROLLOVER" | "APPDEV_NETWORK_STATE"
            | "STATE_DIRECTORY" | "CREDENTIALS_DIRECTORY" | "APPDEV_CERTIFICATE_INVENTORY"
            | "APPDEV_CERTIFICATE_RENEWAL") {
            return Err(fail("Unknown preview environment variable"));
        }
        if value.is_null() { command.env_remove(key); } else { command.env(key, text(value)?); }
    }
    Ok(())
}

pub fn serve(app: &Path, workflow: &command::Evaluator, facts: &Facts, declaration: &Path, launch: &[&str]) -> Result<()> {
    let declaration = declaration.canonicalize()?;
    let base = declaration.parent().ok_or_else(|| fail("Missing preview declaration directory"))?;
    let config = workflow.run("preview.plan", json!({
        "facts":Facts::read(&declaration)?.0, "launch":launch
    }))?;
    let release = base.join(text(&config["release"])?).canonicalize()?;
    let credentials = base.join(text(&config["credentials"])?).canonicalize()?;
    let ports = config["ports"].as_array().ok_or_else(|| fail("Expected preview ports"))?
        .iter().map(port).collect::<Result<Vec<_>>>()?;
    for address in &ports { available(*address)?; }

    if !config["broker"].is_null() {
        workflow.run("previewBroker.configure", json!({"steward":config["steward"]}))?;
    }
    let gateway_config = if config["gateway"].is_null() { None } else {
        let path = base.join(text(&config["gateway"]["file"])?);
        let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
            return Err(fail("Expected a private preview gateway configuration"));
        }
        let mut contents = String::new();
        file.take(128_001).read_to_string(&mut contents)?;
        if contents.len() > 128_000 { return Err(fail("Preview gateway configuration exceeded its size limit")); }
        workflow.run("preview.gateway", json!({
            "facts":Facts::parse(&contents)?.0, "gateway":config["gateway"]["port"], "broker":config["broker"]["port"],
            "http":config["http"], "workspace":config["workspace"]
        }))?;
        Some(contents)
    };
    let mut gate = Supervisor::new();
    appdev_workflow::check_preview(&mut gate, app, workflow, facts, &release)?;
    for address in &ports { available(*address)?; }

    let scratch = Scratch::create(&appdev_workflow::temporary_root(app), "appdev-preview-")?;
    fs::create_dir(scratch.path().join("state"))?;
    let staged_gateway = scratch.path().join("gateway.rel");
    if let Some(contents) = gateway_config {
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&staged_gateway)?.write_all(contents.as_bytes())?;
    }
    let mut credential = String::new();
    if !config["direct"].is_null() {
        let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK)
            .open(credentials.join("identity-management-auth"))?;
        if !file.metadata()?.is_file() { return Err(fail("Expected a regular preview credential file")); }
        file.take(4097).read_to_string(&mut credential)?;
        if credential.len() > 4096 { return Err(fail("Preview credential exceeds the size limit")); }
    }
    let setup = workflow.run("preview.environment", json!({
        "config":config, "credential":credential, "scratch":scratch.path(), "credentials":credentials
    }))?;
    let config_text = workflow.run("cli.main", json!([setup["proxy"].to_string()]))?;
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(scratch.path().join("nginx.conf"))?.write_all(text(&config_text)?.as_bytes())?;

    let executable = release.join("encounter");
    let prefix = format!("{}/", scratch.path().display());
    // Drop children before the directory containing their state and proxy configuration.
    let mut children = Supervisor::new();
    for step in launch {
        let (mut child, address) = match *step {
            "identity-broker" => {
                if config["broker"].is_null() { continue; }
                let address = port(&config["broker"]["port"])?;
                let mut child = Command::new(env::current_exe()?);
                child.arg("appdev-preview-broker").arg(app).arg(address.to_string())
                    .arg(port(&config["gateway"]["port"])?.to_string()).arg(port(&config["http"])?.to_string())
                    .arg(text(&config["steward"])?).stdin(Stdio::null());
                (child, address)
            }
            "identity-gateway" => {
                if config["gateway"].is_null() { continue; }
                let mut child = Command::new(&executable);
                child.arg("gateway").arg(&staged_gateway);
                (child, port(&config["gateway"]["port"])?)
            }
            "workspace" => {
                let mut child = Command::new(&executable);
                child.arg("workspace-host").arg(&release);
                environment(&mut child, &setup["workspace"])?;
                (child, port(&config["workspace"])?)
            }
            "browser" => {
                let address = port(&config["browser"])?;
                let mut child = Command::new(&executable);
                child.args(["appdev-browser-host", "--allow-aster-stream"]).arg(&release).arg(address.to_string());
                (child, address)
            }
            "proxy" => {
                let mut child = Command::new("/usr/sbin/nginx");
                child.args(["-p", &prefix, "-c", "nginx.conf"]);
                (child, port(&config["http"])?)
            }
            _ => return Err(fail("Unknown AppDev preview host operation")),
        };
        children.start(step, &mut child)?;
        children.listen(address)?;
    }
    println!("AppDev preview ready at {}", text(&setup["url"])?);
    children.supervise()
}
