use crate::{Result, appdev_host_process::{Scratch, Supervisor}, command, fail};
use serde_json::json;
use std::{
    env, fs, io::{BufRead, BufReader},
    path::{Path, PathBuf}, process::{Command, Stdio},
    sync::mpsc, thread, time::{Duration, Instant},
};

pub fn serve(root: &Path, declaration: &str, listen: u16) -> Result<()> {
    let executable = env::current_exe()?;
    let mut ingress = executable.parent().ok_or_else(|| fail("Missing Front Gate runtime directory"))?
        .join("front-gate-ingress");
    if let Some(active) = env::var_os("APPDEV_FRONT_GATE_ACTIVE_RELEASE") {
        let active = PathBuf::from(active).canonicalize()?;
        if crate::appdev_assurance::system_package(&active) {
            crate::appdev_assurance::require(&active)?;
            ingress = active.join("front-gate-ingress");
        }
    }
    let workflow = command::Evaluator::load(&ingress, "local-ingress.rel")?;
    let plan = workflow.run("ingress.hostPlan", json!({"declaration":declaration, "listen":listen}))?;
    let directory = plan["declaration"].as_str().ok_or_else(|| fail("Missing directory declaration"))?;
    let upstream_port = plan["upstreamPort"].as_str().ok_or_else(|| fail("Missing upstream port"))?;
    let runtime = env::var_os("APPDEV_FRONT_GATE_RUNTIME").map(PathBuf::from).unwrap_or(executable);
    let root = root.canonicalize()?;
    let services = command::Evaluator::load(&root, declaration)?.run("gate.apps", json!(null))?;
    let generation = root.ancestors().nth(4).ok_or_else(|| fail("Missing Front Gate generation directory"))?;
    let scratch = Scratch::create(generation, "aster-front.")?;
    let mut children = Supervisor::new();
    let stdout = children.start("Front Gate directory", Command::new(runtime)
        .arg("directory").arg(&root).args([directory, upstream_port]).stdout(Stdio::piped()))?
        .stdout.take().ok_or_else(|| fail("Missing Front Gate directory output"))?;
    let (sender, port) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut sender = Some(sender);
        for line in BufReader::new(stdout).lines().map_while(|line| line.ok()) {
            if let Some(port) = line.strip_prefix("Encounter http://127.0.0.1:")
                .and_then(|port| port.parse::<u16>().ok()) {
                if let Some(sender) = sender.take() { let _ = sender.send(port); }
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let upstream = loop {
        children.check()?;
        match port.recv_timeout(Duration::from_millis(50)) {
            Ok(port) => break port,
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(_) => return Err(fail("Front Gate directory failed to announce a loopback port")),
        }
    };
    let input = json!({"listen": listen, "upstream": upstream, "services": services}).to_string();
    let config = workflow.run("cli.main", json!([input]))?;
    let config = config.as_str().ok_or_else(|| fail("Expected Front Gate proxy configuration text"))?;
    fs::write(scratch.path().join("nginx.conf"), config)?;
    let prefix = format!("{}/", scratch.path().display());
    let nginx = "/usr/sbin/nginx";
    children.run("Front Gate proxy configuration check", Command::new(nginx).args(["-p", &prefix, "-c", "nginx.conf", "-t"]))?;
    children.start("Front Gate loopback proxy", Command::new(nginx).args(["-p", &prefix, "-c", "nginx.conf"]))?;
    children.listen(listen)?;
    children.supervise()
}
