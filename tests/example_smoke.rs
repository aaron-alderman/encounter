use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

const WAIT: Duration = Duration::from_secs(5);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let mut suffix = [0; 12];
        getrandom::getrandom(&mut suffix).expect("random fixture suffix");
        let directory = std::env::temp_dir().join(format!("encounter-example-{}", hex::encode(suffix)));
        fs::create_dir(&directory).expect("create smoke fixture");
        Self(directory)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn encounter() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_encounter"));
    command.current_dir(env!("CARGO_MANIFEST_DIR"));
    command
}

fn stdout(output: Output) -> String {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

fn request(address: SocketAddr, path: &str, basic: Option<&str>) -> String {
    let mut socket = TcpStream::connect_timeout(&address, WAIT).unwrap();
    socket.set_read_timeout(Some(WAIT)).unwrap();
    socket.set_write_timeout(Some(WAIT)).unwrap();
    write!(socket, "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n").unwrap();
    if let Some(token) = basic {
        write!(socket, "Authorization: Basic {token}\r\n").unwrap();
    }
    write!(socket, "\r\n").unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn native_server_temple_installer_binds_artifact_and_preserves_files_on_denial() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let scratch = Scratch::new();
    let temp = &scratch.0;
    let artifact = temp.join("artifact");
    let store = temp.join("store");
    fs::create_dir(&artifact).unwrap();
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = artifact.join("encounter");
    let status = Command::new("/usr/bin/strip").args(["-o"]).arg(&binary)
        .arg(env!("CARGO_BIN_EXE_encounter")).status().unwrap();
    assert!(status.success());
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let image = artifact.join("web.rel");
    let digest = stdout(Command::new(&binary).current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["build", "examples/web", "application.rel"]).arg(&image).output().unwrap());
    let config = temp.join("host.json");
    let unit = temp.join("host.conf");
    let settings = serde_json::json!({
        "protocol": "sourcery/server-temple-process-host-config.v1",
        "nativeApplication": {
            "protocol": "encounter/server-temple-application/1",
            "image": image, "sha256": digest.trim(), "store": store, "port": 8140,
        },
    });
    fs::write(&config, settings.to_string()).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let install = |executable: &Path, options: &str| {
        let mut child = Command::new(executable).arg("install-server-temple-readiness")
            .args([&artifact, &config, &unit]).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(options.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };
    let result: serde_json::Value = serde_json::from_str(&stdout(install(&binary, "{}"))).unwrap();
    assert_eq!(result["protocol"], "sourcery/server-temple-readiness-installation.v1");
    assert_eq!(result["readiness"]["expectedStatus"], 405);
    let contents = fs::read_to_string(&unit).unwrap();
    assert!(contents.contains(&format!("ExecStart={} server-temple-host {}", binary.display(), config.display())));
    assert!(contents.contains(&format!("ExecStartPost={} server-temple-readiness {}", binary.display(), config.display())));
    let before = fs::read(&config).unwrap();
    assert_eq!(fs::metadata(&config).unwrap().permissions().mode() & 0o777, 0o600);
    for options in [r#"{"endpoint":"http://example.test/mcp"}"#, r#"{"intervalMs":-1}"#] {
        assert!(!install(&binary, options).status.success());
        assert_eq!(fs::read(&config).unwrap(), before);
        assert_eq!(fs::read_to_string(&unit).unwrap(), contents);
    }
    assert!(!install(Path::new(env!("CARGO_BIN_EXE_encounter")), "{}").status.success());
    fs::remove_file(&unit).unwrap();
    symlink(&config, &unit).unwrap();
    assert!(!install(&binary, "{}").status.success());
    assert_eq!(fs::read(&config).unwrap(), before);
    assert_eq!(fs::read_link(&unit).unwrap(), config);
}

#[test]
fn example_cli_and_compiled_web_smoke() {
    let scratch = Scratch::new();
    let temp = &scratch.0;
    let cli = ["run", "--declaration", "examples/cli", "application.rel"];
    assert_eq!(stdout(encounter().args(["run", "--declaration", "examples/hello", "application.rel"])
        .output().unwrap()).trim_end(), "Hello, world!");
    assert_eq!(stdout(encounter().args(cli).arg("Ada Lovelace").output().unwrap()).trim_end(), "Hello, Ada Lovelace!");
    assert_eq!(stdout(encounter().args(cli).output().unwrap()).trim_end(), "Usage: greet NAME");
    let rejected = encounter().args(cli).args(["Ada", "Grace"]).output().unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).lines().any(|line| line == "Expected one name."));

    let test = ["test", "--declaration"];
    let declared = stdout(encounter().args(test).args(["examples/cli", "application.rel"]).output().unwrap());
    assert_eq!(declared.trim_end(), "ok - test.greeting\nok - test.usage");
    let cli_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/cli");
    fs::copy(cli_dir.join("application.rel"), temp.join("application.rel")).unwrap();
    let source = fs::read_to_string(cli_dir.join("greet.encounter")).unwrap()
        .replace("The greeting must preserve spaces inside the name.", "Intentional demo test failure.")
        .replace("eq($greeting, \"Hello, Ada Lovelace!\")", "eq($greeting, \"wrong\")");
    fs::write(temp.join("greet.encounter"), source).unwrap();
    let failure = encounter().args(test).arg(temp).arg("application.rel").output().unwrap();
    assert!(!failure.status.success());
    assert!(String::from_utf8_lossy(&failure.stderr).lines()
        .any(|line| line == "test.greeting: Intentional demo test failure."));

    let pin = stdout(encounter().args(["build", "examples/web", "application.rel"])
        .arg(temp.join("web.rel")).output().unwrap());
    let basic = Base64::encode_string(b"demo:disposable-smoke-credential-only");
    let operator_pin = hex::encode(Sha256::digest(basic.as_bytes()));
    let mut operators = fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
        .open(temp.join("operators.rel")).unwrap();
    writeln!(operators, r#"("operators", "version", "encounter/operators/1")"#).unwrap();
    writeln!(operators, r#"("demo", "role", "demo-editor")"#).unwrap();
    writeln!(operators, r#"("demo", "basicSha256", "{operator_pin}")"#).unwrap();

    let config = temp.join("launch.rel");
    let facts = [
        ("version", "encounter/launch/1"), ("mode", "image"), ("image", "web.rel"), ("sha256", pin.trim_end()),
        ("store", "store"), ("port", "0"), ("operators", "operators.rel"),
    ];
    let launch: String = facts.iter().map(|(field, value)| format!("(\"launch\", {field:?}, {value:?})\n")).collect();
    fs::write(&config, launch).unwrap();
    let mut server = Server(encounter().arg("--config").arg(&config).arg("serve")
        .stdout(Stdio::piped()).spawn().unwrap());
    let mut output = BufReader::new(server.0.stdout.take().unwrap());
    let (ready, address) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let _ = ready.send(line);
    });
    let line = address.recv_timeout(WAIT).expect("example server readiness");
    reader.join().unwrap();
    let address: SocketAddr = line.trim_end().strip_prefix("Encounter http://").expect("loopback address").parse().unwrap();
    assert!(address.ip().is_loopback());

    assert!(request(address, "/", None).starts_with("HTTP/1.1 401 "));
    let page = request(address, "/", Some(&basic));
    assert!(page.starts_with("HTTP/1.1 200 ") && page.contains("<h1>Hello from Encounter</h1>"));
    let styles = request(address, "/styles.css", Some(&basic));
    assert!(styles.starts_with("HTTP/1.1 200 ") && styles.contains("system-ui"));

    // The standalone server should shut down cleanly under a service supervisor.
    assert_eq!(unsafe { libc::kill(server.0.id().try_into().unwrap(), libc::SIGTERM) }, 0);
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(std::time::Instant::now() < deadline, "example server did not stop");
        thread::sleep(Duration::from_millis(20));
    }
}
