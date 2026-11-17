use crate::{Result, appdev_host_process::{Supervisor, handle_hangup}, command_sources::Sources, fail,
    hosted_worker_image::Podman, hosted_worker_workspace, http_client, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, env, ffi::CString, fs::File, io::{self, Read, Seek, Write},
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::{FileTypeExt, MetadataExt}},
    path::{Path, PathBuf}, process::{Command, Stdio}, time::{Duration, Instant}};
use zeroize::Zeroizing;

const REQUEST_LIMIT: usize = 16 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(15);
const WORKER_TIMEOUT: Duration = Duration::from_secs(120);
const ENVELOPE_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerLaunch {
    socket: String,
    image: String,
    source_root: PathBuf,
    workspace_root: PathBuf,
    target: WorkerTarget,
    assignment_public_jwk: WorkerKey,
    worker_id: String,
    project_file: String,
    issuer: String,
    audience: String,
    memory_megabytes: u64,
    cpu_limit: u64,
    pid_limit: u64,
    container_user: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerTarget {
    tenant_id: String,
    app_id: String,
    project_id: String,
    workspace_id: String,
    region: String,
    storage_namespace: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerKey { kty: String, crv: String, x: String }

#[derive(Deserialize)]
struct LaunchPlan { socket: String, arguments: Vec<String> }

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("hosted_worker_container.encounter").to_owned(),
        include_str!("hosted_worker_image.encounter").to_owned(), include_str!("hosted_workspace_storage.encounter").to_owned()],
        &["workerContainer.authority", "workerContainer.socket", "workerContainer.ready", "workerContainer.launch", "workerImage.digest"],
        &BTreeSet::from(["kernel.invoke", "text.matches", "number.isNatural", "number.calculate", "json.stringify", "text.base64url", "value.type"]),
        &mut Meter::new(200_000))
}

fn decision(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(200_000))
}

fn remote_podman(podman: &Podman, socket: &str) -> Command {
    let mut command = podman.command();
    command.arg("--remote").arg("--url").arg(socket);
    command
}

pub(crate) fn readiness(image: &str, socket: &str) -> Result<()> {
    let _signals = Supervisor::new();
    println!("{}", probe_readiness(image, Some(socket), Instant::now() + TOOL_TIMEOUT)?);
    Ok(())
}

pub(super) fn probe_readiness(image: &str, socket: Option<&str>, deadline: Instant) -> Result<Value> {
    let policy = policy()?;
    decision(&policy, "workerImage.digest", json!(image))?;
    let authority = match socket {
        Some(socket) => decision(&policy, "workerContainer.authority", json!(socket))?,
        None => decision(&policy, "workerContainer.socket", Value::Null)?,
    };
    let socket = authority.as_str().ok_or_else(|| fail("Expected a Podman authority socket"))?;
    inspect_image(&policy, image, socket, deadline)
}

fn inspect_image(policy: &Programme, image: &str, socket: &str, deadline: Instant) -> Result<Value> {
    let path = Path::new(socket.strip_prefix("unix://").ok_or_else(|| fail("Expected a Unix Podman socket"))?);
    let directory = path.parent().and_then(|parent| parent.strip_prefix("/").ok()).and_then(Path::to_str)
        .ok_or_else(|| fail("Expected an absolute Podman socket directory"))?;
    let name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| fail("Expected a Podman socket name"))?;
    let sources = Sources::open_physical(Path::new("/"))?.open_directory_relative(directory)?;
    let parent = sources.root()?.metadata()?;
    let socket = sources.observe_relative(name)?;
    let metadata = socket.metadata()?;
    if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.uid() != parent.uid() || metadata.mode() & 0o007 != 0 || parent.mode() & 0o022 != 0 {
        return Err(fail("Rootless Podman requires its protected service-owned socket and directory"));
    }
    let socket_path = CString::new(format!("/proc/self/fd/{}", socket.as_raw_fd()))?;
    let timeout = deadline.saturating_duration_since(Instant::now()).min(TOOL_TIMEOUT);
    let response = http_client::send_unix(http_client::Request {
        url: &format!("http://localhost/libpod/images/{image}/json"), method: "GET",
        headers: &[("Accept", "application/json")], body: None, timeout, connect_timeout: timeout,
        limit: 256 * 1024, resolve: None, trust_anchor: None, restoring: false,
    }, &socket_path)?;
    if response.status != 200 { return Err(fail(format!("Rootless Podman image inspection returned HTTP {}", response.status))); }
    #[derive(Deserialize)]
    struct ImageIdentity { #[serde(rename = "Id")] id: String }
    let observed = serde_json::from_slice::<ImageIdentity>(&response.body)?.id;
    let observed = if observed.starts_with("sha256:") { observed.to_owned() } else { format!("sha256:{observed}") };
    decision(policy, "workerContainer.ready", json!({"image": image, "observed": observed}))
}

fn launch_request(request: &str) -> Result<(WorkerLaunch, Value)> {
    if request.len() > REQUEST_LIMIT { return Err(fail("Container worker launch request exceeds its input limit")); }
    let request: WorkerLaunch = serde_json::from_str(request)?;
    let plan = decision(&policy()?, "workerContainer.launch", serde_json::to_value(&request)?)?;
    Ok((request, plan))
}

pub(crate) fn plan(request: &str) -> Result<()> {
    println!("{}", launch_request(request)?.1);
    Ok(())
}

pub(crate) fn dispatch_policy(operation: &str) -> Result<()> {
    let entry = match operation {
        "limits" => "workerContainer.dispatchLimits",
        "failure" => "workerContainer.failure",
        _ => return Err(fail("Unsupported container worker dispatch decision")),
    };
    let input = crate::platform_import_closure::read_bounded_observation(64 * 1024)?;
    let policy = Programme::admit(&[include_str!("hosted_worker_container.encounter").to_owned()], entry,
        &BTreeSet::from(["kernel.invoke", "number.isNatural", "number.calculate", "text.replace",
            "text.split", "text.trim", "text.join", "text.slice", "text.matches"]), &mut Meter::new(100_000))?;
    println!("{}", policy.run(entry, input, &mut Meter::new(2_000_000))?);
    Ok(())
}

fn validate_roots(source: &Path, workspace: &Path) -> Result<()> {
    let runtime = env::current_exe()?;
    if runtime.parent() != Some(source) || source.canonicalize()? != source {
        return Err(fail("Container worker source must be the release that owns the Encounter executable."));
    }
    if workspace.canonicalize()? != workspace || workspace.starts_with(source) || source.starts_with(workspace) {
        return Err(fail("Container worker requires a physical workspace disjoint from its release."));
    }
    Ok(())
}

pub(crate) fn run(request: &str) -> Result<()> {
    let supervisor = Supervisor::new();
    handle_hangup();
    let (request, plan) = launch_request(request)?;
    let mut plan: LaunchPlan = serde_json::from_value(plan)?;
    validate_roots(&request.source_root, &request.workspace_root)?;
    append_application(&request, &mut plan)?;
    let input = admit_input(&request)?;
    execute_worker(supervisor, &request.source_root, plan, Stdio::from(input))
}

fn admit_input(request: &WorkerLaunch) -> Result<File> {
    let mut bytes = Zeroizing::new(Vec::new());
    let stdin = io::stdin().lock();
    crate::appdev_host_process::nonblocking(stdin.as_raw_fd())?;
    let mut input = stdin.take(ENVELOPE_LIMIT + 1);
    let mut buffer = Zeroizing::new([0_u8; 8192]);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        crate::http::check_interruption(false)?;
        if Instant::now() >= deadline { return Err(fail("Container worker input timed out.")); }
        let count = match input.read(&mut *buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if count == 0 { break; }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() as u64 > ENVELOPE_LIMIT { return Err(fail("Container worker input exceeds its byte bound.")); }
    crate::hosted_worker_assignment::admit_container(&bytes, serde_json::to_value(request)?)?;
    crate::http::check_interruption(false)?;
    seal_input(&bytes)
}

fn seal_input(bytes: &[u8]) -> Result<File> {
    let fd = unsafe { libc::memfd_create(c"sourcery-worker-input".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 { return Err(io::Error::last_os_error().into()); }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    file.rewind()?;
    Ok(file)
}

#[cfg(test)]
#[test]
fn sealed_worker_input_preserves_exact_bytes_at_the_start() -> Result<()> {
    let input = b" {\"envelope\":{\"requestId\":\"fixture\"}}\n";
    let mut sealed = seal_input(input)?;
    let mut actual = Vec::new();
    sealed.read_to_end(&mut actual)?;
    assert_eq!(actual, input);
    sealed.rewind()?;
    assert_eq!(sealed.write_all(b"x").unwrap_err().raw_os_error(), Some(libc::EPERM));
    assert_eq!(sealed.set_len(0).unwrap_err().raw_os_error(), Some(libc::EPERM));
    assert_eq!(sealed.set_len(input.len() as u64 + 1).unwrap_err().raw_os_error(), Some(libc::EPERM));
    Ok(())
}

fn append_application(request: &WorkerLaunch, plan: &mut LaunchPlan) -> Result<()> {
    let target = serde_json::to_value(&request.target)?;
    let storage = request.workspace_root.ancestors().nth(4)
        .ok_or_else(|| fail("Container worker requires a complete workspace allocation path"))?;
    let allocation = crate::hosted_workspace_storage::resolve(storage, target.clone())?;
    if allocation["root"].as_str().map(Path::new) != Some(request.workspace_root.as_path()) {
        return Err(fail("Container worker workspace does not match its retained allocation"));
    }
    let (admitted, project) = hosted_worker_workspace::admit(&request.workspace_root, target)?;
    if admitted["projectFile"] != request.project_file || admitted["workerId"] != request.worker_id {
        return Err(fail("Container worker project or identity changed before launch."));
    }
    let application = hosted_worker_workspace::application(&project)
        .map_err(|error| fail(format!("ProjectValidationError: {error}")))?;
    plan.arguments.push(Base64UrlUnpadded::encode_string(&serde_json::to_vec(&application)?));
    Ok(())
}

fn execute_worker(mut supervisor: Supervisor, source_root: &Path, plan: LaunchPlan, input: Stdio) -> Result<()> {
    let mut random = [0; 16];
    getrandom::getrandom(&mut random).map_err(|error| fail(error.to_string()))?;
    let name = format!("sourcery-authoring-{}", hex::encode(random));
    let [operation, arguments @ ..] = plan.arguments.as_slice() else { return Err(fail("Missing worker launch operation")); };
    let podman = Podman::open()?;
    let result = supervisor.run_until("Isolated authoring worker",
        remote_podman(&podman, &plan.socket).arg(operation).arg("--name").arg(&name).args(arguments)
            .current_dir(source_root).stdin(input),
        Some(WORKER_TIMEOUT));
    drop(supervisor);
    if let Err(error) = result {
        let cleanup = Supervisor::release_recovery().capture("Remove isolated authoring worker",
            remote_podman(&podman, &plan.socket).args(["rm", "--ignore", "--force", "--time", "0", &name]), TOOL_TIMEOUT, 1024);
        if let Err(cleanup) = cleanup { return Err(fail(format!("{error}; worker cleanup failed: {cleanup}"))); }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn readiness_requires_an_exact_inspected_image() -> Result<()> {
    let policy = policy()?;
    let image = format!("sha256:{}", "a".repeat(64));
    let result = decision(&policy, "workerContainer.ready", json!({"image": image, "observed": image}))?;
    assert_eq!(result, json!({"status":"ready","image":image,"pullPolicy":"never","localIdentityVerified":true}));
    assert!(decision(&policy, "workerContainer.ready", json!({"image":image,"observed":format!("sha256:{}", "b".repeat(64))})).is_err());
    Ok(())
}

#[cfg(test)]
#[test]
#[ignore = "requires an isolated Podman service and a prepared authoring worker fixture"]
fn worker_launch_over_disposable_podman_socket() -> Result<()> {
    let request = env::var("SOURCERY_WORKER_FIXTURE_REQUEST")?;
    let socket = env::var("SOURCERY_WORKER_FIXTURE_SOCKET")?;
    let (request, plan) = launch_request(&request)?;
    let mut plan: LaunchPlan = serde_json::from_value(plan)?;
    append_application(&request, &mut plan)?;
    // The production entry points obtain the socket exclusively from Encounter's authority rule.
    plan.socket = socket;
    let observed = inspect_image(&policy()?, &request.image, &plan.socket, Instant::now() + TOOL_TIMEOUT)?;
    assert_eq!(observed["localIdentityVerified"], true);
    let result = execute_worker(Supervisor::new(), &request.source_root, plan, Stdio::from(admit_input(&request)?));
    if env::var_os("SOURCERY_WORKER_FIXTURE_INTERRUPT").is_some() {
        assert!(result.is_err());
        assert_eq!(crate::appdev_host_process::interruption(), Some(143));
        Ok(())
    } else {
        result
    }
}
