use crate::{Result, appdev_assurance, appdev_host_process::{Supervisor, interruption}, appdev_lifecycle,
    appdev_workflow::{coordinated_switch, immutable}, command::Evaluator, fail, gateway, http_client, workspace, workspace_sign_in};
use serde_json::{Value, json};
use std::{cell::RefCell, fs, path::{Path, PathBuf}, process::Command, thread, time::{Duration, Instant}};

const POLICY_ROOT: &str = "/etc/sourcery/appdev-module-policy";
const ACK_TIMEOUT: Duration = Duration::from_secs(8);

enum Module {
    Registry,
    WorkspaceSignIn,
    Game,
    Store,
    Work,
    Shop,
    NorthRiver,
}

impl Module {
    fn from_target(target: &str) -> Result<Self> {
        match target {
            "registry-approval" => Ok(Self::Registry),
            "workspace-sign-in" => Ok(Self::WorkspaceSignIn),
            "game-policy" => Ok(Self::Game),
            "store-policy" => Ok(Self::Store),
            "work-policy" => Ok(Self::Work),
            "shop-policy" => Ok(Self::Shop),
            "north-river-policy" => Ok(Self::NorthRiver),
            _ => Err(fail("module has no verified AppDev production activation binding")),
        }
    }

    fn binding(&self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Self::Registry => ("/srv/encounter-apps/registry-approval-presentations", "appdev-vm-manager.service",
                "APPDEV_REGISTRY_APPROVAL_RELEASE", "Registry approval presentation"),
            Self::WorkspaceSignIn => ("/srv/encounter-apps/appdev-workspace-sign-in", "appdev-workspace-sign-in.service",
                "APPDEV_WORKSPACE_SIGN_IN_RELEASE", "Workspace sign-in presentation"),
            Self::Game => ("/srv/encounter-apps/appdev-game-policy", "appdev-game-gateway.service",
                "APPDEV_GATEWAY_POLICY_RELEASE", "AppDev gateway policy"),
            Self::Store => ("/srv/encounter-apps/appdev-store-policy", "appdev-store-gateway.service",
                "APPDEV_GATEWAY_POLICY_RELEASE", "AppDev gateway policy"),
            Self::Work => ("/srv/encounter-apps/appdev-work-policy", "appdev-life-board-gateway.service",
                "APPDEV_GATEWAY_POLICY_RELEASE", "AppDev gateway policy"),
            Self::Shop => ("/srv/encounter-apps/appdev-shop-policy", "appdev-shop-gateway.service",
                "APPDEV_GATEWAY_POLICY_RELEASE", "AppDev gateway policy"),
            Self::NorthRiver => ("/srv/encounter-apps/appdev-north-river-policy", "appdev-north-river-gateway.service",
                "APPDEV_GATEWAY_POLICY_RELEASE", "AppDev gateway policy"),
        }
    }

    fn process(&self) -> Result<u32> {
        let mut command = Command::new("/usr/bin/systemctl");
        if matches!(self, Self::Game | Self::Store) {
            command.args(["--machine=ubuntu@.host", "--user"]);
        }
        command.args(["show", "-p", "MainPID", "--value", self.binding().1]);
        let pid: u32 = output(&mut command)?.trim().parse()?;
        if pid == 0 { return Err(fail("module host is not active")); }
        Ok(pid)
    }

    fn check_binding(&self, pid: u32, active: &Path) -> Result<()> {
        let env = fs::read(format!("/proc/{pid}/environ"))?;
        let expected = format!("{}={}", self.binding().2, active.display());
        if !env.split(|byte| *byte == 0).any(|field| field == expected.as_bytes()) {
            return Err(fail("live host is not following the declared production module pointer"));
        }
        Ok(())
    }

    fn validate(&self, baseline: &Path, candidate: &Path) -> Result<()> {
        match self {
            Self::Registry => {
                workspace::verify_registry_presentation(baseline)?;
                workspace::verify_registry_presentation(candidate)
            }
            Self::WorkspaceSignIn => {
                workspace_sign_in::verify_generation(baseline)?;
                workspace_sign_in::verify_generation(candidate)
            }
            Self::Game => gateway::verify_module_update(baseline, candidate, "/game", "game-hub/https.rel"),
            Self::Store => gateway::verify_module_update(baseline, candidate, "/store", "platform-store/https.rel"),
            Self::Work => gateway::verify_module_update(baseline, candidate, "/life-board", "gateway.rel"),
            Self::Shop => gateway::verify_module_update(baseline, candidate, "/shop", "sourcery-shop/gateway.rel"),
            Self::NorthRiver => gateway::verify_module_update(baseline, candidate, "/encounter-pilot",
                "encounter-platform/applications/front-gate/pilot.rel"),
        }
    }

    fn journal(&self, pid: u32, cursor: bool) -> Result<String> {
        let unit_key = if matches!(self, Self::Game | Self::Store) { "_SYSTEMD_USER_UNIT" } else { "_SYSTEMD_UNIT" };
        let mut command = Command::new("/usr/bin/journalctl");
        command.args(["-b", "-n", "1", "--no-pager", "-o", "cat"]);
        if cursor { command.arg("--show-cursor"); }
        command.arg(format!("_PID={pid}")).arg(format!("{unit_key}={}", self.binding().1))
            .arg("--grep").arg(format!("^{} activated: ", self.binding().3));
        output(&mut command)
    }

    fn acknowledge(&self, pid: u32, target: &Path, initial: &str, restoring: bool) -> Result<()> {
        let deadline = Instant::now() + ACK_TIMEOUT;
        let expected = format!("{} activated: {}", self.binding().3, target.display());
        loop {
            if self.process()? != pid { return Err(fail("module host was replaced during activation")); }
            let observed = self.journal(pid, true)?;
            if observed.lines().any(|line| line == expected) && (restoring || observed != initial) {
                return self.ready(restoring);
            }
            if Instant::now() >= deadline {
                return Err(fail("module host did not acknowledge the selected generation"));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn ready(&self, restoring: bool) -> Result<()> {
        let url = match self {
            Self::Registry => "https://appdev.sourcerytech.com.au/workspace/vm-manager?vm=sourcery-registry-demo&view=display",
            Self::WorkspaceSignIn => "https://appdev.sourcerytech.com.au/workspace/platform",
            Self::Game => "https://appdev.sourcerytech.com.au/game/design-references/",
            Self::Store => "https://appdev.sourcerytech.com.au/store/",
            Self::Work => "https://appdev.sourcerytech.com.au/workspace/work",
            Self::Shop => "https://appdev.sourcerytech.com.au/shop/",
            Self::NorthRiver => "https://appdev.sourcerytech.com.au/encounter-pilot/",
        };
        let response = http_client::send(http_client::Request {
            url, method: "GET", headers: &[("Accept", "text/html"), ("Sec-Fetch-Dest", "document")],
            body: None, timeout: Duration::from_secs(5), connect_timeout: Duration::from_secs(3),
            limit: 128_000, resolve: None, trust_anchor: None, restoring,
        })?;
        if response.status != 401 || !std::str::from_utf8(&response.body)?.contains("Sign in to Workspace") {
            return Err(fail("module's public Workspace sign-in gate did not pass readiness"));
        }
        Ok(())
    }
}

fn output(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    if !result.status.success() { return Err(fail(format!("module observation failed ({})", result.status))); }
    Ok(String::from_utf8(result.stdout)?)
}

fn verify_direct_generation(root: &Path, target: &Path) -> Result<()> {
    if target.parent() != Some(root) || target.canonicalize()? != target || !target.is_dir() {
        return Err(fail("expected an installed direct module generation"));
    }
    immutable(target)
}

pub(crate) fn run(mode: &str, id: &str, previous: &Path, candidate: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    let module = Module::from_target(id)?;
    let policy = Path::new(POLICY_ROOT);
    immutable(policy)?;
    let root = Path::new(module.binding().0);
    // The service and publisher share the fixed, root-owned /srv installation tree.
    for parent in root.ancestors().take_while(|parent| parent.starts_with("/srv")) {
        let metadata = fs::symlink_metadata(parent)?;
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(fail("module generations require immutable parents"));
        }
    }
    let active = root.join("active");
    let inventory = policy.join(format!("{id}.inventory.rel"));
    let make_report = || -> Result<Value> {
        verify_direct_generation(root, previous)?;
        verify_direct_generation(root, candidate)?;
        let system = appdev_assurance::system_package(Path::new("/var/www/appdev-projects/workspace"));
        let mut report = appdev_lifecycle::report_with_system_kind(policy, &inventory, previous, candidate, system)?;
        let installed = Path::new("/etc/sourcery/appdev-system");
        immutable(installed)?;
        let activation = Evaluator::load(installed, "activation.rel")?;
        report["installedActivationActions"] = activation.run("release.activation", json!({"system":system}))?;
        Ok(report)
    };
    if mode == "plan" {
        let mut report = make_report()?;
        match module.validate(previous, candidate) {
            Ok(()) => report["moduleValidation"] = json!("compatible"),
            Err(error) => {
                report["moduleValidation"] = json!(error.to_string());
                report["requiresReview"] = json!(true);
            }
        }
        println!("{report}");
        return Ok(());
    }
    if mode != "publish" || previous == candidate || unsafe { libc::geteuid() } != 0 {
        return Err(fail("expected a distinct generation and a privileged module publication"));
    }
    let observation = RefCell::<Option<(u32,String)>>::new(None);
    let lock: PathBuf = root.join(".activation.lock");
    coordinated_switch(&active, &lock, candidate, previous, || interruption().is_some(), || {
        let report = make_report()?;
        let evaluator = Evaluator::load(policy, "lifecycle.rel")?;
        if evaluator.run("release.modulePromotion", json!({"report":report,"component":id}))? != true {
            return Err(fail("the AppDev lifecycle policy did not admit an isolated reload"));
        }
        module.validate(previous, candidate)?;
        let pid = module.process()?;
        module.check_binding(pid, &active)?;
        module.ready(false)?;
        let observed = module.journal(pid, true)?;
        let expected = format!("{} activated: {}", module.binding().3, previous.display());
        if !observed.lines().any(|line| line == expected) {
            return Err(fail("running module generation differs from the publication baseline"));
        }
        println!("{report}");
        *observation.borrow_mut() = Some((pid, observed));
        Ok(())
    }, |target, restoring| {
        let observation = observation.borrow();
        let (pid, cursor) = observation.as_ref().ok_or_else(|| fail("missing initial module observation"))?;
        module.acknowledge(*pid, target, cursor, restoring)
    })?;
    println!("Reloaded {id} on {}", module.binding().1);
    Ok(())
}
