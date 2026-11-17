use crate::{
    Result, appdev_host_process::Supervisor, appdev_reload::ReleaseSlot, application::{Application, CheckProfile}, fail, process::Meter, workspace,
};
use base64ct::{Base64, Encoding};
use std::{fs, net::{Ipv4Addr, TcpListener}, path::{Path, PathBuf}, process::Command, sync::Arc};

pub const ASTER_STREAM: &str = "browser.asterStream";
pub(crate) const STANDALONE_CATALOG: &str = "standalone-browser-wasm.rel";
pub(crate) const STANDALONE_DIRECTORY: &str = "standalone-browser-wasm";
pub(crate) const WASM_HOME_BRIDGE: &str = "/_encounter/browser.mjs?wasm=1";
const BROWSER_DECLARATION: &str = "applications/appdev-projects/browser.rel";
pub(crate) const WORK_BROWSER_DECLARATION: &str = "applications/life-board-prototype/hosting/application.rel";

pub struct Release {
    pub workspace: Arc<workspace::Release>,
    pub browser: Arc<Application>,
    pub browser_assets: PathBuf,
}

pub struct BrowserWasm {
    pub catalog_pin: String,
    pub bindings: String,
    pub interaction_binding: String,
    pub mobile: Option<Vec<u8>>,
    pub temple: Option<Vec<u8>>,
    pub temple_assurance: Option<Vec<u8>>,
    pub aster_frame: Option<Vec<u8>>,
    running_compiler: bool,
}

impl BrowserWasm {
    fn load(root: &Path, work: bool) -> Result<Option<Self>> {
        const CATALOG: &str = "browser-wasm.rel";
        const RECEIPT: &str = "package-receipt.rel";
        let package = match fs::symlink_metadata(root.join(RECEIPT)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            other => {
                other?;
                let bytes = crate::browser_release::artifact(root, RECEIPT, 1_000_000)?;
                Some(crate::rel::Facts::parse(std::str::from_utf8(&bytes)?)?)
            }
        };
        match fs::symlink_metadata(root.join(CATALOG)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if root.join("browser-wasm").exists() { return Err(fail("browser Wasm assets require a release catalog")); }
                if package.as_ref().is_some_and(|receipt| !receipt.values("artifact", CATALOG).is_empty()) {
                    return Err(fail("AppDev package receipt pins a missing browser Wasm catalog"));
                }
                return Ok(None);
            }
            other => { other?; }
        }
        let catalog = crate::browser_release::artifact(root, CATALOG, 4096)?;
        let catalog_pin = crate::rel::hash(&catalog);
        let package = package.ok_or_else(|| fail("AppDev browser Wasm requires a package receipt"))?;
        if package.one("package", "contract")? != "encounter/gated-release/1"
            || package.values("artifact", CATALOG) != [catalog_pin.as_str()] {
            return Err(fail("AppDev browser Wasm catalog differs from its package receipt"));
        }
        let facts = crate::rel::Facts::parse(std::str::from_utf8(&catalog)?)?;
        let (count, workspace_modules, has_aster_frame) = match (work, facts.one("wasm", "contract")?) {
            (true, "encounter/appdev-work-browser-wasm/1") => (2, false, false),
            (false, "encounter/appdev-browser-wasm/1") => (4, false, false),
            (false, "encounter/appdev-browser-wasm/2") => (6, true, false),
            (false, "encounter/appdev-browser-wasm/3") => (7, true, true),
            _ => return Err(fail("invalid AppDev browser Wasm catalog")),
        };
        if facts.0.len() != count {
            return Err(fail("invalid AppDev browser Wasm catalog"));
        }
        let runtime_pin = crate::rel::hash(crate::browser_release::artifact(root, "encounter", 64_000_000)?);
        if package.values("package", "runtimeSha256") != [runtime_pin.as_str()]
            || package.values("artifact", "encounter") != [runtime_pin.as_str()] {
            return Err(fail("AppDev browser Wasm runtime differs from its package receipt"));
        }
        // A release driver can check packages built by a different version. The
        // browser host verifies the exact source closure when it loads its own package.
        let running_compiler = runtime_pin == crate::rel::hash(fs::read("/proc/self/exe")?);
        if !work && running_compiler && !has_aster_frame {
            return Err(fail("current Home runtime requires a complete browser Wasm catalog"));
        }
        let read_module = |name: &str, sources: &[(&str, &str); 2]| {
            let pin = facts.one(name, "receiptSha256")?;
            crate::browser_release::wasm(&root.join("browser-wasm").join(name), pin, &runtime_pin,
                sources, running_compiler).map_err(|error| fail(format!("AppDev browser Wasm {name}: {error}")))
        };
        let mut bindings = String::new();
        let mut interaction_binding = String::new();
        let mut temple_assurance = None;
        for (name, binding, sources) in [
            ("interaction", "encounterInteractionWasm", [
                ("interaction.rel", include_str!("../browser/interaction.rel")),
                ("interaction.encounter", include_str!("../browser/interaction.encounter")),
            ]),
            ("countdown", "encounterCountdownWasm", [
                ("countdown.rel", include_str!("../browser/countdown.rel")),
                ("countdown.encounter", include_str!("../browser/countdown.encounter")),
            ]),
            ("assurance", "encounterAssuranceWasm", [
                ("assurance.rel", include_str!("../browser/assurance.rel")),
                ("assurance.encounter", include_str!("../browser/assurance.encounter")),
            ]),
        ] {
            if work && name != "interaction" { continue; }
            let module = read_module(name, &sources)?;
            let script_binding = format!("const {binding} = '{}';\n", Base64::encode_string(&module));
            if name == "interaction" { interaction_binding.clone_from(&script_binding); }
            bindings.push_str(&script_binding);
            if workspace_modules && name == "assurance" { temple_assurance = Some(module); }
        }
        let (mobile, temple) = if workspace_modules {
            (Some(read_module("mobile", &[
                ("mobile.rel", include_str!("../browser/mobile.rel")),
                ("mobile.encounter", include_str!("../browser/mobile.encounter")),
            ])?), Some(read_module("temple", &[
                ("temple.rel", include_str!("../browser/temple.rel")),
                ("temple.encounter", include_str!("../browser/temple.encounter")),
            ])?))
        } else { (None, None) };
        let aster_frame = has_aster_frame.then(|| read_module("aster-frame", &[
            ("aster-frame.rel", include_str!("../browser/aster-frame.rel")),
            ("aster-frame.encounter", include_str!("../browser/aster-frame.encounter")),
        ])).transpose()?;
        Ok(Some(Self { catalog_pin, bindings, interaction_binding, mobile, temple, temple_assurance, aster_frame, running_compiler }))
    }

    pub(crate) fn load_home(root: &Path) -> Result<Option<Self>> {
        Self::load(root, false)
    }

    pub(crate) fn require_bundled_runtime(&self) -> Result<()> {
        if !self.running_compiler {
            return Err(fail("AppDev browser Wasm release requires its bundled runtime"));
        }
        Ok(())
    }

    pub(crate) fn load_work(root: &Path) -> Result<Option<Self>> {
        let wasm = Self::load(root, true)?;
        if wasm.as_ref().is_some_and(|module| !module.running_compiler) {
            return Err(fail("AppDev Work browser Wasm release requires its bundled runtime"));
        }
        Ok(wasm)
    }
}

impl Release {
    fn load(root: &Path, require_assurance: bool) -> Result<Self> {
        if require_assurance { crate::appdev_assurance::require(root)?; }
        let workspace = Arc::new(workspace::Release::load(root, &root.join("index.html")).map_err(|error| fail(format!("AppDev workspace load: {error}")))?);
        workspace.validate().map_err(|error| fail(format!("AppDev workspace validation: {error}")))?;
        let browser = Arc::new(Application::load(&root.join("browser-programme"), BROWSER_DECLARATION).map_err(|error| fail(format!("AppDev browser load: {error}")))?);
        if !browser.has_entry("browser.boot") || browser.has_entry("device.check")
        {
            return Err(fail("expected an AppDev browser declaration"));
        }
        browser.admit_native_browser(&mut Meter::new(20_000_000), CheckProfile::Browser).map_err(|error| fail(format!("AppDev browser admission: {error}")))?;
        let browser_assets = root.join("browser-assets");
        if !browser_assets.join("index.html").is_file() {
            return Err(fail("expected AppDev browser assets"));
        }
        Ok(Self { workspace, browser, browser_assets })
    }

    fn uses_aster_stream(&self) -> bool {
        self.browser.declared_grants().contains(ASTER_STREAM)
    }

    fn load_for_serving(root: &Path, require_assurance: bool) -> Result<Self> {
        let release = Self::load(root, require_assurance)?;
        if let Some(wasm) = &release.workspace.browser_wasm { wasm.require_bundled_runtime()?; }
        release.workspace.validate_workspace_policy()?;
        Ok(release)
    }
}

pub struct Releases(ReleaseSlot<Release>);

impl Releases {
    pub fn open(link: &Path, require_assurance: bool) -> Result<Self> {
        if !link.is_absolute() {
            return Err(fail("expected an absolute AppDev release link"));
        }
        let pointer = fs::symlink_metadata(link)?.file_type().is_symlink().then(|| link.to_owned());
        let load = move |root: &Path, current: Option<&Release>| {
            let release = Release::load_for_serving(root, require_assurance)?;
            if current.is_some_and(|active| release.uses_aster_stream() != active.uses_aster_stream()
                || release.browser.state_profile != active.browser.state_profile
                || !release.workspace.compatible(&active.workspace)) {
                return Err(fail("AppDev state profile or browser streaming permission changed"));
            }
            Ok(release)
        };
        let initial = || load(&link.canonicalize()?, None);
        Ok(Self(ReleaseSlot::start("AppDev release", pointer, initial, load)?))
    }

    pub fn current(&self) -> Arc<Release> {
        self.0.current()
    }
}

pub fn check(root: &Path) -> Result<()> {
    // Activation checks both packages. Each workspace host validates its own policy ABI at startup.
    let root = root.canonicalize()?;
    Release::load(&root, true)?;
    check_work_catalog(&root)?;
    check_standalone_catalog(&root)
}

pub(crate) fn check_rebuild_input(root: &Path) -> Result<()> {
    let release = Release::load(root, false)?;
    release.workspace.validate_workspace_policy()?;
    check_work_catalog(root)?;
    check_standalone_catalog(root)
}

pub(crate) fn check_candidate(root: &Path) -> Result<()> {
    Release::load_for_serving(root, false)?;
    BrowserWasm::load_work(&root.join("work"))?;
    check_standalone_catalog(root)
}

fn check_standalone_catalog(root: &Path) -> Result<()> {
    use crate::{browser_release::{artifact, wasm}, process::browser_wasm, rel::{Facts, hash}};
    let receipt = "package-receipt.rel";
    let package = match fs::symlink_metadata(root.join(receipt)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        other => {
            other?;
            Some(Facts::parse(std::str::from_utf8(&artifact(root, receipt, 1_000_000)?)?)?)
        }
    };
    match fs::symlink_metadata(root.join(STANDALONE_CATALOG)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if package.as_ref().is_some_and(|facts| !facts.values("artifact", STANDALONE_CATALOG).is_empty())
                || root.join(STANDALONE_DIRECTORY).symlink_metadata().is_ok() {
                return Err(fail("Standalone browser Wasm assets require their pinned catalog"));
            }
            return Ok(());
        }
        other => { other?; }
    }
    let package = package.ok_or_else(|| fail("Standalone browser Wasm catalog requires a package receipt"))?;
    let pins = package.values("artifact", STANDALONE_CATALOG);
    let catalog = artifact(root, STANDALONE_CATALOG, 4096)?;
    if pins != [hash(&catalog).as_str()] {
        return Err(fail("Standalone browser Wasm catalog differs from its package receipt"));
    }
    let catalog = Facts::parse(std::str::from_utf8(&catalog)?)?;
    if catalog.one("wasm", "contract")? != browser_wasm::STANDALONE_CATALOG_CONTRACT
        || catalog.0.len() != browser_wasm::STANDALONE_MODULES.len() + 1 {
        return Err(fail("Invalid standalone browser Wasm catalog"));
    }
    let runtime = hash(artifact(root, "encounter", 64_000_000)?);
    if package.values("package", "runtimeSha256") != [runtime.as_str()] {
        return Err(fail("Standalone browser Wasm runtime differs from its package receipt"));
    }
    let current = runtime == hash(fs::read("/proc/self/exe")?);
    for (name, sources) in browser_wasm::STANDALONE_MODULES {
        let directory = root.join(STANDALONE_DIRECTORY).join(name);
        wasm(&directory, catalog.one(name, "receiptSha256")?, &runtime, &sources, current)?;
    }
    Ok(())
}

fn check_work_catalog(root: &Path) -> Result<()> {
    let work = root.join("work");
    if work.is_dir() { BrowserWasm::load(&work, true)?; }
    Ok(())
}

pub(crate) fn check_staged_receipt(root: &Path, receipt: &Path) -> Result<()> {
    crate::appdev_assurance::require_receipt(root, receipt)?;
    Release::load(root, false)?;
    check_work_catalog(root)?;
    check_standalone_catalog(root)?;

    // The bundled workspace host validates its Home policy before opening its listener.
    let scratch = receipt.parent().ok_or_else(|| fail("Expected a staged receipt directory"))?;
    let state = scratch.join("state");
    let credentials = scratch.join("credentials");
    fs::create_dir(&state)?;
    fs::create_dir(&credentials)?;
    fs::write(credentials.join("identity-management-auth"), "staged-policy-check\n")?;
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port();
    let origin = format!("http://127.0.0.1:{port}");
    let runtime = root.join("encounter");
    crate::package::require_native_runtime(&runtime)?;
    let mut command = Command::new(runtime);
    command.args(["workspace-host"]).arg(root).env_clear()
        .env("APPDEV_PORT", port.to_string())
        .env("APPDEV_ORIGIN", &origin)
        .env("APPDEV_IDENTITY_GATEWAY", &origin)
        .env("APPDEV_NETWORK_ORIGIN", &origin)
        .env("APPDEV_NETWORK_STATE", state.join("network.json"))
        .env("STATE_DIRECTORY", state)
        .env("CREDENTIALS_DIRECTORY", credentials);
    let mut supervisor = Supervisor::children();
    supervisor.start("Bundled AppDev Home policy check", &mut command)?;
    supervisor.listen(port)?;
    supervisor.check()
}
