// Versioned coordinates shared by the CLI and a service supervisor.
use crate::{Result, browser_release::{ClientWasmPin, LiveClientPins}, codex_stream::CodexStream, fail, live::Model, rel::Facts};
use std::path::{Path, PathBuf};

pub struct Launch {
    pub image: PathBuf,
    pub pin: String,
    pub store: PathBuf,
    pub port: u16,
    pub attachment_root: Option<PathBuf>,
    pub operators: Option<PathBuf>,
    pub live_model: Model,
    pub gateway_identity: bool,
    pub(crate) clients: LiveClientPins,
}

impl Launch {
    pub fn read(file: &Path) -> Result<Self> {
        let file = file.canonicalize()?;
        let directory = file.parent().ok_or_else(|| fail("missing launch configuration directory"))?;
        let facts = Facts::read(&file)?;
        let field = |property| facts.one("launch", property);
        if field("version")? != "encounter/launch/1" {
            return Err(fail("unsupported launch configuration version"));
        }
        if field("mode")? != "image" {
            return Err(fail("unsupported launch configuration mode"));
        }
        let fields = ["version", "mode", "port", "image", "sha256", "store", "attachmentRoot", "operators", "liveModel", "codexBinary", "codexWorkspace", "gatewayIdentity"];
        for [subject, property, _] in &facts.0 {
            if matches!(subject.as_str(), "live-events" | "canvas")
                && matches!(property.as_str(), "directory" | "receiptSha256") { continue; }
            if subject != "launch" || !fields.contains(&property.as_str())
            {
                return Err(fail(format!("unknown launch field {subject}.{property}")));
            }
        }
        let path = |property| -> Result<PathBuf> {
            let value = field(property)?;
            if value.is_empty() { return Err(fail(format!("empty launch path {property}"))); }
            Ok(directory.join(value))
        };
        let optional_path = |name| -> Result<Option<PathBuf>> {
            match facts.values("launch", name).as_slice() {
                [] => Ok(None),
                _ => path(name).map(Some),
            }
        };
        let live_model = match facts.values("launch", "liveModel").as_slice() {
            [] => Model::Off,
            [name] if *name == "ollama-loopback" => Model::Ollama,
            [name] if *name == "codex-app-server" => {
                let binary = path("codexBinary")?.canonicalize()?;
                let workspace = path("codexWorkspace")?.canonicalize()?;
                if !binary.is_file() || !workspace.is_dir() {
                    return Err(fail("invalid Codex host coordinates"));
                }
                Model::Codex(CodexStream { binary, workspace })
            }
            _ => return Err(fail("unsupported live model transport")),
        };
        if !matches!(live_model, Model::Codex(_)) && ["codexBinary", "codexWorkspace"].iter()
            .any(|field| !facts.values("launch", field).is_empty()) {
            return Err(fail("Codex coordinates require the Codex transport"));
        }
        Ok(Self {
            image: path("image")?,
            pin: field("sha256")?.to_owned(),
            store: path("store")?,
            port: field("port")?.parse()?,
            attachment_root: optional_path("attachmentRoot")?,
            operators: optional_path("operators")?,
            live_model,
            clients: LiveClientPins {
                events: ClientWasmPin::from_config(&facts, directory, "live-events")?,
                canvas: ClientWasmPin::from_config(&facts, directory, "canvas")?,
            },
            gateway_identity: match facts.values("launch", "gatewayIdentity").as_slice() {
                [] => false,
                [mode] if *mode == "temple" && optional_path("operators")?.is_some() => true,
                _ => return Err(fail("gateway identity requires configured operators")),
            },
        })
    }
}
