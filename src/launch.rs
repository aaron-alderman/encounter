// Versioned coordinates shared by the CLI and a service supervisor.
use crate::{Result, fail, rel::Facts};
use std::path::{Path, PathBuf};

pub struct Launch {
    pub image: PathBuf,
    pub pin: String,
    pub store: PathBuf,
    pub port: u16,
    pub attachment_root: Option<PathBuf>,
    pub operators: Option<PathBuf>,
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
        let fields = ["version", "mode", "port", "image", "sha256", "store", "attachmentRoot", "operators"];
        for [subject, property, _] in &facts.0 {
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
        Ok(Self {
            image: path("image")?,
            pin: field("sha256")?.to_owned(),
            store: path("store")?,
            port: field("port")?.parse()?,
            attachment_root: optional_path("attachmentRoot")?,
            operators: optional_path("operators")?,
        })
    }
}
