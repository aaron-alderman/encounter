// Release startup verifies one independently supplied receipt pin and serves
// the exact asset bytes that passed verification.
use crate::{Result, fail, rel::{self, Facts}, surface_image::SurfaceImage};
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File}, io::Read, path::{Component, Path, PathBuf}};

type Assets = BTreeMap<String, Vec<u8>>;

pub(crate) struct ClientWasmPin {
    directory: PathBuf,
    pub receipt: String,
}

impl ClientWasmPin {
    pub fn from_config(facts: &Facts, parent: &Path, name: &str) -> Result<Option<Self>> {
        let mut present = false;
        for [subject, property, _] in &facts.0 {
            if subject != name { continue; }
            present = true;
            if !matches!(property.as_str(), "directory" | "receiptSha256") {
                return Err(fail(format!("unknown browser Wasm configuration field {name}.{property}")));
            }
        }
        if !present { return Ok(None); }
        let directory = facts.one(name, "directory")?;
        let receipt = facts.one(name, "receiptSha256")?;
        if directory.is_empty() || receipt.len() != 64
            || !receipt.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(fail(format!("invalid browser Wasm launch pin for {name}")));
        }
        Ok(Some(Self { directory: parent.join(directory), receipt: receipt.to_owned() }))
    }

    pub fn read(&self, sources: &[(&str, &str); 2]) -> Result<Vec<u8>> {
        let directory = self.directory.canonicalize()?;
        crate::package::check(&directory)?;
        let runtime_pin = rel::hash(fs::read("/proc/self/exe")?);
        wasm(&directory, &self.receipt, &runtime_pin, sources, true)
    }
}

#[derive(Default)]
pub(crate) struct LiveClientPins {
    pub events: Option<ClientWasmPin>,
    pub canvas: Option<ClientWasmPin>,
}

fn bounded(file: File, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(fail("browser release file size limit")); }
    Ok(bytes)
}

pub(crate) fn artifact(root: &Path, name: &str, limit: u64) -> Result<Vec<u8>> {
    let path = Path::new(name);
    crate::package::check_path(path)?;
    if path.as_os_str().is_empty() || name.contains('\\') || name.chars().any(char::is_control)
        || path.components().any(|part| !matches!(part, Component::Normal(_)))
        || name.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
        return Err(fail("invalid browser release artifact path"));
    }
    let file = root.join(path).canonicalize()?;
    if !file.starts_with(root) || !file.is_file() { return Err(fail("invalid browser release artifact")); }
    bounded(File::open(file)?, limit)
}

pub(crate) fn wasm(root: &Path, pin: &str, runtime_pin: &str, sources: &[(&str, &str); 2],
    running_compiler: bool) -> Result<Vec<u8>>
{
    let receipt = artifact(root, "build-receipt.rel", 256_000)?;
    if rel::hash(&receipt) != pin { return Err(fail("browser Wasm receipt hash differs from its pin")); }
    let facts = Facts::parse(std::str::from_utf8(&receipt)?)?;
    if facts.one("build", "contract")? != "encounter/browser-wasm-receipt/1"
        || facts.one("build", "runtimeSha256")? != runtime_pin {
        return Err(fail("browser Wasm receipt contract or runtime pin differs"));
    }
    if facts.0.len() != 4 + sources.len() {
        return Err(fail("unexpected browser Wasm receipt fields"));
    }
    for (name, text) in sources {
        let source_pin = facts.one("source", name)?;
        if source_pin.len() != 64 || !source_pin.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || (running_compiler && source_pin != rel::hash(text)) {
            return Err(fail(format!("browser Wasm source pin differs for {name}")));
        }
    }
    let module = artifact(root, "browser.wasm", 2_000_000)?;
    if !module.starts_with(b"\0asm\x01\0\0\0") || rel::hash(&module) != facts.one("artifact", "browser.wasm")? {
        return Err(fail("browser Wasm module differs from its receipt"));
    }
    let map = artifact(root, "browser.wasm.map.rel", 256_000)?;
    if rel::hash(&map) != facts.one("artifact", "browser.wasm.map.rel")? {
        return Err(fail("browser Wasm source map differs from its receipt"));
    }
    if running_compiler {
        let [(_, declaration), (source_name, source)] = sources;
        let declaration = Facts::parse(declaration)?;
        if declaration.one("wasm", "source")? != *source_name {
            return Err(fail("browser Wasm declaration names a different source"));
        }
        let (expected_module, expected_map) = crate::process::browser_wasm::compile(&declaration, source)?;
        if module != expected_module {
            return Err(fail("browser Wasm module differs from the Encounter build"));
        }
        if map != expected_map.as_bytes() {
            return Err(fail("browser Wasm source map differs from the Encounter build"));
        }
    }
    Ok(module)
}

pub fn read(root: &Path, pin: &str) -> Result<(SurfaceImage, Assets)> {
    let root = root.canonicalize()?;
    crate::package::check(&root)?;
    let receipt = artifact(&root, "build-receipt.rel", 256_000)?;
    if rel::hash(&receipt) != pin { return Err(fail("browser release receipt hash differs from its pin")); }
    let facts = Facts::parse(std::str::from_utf8(&receipt)?)?;
    if facts.one("build", "contract")? != "encounter/browser-build-receipt/1" {
        return Err(fail("unsupported browser release receipt"));
    }
    if facts.one("build", "runtimeSha256")? != rel::hash(fs::read("/proc/self/exe")?) {
        return Err(fail("browser release runtime hash differs from receipt"));
    }

    let mut assets = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut remaining = 128_000_000_u64;
    let mut launch = None;
    let mut surface = None;
    for [subject, name, digest] in &facts.0 {
        if subject != "artifact" { continue; }
        if !seen.insert(name) { return Err(fail("duplicate browser release artifact")); }
        let bytes = artifact(&root, name, remaining.min(16_000_000))
            .map_err(|error| fail(format!("browser release artifact {name}: {error}")))?;
        if rel::hash(&bytes) != *digest {
            return Err(fail(format!("browser release artifact hash differs from receipt: {name}")));
        }
        remaining -= bytes.len() as u64;
        match name.as_str() {
            "launch.rel" => launch = Some(Facts::parse(std::str::from_utf8(&bytes)?)?),
            "published.surface" => surface = Some(bytes),
            name => if let Some(path) = name.strip_prefix("assets/") { assets.insert(path.to_owned(), bytes); },
        }
    }
    if !assets.contains_key("index.html") { return Err(fail("missing verified index.html")); }
    let launch = launch.ok_or_else(|| fail("missing verified launch.rel"))?;
    if launch.one("surface", "image")? != "published.surface" {
        return Err(fail("unexpected browser release image name"));
    }
    let surface = surface.ok_or_else(|| fail("missing verified published.surface"))?;
    Ok((SurfaceImage::parse(&launch, &surface)?, assets))
}
