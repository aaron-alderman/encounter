// The catalogue is a private projection of declared artifacts and committed
// app records. No provider discovers files by walking its storage directory.
use crate::{Result, fail, nonce::nonce, process::{Meter, Programme}, rel::{self, Facts}, sqlite::Db};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::{fd::AsRawFd, unix::{fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream}}},
    path::{Component, Path, PathBuf},
    thread,
    time::{Duration, SystemTime},
};

const CONFIG: &str = "encounter/file-index/1";
const SNAPSHOT: &str = "EncounterFileIndex";
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_METADATA: u64 = 2 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_RUN_RECEIPT: u64 = 64 * 1024;
const MAX_RELEASE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) const HOME_RELEASES: &str = "Platform/Releases/Home";
pub(crate) const KERNEL_RELEASES: &str = "Platform/Kernel/Releases";
pub(crate) const GAME_ASSETS: &str = "Apps/Game Hub/Assets";
pub(crate) const STORE_ASSETS: &str = "Apps/Game Hub/Store/Published assets";
pub(crate) const NORTH_SOURCE: &str = "Apps/North River/Source";
pub(crate) const NORTH_RECEIPTS: &str = "Apps/North River/Receipts";
pub(crate) const SCHEDULED_RECEIPTS: &str = "Platform/Scheduled run receipts";
pub(crate) const MAX_VIEW: u64 = 900_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Provider { Home, Kernel, Game, NorthRiver, ScheduledReceipts }

impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::Home => "home-release",
            Self::Kernel => "kernel-release",
            Self::Game => "game-hub",
            Self::NorthRiver => "north-river",
            Self::ScheduledReceipts => "scheduled-receipts",
        }
    }
}

pub(crate) struct IndexPolicy(Programme);

pub(crate) enum FileHttpDecision { Request, MediaAccess, MediaFrame, Gateway, GatewaySession, GatewayResponse, Image }

impl IndexPolicy {
    pub(crate) fn load() -> Result<Self> {
        let source = include_str!("file_index_policy.encounter").to_owned();
        let programme = Programme::admit_entries(&[source], &["fileIndex.policy", "fileIndex.userUnit", "fileIndex.relFilter",
            "fileIndex.httpRequest", "fileIndex.httpMediaAccess", "fileIndex.httpGateway", "fileIndex.httpGatewaySession", "fileIndex.httpGatewayResponse",
            "fileIndex.httpMediaFrame", "fileIndex.httpImage"],
            &BTreeSet::from(["text.matches", "text.match", "text.startsWith", "kernel.invoke", "number.calculate"]), &mut Meter::new(100_000))?;
        Ok(Self(programme))
    }

    pub(crate) fn http(&self, operation: FileHttpDecision, input: Value) -> Result<Value> {
        let entry = match operation {
            FileHttpDecision::Request => "fileIndex.httpRequest",
            FileHttpDecision::MediaAccess => "fileIndex.httpMediaAccess",
            FileHttpDecision::MediaFrame => "fileIndex.httpMediaFrame",
            FileHttpDecision::Gateway => "fileIndex.httpGateway",
            FileHttpDecision::GatewaySession => "fileIndex.httpGatewaySession",
            FileHttpDecision::GatewayResponse => "fileIndex.httpGatewayResponse",
            FileHttpDecision::Image => "fileIndex.httpImage",
        };
        self.0.run(entry, input, &mut Meter::new(100_000))
    }

    fn rel_filter(&self, filter: &str) -> bool {
        self.0.run("fileIndex.relFilter", json!(filter), &mut Meter::new(100_000)).is_ok_and(|result| result == true)
    }

    fn admit_user_unit(&self, provider: Provider, unit: &str) -> Result<bool> {
        let result = self.0.run("fileIndex.userUnit", json!({"provider":provider.name(),"unit":unit}), &mut Meter::new(100_000))?;
        result.as_bool().ok_or_else(|| fail("invalid file index unit admission"))
    }

    fn decide(&self, input: Value) -> Result<Vec<Value>> {
        match self.0.run("fileIndex.policy", input, &mut Meter::new(100_000))? {
            Value::Array(rows) => Ok(rows),
            _ => Err(fail("invalid file index policy result")),
        }
    }
}

enum Location { Path(PathBuf), UserUnit(String) }

impl Location {
    fn resolve(&self) -> Result<PathBuf> {
        match self {
            Self::Path(path) => Ok(path.clone()),
            Self::UserUnit(unit) => {
                let pid = crate::systemd_user_service::main_pid(unit)?;
                let process = File::open(format!("/proc/{pid}"))?;
                let process_path = PathBuf::from(format!("/proc/self/fd/{}", process.as_raw_fd()));
                if fs::read_link(process_path.join("exe"))?.file_name().and_then(|name| name.to_str()) != Some("encounter") {
                    return Err(fail("application unit main process is not Encounter"));
                }
                let mut command = Vec::new();
                File::open(process_path.join("cmdline"))?.take(64 * 1024 + 1).read_to_end(&mut command)?;
                if command.len() > 64 * 1024 { return Err(fail("application unit command line exceeds the file index bound")); }
                let args: Vec<_> = command.split(|byte| *byte == 0).collect();
                let [_, b"--config", path, b"serve", b""] = args.as_slice() else {
                    return Err(fail("application unit does not run an Encounter launch configuration"));
                };
                let path = Path::new(std::str::from_utf8(path)?);
                Ok(if path.is_absolute() { path.to_owned() } else { fs::read_link(process_path.join("cwd"))?.join(path) })
            }
        }
    }
}

struct Source {
    id: String,
    provider: Provider,
    location: Location,
    steward: Option<String>,
    binding: String,
}

fn config(policy: &IndexPolicy, path: &Path) -> Result<Vec<Source>> {
    let contents = read(&path.canonicalize()?, 64 * 1024)?;
    let facts = Facts::parse(std::str::from_utf8(&contents)?)?;
    if facts.one("index", "format")? != CONFIG { return Err(fail("unsupported file index configuration")); }
    let names = facts.values("index", "source");
    if names.is_empty() || names.len() > 16 { return Err(fail("expected between 1 and 16 file index sources")); }
    for [subject, field, _] in &facts.0 {
        let admitted = if subject == "index" { matches!(field.as_str(), "format" | "source") }
            else { names.contains(&subject.as_str()) && matches!(field.as_str(), "provider" | "location" | "unit" | "steward") };
        if !admitted { return Err(fail("unknown file index configuration field")); }
    }
    names.into_iter().map(|id| {
        if id == "index" || !identifier(id) { return Err(fail("invalid file index source ID")); }
        let kind = facts.one(id, "provider")?;
        let provider = match kind {
            "home-release" => Provider::Home,
            "kernel-release" => Provider::Kernel,
            "game-hub" => Provider::Game,
            "north-river" => Provider::NorthRiver,
            "scheduled-receipts" => Provider::ScheduledReceipts,
            _ => return Err(fail("unknown file index provider")),
        };
        let paths = facts.values(id, "location");
        let units = facts.values(id, "unit");
        let location = match (paths.as_slice(), units.as_slice()) {
            ([path], []) if Path::new(path).is_absolute() => Location::Path(PathBuf::from(path)),
            ([], [unit]) if policy.admit_user_unit(provider, unit)? => Location::UserUnit((*unit).to_owned()),
            _ => return Err(fail("file index source requires an absolute location or an application user service")),
        };
        let steward = match facts.values(id, "steward").as_slice() {
            [] => None,
            [value] if !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control) => Some((*value).to_owned()),
            _ => return Err(fail("invalid file index steward")),
        };
        let binding = rel::hash(serde_json::to_vec(&json!([id,kind,paths,units,steward]))?);
        Ok(Source { id:id.to_owned(), provider, location, steward, binding })
    }).collect()
}

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn relative(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value.split('/').all(|part| !matches!(part, "" | "." | ".."))
        && Path::new(value).components().all(|c| matches!(c, Component::Normal(_)))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field].as_str().filter(|value| !value.is_empty()).ok_or_else(|| fail(format!("missing file index field {field}")))
}

fn optional_text<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value[field].as_str().filter(|value| !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control))
}

fn sha(value: &str) -> Result<&str> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        Ok(value)
    } else { Err(fail("invalid file index SHA-256")) }
}

fn open_file(path: &Path, limit: u64) -> Result<(File, u64)> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > limit { return Err(fail("file index expects a bounded regular file")); }
    Ok((file, meta.len()))
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let (file, size) = open_file(path, limit)?;
    let mut content = Vec::new();
    file.take(limit + 1).read_to_end(&mut content)?;
    if content.len() as u64 != size { return Err(fail("file changed during index read")); }
    Ok(content)
}

fn mounted(root: &Path, path: &str) -> Result<PathBuf> {
    if !relative(path) { return Err(fail("invalid declared artifact path")); }
    let file = root.join(path);
    if file.canonicalize()? != file { return Err(fail("declared artifact escapes its mount or uses a symlink")); }
    Ok(file)
}

#[derive(PartialEq, Eq)]
struct ArtifactVersion {
    inode: u64,
    device: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for ArtifactVersion {
    fn from(meta: Metadata) -> Self {
        Self {
            inode: meta.ino(), device: meta.dev(), size: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()), changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

thread_local! {
    static VERIFIED_RELEASE: RefCell<BTreeMap<PathBuf, (ArtifactVersion, String)>> =
        const { RefCell::new(BTreeMap::new()) };
}

fn verified(root: &Path, path: &str, pin: &str, size: Option<u64>) -> Result<u64> {
    let path = mounted(root, path)?;
    let (file, _) = open_file(&path, MAX_FILE)?;
    let meta = file.metadata()?;
    let cache = root.starts_with("/srv/encounter-apps") && meta.uid() == 0 && meta.mode() & 0o022 == 0;
    let version = ArtifactVersion::from(meta);
    let pin = sha(pin)?;
    if size.is_some_and(|size| size != version.size) {
        return Err(fail("declared artifact size or hash differs"));
    }
    if cache && VERIFIED_RELEASE.with_borrow(|entries|
        entries.get(&path).is_some_and(|(saved, hash)| saved == &version && hash == pin)) {
        return Ok(version.size);
    }

    let mut file = file.take(MAX_FILE + 1);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut bytes = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        bytes += count as u64;
        hasher.update(&buffer[..count]);
    }
    if bytes != version.size || ArtifactVersion::from(file.get_ref().metadata()?) != version
        || hex::encode(hasher.finalize()) != pin {
        return Err(fail("declared artifact size or hash differs"));
    }
    if cache {
        VERIFIED_RELEASE.with_borrow_mut(|entries| {
            if entries.len() >= MAX_ENTRIES { entries.clear(); }
            entries.insert(path, (version, pin.to_owned()));
        });
    }
    Ok(bytes)
}

fn entry(root: &str, path: &str, bytes: u64, pin: &str, kind: &str, source: &str) -> Value {
    json!({"root":root,"path":path,"kind":kind,"bytes":bytes,"sha256":pin,"sizeSource":source})
}

fn release(source: &Source) -> Result<Value> {
    let root = source.location.resolve()?.canonicalize()?;
    let home = source.provider == Provider::Home;
    let manifest = if home { "package-receipt.rel" } else { "release.rel" };
    let manifest_bytes = read(&mounted(&root, manifest)?, MAX_METADATA)?;
    let revision = rel::hash(&manifest_bytes);
    let facts = Facts::parse(std::str::from_utf8(&manifest_bytes)?)?;
    let mut declared = BTreeMap::new();
    if home {
        if facts.one("package", "contract")? != "encounter/gated-release/1" { return Err(fail("unexpected Home release receipt")); }
        for [subject, path, pin] in &facts.0 {
            if subject == "artifact" && declared.insert(path.as_str(), pin.as_str()).is_some() {
                return Err(fail("multiple pins for release artifact"));
            }
        }
        if declared.get("encounter").copied() != Some(facts.one("package", "runtimeSha256")?) {
            return Err(fail("Home runtime pin differs from receipt"));
        }
    } else {
        if facts.one("release", "format")? != "encounter/release/1" { return Err(fail("unexpected kernel release manifest")); }
        for [subject, property, pin] in &facts.0 {
            if property == "sha256" {
                let image = facts.values(subject, "image");
                let path = match image.as_slice() {
                    [] => subject.as_str(),
                    [path] => *path,
                    _ => return Err(fail("multiple image paths for release artifact")),
                };
                if declared.insert(path, pin.as_str()).is_some() { return Err(fail("multiple pins for release artifact")); }
            }
        }
        if !declared.contains_key(facts.one("release", "runtime")?) { return Err(fail("kernel release runtime is unpinned")); }
    }
    if declared.is_empty() || declared.len() >= MAX_ENTRIES { return Err(fail("release file index entry limit")); }
    let path = if home { HOME_RELEASES } else { KERNEL_RELEASES };
    let mut items = vec![entry(path, manifest, manifest_bytes.len() as u64, &revision, "manifest", "measured")];
    let mut total = manifest_bytes.len() as u64;
    for (name, pin) in declared {
        if name == manifest { return Err(fail("release manifest cannot list itself")); }
        let bytes = verified(&root, name, pin, None)?;
        total += bytes;
        if total > MAX_RELEASE_BYTES { return Err(fail("release file index byte limit")); }
        items.push(entry(path, name, bytes, pin, "release-artifact", "measured-and-verified"));
    }
    Ok(json!({"revision":revision,"files":items}))
}

struct LaunchSource { image: Value, pin: String, store: PathBuf, assets: Option<PathBuf> }

fn launch(path: &Path) -> Result<LaunchSource> {
    let path = path.canonicalize()?;
    let parent = path.parent().ok_or_else(|| fail("file index launch has no parent"))?;
    let config = Facts::parse(std::str::from_utf8(&read(&path, MAX_METADATA)?)?)?;
    if config.one("launch", "version")? != "encounter/launch/1" || config.one("launch", "mode")? != "image" {
        return Err(fail("unsupported application launch for file index"));
    }
    let resolve = |property| -> Result<PathBuf> {
        let value = Path::new(config.one("launch", property)?);
        Ok(parent.join(value).canonicalize()?)
    };
    let pin = sha(config.one("launch", "sha256")?)?.to_owned();
    let image_path = resolve("image")?;
    let bytes = read(&image_path, MAX_FILE)?;
    if rel::hash(&bytes) != pin { return Err(fail("file index image pin differs")); }
    let image = rel::decode(std::str::from_utf8(&bytes)?, "EncounterApplicationImage")?;
    if image["format"] != "encounter/application-image/2" || !image["files"].is_object() {
        return Err(fail("unsupported file index image format"));
    }
    let assets = if config.values("launch", "attachmentRoot").is_empty() { None } else { Some(resolve("attachmentRoot")?) };
    Ok(LaunchSource { image, pin, store:resolve("store")?, assets })
}

fn image_file<'a>(launch: &'a LaunchSource, name: &str) -> Result<(&'a str, &'a str)> {
    let record = &launch.image["files"][name];
    let source = text(record, "text")?;
    let pin = sha(text(record, "sha256")?)?;
    if source.len() as u64 > MAX_METADATA || rel::hash(source) != pin { return Err(fail("indexed image file pin differs")); }
    Ok((source,pin))
}

fn store_rows(launch: &LaunchSource, profile: &str, selection: &str) -> Result<(i64, BTreeMap<String, String>)> {
    let db = Db::open_readonly(&mounted(&launch.store, "workspace.sqlite")?)?;
    db.exec("BEGIN")?;
    let current = db.query("SELECT value FROM metadata WHERE key='profile'", &[])?;
    if current.first().map(|row| &row["value"]) != Some(&json!(profile)) { return Err(fail("file index store profile differs")); }
    let head = db.query("SELECT COALESCE(MAX(id), 0) AS head FROM revisions", &[])?[0]["head"].as_i64()
        .ok_or_else(|| fail("invalid file index store revision"))?;
    // Each caller supplies a constant predicate for its own declared documents.
    let selected = format!("FROM documents WHERE revision=? AND ({selection})");
    let bounds = db.query(&format!("SELECT count(*) AS files, max(length(CAST(text AS BLOB))) AS largest,
        sum(length(CAST(text AS BLOB))) AS bytes {selected}"), &[json!(head)])?;
    let bounds = &bounds[0];
    if bounds["files"].as_u64().unwrap_or(u64::MAX) > MAX_ENTRIES as u64
        || bounds["largest"].as_u64().unwrap_or(0) > MAX_METADATA
        || bounds["bytes"].as_u64().unwrap_or(0) > MAX_STORE_BYTES {
        return Err(fail("file index store document limit"));
    }
    let rows = db.query(&format!("SELECT path, text {selected} ORDER BY path"), &[json!(head)])?;
    let documents = rows.iter().map(|row| Ok((text(row,"path")?.to_owned(), text(row,"text")?.to_owned()))).collect::<Result<_>>()?;
    db.exec("COMMIT")?;
    Ok((head,documents))
}

fn game_hub(source: &Source) -> Result<Value> {
    let launch = launch(&source.location.resolve()?)?;
    if launch.image["declaration"] != "game-hub/application.rel" { return Err(fail("unexpected Game Hub declaration")); }
    let (catalog, _) = image_file(&launch, "game-hub/catalog.encounter")?;
    let mut meter = Meter::new(2_000_000);
    let programme = Programme::admit(&[catalog.to_owned()], "hub.catalog", &BTreeSet::new(), &mut meter)?;
    let catalogue = programme.run("hub.catalog", Value::Null, &mut meter)?;
    let mount = launch.assets.as_deref().ok_or_else(|| fail("Game Hub has no declared asset mount"))?;
    let media = GAME_ASSETS;
    let store = STORE_ASSETS;
    let mut files = Vec::new();
    for section in catalogue.as_array().ok_or_else(|| fail("invalid Game Hub file catalogue"))? {
        let id = text(section,"id")?;
        if !identifier(id) { return Err(fail("invalid Game Hub collection ID")); }
        for asset in section["images"].as_array().ok_or_else(|| fail("invalid Game Hub image list"))? {
            let path = text(asset,"file")?;
            let size = asset["bytes"].as_u64().ok_or_else(|| fail("invalid Game Hub file size"))?;
            let pin = text(asset,"sha256")?;
            verified(mount,path,pin,Some(size))?;
            let mut item = entry(media,&format!("{id}/{path}"),size,pin,"image","declared-and-verified");
            item["title"] = asset["title"].clone();
            files.push(item);
        }
    }
    let (head, documents) = store_rows(&launch,"encounter/game-hub/1","path='store/catalog.rel'")?;
    if let Some(document) = documents.get("store/catalog.rel") {
        let value = rel::decode(document,"GameStore")?;
        for asset in value["assets"].as_array().ok_or_else(|| fail("invalid Store asset catalogue"))? {
            let id = text(asset,"asset")?;
            if !identifier(id) { return Err(fail("invalid published asset ID")); }
            let bundle = sha(text(asset,"bundle")?)?;
            let pin = sha(text(asset,"hash")?)?;
            let size = asset["bytes"].as_u64().ok_or_else(|| fail("invalid published asset size"))?;
            let mut item = entry(store,&format!("{id}/{bundle}/high.glb"),size,pin,"published-asset","provider-declared");
            item["title"] = asset["name"].clone();
            item["downloadable"] = json!(asset["downloadable"] == true && size <= 16 * 1024 * 1024);
            files.push(item);
        }
    }
    Ok(json!({"revision":{"image":launch.pin,"store":head},"files":files}))
}

fn add_receipt(files: &mut Vec<Value>, root: &str, path: &str, receipt: &Value, kind: &str) -> Result<()> {
    if receipt.is_null() { return Ok(()); }
    if !receipt.is_object() { return Err(fail("invalid North River receipt")); }
    let declared = sha(text(receipt,"sha256")?)?;
    let mut unsigned = receipt.clone();
    unsigned.as_object_mut().expect("receipt object").remove("sha256");
    if rel::hash(rel::encode(&unsigned,kind)?) != declared { return Err(fail("North River decision receipt pin differs")); }
    let contents = rel::encode(receipt,kind)?;
    let mut item = entry(root,path,contents.len() as u64,&rel::hash(&contents),"receipt","canonical-rel-export");
    item["decisionSha256"] = json!(declared);
    item["author"] = json!(optional_text(receipt,"reviewer").or_else(|| optional_text(receipt,"approver")));
    item["decisionRevision"] = receipt["revision"].clone();
    files.push(item);
    Ok(())
}

fn north_river(source: &Source) -> Result<(Value, Option<String>)> {
    let launch = launch(&source.location.resolve()?)?;
    let declaration = text(&launch.image,"declaration")?;
    if declaration != "north-river/application.rel" { return Err(fail("unexpected North River declaration")); }
    let (declaration, _) = image_file(&launch,declaration)?;
    let facts = Facts::parse(declaration)?;
    let sources = NORTH_SOURCE;
    let receipts = NORTH_RECEIPTS;
    let mut files = Vec::new();
    for path in facts.values("application","module").into_iter().filter(|path| path.starts_with("north-river/")) {
        let (body,pin) = image_file(&launch,path)?;
        files.push(entry(sources,path.strip_prefix("north-river/").expect("module prefix"),body.len() as u64,pin,"source","pinned-image"));
    }
    if files.is_empty() { return Err(fail("North River image has no declared project modules")); }
    let (head, documents) = store_rows(&launch,"encounter/north-river-plan/1",
        "path IN ('project.rel','task.rel','release.rel') OR path GLOB 'tasks/*.rel'")?;
    let project = documents.get("project.rel").map(|document| rel::decode(document,"NorthRiverProject")).transpose()?;
    let primary = documents.get("task.rel").map(|document| rel::decode(document,"NorthRiverTask")).transpose()?;
    let owner = project.as_ref().and_then(|value| optional_text(value,"owner"))
        .or_else(|| primary.as_ref().and_then(|value| optional_text(value,"owner")));
    for (path, document) in &documents {
        let task_id = if path == "task.rel" { "primary" }
            else if let Some(id) = path.strip_prefix("tasks/").and_then(|path| path.strip_suffix(".rel")).filter(|id| identifier(id)) { id }
            else { continue };
        let task = rel::decode(document,"NorthRiverTask")?;
        if !task["approval"].is_null() || !task["import"]["receipt"].is_null() {
            if owner.is_none() || optional_text(&task,"owner") != owner { return Err(fail("North River receipt lacks the current project owner")); }
            add_receipt(&mut files,receipts,&format!("{task_id}/plan-approval.rel"),&task["approval"],"NorthRiverPlanDecision")?;
            add_receipt(&mut files,receipts,&format!("{task_id}/employee-import.rel"),&task["import"]["receipt"],"NorthRiverImportDecision")?;
        }
    }
    if let Some(document) = documents.get("release.rel") {
        let release = rel::decode(document,"NorthRiverRelease")?;
        if !release["receipt"].is_null() && owner.is_none() { return Err(fail("North River release receipt has no owner")); }
        add_receipt(&mut files,receipts,"primary/demo-approval.rel",&release["receipt"],"NorthRiverDemoDecision")?;
    }
    Ok((json!({"revision":{"image":launch.pin,"store":head},"files":files}), owner.map(str::to_owned)))
}

#[derive(Default)]
struct Total {
    files: u64,
    bytes: u64,
    unique: u64,
    digests: BTreeSet<String>,
}

fn scheduled_receipts(source: &Source) -> Result<Value> {
    use crate::directory::{observed_unit, valid_invocation_id};

    let root = source.location.resolve()?.canonicalize()?;
    let manifest = read(&mounted(&root, "publication.rel")?, MAX_METADATA)?;
    let facts = Facts::parse(std::str::from_utf8(&manifest)?)?;
    if facts.one("publication", "format")? != "encounter/scheduled-run-receipts/1" {
        return Err(fail("unexpected scheduled receipt publication format"));
    }
    let paths = facts.values("publication", "receipt");
    if paths.len() > MAX_ENTRIES { return Err(fail("scheduled receipt publication entry limit")); }
    let mut files = Vec::new();
    for path in paths {
        let invocation = path.strip_suffix(".rel").filter(|id| valid_invocation_id(id))
            .ok_or_else(|| fail("expected an invocation ID as the scheduled receipt filename"))?;
        let pin = sha(facts.one(path, "sha256")?)?;
        let contents = read(&mounted(&root, path)?, MAX_RUN_RECEIPT)?;
        if rel::hash(&contents) != pin { return Err(fail("scheduled receipt pin differs")); }
        let receipt = Facts::parse(std::str::from_utf8(&contents)?)?;
        if receipt.one("execution", "invocation-id")? != invocation {
            return Err(fail("scheduled receipt invocation differs from its filename"));
        }
        let service = receipt.one("execution", "service")?;
        let scope = receipt.one("execution", "scope")?;
        let started = receipt.one("execution", "started")?;
        let result = receipt.one("execution", "result")?;
        let duration = receipt.one("execution", "duration-seconds")?.parse::<u64>()?;
        if !observed_unit(service, ".service") || !matches!(scope, "system" | "user")
            || chrono::NaiveDateTime::parse_from_str(started, "%Y-%m-%d %H:%M:%S").is_err()
            || result.is_empty() || result.len() > 64 || !result.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'-') {
            return Err(fail("invalid scheduled receipt execution metadata"));
        }
        let mut execution = json!({"invocationId":invocation, "service":service, "scope":scope,
            "started":started, "duration":duration, "result":result});
        match (receipt.values("execution", "timer").as_slice(), receipt.values("execution", "last-trigger").as_slice()) {
            ([], []) => (),
            ([timer], [trigger]) if observed_unit(timer, ".timer")
                && chrono::NaiveDateTime::parse_from_str(trigger, "%Y-%m-%d %H:%M:%S").is_ok() => {
                execution["timer"] = json!(timer);
                execution["lastTrigger"] = json!(trigger);
            }
            _ => return Err(fail("invalid scheduled receipt timer binding")),
        }
        let mut file = entry(SCHEDULED_RECEIPTS, path, contents.len() as u64, pin, "receipt", "pinned-publication");
        file["execution"] = execution;
        files.push(file);
    }
    Ok(json!({"revision":{"publication":rel::hash(&manifest)},"files":files}))
}

fn project(policy: &IndexPolicy, source: &Source) -> Result<Value> {
    let (mut record, owner) = match source.provider {
        Provider::Home | Provider::Kernel => (release(source)?, None),
        Provider::Game => (game_hub(source)?, None),
        Provider::NorthRiver => north_river(source)?,
        Provider::ScheduledReceipts => (scheduled_receipts(source)?, None),
    };
    let collections = policy.decide(json!({"operation":"publish","provider":source.provider.name(),
        "owner":owner,"steward":source.steward}))?;
    let mut folders = BTreeMap::<String, Total>::new();
    for collection in &collections { folders.insert(text(collection,"root")?.to_owned(), Total::default()); }
    let files = record["files"].as_array_mut().ok_or_else(|| fail("missing file index files"))?;
    if files.len() > MAX_ENTRIES { return Err(fail("file index entry limit")); }
    let mut paths = BTreeSet::new();
    let mut digests = BTreeMap::new();
    for file in files.iter_mut() {
        let root = text(file,"root")?.to_owned();
        let path = text(file,"path")?;
        let full = format!("{root}/{path}");
        if !relative(path) || !paths.insert(full.clone()) { return Err(fail("invalid or duplicate indexed file path")); }
        let pin = sha(text(file,"sha256")?)?;
        let bytes = file["bytes"].as_u64().ok_or_else(|| fail("indexed file lacks byte size"))?;
        if digests.insert(pin.to_owned(), bytes).is_some_and(|previous| previous != bytes) {
            return Err(fail("file index has different byte sizes for one digest"));
        }
        let policy = collections.iter().find(|collection| collection["root"] == root)
            .ok_or_else(|| fail("file index path has no declared collection"))?;
        let mut parent = full.rsplit_once('/').expect("qualified file path").0;
        loop {
            let total = folders.entry(parent.to_owned()).or_default();
            total.files += 1;
            total.bytes = total.bytes.checked_add(bytes).ok_or_else(|| fail("folder byte size overflow"))?;
            if total.digests.insert(pin.to_owned()) {
                total.unique = total.unique.checked_add(bytes).ok_or_else(|| fail("folder unique byte size overflow"))?;
            }
            if parent == root { break; }
            parent = parent.rsplit_once('/').expect("indexed folder has a collection").0;
        }
        file["id"] = json!(format!("{}:{full}",source.id));
        file["ownership"] = policy["ownership"].clone();
        file["permissions"] = policy["permissions"].clone();
    }
    let mut rows = Vec::new();
    for (path,total) in folders {
        if paths.contains(&path) { return Err(fail("indexed path is both a file and a folder")); }
        let policy = collections.iter().filter(|collection| collection["root"].as_str().is_some_and(|root|
            path == root || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/'))))
            .max_by_key(|collection| collection["root"].as_str().unwrap_or_default().len())
            .ok_or_else(|| fail("indexed folder has no collection"))?;
        rows.push(json!({"id":format!("{}:{path}",source.id),"path":path,"root":policy["root"],
            "fileCount":total.files,"logicalBytes":total.bytes,"uniqueContentBytes":total.unique,
            "ownership":policy["ownership"],"permissions":policy["permissions"]}));
    }
    files.sort_by(|a,b| a["id"].as_str().cmp(&b["id"].as_str()));
    record["folders"] = json!(rows);
    record["collections"] = json!(collections);
    Ok(record)
}

fn private_directory(path: &Path) -> Result<PathBuf> {
    let requested = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    let parent = requested.parent().ok_or_else(|| fail("invalid file index cache directory"))?.canonicalize()?;
    let name = requested.file_name().ok_or_else(|| fail("invalid file index cache directory name"))?;
    let directory = parent.join(name);
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let meta = directory.symlink_metadata()?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
        return Err(fail("file index cache must be an owner-only directory"));
    }
    Ok(directory)
}

fn publish(directory: &Path, value: &Value) -> Result<()> {
    let encoded = rel::encode(value, SNAPSHOT)?;
    if encoded.len() as u64 > MAX_FILE { return Err(fail("file index snapshot size limit")); }
    let temporary = directory.join(format!(".index-{}.tmp",nonce()?));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary,directory.join("index.rel"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(temporary); }
    result
}

fn snapshot(directory: &Path) -> Result<Value> {
    let cache = directory.join("index.rel");
    match cache.symlink_metadata() {
        Ok(meta) if meta.is_file() && meta.permissions().mode() & 0o077 == 0 =>
            rel::decode(std::str::from_utf8(&read(&cache,MAX_FILE)?)?,SNAPSHOT),
        Ok(_) => Err(fail("file index snapshot must be a private regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        Err(error) => Err(error.into()),
    }
}

fn refresh(policy: &IndexPolicy, sources: &[Source], directory: &Path) -> Result<bool> {
    let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(directory.join(".refresh.lock"))?;
    if !lock.metadata()?.is_file() { return Err(fail("invalid file index refresh lock")); }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 { return Err(std::io::Error::last_os_error().into()); }
    let previous = snapshot(directory)?;
    let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut providers = serde_json::Map::new();
    let mut complete = true;
    for source in sources {
        let old = &previous["providers"][&source.id];
        let mut row = match project(policy, source) {
            Ok(mut projected) => {
                projected["status"] = json!("indexed");
                projected["lastSuccessfulRefresh"] = json!(now);
                projected
            }
            Err(error) => {
                complete = false;
                let mut retained = if old["binding"] == source.binding && old["lastSuccessfulRefresh"].is_string() {
                    let mut retained = old.clone();
                    retained["status"] = json!("stale");
                    retained
                } else { json!({"status":"unavailable","files":[],"folders":[],"collections":[]}) };
                retained["diagnostic"] = json!(error.to_string());
                eprintln!("file index provider {}: {error}", source.id);
                retained
            }
        };
        row["binding"] = json!(source.binding);
        row["lastAttempt"] = json!(now);
        providers.insert(source.id.clone(),row);
    }
    publish(directory,&json!({"format":CONFIG,"generatedAt":now,"complete":complete,"providers":providers}))?;
    Ok(complete)
}

fn release_index_scratch() {
    // REL decoding can allocate large temporary graphs for the pinned provider
    // images. Return unused allocator pages once a refresh or view is complete.
    #[cfg(target_env = "gnu")]
    unsafe { libc::malloc_trim(0); }
}

pub(crate) fn run(path: &Path, cache: &Path, interval: Option<u64>) -> Result<()> {
    if interval.is_some_and(|seconds| !(1..=3600).contains(&seconds)) {
        return Err(fail("file index refresh interval must be 1 to 3600 seconds"));
    }
    let directory = private_directory(cache)?;
    let policy = IndexPolicy::load()?;
    let mut sources = Ok(config(&policy, path)?);
    loop {
        let result = sources.and_then(|sources| refresh(&policy,&sources,&directory));
        let Some(seconds) = interval else {
            return if result? { Ok(()) } else { Err(fail("one or more providers could not refresh; see the private index")) };
        };
        if let Err(error) = result { eprintln!("file index refresh: {error}"); }
        release_index_scratch();
        thread::sleep(Duration::from_secs(seconds));
        sources = config(&policy, path);
    }
}

fn current_north_evidence(source: &Source, record: &Value) -> Result<Value> {
    let launch = launch(&source.location.resolve()?)?;
    if record["revision"]["image"] != launch.pin { return Ok(Value::Null); }
    let (head, documents) = store_rows(&launch, "encounter/north-river-plan/1", "path IN ('project.rel','task.rel')")?;
    if record["revision"]["store"] != head { return Ok(Value::Null); }
    let Some(project) = documents.get("project.rel") else { return Ok(Value::Null); };
    let Some(task) = documents.get("task.rel") else { return Ok(Value::Null); };
    let project = rel::decode(project, "NorthRiverProject")?;
    let task = rel::decode(task, "NorthRiverTask")?;
    Ok(json!({"projectOwner":optional_text(&project,"owner"),
        "taskOwner":optional_text(&task,"owner"), "taskPhase":optional_text(&task,"phase")}))
}

fn view_row(row: &Value, folder: bool, permission: &str) -> Result<Value> {
    let root = text(row, "root")?;
    let path = text(row, "path")?;
    let full = if folder { path.to_owned() } else { format!("{root}/{path}") };
    let id = rel::hash(full.as_bytes());
    let (parent, name) = full.rsplit_once('/').ok_or_else(|| fail("invalid file index view path"))?;
    let parent = (full != root).then(|| rel::hash(parent.as_bytes()));
    Ok(json!({
        "id":id, "parent":parent, "path":full, "name":name, "kind":if folder { "Folder" } else { text(row,"kind")? },
        "bytes":if folder { &row["logicalBytes"] } else { &row["bytes"] },
        "uniqueBytes":row["uniqueContentBytes"], "fileCount":row["fileCount"],
        "owner":row["ownership"]["owner"], "steward":row["ownership"]["steward"],
        "permission":permission
    }))
}

fn release_text(provider: Provider, path: &str) -> bool {
    matches!(path, "package-receipt.rel" | "release.rel")
        || (provider == Provider::Kernel && path.starts_with("images/") && path.ends_with(".rel"))
        || (["spec/", "browser-programme/", "version-programme/", "claimipedia-programme/"].iter().any(|prefix| path.starts_with(prefix))
            && path.rsplit_once('.').is_some_and(|(_, suffix)| matches!(suffix, "rel" | "encounter" | "md" | "txt" | "js" | "css" | "json" | "rs" | "py" | "ts")))
}

fn movie_type(path: &str) -> Option<&'static str> {
    match path.rsplit_once('.')?.1 {
        "mp4" => Some("video/mp4"),
        "webm" => Some("video/webm"),
        _ => None,
    }
}

fn viewer_type(provider: Provider, row: &Value) -> Option<&'static str> {
    let path = row["path"].as_str()?;
    match provider {
        Provider::Home | Provider::Kernel if movie_type(path).is_some() => Some("video"),
        Provider::Home | Provider::Kernel if release_text(provider, path) => Some("text"),
        Provider::NorthRiver if row["root"] == NORTH_SOURCE || row["kind"] == "receipt" => Some("text"),
        Provider::ScheduledReceipts => Some("text"),
        Provider::Game if row["root"] == GAME_ASSETS && row["kind"] == "image"
            && path.rsplit_once('.').is_some_and(|(_, extension)| matches!(extension.to_ascii_lowercase().as_str(), "jpg" | "jpeg" | "png")) => Some("image"),
        _ => None,
    }
}

fn rel_view(contents: &str, filter: &str) -> Result<Value> {
    const ROW_LIMIT: usize = 100;
    const ATOM_LIMIT: usize = 256;
    let search = filter.to_lowercase();
    let mut total = 0;
    let mut matches = 0;
    let mut visible = Vec::new();
    for row in rel::relation_atoms(contents) {
        let ([subject, predicate, object], polarity) = row?;
        total += 1;
        if !search.is_empty() && ![subject.as_str(), predicate.as_str(), object.as_str(), polarity]
            .iter().any(|atom| atom.to_lowercase().contains(&search)) { continue; }
        matches += 1;
        if visible.len() == ROW_LIMIT { continue; }
        let clip = |value: String| {
            if value.len() <= ATOM_LIMIT { value }
            else { format!("{}…", &value[..value.floor_char_boundary(ATOM_LIMIT)]) }
        };
        visible.push(json!({"subject":clip(subject), "predicate":clip(predicate), "object":clip(object), "polarity":polarity}));
    }
    Ok(json!({"rows":visible, "total":total, "matches":matches, "filter":filter}))
}

fn preview(source: &Source, record: &Value, row: &Value, filter: &str) -> Result<Option<(String, Option<Value>)>> {
    let path = text(row, "path")?;
    let pin = text(row, "sha256")?;
    let contents = match source.provider {
        Provider::Home | Provider::Kernel => {
            if !release_text(source.provider, path) {
                return Ok(None);
            }
            let root = source.location.resolve()?.canonicalize()?;
            read(&mounted(&root, path)?, MAX_FILE)?
        }
        Provider::NorthRiver => {
            let launch = launch(&source.location.resolve()?)?;
            if launch.pin != record["revision"]["image"] { return Ok(None); }
            if row["root"] == NORTH_SOURCE {
                image_file(&launch, &format!("north-river/{path}"))?.0.as_bytes().to_vec()
            } else {
                let Some((task, name)) = path.split_once('/') else { return Ok(None); };
                if !identifier(task) { return Ok(None); }
                let (selection, kind, decision_kind) = match name {
                    "plan-approval.rel" => ("task", "NorthRiverTask", "NorthRiverPlanDecision"),
                    "employee-import.rel" => ("task", "NorthRiverTask", "NorthRiverImportDecision"),
                    "demo-approval.rel" if task == "primary" => ("release", "NorthRiverRelease", "NorthRiverDemoDecision"),
                    _ => return Ok(None),
                };
                let predicate = if selection == "release" { "path='release.rel'".to_owned() }
                    else if task == "primary" { "path='task.rel'".to_owned() }
                    else { format!("path='tasks/{task}.rel'") };
                let (head, documents) = store_rows(&launch, "encounter/north-river-plan/1", &predicate)?;
                if record["revision"]["store"] != head { return Ok(None); }
                let Some(document) = documents.values().next() else { return Ok(None); };
                let value = rel::decode(document, kind)?;
                let receipt = match name {
                    "plan-approval.rel" => &value["approval"],
                    "employee-import.rel" => &value["import"]["receipt"],
                    _ => &value["receipt"],
                };
                rel::encode(receipt, decision_kind)?.into_bytes()
            }
        }
        Provider::ScheduledReceipts => {
            let root = source.location.resolve()?.canonicalize()?;
            read(&mounted(&root, path)?, MAX_RUN_RECEIPT)?
        }
        Provider::Game => return Ok(None),
    };
    if rel::hash(&contents) != pin { return Ok(None); }
    let mut contents = String::from_utf8(contents)?;
    let relations = if path.ends_with(".rel") { rel_view(&contents, filter).ok() } else { None };
    const EXCERPT: usize = 4096;
    if contents.len() > EXCERPT {
        contents.truncate(contents.floor_char_boundary(EXCERPT));
        contents.push_str("\n…");
    }
    Ok(Some((contents, relations)))
}

fn admitted_view(policy: &IndexPolicy, sources: &[Source], cached: &Value, requested: &Value) -> Result<Value> {
    let roots = requested["roots"].as_array().filter(|roots| roots.len() <= 7)
        .ok_or_else(|| fail("invalid file index view request"))?;
    let selected = requested["file"].as_str().filter(|file| sha(file).is_ok());
    let filter = requested["relFilter"].as_str().filter(|filter| policy.rel_filter(filter)).unwrap_or_default();
    let mut view = serde_json::Map::new();
    for source in sources {
        let record = &cached["providers"][&source.id];
        if !fresh_record(source, record) { continue; }
        let Some(collections) = record["collections"].as_array() else { continue; };
        if !collections.iter().any(|row| roots.contains(&row["root"])) { continue; }
        let north = if source.provider == Provider::NorthRiver {
            current_north_evidence(source, record).unwrap_or(Value::Null)
        } else { Value::Null };
        let allowed = policy.decide(json!({"operation":"collections","provider":source.provider.name(),
            "roots":roots,"collections":collections,"north":north}))?;
        for collection in &allowed {
            let root = text(collection,"root")?;
            let permission = text(collection,"label")?;
            let rows = [("folders", true), ("files", false)].into_iter().flat_map(|(key, folder)|
                record[key].as_array().into_iter().flatten()
                    .filter(move |row| row["root"] == collection["root"])
                    .map(move |row| {
                        let mut view = view_row(row, folder, permission)?;
                        if !folder && let Some(kind) = viewer_type(source.provider, row) {
                            view["viewer"] = json!(kind);
                        }
                        if !folder && source.provider == Provider::ScheduledReceipts {
                            let execution = &row["execution"];
                            view["name"] = json!(format!("{} · {} AWST", text(execution, "service")?, text(execution, "started")?));
                            view["execution"] = execution.clone();
                        }
                        if !folder && selected.is_some_and(|id| view["id"] == id)
                            && let Ok(Some((contents, relations))) = preview(source, record, row, filter) {
                            view["text"] = json!(contents);
                            if let Some(relations) = relations { view["rel"] = relations; }
                        }
                        Ok(view)
                    })).collect::<Result<Vec<_>>>()?;
            if view.insert(root.to_owned(), json!(rows)).is_some() {
                return Err(fail("duplicate file index collection binding"));
            }
        }
    }
    Ok(Value::Object(view))
}

fn fresh_record(source: &Source, record: &Value) -> bool {
    record["binding"] == source.binding && record["status"] == "indexed"
        && record["lastSuccessfulRefresh"].as_str().and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
            .is_some_and(|time| {
                let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now());
                (0..=180).contains(&now.signed_duration_since(time).num_seconds())
            })
}

pub(crate) const MAX_MOVIE: u64 = MAX_FILE;

fn movie_range(range: &str, length: usize) -> Option<(usize, usize)> {
    let (first, last) = range.strip_prefix("bytes=")?.split_once('-')?;
    if length == 0 { return None; }
    if first.is_empty() {
        let suffix = last.parse::<usize>().ok()?;
        return (suffix > 0).then(|| (length.saturating_sub(suffix), length - 1));
    }
    let start = first.parse::<usize>().ok()?;
    let end = if last.is_empty() { length - 1 } else { last.parse::<usize>().ok()?.min(length - 1) };
    (start <= end).then_some((start, end))
}

fn send_movie(policy: &IndexPolicy, stream: &mut UnixStream, sources: &[Source], cached: &Value, request: &Value) -> Result<()> {
    let Some(id) = request["media"].as_str().filter(|id| sha(id).is_ok()) else { return Ok(()); };
    let range = request["range"].as_str().unwrap_or_default();
    for source in sources {
        let roots = policy.decide(json!({"operation":"media","provider":source.provider.name()}))?;
        if roots.is_empty() { continue; }
        let record = &cached["providers"][&source.id];
        if !fresh_record(source, record) { continue; }
        for row in record["files"].as_array().into_iter().flatten() {
            let path = text(row, "path")?;
            let Some(mime) = movie_type(path) else { continue; };
            let root = text(row,"root")?;
            if !roots.contains(&row["root"]) || rel::hash(format!("{root}/{path}")) != id { continue; }
            let directory = source.location.resolve()?.canonicalize()?;
            let bytes = read(&mounted(&directory, path)?, MAX_MOVIE)?;
            if row["sha256"] != rel::hash(&bytes) { return Ok(()); }
            let valid = match mime {
                "video/mp4" => bytes.get(4..8) == Some(b"ftyp"),
                _ => bytes.starts_with(b"\x1a\x45\xdf\xa3"),
            };
            if !valid { return Ok(()); }
            let total = bytes.len();
            let bounds = if range.is_empty() { Some((0, total - 1)) } else { movie_range(range, total) };
            let Some((start, end)) = bounds else {
                writeln!(stream, "{}", json!({"status":416,"total":total}))?;
                return Ok(());
            };
            let status = if range.is_empty() { 200 } else { 206 };
            writeln!(stream, "{}", json!({"status":status,"mime":mime,"total":total,"start":start,"end":end}))?;
            stream.write_all(&bytes[start..=end])?;
            return Ok(());
        }
    }
    Ok(())
}

pub(crate) fn serve(path: &Path, cache: &Path, socket: &Path) -> Result<()> {
    let policy = IndexPolicy::load()?;
    let directory = private_directory(cache)?;
    config(&policy, path)?;
    let parent = socket.parent().filter(|path| path.is_absolute()).ok_or_else(|| fail("expected an absolute file index socket path"))?;
    let metadata = parent.symlink_metadata()?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o027 != 0 {
        return Err(fail("file index socket parent must be private to the indexer and its trusted reader group"));
    }
    match socket.symlink_metadata() {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == uid => {
            match UnixStream::connect(socket) {
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => fs::remove_file(socket)?,
                _ => return Err(fail("file index socket is already in use")),
            }
        }
        Ok(_) => return Err(fail("refusing to replace file index socket path")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let result = (|| -> Result<()> {
            let timeout = Some(Duration::from_secs(3));
            stream.set_read_timeout(timeout)?;
            stream.set_write_timeout(timeout)?;
            let mut request = String::new();
            BufReader::new((&stream).take(2048)).read_line(&mut request)?;
            if !request.ends_with('\n') { return Err(fail("invalid file index view request")); }
            let sources = config(&policy, path)?;
            let cached = snapshot(&directory)?;
            let request: Value = serde_json::from_str(&request)?;
            if request.get("media").is_some() { return send_movie(&policy, &mut stream, &sources, &cached, &request); }
            let value = admitted_view(&policy, &sources, &cached, &request)?;
            let body = serde_json::to_vec(&value)?;
            if body.len() as u64 > MAX_VIEW { return Err(fail("file index view exceeds the response limit")); }
            stream.write_all(&body)?;
            Ok(())
        })();
        if let Err(error) = result { eprintln!("file index view: {error}"); }
        release_index_scratch();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Result<Self> {
            let directory = std::env::temp_dir().join(format!("encounter-index-{}",nonce()?));
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
            Ok(Self(directory))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn user_unit_policy_limits_provider_and_systemd_service_name() -> Result<()> {
        let policy = IndexPolicy::load()?;
        for provider in [Provider::Game, Provider::NorthRiver] {
            assert!(policy.admit_user_unit(provider, "appdev-gateway_1.service")?);
            for unit in ["../other.service", "external.timer", "unit@template.service", "unit.service\n", ".service"] {
                assert!(!policy.admit_user_unit(provider, unit)?);
            }
            assert!(!policy.admit_user_unit(provider, &format!("{}.service", "a".repeat(129)))?);
        }
        for provider in [Provider::Home, Provider::Kernel, Provider::ScheduledReceipts] {
            assert!(!policy.admit_user_unit(provider, "appdev-gateway.service")?);
        }
        Ok(())
    }

    #[test]
    fn read_policy_requires_current_ownership_and_exact_collection_binding() -> Result<()> {
        let policy = IndexPolicy::load()?;
        let mut request = json!({
            "operation":"collections", "provider":"north-river", "roots":[NORTH_SOURCE],
            "collections":[{"root":NORTH_SOURCE, "permissions":{"metadataAndRead":"north-river-project-owner"},
                "ownership":{"owner":"owner-a"}}],
            "north":{"projectOwner":"owner-a","taskOwner":"owner-a","taskPhase":"draft"}
        });
        let decide = |input: &Value| policy.decide(input.clone());
        assert_eq!(decide(&request)?, [json!({"root":NORTH_SOURCE,"label":"North River project owner"})]);
        for (field, denied) in [("taskOwner", json!("owner-b")), ("taskPhase", json!("empty")), ("taskPhase", Value::Null)] {
            let mut changed = request.clone();
            changed["north"][field] = denied;
            assert!(decide(&changed)?.is_empty());
        }
        request["collections"][0]["permissions"]["metadataAndRead"] = json!("platform-steward");
        assert!(decide(&request)?.is_empty());
        assert!(decide(&json!({"operation":"media","provider":"north-river"}))?.is_empty());
        assert_eq!(decide(&json!({"operation":"media","provider":"kernel-release"}))?, [json!(KERNEL_RELEASES)]);
        let published = decide(&json!({"operation":"publish","provider":"kernel-release","owner":null,"steward":null}))?;
        assert_eq!(decide(&json!({"operation":"collections","provider":"kernel-release",
            "roots":[KERNEL_RELEASES],"collections":published,"north":null}))?,
            [json!({"root":KERNEL_RELEASES,"label":"Platform steward"})]);
        Ok(())
    }

    #[test]
    fn release_sizes_are_scoped_and_last_valid_snapshot_survives_failed_refresh() -> Result<()> {
        let policy = IndexPolicy::load()?;
        let scratch = Scratch::new()?;
        let mounted_release = scratch.0.join("release");
        fs::create_dir_all(mounted_release.join("programmes"))?;
        let cache = private_directory(&scratch.0.join("cache"))?;
        let programme = b"four";
        let pin = rel::hash(programme);
        let runtime = rel::hash(b"runtime");
        fs::write(mounted_release.join("encounter"), b"runtime")?;
        fs::write(mounted_release.join("programmes/one.rel"), programme)?;
        fs::write(mounted_release.join("programmes/two.rel"), programme)?;
        let manifest = format!("(\"package\", \"contract\", \"encounter/gated-release/1\")\n(\"package\", \"runtimeSha256\", \"{runtime}\")\n(\"artifact\", \"encounter\", \"{runtime}\")\n(\"artifact\", \"programmes/one.rel\", \"{pin}\")\n");
        fs::write(mounted_release.join("package-receipt.rel"), format!("{manifest}(\"artifact\", \"programmes/two.rel\", \"{pin}\")\n"))?;
        let sources = [Source { id:"home".into(),provider:Provider::Home,location:Location::Path(mounted_release.clone()),
            steward:Some("test-steward".into()),binding:"test-binding".into() }];
        let snapshot = || rel::decode(&fs::read_to_string(cache.join("index.rel"))?, SNAPSHOT);
        assert!(refresh(&policy,&sources,&cache)?);
        let initial = snapshot()?;
        let folders = initial["providers"]["home"]["folders"].as_array().unwrap();
        let folder = folders.iter().find(|folder| folder["path"] == "Platform/Releases/Home/programmes").unwrap();
        assert_eq!(folder["logicalBytes"],8);
        assert_eq!(folder["uniqueContentBytes"],4);
        assert_eq!(folder["ownership"]["steward"],"test-steward");
        assert_eq!(folder["permissions"]["metadataAndRead"],"platform-steward");
        fs::write(mounted_release.join("programmes/two.rel"), b"changed")?;
        assert!(!refresh(&policy,&sources,&cache)?);
        let stale = snapshot()?;
        assert_eq!(stale["providers"]["home"]["status"],"stale");
        assert_eq!(stale["providers"]["home"]["folders"],initial["providers"]["home"]["folders"]);
        fs::write(mounted_release.join("package-receipt.rel"), manifest)?;
        assert!(refresh(&policy,&sources,&cache)?);
        let refreshed = snapshot()?;
        let folders = refreshed["providers"]["home"]["folders"].as_array().unwrap();
        let folder = folders.iter().find(|folder| folder["path"] == "Platform/Releases/Home/programmes").unwrap();
        assert_eq!(folder["fileCount"],1);
        assert_eq!(folder["logicalBytes"],4);
        Ok(())
    }

    #[test]
    fn rel_view_filters_beyond_the_visible_rows_and_preserves_polarity() -> Result<()> {
        let mut source = String::new();
        for i in 0..105 {
            source.push_str(&format!("(\"item-{i}\", \"type\", \"sample\")\n"));
        }
        source.push_str("(\"last\", \"status\", \"Excluded\", \"is-not\")\n");
        let initial = rel_view(&source, "")?;
        assert_eq!(initial["total"], 106);
        assert_eq!(initial["rows"].as_array().unwrap().len(), 100);
        let filtered = rel_view(&source, "EXCLUDED")?;
        assert_eq!(filtered["matches"], 1);
        assert_eq!(filtered["rows"][0]["polarity"], "is-not");
        assert!(rel_view("(\"incomplete\"", "").is_err());
        Ok(())
    }

    #[test]
    fn pinned_receipt_exports_use_exact_rel_bytes_and_reject_changed_decisions() -> Result<()> {
        let mut decision = json!({"reviewer":"author","revision":9,"outcome":"plan-approved"});
        let kind = "NorthRiverPlanDecision";
        decision["sha256"] = json!(rel::hash(rel::encode(&decision,kind)?));
        let mut files = Vec::new();
        add_receipt(&mut files,"Apps/North River/Receipts","primary/plan-approval.rel",&decision,kind)?;
        assert_eq!(files[0]["bytes"], rel::encode(&decision,kind)?.len());
        assert_eq!(files[0]["author"], "author");
        decision["revision"] = json!(10);
        assert!(add_receipt(&mut files,"Apps/North River/Receipts","primary/plan-approval.rel",&decision,kind).is_err());
        Ok(())
    }
}
