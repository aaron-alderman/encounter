use crate::{Result, appdev_host_process::{Scratch, Supervisor, interruption, rename_new_path}, application::validate_path, fail, image, package,
    process::{Meter, Programme}, rel::{self, Facts}};
use flate2::{Compression, GzBuilder, write::GzEncoder};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet, fs::{self, File, OpenOptions}, io::{self, Read, Write},
    os::{fd::AsRawFd, unix::{ffi::OsStrExt, fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt}}},
    path::{Path, PathBuf}, process::{Command, Stdio}, thread, time::{Duration, Instant},
};

#[path = "guard_promotion.rs"]
mod guard_promotion;
pub use guard_promotion::promote_guards;

const PLATFORM: &str = "linux-x86_64";
const GUARDS: [&str; 3] = ["dependency-guard.encounter", "occurrence-guard.encounter", "review-guard.encounter"];
const GUARD_LIBRARY: &str = "applications/encounter-libraries/guards";
const SOURCE_LIMIT: u64 = 2 * 1024 * 1024;
const IMAGE_LIMIT: u64 = 64_000_000;
const ARCHIVE_LIMIT: u64 = 1 << 30;
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy)]
pub enum ReleaseLayout { Aggregate, Platform }

fn policy() -> Result<Programme> {
    let source = include_str!("release_package.encounter").to_owned();
    Programme::admit_entries(&[source], &["package.plan", "package.runtime", "package.executable", "package.loader",
        "package.guardVersion", "package.guardRelease", "package.guards", "package.guardedApplications",
        "package.guardPromotion", "package.guardImageReady", "package.guardLock",
        "package.manifest", "package.temple3Inputs"],
        &BTreeSet::from(["text.matches", "text.match", "text.split", "text.join", "record.entries",
            "value.sort", "value.type", "scalar.quoteValue"]), &mut Meter::new(20_000_000))
}

fn run(policy: &Programme, entry: &str, input: Value) -> Result<Value> {
    policy.run(entry, input, &mut Meter::new(20_000_000))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field].as_str().ok_or_else(|| fail(format!("Invalid release policy field {field}")))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    value[field].as_array().map(Vec::as_slice).ok_or_else(|| fail(format!("Invalid release policy field {field}")))
}

fn read(path: &Path, limit: u64) -> Result<String> {
    let mut body = String::new();
    File::open(path)?.take(limit + 1).read_to_string(&mut body)?;
    if body.len() as u64 > limit { return Err(fail(format!("Release input exceeds its size limit: {}", path.display()))); }
    Ok(body)
}

fn hash(path: &Path, limit: u64) -> Result<String> {
    let mut digest = Sha256::new();
    let length = io::copy(&mut File::open(path)?.take(limit + 1), &mut digest)?;
    if length > limit { return Err(fail(format!("Release artifact exceeds its size limit: {}", path.display()))); }
    Ok(hex::encode(digest.finalize()))
}

fn write(path: &Path, body: &str, mode: u32) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn verify_loader(policy: &Programme, projection: &Path, shared_owner: Option<&Path>) -> Result<()> {
    let name = projection.file_stem().and_then(|name| name.to_str()).ok_or_else(|| fail("Invalid loader projection name"))?;
    let adjacent = projection.with_file_name(format!("{name}.loader.encounter"));
    let owner = shared_owner.unwrap_or(&adjacent);
    let source = read(&owner, SOURCE_LIMIT).map_err(|error| fail(format!("{}: {error}", owner.display())))?;
    let declaration = Programme::static_loader(&source, &mut Meter::new(20_000_000))
        .map_err(|error| fail(format!("{}: {error}", owner.display())))?;
    let expected = run(policy, "package.loader", declaration)
        .map_err(|error| fail(format!("{}: {error}", owner.display())))?;
    if expected.as_str() != Some(read(projection, SOURCE_LIMIT)?.as_str()) {
        return Err(fail(format!("Generated loader REL differs from Encounter: {}", projection.display())));
    }
    Ok(())
}

fn check_loaders(policy: &Programme, applications: &Path, runtime: &Path, plan: &Value) -> Result<()> {
    let mut paths = array(plan, "loaders")?.iter().map(|path| path.as_str().map(|path| applications.join(path))
        .ok_or_else(|| fail("Invalid loader path"))).collect::<Result<BTreeSet<_>>>()?;
    let all_profiles = plan["allProfiles"] == true;
    if all_profiles {
        let profiles = runtime.join("profiles");
        for entry in fs::read_dir(&profiles)? {
            let name = entry?.file_name().into_string().map_err(|_| fail("Invalid platform loader name"))?;
            if name.ends_with(".rel") { paths.insert(profiles.join(name)); }
            else if let Some(stem) = name.strip_suffix(".loader.encounter") { paths.insert(profiles.join(format!("{stem}.rel"))); }
        }
    }
    for root in array(plan, "productRoots")? {
        let root = root.as_str().ok_or_else(|| fail("Invalid loader product root"))?;
        let previous = paths.len();
        for entry in fs::read_dir(applications.join(root))? {
            let entry = entry?;
            let path = entry.path().join("application.rel");
            if entry.file_type()?.is_dir() && (all_profiles || path.is_file()) { paths.insert(path); }
        }
        if paths.len() == previous { return Err(fail(format!("No release product loaders in {root}"))); }
    }
    for path in paths { verify_loader(policy, &path, None)?; }
    let platform = applications.parent().ok_or_else(|| fail("Missing platform source directory"))?;
    let owner = platform.join("shared/authoring/application.loader.encounter");
    for path in array(plan, "sharedLoaders")? {
        let path = path.as_str().ok_or_else(|| fail("Invalid shared loader path"))?;
        verify_loader(policy, &applications.join(path), Some(&owner))?;
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
struct CheckedGuards { version: String, lock: String, files: Map<String, Value> }

fn canonical_guard_files(release: &Path) -> Result<Value> {
    let mut canonical = Map::new();
    for guard in GUARDS {
        canonical.insert(guard.to_owned(), json!(hash(&release.join(guard), SOURCE_LIMIT)?));
    }
    Ok(json!({"canonical":canonical,"manifest":read(&release.join("SHA256SUMS"), SOURCE_LIMIT)?}))
}

fn guard_inputs(policy: &Programme, guard_root: &Path, root: &Path, declaration: &str, guards: &[Value]) -> Result<CheckedGuards> {
    let declaration_file = root.join(declaration);
    let lock = read(&declaration_file.with_file_name("guards.sha256"), SOURCE_LIMIT)?;
    let version = run(policy, "package.guardVersion", json!(lock))?;
    let version = version.as_str().ok_or_else(|| fail("Invalid guard version"))?;
    let release = guard_root.join(version);
    let mut request = canonical_guard_files(&release)?;
    let mut vendored = Map::new();
    for guard in guards {
        let guard = guard.as_str().filter(|name| GUARDS.contains(name)).ok_or_else(|| fail("Invalid release guard name"))?;
        let path = format!("source/{guard}");
        vendored.insert(path.clone(), json!(hash(&root.join(path), SOURCE_LIMIT)?));
    }
    let source = read(&declaration_file, SOURCE_LIMIT)?;
    let facts = Facts::parse(&source)?;
    request["version"] = json!(version);
    request["lock"] = json!(lock);
    request["modules"] = json!(facts.values("application","module"));
    request["guards"] = json!(guards);
    request["vendored"] = json!(vendored);
    let verified = run(policy, "package.guards", request)?;
    let mut verified = verified.as_object().cloned().ok_or_else(|| fail("Invalid release guard decision"))?;
    verified.insert(declaration.to_owned(), json!(rel::hash(source)));
    Ok(CheckedGuards { version: version.to_owned(), lock, files: verified })
}

fn check_image(path: &Path, pin: &str, runtime_pin: &str, declaration: &str, sources: &Map<String, Value>) -> Result<()> {
    let body = read(path, IMAGE_LIMIT)?;
    if rel::hash(&body) != pin { return Err(fail("Compiler image differs from its reported pin")); }
    if sources.is_empty() { return Ok(()); }
    let image = rel::decode(&body, "EncounterApplicationImage")?;
    if image["declaration"] != declaration || image["runtimeSha256"] != runtime_pin {
        return Err(fail("Image uses a different runtime or application declaration"));
    }
    for (file, digest) in sources {
        let capture = &image["files"][file];
        if &capture["sha256"] != digest || capture["text"].as_str().is_none_or(|body| digest.as_str() != Some(&rel::hash(body))) {
            return Err(fail(format!("Image source differs from the verified release input: {file}")));
        }
    }
    Ok(())
}

fn binary_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command.stdin(Stdio::null()).env_clear().env("LC_ALL", "C");
    command
}

struct Compiler<'a> { binary: &'a Path, pin: String, in_process: bool }

impl Compiler<'_> {
    fn check_package(&self, supervisor: &mut Supervisor, root: &Path) -> Result<()> {
        if self.in_process { return package::check(root); }
        supervisor.capture("application package check", binary_command(self.binary).arg("check-package").arg(root), TIMEOUT, 4096)?;
        Ok(())
    }

    fn build(&self, supervisor: &mut Supervisor, root: &Path, declaration: &str, output: &Path,
        sources: &Map<String, Value>) -> Result<String> {
        supervisor.check()?;
        let pin = if self.in_process {
            image::build(root, declaration, output)?
        } else {
            let pin = supervisor.capture("compile release image",
                binary_command(self.binary).arg("build").arg(root).arg(declaration).arg(output), TIMEOUT, 4096)?;
            std::str::from_utf8(&pin)?.trim().to_owned()
        };
        check_image(output, &pin, &self.pin, declaration, sources)?;
        Ok(pin)
    }
}

fn build_images(supervisor: &mut Supervisor, policy: &Programme, applications: &Path, guard_root: &Path, package: &Path,
    compiler: &Compiler<'_>, plan: &Value) -> Result<Vec<Value>> {
    let mut images = Vec::new();
    for entry in array(plan, "images")? {
        let app = text(entry, "app")?;
        let declaration = text(entry, "declaration")?;
        validate_path(declaration, "rel")?;
        let root = applications.join(text(entry, "root")?);
        let relative = text(entry, "image")?;
        validate_path(relative, "rel")?;
        supervisor.check()?;
        compiler.check_package(supervisor, &root)?;
        let guards = array(entry, "guards")?;
        let inputs = if guards.is_empty() { Map::new() } else { guard_inputs(policy, guard_root, &root, declaration, guards)?.files };
        let pin = compiler.build(supervisor, &root, declaration, &package.join(relative), &inputs)
            .map_err(|error| fail(format!("{app}: {error}")))?;
        images.push(json!({"app":app,"path":relative,"pin":pin}));
    }
    Ok(images)
}

fn stage_compiler<'a>(supervisor: &mut Supervisor, policy: &Programme, binary: &Path, staged_binary: &'a Path,
    version: &str, binary_pin: Option<&str>) -> Result<Compiler<'a>> {
    let binary = binary.canonicalize()?;
    crate::package::require_native_runtime(&binary)?;
    let source = package::open_artifact(&File::open("/")?, binary.strip_prefix("/")?)?;
    let mut staged = OpenOptions::new().write(true).create_new(true).mode(0o755).open(staged_binary)?;
    staged.set_permissions(fs::Permissions::from_mode(0o755))?;
    if io::copy(&mut source.take(IMAGE_LIMIT + 1), &mut staged)? > IMAGE_LIMIT {
        return Err(fail("Release runtime exceeds its size limit"));
    }
    staged.sync_all()?;
    drop(staged);
    crate::package::require_native_runtime(staged_binary)?;
    let runtime_pin = hash(staged_binary, IMAGE_LIMIT)?;
    let current = image::runtime_pin()?;
    if run(policy, "package.executable", json!({"version":version,"pin":runtime_pin,"running":current,"supplied":binary_pin}))? != true {
        return Err(fail("Supply an independent SHA-256 pin for a separate release runtime"));
    }
    let running_binary = current == runtime_pin;
    let (reported, version_line) = if running_binary { (true, format!("encounter {}", env!("CARGO_PKG_VERSION"))) } else {
        let (status, version_line) = supervisor.capture_status("release version",
            binary_command(staged_binary).arg("--version").stderr(Stdio::null()), Duration::from_secs(5), 4096)?;
        (status.success(), String::from_utf8(version_line)?.trim_end_matches('\n').to_owned())
    };
    if run(policy, "package.runtime", json!({"reported":reported,"version":version,"pin":runtime_pin,"versionLine":version_line}))? != true {
        return Err(fail("Release binary must report its matching version or match the preserved 0.1.0 baseline"));
    }
    Ok(Compiler { binary: staged_binary, pin: runtime_pin, in_process: running_binary })
}

fn make_archive(stage: &Path, name: &str, archive: &Path) -> Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(archive)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let root = File::open(stage)?;
    let mut tar = Archive { gzip:GzBuilder::new().mtime(0).operating_system(3).write(file, Compression::default()),
        bytes:0, deadline:Instant::now() + TIMEOUT };
    tar.member(stage, &root, Path::new(name))?;
    let end = (tar.bytes + 1024).next_multiple_of(10240);
    tar.write(&[0; 11264][..usize::try_from(end-tar.bytes)?])?;
    tar.gzip.finish()?.sync_all()?;
    Ok(())
}

struct Archive {
    gzip: GzEncoder<File>,
    bytes: u64,
    deadline: Instant,
}

impl Archive {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if interruption().is_some() { return Err(fail("Release archive interrupted")); }
        if Instant::now() >= self.deadline { return Err(fail("Release archive timed out")); }
        self.bytes = self.bytes.checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= ARCHIVE_LIMIT).ok_or_else(|| fail("Release archive exceeds its size limit"))?;
        self.gzip.write_all(bytes)?;
        Ok(())
    }

    fn header(&mut self, name: &[u8], mode: u32, length: u64, kind: u8) -> Result<()> {
        let mut header = [0; 512];
        let prefix = &name[..name.len().min(100)];
        header[..prefix.len()].copy_from_slice(prefix);
        header[100..107].copy_from_slice(format!("{:07o}", mode & 0o7777).as_bytes());
        header[108..115].fill(b'0');
        header[116..123].fill(b'0');
        header[124..135].copy_from_slice(format!("{length:011o}").as_bytes());
        header[136..147].fill(b'0');
        header[148..156].fill(b' ');
        header[156] = kind;
        header[257..265].copy_from_slice(b"ustar  \0");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
        header[154] = 0;
        self.write(&header)
    }

    fn member(&mut self, stage: &Path, root: &File, relative: &Path) -> Result<()> {
        let path = stage.join(relative);
        let metadata = path.symlink_metadata()?;
        let mut name = relative.as_os_str().as_bytes().to_vec();
        let directory = metadata.is_dir();
        if directory { name.push(b'/'); }
        if !directory && !metadata.is_file() { return Err(fail("Release archive member must be a regular file or directory")); }
        if name.len() > 100 {
            let length = name.len() + 1;
            self.header(b"././@LongLink", 0o644, length as u64, b'L')?;
            self.write(&name)?;
            self.write(&[0; 512][..1 + (512 - length % 512) % 512])?;
        }
        if directory {
            self.header(&name, metadata.permissions().mode(), 0, b'5')?;
            let mut entries = fs::read_dir(&path)?.map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<io::Result<Vec<_>>>()?;
            entries.sort_unstable();
            for entry in entries { self.member(stage, root, &relative.join(entry))?; }
            return Ok(());
        }
        let mut file = package::open_artifact(root, relative)?;
        let metadata = file.metadata()?;
        let length = metadata.len();
        if length > ARCHIVE_LIMIT { return Err(fail("Release archive member exceeds its size limit")); }
        self.header(&name, metadata.permissions().mode(), length, b'0')?;
        let mut left = length;
        let mut buffer = [0; 64 * 1024];
        while left != 0 {
            let size = usize::try_from(left.min(buffer.len() as u64))?;
            file.read_exact(&mut buffer[..size])?;
            self.write(&buffer[..size])?;
            left -= size as u64;
        }
        if file.read(&mut buffer[..1])? != 0 { return Err(fail("Release archive member changed while reading")); }
        self.write(&[0; 512][..((512 - length % 512) % 512) as usize])
    }
}

fn publish(supervisor: &mut Supervisor, output: &Path, stage: &Path, archive: &str) -> Result<PathBuf> {
    let directory = File::open(output)?;
    loop {
        supervisor.check()?;
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 { break; }
        let error = io::Error::last_os_error();
        if !matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) { return Err(error.into()); }
        thread::sleep(Duration::from_millis(25));
    }
    let checksum = format!("{archive}.sha256");
    let destination = output.join(archive);
    let checksum_destination = output.join(&checksum);
    fs::hard_link(stage.join(checksum), &checksum_destination)?;
    if let Err(error) = fs::hard_link(stage.join(archive), &destination) {
        fs::remove_file(checksum_destination)?;
        return Err(error.into());
    }
    directory.sync_all()?;
    Ok(destination)
}

pub fn build(layout: ReleaseLayout, runtime: &Path, version: &str, binary: &Path, output: &Path, binary_pin: Option<&str>) -> Result<()> {
    let mut supervisor = Supervisor::new();
    println!("{}", build_archive(&mut supervisor, layout, runtime, version, binary, output, binary_pin)?.display());
    Ok(())
}

fn build_archive(supervisor: &mut Supervisor, layout: ReleaseLayout, runtime: &Path, version: &str, binary: &Path,
    output: &Path, binary_pin: Option<&str>) -> Result<PathBuf> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) { return Err(fail("Expected an x86-64 Linux host")); }
    let runtime = runtime.canonicalize()?;
    let applications = runtime.parent().ok_or_else(|| fail("Missing release applications directory"))?;
    let (layout_name, catalogue, guard_root) = match layout {
        ReleaseLayout::Aggregate => ("aggregate", "release-applications.rel", applications.join("encounter-libraries/guards")),
        ReleaseLayout::Platform => {
            let projects = applications.ancestors().nth(2).ok_or_else(|| fail("Missing the shared projects directory"))?;
            ("platform", "release-applications-platform.rel", projects.join(GUARD_LIBRARY))
        }
    };
    let policy = policy()?;
    let catalogue = Facts::parse(&read(&runtime.join(catalogue), SOURCE_LIMIT)?)?;
    let plan = run(&policy, "package.plan", json!({"version":version,"platform":PLATFORM,"layout":layout_name,"catalogue":catalogue.0}))?;
    check_loaders(&policy, applications, &runtime, &plan)?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(output)?;
    let output = output.canonicalize()?;
    let name = text(&plan, "name")?;
    let archive = format!("{name}.tar.gz");
    for path in [output.join(&archive), output.join(format!("{archive}.sha256"))] {
        match path.symlink_metadata() {
            Ok(_) => return Err(fail("Release output already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let stage = Scratch::create(&output, ".package-")?;
    let package = stage.path().join(name);
    for path in [&package, &package.join("bin"), &package.join("images")] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    let staged_binary = package.join("bin/encounter");
    let compiler = stage_compiler(supervisor, &policy, binary, &staged_binary, version, binary_pin)?;
    let images = build_images(supervisor, &policy, applications, &guard_root, &package, &compiler, &plan)?;
    let mut specs = Vec::new();
    if !array(&plan, "specs")?.is_empty() {
        let directory = package.join("spec");
        fs::create_dir(&directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
        for path in array(&plan, "specs")? {
            let path = path.as_str().ok_or_else(|| fail("Invalid release specification"))?;
            let body = read(&runtime.join(path), SOURCE_LIMIT)?;
            write(&package.join(path), &body, 0o644)?;
            specs.push(json!({"path":path,"pin":rel::hash(body)}));
        }
    }
    let manifest = run(&policy, "package.manifest", json!({"version":version,"platform":PLATFORM,
        "runtimePin":compiler.pin,"images":images,"specs":specs}))?;
    write(&package.join("release.rel"), manifest.as_str().ok_or_else(|| fail("Invalid release manifest"))?, 0o644)?;
    write(&package.join("README.md"), include_str!("release-package-readme.md"), 0o644)?;
    compiler.check_package(supervisor, &package)?;
    let path = stage.path().join(&archive);
    make_archive(stage.path(), name, &path)?;
    let pin = hash(&path, ARCHIVE_LIMIT)?;
    write(&stage.path().join(format!("{archive}.sha256")), &format!("{pin}  {archive}\n"), 0o600)?;
    publish(supervisor, &output, stage.path(), &archive)
}

fn guarded_application<'a>(applications: &'a [Value], name: &str) -> Result<&'a Value> {
    applications.iter().find(|app| app["name"].as_str() == Some(name)).ok_or_else(|| fail("Unknown guarded application"))
}

pub fn check_guard_pins(projects: &Path, name: Option<&str>) -> Result<()> {
    let projects = projects.canonicalize()?;
    let policy = policy()?;
    let applications = run(&policy, "package.guardedApplications", Value::Null)?;
    let all = applications.as_array().ok_or_else(|| fail("Expected guarded application declarations"))?;
    let selected = match name {
        Some(name) => std::slice::from_ref(guarded_application(all, name)?),
        None => all.as_slice(),
    };
    let guard_root = projects.join(GUARD_LIBRARY);
    for entry in selected {
        let root = projects.join(text(entry, "directory")?);
        let declaration = text(entry, "declaration")?;
        let guards = array(entry, "guards")?;
        let checked = guard_inputs(&policy, &guard_root, &root, declaration, guards)?;
        println!("{} encounter-guards {}", text(entry, "name")?, checked.version);
    }
    Ok(())
}

pub fn build_guarded_image(projects: &Path, name: &str, version: &str, binary: &Path, output: &Path,
    binary_pin: Option<&str>) -> Result<()> {
    let projects = projects.canonicalize()?;
    let policy = policy()?;
    let applications = run(&policy, "package.guardedApplications", Value::Null)?;
    let all = applications.as_array().ok_or_else(|| fail("Expected guarded application declarations"))?;
    let entry = guarded_application(all, name)?;
    let root = projects.join(text(entry, "directory")?);
    let declaration = text(entry, "declaration")?;
    package::check(&root)?;
    let checked = guard_inputs(&policy, &projects.join(GUARD_LIBRARY), &root, declaration, array(entry, "guards")?)?;
    package::check_path(output)?;
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new(".")).canonicalize()?;
    let output = parent.join(output.file_name().ok_or_else(|| fail("Expected a guarded image filename"))?);
    let mut supervisor = Supervisor::new();
    let scratch = Scratch::create(&parent, ".guarded-image-")?;
    let staged_binary = scratch.path().join("encounter");
    let compiler = stage_compiler(&mut supervisor, &policy, binary, &staged_binary, version, binary_pin)?;
    let candidate = scratch.path().join("image.rel");
    let pin = compiler.build(&mut supervisor, &root, declaration, &candidate, &checked.files)?;
    supervisor.check()?;
    fs::hard_link(candidate, output)?;
    File::open(parent)?.sync_all()?;
    println!("{pin}");
    Ok(())
}

pub fn stage_temple3(runtime: &Path, intake: &Path) -> Result<()> {
    let mut supervisor = Supervisor::new();
    let runtime = runtime.canonicalize()?;
    let platform = runtime.ancestors().nth(2).ok_or_else(|| fail("Expected a platform runtime directory"))?;
    let research = platform.join("research");
    fs::create_dir_all(&research)?;
    if research.canonicalize()? != research { return Err(fail("Expected the platform's own research directory")); }
    let output = research.join("temple3");
    match output.symlink_metadata() {
        Ok(_) => return Err(fail("Temple3 destination already exists. Stage the pinned input in a fresh checkout.")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let input = read(&runtime.join("temple3.sha256"), SOURCE_LIMIT)?;
    let plan = run(&policy()?, "package.temple3Inputs", json!(input))?;
    let intake = intake.canonicalize()?;
    let intake_root = File::open(&intake)?;
    let stage = Scratch::create(&research, ".temple3-")?;
    let mut remaining: u64 = 128 * 1024 * 1024;
    for row in array(&plan, "files")? {
        supervisor.check()?;
        let path = text(row, "path")?;
        let canonical = intake.join(path).canonicalize()?;
        let source = package::open_artifact(&intake_root, canonical.strip_prefix(&intake)
            .map_err(|_| fail("Temple3 input escapes the intake directory"))?)?;
        let mode = source.metadata()?.permissions().mode() & 0o777;
        let target = stage.path().join(path);
        fs::create_dir_all(target.parent().ok_or_else(|| fail("Missing Temple3 staged parent"))?)?;
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&target)?;
        let bytes = io::copy(&mut source.take(remaining + 1), &mut file)?;
        remaining = remaining.checked_sub(bytes).ok_or_else(|| fail("Temple3 intake exceeds its size limit"))?;
        if hash(&target, bytes)? != text(row, "sha256")? {
            return Err(fail(format!("Temple3 input differs from its pinned SHA-256: {path}")));
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
    }
    supervisor.check()?;
    rename_new_path(stage.path(), &output)?;
    File::open(&research)?.sync_all()?;
    println!("Staged verified Temple3 input at {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_release_plan_requires_guarded_product_coordinates() -> Result<()> {
        let policy = policy()?;
        let catalogue = json!([
            ["harborboard", "encounter-work-boards", "products/harborboard/application.rel"],
            ["super-crm", "encounter-portfolio", "products/super-crm/application.rel"]
        ]);
        let input = |catalogue| json!({"version":"0.1.7","platform":PLATFORM,"layout":"platform","catalogue":catalogue});
        let plan = run(&policy, "package.plan", input(catalogue.clone()))?;
        assert_eq!(plan["images"][0]["guards"], json!(["dependency-guard.encounter"]));
        assert_eq!(plan["images"][1]["guards"], json!(["occurrence-guard.encounter","review-guard.encounter"]));
        assert_eq!(plan["sharedLoaders"].as_array().map(Vec::len), Some(3));
        let mut unguarded = catalogue;
        unguarded[1][2] = json!("products/world/application.rel");
        assert!(run(&policy, "package.plan", input(unguarded)).is_err());
        assert!(run(&policy, "package.plan", input(json!([
            ["harborboard", "encounter-work-boards", "products/harborboard/application.rel"]
        ]))).unwrap_err().to_string().contains("missing a required guarded application"));
        let promotion = run(&policy, "package.guardPromotion", json!("1.0.2"))?;
        let steps = array(&promotion, "steps")?;
        assert_eq!(steps.iter().map(|step| step["kind"].as_str().unwrap()).collect::<Vec<_>>(),
            ["baseline", "upgrade", "upgrade", "archive", "archive", "upgrade", "upgrade",
             "rollback", "rollback", "rollback", "rollback"]);
        assert_eq!(steps[2]["application"], "claimipedia");
        assert_eq!(steps[7]["application"], "super-crm");
        assert_eq!(steps[10]["application"], "harborboard");
        Ok(())
    }

    #[test]
    fn loader_projection_requires_the_exact_static_encounter_source() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "release-loader-")?;
        let rel = fixture.path().join("application.rel");
        let source = fixture.path().join("application.loader.encounter");
        let loader = "process-module \"temple/surface-process-module/1\"\n\nprocess loader.declaration:\n  let result = { sections = list({ subject = \"app\"; module = \"source/app.encounter\" }) }\n";
        fs::write(&source, loader)?;
        fs::write(&rel, "(\"app\", \"module\", \"source/app.encounter\")\n")?;
        let policy = policy()?;
        verify_loader(&policy, &rel, None)?;
        fs::write(&rel, "(\"app\", \"module\", \"source/other.encounter\")\n")?;
        assert!(verify_loader(&policy, &rel, None).unwrap_err().to_string().contains("differs"));
        fs::write(&source, format!("{loader}\nprocess hidden:\n  let result = true\n"))?;
        assert!(verify_loader(&policy, &rel, None).unwrap_err().to_string().contains("one static"));
        Ok(())
    }

    #[test]
    fn archive_retains_tar_metadata_and_reproducible_gzip() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "release-archive-")?;
        let root = fixture.path().join("release");
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
        write(&root.join("z"), "file", 0o644)?;
        write(&root.join("a"), "runtime", 0o755)?;
        let first = fixture.path().join("first.gz");
        let second = fixture.path().join("second.gz");
        make_archive(fixture.path(), "release", &first)?;
        make_archive(fixture.path(), "release", &second)?;
        let compressed = fs::read(first)?;
        assert_eq!(compressed, fs::read(second)?);
        assert_eq!(&compressed[..10], &[31, 139, 8, 0, 0, 0, 0, 0, 0, 3]);
        let mut tar = Vec::new();
        flate2::read::GzDecoder::new(compressed.as_slice()).read_to_end(&mut tar)?;
        assert_eq!(tar.len(), 10240);
        assert_eq!(&tar[..8], b"release/");
        assert_eq!(&tar[512..521], b"release/a");
        assert_eq!(&tar[612..620], b"0000755\0");
        assert_eq!(&tar[620..628], b"0000000\0");
        assert_eq!(&tar[1024..1031], b"runtime");
        assert_eq!(&tar[1536..1545], b"release/z");
        assert_eq!(&tar[1636..1644], b"0000644\0");
        std::os::unix::fs::symlink(root.join("a"), root.join("linked"))?;
        assert!(make_archive(fixture.path(), "release", &fixture.path().join("linked.gz")).is_err());
        Ok(())
    }

    #[test]
    fn archive_publish_does_not_replace_an_existing_release() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "release-publish-")?;
        let stage = fixture.path().join("stage");
        let output = fixture.path().join("out");
        fs::create_dir(&stage)?;
        fs::create_dir(&output)?;
        let archive = "encounter-0.1.14-linux-x86_64.tar.gz";
        let checksum = format!("{archive}.sha256");
        fs::write(stage.join(archive), b"new archive")?;
        fs::write(stage.join(&checksum), b"new checksum")?;
        fs::write(output.join(archive), b"retained archive")?;
        let mut supervisor = Supervisor::children();
        assert!(publish(&mut supervisor, &output, &stage, archive).is_err());
        assert_eq!(fs::read(output.join(archive))?, b"retained archive");
        assert!(!output.join(&checksum).exists());
        fs::remove_file(output.join(archive))?;
        publish(&mut supervisor, &output, &stage, archive)?;
        assert_eq!(fs::read(output.join(archive))?, b"new archive");
        assert_eq!(fs::read(output.join(checksum))?, b"new checksum");
        Ok(())
    }
}
