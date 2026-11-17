use super::*;
use crate::{appdev_host_process::nonblocking, http};
use flate2::read::GzDecoder;
use std::{collections::BTreeMap, ffi::OsStr, path::Component};

const ROLES: [&str; 3] = ["authoring", "platform", "claimipedia"];
const PROMOTION_LIMIT: u64 = 256 * 1024 * 1024;

struct App<'a> {
    name: &'a str,
    product: &'a str,
    role: &'a str,
    directory: &'a str,
    declaration: &'a str,
    guards: &'a [Value],
}

impl<'a> App<'a> {
    fn from_plan(entry: &'a Value) -> Result<Self> {
        Ok(Self { name: text(entry, "name")?, product: text(entry, "app")?, role: text(entry, "compiler")?,
            directory: text(entry, "directory")?, declaration: text(entry, "declaration")?, guards: array(entry, "guards")? })
    }

    fn pins(&self, policy: &Programme, projects: &Path) -> Result<CheckedGuards> {
        guard_inputs(policy, &projects.join(GUARD_LIBRARY), &projects.join(self.directory), self.declaration, self.guards)
    }
}

#[derive(Clone)]
struct Image { path: PathBuf, pin: String, version: String }

fn copy_source(supervisor: &mut Supervisor, source: &File, projects: &Path, staged: &Path, relative: &Path,
    remaining: &mut u64) -> Result<()> {
    supervisor.check()?;
    if !relative.components().all(|part| matches!(part, Component::Normal(_))) {
        return Err(fail("Invalid guard qualification source path"));
    }
    let path = projects.join(relative);
    let target = staged.join(relative);
    let metadata = path.symlink_metadata()?;
    if metadata.is_dir() {
        fs::create_dir_all(&target)?;
        for entry in fs::read_dir(&path)? {
            let name = entry?.file_name();
            if [".git", ".local", "node_modules", "target"].iter().any(|skip| name == OsStr::new(skip))
                || name.as_encoded_bytes().starts_with(b".guard-promotion-") { continue; }
            copy_source(supervisor, source, projects, staged, &relative.join(name), remaining)?;
        }
    } else if metadata.is_file() {
        let input = package::open_artifact(source, relative)?;
        let mut target = OpenOptions::new().write(true).create_new(true).mode(0o600).open(target)?;
        let bytes = io::copy(&mut input.take(*remaining + 1), &mut target)?;
        *remaining = remaining.checked_sub(bytes).ok_or_else(|| fail("Guard qualification sources exceed their size limit"))?;
    } else {
        return Err(fail(format!("Expected a regular guard qualification source: {}", path.display())));
    }
    Ok(())
}

fn open_image(compiler: &Compiler<'_>, image: &Image, store: &Path) -> Result<u16> {
    let mut children = Supervisor::children();
    let child = children.start("guard qualification image server", binary_command(compiler.binary)
        .args(["serve", "--image"]).arg(&image.path).arg(&image.pin).arg(store).arg("0")
        .stdin(Stdio::piped()).stdout(Stdio::piped()))?;
    let mut stdout = child.stdout.take().ok_or_else(|| fail("Missing guard image startup pipe"))?;
    let mut stdin = child.stdin.take().ok_or_else(|| fail("Missing guard image shutdown pipe"))?;
    nonblocking(stdout.as_raw_fd())?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut announcement = Vec::new();
    let port = loop {
        children.check()?;
        if Instant::now() >= deadline { return Err(fail("Guard qualification image startup timed out")); }
        let mut chunk = [0; 128];
        match stdout.read(&mut chunk) {
            Ok(0) => return Err(fail("Guard qualification image closed its startup pipe")),
            Ok(count) => {
                announcement.extend_from_slice(&chunk[..count]);
                if announcement.len() > chunk.len() { return Err(fail("Guard image startup announcement exceeded its bound")); }
                if let Some(line) = announcement.split_inclusive(|byte| *byte == b'\n').next()
                    && line.ends_with(b"\n") {
                    let port: u16 = std::str::from_utf8(line)?.strip_prefix("Encounter http://127.0.0.1:")
                        .and_then(|value| value.strip_suffix('\n')).ok_or_else(|| fail("Expected a loopback guard image listener"))?
                        .parse()?;
                    if port == 0 { return Err(fail("Expected an assigned guard image port")); }
                    break port;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(25)),
            Err(error) => return Err(error.into()),
        }
    };
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let mut reply = http::LoopbackReply::open(port, request.as_bytes(), Duration::from_secs(10))?;
    let (status, headers) = http::read_response_head(&mut reply)?;
    http::copy_response_body(&mut reply, &headers, &mut io::sink(), IMAGE_LIMIT)?;
    stdin.write_all(b"close\n")?;
    drop(stdin);
    children.wait_for_success(Duration::from_secs(5))?;
    Ok(status)
}

fn verify_image_host(policy: &Programme, compiler: &Compiler<'_>, image: &Image, store: &Path) -> Result<()> {
    let status = open_image(compiler, image, store)?;
    if run(policy, "package.guardImageReady", json!(status))? != true {
        return Err(fail(format!("Guard qualification image returned HTTP {status}")));
    }
    Ok(())
}

fn compile(supervisor: &mut Supervisor, policy: &Programme, projects: &Path, app: &App<'_>,
    compiler: &Compiler<'_>, output: PathBuf) -> Result<Image> {
    let root = projects.join(app.directory);
    package::check(&root)?;
    let checked = app.pins(policy, projects)?;
    let pin = compiler.build(supervisor, &root, app.declaration, &output, &checked.files)?;
    Ok(Image { path: output, pin, version: checked.version })
}

fn matrix(supervisor: &mut Supervisor, policy: &Programme, projects: &Path, apps: &[App<'_>],
    compilers: &BTreeMap<&str, Compiler<'_>>, images: &[Image], scratch: &Path, label: &str) -> Result<()> {
    let trial = scratch.join("comparison.rel");
    for (app, image) in apps.iter().zip(images) {
        let rebuilt = compile(supervisor, policy, projects, app, &compilers[app.role], trial.clone())?;
        if rebuilt.version != image.version || rebuilt.pin != image.pin || fs::read(&trial)? != fs::read(&image.path)? {
            return Err(fail(format!("{label}: {} did not rebuild the expected image", app.name)));
        }
        fs::remove_file(&trial)?;
    }
    println!("{label} {}", apps.iter().zip(images).map(|(app, image)| format!("{}={}", app.name, image.version))
        .collect::<Vec<_>>().join(" "));
    Ok(())
}

fn archive_image_pins(archive: &Path, requested: &[String]) -> Result<BTreeMap<String, String>> {
    let mut data = GzDecoder::new(File::open(archive)?).take(ARCHIVE_LIMIT + 1);
    let mut found = BTreeMap::new();
    loop {
        if interruption().is_some() { return Err(fail("Guard archive verification interrupted")); }
        let mut header = [0u8; 512];
        data.read_exact(&mut header)?;
        if header == [0; 512] {
            data.read_exact(&mut header)?;
            if header != [0; 512] { return Err(fail("Invalid guard archive terminator")); }
            break;
        }
        if !matches!(header[156], b'0' | b'5') || &header[257..265] != b"ustar  \0" {
            return Err(fail("Unexpected member in native guard archive"));
        }
        let name = std::str::from_utf8(header[..100].split(|byte| *byte == 0).next().unwrap_or_default())?;
        let size = u64::from_str_radix(std::str::from_utf8(&header[124..135])?, 8)?;
        if size > IMAGE_LIMIT { return Err(fail("Guard archive member exceeds its bound")); }
        if requested.iter().any(|path| path == name) {
            let mut digest = Sha256::new();
            http::copy_exact(&mut data, &mut digest, size)?;
            if header[156] != b'0' || found.insert(name.to_owned(), hex::encode(digest.finalize())).is_some() {
                return Err(fail("Invalid or duplicate guarded archive image"));
            }
        } else {
            http::copy_exact(&mut data, &mut io::sink(), size)?;
        }
        http::copy_exact(&mut data, &mut io::sink(), (512 - size % 512) % 512)?;
    }
    io::copy(&mut data, &mut io::sink())?;
    if data.limit() == 0 || found.len() != requested.len() { return Err(fail("Missing or oversized guarded archive content")); }
    Ok(found)
}

fn mixed_archive(supervisor: &mut Supervisor, policy: &Programme, projects: &Path, apps: &[App<'_>], images: &[Image],
    compilers: &BTreeMap<&str, Compiler<'_>>, versions: &Facts, plan: &Value, scratch: &Path) -> Result<()> {
    let names = array(plan, "applications")?;
    let indices = names.iter().map(|name| apps.iter().position(|app| name.as_str() == Some(app.name))
        .ok_or_else(|| fail("Unknown guarded archive application"))).collect::<Result<Vec<_>>>()?;
    if indices.len() != 2 || images[indices[0]].version == images[indices[1]].version {
        return Err(fail("Expected a mixed-version release archive"));
    }
    let role = text(plan, "compiler")?;
    let compiler = &compilers[role];
    let layout = match text(plan, "layout")? {
        "platform" => ReleaseLayout::Platform, "aggregate" => ReleaseLayout::Aggregate,
        _ => return Err(fail("Unknown guarded archive layout")),
    };
    let archive = build_archive(supervisor, layout, &projects.join(text(plan, "runtime")?), versions.one(role, "version")?,
        compiler.binary, &scratch.join(format!("archive-{role}")), Some(&compiler.pin))?;
    let directory = archive.file_name().and_then(OsStr::to_str).and_then(|name| name.strip_suffix(".tar.gz"))
        .ok_or_else(|| fail("Expected the native guard archive filename"))?;
    let members = indices.iter().map(|index| format!("{directory}/images/{}.rel", apps[*index].product)).collect::<Vec<_>>();
    let pins = archive_image_pins(&archive, &members)?;
    let trial = scratch.join("archive-comparison.rel");
    for (index, member) in indices.iter().zip(&members) {
        let image = compile(supervisor, policy, projects, &apps[*index], compiler, trial.clone())?;
        if image.pin != pins[member] { return Err(fail("Guarded archive image differs from the matching compiler build")); }
        fs::remove_file(&trial)?;
    }
    println!("mixed package {directory} {}", indices.iter().map(|index| format!("{}={}", apps[*index].name, images[*index].version))
        .collect::<Vec<_>>().join(" "));
    Ok(())
}

pub fn promote_guards(projects: &Path, version: &str, candidate: &Path, compiler_facts: &Path) -> Result<()> {
    let mut supervisor = Supervisor::new();
    let projects = projects.canonicalize()?;
    let library = projects.join(GUARD_LIBRARY);
    if library.canonicalize()? != library { return Err(fail("Expected the project's canonical guard library")); }
    let policy = policy()?;
    let plan = run(&policy, "package.guardPromotion", json!(version))?;
    let apps = array(&plan, "apps")?.iter().map(App::from_plan).collect::<Result<Vec<_>>>()?;
    let destination = library.join(version);
    match destination.symlink_metadata() {
        Ok(_) => return Err(fail("Guard release already exists")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let initial = apps.iter().map(|app| app.pins(&policy, &projects)).collect::<Result<Vec<_>>>()?;
    let candidate = candidate.canonicalize()?;
    let expected = canonical_guard_files(&candidate)?;
    run(&policy, "package.guardRelease", expected.clone())?;
    let pending = Scratch::create(&library, ".guard-promotion-")?;
    for file in GUARDS.into_iter().chain(["SHA256SUMS"]) {
        write(&pending.path().join(file), &read(&candidate.join(file), SOURCE_LIMIT)?, 0o644)?;
    }
    if canonical_guard_files(pending.path())? != expected { return Err(fail("Guard release changed while being staged")); }
    let scratch = Scratch::create(&std::env::temp_dir(), "encounter-guard-gate-")?;
    let facts = Facts::parse(&read(compiler_facts, SOURCE_LIMIT)?)?;
    if facts.0.len() != ROLES.len() * 3 { return Err(fail("Expected three pinned guard compilers")); }
    let binaries = ROLES.iter().map(|role| scratch.path().join(format!("{role}-compiler"))).collect::<Vec<_>>();
    let mut compilers = BTreeMap::new();
    for (&role, staged) in ROLES.iter().zip(&binaries) {
        let path = Path::new(facts.one(role, "binary")?);
        if !path.is_absolute() { return Err(fail("Expected an absolute guard compiler path")); }
        let compiler = stage_compiler(&mut supervisor, &policy, path, staged,
            facts.one(role, "version")?, Some(facts.one(role, "sha256")?))?;
        println!("compiler {role} {}", compiler.pin);
        compilers.insert(role, compiler);
    }
    let staged = scratch.path().join("projects");
    let source = File::open(&projects)?;
    let mut remaining = PROMOTION_LIMIT;
    for directory in apps.iter().map(|app| Ok(app.directory)).chain(array(&plan, "copies")?.iter()
        .map(|directory| directory.as_str().ok_or_else(|| fail("Invalid guard qualification source")))) {
        copy_source(&mut supervisor, &source, &projects, &staged, Path::new(directory?), &mut remaining)?;
    }
    let staged_release = staged.join(GUARD_LIBRARY).join(version);
    fs::create_dir(&staged_release)?;
    for file in GUARDS.into_iter().chain(["SHA256SUMS"]) {
        fs::copy(pending.path().join(file), staged_release.join(file))?;
    }
    if canonical_guard_files(&staged_release)? != expected { return Err(fail("Staged guard candidate differs from its verified source")); }

    let images = scratch.path().join("images");
    fs::create_dir(&images)?;
    let mut originals = Vec::new();
    for (app, before) in apps.iter().zip(&initial) {
        if app.pins(&policy, &staged)? != *before { return Err(fail("Guard pins changed while being staged")); }
        let image = compile(&mut supervisor, &policy, &staged, app, &compilers[app.role], images.join(format!("{}-original.rel", app.name)))?;
        originals.push(image);
    }
    let mut current = originals.clone();
    for step in array(&plan, "steps")? {
        let kind = text(step, "kind")?;
        match kind {
            "baseline" => {
                matrix(&mut supervisor, &policy, &staged, &apps, &compilers, &current, &images, "baseline")?;
                continue;
            }
            "archive" => {
                mixed_archive(&mut supervisor, &policy, &staged, &apps, &current, &compilers, &facts, step, &images)?;
                continue;
            }
            "upgrade" | "rollback" => (),
            _ => return Err(fail("Unknown guard qualification step")),
        }
        let name = text(step, "application")?;
        let index = apps.iter().position(|app| app.name == name).ok_or_else(|| fail("Unknown guard qualification application"))?;
        let app = &apps[index];
        let root = staged.join(app.directory);
        let lock = root.join(app.declaration).with_file_name("guards.sha256");
        let store = scratch.path().join(format!("{}-store", app.name));
        if kind == "rollback" {
            for guard in app.guards {
                let relative = Path::new("source").join(guard.as_str().ok_or_else(|| fail("Invalid guard name"))?);
                let source = projects.join(app.directory).join(&relative);
                let original = read(&source, SOURCE_LIMIT)?;
                if initial[index].files[relative.to_string_lossy().as_ref()] != rel::hash(&original) {
                    return Err(fail("Guard source changed during qualification"));
                }
                fs::write(root.join(relative), original)?;
            }
            fs::write(&lock, &initial[index].lock)?;
            current[index] = originals[index].clone();
            matrix(&mut supervisor, &policy, &staged, &apps, &compilers, &current, &images, &format!("rollback-{name}"))?;
            verify_image_host(&policy, &compilers[app.role], &current[index], &store)?;
            continue;
        }
        let output = images.join(format!("{}-candidate.rel", app.name));
        let candidate_lock = run(&policy, "package.guardLock",
            json!({"version":version,"guards":app.guards,"canonical":expected["canonical"]}))?;
        fs::write(&lock, candidate_lock.as_str().ok_or_else(|| fail("Expected a candidate guard lock"))?)?;
        for name in app.guards {
            let name = name.as_str().ok_or_else(|| fail("Invalid guard name"))?;
            fs::copy(staged_release.join(name), root.join("source").join(name))?;
        }
        let first = app.guards.first().and_then(Value::as_str).ok_or_else(|| fail("Missing qualification guard"))?;
        let drift = root.join("source").join(first);
        fs::OpenOptions::new().append(true).open(&drift)?.write_all(b"\n# Deliberate failed-upgrade witness.\n")?;
        match compile(&mut supervisor, &policy, &staged, app, &compilers[app.role], output.clone()) {
            Err(error) if error.to_string().contains("Vendored guard differs from release") && !output.exists() => (),
            Err(error) => return Err(fail(format!("Guard qualification failed while checking drift: {error}"))),
            Ok(_) => return Err(fail("Guard qualification admitted a drifted upgrade")),
        }
        for image in &current {
            if hash(&image.path, IMAGE_LIMIT)? != image.pin { return Err(fail("A retained guarded image changed")); }
        }
        verify_image_host(&policy, &compilers[app.role], &originals[index], &store)?;
        println!("failed upgrade refused, retained image served {}", app.name);
        fs::copy(staged_release.join(first), drift)?;
        let next = compile(&mut supervisor, &policy, &staged, app, &compilers[app.role], output)?;
        verify_image_host(&policy, &compilers[app.role], &next, &store)?;
        current[index] = next;
        matrix(&mut supervisor, &policy, &staged, &apps, &compilers, &current, &images, &format!("upgrade-{}", app.name))?;
    }
    for (app, before) in apps.iter().zip(&initial) {
        if app.pins(&policy, &projects)? != *before { return Err(fail("Guard pins changed during qualification")); }
    }
    if canonical_guard_files(pending.path())? != expected { return Err(fail("Guard candidate changed during qualification")); }
    supervisor.check()?;
    fs::set_permissions(pending.path(), fs::Permissions::from_mode(0o755))?;
    rename_new_path(pending.path(), &destination)?;
    File::open(&library)?.sync_all()?;
    println!("Promoted encounter-guards {version}");
    Ok(())
}
