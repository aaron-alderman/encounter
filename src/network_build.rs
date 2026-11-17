use crate::{Result, appdev_host_process::{Scratch, rename_new_path}, application::{Application, CheckProfile},
    fail, package, rel::Facts};
use std::{env, fs, path::{Component, Path}};

pub(crate) fn local(name: &str) -> Result<&Path> {
    let path = Path::new(name);
    if name.is_empty() || name.contains('\\')
        || path.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(fail("Expected a relative build path without traversal"));
    }
    Ok(path)
}

pub(crate) fn copy_file(input: &Path, output: &Path) -> Result<()> {
    if !fs::symlink_metadata(input)?.is_file() || output.symlink_metadata().is_ok() {
        return Err(fail(format!("Expected a regular input and unused output at {}", output.display())));
    }
    fs::create_dir_all(output.parent().ok_or_else(|| fail("Missing output parent"))?)?;
    fs::copy(input, output)?;
    Ok(())
}

pub(crate) fn copy_tree(input: &Path, output: &Path) -> Result<()> {
    if !fs::symlink_metadata(input)?.is_dir() { return Err(fail("Expected a regular build input directory")); }
    fs::create_dir(output)?;
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        let target = output.join(entry.file_name());
        if entry.file_type()?.is_dir() { copy_tree(&entry.path(), &target)?; }
        else { copy_file(&entry.path(), &target)?; }
    }
    Ok(())
}

pub fn build(root: &Path, managed: &Path, output: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let projects = root.ancestors().nth(3).ok_or_else(|| fail("Expected the network source in the projects tree"))?;
    let runtime = env::current_exe()?;
    let managed = managed.canonicalize()?;
    let output_name = output.file_name().ok_or_else(|| fail("Choose a new release directory"))?;
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new(".")).canonicalize()?;
    let output = parent.join(output_name);
    if output.symlink_metadata().is_ok() { return Err(fail("Choose a new release directory")); }
    if parent.starts_with(&managed) { return Err(fail("The release must be outside its managed source")); }
    let plan = Facts::read(&root.join("build.rel"))?;
    if plan.one("build", "contract")? != "encounter/network-release-build/1" {
        return Err(fail("Unsupported network release build contract"));
    }
    let scratch = Scratch::create(&parent, ".network-release-")?;
    let stage = scratch.path().join("package");
    fs::create_dir(&stage)?;
    for [action, input, output] in &plan.0 {
        match (action.as_str(), input.as_str(), output.as_str()) {
            ("build", "contract", _) => (),
            ("copy", _, _) => copy_file(&root.join(local(input)?), &stage.join(local(output)?))?,
            ("copy-project", _, _) => copy_file(&projects.join(local(input)?), &stage.join(local(output)?))?,
            ("copy-managed", "source", _) => copy_tree(&managed, &stage.join(local(output)?))?,
            ("replace-tree", _, _) => {
                let target = stage.join(local(output)?);
                fs::remove_dir_all(&target)?;
                copy_tree(&projects.join(local(input)?), &target)?;
            }
            ("copy-runtime", "runtime", _) => copy_file(&runtime, &stage.join(local(output)?))?,
            ("check", _, "application") => {
                let declaration = stage.join(local(input)?);
                let root = declaration.parent().ok_or_else(|| fail("Missing declaration directory"))?;
                let name = declaration.file_name().and_then(|name| name.to_str())
                    .ok_or_else(|| fail("Missing declaration name"))?;
                let application = Application::load(root, name)
                    .map_err(|error| fail(format!("Release declaration {input}: {error}")))?;
                if !application.check(CheckProfile::Application)? {
                    return Err(fail(format!("Release declaration refused: {input}")));
                }
            }
            _ => return Err(fail(format!("Unknown release build step: {action} {input} {output}"))),
        }
    }
    package::check(&stage)?;
    rename_new_path(&stage, &output)
}
