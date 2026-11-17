use crate::{Result, appdev_reload::{ReleaseSlot, presentation_sources}, fail, http, mcp_project_socket, runtime_authority::Socket,
    process::{HTML_PORTS, HTML_RENDERER, Meter, Programme, SharedProgramme}};
use serde_json::json;
use std::{
    collections::BTreeSet, env, io::{self, Write}, net::Shutdown, path::{Path, PathBuf},
    sync::Arc, thread, time::{Duration, Instant},
};

const MODULE: &str = "workspace_sign_in.encounter";
const EMBEDDED: &str = include_str!("workspace_sign_in.encounter");
const CONTRACT: &str = "encounter/workspace-sign-in-presentation/1";
const LIMIT: usize = 250_000;
const PAGE_LIMIT: usize = 64_000;
const RETURN_LIMIT: usize = 1024;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) enum Screen { Required, Complete }

impl Screen {
    fn entry(&self) -> &'static str {
        match self {
            Self::Required => "workspaceSignIn.required",
            Self::Complete => "workspaceSignIn.complete",
        }
    }
}

pub(crate) struct Presentation(ReleaseSlot<SharedProgramme>);

impl Presentation {
    pub(crate) fn start(follow: bool) -> Result<Self> {
        let link = follow.then(|| env::var_os("APPDEV_WORKSPACE_SIGN_IN_RELEASE")).flatten().map(PathBuf::from);
        Ok(Self(ReleaseSlot::start("Workspace sign-in presentation", link, || compile(EMBEDDED),
            |root, _| generation(root))?))
    }

    pub(crate) fn page(&self, screen: Screen, destination: &str) -> Result<String> {
        page(&self.0.current(), screen, destination)
    }
}

/// Match the whole bundled completion document before using the only dynamic field.
pub(crate) struct LegacyCompletion {
    programme: SharedProgramme,
    parts: [String; 3],
}

impl LegacyCompletion {
    pub(crate) fn load() -> Result<Self> {
        let marker = "/workspace/home?encounter-completion-destination";
        let programme = compile(EMBEDDED)?;
        let template = page(&programme, Screen::Complete, marker)?;
        let parts = template.split(marker).map(str::to_owned).collect::<Vec<_>>();
        let parts = parts.try_into().map_err(|_| fail("Invalid bundled completion layout"))?;
        Ok(Self { programme, parts })
    }

    pub(crate) fn destination(&self, body: &[u8]) -> Option<String> {
        let [start, between, end] = &self.parts;
        let remainder = std::str::from_utf8(body).ok()?.strip_prefix(start)?.strip_suffix(end)?;
        let (encoded, repeated) = remainder.split_once(between)?;
        if encoded != repeated || encoded.len() > RETURN_LIMIT * 6 { return None; }
        let mut decoded = String::with_capacity(encoded.len());
        let mut rest = encoded;
        while let Some((prefix, entity)) = rest.split_once('&') {
            decoded.push_str(prefix);
            let (entity, next) = entity.split_once(';')?;
            decoded.push(match entity {
                "amp" => '&',
                "quot" => '"',
                "lt" => '<',
                "gt" => '>',
                "apos" | "#39" | "#x27" => '\'',
                _ => return None,
            });
            rest = next;
        }
        decoded.push_str(rest);
        // Compare the actual serializer spelling rather than accepting alternate encodings.
        if decoded.len() > RETURN_LIMIT { return None; }
        (page(&self.programme, Screen::Complete, &decoded).ok()?.as_bytes() == body).then_some(decoded)
    }
}

pub(crate) struct CompletionClient {
    path: PathBuf,
    uid: u32,
}

impl CompletionClient {
    pub(crate) fn configured() -> Result<Option<Self>> {
        let path = env::var_os("APPDEV_WORKSPACE_COMPLETION_SOCKET");
        let uid = env::var("APPDEV_WORKSPACE_COMPLETION_UID").ok();
        match (path.map(PathBuf::from), uid) {
            (None, None) => Ok(None),
            (Some(path), Some(uid)) if path.is_absolute() => Ok(Some(Self { path, uid: uid.parse()? })),
            _ => Err(fail("Workspace completion requires an absolute socket and renderer UID")),
        }
    }

    pub(crate) fn page(&self, destination: &str) -> Result<String> {
        let deadline = Instant::now() + COMPLETION_TIMEOUT;
        let mut stream = crate::runtime_authority_client::connect(&self.path, deadline)?;
        mcp_project_socket::peer(&stream, self.uid)?;
        stream.write_all(destination.as_bytes())?;
        stream.shutdown(Shutdown::Write)?;
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() { return Err(fail("Workspace completion render timed out")); }
        let html = mcp_project_socket::receive(&mut stream, PAGE_LIMIT, timeout)?;
        Ok(std::str::from_utf8(&html)?.to_owned())
    }
}

pub(crate) fn serve_completion<V>(path: &Path, authority_uid: u32, presentation: Arc<Presentation>,
    validate: impl FnOnce() -> Result<V> + Send + 'static,
) -> Result<Socket> where V: Fn(&str) -> Result<bool> {
    let (socket, listener) = Socket::bind(path.to_owned(), 0o660)?;
    thread::Builder::new().name("workspace-sign-in-completion".into()).spawn(move || {
        let run = || -> Result<()> {
            let validate = validate()?;
            while !http::stopping() {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                };
                if mcp_project_socket::peer(&stream, authority_uid).is_err() { continue; }
                let mut request = || -> Result<()> {
                    let request = mcp_project_socket::receive(&mut stream, RETURN_LIMIT, COMPLETION_TIMEOUT)?;
                    let destination = std::str::from_utf8(&request)?;
                    if !validate(destination)? { return Ok(()); }
                    let page = presentation.page(Screen::Complete, destination)?;
                    stream.set_write_timeout(Some(COMPLETION_TIMEOUT))?;
                    stream.write_all(page.as_bytes())?;
                    Ok(())
                };
                let _ = request();
            }
            Ok(())
        };
        if let Err(error) = run() { eprintln!("Workspace completion renderer: {error}"); }
    })?;
    Ok(socket)
}

fn generation(root: &Path) -> Result<SharedProgramme> {
    let [source] = presentation_sources(root, CONTRACT, [(MODULE, 64_000)])?;
    compile(&source)
}

pub(crate) fn verify_generation(root: &Path) -> Result<()> {
    generation(root).map(|_| ())
}

fn page(programme: &SharedProgramme, screen: Screen, destination: &str) -> Result<String> {
    let rendered = programme.run(screen.entry(), json!({"destination":destination}), &mut Meter::new(LIMIT))?;
    rendered.as_str().filter(|html| html.len() <= PAGE_LIMIT).map(str::to_owned)
        .ok_or_else(|| fail("Workspace sign-in page did not render"))
}

fn compile(source: &str) -> Result<SharedProgramme> {
    let sources = HTML_RENDERER.into_iter().chain([source]).map(str::to_owned).collect::<Vec<_>>();
    let programme = Programme::admit_entries(&sources, &[Screen::Required.entry(), Screen::Complete.entry()],
        &BTreeSet::from(HTML_PORTS), &mut Meter::new(LIMIT))?.into_shared()?;
    let required = page(&programme, Screen::Required, "/identity-management/?workspace-return=%2Fworkspace%2Fhome")?;
    let complete = page(&programme, Screen::Complete, "/workspace/home?test=1&other=2")?;
    if !required.contains("href=\"/identity-management/?workspace-return=%2Fworkspace%2Fhome\"")
        || !required.contains("target=\"_top\"") || required.contains("http-equiv=\"refresh\"")
        || !complete.contains("href=\"/workspace/home?test=1&amp;other=2\"")
        || !complete.contains("content=\"2;url=/workspace/home?test=1&amp;other=2\"") {
        return Err(fail("Workspace sign-in presentation changed the navigation contract"));
    }
    Ok(programme)
}

#[cfg(test)]
#[test]
fn appdev_legacy_completion_accepts_only_the_exact_escaped_document() -> Result<()> {
    let legacy = LegacyCompletion::load()?;
    let destination = "/aster-codex/chat?id=fixture&tab=work";
    let html = page(&legacy.programme, Screen::Complete, destination)?;
    assert_eq!(legacy.destination(html.as_bytes()).as_deref(), Some(destination));
    let mismatched_link = html.replacen("tab=work", "tab=outside", 1);
    let unknown_page = html.replacen("Continuing to your application", "Other text", 1);
    let alternate_encoding = html.replace("&amp;", "&#38;");
    for body in [mismatched_link, unknown_page, alternate_encoding] {
        assert_eq!(legacy.destination(body.as_bytes()), None);
    }
    Ok(())
}
