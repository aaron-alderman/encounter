use crate::{Result, appdev_host_process::{Scratch, Supervisor, handle_hangup, interruption, rename_new_path}, fail,
    self_hosted_identity::decide, self_hosted_identity_crypto::{SigningKey, derive_password}, workspace::transport::random};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use serde_json::json;
use std::{fs::{self, File, OpenOptions}, io::{self, Write}, os::{fd::RawFd, unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt}},
    path::{Component, Path, PathBuf}};
use zeroize::Zeroizing;

const TERMINAL: RawFd = libc::STDIN_FILENO;
const INPUT_LIMIT: usize = 4096;
const STAGING: &str = "/run/sourcery-identity-staging";
const KEY_ID_FILE: &str = "/run/sourcery-identity-key-id";

fn check_interruption() -> Result<()> {
    if interruption().is_some() { return Err(fail("Operator identity provisioning interrupted")); }
    Ok(())
}

struct HiddenInput { fd: RawFd, original: libc::termios, hidden: bool }

fn terminal_settings(fd: RawFd) -> io::Result<libc::termios> {
    let mut settings = std::mem::MaybeUninit::uninit();
    if unsafe { libc::tcgetattr(fd, settings.as_mut_ptr()) } != 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { settings.assume_init() })
}

fn set_terminal(fd: RawFd, settings: &libc::termios) -> io::Result<()> {
    loop {
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, settings) } == 0 { return Ok(()); }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
    }
}

impl HiddenInput {
    fn begin(fd: RawFd) -> Result<Self> {
        let original = terminal_settings(fd)?;
        let mut settings = original;
        settings.c_lflag = (settings.c_lflag | libc::ICANON) & !(libc::ECHO | libc::ECHONL);
        settings.c_cc[libc::VSUSP] = 0;
        set_terminal(fd, &settings)?;
        Ok(Self { fd, original, hidden: true })
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.hidden {
            set_terminal(self.fd, &self.original)?;
            self.hidden = false;
        }
        Ok(())
    }
}

impl Drop for HiddenInput {
    fn drop(&mut self) { let _ = self.restore(); }
}

fn read_secret(fd: RawFd, interactive: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut secret = Zeroizing::new(Vec::with_capacity(INPUT_LIMIT + 1));
    let mut chunk = Zeroizing::new([0_u8; 512]);
    loop {
        check_interruption()?;
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, 100) };
        if ready == 0 { continue; }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        let count = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(error.into());
        }
        if count == 0 {
            if interactive { return Err(fail("Operator secret entry ended before the line was submitted")); }
            break;
        }
        let input = &chunk[..count as usize];
        let line_end = interactive.then(|| input.iter().position(|byte| *byte == b'\n')).flatten();
        let input = &input[..line_end.unwrap_or(input.len())];
        if input.len() > INPUT_LIMIT - secret.len() { return Err(fail("Operator secret input is too large")); }
        secret.extend_from_slice(input);
        if line_end.is_some() { break; }
    }
    check_interruption()?;
    Ok(secret)
}

fn read_hidden(fd: RawFd, prompt: &mut impl Write) -> Result<Zeroizing<Vec<u8>>> {
    let mut terminal = HiddenInput::begin(fd)?;
    prompt.write_all(b"Choose operator secret (20+ characters; input hidden): ")?;
    prompt.flush()?;
    let input = read_secret(fd, true);
    terminal.restore()?;
    prompt.write_all(b"\n")?;
    input
}

fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(fail("Operator identity custody already exists")),
    }
}

pub(super) fn destination(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().filter(|_| path.is_absolute()
        && !path.components().any(|part| matches!(part, Component::ParentDir)))
        .ok_or_else(|| fail("Expected an absolute operator identity staging directory"))?;
    let parent = path.parent().ok_or_else(|| fail("Missing operator identity staging parent"))?.canonicalize()?;
    let target = parent.join(name);
    absent(&target)?;
    Ok(target)
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn provision(target: &Path, receipt: Option<&Path>, input: &[u8]) -> Result<String> {
    let password = std::str::from_utf8(input).map_err(|_| fail("Operator secret must be valid UTF-8"))?.trim_end_matches(['\r', '\n']);
    let parameters = decide("identity.provision", json!(password.encode_utf16().count()))?;
    let number = |field| parameters[field].as_u64().ok_or_else(|| fail("Invalid operator provisioning parameter"));
    let cost = number("cost")?;
    let block_size = number("blockSize")?;
    let parallelization = number("parallelization")?;
    let key_length = usize::try_from(number("keyLength")?)?;
    let prefix = parameters["keyIdPrefix"].as_str().ok_or_else(|| fail("Missing operator key identity prefix"))?;
    let algorithm = parameters["algorithm"].as_str().ok_or_else(|| fail("Missing operator password algorithm"))?;
    let salt = random::<32>()?;
    let digest = derive_password(password.as_bytes(), &salt, cost, block_size, parallelization, key_length)?;
    check_interruption()?;
    let signer = SigningKey::generate()?;
    let (scalar, x, y) = signer.private_parts();
    let scalar = Zeroizing::new(Base64UrlUnpadded::encode_string(scalar));
    let x = Base64UrlUnpadded::encode_string(x);
    let y = Base64UrlUnpadded::encode_string(y);
    let private_jwk = Zeroizing::new(format!("{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{x}\",\"y\":\"{y}\",\"d\":\"{}\"}}\n", &*scalar));
    let salt = Base64::encode_string(&salt);
    let digest = Zeroizing::new(Base64::encode_string(&digest));
    let record = Zeroizing::new(format!("{{\"algorithm\":\"{algorithm}\",\"salt\":\"{salt}\",\"digest\":\"{}\",\"cost\":{cost},\"blockSize\":{block_size},\"parallelization\":{parallelization},\"keyLength\":{key_length}}}\n", &*digest));
    let key_id = format!("{prefix}{}", hex::encode(random::<12>()?));

    let (stage, staged_custody) = private_stage(target)?;
    write_private(&staged_custody.join("signing-key.json"), private_jwk.as_bytes())?;
    write_private(&staged_custody.join("operator-secret.json"), record.as_bytes())?;
    if receipt.is_some() { write_private(&stage.path().join("key-id"), format!("{key_id}\n").as_bytes())?; }
    publish(stage, &staged_custody, target, receipt)?;
    Ok(key_id)
}

pub(super) fn private_stage(target: &Path) -> Result<(Scratch, PathBuf)> {
    let parent = target.parent().ok_or_else(|| fail("Missing operator identity staging parent"))?;
    let stage = Scratch::create(parent, ".sourcery-identity-")?;
    let custody = stage.path().join("custody");
    fs::DirBuilder::new().mode(0o700).create(&custody)?;
    fs::set_permissions(&custody, fs::Permissions::from_mode(0o700))?;
    Ok((stage, custody))
}

pub(super) fn publish(stage: Scratch, staged_custody: &Path, target: &Path, receipt: Option<&Path>) -> Result<()> {
    let parent = target.parent().ok_or_else(|| fail("Missing operator identity staging parent"))?;
    let directory = File::open(parent)?;
    let staged_receipt = stage.path().join("key-id");
    File::open(staged_custody)?.sync_all()?;
    File::open(stage.path())?.sync_all()?;

    let mut published_custody = false;
    let mut published_receipt = false;
    let result = (|| -> Result<()> {
        check_interruption()?;
        rename_new_path(staged_custody, target)?;
        published_custody = true;
        if let Some(receipt) = receipt {
            check_interruption()?;
            rename_new_path(&staged_receipt, receipt)?;
            published_receipt = true;
        }
        directory.sync_all()?;
        check_interruption()
    })();
    if let Err(error) = result {
        let restore = (|| -> Result<()> {
            if published_receipt && let Some(receipt) = receipt { rename_new_path(receipt, &staged_receipt)?; }
            if published_custody { rename_new_path(target, staged_custody)?; }
            directory.sync_all()?;
            Ok(())
        })();
        if let Err(restore) = restore {
            return Err(fail(format!("{error}. Operator custody rollback failed ({restore}); retained {}", stage.retain().display())));
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn from_stdin(target: &Path) -> Result<()> {
    let _signals = Supervisor::new();
    if unsafe { libc::isatty(TERMINAL) } == 1 { return Err(fail("Use self-hosted-identity-prompt to enter the operator secret from a terminal")); }
    let target = destination(target)?;
    let input = read_secret(TERMINAL, false)?;
    let key_id = provision(&target, None, &input)?;
    println!("{key_id}");
    Ok(())
}

pub(crate) fn prompt() -> Result<()> {
    let _signals = Supervisor::new();
    handle_hangup();
    if unsafe { libc::isatty(TERMINAL) } != 1 { return Err(fail("Operator identity secret must be entered from a terminal")); }
    if unsafe { libc::geteuid() } != 0 { return Err(fail("Operator identity staging requires root")); }
    let target = destination(Path::new(STAGING))?;
    let receipt = Path::new(KEY_ID_FILE);
    absent(receipt)?;
    let input = read_hidden(TERMINAL, &mut io::stderr().lock())?;
    let key_id = provision(&target, Some(receipt), &input)?;
    println!("Identity material generated. Key ID: {key_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, os::fd::{AsRawFd, FromRawFd}, process::{Command, Stdio}, thread, time::{Duration, Instant}};

    const SECRET: &[u8] = b"a sufficiently long operator secret";

    #[test]
    fn provisions_compatible_credentials_in_private_non_replacing_custody() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "operator-custody-test-")?;
        let target = fixture.path().join("custody");
        assert!(provision(&target, None, b"short").is_err());
        assert!(!target.exists());
        let key_id = provision(&destination(&target)?, None, SECRET)?;
        let id = key_id.strip_prefix("self-hosted-").ok_or_else(|| fail("Invalid fixture key identity"))?;
        assert_eq!(id.len(), 24);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o700);

        let key = target.join("signing-key.json");
        let record = target.join("operator-secret.json");
        for path in [&key, &record] { assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600); }
        let private = Zeroizing::new(fs::read(key)?);
        let jwk: serde_json::Value = serde_json::from_slice(&private)?;
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        let source = Zeroizing::new(fs::read(&record)?);
        let data: serde_json::Value = serde_json::from_slice(&source)?;
        let salt = Base64::decode_vec(data["salt"].as_str().ok_or_else(|| fail("Missing fixture salt"))?)?;
        let digest = Base64::decode_vec(data["digest"].as_str().ok_or_else(|| fail("Missing fixture digest"))?)?;
        assert_eq!(data["algorithm"], "scrypt-v1");
        assert_eq!(derive_password(SECRET, &salt, 65_536, 8, 1, 32)?.as_slice(), digest);
        assert!(destination(&target).is_err());
        assert_eq!(fs::read(record)?, *source);
        Ok(())
    }

    #[test]
    fn operator_prompt_hides_input_and_restores_the_terminal() -> Result<()> {
        const CHILD: &str = "ENCOUNTER_TEST_OPERATOR_PROMPT_CHILD";
        if let Some(mode) = std::env::var_os(CHILD) {
            let _signals = Supervisor::new();
            let input = read_hidden(TERMINAL, &mut io::stderr().lock());
            if mode == "interrupt" {
                assert_eq!(interruption(), Some(143));
                assert!(input.unwrap_err().to_string().contains("interrupted"));
            } else {
                assert_eq!(input?.as_slice(), SECRET);
            }
            return Ok(());
        }
        for mode in ["success", "interrupt"] {
            let (mut master, mut slave) = (-1, -1);
            if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let mut master = unsafe { File::from_raw_fd(master) };
            let slave = unsafe { File::from_raw_fd(slave) };
            let original = terminal_settings(slave.as_raw_fd())?;
            assert_ne!(original.c_lflag & libc::ECHO, 0);
            let mut command = Command::new(std::env::current_exe()?);
            command.args(["--exact", "self_hosted_identity_provision::tests::operator_prompt_hides_input_and_restores_the_terminal", "--nocapture"])
                .env(CHILD, mode).stdin(Stdio::from(slave.try_clone()?)).stdout(Stdio::null()).stderr(Stdio::piped());
            let mut supervisor = Supervisor::children();
            let child = supervisor.start("Exercise operator terminal prompt", &mut command)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while terminal_settings(slave.as_raw_fd())?.c_lflag & libc::ECHO != 0 {
                if child.try_wait()?.is_some() || Instant::now() >= deadline { return Err(fail("Operator prompt never hid terminal input")); }
                thread::sleep(Duration::from_millis(10));
            }
            master.write_all(SECRET)?;
            if mode == "interrupt" {
                assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
            } else { master.write_all(b"\n")?; }
            let status = loop {
                if let Some(status) = child.try_wait()? { break status; }
                if Instant::now() >= deadline { return Err(fail("Operator prompt did not terminate")); }
                thread::sleep(Duration::from_millis(10));
            };
            let restored = terminal_settings(slave.as_raw_fd())?;
            assert_eq!(restored.c_lflag, original.c_lflag);
            assert_eq!(restored.c_cc, original.c_cc);
            let mut errors = Vec::new();
            child.stderr.take().ok_or_else(|| fail("Missing terminal diagnostic pipe"))?.read_to_end(&mut errors)?;
            assert!(status.success(), "operator prompt fixture failed");
            assert!(!errors.windows(SECRET.len()).any(|window| window == SECRET));
            crate::appdev_host_process::nonblocking(master.as_raw_fd())?;
            let mut echoed = Vec::new();
            match master.read_to_end(&mut echoed) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            assert!(!echoed.windows(SECRET.len()).any(|window| window == SECRET));
        }
        Ok(())
    }

    #[test]
    fn a_key_id_collision_rolls_back_new_custody() -> Result<()> {
        let fixture = Scratch::create(&std::env::temp_dir(), "operator-custody-test-")?;
        let target = fixture.path().join("custody");
        let receipt = fixture.path().join("key-id");
        write_private(&receipt, b"previous-key-id\n")?;
        assert!(provision(&target, Some(&receipt), SECRET).is_err());
        assert!(!target.exists());
        assert_eq!(fs::read(&receipt)?, b"previous-key-id\n");
        assert_eq!(fs::read_dir(fixture.path())?.count(), 1);
        Ok(())
    }
}
