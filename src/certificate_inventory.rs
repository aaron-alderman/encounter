use crate::{Result, command::Evaluator, fail, http, rel::Facts, x509::Certificate};
use serde_json::{Value, json};
use std::{ffi::CString, fs, io::{self, Read}, os::{fd::{AsRawFd, FromRawFd},
    unix::fs::OpenOptionsExt}, path::Path};

const LIMIT: usize = 16_384;

fn filename(name: &Value) -> Result<CString> {
    let name = name.as_str().ok_or_else(|| fail("Expected certificate credential name"))?;
    if !name.strip_suffix(".pem").is_some_and(|stem| !stem.is_empty()
        && stem.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')) {
        return Err(fail("Expected a single public certificate credential name"));
    }
    Ok(CString::new(name)?)
}

fn read(directory: &fs::File, name: &CString) -> Result<Certificate> {
    // Resolve only an admitted basename beneath the pinned credentials directory.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 { return Err(io::Error::last_os_error().into()); }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > LIMIT as u64 { return Err(fail("Unexpected certificate file")); }
    let mut pem = String::new();
    file.take((LIMIT + 1) as u64).read_to_string(&mut pem)?;
    if pem.len() > LIMIT { return Err(fail("Invalid public certificate encoding")); }
    Certificate::from_pem(&pem)
}

pub fn serve(root: &Path, credentials: &Path, port: u16) -> Result<()> {
    if !credentials.is_absolute() || port < 1024 {
        return Err(fail("Expected an absolute credential directory and unprivileged loopback port"));
    }
    let directory = fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(credentials)?;
    let app = Evaluator::load(root, "inventory.rel")?;
    let plan = app.run("inventory.plan", json!(Facts::read(&root.join("profiles.rel"))?.0))?;
    let profiles = plan.as_array().ok_or_else(|| fail("Expected certificate profiles"))?.iter()
        .map(|row| Ok((row, filename(&row["leaf"])?, filename(&row["issuer"])?)))
        .collect::<Result<Vec<_>>>()?;
    let loopback = format!("127.0.0.1:{port}");
    let inventory = || -> Result<Value> {
        let mut observations = Vec::new();
        for (row, leaf, issuer) in &profiles {
            let leaf = read(&directory, leaf)?;
            let issuer = read(&directory, issuer)?;
            leaf.verify_issuer(&issuer)?;
            observations.push(json!({"name":row["name"], "authority":row["authority"],
                "leaf":leaf.metadata()?, "issuer":issuer.metadata()?}));
        }
        app.run("inventory.response", json!(observations))
    };
    http::serve_gateway(port, |_, stream, request| {
        let route = app.run("inventory.route", json!({"loopback":loopback,
            "host":request.headers.get("host"), "path":request.path, "method":request.method}))?;
        match route.as_u64() {
            Some(404) => http::send_bytes(stream, "404 Not Found", "text/plain", "", b""),
            Some(405) => http::send_bytes(stream, "405 Method Not Allowed", "text/plain", "Allow: GET\r\n", b""),
            Some(200) => match inventory().and_then(|value| Ok(serde_json::to_vec(&value)?)) {
                Ok(body) if body.len() <= LIMIT => http::send_bytes(stream, "200 OK", "application/json; charset=utf-8", "", &body),
                _ => http::send_bytes(stream, "503 Service Unavailable", "text/plain", "", b""),
            },
            _ => Err(fail("Invalid inventory route result")),
        }
    })
}
