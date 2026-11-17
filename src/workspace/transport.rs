use crate::{Result, fail, http::Request, http_client};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions}, io::{Read, Write}, net::TcpStream,
    os::unix::fs::OpenOptionsExt, path::Path, time::Duration,
};
use subtle::ConstantTimeEq;

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| fail("workspace entropy unavailable"))?;
    Ok(bytes)
}

pub fn token<const N: usize>() -> Result<String> {
    Ok(Base64UrlUnpadded::encode_string(&random::<N>()?))
}

pub fn pairing_code() -> Result<String> {
    loop {
        let value = u32::from_le_bytes(random()?);
        if value < u32::MAX - u32::MAX % 1_000_000 {
            return Ok(format!("{:06}", value % 1_000_000));
        }
    }
}

pub fn timestamp() -> (i64, String) {
    let now: DateTime<Utc> = std::time::SystemTime::now().into();
    (now.timestamp_millis(), now.to_rfc3339_opts(SecondsFormat::Millis, true))
}

pub fn qr(text: &str) -> Result<String> {
    let code = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium)
        .map_err(|_| fail("workspace QR payload exceeds capacity"))?;
    let scale = 240 / (code.size() + 8);
    let start = (240 - code.size() * scale) / 2;
    let mut pixels = vec![255; 240 * 240];
    for y in 0..code.size() {
        for x in 0..code.size() {
            if code.get_module(x, y) {
                for row in start + y * scale..start + (y + 1) * scale {
                    let offset = (row * 240 + start + x * scale) as usize;
                    pixels[offset..offset + scale as usize].fill(0);
                }
            }
        }
    }
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 240, 240);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.write_header()?.write_image_data(&pixels)?;
    }
    Ok(format!("data:image/png;base64,{}", Base64::encode_string(&bytes)))
}

pub fn hmac(secret: &[u8], data: &[u8]) -> String {
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    let digest;
    let key = if secret.len() > 64 {
        digest = Sha256::digest(secret);
        digest.as_slice()
    } else { secret };
    for (i, byte) in key.iter().enumerate() {
        inner[i] ^= byte;
        outer[i] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(inner);
    hash.update(data);
    let digest = hash.finalize_reset();
    hash.update(outer);
    hash.update(digest);
    format!("sha256={}", Base64::encode_string(&hash.finalize()))
}

pub fn equal(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

pub fn read_record(path: &Path) -> Result<Value> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Value::Null),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(2_000_001).read_to_end(&mut bytes)?;
    if bytes.len() > 2_000_000 { return Err(fail("workspace record limit")); }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_record(path: &Path, record: &Value, replace: bool) -> Result<()> {
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    write_atomic(path, &bytes, replace)
}

pub fn write_atomic(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let temporary = path.with_extension(format!("{}.pending", token::<12>()?));
    let mut file = OpenOptions::new().mode(0o600).write(true).create_new(true).open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace { fs::rename(&temporary, path)?; } else { fs::hard_link(&temporary, path)?; }
        File::open(path.parent().ok_or_else(|| fail("missing workspace state directory"))?)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}

pub struct Fields(Vec<(String, String)>);

impl Fields {
    pub fn parse(bytes: &[u8]) -> Self {
        Self(form_urlencoded::parse(bytes).into_owned().collect())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str())
    }

    pub fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0.iter().filter(move |(name, _)| name == key).map(|(_, value)| value.as_str())
    }

    pub fn len(&self) -> usize { self.0.len() }

    pub fn record(&self) -> Value {
        Value::Object(self.0.iter().cloned().map(|(key, value)| (key, Value::String(value))).collect())
    }
}

pub fn encode(fields: &Value) -> Result<String> {
    let mut encoded = form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields.as_object().ok_or_else(|| fail("expected form fields"))? {
        encoded.append_pair(name, string(value)?);
    }
    Ok(encoded.finish())
}

pub fn string(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| fail("expected workspace programme text"))
}

pub fn header<'a>(request: &'a Request, name: &str) -> &'a str {
    request.headers.get(name).map(String::as_str).unwrap_or_default()
}

pub fn form(request: &Request, limit: usize, charset: bool) -> bool {
    let kind = header(request, "content-type");
    let plain = "application/x-www-form-urlencoded";
    let matches = kind == plain || charset && kind.split_once(';').is_some_and(|(media, parameters)|
        media.eq_ignore_ascii_case(plain) && parameters.trim().eq_ignore_ascii_case("charset=utf-8"));
    matches && !request.body.is_empty() && request.body.len() <= limit
}

pub struct Response {
    status: u16,
    kind: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    file: Option<Box<dyn Read + Send>>,
    length: u64,
}

impl Response {
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        let body = body.into().into_bytes();
        Self { status, kind: "text/plain; charset=utf-8", headers: vec![], length: body.len() as u64, body, file: None }
    }

    pub fn empty(status: u16) -> Self { Self::text(status, "") }

    pub fn script(body: &str) -> Self {
        Self { kind: "text/javascript; charset=utf-8", ..Self::text(200, body) }
    }

    pub fn css(body: &str) -> Self {
        Self { kind: "text/css; charset=utf-8", ..Self::text(200, body) }
    }

    pub fn json(status: u16, body: &Value) -> Self {
        Self { kind: "application/json; charset=utf-8", ..Self::text(status, body.to_string()) }
    }

    pub fn html(status: u16, body: impl Into<String>, policy: String) -> Self {
        Self::html_body(status, body).with("Content-Security-Policy", policy)
    }

    pub(crate) fn html_body(status: u16, body: impl Into<String>) -> Self {
        Self { kind: "text/html; charset=utf-8", ..Self::text(status, body) }
    }

    pub fn download(path: &Path, name: &str) -> Result<Self> {
        let file = File::open(path)?;
        let length = file.metadata()?.len();
        Ok(Self { length, file: Some(Box::new(file)), kind: "application/octet-stream", ..Self::empty(200) }
            .with("Content-Disposition", format!("attachment; filename=\"{name}\"")))
    }

    pub fn stream(status: u16, kind: &'static str, length: u64, stream: impl Read + Send + 'static) -> Self {
        Self { kind, length, file: Some(Box::new(stream)), ..Self::empty(status) }
    }

    pub fn with(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((key, value.into()));
        self
    }

    pub fn send(mut self, stream: &mut TcpStream, head: bool) -> Result<()> {
        let reason = match self.status {
            200 => "OK", 201 => "Created", 204 => "No Content", 206 => "Partial Content", 303 => "See Other",
            400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found",
            405 => "Method Not Allowed", 409 => "Conflict", 413 => "Content Too Large",
            416 => "Range Not Satisfiable", 429 => "Too Many Requests", 500 => "Internal Server Error", 503 => "Service Unavailable",
            _ => "Response",
        };
        if self.headers.iter().any(|(_, value)| value.contains(['\r', '\n', '\0'])) {
            return Err(fail("invalid workspace response header"));
        }
        write!(stream, "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Robots-Tag: noindex\r\n",
            self.status, self.kind, self.length)?;
        if !self.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("Referrer-Policy")) {
            write!(stream, "Referrer-Policy: no-referrer\r\n")?;
        }
        for (name, value) in &self.headers { write!(stream, "{name}: {value}\r\n")?; }
        stream.write_all(b"\r\n")?;
        if !head {
            if let Some(file) = self.file.take() { std::io::copy(&mut file.take(self.length), stream)?; }
            else { stream.write_all(&self.body)?; }
        }
        Ok(())
    }
}

pub struct Upstream {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Upstream {
    pub fn success(&self) -> bool { (200..300).contains(&self.status) }
}

pub(super) const X_API: &str = "https://api.x.com";
pub(super) const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com";
pub(super) const GOOGLE_INFO: &str = "https://openidconnect.googleapis.com";
pub(super) const MICROSOFT_TOKEN: &str = "https://login.microsoftonline.com";
pub(super) const MICROSOFT_INFO: &str = "https://graph.microsoft.com";

pub fn exchange(origin: &str, path: &str, method: &str, headers: &[(&str, &str)],
    body: Option<&str>, seconds: &str) -> Result<Upstream> {
    let loopback = origin.strip_prefix("http://127.0.0.1:").is_some_and(|port|
        !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|port| port != 0));
    let provider = matches!(origin, X_API | GOOGLE_TOKEN | GOOGLE_INFO | MICROSOFT_TOKEN | MICROSOFT_INFO);
    if !(loopback || provider) || !path.starts_with('/') || path.starts_with("//") || path.contains(['#', '\\']) {
        return Err(fail("invalid workspace upstream request"));
    }
    let timeout = Duration::try_from_secs_f64(seconds.parse()?)?;
    let result = http_client::send(http_client::Request {
        url: &format!("{origin}{path}"), method, headers, body: body.map(str::as_bytes),
        timeout, connect_timeout: Duration::from_secs(3), limit: 2_097_152,
        resolve: None, trust_anchor: None, restoring: false,
    }).map_err(|_| fail("workspace upstream unavailable"))?;
    Ok(Upstream { status: result.status, content_type: result.content_type, body: result.body })
}

#[cfg(test)]
#[test]
fn workspace_upstream_refuses_undeclared_hosts_and_authority_paths() {
    for (origin, path) in [("https://elsewhere.example", "/"), ("http://127.0.0.1:0", "/"),
        ("http://127.0.0.1:1234", "//elsewhere.example"), ("http://127.0.0.1:1234", "/#fragment")] {
        assert_eq!(exchange(origin, path, "GET", &[], None, "1").err().unwrap().to_string(),
            "invalid workspace upstream request");
    }
}
