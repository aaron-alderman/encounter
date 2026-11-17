use crate::{Result, application::Application, fail, gateway, http, process::{Meter, Programme}};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::{cell::OnceCell, io::Read, net::TcpStream, path::Path, sync::Mutex, time::Duration};
use subtle::ConstantTimeEq;

const HOSTED_COOKIE: &str = "__Host-sourcery_session";
const RESPONSE_LIMIT: u64 = 256 * 1024;

thread_local! {
    static PROGRAMME: OnceCell<Programme> = const { OnceCell::new() };
}

fn evaluate(programme: &Programme, entry: &str, input: Value) -> Result<Value> {
    programme.run(entry, input, &mut Meter::new(20_000_000))
}

struct Broker {
    app: Application,
    authority: String,
    gateway: u16,
    preview: u16,
    accounts: [(&'static str, String, Value); 2],
    forwarding: Mutex<()>,
}

impl Broker {
    fn account(&self, name: &str) -> Result<&(&'static str, String, Value)> {
        self.accounts.iter().find(|(role, _, _)| *role == name)
            .ok_or_else(|| fail("Unknown synthetic broker account"))
    }

    fn forward(&self, programme: &Programme, client: &mut TcpStream, decision: &Value) -> Result<()> {
        // The gateway calls back into this broker to resolve the synthetic principal.
        let Ok(_forwarding) = self.forwarding.try_lock() else {
            return http::send(client, "503 Service Unavailable", "text/plain", "Preview sign-in is busy.");
        };
        let target = decision["target"].as_str().filter(|target| target.starts_with('/') && !target.starts_with("//")
            && target.len() <= 8192 && target.bytes().all(|byte| byte.is_ascii_graphic() && !b"\\#".contains(&byte)))
            .ok_or_else(|| fail("Invalid preview gateway request target"))?;
        let cookie = match decision["account"].as_str() {
            Some(name) => format!("Cookie: {HOSTED_COOKIE}={}\r\n", self.account(name)?.1),
            None if decision["account"].is_null() => String::new(),
            None => return Err(fail("Invalid preview sign-in account")),
        };
        let request = format!("GET {target} HTTP/1.1\r\nHost: {}\r\n{cookie}Connection: close\r\n\r\n", self.authority);
        let mut reply = http::LoopbackReply::open(self.gateway, request.as_bytes(), Duration::from_secs(5))?;
        let (start, headers) = http::read_head(&mut reply)?;
        let mut line = start.splitn(3, ' ');
        if !matches!(line.next(), Some("HTTP/1.0" | "HTTP/1.1")) || headers.contains_key("transfer-encoding") {
            return Err(fail("Invalid preview gateway response framing"));
        }
        let response = evaluate(programme, "previewBroker.gatewayResponse", json!({
            "status":line.next(), "location":headers.get("location"), "preview":self.preview
        }))?;
        let status = response["status"].as_str()
            .filter(|line| line.bytes().all(|byte| byte.is_ascii_graphic() || byte == b' '))
            .ok_or_else(|| fail("Invalid preview gateway status decision"))?;
        let length = headers.get("content-length").and_then(|value| value.parse::<u64>().ok())
            .filter(|length| *length <= RESPONSE_LIMIT).ok_or_else(|| fail("Invalid preview gateway response length"))?;
        let mut body = vec![0; length as usize];
        reply.read_exact(&mut body)?;
        let body = std::str::from_utf8(&body)?;
        let location = match response["location"].as_str() {
            Some(location) if location.bytes().all(|byte| byte.is_ascii_graphic()) =>
                format!("Location: {location}\r\nReferrer-Policy: no-referrer\r\n"),
            None if response["location"].is_null() => String::new(),
            _ => return Err(fail("Invalid preview gateway redirect decision")),
        };
        http::send_headers(client, status, "text/html", &location, body)
    }

    fn handle(&self, programme: &Programme, client: &mut TcpStream, request: http::Request) -> Result<()> {
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        let fields = match http::form(query.as_bytes()) {
            Ok(fields) => fields,
            Err(_) => return http::send(client, "400 Bad Request", "text/plain", "Invalid preview request."),
        };
        let account = gateway::cookie(&request, HOSTED_COOKIE).and_then(|token| self.accounts.iter()
            .find(|(_, expected, _)| bool::from(expected.as_bytes().ct_eq(token.as_bytes()))).map(|(name, _, _)| *name));
        let decision = evaluate(programme, "previewBroker.route", json!({
            "localHost":request.headers.get("host") == Some(&self.authority),
            "method":request.method,"path":path,"query":fields,"account":account
        }))?;
        match decision["kind"].as_str() {
            Some("gateway") => self.forward(programme, client, &decision),
            Some("login") => http::send(client, "200 OK", "text/html",
                decision["body"].as_str().ok_or_else(|| fail("Invalid synthetic sign-in page"))?),
            Some("identity") => {
                let name = decision["account"].as_str().ok_or_else(|| fail("Invalid synthetic identity decision"))?;
                http::send(client, "200 OK", "application/json",
                    &json!({"kind":"user","identity":self.account(name)?.2}).to_string())
            }
            Some("refuse") => {
                let status = match decision["status"].as_u64() {
                    Some(400) => "400 Bad Request",
                    Some(401) => "401 Unauthorized",
                    Some(403) => "403 Forbidden",
                    Some(404) => "404 Not Found",
                    Some(405) => "405 Method Not Allowed",
                    _ => return Err(fail("Invalid synthetic broker refusal")),
                };
                http::send(client, status, "text/plain", "Preview request refused.")
            }
            _ => Err(fail("Invalid synthetic broker decision")),
        }
    }
}

pub fn serve(app: &Path, listener: &str, gateway: &str, preview: &str, steward: &str) -> Result<()> {
    let listener: u16 = listener.parse()?;
    let gateway: u16 = gateway.parse()?;
    let preview: u16 = preview.parse()?;
    if [listener, gateway, preview].iter().any(|port| *port < 1024)
        || listener == gateway || listener == preview || gateway == preview {
        return Err(fail("Expected distinct unprivileged loopback preview ports"));
    }
    let app = Application::load(app, "release/workflow.rel")?;
    if ["previewBroker.configure", "previewBroker.route", "previewBroker.gatewayResponse"].iter().any(|entry| !app.has_entry(entry)) {
        return Err(fail("Expected the declared synthetic preview broker entries"));
    }
    let programme = app.admit(&mut Meter::new(20_000_000))?;
    let identities = evaluate(&programme, "previewBroker.configure", json!({"steward":steward}))?;
    let account = |role| -> Result<_> {
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| fail("Synthetic broker entropy unavailable"))?;
        Ok((role, format!("src_session_{}", Base64UrlUnpadded::encode_string(&nonce)), identities[role].clone()))
    };
    let accounts = [account("steward")?, account("member")?];
    let broker = Broker { app, authority:format!("127.0.0.1:{listener}"), gateway, preview, accounts,
        forwarding:Mutex::new(()) };
    http::serve_workers(listener, 4, 0, move |client, request| {
        let result = PROGRAMME.with(|slot| {
            if slot.get().is_none() {
                let programme = broker.app.admit(&mut Meter::new(20_000_000))?;
                let _ = slot.set(programme);
            }
            broker.handle(slot.get().expect("initialized preview broker"), client, request)
        });
        if let Err(error) = result {
            eprintln!("Preview identity broker: {error}");
            let _ = http::send(client, "502 Bad Gateway", "text/plain", "Preview identity is unavailable.");
        }
    })
}

#[cfg(test)]
#[path = "../tests/unit/appdev_preview_broker.rs"]
mod tests;
