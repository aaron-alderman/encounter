use crate::{
    Result, fail, gateway::{self, IdentityPolicy}, http, http_client,
    workspace_sign_in::{CompletionClient, LegacyCompletion},
};
use std::{io::Write, time::Duration};

const FINISH: &str = "/identity-management/finish";
const PREFIX: &str = "/identity-management";

pub(crate) fn serve(port: u16, upstream: u16, origin: &str) -> Result<()> {
    if upstream == 0 || upstream == port { return Err(fail("Expected a separate Workspace authority port")); }
    let origin = gateway::origin(origin)?;
    let (_, host) = origin.split_once("://").ok_or_else(|| fail("Expected a Workspace origin"))?;
    let state_cookie = gateway::state_cookie(PREFIX, &origin);
    let legacy = LegacyCompletion::load()?;
    let identity = IdentityPolicy::load()?;
    let renderer = CompletionClient::configured()?.ok_or_else(|| fail("Workspace completion renderer is required"))?;

    http::serve_gateway(port, |_, stream, request| {
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        if path != FINISH || request.method != "GET" || !request.body.is_empty() || query.len() > 4096
            || !query.bytes().all(|byte| byte.is_ascii_graphic() && !b"#\\\"".contains(&byte))
            || request.headers.get("host").is_none_or(|value| value != host)
        {
            return http::send(stream, "404 Not Found", "text/plain", "Not found.");
        }
        // This bridge forwards the callback once. The session authority still owns
        // the OAuth result and emits every browser credential.
        let state = gateway::cookie(&request, &state_cookie);
        let cookie = state.as_deref().filter(|value| value.len() <= 1536 &&
            value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)))
            .map(|value| format!("{state_cookie}={value}"));
        let mut headers = vec![("Host", host)];
        if let Some(cookie) = cookie.as_deref() { headers.push(("Cookie", cookie)); }
        if let Some(accept) = request.headers.get("accept") { headers.push(("Accept", accept)); }
        let url = format!("http://127.0.0.1:{upstream}{FINISH}?{query}");
        let response = match http_client::send(http_client::Request {
            url: &url, method: "GET", headers: &headers, body: None,
            timeout: Duration::from_secs(8), connect_timeout: Duration::from_secs(1), limit: 128_000,
            resolve: None, trust_anchor: None, restoring: false,
        }) {
            Ok(response) => response,
            Err(_) => return http::send(stream, "502 Bad Gateway", "text/plain", "Workspace sign-in is unavailable."),
        };
        let destination = (response.status == 200
            && response.content_type == "text/html; charset=utf-8"
            && response.header_values("Set-Cookie").count() == 2
            && response.header_values("Content-Encoding").next().is_none())
            .then(|| legacy.destination(&response.body)).flatten()
            .filter(|destination| gateway::workspace_return(&identity, destination).unwrap_or(false));
        let replacement = destination.as_deref().and_then(|destination| renderer.page(destination).ok());
        let body = replacement.as_deref().map(str::as_bytes).unwrap_or(&response.body);
        write!(stream, "HTTP/1.1 {} Response\r\nContent-Length: {}\r\nConnection: close\r\n", response.status, body.len())?;
        for name in ["Content-Type", "Cache-Control", "Content-Security-Policy", "Referrer-Policy",
            "X-Content-Type-Options", "Location", "Set-Cookie", "Content-Encoding", "Vary", "Expires", "Pragma"]
        {
            for value in response.header_values(name).filter(|value| !value.bytes().any(|byte| byte.is_ascii_control())) {
                write!(stream, "{name}: {value}\r\n")?;
            }
        }
        stream.write_all(b"\r\n")?;
        stream.write_all(body)?;
        if destination.is_some() {
            let outcome = if replacement.is_some() { "rendered" } else { "authority-fallback" };
            eprintln!("AppDev Workspace completion response: {outcome}");
        }
        Ok(())
    })
}
