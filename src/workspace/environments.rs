use super::{Request, Response, Workspace, header, read_record};
use super::transport::{exchange, form, write_record};
use crate::{Result, fail, gateway, http, process::{HTML_PORTS, HTML_RENDERER, Meter, Programme}};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::PathBuf};

pub(super) struct Identity {
    preference: PathBuf,
    pub(super) principal_key: String,
    pub(super) email: String,
}

fn redirect_query<'a>(decision: &Value, raw_query: &'a str) -> &'a str {
    if decision["dropQuery"] == true { "" } else { raw_query }
}

pub(super) fn redirect(path: &str, query: &str) -> Response {
    let location = if query.is_empty() { path.to_owned() } else { format!("{path}?{query}") };
    Response::empty(303).with("Location", location)
}

pub(super) fn environment_markup(html: &str, steward: bool, picker: &str, mobile: bool) -> Result<String> {
    // This programme belongs to the host so it can also project releases
    // installed before the typed shell slots were introduced.
    thread_local! {
        static MARKUP: Result<Programme> = {
            let sources = HTML_RENDERER.into_iter().chain([include_str!("environment_markup.encounter")])
                .map(str::to_owned).collect::<Vec<_>>();
            let grants = BTreeSet::from_iter(HTML_PORTS.into_iter().chain(["html.select", "html.edit"]));
            Programme::admit_entries(&sources, &["environment.markup"], &grants, &mut Meter::new(20_000_000))
        };
    }
    MARKUP.with(|program| {
        let program = program.as_ref().map_err(|error| fail(error.to_string()))?;
        let result = program.run("environment.markup",
            json!({"html":html, "steward":steward, "picker":picker, "mobile":mobile}),
            &mut Meter::new(20_000_000))?;
        Ok(super::string(&result)?.to_owned())
    })
}

impl Workspace {
    pub(super) fn workspace_sign_out(&self, request: &Request) -> Result<Response> {
        let origin = &self.runtime.origin;
        let name = gateway::session_cookie("/identity-management", origin);
        let state_cookie = gateway::state_cookie("/identity-management", origin);
        if let Some(session) = gateway::cookie(request, &name)
            .filter(|value| value.len() == 48 && value.bytes().all(|b| b.is_ascii_hexdigit())) {
            let authority = origin.split_once("://").expect("validated origin").1;
            let cookie = format!("{name}={session}");
            let revoked = exchange(&self.runtime.identity_gateway, "/identity-management/workspace-sign-out", "POST",
                &[("Host", authority), ("Authorization", &self.runtime.authorization), ("Cookie", &cookie)], None, "5");
            if !revoked.is_ok_and(|response| response.status == 204) {
                return Ok(Response::text(503, "Temple sign-out is temporarily unavailable. Try again."));
            }
        }
        let local = super::SESSION_COOKIE;
        let pending = super::public_accounts::OAUTH_COOKIE;
        let mut state = self.state();
        state.sessions.remove(super::cookie_value(request, local));
        state.public_logins.remove(super::cookie_value(request, pending));
        Ok(Response::empty(204)
            .with("Set-Cookie", super::cookie(&name, "", 0))
            .with("Set-Cookie", super::cookie(&state_cookie, "", 0))
            .with("Set-Cookie", super::cookie(local, "", 0))
            .with("Set-Cookie", super::cookie(pending, "", 0)))
    }

    pub(super) fn workspace_identity(&self, request: &Request) -> Result<Option<Identity>> {
        self.observe_workspace_identity(request, false)
    }

    pub(super) fn observe_workspace_identity(&self, request: &Request, strict: bool) -> Result<Option<Identity>> {
        let origin = &self.runtime.origin;
        let authority = origin.split_once("://").expect("validated origin").1;
        let name = gateway::session_cookie("/identity-management", origin);
        let Some(session) = gateway::cookie(request, &name) else { return Ok(None); };
        if session.is_empty() || !session.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)) {
            return Ok(None);
        }
        let cookie = format!("{name}={session}");
        let response = exchange(&self.runtime.identity_gateway, "/identity-management/workspace-access", "GET",
            &[("Host", authority), ("Authorization", &self.runtime.authorization), ("Cookie", &cookie)], None, if strict { "2" } else { "5" });
        let response = match response {
            Ok(response) => response,
            Err(error) if strict => return Err(error),
            Err(_) => return Ok(None),
        };
        if !response.success() {
            if strict && !matches!(response.status, 401 | 403) {
                return Err(fail("workspace identity check unavailable"));
            }
            return Ok(None);
        }
        let value: Value = serde_json::from_slice(&response.body)?;
        let (Some(id), Some(email)) = (value["id"].as_str(), value["email"].as_str()) else { return Ok(None) };
        if id.is_empty() || email.is_empty() { return Ok(None); }
        let principal_key = format!("{:x}", Sha256::digest(id.as_bytes()));
        let preference = self.runtime.private.join(format!("workspace-default-{principal_key}.json"));
        Ok(Some(Identity { preference, principal_key, email: email.to_owned() }))
    }

    fn environment_policy(
        &self, identity: Option<&Identity>, saved: Option<Value>, submitted: Option<&str>, picker: bool,
    ) -> Result<Value> {
        self.run(json!({
            "program":"workspace", "operation":"environment-policy",
            "signedIn":identity.is_some(), "email":identity.map(|identity| identity.email.as_str()),
            "stewardEmail":self.runtime.steward,
            "saved":saved, "submitted":submitted, "picker":picker
        }))
    }

    pub(super) fn workspace_default(&self, identity: Option<&Identity>) -> Result<String> {
        let saved = identity.map(|identity| read_record(&identity.preference)).transpose()?;
        let decision = self.environment_policy(identity, saved, None, false)?;
        Ok(super::string(&decision["destination"])?.to_owned())
    }

    pub(super) fn platform_allowed(&self, identity: Option<&Identity>) -> Result<bool> {
        Ok(self.environment_policy(identity, None, None, false)?["platform"] == true)
    }

    pub(super) fn default_workspace(&self, request: &Request, route: &Value, raw_query: &str) -> Result<Response> {
        if let Some(path) = route["destination"].as_str() {
            return Ok(redirect(path, redirect_query(route, raw_query)));
        }
        Ok(redirect(&self.workspace_default(self.workspace_identity(request)?.as_ref())?, raw_query))
    }

    pub(super) fn environment_page(&self, request: &Request, route: &Value, raw_query: &str) -> Result<Response> {
        if route["route"] == "platform" {
            if !self.platform_allowed(self.workspace_identity(request)?.as_ref())? {
                return Ok(Response::text(403, "Platform is available to the Platform steward."));
            }
            if let Some(path) = route["destination"].as_str() {
                return Ok(redirect(path, redirect_query(route, raw_query)));
            }
            return self.platform_page(request, &route["platformView"]);
        }
        if let Some(path) = route["destination"].as_str() {
            return Ok(redirect(path, redirect_query(route, raw_query)));
        }
        let identity = self.workspace_identity(request)?;
        let saved = identity.as_ref().map(|identity| read_record(&identity.preference)).transpose()?;
        let decision = self.environment_policy(identity.as_ref(), saved, None, true)?;
        let steward = decision["platform"] == true;
        let projected = self.projected()?;
        let html = super::string(&projected["html"])?;
        let picker = if identity.is_some() { super::string(&decision["picker"])? } else { "" };
        let html = environment_markup(html, steward, picker, false)?;
        let image_source = format!("img-src data: {}{};", self.runtime.origin, super::files::GAME_IMAGE_PREFIX);
        let policy = self.release.policy.replace("img-src data:;", &image_source);
        let policy = self.workspace_frame_policy(format!("{policy}; media-src {origin}/workspace/file-media; frame-src {origin}/workspace/vm-manager http://localhost:24220/decompiler", origin = self.runtime.origin), request);
        Ok(Response::html(200, html, policy)
            .with("Referrer-Policy", "same-origin"))
    }

    fn platform_page(&self, request: &Request, view: &Value) -> Result<Response> {
        let page = self.run(json!({"program":"workspace","operation":"platform-page","view":view}))?;
        let html = super::string(&page)?;
        let style = html.split_once("<style>").and_then(|(_, tail)| tail.split_once("</style>"))
            .map(|(style, _)| style).ok_or_else(|| fail("missing Platform stylesheet"))?;
        let style_hash = Base64::encode_string(&Sha256::digest(style));
        let policy = self.workspace_frame_policy(format!(
            "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'sha256-{style_hash}'; frame-src http://localhost:24220/decompiler; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"), request);
        Ok(Response::html(200, html, policy).with("Referrer-Policy", "same-origin"))
    }

    pub(super) fn workspace_access(&self, request: &Request) -> Result<Response> {
        let allowed = self.platform_allowed(self.workspace_identity(request)?.as_ref())?;
        Ok(Response::json(200, &json!({"platform":allowed})))
    }

    pub(super) fn save_workspace_preference(&self, request: &Request) -> Result<Response> {
        if header(request, "origin") != self.runtime.origin { return Ok(Response::empty(403)); }
        let Some(identity) = self.workspace_identity(request)? else { return Ok(Response::empty(401)) };
        if !form(request, 256, true) { return Ok(Response::empty(400)); }
        let Ok(fields) = http::form(&request.body) else { return Ok(Response::empty(400)) };
        let Some(path) = fields.get("environment").filter(|_| fields.len() == 1) else { return Ok(Response::empty(400)) };
        if self.environment_policy(Some(&identity), None, Some(path), false)?["save"] != true {
            return Ok(Response::empty(403));
        }
        write_record(&identity.preference, &json!(path), true)?;
        if header(request, "accept") == "application/json" {
            return Ok(Response::json(200, &json!({"environment":path})));
        }
        Ok(redirect(path, ""))
    }
}

#[cfg(test)]
mod tests {
    use super::environment_markup;

    #[test]
    fn environment_markup_projects_legacy_and_typed_platform_slots() {
        let style = "<style>.desktop{display:grid}</style>";
        let card = "<li><a href=\"/workspace/platform\">Platform card</a></li>";
        for marker in ["", "=\"\""] {
            let start = format!("<span data-workspace-platform-start{marker}></span>");
            let html = format!(
                "{style}<span data-workspace-platform{marker}></span>{start}\
                 <template data-workspace-platform-card{marker}>{card}</template>\
                 <span data-workspace-preference{marker}></span>"
            );
            let anonymous = environment_markup(&html, false, "", false).unwrap();
            assert!(anonymous.starts_with(style));
            assert!(anonymous.contains(&start));
            assert!(!anonymous.contains("/workspace/platform"));
            assert!(!anonymous.contains("data-workspace-platform-card"));
            let signed_in = environment_markup(&html, true, "<form>Preference</form>", false).unwrap();
            assert!(signed_in.starts_with(style));
            assert!(signed_in.contains("id=\"notes-platform-launch\""));
            assert!(signed_in.contains(card));
            assert!(signed_in.contains("<form>Preference</form>"));
            assert!(!signed_in.contains("data-workspace-platform-card"));
            let mobile = environment_markup(&html, true, "", true).unwrap();
            assert!(mobile.contains("<a href=\"/workspace/platform\">Platform</a>"));
            assert!(mobile.contains("data-workspace-platform-card"));
            assert!(!mobile.contains("id=\"notes-platform-launch\""));
        }
    }
}
