use super::{Account, Fields, Request, Response, ROOM_LIMIT, SESSION_COOKIE, SESSION_LIFETIME,
    Workspace, cookie, cookie_value, equal, timestamp, token};
use super::transport::{GOOGLE_INFO, GOOGLE_TOKEN, MICROSOFT_INFO, MICROSOFT_TOKEN, encode, exchange};
use crate::{Result, fail};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, fs, io::ErrorKind, path::Path};

pub(super) const OAUTH_COOKIE: &str = "__Host-appdev-public-oauth";
const FAILURE: &str = "/workspace/home?open=front-gate#public-sign-in-failed";
const ATTEMPT_SECONDS: u32 = 600;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Provider { Gmail, Microsoft }

impl Provider {
    pub(super) fn parse(name: &str) -> Result<Self> {
        match name {
            "gmail" => Ok(Self::Gmail),
            "microsoft" => Ok(Self::Microsoft),
            _ => Err(fail("unknown public sign-in provider")),
        }
    }

    fn callback(self, origin: &str) -> String {
        let name = match self { Self::Gmail => "gmail", Self::Microsoft => "microsoft" };
        format!("{origin}/workspace/auth/{name}/callback")
    }

    fn authorize(self) -> (&'static str, &'static str) {
        match self {
            Self::Gmail => ("https://accounts.google.com/o/oauth2/v2/auth", "openid email"),
            Self::Microsoft => ("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize", "openid profile"),
        }
    }

    fn display(self, profile: &Value) -> Option<String> {
        profile["sub"].as_str().filter(|subject| printable(subject, 255))?;
        match self {
            Self::Gmail => {
                let email = profile["email"].as_str().filter(|email| printable(email, 320))?;
                let (user, domain) = email.split_once('@')?;
                (profile["email_verified"] == true && !user.is_empty() && domain.eq_ignore_ascii_case("gmail.com"))
                    .then(|| email.to_owned())
            }
            Self::Microsoft => Some(profile["name"].as_str().map(str::trim)
                .filter(|name| !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control))
                .unwrap_or("Microsoft account").to_owned()),
        }
    }

    fn profile(self, credentials: &Credentials, callback: &str, verifier: &str, code: &str) -> Result<Option<String>> {
        let ((token_origin, token_path), (info_origin, info_path)) = match self {
            Self::Gmail => ((GOOGLE_TOKEN, "/token"), (GOOGLE_INFO, "/v1/userinfo")),
            Self::Microsoft => ((MICROSOFT_TOKEN, "/consumers/oauth2/v2.0/token"), (MICROSOFT_INFO, "/oidc/userinfo")),
        };
        let form = encode(&json!({
            "grant_type":"authorization_code", "code":code, "redirect_uri":callback, "code_verifier":verifier,
            "client_id":credentials.id, "client_secret":credentials.secret,
        }))?;
        let reply = exchange(token_origin, token_path, "POST", &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(&form), "8")?;
        if !reply.success() { return Ok(None); }
        let tokens: Value = serde_json::from_slice(&reply.body)?;
        let Some(access) = tokens["access_token"].as_str().filter(|token| printable(token, 16384)) else {
            return Ok(None);
        };
        if !tokens["token_type"].as_str().is_some_and(|kind| kind.eq_ignore_ascii_case("Bearer")) {
            return Ok(None);
        }
        // Only the fixed provider UserInfo endpoint supplies the display profile.
        let reply = exchange(info_origin, info_path, "GET", &[("Authorization", &format!("Bearer {access}"))], None, "8")?;
        if !reply.success() { return Ok(None); }
        Ok(self.display(&serde_json::from_slice(&reply.body)?))
    }
}

fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub(super) struct Credentials { id: String, secret: String }

impl Credentials {
    fn load(directory: &Path, name: &str) -> Result<Option<Self>> {
        let content = match fs::read(directory.join(name)) {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let invalid = || fail(format!("invalid {name} credential"));
        if content.len() > 4096 { return Err(invalid()); }
        let value: Value = serde_json::from_slice(&content).map_err(|_| invalid())?;
        let field = |key| value[key].as_str().filter(|value| printable(value, 1024))
            .map(str::to_owned).ok_or_else(invalid);
        Ok(Some(Self { id: field("clientId")?, secret: field("clientSecret")? }))
    }
}

#[derive(Default)]
pub(super) struct Providers {
    pub(super) gmail: Option<Credentials>,
    pub(super) microsoft: Option<Credentials>,
}

impl Providers {
    pub(super) fn load() -> Result<Self> {
        let Some(directory) = env::var_os("CREDENTIALS_DIRECTORY") else { return Ok(Self::default()); };
        let directory = Path::new(&directory);
        Ok(Self {
            gmail: Credentials::load(directory, "public-gmail-oauth")?,
            microsoft: Credentials::load(directory, "public-microsoft-oauth")?,
        })
    }

    fn get(&self, provider: Provider) -> Option<&Credentials> {
        match provider { Provider::Gmail => self.gmail.as_ref(), Provider::Microsoft => self.microsoft.as_ref() }
    }
}

pub(super) struct Login { provider: Provider, verifier: String, expires: i64 }

impl Workspace {
    pub(super) fn authorize_public(&self, request: &Request, provider: Provider, now: i64) -> Result<Response> {
        let Some(credentials) = self.runtime.public_providers.get(provider) else {
            return Ok(Response::text(503, "This public sign-in provider is unavailable."));
        };
        let mut state = self.state();
        state.public_logins.remove(cookie_value(request, OAUTH_COOKIE));
        state.public_logins.retain(|_, login| login.expires > now);
        if state.public_logins.len() >= ROOM_LIMIT {
            return Ok(Response::text(503, "Sign-in is busy. Try again shortly."));
        }
        let key = token::<32>()?;
        let verifier = token::<32>()?;
        let (endpoint, scope) = provider.authorize();
        let fields = encode(&json!({
            "response_type":"code", "client_id":credentials.id, "redirect_uri":provider.callback(&self.runtime.origin),
            "scope":scope, "state":key, "prompt":"select_account", "code_challenge_method":"S256",
            "code_challenge":Base64UrlUnpadded::encode_string(&Sha256::digest(&verifier)),
        }))?;
        state.public_logins.insert(key.clone(), Login {
            provider, verifier, expires: now + i64::from(ATTEMPT_SECONDS) * 1000,
        });
        Ok(redirect(&format!("{endpoint}?{fields}"), cookie(OAUTH_COOKIE, &key, ATTEMPT_SECONDS)))
    }

    pub(super) fn callback_public(&self, request: &Request, query: &Fields, provider: Provider, now: i64) -> Result<Response> {
        let Some(credentials) = self.runtime.public_providers.get(provider) else { return Ok(Response::empty(404)); };
        let clear = || cookie(OAUTH_COOKIE, "", 0);
        let failed = || redirect(FAILURE, clear());
        let key = cookie_value(request, OAUTH_COOKIE);
        let mut received = query.all("state");
        if !received.next().is_some_and(|received| !key.is_empty() && equal(received, key)) || received.next().is_some() {
            return Ok(failed());
        }
        let login = self.state().public_logins.remove(key);
        let Some(login) = login.filter(|login| login.provider == provider && login.expires > now) else {
            return Ok(failed());
        };
        let mut codes = query.all("code");
        let Some(code) = codes.next().filter(|code| printable(code, 4096)) else { return Ok(failed()); };
        if codes.next().is_some() || query.get("error").is_some() { return Ok(failed()); }
        let callback = provider.callback(&self.runtime.origin);
        let Ok(Some(display)) = provider.profile(credentials, &callback, &login.verifier, code) else {
            return Ok(failed());
        };
        let Some(session) = self.state().start_local_session(request, Account::Public(display), timestamp().0)? else {
            return Ok(failed());
        };
        Ok(redirect("/workspace/home?open=front-gate#public-sign-in-complete", clear())
            .with("Set-Cookie", cookie(SESSION_COOKIE, &session, SESSION_LIFETIME)))
    }
}

fn redirect(location: &str, cookie: String) -> Response {
    Response::empty(303).with("Location", location).with("Set-Cookie", cookie)
        .with("Cache-Control", "no-store").with("Referrer-Policy", "no-referrer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_profiles_are_provider_specific() {
        let gmail = json!({"sub":"42","email":"personal@gmail.com","email_verified":true});
        assert_eq!(Provider::Gmail.display(&gmail).as_deref(), Some("personal@gmail.com"));
        assert_eq!(Provider::Gmail.display(&json!({"sub":"42","email":"personal@gmail.com","email_verified":false})), None);
        assert_eq!(Provider::Gmail.display(&json!({"sub":"42","email":"staff@example.org","email_verified":true})), None);
        assert_eq!(Provider::Microsoft.display(&json!({"sub":"42","email":"staff@example.org"})).as_deref(), Some("Microsoft account"));
        assert_eq!(Provider::Microsoft.display(&json!({"name":"Missing subject"})), None);
    }
}
