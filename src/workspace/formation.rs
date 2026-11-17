use super::{Request, Response, Workspace, cookie, cookie_value, equal, header, http, timestamp, token};
use super::transport::{form, write_atomic};
use crate::{Result, fail, rel};
use serde_json::{Value, json};
use std::{fs::{self, File}, io::{ErrorKind, Read}};

const KIND: &str = "SourceryFormationRecords";
const LIMIT: usize = 32_768;
const TEST_COOKIE: &str = "__Host-appdev-formation-test";
const TEST_GRANT: &str = "formation-test-grant";
const TEST_TTL_MS: i64 = 300_000;

pub(super) struct TestSession {
    secret: String,
    expires: i64,
}

impl TestSession {
    fn accepts(&self, secret: &str, now: i64) -> bool {
        self.expires > now && equal(&self.secret, secret)
    }
}

impl Workspace {
    pub(super) fn formation_test_session(&self, request: &Request, now: i64) -> Result<Response> {
        if request.path != "/workspace/formation/test-session" || !request.body.is_empty() {
            return Ok(Response::empty(400));
        }
        let mut active = self.runtime.formation_test.lock().map_err(|_| fail("Formation test session unavailable"))?;
        let authorization = header(request, "authorization");
        if authorization.is_empty() {
            let secret = cookie_value(request, TEST_COOKIE);
            if !active.as_ref().is_some_and(|session| session.accepts(secret, now)) {
                return Ok(Response::empty(401));
            }
            *active = None;
            return Ok(Response::empty(204).with("Set-Cookie", cookie(TEST_COOKIE, "", 0)));
        }
        let Some(grant) = authorization.strip_prefix("Bearer ").filter(|value|
            value.len() == 43 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))) else {
            return Ok(Response::empty(401));
        };
        let path = self.runtime.private.join(TEST_GRANT);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Response::empty(401)),
            Err(error) => return Err(error.into()),
        };
        let mut declaration = String::new();
        file.take(128).read_to_string(&mut declaration)?;
        let Some(expires) = grant_expiry(&declaration, grant, now) else { return Ok(Response::empty(401)); };
        let secret = token::<32>()?;
        // Consume the disk grant before issuing the browser credential, including across restarts.
        fs::remove_file(&path)?;
        let seconds = ((expires - now + 999) / 1000) as u32;
        let response = Response::empty(204).with("Set-Cookie", cookie(TEST_COOKIE, &secret, seconds));
        *active = Some(TestSession { secret, expires });
        Ok(response)
    }

    pub(super) fn formation_records(&self, request: &Request) -> Result<Response> {
        let secret = cookie_value(request, TEST_COOKIE);
        // Only this route reads the test cookie. The test store is separate from user records.
        let (owner, file) = if !secret.is_empty() {
            let active = self.runtime.formation_test.lock().map_err(|_| fail("Formation test session unavailable"))?;
            if !active.as_ref().is_some_and(|session| session.accepts(secret, timestamp().0)) {
                return Ok(Response::empty(401));
            }
            (rel::hash("appdev/formation-test/1"), "formation-test-records.rel".to_owned())
        } else {
            let Some(identity) = self.workspace_identity(request)? else { return Ok(Response::empty(401)); };
            let file = format!("formation-{}.rel", identity.principal_key);
            (identity.principal_key, file)
        };
        let path = self.runtime.private.join(file);
        let fields = if request.method == "POST" {
            if !form(request, LIMIT, true) {
                return Ok(Response::empty(400));
            }
            let Ok(fields) = http::form(&request.body) else {
                return Ok(Response::empty(400));
            };
            json!(fields)
        } else {
            Value::Null
        };
        let _guard = self.runtime.formation.lock().map_err(|_| fail("Formation storage lock unavailable"))?;
        let record = match File::open(&path) {
            Ok(file) => {
                let mut text = String::new();
                file.take(LIMIT as u64 + 1).read_to_string(&mut text)?;
                if text.len() > LIMIT { return Err(fail("Formation record exceeds storage limit")); }
                rel::decode(&text, KIND)?
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Value::Null,
            Err(error) => return Err(error.into()),
        };
        let result = self.run(json!({"program":"formation-records","owner":owner,
            "state":record,"fields":fields,"revision":token::<18>()?}))?;
        if let Some(write) = result.get("write").filter(|value| !value.is_null()) {
            let text = rel::encode(write, KIND)?;
            if text.len() > LIMIT { return Err(fail("Formation record exceeds storage limit")); }
            write_atomic(&path, text.as_bytes(), true)?;
        }
        let status = result["status"].as_u64().filter(|code| matches!(code, 200 | 400 | 409))
            .ok_or_else(|| fail("invalid Formation response status"))?;
        Ok(Response::json(status as u16, &result["body"]).with("Cache-Control", "no-store"))
    }
}

fn grant_expiry(declaration: &str, grant: &str, now: i64) -> Option<i64> {
    let (digest, expires) = declaration.trim_end().split_once(' ')?;
    let expires = expires.parse::<i64>().ok()?;
    (expires > now && expires <= now + TEST_TTL_MS && equal(digest, &rel::hash(grant))).then_some(expires)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_requires_the_token_and_a_short_remaining_lifetime() {
        let grant = "formation-test-fixture";
        let digest = rel::hash(grant);
        let now = 1_000_000;
        assert_eq!(grant_expiry(&format!("{digest} 1100000"), grant, now), Some(1_100_000));
        assert_eq!(grant_expiry(&format!("{digest} 1100000"), "wrong", now), None);
        assert_eq!(grant_expiry(&format!("{digest} 1000000"), grant, now), None);
        assert_eq!(grant_expiry(&format!("{digest} 1300001"), grant, now), None);
    }
}
