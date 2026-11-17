use super::{Fields, Request, Response, Workspace, header, token};
use super::transport::form;
use crate::{Result, gateway};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::{Duration, Instant}};

const SIGN_IN: &str = "/identity-management/terminal";
const PENDING_TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_secs(3600);
const LIMIT: usize = 256;

type Key = [u8; 32];

struct Session {
    expires: Instant,
    approval: Approval,
}

enum Approval {
    Pending(String),
    Linked(String),
}

#[derive(Default)]
pub(super) struct Sessions(HashMap<Key, Session>);

fn key(value: &str) -> Key {
    Sha256::digest(value.as_bytes()).into()
}

fn bearer(request: &Request) -> Option<Key> {
    let value = header(request, "authorization").strip_prefix("Bearer ")?;
    valid_token(value, 43).then(|| key(value))
}

fn valid_token(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

fn sign_in_redirect() -> Response {
    Response::empty(303).with("Location", SIGN_IN)
}

impl Workspace {
    fn start_terminal(&self) -> Result<Response> {
        let mut sessions = self.runtime.terminal.lock().expect("terminal sessions");
        let now = Instant::now();
        sessions.0.retain(|_, session| session.expires > now);
        if sessions.0.len() >= LIMIT {
            return Ok(Response::empty(429));
        }
        let secret = token::<32>()?;
        let code = token::<9>()?;
        sessions.0.insert(key(&secret), Session {
            expires: now + PENDING_TTL,
            approval: Approval::Pending(code.clone()),
        });
        Ok(Response::json(201, &json!({"token":secret, "code":code, "expiresIn":PENDING_TTL.as_secs()})))
    }

    fn approve_terminal(&self, request: &Request) -> Result<Response> {
        if !form(request, 100, false) {
            return Ok(Response::empty(400));
        }
        let fields = Fields::parse(&request.body);
        let Some(code) = fields.get("code").filter(|code| fields.len() == 1 && valid_token(code, 12)) else {
            return Ok(Response::text(400, "Enter the case-sensitive code shown in your Terminal."));
        };
        let name = gateway::session_cookie("/identity-management", &self.runtime.origin);
        let Some(cookie) = gateway::cookie(request, &name) else {
            return Ok(sign_in_redirect());
        };
        if self.workspace_identity(request)?.is_none() {
            return Ok(sign_in_redirect());
        }
        let mut sessions = self.runtime.terminal.lock().expect("terminal sessions");
        let now = Instant::now();
        let Some(session) = sessions.0.values_mut().find(|session| {
            session.expires > now && matches!(&session.approval, Approval::Pending(candidate) if candidate == code)
        }) else {
            return Ok(Response::text(404, "The code has expired or has already been approved. Return to Terminal."));
        };
        session.approval = Approval::Linked(cookie);
        session.expires = now + SESSION_TTL;
        Ok(Response::text(200, "Sourcery Workspace Terminal approved. Return to your terminal."))
    }

    pub(super) fn terminal_route(&self, route: &str, request: &Request, fields: &Fields, raw_query: &str) -> Result<Response> {
        if (route != "terminal-files" && !raw_query.is_empty())
            || (route != "terminal-approve" && !request.body.is_empty()) {
            return Ok(Response::empty(400));
        }

        match route {
            "terminal-start" => return self.start_terminal(),
            "terminal-entry" => {
                let destination = if self.workspace_identity(request)?.is_some() {
                    "/workspace/terminal/approve"
                } else {
                    "/identity-management/"
                };
                return Ok(Response::empty(303).with("Location", destination));
            }
            "terminal-approval-page" => {
                if self.workspace_identity(request)?.is_none() {
                    return Ok(sign_in_redirect());
                }
                let page = self.run(json!({"program":"workspace", "operation":"terminal-approval-page"}))?;
                return Ok(Response::html(200, super::string(&page)?,
                    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'".to_owned())
                    .with("Referrer-Policy", "same-origin"));
            }
            "terminal-approve" => return self.approve_terminal(request),
            _ => {}
        }

        let Some(key) = bearer(request) else { return Ok(Response::empty(401)); };
        let cookie = {
            let mut sessions = self.runtime.terminal.lock().expect("terminal sessions");
            if route == "terminal-end" {
                sessions.0.remove(&key);
                return Ok(Response::empty(204));
            }
            let Some(session) = sessions.0.get(&key).filter(|session| session.expires > Instant::now()) else {
                return Ok(Response::empty(401));
            };
            match &session.approval {
                Approval::Linked(cookie) => cookie.clone(),
                Approval::Pending(_) if route == "terminal-session" => return Ok(Response::empty(202)),
                Approval::Pending(_) => return Ok(Response::empty(401)),
            }
        };

        // The workspace gateway cookie stays server-side. Treat it like any other
        // gateway session and let the regular file policy choose admitted roots.
        let name = gateway::session_cookie("/identity-management", &self.runtime.origin);
        let authenticated = Request {
            method: "GET".to_owned(),
            path: request.path.clone(),
            headers: [("cookie".to_owned(), format!("{name}={cookie}"))].into(),
            body: Vec::new(),
        };
        let Some(identity) = self.workspace_identity(&authenticated)? else {
            return Ok(Response::empty(401));
        };
        match route {
            "terminal-session" => Ok(Response::json(200, &json!({"email":identity.email}))),
            "terminal-catalogue" => {
                let data = self.run(json!({"program":"workspace", "operation":"terminal-catalogue"}))?;
                Ok(Response::json(200, &data))
            }
            "terminal-files" if raw_query.is_empty() => self.file_index(&authenticated, ""),
            "terminal-files" => {
                let Some(id) = fields.get("file").filter(|id| fields.len() == 1 && id.len() == 64 &&
                    id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())) else {
                    return Ok(Response::empty(400));
                };
                self.file_index(&authenticated, &format!("file={id}&view=file"))
            }
            _ => Ok(Response::empty(404)),
        }
    }
}
