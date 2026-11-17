use super::{registry_presentation::Presentation, Base64, Encoding, Fields, Request, Response, Sha256, Workspace, environments::redirect, header, string, token};
use crate::{Result, gateway};
use serde_json::json;
use sha2::Digest;
use std::{collections::HashMap, time::{Duration, Instant}};

pub(super) const PAGE: &str = "/workspace/vm-manager";
pub(super) const DEMO: &str = "vm=sourcery-registry-demo&view=display";
const APPROVAL_LIMIT: Duration = Duration::from_secs(5 * 60);
const SESSION_LIMIT: Duration = Duration::from_secs(60 * 60);
const CAPACITY: usize = 256;

type Binding = [u8; 32];

struct Entry {
    binding: Binding,
    expires: Instant,
}

#[derive(Default)]
pub(super) struct Sessions {
    approvals: HashMap<String, Entry>,
    launches: HashMap<String, Entry>,
}

impl Sessions {
    fn create_approval(&mut self, binding: Binding, now: Instant) -> Result<Option<String>> {
        self.approvals.retain(|_, entry| entry.expires > now);
        if self.approvals.len() >= CAPACITY { return Ok(None); }
        let ticket = token::<24>()?;
        self.approvals.insert(ticket.clone(), Entry { binding, expires: now + APPROVAL_LIMIT });
        Ok(Some(ticket))
    }

    fn approve(&mut self, ticket: &str, binding: Binding, now: Instant) -> Result<Option<String>> {
        if !self.approvals.get(ticket).is_some_and(|entry| entry.binding == binding && entry.expires > now) {
            return Ok(None);
        }
        self.launches.retain(|_, entry| entry.expires > now);
        if self.launches.len() >= CAPACITY { return Ok(None); }
        let launch = token::<24>()?;
        self.approvals.remove(ticket);
        self.launches.insert(launch.clone(), Entry { binding, expires: now + SESSION_LIMIT });
        Ok(Some(launch))
    }

    fn remaining(&self, launch: &str, binding: Binding, now: Instant) -> Option<Duration> {
        let entry = self.launches.get(launch).filter(|entry| entry.binding == binding && entry.expires > now)?;
        Some(entry.expires.duration_since(now))
    }

    fn end(&mut self, launch: &str, binding: Binding, now: Instant) {
        if self.remaining(launch, binding, now).is_some() { self.launches.remove(launch); }
    }
}

impl Workspace {
    fn steward_binding(&self, request: &Request) -> Option<Binding> {
        let name = gateway::session_cookie("/identity-management", &self.runtime.origin);
        gateway::cookie(request, &name).map(|session| Sha256::digest(session.as_bytes()).into())
    }

    pub(super) fn workspace_sign_in_page(&self, destination: &str) -> Result<Response> {
        // All callers build destinations from declared routes and validated fields.
        let encoded = super::transport::encode(&json!({"workspace-return":destination}))?;
        self.workspace_access_page(401, "Sign in to Workspace",
            "Sign in with your AppDev account to continue.", Some(&format!("/identity-management/?{encoded}")), None)
    }

    pub(super) fn workspace_access_page(&self, status: u16, title: &str, message: &str,
                                        sign_in: Option<&str>, approval: Option<(&str, &Presentation)>) -> Result<Response> {
        let page = self.run(json!({"program":"workspace", "operation":"workspace-access-page",
            "title":title, "message":message, "signIn":sign_in, "approval":approval.map(|(ticket, _)| ticket),
            "approvalWarning":approval.map(|(_, view)| view.text("warning")),
            "approvalAcknowledgment":approval.map(|(_, view)| view.text("acknowledgment")),
            "approvalStyle":approval.map(|(_, view)| view.css.as_str()),
            "approvalAction":format!("{PAGE}?{DEMO}")}))?;
        let style = approval.map(|(_, view)| format!(" 'sha256-{}'", Base64::encode_string(&Sha256::digest(view.css.as_bytes())))).unwrap_or_default();
        let policy = format!("default-src 'none'; style-src 'self'{style}; frame-ancestors 'self'; base-uri 'none'; form-action 'self'");
        Ok(Response::html(status, string(&page)?, policy).with("Referrer-Policy", "strict-origin"))
    }

    pub(super) fn registry_approval(&self, request: &Request) -> Result<Response> {
        let Some(binding) = self.steward_binding(request) else { return Ok(Response::empty(403)); };
        let ticket = self.runtime.steward_sessions.lock().unwrap_or_else(|e| e.into_inner())
            .create_approval(binding, Instant::now())?;
        let Some(ticket) = ticket else { return Ok(Response::text(503, "Steward approval is temporarily busy.")); };
        let view = self.runtime.registry_presentation.current();
        self.workspace_access_page(200, view.text("title"), view.text("message"), None, Some((&ticket, &view)))
    }

    pub(super) fn registry_steward_action(&self, request: &Request, query: &Fields) -> Result<Response> {
        if header(request, "origin") != self.runtime.origin || !super::transport::form(request, 512, false)
            || query.len() != 2 || query.get("vm") != Some(super::registry_shadow::GUEST)
            || query.get("view") != Some("display") {
            return Ok(Response::empty(403));
        }
        let identity = self.observe_workspace_identity(request, true)?;
        if !self.platform_allowed(identity.as_ref())? { return Ok(Response::empty(403)); }
        let Some(binding) = self.steward_binding(request) else { return Ok(Response::empty(403)); };
        let fields = Fields::parse(&request.body);
        let mut sessions = self.runtime.steward_sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if let Some(ticket) = fields.get("approve") {
            if fields.len() != 2 || fields.get("acknowledge") != Some("registry-display") {
                return Ok(Response::text(400, "Acknowledge elevated access before approving Registry Demo Display."));
            }
            let Some(launch) = sessions.approve(ticket, binding, now)? else {
                return Ok(Response::text(409, "Approval is no longer available. Reopen Registry Demo Display to try again."));
            };
            return Ok(redirect(PAGE, &format!("{DEMO}&launch={launch}")));
        }
        if let Some(launch) = fields.get("end").filter(|_| fields.len() == 1) {
            sessions.end(launch, binding, now);
            return Ok(redirect(PAGE, DEMO));
        }
        Ok(Response::empty(400))
    }

    pub(super) fn registry_steward_remaining(&self, request: &Request, launch: &str) -> Option<Duration> {
        let binding = self.steward_binding(request)?;
        self.runtime.steward_sessions.lock().unwrap_or_else(|e| e.into_inner())
            .remaining(launch, binding, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_single_use_and_bound_to_the_appdev_session() {
        let mut sessions = Sessions::default();
        let now = Instant::now();
        let owner = [1; 32];
        let other = [2; 32];
        let ticket = sessions.create_approval(owner, now).unwrap().unwrap();
        assert!(sessions.approve(&ticket, other, now).unwrap().is_none());
        let launch = sessions.approve(&ticket, owner, now).unwrap().unwrap();
        assert!(sessions.approve(&ticket, owner, now).unwrap().is_none());
        assert!(sessions.remaining(&launch, other, now).is_none());
        assert_eq!(sessions.remaining(&launch, owner, now), Some(SESSION_LIMIT));
        assert!(sessions.remaining(&launch, owner, now + SESSION_LIMIT).is_none());
        sessions.end(&launch, other, now);
        assert!(sessions.remaining(&launch, owner, now).is_some());
        sessions.end(&launch, owner, now);
        assert!(sessions.remaining(&launch, owner, now).is_none());
        let ticket = sessions.create_approval(owner, now).unwrap().unwrap();
        assert!(sessions.approve(&ticket, owner, now + APPROVAL_LIMIT).unwrap().is_none());
    }
}
