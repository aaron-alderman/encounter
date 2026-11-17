use crate::{Result, fail, http, mcp_client_socket, mcp_workspace_access::{Access, BrowserLookup, now_ms, portfolio_bearer},
    package, process::{Meter, Programme}};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::{BTreeSet, VecDeque}, ffi::{c_int, c_uint, c_void}, fs::File, io::{self, Read, Write},
    os::unix::fs::MetadataExt, path::Path, ptr::{self, NonNull}};
use zeroize::Zeroizing;
use subtle::ConstantTimeEq;

const PROTOCOL: &[u8] = b"sourcery.hosted/mcp-project-context.v1";
const WORKSPACE_SELECTION_PROTOCOL: &[u8] = b"sourcery-mcp-workspace-selection/1";
const TOKEN_LIMIT: usize = 4096;
const METER: usize = 100_000;
const GET_TAG: c_int = 0x10;
const SET_TAG: c_int = 0x11;
const HANDSHAKE_CLIENT_LIMIT: usize = 1024;

#[link(name = "libcrypto.so.3", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn EVP_CIPHER_CTX_new() -> *mut c_void;
    fn EVP_CIPHER_CTX_free(context: *mut c_void);
    fn EVP_aes_256_gcm() -> *const c_void;
    fn EVP_CipherInit_ex(context: *mut c_void, cipher: *const c_void, engine: *mut c_void,
        key: *const u8, iv: *const u8, encrypt: c_int) -> c_int;
    fn EVP_CipherUpdate(context: *mut c_void, output: *mut u8, written: *mut c_int,
        input: *const u8, length: c_int) -> c_int;
    fn EVP_CipherFinal_ex(context: *mut c_void, output: *mut u8, written: *mut c_int) -> c_int;
    fn EVP_CIPHER_CTX_ctrl(context: *mut c_void, operation: c_int, size: c_int, value: *mut c_void) -> c_int;
    fn EVP_sha256() -> *const c_void;
    fn HMAC(digest: *const c_void, key: *const c_void, key_len: c_int, data: *const u8, data_len: usize,
        output: *mut u8, output_len: *mut c_uint) -> *mut u8;
}

struct Cipher(NonNull<c_void>);

impl Drop for Cipher {
    fn drop(&mut self) { unsafe { EVP_CIPHER_CTX_free(self.0.as_ptr()); } }
}

struct ProjectKey(Zeroizing<[u8; 32]>);

fn double_submit(cookie: &str, name: &str, submitted: &str) -> bool {
    if cookie.len() > 16 * 1024 { return false; }
    let mut matching = false;
    for (_, value) in http::cookie_fields(cookie).filter(|(key, _)| *key == name) {
        let Ok(value) = http::decode_cookie(value) else { return false; };
        matching |= bool::from(submitted.as_bytes().ct_eq(Zeroizing::new(value).as_bytes()));
    }
    matching
}

impl ProjectKey {
    fn load(path: &Path) -> Result<Self> {
        let root = File::open("/")?;
        let mut file = package::open_artifact(&root, path.strip_prefix("/")?)?;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1 || metadata.len() != 32 {
            return Err(fail("Expected an owner-only 32-byte hosted MCP project context key"));
        }
        let mut key = Zeroizing::new([0; 32]);
        file.read_exact(&mut *key)?;
        if file.read(&mut [0; 1])? != 0 { return Err(fail("Hosted MCP project context key changed while reading")); }
        let after = file.metadata()?;
        if metadata.ctime() != after.ctime() || metadata.ctime_nsec() != after.ctime_nsec() {
            return Err(fail("Hosted MCP project context key changed while reading"));
        }
        Ok(Self(key))
    }

    fn crypt(&self, protocol: &[u8], encrypt: bool, iv: &[u8; 12], input: &[u8], tag: &mut [u8; 16]) -> Result<Zeroizing<Vec<u8>>> {
        let error = || fail("Hosted MCP project context authentication failed");
        let context = Cipher(NonNull::new(unsafe { EVP_CIPHER_CTX_new() }).ok_or_else(error)?);
        let context = context.0.as_ptr();
        let mut output = Zeroizing::new(vec![0u8; input.len() + 32]);
        let mut ignored = 0;
        let mut written = 0;
        let mut final_written = 0;
        unsafe {
            if EVP_CipherInit_ex(context, EVP_aes_256_gcm(), ptr::null_mut(), self.0.as_ptr(), iv.as_ptr(), encrypt.into()) != 1
                || EVP_CipherUpdate(context, ptr::null_mut(), &mut ignored, protocol.as_ptr(), protocol.len().try_into()?) != 1
                || EVP_CipherUpdate(context, output.as_mut_ptr(), &mut written, input.as_ptr(), input.len().try_into()?) != 1
                || !encrypt && EVP_CIPHER_CTX_ctrl(context, SET_TAG, 16, tag.as_mut_ptr().cast()) != 1
            {
                return Err(error());
            }
            let offset = usize::try_from(written)?;
            if offset > input.len() || EVP_CipherFinal_ex(context, output.as_mut_ptr().add(offset), &mut final_written) != 1
                || encrypt && EVP_CIPHER_CTX_ctrl(context, GET_TAG, 16, tag.as_mut_ptr().cast()) != 1
            {
                return Err(error());
            }
        }
        let length = usize::try_from(written.checked_add(final_written).ok_or_else(error)?)?;
        if length != input.len() { return Err(error()); }
        output.truncate(length);
        Ok(output)
    }

    fn seal(&self, claims: &Value) -> Result<String> {
        self.seal_for(PROTOCOL, claims)
    }

    fn seal_for(&self, protocol: &[u8], claims: &Value) -> Result<String> {
        let mut iv = [0; 12];
        getrandom::getrandom(&mut iv).map_err(|_| fail("Hosted MCP project context entropy unavailable"))?;
        let mut tag = [0; 16];
        let plaintext = Zeroizing::new(serde_json::to_vec(claims)?);
        let ciphertext = self.crypt(protocol, true, &iv, &plaintext, &mut tag)?;
        let token = [&iv[..], ciphertext.as_slice(), &tag[..]].map(Base64UrlUnpadded::encode_string).join(".");
        if token.len() > TOKEN_LIMIT { return Err(fail("Hosted MCP project context exceeds its size limit")); }
        Ok(token)
    }

    fn unseal(&self, token: &str) -> Result<Value> {
        self.unseal_for(PROTOCOL, token)
    }

    fn unseal_for(&self, protocol: &[u8], token: &str) -> Result<Value> {
        let error = || fail("Invalid hosted MCP project context envelope");
        if token.len() > TOKEN_LIMIT { return Err(error()); }
        let mut parts = token.split('.');
        let mut part = || Base64UrlUnpadded::decode_vec(parts.next().ok_or_else(error)?).map_err(|_| error());
        let iv: [u8; 12] = part()?.try_into().map_err(|_| error())?;
        let ciphertext = part()?;
        let mut tag: [u8; 16] = part()?.try_into().map_err(|_| error())?;
        if parts.next().is_some() || ciphertext.is_empty() { return Err(error()); }
        let plaintext = self.crypt(protocol, false, &iv, &ciphertext, &mut tag)?;
        let claims = serde_json::from_slice(&plaintext).map_err(|_| error())?;
        crate::compat_value::external(&claims)?;
        Ok(claims)
    }

    fn signed_form(&self, token: &str, limit: usize) -> Option<Value> {
        let (payload, proof) = token.split_once('.')?;
        if payload.is_empty() || token.len() > limit { return None; }
        let proof = Base64UrlUnpadded::decode_vec(proof).ok()?;
        let mac = self.mac(payload).ok()?;
        if !bool::from(mac.as_slice().ct_eq(&proof)) { return None; }
        let bytes = Zeroizing::new(Base64UrlUnpadded::decode_vec(payload).ok()?);
        let claims: Value = serde_json::from_slice(&bytes).ok()?;
        claims.as_object()?;
        crate::compat_value::external(&claims).ok()?;
        Some(claims)
    }

    fn mac(&self, message: &str) -> Result<Zeroizing<[u8; 32]>> {
        let mut mac = Zeroizing::new([0; 32]);
        let mut len = 0;
        let written = unsafe { HMAC(EVP_sha256(), self.0.as_ptr().cast(), 32, message.as_ptr(), message.len(),
            mac.as_mut_ptr(), &mut len) };
        if written.is_null() || len != 32 { return Err(fail("Hosted browser signature mechanism failed")); }
        Ok(mac)
    }

    fn sign_form(&self, claims: &Value) -> Result<String> {
        let payload = Base64UrlUnpadded::encode_string(&serde_json::to_vec(claims)?);
        let proof = Base64UrlUnpadded::encode_string(&*self.mac(&payload)?);
        Ok(format!("{payload}.{proof}"))
    }
}

fn policy() -> Result<Programme> {
    Programme::admit_entries(&[include_str!("mcp_project_context.encounter").to_owned(),
        include_str!("mcp_project_portfolio.encounter").to_owned(), include_str!("mcp_project_http.encounter").to_owned(),
        include_str!("mcp_browser_selection.encounter").to_owned(), include_str!("mcp_browser_consent.encounter").to_owned(),
        include_str!("mcp_client.encounter").to_owned(), include_str!("mcp_browser_authorize.encounter").to_owned()],
        &["mcpProjectContext.issue", "mcpProjectContext.coordinates", "mcpProjectContext.verify",
            "mcpProjectPortfolio.request", "mcpProjectPortfolio.reply", "mcpProjectHttp.operation", "mcpProjectHttp.transport",
            "mcpProjectHttp.discovery", "mcpProjectHttp.reply", "mcpProjectHttp.error", "mcpProjectHttp.handshakeContract",
            "mcpProjectHttp.handshakeClient", "mcpProjectHttp.handshakeReply",
            "mcpBrowserSelection.form", "mcpBrowserSelection.binding", "mcpBrowserSelection.plan", "mcpBrowserSelection.error",
            "mcpBrowserConsent.form", "mcpBrowserConsent.binding", "mcpBrowserConsent.redirect", "mcpBrowserConsent.error",
            "mcpBrowserAuthorize.request", "mcpBrowserAuthorize.portfolio", "mcpBrowserAuthorize.record", "mcpBrowserAuthorize.form"],
        &BTreeSet::from(["digest.sha256", "json.canonical", "json.stringify", "kernel.invoke", "number.calculate", "number.isNatural",
            "record.entries", "record.put", "text.matches", "text.slice", "text.split", "value.describe"]),
        &mut Meter::new(METER))
}

pub(crate) struct Tool {
    access: Access,
    key: ProjectKey,
    consent_key: Option<ProjectKey>,
    consent_commit_key: Option<ProjectKey>,
    policy: Programme,
    handshake_contract: Value,
    handshake_clients: RefCell<VecDeque<String>>,
}

impl Tool {
    pub(crate) fn load(key: &Path, configuration: &[String]) -> Result<Self> {
        let policy = policy()?;
        let handshake_contract = policy.run("mcpProjectHttp.handshakeContract", Value::Null, &mut Meter::new(METER))?;
        Ok(Self { access:Access::load(configuration)?, key:ProjectKey::load(key)?, consent_key:None, consent_commit_key:None, policy, handshake_contract,
            handshake_clients:RefCell::new(VecDeque::new()) })
    }

    pub(crate) fn with_consent_keys(mut self, path: &Path, commit: &Path) -> Result<Self> {
        let key = ProjectKey::load(path)?;
        let commit = ProjectKey::load(commit)?;
        if bool::from(self.key.0.as_slice().ct_eq(key.0.as_slice())
            | self.key.0.as_slice().ct_eq(commit.0.as_slice()) | key.0.as_slice().ct_eq(commit.0.as_slice())) {
            return Err(fail("Hosted browser consent, commit, and workspace selection require separate keys"));
        }
        self.consent_key = Some(key);
        self.consent_commit_key = Some(commit);
        Ok(self)
    }

    pub(crate) fn ready(&self) -> Result<()> {
        self.access.portfolio_ready()?;
        self.access.browser_authorize_ready()?;
        let key = self.consent_commit_key.as_ref().ok_or_else(|| fail("Hosted browser consent commit key is unavailable"))?;
        self.access.browser_consent_ready(&hex::encode(&*key.mac("encounter/browser-consent-ready/1")?))
    }

    pub(crate) fn browser_lookup(&self, cookie: &str, lookup: BrowserLookup) -> Result<Value> {
        self.access.browser_lookup(cookie, lookup)
    }

    pub(crate) fn authorize_browser(&self, cookie: &str, href: &str, resolver: &mcp_client_socket::Client) -> Result<Value> {
        let Some(query) = href.strip_prefix("/oauth/authorize?").filter(|_| href.len() <= 8192
            && href.bytes().all(|byte| byte.is_ascii_graphic()) && !href.contains(['#', '\\']))
            else { return Ok(json!({"error":"parameter","detail":"authorization request"})); };
        let fields: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();
        let request = self.evaluate("mcpBrowserAuthorize.request", json!({"fields":fields,"resource":self.access.browser_resource()}))?;
        if request["error"] != "" { return Ok(request); }
        let selection = fields.iter().find(|(name, _)| name == "sourcery_portfolio")
            .and_then(|(_, token)| self.key.unseal_for(WORKSPACE_SELECTION_PROTOCOL, token).ok());
        let mut registration = None;
        for _ in 0..2 {
            let Some((digest, revision, browser)) = self.access.browser_portfolio_evidence(cookie)?
                else { return Ok(json!({"error":"session"})); };
            let chosen = self.evaluate("mcpBrowserAuthorize.portfolio", json!({
                "fields":fields,"browser":browser,"selection":selection,"nowMs":now_ms()
            }))?;
            if chosen["error"].is_string() { return Ok(chosen); }
            let user = browser["subject"]["userId"].as_str().ok_or_else(|| fail("Missing verified browser subject"))?;
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce).map_err(|_| fail("Browser authorization entropy unavailable"))?;
            let nonce = Base64UrlUnpadded::encode_string(&nonce);
            if let Some(portfolios) = chosen.get("portfolios") {
                let claims = self.evaluate("mcpBrowserAuthorize.form", json!({"userId":user,"href":href,"nonce":nonce,"nowMs":now_ms()}))?;
                return Ok(json!({"kind":"portfolio","portfolios":portfolios,"scopeText":request["scopeText"],
                    "csrf":self.key.sign_form(&claims)?}));
            }
            if registration.is_none() {
                let id = request["clientId"].as_str().ok_or_else(|| fail("Missing authorization client identity"))?;
                let redirect = request["redirectUri"].as_str().ok_or_else(|| fail("Missing authorization callback"))?;
                let client = resolver.resolve(id, redirect)?;
                if client["error"] == "invalid_client" { return Ok(json!({"error":"client"})); }
                if client["error"] == "invalid_redirect" { return Ok(json!({"error":"callback"})); }
                registration = Some(client);
            }
            let mut entropy = [0; 12];
            getrandom::getrandom(&mut entropy).map_err(|_| fail("Browser authorization request entropy unavailable"))?;
            let id = format!("mcp_arq_{}", hex::encode(entropy));
            let record = self.evaluate("mcpBrowserAuthorize.record", json!({"request":request,"registration":registration,
                "portfolio":chosen["selected"],"userId":user,"id":id}))?;
            let record_json = serde_json::to_string(&record)?;
            let now = now_ms();
            let deadline = selection.as_ref().and_then(|claims| claims["expiresAt"].as_i64())
                .map_or(now + 5000, |expires| expires.min(now + 5000));
            let message = format!("encounter/browser-authorize/1|{digest}|{revision}|{deadline}|{}", crate::rel::hash(&record_json));
            let commit_key = self.consent_commit_key.as_ref().ok_or_else(|| fail("Hosted browser authorization commit key is unavailable"))?;
            let proof = hex::encode(&*commit_key.mac(&message)?);
            let consent_key = self.consent_key.as_ref().ok_or_else(|| fail("Hosted browser consent key is unavailable"))?;
            let claims = self.evaluate("mcpBrowserAuthorize.form", json!({"userId":user,"requestId":id,"nonce":nonce,"nowMs":now}))?;
            let csrf = consent_key.sign_form(&claims)?;
            let receipt = self.access.begin_browser_authorization(&digest, &revision.to_string(), &deadline.to_string(), &record_json, &proof)?;
            match receipt["status"].as_str() {
                Some("committed") => return Ok(json!({"kind":"consent","csrf":csrf,"requestId":id,
                    "clientName":record["clientName"],"resource":record["resource"],"redirectUri":record["redirectUri"],
                    "scopes":record["scopes"],"summary":record["grant"]["summary"]})),
                Some("stale") => {}
                _ => return Ok(json!({"error":"selection"})),
            }
        }
        Ok(json!({"error":"selection"}))
    }

    pub(crate) fn select_browser_portfolio(&self, cookie: &str, form: Value) -> Result<Value> {
        let reject = |reason| self.evaluate("mcpBrowserSelection.error", json!(reason));
        let available = self.access.browser_lookup(cookie, BrowserLookup::Portfolio)?;
        let Some(user) = available["subject"]["userId"].as_str() else { return reject("session"); };
        let fields = self.evaluate("mcpBrowserSelection.form", form)?;
        if let Some(error) = fields["error"].as_str() { return reject(error); }
        let submitted = fields["csrf"].as_str().unwrap_or_default();
        let cookie_name = fields["cookieName"].as_str().ok_or_else(|| fail("Missing portfolio cookie name"))?;
        if !double_submit(cookie, cookie_name, submitted) { return reject("csrf"); }
        let Some(claims) = self.key.signed_form(submitted, 16 * 1024) else { return reject("binding"); };
        let now = now_ms();
        if self.evaluate("mcpBrowserSelection.binding", json!({"claims":claims,"userId":user,"nowMs":now}))? != true {
            return reject("binding");
        }
        let href = claims["authorizeHref"].as_str().unwrap_or_default();
        let (path, query) = if href.len() <= 8192 && !href.contains(['#', '\\'])
            && href.bytes().all(|byte| byte.is_ascii_graphic()) {
            href.split_once('?').unwrap_or((href, ""))
        } else { ("", "") };
        let query: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| fail("Portfolio selection entropy unavailable"))?;
        let plan = self.evaluate("mcpBrowserSelection.plan", json!({"userId":user,"portfolios":available["portfolios"],
            "selected":fields["selected"],"path":path,"query":query,"nowMs":now,"nonce":Base64UrlUnpadded::encode_string(&nonce)}))?;
        if let Some(error) = plan["error"].as_str() { return reject(error); }
        let token = self.key.seal_for(WORKSPACE_SELECTION_PROTOCOL, &plan["claims"])?;
        let query = form_urlencoded::Serializer::new(String::new()).extend_pairs(query)
            .append_pair("sourcery_portfolio", &token).finish();
        Ok(json!({"status":303,"location":format!("{path}?{query}")}))
    }

    fn browser_consent_plan(&self, cookie: &str, form: Value) -> Result<Value> {
        let fields = self.evaluate("mcpBrowserConsent.form", form)?;
        if fields["error"].is_string() { return Ok(fields); }
        let Some(submitted) = fields["csrf"].as_str() else { return Ok(json!({"error":"csrf"})); };
        let name = fields["cookieName"].as_str().ok_or_else(|| fail("Missing browser consent cookie name"))?;
        if !double_submit(cookie, name, submitted) { return Ok(json!({"error":"csrf"})); }
        let key = self.consent_key.as_ref().ok_or_else(|| fail("Hosted browser consent key is unavailable"))?;
        let Some(claims) = key.signed_form(submitted, 4096) else { return Ok(json!({"error":"binding"})); };
        if self.evaluate("mcpBrowserConsent.binding", json!({"claims":claims,"nowMs":now_ms()}))? != true {
            return Ok(json!({"error":"binding"}));
        }
        let decision = fields["decision"].as_str().ok_or_else(|| fail("Missing browser consent decision"))?;
        self.access.browser_consent_plan(cookie, &claims, decision)
    }

    pub(crate) fn commit_browser_consent(&self, cookie: &str, form: Value) -> Result<Value> {
        if let Some(result) = self.try_browser_consent(cookie, form.clone())? { return Ok(result); }
        if let Some(result) = self.try_browser_consent(cookie, form)? { return Ok(result); }
        self.evaluate("mcpBrowserConsent.error", json!("stale"))
    }

    fn try_browser_consent(&self, cookie: &str, form: Value) -> Result<Option<Value>> {
        let reject = |reason| self.evaluate("mcpBrowserConsent.error", json!(reason)).map(Some);
        let plan = self.browser_consent_plan(cookie, form)?;
        if let Some(reason) = plan["error"].as_str() { return reject(reason); }
        let decision = plan["decision"].as_str().ok_or_else(|| fail("Missing planned consent decision"))?;
        let mut code_id = String::new();
        let mut code_digest = String::new();
        let mut code = Zeroizing::new(String::new());
        if decision == "approve" {
            let mut entropy = Zeroizing::new([0; 44]);
            getrandom::getrandom(entropy.as_mut_slice()).map_err(|_| fail("Browser authorization code entropy unavailable"))?;
            code_id = format!("mcp_code_{}", hex::encode(&entropy[..12]));
            *code = format!("src_mcp_code_{}", Base64UrlUnpadded::encode_string(&entropy[12..]));
            code_digest = crate::rel::hash(code.as_str());
        }
        let parameters = self.evaluate("mcpBrowserConsent.redirect", json!({
            "redirectUri":plan["redirectUri"],"state":plan["state"],"decision":decision,
            "code":code.as_str(),"issuer":self.access.browser_issuer()
        }))?;
        if parameters.is_null() { return reject("pending"); }
        let parameters: Vec<(String, String)> = serde_json::from_value(parameters)?;
        let target = plan["redirectUri"].as_str().ok_or_else(|| fail("Missing retained consent callback"))?;
        let (base, query) = target.split_once('?').unwrap_or((target, ""));
        let mut retained: Vec<_> = form_urlencoded::parse(query.as_bytes()).into_owned().collect();
        for (name, value) in parameters {
            let mut replacement = Some(value);
            retained.retain_mut(|(key, current)| {
                if *key != name { return true; }
                let Some(value) = replacement.take() else { return false; };
                *current = value;
                true
            });
            if let Some(value) = replacement { retained.push((name, value)); }
        }
        let query = form_urlencoded::Serializer::new(String::new()).extend_pairs(retained).finish();
        let location = format!("{base}?{query}");
        let digest = self.access.browser_coordinate(cookie)?.ok_or_else(|| fail("Missing verified browser session coordinate"))?;
        let request = plan["requestId"].as_str().ok_or_else(|| fail("Missing planned consent request"))?;
        let revision = |field| plan[field].as_u64().map(|number| number.to_string())
            .ok_or_else(|| fail("Missing browser consent revision"));
        let oauth = revision("oauthRevision")?;
        let control = revision("controlRevision")?;
        let expiry = revision("csrfExpiry")?;
        let fields = [digest.as_str(), request, decision, &oauth, &control, &expiry, &code_id, &code_digest];
        let message = format!("encounter/browser-consent-commit/1|{}", fields.join("|"));
        let key = self.consent_commit_key.as_ref().ok_or_else(|| fail("Hosted browser consent commit key is unavailable"))?;
        let proof = hex::encode(&*key.mac(&message)?);
        let receipt = self.access.commit_browser_consent(fields, &proof)?;
        match receipt["status"].as_str() {
            Some("committed") => Ok(Some(json!({"status":302,"location":location}))),
            Some("stale") => Ok(None),
            Some("refused") => reject("stale"),
            _ => Err(fail("Missing hosted browser consent receipt")),
        }
    }

    pub(crate) fn exchange_oauth(&self, plan: &Value) -> Result<Value> {
        self.access.exchange_oauth(plan)
    }

    pub(crate) fn revoke_oauth(&self, digest: &str) -> Result<()> {
        self.access.revoke_oauth(digest)
    }

    fn evaluate(&self, name: &str, input: Value) -> Result<Value> {
        self.policy.run(name, input, &mut Meter::new(METER))
    }

    fn reply(&self, request: Value, selection: Value) -> Result<Value> {
        let context = selection.get("access").map(|grant| {
            let claims = self.evaluate("mcpProjectContext.issue", json!({"access":grant, "nowMs":now_ms()}))?;
            self.key.seal(&claims)
        }).transpose()?;
        self.evaluate("mcpProjectPortfolio.reply", json!({"request":request,"selection":selection,"projectContext":context}))
    }

    fn failure(&self, message: &Value, reason: &str, detail: &str) -> Result<Value> {
        self.evaluate("mcpProjectHttp.error", json!({"id":message["id"],"reason":reason,"detail":detail,
            "requestId":crate::nonce::uuid_v4()?}))
    }

    pub(crate) fn http_call(&self, bearer: &str, message: Value, headers: &Value) -> Result<Value> {
        fn mirrored(header: &str) -> Option<String> {
            if let Some(encoded) = header.strip_prefix("=?base64?").and_then(|value| value.strip_suffix("?=")) {
                let decoded = Base64::decode_vec(encoded).ok()?;
                if Base64::encode_string(&decoded) == encoded { return String::from_utf8(decoded).ok(); }
                return None;
            }
            (header.trim() == header && header.bytes().all(|byte| (32..=126).contains(&byte)))
                .then(|| header.to_owned())
        }
        let operation = self.evaluate("mcpProjectHttp.operation", message.clone())?;
        if operation.is_null() { return self.failure(&message, "request", ""); }
        if !portfolio_bearer(bearer) { return self.failure(&message, "invalidToken", ""); }
        let authentication = if operation == "project" { self.access.portfolio(bearer) }
            else { self.access.connection(bearer) };
        let portfolio = match authentication {
            Ok(Ok(portfolio)) => portfolio,
            Ok(Err(_)) => return self.failure(&message, "invalidToken", ""),
            Err(_) => return self.failure(&message, "backend", ""),
        };
        let header = |name| headers[name].as_str().unwrap_or("");
        let method = header("method");
        let name = header("name");
        let wire = self.evaluate("mcpProjectHttp.transport", json!({"message":message,"version":header("version"),
            "method":mirrored(method),"name":mirrored(name),"methodPresent":!method.is_empty(),"namePresent":!name.is_empty()}))?;
        if let Some(reason) = wire["reason"].as_str() {
            let detail = match reason {
                "method" => message["method"].as_str(),
                "version" => wire["requested"].as_str(),
                _ => wire["detail"].as_str(),
            };
            return self.failure(&message, reason, detail.unwrap_or_default());
        }
        let client = if wire["handshake"] == true {
            self.evaluate("mcpProjectHttp.handshakeClient", json!({"subject":portfolio.subject(),
                "session":header("session"),"userAgent":header("userAgent")}))?
        } else { Value::Null };
        let reply = match operation.as_str() {
            Some("project") => {
                if !portfolio.read { return self.failure(&message, "scope", ""); }
                let request = match self.evaluate("mcpProjectPortfolio.request", message.clone()) {
                    Ok(request) => request,
                    Err(_) => return self.failure(&message, "request", ""),
                };
                let selection = match self.access.select(portfolio, &request) {
                    Ok(selection) => selection,
                    Err(_) => return self.failure(&message, "backend", ""),
                };
                if let Some(reason) = selection["denied"].as_str() { return self.failure(&message, reason, ""); }
                self.reply(request, selection)?
            }
            Some("initialize" | "notifications/initialized") => Value::Null,
            _ => self.evaluate("mcpProjectHttp.discovery", json!({
                "message":message,"projectRead":portfolio.read,"handshake":wire["handshake"]
            }))?,
        };
        if wire["handshake"] != true { return self.evaluate("mcpProjectHttp.reply", reply); }
        let client = client.as_str().ok_or_else(|| fail("Expected a handshake cache coordinate"))?;
        let mut clients = self.handshake_clients.borrow_mut();
        let known = clients.iter().position(|key| key == client);
        let session = (operation == "initialize").then(crate::nonce::uuid_v4).transpose()?
            .map(|id| format!("sourcery-handshake-{id}"));
        let result = self.evaluate("mcpProjectHttp.handshakeReply", json!({"message":message,"body":reply,
            "version":wire["version"],"contract":self.handshake_contract,"session":session,"seen":known.is_some()}))?;
        if result["remember"] == true {
            if let Some(index) = known { clients.remove(index); }
            clients.push_back(client.to_owned());
            if clients.len() > HANDSHAKE_CLIENT_LIMIT { clients.pop_front(); }
        }
        Ok(result)
    }
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let [operation, key, arguments @ ..] = args else { return Err(fail("Expected a hosted MCP project operation and key")); };
    let (configuration, requested_scope) = match (operation.as_str(), arguments) {
        ("open", [configuration @ .., tenant, app, project, workspace]) =>
            (configuration, Some([tenant.clone(), app.clone(), project.clone(), workspace.clone()])),
        ("resolve" | "tool", configuration) => (configuration, None),
        _ => return Err(fail("Expected hosted MCP project open, resolve, or tool")),
    };
    http::install_stop_signals()?;
    let tool = Tool::load(Path::new(key), configuration)?;
    let evaluate = |name, input| tool.evaluate(name, input);
    let mut input = Zeroizing::new(String::new());
    io::stdin().lock().take(8193).read_to_string(&mut input)?;
    if input.len() > 8192 { return Err(fail("Hosted MCP project input exceeds its size limit")); }
    let response = if let Some(scope) = requested_scope {
        let grant = tool.access.authorize(input.strip_suffix('\n').unwrap_or(&input), &scope)?;
        let claims = evaluate("mcpProjectContext.issue", json!({"access":grant, "nowMs":now_ms()}))?;
        json!({"projectContext":tool.key.seal(&claims)?,"expiresAt":claims["expiresAt"]})
    } else if operation == "resolve" {
        let fields: [String; 2] = serde_json::from_str(&input)
            .map_err(|_| fail("Expected a hosted MCP credential and project context in a two-element JSON array"))?;
        let [bearer, context] = fields.map(Zeroizing::new);
        let claims = tool.key.unseal(&context)?;
        let scope: [String; 4] = serde_json::from_value(evaluate("mcpProjectContext.coordinates",
            json!({"claims":claims, "nowMs":now_ms()}))?)?;
        let grant = tool.access.authorize(&bearer, &scope)?;
        evaluate("mcpProjectContext.verify", json!({"claims":claims, "access":grant, "nowMs":now_ms()}))?
    } else {
        let [bearer, call]: [Value; 2] = serde_json::from_str(&input)
            .map_err(|_| fail("Expected a hosted MCP credential and MCP request in a two-element JSON array"))?;
        let Value::String(bearer) = bearer else { return Err(fail("Expected a hosted MCP credential")); };
        let bearer = Zeroizing::new(bearer);
        crate::compat_value::external(&call)?;
        let request = evaluate("mcpProjectPortfolio.request", call)?;
        let selection = tool.access.select(tool.access.portfolio(&bearer)??, &request)?;
        match selection["denied"].as_str() {
            Some("ambiguous") => return Err(fail("Project selection is ambiguous; include workspaceId.")),
            Some("unavailable") => return Err(fail("Project is not available to this MCP connection.")),
            _ => {}
        }
        tool.reply(request, selection)?
    };
    if http::stopping() { return Err(fail("Hosted MCP project operation interrupted")); }
    writeln!(io::stdout().lock(), "{response}")?;
    Ok(())
}

#[cfg(test)]
#[test]
fn portfolio_selection_binds_current_user_and_the_original_query() -> Result<()> {
    let policy = policy()?;
    let run = |entry, input| policy.run(entry, input, &mut Meter::new(METER));
    let claims = json!({"protocol":"sourcery-mcp-workspace-csrf/1","userId":"alice",
        "authorizeHref":"/oauth/authorize?state=original","expiresAt":2000});
    let check = |user, now| run("mcpBrowserSelection.binding", json!({"claims":claims,"userId":user,"nowMs":now}));
    assert_eq!(check("alice", 1999)?, true);
    assert_eq!(check("alice", 2000)?, false);
    assert_eq!(check("another-user", 1999)?, false);
    let mut input = json!({"userId":"alice","path":"/oauth/authorize","query":[["state","original"]],
        "nowMs":1999,"selected":["choice"],"nonce":"fixture","portfolios":[
            {"id":"choice","scope":{"tenantId":"tenant","appId":"app"},"summary":{"tenant":"Tenant","application":"App"}}
        ]});
    let planned = run("mcpBrowserSelection.plan", input.clone())?;
    assert_eq!(planned["claims"]["requestHash"], crate::rel::hash(r#"[["state","original"]]"#));
    assert_eq!(planned["claims"]["expiresAt"], 301999);
    input["query"] = json!([["sourcery_portfolio","prior"]]);
    assert_eq!(run("mcpBrowserSelection.plan", input)?["error"], "retained");
    Ok(())
}

#[cfg(test)]
#[test]
fn handshake_transport_preserves_versions_and_notification_semantics() -> Result<()> {
    let policy = policy()?;
    let run = |entry, value| policy.run(entry, value, &mut Meter::new(METER));
    for version in ["2025-11-25", "2025-06-18", "2025-03-26"] {
        let wire = |message| run("mcpProjectHttp.transport", json!({"version":version,"message":message}));
        let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
        assert_eq!(wire(ping.clone())?, json!({"handshake":true,"version":version}));
        let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert_eq!(wire(notification.clone())?, json!({"handshake":true,"version":version}));
        let wrong_id = json!({"jsonrpc":"2.0","id":2,"method":"notifications/initialized"});
        assert_eq!(wire(wrong_id)?["reason"], "id");
        let reply = run("mcpProjectHttp.handshakeReply", json!({"message":notification}))?;
        assert_eq!(reply, json!({"status":202}));
        let body = json!({"jsonrpc":"2.0","id":1,"result":{}});
        let reply = run("mcpProjectHttp.handshakeReply", json!({"message":ping,"body":body,"contract":"fixture","seen":false}))?;
        assert_eq!(reply["events"][0]["method"], "notifications/tools/list_changed");
        assert_eq!(reply["events"][1], body);
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn project_context_preserves_the_issued_scope_and_current_connection() -> Result<()> {
    let policy = policy()?;
    let run = |entry, value| policy.run(entry, value, &mut Meter::new(METER));
    let key = ProjectKey(Zeroizing::new([19; 32]));
    let access = json!({
        "protocol":"sourcery-hosted-mcp-workspace-access/1",
        "principal":{"kind":"user","userId":"alice"},
        "scope":{"tenantId":"tenant","appId":"app","projectId":"project","workspaceId":"workspace"},
        "scopes":["authoring.read"],"clientId":"https://agent.example/client","familyId":"family"
    });
    let claims = run("mcpProjectContext.issue", json!({"access":access,"nowMs":1000}))?;
    let context = key.seal(&claims)?;
    let decoded = key.unseal(&context)?;
    assert_eq!(claims, decoded);
    assert_eq!(run("mcpProjectContext.verify", json!({"claims":decoded,"access":access,"nowMs":1001}))?, access);
    let mut other = access.clone();
    other["familyId"] = json!("other");
    assert!(run("mcpProjectContext.verify", json!({"claims":decoded,"access":other,"nowMs":1001})).is_err());
    assert!(run("mcpProjectContext.coordinates", json!({"claims":decoded,"nowMs":claims["expiresAt"]})).is_err());
    assert!(ProjectKey(Zeroizing::new([20; 32])).unseal(&context).is_err());
    Ok(())
}
