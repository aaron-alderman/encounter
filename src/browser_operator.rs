// Host-local operator sessions for an explicitly framed browser application.
use crate::{Result, fail, http, nonce::nonce, operator::Operators, rel, sqlite::Db};
use base64ct::{Base64, Encoding};
use serde_json::{Value, json};
use std::{
    cell::RefCell, collections::BTreeMap, fs, net::TcpStream, path::Path,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const PATH: &str = "/_encounter/operator";
pub const SIGN_OUT: &str = "/_encounter/operator/sign-out";
const COOKIE: &str = "__Host-encounter-operator";
const LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
const LIMIT: usize = 128;

pub struct Lease {
    expires: Instant,
    revoked: AtomicBool,
}

impl Lease {
    pub fn active(&self) -> bool {
        !self.revoked.load(Ordering::Acquire) && Instant::now() < self.expires
    }
}

pub struct WindowOperators {
    login: String,
    rejected: String,
    database: Db,
    leases: RefCell<BTreeMap<String, Arc<Lease>>>,
}

fn page(assets: &Path, file: &str) -> Result<String> {
    let path = assets.join(file).canonicalize()?;
    if !path.starts_with(assets) || !path.is_file() || path.metadata()?.len() > 128 * 1024 {
        return Err(fail("expected a bounded operator page within browser assets"));
    }
    Ok(fs::read_to_string(path)?)
}

fn session_token(request: &http::Request) -> Option<&str> {
    let mut tokens = request.headers.get("cookie")?.split(';')
        .filter_map(|part| part.trim().strip_prefix(COOKIE)?.strip_prefix('='));
    let token = tokens.next()?;
    (tokens.next().is_none() && token.len() == 48
        && token.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then_some(token)
}

fn utc_seconds() -> Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs().try_into()?)
}

fn redirect(stream: &mut TcpStream, token: &str, max_age: u64) -> Result<()> {
    http::send_headers(stream, "303 See Other", "text/plain", &format!(
        "Location: /\r\nReferrer-Policy: same-origin\r\nSet-Cookie: {COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=None; Partitioned\r\n"
    ), "")
}

impl WindowOperators {
    pub fn read(assets: &Path, directory: &Path) -> Result<Self> {
        let database = Db::open(&directory.join("browser-operators.sqlite"))?;
        database.exec("CREATE TABLE IF NOT EXISTS sessions(\
            token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, binding TEXT NOT NULL, expires INTEGER NOT NULL)")?;
        Ok(Self { login: page(assets, "operator.html")?, rejected: page(assets, "operator-rejected.html")?,
            database, leases: RefCell::default() })
    }

    pub fn actor(&self, operators: &Operators, request: &http::Request) -> Result<Option<(Value, Arc<Lease>)>> {
        let Some(token) = session_token(request) else { return Ok(None); };
        let token_hash = rel::hash(token);
        let now = utc_seconds()?;
        let row = self.database.query("SELECT subject,binding,expires FROM sessions WHERE token_hash=? AND expires>?",
            &[json!(token_hash), json!(now)])?.pop();
        let Some(row) = row else { return Ok(None); };
        let subject = row["subject"].as_str().ok_or_else(|| fail("invalid operator session subject"))?;
        let binding = row["binding"].as_str().ok_or_else(|| fail("invalid operator session binding"))?;
        let Some(actor) = operators.session_actor(subject, binding) else { return Ok(None); };
        let remaining = row["expires"].as_i64().ok_or_else(|| fail("invalid operator session expiry"))? - now;
        let mut leases = self.leases.borrow_mut();
        leases.retain(|_, lease| lease.active());
        let lease = leases.entry(token_hash).or_insert_with(|| Arc::new(Lease {
            expires: Instant::now() + Duration::from_secs(remaining.min(LIFETIME.as_secs() as i64) as u64),
            revoked: AtomicBool::new(false),
        }));
        Ok(Some((actor, Arc::clone(lease))))
    }

    fn revoke(&self, request: &http::Request) -> Result<()> {
        if let Some(token) = session_token(request) {
            let token_hash = rel::hash(token);
            self.database.query("DELETE FROM sessions WHERE token_hash=?", &[json!(token_hash)])?;
            if let Some(lease) = self.leases.borrow_mut().remove(&token_hash) {
                lease.revoked.store(true, Ordering::Release);
            }
        }
        Ok(())
    }

    pub fn prompt(&self, stream: &mut TcpStream) -> Result<()> {
        http::send_headers(stream, "200 OK", "text/html", "Referrer-Policy: same-origin\r\n", &self.login)
    }

    pub fn handle(&self, operators: &Operators, stream: &mut TcpStream, request: &http::Request, origin: &str) -> Result<()> {
        if request.path == PATH && request.method == "GET" {
            return self.prompt(stream);
        }
        if request.method != "POST" || request.body.len() > 2048
            || request.headers.get("origin").map(String::as_str) != Some(origin)
            || request.headers.get("content-type").map(String::as_str) != Some("application/x-www-form-urlencoded") {
            return http::send(stream, "403 Forbidden", "text/plain", "Expected a same-origin operator form.");
        }
        if request.path == SIGN_OUT {
            self.revoke(request)?;
            return redirect(stream, "", 0);
        }
        let actor = http::form(&request.body).ok().and_then(|fields| {
            let (user, password) = (fields.get("username")?, fields.get("password")?);
            if fields.len() != 2 || user.len() > 80 || password.len() > 303 || user.contains(':') {
                return None;
            }
            let token = Base64::encode_string(format!("{user}:{password}").as_bytes());
            operators.verify_token(&token).filter(|actor| actor["id"].as_str() == Some(user))
                .map(|_| (user.clone(), rel::hash(&rel::hash(&token))))
        });
        let Some((subject, binding)) = actor else {
            return http::send_headers(stream, "401 Unauthorized", "text/html", "Referrer-Policy: same-origin\r\n", &self.rejected);
        };
        self.revoke(request)?;
        let now = utc_seconds()?;
        self.database.query("DELETE FROM sessions WHERE expires<=?", &[json!(now)])?;
        let token = nonce()?;
        let inserted = self.database.query("INSERT INTO sessions SELECT ?,?,?,? \
            WHERE (SELECT COUNT(*) FROM sessions) < ? RETURNING token_hash",
            &[json!(rel::hash(&token)), json!(subject), json!(binding),
              json!(now + LIFETIME.as_secs() as i64), json!(LIMIT)])?;
        if inserted.is_empty() {
            return http::send(stream, "503 Service Unavailable", "text/plain", "Operator session capacity.");
        }
        redirect(stream, &token, LIFETIME.as_secs())
    }
}
