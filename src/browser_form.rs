// Private resumable state for one admitted browser form programme.
use crate::{Result, fail, nonce::nonce, rel, sqlite::Db};
use serde_json::{Value, json};
use std::{cell::{Cell, RefCell}, path::Path, time::{SystemTime, UNIX_EPOCH}};

const MAX_STATE: usize = 32 * 1024;
const LIFETIME: i64 = 8 * 60 * 60;
const LIMIT: i64 = 256;

pub struct FormSession {
    database: Db,
    basis: String,
    binding: RefCell<Option<String>>,
    open_transaction: Cell<bool>,
}

fn now() -> Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs().try_into()?)
}

fn state_text(state: &Value) -> Result<String> {
    if !state.is_object() { return Err(fail("expected a form session record")); }
    crate::compat_value::external(state)?;
    let text = serde_json::to_string(state)?;
    if text.len() > MAX_STATE { return Err(fail("form session size limit")); }
    Ok(text)
}

impl FormSession {
    pub fn open(directory: &Path, basis: &str) -> Result<Self> {
        let database = Db::open(&directory.join("browser-form-sessions.sqlite"))?;
        database.exec("PRAGMA busy_timeout=500; CREATE TABLE IF NOT EXISTS sessions(\
            token_hash TEXT PRIMARY KEY,basis TEXT NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL)")?;
        Ok(Self { database, basis: basis.to_owned(), binding: RefCell::default(), open_transaction: Cell::new(false) })
    }

    pub fn effect(&self, name: &str, args: &Value) -> Result<Value> {
        let fields = args.as_object().ok_or_else(|| fail("expected form session port arguments"))?;
        match name {
            "form.sessionOpen" if fields.len() == 2 && fields.contains_key("token") && fields.contains_key("initial") => {
                self.bind(&args["token"], &args["initial"])
            }
            "form.sessionBegin" if fields.is_empty() => self.begin(),
            "form.sessionSave" if fields.len() == 1 && fields.contains_key("state") => self.save(&args["state"]),
            _ => Err(fail("invalid form session port arguments")),
        }
    }

    fn bind(&self, offered: &Value, initial: &Value) -> Result<Value> {
        if self.binding.borrow().is_some() { return Err(fail("form session is already bound")); }
        let state = state_text(initial)?;
        let time = now()?;
        if let Some(token) = offered.as_str().filter(|token| token.len() == 48
            && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
            let key = rel::hash(token);
            if !self.database.query("SELECT token_hash FROM sessions WHERE token_hash=? AND basis=? AND expires>?",
                &[json!(key), json!(self.basis), json!(time)])?.is_empty()
            {
                self.binding.replace(Some(key));
                return Ok(json!(token));
            }
        }
        self.database.query("DELETE FROM sessions WHERE expires<=?", &[json!(time)])?;
        let token = nonce()?;
        let key = rel::hash(&token);
        let inserted = self.database.query("INSERT INTO sessions SELECT ?,?,?,? WHERE (SELECT COUNT(*) FROM sessions) < ? RETURNING token_hash",
            &[json!(key), json!(self.basis), json!(time + LIFETIME), json!(state), json!(LIMIT)])?;
        if inserted.is_empty() { return Err(fail("form session capacity reached")); }
        self.binding.replace(Some(key));
        Ok(json!(token))
    }

    fn begin(&self) -> Result<Value> {
        let binding = self.binding.borrow();
        let key = binding.as_ref().ok_or_else(|| fail("form session is not bound"))?;
        if self.open_transaction.get() { return Err(fail("form session transaction already open")); }
        self.database.exec("BEGIN IMMEDIATE")?;
        self.open_transaction.set(true);
        let time = now()?;
        let row = self.database.query("SELECT state FROM sessions WHERE token_hash=? AND basis=? AND expires>?",
            &[json!(key), json!(self.basis), json!(time)])?.pop();
        let row = row.ok_or_else(|| fail("Form session expired. Reopen the workspace."))?;
        let text = row["state"].as_str().ok_or_else(|| fail("invalid stored form session"))?;
        let state: Value = serde_json::from_str(text)?;
        state_text(&state)?;
        Ok(state)
    }

    fn save(&self, state: &Value) -> Result<Value> {
        let binding = self.binding.borrow();
        let key = binding.as_ref().ok_or_else(|| fail("form session is not bound"))?;
        if !self.open_transaction.get() { return Err(fail("form session transaction is not open")); }
        let text = state_text(state)?;
        let time = now()?;
        let persisted = self.database.query("UPDATE sessions SET state=?, expires=? WHERE token_hash=? AND basis=? RETURNING token_hash",
            &[json!(text), json!(time + LIFETIME), json!(key), json!(self.basis)])?;
        if persisted.is_empty() { return Err(fail("form session could not be saved")); }
        self.database.exec("COMMIT")?;
        self.open_transaction.set(false);
        Ok(json!(true))
    }

    pub fn finish(&self) {
        if self.open_transaction.replace(false) { let _ = self.database.exec("ROLLBACK"); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_session_resume_keeps_current_state_and_isolates_other_tabs() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("form-test-{}", nonce()?));
        std::fs::create_dir(&dir)?;
        let run = || -> Result<()> {
            let first = FormSession::open(&dir, "test-basis")?;
            let token = first.bind(&Value::Null, &json!({}))?;
            assert_eq!(first.begin()?, json!({}));
            first.save(&json!({"review": "first"}))?;
            drop(first);

            let resumed = FormSession::open(&dir, "test-basis")?;
            assert_eq!(resumed.bind(&token, &json!({}))?, token);
            assert_eq!(resumed.begin()?, json!({"review": "first"}));
            resumed.finish();
            let other = FormSession::open(&dir, "test-basis")?;
            assert_ne!(other.bind(&Value::Null, &json!({}))?, token);
            assert_eq!(other.begin()?, json!({}));
            other.save(&json!({"review": "other"}))?;
            assert_eq!(resumed.begin()?, json!({"review": "first"}));
            resumed.save(&json!({}))?;
            assert_eq!(resumed.begin()?, json!({}));
            resumed.finish();
            Ok(())
        };
        let outcome = run();
        std::fs::remove_dir_all(dir)?;
        outcome
    }
}
