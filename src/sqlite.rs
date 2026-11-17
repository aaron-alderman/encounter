// Minimal prepared-statement binding to the host's SQLite library.
use crate::{Result, fail};
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
    thread,
    time::{Duration, Instant},
};

const SQLITE_BUSY: c_int = 5;
const BUSY_TIMEOUT: Duration = Duration::from_secs(3);

#[link(name = "libsqlite3.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn sqlite3_open(filename: *const c_char, db: *mut *mut c_void) -> c_int;
    fn sqlite3_open_v2(filename: *const c_char, db: *mut *mut c_void, flags: c_int, vfs: *const c_char) -> c_int;
    fn sqlite3_close(db: *mut c_void) -> c_int;
    fn sqlite3_errmsg(db: *mut c_void) -> *const c_char;
    fn sqlite3_busy_timeout(db: *mut c_void, milliseconds: c_int) -> c_int;
    fn sqlite3_busy_handler(db: *mut c_void, callback: Option<extern "C" fn(*mut c_void, c_int) -> c_int>,
        context: *mut c_void) -> c_int;
    fn sqlite3_sleep(milliseconds: c_int) -> c_int;
    fn sqlite3_exec(db: *mut c_void, sql: *const c_char, callback: Option<unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int>,
        arg: *mut c_void, error: *mut *mut c_char) -> c_int;
    fn sqlite3_prepare_v2(db: *mut c_void, sql: *const c_char, bytes: c_int,
        stmt: *mut *mut c_void, tail: *mut *const c_char) -> c_int;
    fn sqlite3_finalize(stmt: *mut c_void) -> c_int;
    fn sqlite3_bind_int64(stmt: *mut c_void, n: c_int, value: i64) -> c_int;
    fn sqlite3_bind_text(stmt: *mut c_void, n: c_int, text: *const c_char,
        bytes: c_int, destroy: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
    fn sqlite3_bind_blob(stmt: *mut c_void, n: c_int, blob: *const c_void,
        bytes: c_int, destroy: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
    fn sqlite3_step(stmt: *mut c_void) -> c_int;
    fn sqlite3_column_count(stmt: *mut c_void) -> c_int;
    fn sqlite3_column_name(stmt: *mut c_void, n: c_int) -> *const c_char;
    fn sqlite3_column_type(stmt: *mut c_void, n: c_int) -> c_int;
    fn sqlite3_column_int64(stmt: *mut c_void, n: c_int) -> i64;
    fn sqlite3_column_text(stmt: *mut c_void, n: c_int) -> *const u8;
    fn sqlite3_column_bytes(stmt: *mut c_void, n: c_int) -> c_int;
    fn sqlite3_blob_open(db: *mut c_void, schema: *const c_char, table: *const c_char, column: *const c_char,
        rowid: i64, flags: c_int, blob: *mut *mut c_void) -> c_int;
    fn sqlite3_blob_bytes(blob: *mut c_void) -> c_int;
    fn sqlite3_blob_read(blob: *mut c_void, buffer: *mut c_void, bytes: c_int, offset: c_int) -> c_int;
    fn sqlite3_blob_close(blob: *mut c_void) -> c_int;
    fn sqlite3_progress_handler(db: *mut c_void, steps: c_int,
        callback: Option<extern "C" fn(*mut c_void) -> c_int>, context: *mut c_void);
}

pub struct Db(*mut c_void);
struct Statement(*mut c_void);
struct Blob(*mut c_void);

impl Drop for Db {
    fn drop(&mut self) { if !self.0.is_null() { unsafe { sqlite3_close(self.0); } } }
}

impl Drop for Statement {
    fn drop(&mut self) { unsafe { sqlite3_finalize(self.0); } }
}

impl Drop for Blob {
    fn drop(&mut self) { unsafe { sqlite3_blob_close(self.0); } }
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let filename = CString::new(path.as_os_str().as_bytes())?;
        let mut db = Self(ptr::null_mut());
        let result = unsafe { sqlite3_open(filename.as_ptr(), &mut db.0) };
        db.check(result)?;
        db.check(unsafe { sqlite3_busy_timeout(db.0, BUSY_TIMEOUT.as_millis() as c_int) })?;
        Ok(db)
    }

    pub(crate) fn open_readonly(path: &Path) -> Result<Self> {
        const SQLITE_OPEN_READONLY: c_int = 1;
        Self::open_with_flags(path, SQLITE_OPEN_READONLY)
    }

    pub(crate) fn open_temple_for_checkpoint(path: &Path) -> Result<Self> {
        const SQLITE_OPEN_READWRITE: c_int = 2;
        const SQLITE_OPEN_NOFOLLOW: c_int = 0x0100_0000;
        Self::open_with_flags(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW)
    }

    pub(crate) fn open_workspace(path: &Path) -> Result<Self> {
        const SQLITE_OPEN_READWRITE: c_int = 2;
        const SQLITE_OPEN_CREATE: c_int = 4;
        const SQLITE_OPEN_NOFOLLOW: c_int = 0x0100_0000;
        Self::open_with_flags(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOFOLLOW)
    }

    fn open_with_flags(path: &Path, flags: c_int) -> Result<Self> {
        let filename = CString::new(path.as_os_str().as_bytes())?;
        let mut db = Self(ptr::null_mut());
        let result = unsafe { sqlite3_open_v2(filename.as_ptr(), &mut db.0, flags, ptr::null()) };
        db.check(result)?;
        db.check(unsafe { sqlite3_busy_timeout(db.0, BUSY_TIMEOUT.as_millis() as c_int) })?;
        Ok(db)
    }

    pub fn enable_wal(&self) -> Result<()> {
        let deadline = Instant::now() + BUSY_TIMEOUT;
        loop {
            let status = unsafe { sqlite3_exec(self.0, c"PRAGMA journal_mode=WAL".as_ptr(),
                None, ptr::null_mut(), ptr::null_mut()) };
            // Changing the journal mode can return BUSY without invoking SQLite's busy handler.
            if status != SQLITE_BUSY || Instant::now() >= deadline { return self.check(status); }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn error(&self) -> Box<dyn std::error::Error> {
        if self.0.is_null() { return fail("SQLite allocation failed"); }
        fail(unsafe { CStr::from_ptr(sqlite3_errmsg(self.0)) }.to_string_lossy().into_owned())
    }

    fn check(&self, result: c_int) -> Result<()> {
        if result == 0 { Ok(()) } else { Err(self.error()) }
    }

    pub fn exec(&self, sql: &str) -> Result<()> {
        let sql = CString::new(sql)?;
        self.check(unsafe { sqlite3_exec(self.0, sql.as_ptr(), None,
            ptr::null_mut(), ptr::null_mut()) })
    }

    pub fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Value>> {
        let mut rows = Vec::new();
        self.visit(sql, params, |row| { rows.push(row); Ok(()) })?;
        Ok(rows)
    }

    pub(crate) fn visit(&self, sql: &str, params: &[Value], mut receive: impl FnMut(Value) -> Result<()>) -> Result<()> {
        self.visit_bound(sql, params, None, &mut receive)
    }

    fn visit_bound(&self, sql: &str, params: &[Value], blob: Option<&[u8]>, mut receive: impl FnMut(Value) -> Result<()>) -> Result<()> {
        let sql = CString::new(sql)?;
        let mut raw = ptr::null_mut();
        self.check(unsafe { sqlite3_prepare_v2(self.0, sql.as_ptr(), -1, &mut raw, ptr::null_mut()) })?;
        if raw.is_null() { return Err(fail("empty SQLite statement")); }
        // Borrowed text parameters live through finalization.
        let statement = Statement(raw);
        for (index, value) in params.iter().enumerate() {
            let index = c_int::try_from(index + 1)?;
            let status = if let Some(text) = value.as_str() {
                unsafe { sqlite3_bind_text(statement.0, index, text.as_ptr().cast(), c_int::try_from(text.len())?, None) }
            } else if let Some(number) = value.as_i64() {
                unsafe { sqlite3_bind_int64(statement.0, index, number) }
            } else {
                return Err(fail("unsupported SQLite parameter"));
            };
            self.check(status)?;
        }
        if let Some(bytes) = blob {
            self.check(unsafe { sqlite3_bind_blob(statement.0, c_int::try_from(params.len() + 1)?,
                bytes.as_ptr().cast(), c_int::try_from(bytes.len())?, None) })?;
        }
        loop {
            match unsafe { sqlite3_step(statement.0) } {
                101 => return Ok(()),
                100 => {
                    let mut row = serde_json::Map::new();
                    for index in 0..unsafe { sqlite3_column_count(statement.0) } {
                        let name = unsafe { CStr::from_ptr(sqlite3_column_name(statement.0, index)) }.to_str()?;
                        let value = match unsafe { sqlite3_column_type(statement.0, index) } {
                            1 => json!(unsafe { sqlite3_column_int64(statement.0, index) }),
                            3 => {
                                let text = unsafe { sqlite3_column_text(statement.0, index) };
                                if text.is_null() { return Err(self.error()); }
                                let length = unsafe { sqlite3_column_bytes(statement.0, index) };
                                json!(std::str::from_utf8(unsafe { std::slice::from_raw_parts(text, length as usize) })?)
                            }
                            5 => Value::Null,
                            _ => return Err(fail("unsupported SQLite column type")),
                        };
                        row.insert(name.to_owned(), value);
                    }
                    receive(Value::Object(row))?;
                }
                _ => return Err(self.error()),
            }
        }
    }

    pub(crate) fn retain_temple_object(&self, hash: &str, timestamp: &str, bytes: &[u8]) -> Result<()> {
        self.visit_bound("INSERT INTO objects(object_hash, byte_length, retained_at, content) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(object_hash) DO NOTHING", &[json!(hash), json!(bytes.len()), json!(timestamp)], Some(bytes), |_| Ok(()))
    }

    pub(crate) fn temple_object_digest(&self, rowid: i64) -> Result<(usize, String)> {
        use sha2::{Digest, Sha256};
        let mut raw = ptr::null_mut();
        self.check(unsafe { sqlite3_blob_open(self.0, c"main".as_ptr(), c"objects".as_ptr(),
            c"content".as_ptr(), rowid, 0, &mut raw) })?;
        let blob = Blob(raw);
        let length = usize::try_from(unsafe { sqlite3_blob_bytes(blob.0) })?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        for offset in (0..length).step_by(buffer.len()) {
            if crate::http::stopping() { return Err(fail("Server Temple capsule inspection interrupted")); }
            let size = buffer.len().min(length - offset);
            self.check(unsafe { sqlite3_blob_read(blob.0, buffer.as_mut_ptr().cast(),
                size as c_int, offset as c_int) })?;
            digest.update(&buffer[..size]);
        }
        Ok((length, hex::encode(digest.finalize())))
    }

    pub(crate) fn interrupt_on_stop(&self) -> Result<()> {
        extern "C" fn stopped(_: *mut c_void) -> c_int { c_int::from(crate::http::stopping()) }
        extern "C" fn waiting(_: *mut c_void, attempts: c_int) -> c_int {
            const STEP_MS: c_int = 20;
            if crate::http::stopping() || attempts >= BUSY_TIMEOUT.as_millis() as c_int / STEP_MS { return 0; }
            unsafe { sqlite3_sleep(STEP_MS); }
            c_int::from(!crate::http::stopping())
        }
        unsafe { sqlite3_progress_handler(self.0, 10_000, Some(stopped), ptr::null_mut()); }
        self.check(unsafe { sqlite3_busy_handler(self.0, Some(waiting), ptr::null_mut()) })
    }
}
