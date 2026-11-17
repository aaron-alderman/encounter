use crate::{Result, fail, http};
use libc::{c_char, c_int, c_void};
use serde_json::{Value, json};
use std::{ffi::CStr, io, ptr::{self, NonNull}, slice, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

const CAPACITY: &[u8] = b"_SYSTEMD_UNIT=sourcery-encounter-capacity-sweep.service";
const LAUNCH: &[u8] = b"_SYSTEMD_UNIT=sourcery-home-launch-sweep.service";
const LIMIT: usize = 4 * 1024 * 1024;

#[link(name = "libsystemd.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn sd_journal_open(journal: *mut *mut c_void, flags: c_int) -> c_int;
    fn sd_journal_close(journal: *mut c_void);
    fn sd_journal_add_match(journal: *mut c_void, data: *const c_void, size: usize) -> c_int;
    fn sd_journal_set_data_threshold(journal: *mut c_void, size: usize) -> c_int;
    fn sd_journal_seek_realtime_usec(journal: *mut c_void, time: u64) -> c_int;
    fn sd_journal_next(journal: *mut c_void) -> c_int;
    fn sd_journal_get_data(journal: *mut c_void, field: *const c_char, data: *mut *const c_void, size: *mut usize) -> c_int;
    fn sd_journal_get_realtime_usec(journal: *mut c_void, time: *mut u64) -> c_int;
}

struct Journal(NonNull<c_void>);

impl Drop for Journal {
    fn drop(&mut self) { unsafe { sd_journal_close(self.0.as_ptr()); } }
}

fn checked(result: c_int) -> io::Result<c_int> {
    if result < 0 { Err(io::Error::from_raw_os_error(-result)) } else { Ok(result) }
}

impl Journal {
    fn field(&mut self, field: &CStr) -> Result<Option<&[u8]>> {
        let mut data = ptr::null();
        let mut size = 0;
        let result = unsafe { sd_journal_get_data(self.0.as_ptr(), field.as_ptr(), &mut data, &mut size) };
        if result == -libc::ENOENT { return Ok(None); }
        checked(result)?;
        if data.is_null() || size > LIMIT { return Err(fail("Sweep journal field exceeds its byte bound")); }
        let bytes = unsafe { slice::from_raw_parts(data.cast::<u8>(), size) };
        let prefix = field.to_bytes().len();
        if !bytes.starts_with(field.to_bytes()) || bytes.get(prefix) != Some(&b'=') {
            return Err(fail("Malformed sweep journal field"));
        }
        Ok(Some(&bytes[prefix + 1..]))
    }
}

pub(super) fn entries(channel: Option<bool>) -> Result<Vec<Value>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    http::check_interruption(false)?;
    let mut raw = ptr::null_mut();
    // SD_JOURNAL_LOCAL_ONLY excludes journal files received from other hosts.
    checked(unsafe { sd_journal_open(&mut raw, 1) })?;
    let mut journal = Journal(NonNull::new(raw).ok_or_else(|| fail("Missing sweep journal handle"))?);
    let units = match channel { Some(true) => &[CAPACITY][..], Some(false) => &[LAUNCH][..], None => &[CAPACITY, LAUNCH][..] };
    // Matches for the same trusted field are disjoined by libsystemd.
    for unit in units {
        checked(unsafe { sd_journal_add_match(raw, unit.as_ptr().cast(), unit.len()) })?;
    }
    checked(unsafe { sd_journal_set_data_threshold(raw, LIMIT + 1) })?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let since = now.saturating_sub(86_400_000_000);
    checked(unsafe { sd_journal_seek_realtime_usec(raw, since) })?;
    let mut rows = Vec::new();
    let mut bytes = 0;
    for _ in 0..100_000 {
        http::check_interruption(false)?;
        if Instant::now() >= deadline { return Err(fail("Sweep journal observation timed out")); }
        if checked(unsafe { sd_journal_next(raw) })? == 0 { return Ok(rows); }
        let mut stamp = 0;
        checked(unsafe { sd_journal_get_realtime_usec(raw, &mut stamp) })?;
        if stamp < since { continue; }
        let Some(invocation) = journal.field(c"_SYSTEMD_INVOCATION_ID")? else { continue; };
        let invocation = std::str::from_utf8(invocation)?.to_owned();
        let Some(message) = journal.field(c"MESSAGE")? else { continue; };
        if !message.starts_with(br#"{"scope":""#) { continue; }
        let Ok(report) = serde_json::from_slice::<Value>(message) else { continue; };
        bytes += invocation.len() + message.len();
        if bytes > LIMIT { return Err(fail("Sweep journal observation exceeds its byte bound")); }
        rows.push(json!({"invocation":invocation,"stamp":stamp,"report":report,"index":rows.len()}));
    }
    Err(fail("Sweep journal observation exceeds its entry bound"))
}
