use super::{File, Mutex, Path, PathBuf, Reader, Result, fail, fs, id, json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, BTreeSet}, io::{Read, Seek, SeekFrom}, time::{Duration, Instant, SystemTime}};

#[derive(Clone, Default, Deserialize, Serialize)]
struct Seen {
    first_visit: Option<i64>,
    chats: BTreeMap<String, i64>,
}

#[derive(Clone, Copy)]
pub(super) struct ChatState {
    pub running: bool,
    pub unread: bool,
}

impl ChatState {
    pub fn label(self) -> &'static str {
        if self.running { "running" } else { "finished" }
    }
}

pub(super) struct Badges {
    file: Option<PathBuf>,
    seen: Mutex<Seen>,
    running: Mutex<(Option<Instant>, BTreeSet<String>)>,
}

impl Badges {
    pub(super) fn load(file: Option<PathBuf>) -> Result<Self> {
        let seen = match file.as_deref().map(fs::read).transpose() {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes)?,
            Ok(None) => Seen::default(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Seen::default(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self { file, seen: Mutex::new(seen), running: Mutex::new((None, BTreeSet::new())) })
    }

    fn store(path: Option<&Path>, seen: &Seen) -> Result<()> {
        if let Some(path) = path {
            let next = path.with_extension("next");
            fs::write(&next, serde_json::to_vec(seen)?)?;
            File::open(&next)?.sync_all()?;
            fs::rename(&next, path)?;
            if let Some(parent) = path.parent() { File::open(parent)?.sync_all()?; }
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Seen> {
        let mut seen = self.seen.lock().map_err(|_| fail("Seen state unavailable"))?;
        if seen.first_visit.is_none() {
            let initial = Seen { first_visit: Some(DateTime::<Utc>::from(SystemTime::now()).timestamp_millis()), chats: BTreeMap::new() };
            Self::store(self.file.as_deref(), &initial)?;
            *seen = initial;
        }
        Ok(seen.clone())
    }

    pub(super) fn acknowledge(&self, chat: &str, finished: Option<i64>) -> Result<()> {
        let Some(finished) = finished else { return Ok(()); };
        let mut seen = self.seen.lock().map_err(|_| fail("Seen state unavailable"))?;
        if finished <= seen.chats.get(chat).copied().or(seen.first_visit).unwrap_or(i64::MAX) { return Ok(()); }
        let mut updated = seen.clone();
        updated.chats.insert(chat.to_owned(), finished);
        Self::store(self.file.as_deref(), &updated)?;
        *seen = updated;
        Ok(())
    }

    pub(super) fn annotate(&self, reader: &Reader, rows: &[&serde_json::Value]) -> Result<BTreeMap<String, ChatState>> {
        let seen = self.snapshot()?;
        let running = self.running(reader);
        let mut result = BTreeMap::new();
        for row in rows {
            let Some(chat) = row["id"].as_str().filter(|v| id(v)) else { continue; };
            let running = running.contains(chat);
            let cutoff = seen.chats.get(chat).copied().or(seen.first_visit).unwrap_or(i64::MAX);
            let unread = reader.rollout(row)?.filter(|file| {
                let modified = file.metadata().and_then(|meta| meta.modified()).ok()
                    .map(|time| DateTime::<Utc>::from(time).timestamp_millis());
                modified.is_none_or(|time| time >= cutoff)
            }).and_then(finished_at).is_some_and(|finished| finished > cutoff);
            if running || unread { result.insert(chat.to_owned(), ChatState { running, unread }); }
        }
        Ok(result)
    }

    fn running(&self, reader: &Reader) -> BTreeSet<String> {
        let Ok(mut cache) = self.running.try_lock() else { return BTreeSet::new(); };
        if cache.0.is_some_and(|stamp| stamp.elapsed() < Duration::from_secs(3)) { return cache.1.clone(); }
        let active = (|| -> Result<BTreeSet<String>> {
            let mut desktop = reader.desktop()?;
            let mut cursor = serde_json::Value::Null;
            let mut active = BTreeSet::new();
            for _ in 0..4 {
                let result = desktop.call("thread/list", json!({"limit":100,"sortKey":"updated_at","archived":false,"cursor":cursor}), |_| Ok(()))?;
                if let Some(threads) = result["data"].as_array() {
                    active.extend(threads.iter().filter(|thread| thread["status"]["type"] == "active")
                        .filter_map(|thread| thread["id"].as_str().filter(|v| id(v)).map(str::to_owned)));
                }
                cursor = result["nextCursor"].clone();
                if cursor.is_null() { break; }
            }
            Ok(active)
        })().unwrap_or_default();
        *cache = (Some(Instant::now()), active.clone());
        active
    }
}

pub(super) fn finished_at(file: File) -> Option<i64> {
    finished_before(file, None)
}

pub(super) fn finished_before(mut file: File, end: Option<u64>) -> Option<i64> {
    const TAIL_LIMIT: u64 = 512 * 1024;
    let length = file.metadata().ok()?.len();
    let end = end.unwrap_or(length).min(length);
    let start = end.saturating_sub(TAIL_LIMIT);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut tail = Vec::new();
    file.take(end - start).read_to_end(&mut tail).ok()?;
    let complete = tail.iter().rposition(|byte| *byte == b'\n')?;
    let first = if start == 0 { 0 } else { tail.iter().position(|byte| *byte == b'\n')? + 1 };
    if first > complete { return None; }
    tail[first..complete].rsplit(|byte| *byte == b'\n').find_map(|line| {
        if !line.windows(b"task_complete".len()).any(|part| part == b"task_complete") { return None; }
        let event: serde_json::Value = serde_json::from_slice(line).ok()?;
        (event["type"] == "event_msg" && event["payload"]["type"] == "task_complete")
            .then(|| DateTime::parse_from_rfc3339(event["timestamp"].as_str()?).ok().map(|time| time.timestamp_millis()))
            .flatten()
    })
}
