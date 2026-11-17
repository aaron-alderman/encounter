//! Native Encounter reader for the server's Codex state. Codex storage is read-only. Turn actions go through the Desktop server.
use crate::{Result, fail, http, process::{CSS_RENDERER, HTML_PORTS, HTML_RENDERER, Meter, Programme}, sqlite::Db};
use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{
    cell::OnceCell, collections::{BTreeMap, BTreeSet, VecDeque}, fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write}, net::TcpStream,
    os::unix::fs::OpenOptionsExt, path::{Path, PathBuf}, sync::Mutex, time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

#[path = "aster_codex_markdown.rs"]
mod markdown;
#[path = "aster_codex_badges.rs"]
mod badges;

const ROOT: &str = "/aster-codex/";
const SECURITY: &str = "X-Robots-Tag: noindex, nofollow\r\nReferrer-Policy: same-origin\r\n";
const WINDOW: u64 = 8 * 1024 * 1024;
const MEDIA_LIMIT: u64 = 20 * 1024 * 1024;
const TEXT_LIMIT: usize = 192 * 1024;
const PAGE_SIZE: usize = 25;
const PROMPT_LIMIT: usize = 16_000;
const PIN_LIMIT: usize = 100;
const FORM_ORIGIN: &str = "https://appdev.sourcerytech.com.au";
const RECENCY: &str = "coalesce(nullif(recency_at_ms,0),updated_at_ms,updated_at*1000)";
const NAME: &str = "coalesce(nullif(name,''),nullif(title,''),nullif(first_user_message,''),'Untitled chat')";
const VISIBLE: &str = "creator_account_id=?1 AND (source NOT LIKE '{%' OR thread_source='agent_forked_thread')";

thread_local! { static POLICY: OnceCell<Programme> = const { OnceCell::new() }; }

fn policy() -> Result<Programme> {
    let sources = HTML_RENDERER.into_iter().chain([
        include_str!("aster_codex.encounter"), CSS_RENDERER,
    ]).map(str::to_owned).collect::<Vec<_>>();
    let ports = HTML_PORTS.into_iter().chain(["record.put", "text.split"]).collect();
    Programme::admit_entries(&sources,
        &["asterCodex.route", "asterCodex.shell", "asterCodex.article", "asterCodex.markdownLink", "asterCodex.markdownTable", "asterCodex.liveStatus", "asterCodex.liveDocument", "asterCodex.liveText", "asterCodex.liveLink", "asterCodex.notice", "asterCodex.statusDocument", "asterCodex.markdownStyles"], &ports, &mut Meter::new(150_000))
}

struct Reader {
    home: PathBuf,
    workspace: PathBuf,
    owner: String,
    admission: String,
    previews: BTreeMap<String, String>,
    pins: Mutex<BTreeSet<String>>,
    pin_file: Option<PathBuf>,
    badges: badges::Badges,
    tickets: Mutex<VecDeque<ComposerTicket>>,
    submit: Mutex<()>,
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;").replace('\'', "&#39;")
}

fn id(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(index, byte)|
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' } else { byte.is_ascii_hexdigit() })
}

fn field<'a>(values: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    values.get(key).map(String::as_str).unwrap_or("")
}

fn clipped(value: &str, limit: usize) -> &str {
    &value[..value.floor_char_boundary(value.len().min(limit))]
}

struct ComposerTicket {
    value: String,
    chat: String,
    issued: Instant,
}

fn perth() -> chrono::FixedOffset {
    chrono::FixedOffset::east_opt(8 * 3600).expect("Perth")
}

fn day_group(value: Option<DateTime<Utc>>, today: chrono::NaiveDate) -> usize {
    let Some(value) = value else { return 5; };
    match (today - value.with_timezone(&perth()).date_naive()).num_days() {
        ..=0 => 0,
        1 => 1,
        2 => 2,
        3..=7 => 3,
        8..=14 => 4,
        _ => 5,
    }
}

fn timestamp(value: Option<DateTime<Utc>>) -> Option<Value> {
    value.map(|time| json!({
        "dateTime": time.to_rfc3339(),
        "label": time.with_timezone(&perth()).format("%d %b %Y, %H:%M AWST").to_string(),
    }))
}

fn url(path: &str, fields: &[(&str, &str)]) -> String {
    let query = form_urlencoded::Serializer::new(String::new()).extend_pairs(fields).finish();
    format!("{ROOT}{path}?{query}")
}

fn page(stream: &mut TcpStream, programme: &Programme, status: &str, title: &str, mut view: Value) -> Result<()> {
    view["title"] = json!(title);
    let html = programme.run("asterCodex.shell", view,
        &mut Meter::new(5_000_000))?;
    http::send_raster_html(stream, status, SECURITY,
        html.as_str().ok_or_else(|| fail("Missing Aster Codex view"))?)
}

fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(path)?;
    if !file.metadata()?.is_file() { return Err(fail("Expected a regular file")); }
    Ok(file)
}

fn under(path: &Path, roots: &[&Path]) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    roots.iter().any(|root| canonical.starts_with(root)).then_some(canonical)
}

fn local_preview(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else { return false; };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') { return false; }
    let host = if let Some(v6) = authority.strip_prefix('[') { v6.split(']').next().unwrap_or("") }
        else { authority.split(':').next().unwrap_or("") };
    matches!(scheme, "http" | "https")
        && (matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0") || host.ends_with(".localhost"))
}

impl Reader {
    fn db(&self) -> Result<Db> { Db::open_readonly(&self.home.join("state_5.sqlite")) }

    fn thread(&self, chat: &str) -> Result<Option<Value>> {
        if !id(chat) { return Ok(None); }
        let sql = format!("SELECT {NAME} AS title,rollout_path AS path,archived FROM threads WHERE {VISIBLE} AND id=?2");
        Ok(self.db()?.query(&sql, &[json!(self.owner), json!(chat)])?.pop())
    }

    fn rollout(&self, row: &Value) -> Result<Option<File>> {
        let path = Path::new(row["path"].as_str().unwrap_or(""));
        let roots = [self.home.join("sessions"), self.home.join("archived_sessions")];
        let Some(path) = under(path, &[&roots[0], &roots[1]]) else { return Ok(None); };
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") { return Ok(None); }
        Ok(regular(&path).ok())
    }

    fn index(&self, list: ChatList<'_>, chat: &str, before: Option<u64>) -> Result<Value> {
        let (older, after) = list.cursor.split_once(':')
            .and_then(|(time, id_text)| Some((time.parse::<i64>().ok()?, id(id_text).then_some(id_text)?)))
            .unwrap_or((i64::MAX, ""));
        let pin_ids = json!(*self.pins.lock().map_err(|_| fail("Pins unavailable"))?);
        let projection = format!("SELECT id, substr({NAME},1,600) AS title, rollout_path AS path, {RECENCY} AS updated
            FROM threads WHERE {VISIBLE} AND archived=?2
            AND (instr(lower({NAME}),lower(?3))>0 OR ?3='')");
        let sql = format!("{projection} AND ({RECENCY},id)<(?4,?5)
            AND id NOT IN (SELECT value FROM json_each(?6)) ORDER BY updated DESC,id DESC LIMIT 26");
        let database = self.db()?;
        let rows = database.query(&sql, &[json!(self.owner), json!(list.archived as i64),
            json!(list.search), json!(older), json!(after), json!(pin_ids.to_string())])?;
        let pinned_sql = format!("{projection} AND id IN (SELECT value FROM json_each(?4))
            ORDER BY updated DESC,id DESC LIMIT {PIN_LIMIT}");
        let pinned = database.query(&pinned_sql, &[json!(self.owner), json!(list.archived as i64),
            json!(list.search), json!(pin_ids.to_string())])?;
        let today = DateTime::<Utc>::from(std::time::SystemTime::now()).with_timezone(&perth()).date_naive();
        let notification_sql = format!("SELECT id, substr({NAME},1,600) AS title, rollout_path AS path,
            {RECENCY} AS updated FROM threads WHERE {VISIBLE} AND archived=0 ORDER BY updated DESC,id DESC");
        let active_chats = database.query(&notification_sql, &[json!(self.owner)])?;
        let mut candidates: BTreeMap<&str, &Value> = active_chats.iter().filter_map(|row|
            row["id"].as_str().map(|id| (id,row))).collect();
        for row in rows.iter().take(PAGE_SIZE).chain(&pinned) {
            if let Some(id) = row["id"].as_str() { candidates.entry(id).or_insert(row); }
        }
        let candidates: Vec<_> = candidates.into_values().collect();
        let badges = self.badges.annotate(self, &candidates).unwrap_or_default();
        let entry = |row: &Value| {
            let row_id = row["id"].as_str().filter(|value| id(value))?;
            let time = row["updated"].as_i64().and_then(DateTime::from_timestamp_millis);
            Some(json!({"href":list.href(row_id, None), "anchor":row_id,
                "title":subject(row["title"].as_str().unwrap_or("Untitled chat"), 36),
                "time":timestamp(time), "current":row_id == chat, "badge":badges.get(row_id).map(|state| state.label())}))
        };
        let notifications: Vec<_> = active_chats.iter().filter_map(|row| {
            let id = row["id"].as_str()?;
            if !badges.get(id).is_some_and(|state| state.unread) { return None; }
            let title = subject(row["title"].as_str().unwrap_or("Untitled chat"), 36);
            let list = ChatList { search:"", archived:false, cursor:"" };
            Some(json!({"href":list.href(id,None), "title":title}))
        }).collect();
        let pins: Vec<_> = pinned.iter().filter_map(entry).collect();
        let mut groups = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for row in rows.iter().take(PAGE_SIZE) {
            let time = row["updated"].as_i64().and_then(DateTime::from_timestamp_millis);
            if let Some(item) = entry(row) { groups[day_group(time, today)].push(item); }
        }
        let labels = ["Today", "Yesterday", "2 days ago", "Last week", "2 weeks", "> 2 weeks"];
        let groups: Vec<_> = labels.iter().zip(groups).enumerate().filter(|(_, (_, entries))| !entries.is_empty())
            .map(|(index,(label,entries))| {
                let open = index < 2 || !list.search.is_empty() || entries.iter().any(|item| item["current"] == true);
                json!({"label":label, "entries":entries, "open":open})
            }).collect();
        let older = rows.get(PAGE_SIZE).map(|_| {
            let last = &rows[PAGE_SIZE - 1];
            let cursor = format!("{}:{}", last["updated"], last["id"].as_str().unwrap_or(""));
            ChatList { cursor: &cursor, ..list }.href(chat, before)
        });
        let alternate = ChatList { archived: !list.archived, cursor: "", ..list }.href(chat, before);
        Ok(json!({"groups":groups,"pins":pins,"notifications":notifications,
            "search":list.search,"archived":list.archived,
            "alternate":alternate,"older":older,"chat":chat,"position":before}))
    }

    fn conversation(&self, programme: &Programme, row: &Value, chat: &str, list: ChatList<'_>, before: Option<u64>) -> Result<Value> {
        let stored_title = row["title"].as_str().unwrap_or("Untitled chat");
        let title = subject(stored_title, 68);
        let full_title = clipped(stored_title, 1200);
        let back = format!("{}#chat-entry-{chat}", list.href("",None));
        let Some(mut file) = self.rollout(row)? else {
            return Ok(json!({"title":title,"fullTitle":full_title,"back":back,"available":false}));
        };
        let length = file.metadata()?.len();
        let end = before.unwrap_or(length).min(length);
        let transcript = transcript_page(&mut file, end)?;
        let mut body = String::new();
        for (offset, event) in transcript.items.iter().rev() {
            body.push_str(&self.render(programme, chat, *offset, event)?);
        }
        Ok(json!({
            "title":title,
            "fullTitle":full_title,
            "back":back,
            "available":true,
            "latest":list.href(chat,None),
            "readingLatest":end == length,
            "seenThrough":if end == length {file.try_clone().ok().and_then(|copy| badges::finished_before(copy, Some(end)))} else {None},
            "live":url("live",&[("id",chat)]),
            "statusUrl":url("status",&[("id",chat)]),
            "stopUrl":url("status",&[("id",chat),("control","1")]),
            "id":chat,
            "pinned":self.pins.lock().map_err(|_| fail("Pins unavailable"))?.contains(chat),
            "canPin":self.pin_file.is_some(),
            "ticket":if row["archived"].as_i64() == Some(1) {None} else {Some(self.ticket(chat)?)},
            "older":(transcript.older > 0).then(|| list.href(chat,Some(transcript.older))),
            "body":body
        }))
    }

    fn workspace(&self, programme: &Programme, stream: &mut TcpStream, query: &BTreeMap<String, String>,
        open_chat: bool) -> Result<()> {
        let chat = if open_chat { field(query, "id") } else { "" };
        let row = if open_chat { self.thread(chat)? } else { None };
        let found = row.is_some();
        let valid_chat = if found { chat } else { "" };
        let archived = query.get("archived").map_or_else(
            || row.as_ref().is_some_and(|detail| detail["archived"].as_i64() == Some(1)),
            |value| value == "1");
        let cursor = query.get("listBefore").map(String::as_str)
            .or_else(|| (!open_chat).then(|| field(query, "before"))).unwrap_or("");
        let list = ChatList { search:clipped(field(query, "q").trim(), 320), archived, cursor };
        let before = open_chat.then(|| field(query, "before").parse().ok()).flatten();
        let mut detail = row.as_ref().map(|row| self.conversation(programme, row, valid_chat, list, before)).transpose()?;
        if let Some(view) = &detail {
            let _ = self.badges.acknowledge(valid_chat, view["seenThrough"].as_i64());
        }
        if let Some(detail) = detail.as_mut() {
            let notice = match field(query, "result") {
                "sent" => "Message sent to Codex.",
                "pinned" => "Chat pinned.",
                "unpinned" => "Chat unpinned.",
                _ => "",
            };
            detail["notice"] = json!(notice);
        }
        let status = if !open_chat || found { "200 OK" } else { "404 Not Found" };
        let title = detail.as_ref().and_then(|d| d["title"].as_str()).unwrap_or("Chats");
        page(stream, programme, status, title, json!({
            "list":self.index(list, valid_chat, before)?,"detail":detail,"missing":open_chat && !found,
            "view":if open_chat {"chat"} else {"list"},
            "signIn":false
        }))
    }

    fn ticket(&self, chat: &str) -> Result<String> {
        let mut random = [0; 24];
        getrandom::getrandom(&mut random).map_err(|_| fail("Composer unavailable"))?;
        let value = Base64::encode_string(&random);
        let mut tickets = self.tickets.lock().map_err(|_| fail("Composer unavailable"))?;
        tickets.retain(|ticket| ticket.issued.elapsed() < Duration::from_secs(3600));
        if tickets.len() >= 1024 { tickets.pop_front(); }
        tickets.push_back(ComposerTicket { value:value.clone(), chat:chat.to_owned(), issued:Instant::now() });
        Ok(value)
    }

    fn set_pin(&self, chat: &str, pin: bool) -> Result<()> {
        let file = self.pin_file.as_ref().ok_or_else(|| fail("Pins unavailable"))?;
        let mut pins = self.pins.lock().map_err(|_| fail("Pins unavailable"))?;
        let mut next = pins.clone();
        if pin { next.insert(chat.to_owned()); } else { next.remove(chat); }
        if next.len() > PIN_LIMIT { return Err(fail("Pin limit reached")); }
        let temporary = file.with_extension("next");
        let mut pending = OpenOptions::new().write(true).create(true).truncate(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temporary)?;
        pending.write_all(&serde_json::to_vec(&next)?)?;
        pending.sync_all()?;
        fs::rename(&temporary, file)?;
        *pins = next;
        if let Some(parent) = file.parent() { File::open(parent)?.sync_all()?; }
        Ok(())
    }

    fn submit_turn(&self, chat: &str, token: &str, prompt: &str) -> Result<&'static str> {
        let _submit = self.submit.lock().map_err(|_| fail("Composer unavailable"))?;
        {
            let mut tickets = self.tickets.lock().map_err(|_| fail("Composer unavailable"))?;
            let Some(index) = tickets.iter().position(|ticket| ticket.chat == chat
                && ticket.issued.elapsed() < Duration::from_secs(3600) && ticket.value == token) else {
                return Ok("expired");
            };
            tickets.remove(index);
        }
        let mut desktop = self.desktop()?;
        let thread = desktop.read_thread(chat)?;
        if thread["id"] != chat || thread["status"]["type"] == "active" { return Ok("active"); }
        let resumed = desktop.call("thread/resume", json!({"threadId":chat,"excludeTurns":true}), |_| Ok(()))?;
        if resumed["thread"]["id"] != chat || resumed["thread"]["status"]["type"] != "idle" { return Ok("active"); }
        let result = desktop.call("turn/start", json!({"threadId":chat,
            "input":[{"type":"text","text":prompt,"text_elements":[]}]}), |_| Ok(()))?;
        Ok(if result["turn"]["id"].as_str().is_some_and(id) { "sent" } else { "unknown" })
    }

    fn chat_redirect(stream: &mut TcpStream, chat: &str, result: &str) -> Result<()> {
        let headers = format!("{SECURITY}Location: /aster-codex/chat?id={chat}&result={result}#latest\r\n");
        http::send_headers(stream,"303 See Other","text/plain",&headers,"")
    }

    fn composer_error(&self, programme: &Programme, stream: &mut TcpStream, row: &Value, chat: &str,
        prompt: &str, status: &'static str, message: &'static str) -> Result<()> {
        let list = ChatList { search:"", archived:false, cursor:"" };
        let mut detail = self.conversation(programme, row, chat, list, None)?;
        detail["draft"] = json!(prompt);
        detail["notice"] = json!(message);
        page(stream, programme, status, detail["title"].as_str().unwrap_or("Chat"), json!({
            "list":self.index(list, chat, None)?, "detail":detail, "view":"chat"
        }))
    }

    fn render(&self, programme: &Programme, chat: &str, offset: u64, entry: &Entry) -> Result<String> {
        let (label, class) = match entry.kind {
            "user" => ("You", "user"), "commentary" => ("Codex · Activity", "progress"),
            "image" => ("Attachment", "image"), _ => ("Codex · Reply", "assistant"),
        };
        let time = timestamp(DateTime::parse_from_rfc3339(&entry.timestamp).ok().map(|time| time.to_utc()));
        let mut parts = Vec::new();
        let mut remaining = TEXT_LIMIT;
        let mut linked = BTreeSet::new();
        let mut addresses = markdown::LinkAddresses::new(offset);
        for text in &entry.text {
            let part = clipped(text, remaining);
            parts.push(json!({"kind":"markdown","rendered":markdown::render(programme, part, &self.previews, &mut linked, &mut addresses)?}));
            remaining -= part.len();
            if part.len() < text.len() {
                parts.push(json!({"kind":"limit"}));
                break;
            }
        }
        for (index, source) in entry.assets.iter().enumerate() {
            let href = url("artifact", &[("id", chat), ("event", &offset.to_string()), ("part", &index.to_string())]);
            let kind = if source.starts_with("data:image/") || image_suffix(source) { "image" } else { "download" };
            parts.push(json!({"kind":kind,"href":href}));
        }
        for link in &entry.links {
            if linked.contains(link) { continue; }
            if local_preview(link) {
                if let Some(target) = self.previews.get(link) {
                    parts.push(json!({"kind":"preview","rendered":addresses.link(programme, "Open published preview", target)?}));
                } else {
                    parts.push(json!({"kind":"local","href":link}));
                }
            } else if let Some(href) = markdown::destination(link, &self.previews) {
                parts.push(json!({"kind":"link","rendered":addresses.link(programme, clipped(link, 300), href)?}));
            }
        }
        let article = programme.run("asterCodex.article", json!({
            "label":label, "class":class, "time":time, "parts":parts,
        }), &mut Meter::new(5_000_000))?;
        article.as_str().map(str::to_owned).ok_or_else(|| fail("Missing Aster Codex transcript article"))
    }
}

#[derive(Clone, Copy)]
struct ChatList<'a> {
    search: &'a str,
    archived: bool,
    cursor: &'a str,
}

impl ChatList<'_> {
    fn href(self, chat: &str, before: Option<u64>) -> String {
        let mut fields = vec![];
        if !self.search.is_empty() { fields.push(("q", self.search)); }
        if self.archived || !chat.is_empty() {
            fields.push(("archived", if self.archived { "1" } else { "0" }));
        }
        if !self.cursor.is_empty() { fields.push(("listBefore", self.cursor)); }
        if !chat.is_empty() { fields.push(("id", chat)); }
        let position = before.map(|value| value.to_string());
        if let Some(position) = &position { fields.push(("before", position)); }
        let mut href = url(if chat.is_empty() { "" } else { "chat" }, &fields);
        if !chat.is_empty() && before.is_none() { href.push_str("#latest"); }
        href
    }
}

fn subject(value: &str, limit: usize) -> String {
    let mut rest = value.lines().find(|line| !line.trim().is_empty()).unwrap_or("");
    let mut plain = String::new();
    while let Some((label, destination)) = rest.split_once("](") {
        let Some((_, trailing)) = destination.split_once(')') else { break; };
        plain.push_str(label);
        rest = trailing;
    }
    plain.push_str(rest);
    let text = plain.replace(['[', ']', '`'], "");
    let text = text.split_whitespace().filter(|part|
        !part.trim_start_matches(['<', '(']).starts_with("https://")
        && !part.trim_start_matches(['<', '(']).starts_with("http://"))
        .collect::<Vec<_>>().join(" ");
    if text.is_empty() { return "Untitled chat".into(); }
    match text.char_indices().nth(limit - 1) {
        Some((end, _)) if text[end..].chars().count() > 1 => format!("{}…", text[..end].trim_end()),
        _ => text,
    }
}

#[derive(Default)]
struct Entry {
    kind: &'static str,
    timestamp: String,
    text: Vec<String>,
    assets: Vec<String>,
    links: Vec<String>,
}

fn image_suffix(source: &str) -> bool {
    matches!(Path::new(source).extension().and_then(|ext| ext.to_str())
        .unwrap_or("").to_ascii_lowercase().as_str(), "png" | "jpg" | "jpeg" | "webp" | "gif")
}

fn local_path(source: &str) -> Option<String> {
    if let Some(path) = source.strip_prefix("file://").or_else(|| source.strip_prefix("sandbox:")) {
        if !path.starts_with('/') { return None; }
        let path = http::decode_path(path).ok()?;
        return (!path.contains('\0')).then_some(path);
    }
    source.starts_with('/').then(|| source.to_owned())
}

fn reference(entry: &mut Entry, source: &str) {
    if source.len() > 2048 { return; }
    if let Some(path) = local_path(source) {
        if entry.assets.len() < 12 && (image_suffix(&path) || path.ends_with(".html")) && !entry.assets.contains(&path) {
            entry.assets.push(path);
        }
    } else if entry.links.len() < 12
        && (source.starts_with("https://") || source.starts_with("http://"))
        && !source.contains(['\\', '<', '>', '"', '\r', '\n']) && !entry.links.iter().any(|old| old == source) {
        entry.links.push(source.to_owned());
    }
}

fn text_part(entry: &mut Entry, text: &str) {
    if entry.kind == "user" && ["# AGENTS.md instructions for ", "<environment_context>", "<user_shell_command>",
        "<turn_aborted>", "<permissions instructions>"].iter().any(|prefix| text.trim_start().starts_with(prefix)) {
        return;
    }
    if text.trim().is_empty() { return; }
    for token in clipped(text, TEXT_LIMIT).split_ascii_whitespace() {
        let trimmed = token.trim_start_matches(['(', '[', '<', '\x60', '"']);
        let target = trimmed.rsplit_once("](").map_or(trimmed, |(_, target)| target);
        let target = target.trim_end_matches([')', ']', '>', '\x60', '"', ',', '.', ';']);
        reference(entry, target);
    }
    entry.text.push(clipped(text, TEXT_LIMIT + 4).to_owned());
}

fn parse_entry(line: &[u8], modern: bool) -> Option<Entry> {
    let event: Value = serde_json::from_slice(line).ok()?;
    let payload = &event["payload"];
    let item = &payload["item"];
    let mut entry = Entry { timestamp: event["timestamp"].as_str().unwrap_or("").to_owned(), ..Entry::default() };
    let content = match (event["type"].as_str()?, payload["type"].as_str()?) {
        ("event_msg", "item_completed") => match item["type"].as_str()? {
            "UserMessage" if modern => { entry.kind = "user"; &item["content"] }
            "AgentMessage" if modern => {
                entry.kind = if item["phase"] == "commentary" { "commentary" } else { "assistant" };
                &item["content"]
            }
            "ImageView" | "Extension" => {
                entry.kind = "image";
                if let Some(path) = item["path"].as_str().or_else(|| item["savedPath"].as_str()) { reference(&mut entry, path); }
                &Value::Null
            }
            _ => return None,
        },
        ("response_item", "message") if !modern => {
            entry.kind = match payload["role"].as_str()? {
                "user" => "user",
                "assistant" if payload["phase"] == "commentary" => "commentary",
                "assistant" => "assistant",
                _ => return None,
            };
            &payload["content"]
        }
        _ => return None,
    };
    for part in content.as_array().into_iter().flatten() {
        match part["type"].as_str() {
            Some("text" | "Text" | "input_text" | "output_text") => {
                if let Some(text) = part["text"].as_str() { text_part(&mut entry, text); }
            }
            Some("image" | "input_image") => {
                if let Some(source) = part["image_url"].as_str() {
                    if source.starts_with("data:image/") && source.len() <= WINDOW as usize {
                        entry.assets.push(source.to_owned());
                    } else { reference(&mut entry, source); }
                }
            }
            Some("localImage" | "LocalImage") => {
                if let Some(path) = part["path"].as_str() { reference(&mut entry, path); }
            }
            _ => {}
        }
        if entry.assets.len() >= 12 { break; }
    }
    (!entry.text.is_empty() || !entry.assets.is_empty() || !entry.links.is_empty()).then_some(entry)
}

fn paginated(file: &mut File) -> Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut first = Vec::new();
    BufReader::new(file.take(WINDOW)).read_until(b'\n', &mut first)?;
    let event: Value = serde_json::from_slice(&first).unwrap_or(Value::Null);
    Ok(event["payload"]["history_mode"] == "paginated")
}

struct Transcript {
    items: Vec<(u64, Entry)>,
    older: u64,
}

fn transcript_page(file: &mut File, end: u64) -> Result<Transcript> {
    let modern = paginated(file)?;
    let base = end.saturating_sub(WINDOW);
    file.seek(SeekFrom::Start(base))?;
    let mut bytes = Vec::new();
    file.take(end - base).read_to_end(&mut bytes)?;
    let mut items = Vec::new();
    let mut used = 0;
    let mut splits = bytes.iter().enumerate().rev().filter_map(|(index, byte)| (*byte == b'\n').then_some(index));
    let Some(mut stop) = splits.next() else { return Ok(Transcript { items, older: base }); };
    let older = loop {
        let previous = splits.next();
        if previous.is_none() && base > 0 {
            let boundary = base + stop as u64 + 1;
            break if boundary < end { boundary } else { base };
        }
        let start = previous.map_or(0, |index| index + 1);
        let offset = base + start as u64;
        if let Some(entry) = parse_entry(&bytes[start..stop], modern) {
            used += entry.text.iter().map(String::len).sum::<usize>()
                + entry.assets.iter().map(String::len).sum::<usize>();
            if !items.is_empty() && (items.len() >= PAGE_SIZE || used > 768 * 1024) { break base + stop as u64 + 1; }
            items.push((offset, entry));
        }
        let Some(previous) = previous else { break 0; };
        stop = previous;
    };
    Ok(Transcript { items, older })
}

fn mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") { Some("image/png") }
    else if bytes.starts_with(b"\xff\xd8\xff") { Some("image/jpeg") }
    else if matches!(bytes.get(..6), Some(b"GIF87a" | b"GIF89a")) { Some("image/gif") }
    else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") { Some("image/webp") }
    else { None }
}

fn desktop_status(status: &Value) -> &'static str {
    match status["type"].as_str() {
        Some("active") if status["activeFlags"].as_array().is_some_and(|flags| flags.iter().any(|f| f == "waitingOnApproval")) => "approval",
        Some("active") if status["activeFlags"].as_array().is_some_and(|flags| flags.iter().any(|f| f == "waitingOnUserInput")) => "input",
        Some("active") => "running",
        Some("idle") => "idle",
        Some("systemError") => "failed",
        _ => "unavailable",
    }
}

fn turn_status(turn: &Value) -> Option<&'static str> {
    match turn["status"].as_str()? {
        "completed" => Some("finished"),
        "interrupted" => Some("stopped"),
        "failed" => Some("failed"),
        _ => None,
    }
}

fn live_piece(programme: &Programme, state: &str, chat: &str, turn: Option<&str>) -> Result<String> {
    let view = programme.run("asterCodex.liveStatus", json!({"state":state,"chat":chat,"turn":turn}), &mut Meter::new(100_000))?;
    Ok(view.as_str().ok_or_else(|| fail("Missing live view"))?.to_owned())
}

fn live_end(programme: &Programme, chat: &str, new_turn: bool) -> Result<String> {
    let view = programme.run("asterCodex.liveLink", json!({
        "href": url("live", &[("id", chat)]), "newTurn": new_turn,
    }), &mut Meter::new(100_000))?;
    Ok(view.as_str().ok_or_else(|| fail("Missing live link"))?.to_owned())
}

fn notice(stream: &mut TcpStream, programme: &Programme, status: &str, message: &str) -> Result<()> {
    let view = programme.run("asterCodex.notice", json!(message), &mut Meter::new(100_000))?;
    http::send_raster_html(stream, status, SECURITY, view.as_str().ok_or_else(|| fail("Missing notice view"))?)
}

fn view_text<'a>(view: &'a Value, key: &str) -> Result<&'a str> {
    view[key].as_str().ok_or_else(|| fail("Missing live view fragment"))
}

static LIVE_SLOTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct LiveSlot;
impl LiveSlot {
    fn admit() -> Option<Self> {
        use std::sync::atomic::Ordering;
        LIVE_SLOTS.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |count| (count < 2).then_some(count + 1)).ok()?;
        Some(Self)
    }
}
impl Drop for LiveSlot {
    fn drop(&mut self) { LIVE_SLOTS.fetch_sub(1, std::sync::atomic::Ordering::Release); }
}

struct LiveFeed<'a> {
    stream: &'a mut TcpStream,
    programme: &'a Programme,
    chat: &'a str,
    turn: Option<String>,
    item: Option<String>,
    text_open: &'a str,
    text_close: &'a str,
    text_limit: &'a str,
    bytes: usize,
    status: &'static str,
    done: bool,
}

impl LiveFeed<'_> {
    fn close_text(&mut self) -> Result<()> {
        if self.item.take().is_some() { self.stream.write_all(self.text_close.as_bytes())?; }
        Ok(())
    }

    fn state(&mut self, label: &'static str) -> Result<()> {
        self.close_text()?;
        self.status = label;
        let can_stop = matches!(label, "running" | "approval" | "input");
        let turn = if can_stop { self.turn.as_deref() } else { None };
        self.stream.write_all(live_piece(self.programme, label, self.chat, turn)?.as_bytes())?;
        Ok(())
    }

    fn event(&mut self, message: Value) -> Result<()> {
        let data = &message["params"];
        if data["threadId"] != self.chat { return Ok(()); }
        match message["method"].as_str() {
            Some("thread/status/changed") => {
                let status = desktop_status(&data["status"]);
                if status != self.status && status != "idle" { self.state(status)?; }
            }
            Some("turn/started") => {
                self.done = false;
                self.turn = data["turn"]["id"].as_str().filter(|value| id(value)).map(str::to_owned);
                self.state("running")?;
            }
            Some("item/agentMessage/delta") => {
                let Some(turn) = data["turnId"].as_str().filter(|value| id(value)) else { return Ok(()); };
                if let Some(current) = &self.turn {
                    if current != turn { return Ok(()); }
                } else {
                    self.turn = Some(turn.to_owned());
                    self.state("running")?;
                }
                if self.bytes >= 192 * 1024 { return Ok(()); }
                let item = data["itemId"].as_str().unwrap_or("");
                if self.item.as_deref() != Some(item) {
                    self.close_text()?;
                    self.stream.write_all(self.text_open.as_bytes())?;
                    self.item = Some(item.to_owned());
                }
                let delta = data["delta"].as_str().unwrap_or("");
                let text = clipped(delta, (192 * 1024usize).saturating_sub(self.bytes));
                self.bytes += text.len();
                self.stream.write_all(escape(text).as_bytes())?;
                if text.len() < delta.len() {
                    self.bytes = 192 * 1024;
                    self.close_text()?;
                    self.stream.write_all(self.text_limit.as_bytes())?;
                }
            }
            Some("item/completed") if data["item"]["id"].as_str() == self.item.as_deref() => self.close_text()?,
            Some("turn/completed") if self.turn.as_deref().is_none_or(|turn| data["turn"]["id"] == turn) => {
                self.turn = None;
                self.done = true;
                self.state(turn_status(&data["turn"]).unwrap_or("unavailable"))?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl Reader {
    fn desktop(&self) -> Result<crate::aster_codex_live::Desktop> {
        crate::aster_codex_live::Desktop::connect(&self.home.join("app-server-control/app-server-control.sock"))
    }

    fn live_document(programme: &Programme, state: &str, chat: &str) -> Result<String> {
        let document = programme.run("asterCodex.liveDocument", Value::Null, &mut Meter::new(100_000))?;
        Ok(format!("{}{}{}{}",
            view_text(&document, "head")?, live_piece(programme, state, chat, None)?,
            live_end(programme, chat, true)?, view_text(&document, "tail")?))
    }

    fn watch(&self, programme: &Programme, stream: &mut TcpStream, chat: &str) -> Result<()> {
        let Some(_slot) = LiveSlot::admit() else {
            return http::send_raster_html(stream, "503 Service Unavailable", SECURITY, &Self::live_document(programme,"busy",chat)?);
        };
        let document = programme.run("asterCodex.liveDocument", json!({"heading":true}), &mut Meter::new(100_000))?;
        let text = programme.run("asterCodex.liveText", Value::Null, &mut Meter::new(100_000))?;
        let mut feed = LiveFeed { stream, programme, chat, turn: None, item: None,
            text_open: view_text(&text, "open")?, text_close: view_text(&text, "close")?, text_limit: view_text(&text, "limit")?,
            bytes: 0, status: "checking", done: false };
        http::begin_raster_stream(feed.stream, SECURITY, view_text(&document, "head")?)?;
        // Send a bounded initial chunk so embedded browsers begin parsing before the first delta.
        write!(feed.stream, "<!--{}-->", " ".repeat(2048))?;
        let watch = (|| -> Result<()> {
            let mut desktop = self.desktop()?;
            let thread = desktop.read_thread(chat)?;
            let runtime = desktop_status(&thread["status"]);
            if !matches!(runtime, "running" | "approval" | "input" | "idle") { return feed.state(runtime); }
            let latest = desktop.latest_turn(chat).unwrap_or(Value::Null);
            feed.turn = (runtime != "idle" && latest["status"] == "inProgress")
                .then(|| latest["id"].as_str().filter(|value| id(value))).flatten().map(str::to_owned);
            feed.state(if runtime=="idle" {turn_status(&latest).unwrap_or(runtime)} else {runtime})?;
            let result = desktop.call("thread/resume", json!({"threadId":chat,"excludeTurns":true}), |event| feed.event(event))?;
            if result["thread"]["id"] != chat { return Err(fail("Desktop subscribed to a different thread")); }
            if feed.done { return Ok(()); }
            let resumed = desktop_status(&result["thread"]["status"]);
            if resumed == "idle" && runtime != "idle" {
                let turn = desktop.latest_turn(chat).unwrap_or(Value::Null);
                return feed.state(turn_status(&turn).unwrap_or("idle"));
            }
            if resumed != "idle" && resumed != feed.status { feed.state(resumed)?; }
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(240) {
                if desktop.ready(feed.stream)? {
                    feed.event(desktop.next()?)?;
                    if feed.done || feed.status == "unavailable" { return Ok(()); }
                } else {
                    feed.stream.write_all(b"<!-- keep-alive -->")?;
                }
            }
            feed.state("unavailable")
        })();
        if watch.is_err() { let _ = feed.state("unavailable"); }
        let _ = feed.close_text();
        if let Ok(link) = live_end(programme, chat, watch.is_ok()) {
            let _ = feed.stream.write_all(link.as_bytes());
        }
        let _ = feed.stream.write_all(view_text(&document, "tail")?.as_bytes());
        Ok(())
    }

    fn status(&self, programme: &Programme, stream: &mut TcpStream, chat: &str, control: bool) -> Result<()> {
        let observed = (|| -> Result<(&'static str, Option<String>)> {
            let mut desktop = self.desktop()?;
            let thread = desktop.read_thread(chat)?;
            let state = desktop_status(&thread["status"]);
            let latest = if state == "idle" || control { desktop.latest_turn(chat).unwrap_or(Value::Null) }
                else { Value::Null };
            let state = if state == "idle" { turn_status(&latest).unwrap_or(state) } else { state };
            let turn = (matches!(state, "running" | "approval" | "input") && latest["status"] == "inProgress")
                .then(|| latest["id"].as_str().filter(|value| id(value))).flatten().map(str::to_owned);
            Ok((state, turn))
        })();
        let (state, turn) = observed.unwrap_or(("unavailable", None));
        let view = programme.run("asterCodex.statusDocument", json!({"state":state,"turn":turn,"chat":chat,"control":control}),
            &mut Meter::new(100_000))?;
        http::send_raster_html(stream,"200 OK",SECURITY,
            view.as_str().ok_or_else(|| fail("Missing compact activity status"))?)
    }

    fn interrupt(&self, programme: &Programme, stream: &mut TcpStream, chat: &str, turn: &str) -> Result<()> {
        let attempt = (|| -> Result<bool> {
            let mut desktop = self.desktop()?;
            let thread = desktop.read_thread(chat)?;
            if thread["status"]["type"] != "active" { return Ok(false); }
            let latest = desktop.latest_turn(chat)?;
            if latest["id"] != turn || latest["status"] != "inProgress" { return Ok(false); }
            desktop.call("turn/interrupt", json!({"threadId":chat,"turnId":turn}), |_| Ok(()))?;
            Ok(true)
        })();
        let (status,state) = match attempt {
            Ok(true) => ("200 OK","requested"),
            Ok(false) => ("409 Conflict","stale"),
            Err(_) => ("503 Service Unavailable","unavailable"),
        };
        let return_url = url("status", &[("id",chat),("control","1")]);
        let view = programme.run("asterCodex.statusDocument",
            json!({"state":state,"control":true,"notice":true,"returnUrl":return_url}), &mut Meter::new(100_000))?;
        http::send_raster_html(stream,status,SECURITY,view.as_str().ok_or_else(|| fail("Missing Stop result"))?)
    }
}

impl Reader {
    fn artifact(&self, query: &BTreeMap<String, String>) -> Result<Option<(&'static str, &'static str, Vec<u8>)>> {
        let chat = field(query, "id");
        let Ok(offset) = field(query, "event").parse::<u64>() else { return Ok(None); };
        let Ok(part) = field(query, "part").parse::<usize>() else { return Ok(None); };
        let Some(thread) = self.thread(chat)? else { return Ok(None); };
        let Some(mut file) = self.rollout(&thread)? else { return Ok(None); };
        if offset >= file.metadata()?.len() { return Ok(None); }
        let modern = paginated(&mut file)?;
        if offset != 0 {
            file.seek(SeekFrom::Start(offset - 1))?;
            let mut prior = [0];
            file.read_exact(&mut prior)?;
            if prior != [b'\n'] { return Ok(None); }
        } else { file.seek(SeekFrom::Start(0))?; }
        let mut line = Vec::new();
        BufReader::new(file.take(WINDOW)).read_until(b'\n', &mut line)?;
        if line.last() != Some(&b'\n') { return Ok(None); }
        let Some(entry) = parse_entry(&line, modern) else { return Ok(None); };
        let Some(source) = entry.assets.get(part) else { return Ok(None); };
        let mut data = Vec::new();
        if let Some(base64) = source.strip_prefix("data:image/").and_then(|value| value.split_once(";base64,").map(|p| p.1)) {
            let Ok(decoded) = Base64::decode_vec(base64) else { return Ok(None); };
            data = decoded;
        } else {
            let generated = self.home.join("generated_images");
            let attachments = self.home.join("attachments");
            let visualizations = self.home.join("visualizations");
            let path = Path::new(source);
            let is_html = path.extension().and_then(|ext| ext.to_str()) == Some("html");
            let roots: Vec<&Path> = if is_html { vec![&visualizations] }
                else { vec![&generated, &attachments, &visualizations, &self.workspace] };
            let Some(path) = under(path, &roots) else { return Ok(None); };
            let Ok(file) = regular(&path) else { return Ok(None); };
            if file.metadata()?.len() > MEDIA_LIMIT { return Ok(None); }
            file.take(MEDIA_LIMIT + 1).read_to_end(&mut data)?;
            if data.len() as u64 > MEDIA_LIMIT { return Ok(None); }
            if is_html {
                return Ok(Some(("application/octet-stream", "Content-Disposition: attachment; filename=\"preview.html\"\r\n", data)));
            }
        }
        Ok(mime(&data).map(|kind| (kind, "", data)))
    }

    fn handle(&self, programme: &Programme, stream: &mut TcpStream, request: http::Request) -> Result<()> {
        let trusted = request.headers.get("x-aster-codex-admission")
            .is_some_and(|value| bool::from(value.as_bytes().ct_eq(self.admission.as_bytes())));
        if !trusted { return http::send_headers(stream, "404 Not Found", "text/plain", SECURITY, "Not found.\n"); }
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        let route = programme.run("asterCodex.route", json!({"method":request.method,"path":path}), &mut Meter::new(100_000))?;
        let Ok(query) = http::form(query.as_bytes()) else {
            return http::send_headers(stream, "400 Bad Request", "text/plain", SECURITY, "Invalid navigation link.\n");
        };
        match route["page"].as_str() {
            Some("sign-in") => return page(stream, programme, "401 Unauthorized", "Sign in", json!({"signIn":true})),
            Some("markdown-style") => {
                let style = programme.run("asterCodex.markdownStyles", Value::Null, &mut Meter::new(100_000))?;
                return http::send_headers(stream, "200 OK", "text/css", SECURITY,
                    style.as_str().ok_or_else(|| fail("Missing Markdown styles"))?);
            },
            Some("index" | "chat") => return self.workspace(programme, stream, &query, route["page"] == "chat"),
            Some("status") => {
                let chat = field(&query,"id");
                if self.thread(chat)?.is_some() { return self.status(programme,stream,chat,field(&query,"control")=="1"); }
            },
            Some("live") => {
                let chat = field(&query,"id");
                if self.thread(chat)?.is_some() { return self.watch(programme,stream,chat); }
            },
            Some(action @ ("stop" | "pin" | "send")) => {
                if request.headers.get("origin").map(String::as_str) != Some(FORM_ORIGIN)
                    || request.headers.get("content-type").map(String::as_str) != Some("application/x-www-form-urlencoded") {
                    return notice(stream, programme, "403 Forbidden", "Origin or request type refused.");
                }
                if let Ok(body) = http::form(&request.body) {
                    let chat = field(&body,"id");
                    let turn = field(&body,"turn");
                    if let Some(row) = self.thread(chat)? {
                        match action {
                            "stop" if body.len()==2 && id(turn) => return self.interrupt(programme,stream,chat,turn),
                            "pin" if body.len()==2 && matches!(field(&body,"pin"), "0" | "1") => {
                                let pin = field(&body,"pin")=="1";
                                if self.set_pin(chat,pin).is_err() {
                                    return notice(stream, programme, "409 Conflict", "The pin could not be saved.");
                                }
                                return Self::chat_redirect(stream,chat,if pin {"pinned"} else {"unpinned"});
                            },
                            "send" if body.len()==3 && row["archived"].as_i64()!=Some(1) => {
                                let original = field(&body,"prompt");
                                let prompt = original.trim();
                                if prompt.is_empty() || prompt.len()>PROMPT_LIMIT {
                                    return self.composer_error(programme,stream,&row,chat,clipped(original,PROMPT_LIMIT),
                                        "400 Bad Request","Enter a message of up to 16,000 UTF-8 bytes.");
                                }
                                let outcome = self.submit_turn(chat,field(&body,"ticket"),prompt).unwrap_or("unknown");
                                if outcome=="sent" { return Self::chat_redirect(stream,chat,"sent"); }
                                let message = match outcome {
                                    "active" => "A turn is already running. Your message is still here.",
                                    "expired" => "This draft form expired or was already submitted. Check the chat before sending again.",
                                    _ => "Desktop did not confirm delivery. Check the chat before sending again.",
                                };
                                return self.composer_error(programme,stream,&row,chat,original,"409 Conflict",message);
                            },
                            _ => {}
                        }
                    }
                }
                return notice(stream, programme, "400 Bad Request", "Invalid turn reference.");
            },
            Some("artifact") => if let Some((kind, headers, data)) = self.artifact(&query)? {
                return http::send_bytes(stream, "200 OK", kind, &format!("{SECURITY}{headers}"), &data);
            },
            _ if route["status"] == 405 => return http::send_headers(stream, "405 Method Not Allowed", "text/plain",
                &format!("{SECURITY}Allow: GET\r\n"), "This app reads saved chats.\n"),
            _ => {}
        }
        page(stream, programme, "404 Not Found", "Unavailable", json!({"signIn":false}))
    }
}

pub fn serve(home: &Path, workspace: &Path, port: u16, admission: &Path) -> Result<()> {
    let config: Value = serde_json::from_slice(&fs::read(admission)?)?;
    let owner = config["account"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| fail("Missing Codex account binding"))?;
    let secret = config["admission"].as_str().filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| fail("Missing gateway admission binding"))?;
    let previews: BTreeMap<String, String> = serde_json::from_value(config["previews"].clone())?;
    if previews.iter().any(|(source, target)| !local_preview(source) || !target.starts_with('/')
        || target.starts_with("//") || target.contains(['\\', '\r', '\n'])) {
        return Err(fail("Invalid registered preview route"));
    }
    let pin_file = std::env::var_os("STATE_DIRECTORY").map(PathBuf::from).map(|root| root.join("pins.json"));
    let pins: BTreeSet<String> = match &pin_file {
        Some(file) => match fs::read(file) {
            Ok(data) => serde_json::from_slice(&data)?,
            Err(error) if error.kind()==std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(error) => return Err(error.into()),
        },
        None => BTreeSet::new(),
    };
    if pins.len()>PIN_LIMIT || pins.iter().any(|chat| !id(chat)) { return Err(fail("Invalid pinned chat state")); }
    let reader = Reader { home: home.canonicalize()?, workspace: workspace.canonicalize()?,
        owner: owner.to_owned(), admission: secret.to_owned(), previews,
        badges: badges::Badges::load(pin_file.as_deref().map(|path| path.with_file_name("seen.json")))?,
        pin_file,
        pins: Mutex::new(pins), tickets:Mutex::new(VecDeque::new()), submit:Mutex::new(()) };
    reader.db()?.query("SELECT id FROM threads LIMIT 1", &[])?;
    policy()?;
    http::serve_workers(port, 4, 64_000, move |stream, request| {
        let result = POLICY.with(|slot| {
            if slot.get().is_none() { let _ = slot.set(policy()?); }
            reader.handle(slot.get().expect("admitted Aster Codex policy"), stream, request)
        });
        if result.is_err() {
            let _ = http::send_headers(stream, "503 Service Unavailable", "text/plain", SECURITY,
                "Aster Codex is temporarily unavailable. Please try again.\n");
        }
    })
}
