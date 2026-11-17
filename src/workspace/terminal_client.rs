use crate::{Result, fail, http_client};
use serde_json::Value;
use std::{io::{self, BufRead, Write}, process::ExitCode, thread, time::{Duration, Instant}};
use zeroize::Zeroizing;

const ROUTE: &str = "/workspace/terminal";
const PAGE_SIZE: usize = 12;

struct Client {
    origin: String,
    token: Zeroizing<String>,
}

impl Client {
    fn request(&self, method: &str, path: &str) -> Result<http_client::Response> {
        let authorization = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let headers = [("Authorization", authorization.as_str())];
        http_client::send(http_client::Request {
            url: &format!("{}{ROUTE}/{path}", self.origin),
            method,
            headers: if self.token.is_empty() { &[] } else { &headers },
            body: None,
            timeout: Duration::from_secs(20),
            connect_timeout: Duration::from_secs(4),
            limit: 8 * 1024 * 1024,
            resolve: None,
            trust_anchor: None,
            restoring: false,
        })
    }

    fn data(&self, path: &str) -> Result<Value> {
        read_data(self.request("GET", path)?, 200)
    }

    fn sign_in(&mut self, out: &mut impl Write) -> Result<Value> {
        let handoff = read_data(self.request("POST", "start")?, 201)?;
        let code = field(&handoff, "code");
        let token = field(&handoff, "token");
        let seconds = handoff["expiresIn"].as_u64().filter(|seconds| (1..=300).contains(seconds));
        let Some(seconds) = seconds.filter(|_| token.len() == 43 && code.len() == 12 &&
            token.bytes().chain(code.bytes()).all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))) else {
            return Err(fail("Invalid terminal sign-in response"));
        };
        self.token = Zeroizing::new(token.to_owned());
        writeln!(out, "Sourcery Workspace\n\nSign in with Temple at {}/identity-management/terminal", self.origin)?;
        writeln!(out, "Enter this code on the approval page: {code}")?;
        out.flush()?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            let reply = self.request("GET", "session")?;
            if reply.status != 202 {
                return read_data(reply, 200);
            }
            thread::sleep(Duration::from_secs(2));
        }
        Err(fail("Terminal sign-in expired. Start Sourcery Workspace again."))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if !self.token.is_empty() {
            let _ = self.request("POST", "end");
        }
    }
}

fn read_data(reply: http_client::Response, status: u16) -> Result<Value> {
    if reply.status == 401 {
        return Err(fail("Temple approval is missing, expired or revoked. Start Sourcery Workspace again."));
    }
    if reply.status != status || !reply.content_type.starts_with("application/json") {
        return Err(fail(format!("Sourcery Workspace request failed (HTTP {})", reply.status)));
    }
    Ok(serde_json::from_slice(&reply.body)?)
}

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn terminal_text(value: &str) -> String {
    value.chars().filter(|&ch| !ch.is_control() || matches!(ch, '\n' | '\t')).collect()
}

fn label(value: &str) -> String {
    terminal_text(value).replace(['\n', '\t'], " ")
}

enum View {
    Catalogue,
    Files,
}

fn file_rows(value: &Value) -> impl Iterator<Item = &Value> {
    value["collections"].as_object().into_iter().flat_map(|collections| collections.values())
        .filter_map(Value::as_array).flatten()
}

fn browse(client: &Client, input: &mut impl BufRead, out: &mut impl Write) -> Result<()> {
    let catalogue = client.data("catalogue")?;
    let entries = catalogue["entries"].as_array().ok_or_else(|| fail("Invalid Home catalogue"))?;
    let mut files = Value::Null;
    let mut view = View::Catalogue;
    let mut filter = String::new();
    let mut page = 0;
    let mut line = String::new();
    loop {
        let (heading, rows, column) = match view {
            View::Catalogue => ("Home catalogue", entries.iter().collect::<Vec<_>>(), "title"),
            View::Files => ("Authorized files", file_rows(&files).collect(), "path"),
        };
        let rows = rows.into_iter().filter(|row| field(row, column).to_lowercase().contains(&filter))
            .collect::<Vec<_>>();
        let pages = rows.len().div_ceil(PAGE_SIZE).max(1);
        page = page.min(pages - 1);
        let rows = &rows[page * PAGE_SIZE..(page * PAGE_SIZE + PAGE_SIZE).min(rows.len())];
        writeln!(out, "\n{heading}")?;
        if pages > 1 {
            writeln!(out, "Page {} of {pages}  [n] Next  [p] Previous", page + 1)?;
        }
        if rows.is_empty() {
            writeln!(out, "No entries.")?;
        }
        for (index, row) in rows.iter().enumerate() {
            writeln!(out, "{:>3}  {}", index + 1, label(field(row, column)))?;
        }
        write!(out, "\n[number] Open  [/text] Filter  [c] Catalogue  [f] Files  [q] Quit\n> ")?;
        out.flush()?;
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(());
        }
        match line.trim() {
            "q" => return Ok(()),
            "c" => {
                view = View::Catalogue;
                filter.clear();
                page = 0;
            }
            "f" => {
                files = client.data("files")?;
                view = View::Files;
                filter.clear();
                page = 0;
            }
            "n" => page = (page + 1).min(pages - 1),
            "p" => page = page.saturating_sub(1),
            query if query.starts_with('/') => {
                filter = query[1..].trim().to_lowercase();
                page = 0;
            }
            selection => {
                let Some(row) = selection.parse::<usize>().ok().and_then(|i| i.checked_sub(1))
                    .and_then(|i| rows.get(i)) else {
                    writeln!(out, "Choose a number from the list.")?;
                    continue;
                };
                match view {
                    View::Catalogue => {
                        writeln!(out, "\n{}  [{}]", label(field(row, "title")), label(field(row, "declaredType")))?;
                        writeln!(out, "Source: {}", label(field(row, "source")))?;
                        writeln!(out, "Terminal shows catalogue details. App launch is available in Web.")?;
                    }
                    View::Files => {
                        let id = field(row, "id");
                        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return Err(fail("Invalid workspace file ID"));
                        }
                        let file = client.data(&format!("files?file={id}"))?;
                        match file_rows(&file).find(|item| item["id"] == id) {
                            Some(item) => {
                                writeln!(out, "\n{}", label(field(item, "path")))?;
                                if let Some(text) = item["text"].as_str() {
                                    writeln!(out, "{}", terminal_text(text))?;
                                } else {
                                    writeln!(out, "No terminal text preview. Use File Viewer in Web when available.")?;
                                }
                            }
                            None => writeln!(out, "File unavailable or access changed.")?,
                        }
                    }
                }
                write!(out, "\n[Enter] Back  [q] Quit\n> ")?;
                out.flush()?;
                line.clear();
                if input.read_line(&mut line)? == 0 || line.trim() == "q" {
                    return Ok(());
                }
            }
        }
    }
}

pub(crate) fn run(origin: &str) -> Result<ExitCode> {
    let origin = super::origin(origin, false)?;
    let mut client = Client { origin, token: Zeroizing::new(String::new()) };
    let mut out = io::stdout().lock();
    let identity = client.sign_in(&mut out)?;
    writeln!(out, "Signed in as {}", label(field(&identity, "email")))?;
    browse(&client, &mut io::stdin().lock(), &mut out)?;
    Ok(ExitCode::SUCCESS)
}
