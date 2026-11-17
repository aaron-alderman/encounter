use super::{escape, local_preview, view_text};
use crate::{Result, process::{Meter, Programme}};
use pulldown_cmark::{Alignment, Event, Options, Parser, Tag, TagEnd, html};
use serde_json::{Value, json};
use std::{collections::{BTreeMap, BTreeSet}, sync::OnceLock};

pub(super) fn destination<'a>(source: &'a str, previews: &'a BTreeMap<String, String>) -> Option<&'a str> {
    if source.len() > 2048 || source.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || source.contains(['\\', '<', '>', '"']) {
        return None;
    }
    let (scheme, address) = source.split_once("://")?;
    if !matches!(scheme, "https" | "http") { return None; }
    let host = address.split(['/', '?', '#']).next()?;
    if host.is_empty() || host.contains('@') { return None; }
    if local_preview(source) {
        return previews.get(source).map(String::as_str);
    }
    Some(source)
}

pub(super) struct LinkAddresses {
    entry: u64,
    next: usize,
}

impl LinkAddresses {
    pub(super) fn new(entry: u64) -> Self { Self { entry, next: 0 } }

    fn boundary(&mut self, programme: &Programme, href: &str) -> Result<(String, String)> {
        let id = format!("link-address-{}-{}", self.entry, self.next);
        self.next += 1;
        let view = programme.run("asterCodex.markdownLink", json!({"id":id,"href":href}), &mut Meter::new(100_000))?;
        Ok((view_text(&view, "open")?.to_owned(), view_text(&view, "close")?.to_owned()))
    }

    pub(super) fn link(&mut self, programme: &Programme, label: &str, href: &str) -> Result<String> {
        let (open, close) = self.boundary(programme, href)?;
        Ok(format!("{open}{}{close}", escape(label)))
    }
}

#[derive(Default)]
struct Table {
    columns: Vec<Alignment>,
    column: usize,
    in_head: bool,
    has_body: bool,
}

impl Table {
    fn cell<'a>(&mut self, boundaries: &'a Value) -> &'a Value {
        let alignment = match self.columns.get(self.column) {
            Some(Alignment::Right) => "right",
            Some(Alignment::Center) => "center",
            _ => "left",
        };
        self.column += 1;
        let tag = if self.in_head { "th" } else { "td" };
        &boundaries[format!("{tag}-{alignment}")]
    }
}

fn table_boundaries(programme: &Programme) -> Result<&'static Value> {
    static BOUNDARIES: OnceLock<Value> = OnceLock::new();
    if let Some(value) = BOUNDARIES.get() { return Ok(value); }
    let value = programme.run("asterCodex.markdownTable", Value::Null, &mut Meter::new(100_000))?;
    Ok(BOUNDARIES.get_or_init(|| value))
}

pub(super) fn render(
    programme: &Programme,
    text: &str,
    previews: &BTreeMap<String, String>,
    linked: &mut BTreeSet<String>,
    addresses: &mut LinkAddresses,
) -> Result<String> {
    let mut table = Table::default();
    let mut links = Vec::new();
    let mut error = None;
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS | Options::ENABLE_GFM;
    let mut adapt = |event| -> Result<_> {
        let markup = match event {
            // Raw HTML in stored transcripts is displayed as text.
            Event::Html(text) | Event::InlineHtml(text) => return Ok(Event::Text(text)),
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                let href = links.is_empty().then(|| destination(&dest_url, previews)).flatten();
                if let Some(href) = href {
                    let (open, close) = addresses.boundary(programme, href)?;
                    linked.insert(dest_url.into_string());
                    links.push(Some(close));
                    open
                } else {
                    links.push(None);
                    String::new()
                }
            }
            Event::End(TagEnd::Link | TagEnd::Image) => links.pop().flatten().unwrap_or_default(),
            Event::Start(Tag::Table(columns)) => {
                table = Table { columns, ..Table::default() };
                view_text(&table_boundaries(programme)?["table"], "open")?.to_owned()
            }
            Event::End(TagEnd::Table) => {
                let parts = table_boundaries(programme)?;
                let close = view_text(&parts["table"], "close")?;
                if table.has_body { format!("{}{close}", view_text(&parts["body"], "close")?) }
                else { close.to_owned() }
            }
            Event::Start(Tag::TableHead) => {
                table.in_head = true;
                view_text(&table_boundaries(programme)?["header"], "open")?.to_owned()
            }
            Event::End(TagEnd::TableHead) => {
                table.in_head = false;
                view_text(&table_boundaries(programme)?["header"], "close")?.to_owned()
            }
            Event::Start(Tag::TableRow) => {
                table.column = 0;
                let parts = table_boundaries(programme)?;
                let row = view_text(&parts["row"], "open")?;
                if table.has_body { row.to_owned() } else {
                    table.has_body = true;
                    format!("{}{row}", view_text(&parts["body"], "open")?)
                }
            }
            Event::End(TagEnd::TableRow) => view_text(&table_boundaries(programme)?["row"], "close")?.to_owned(),
            Event::Start(Tag::TableCell) => view_text(table.cell(table_boundaries(programme)?), "open")?.to_owned(),
            Event::End(TagEnd::TableCell) => {
                let key = if table.in_head { "th-left" } else { "td-left" };
                view_text(&table_boundaries(programme)?[key], "close")?.to_owned()
            }
            other => return Ok(other),
        };
        Ok(Event::InlineHtml(markup.into()))
    };
    let events = Parser::new_ext(text, options).map_while(|event| match adapt(event) {
        Ok(event) => Some(event),
        Err(failure) => { error = Some(failure); None }
    });
    let mut body = String::new();
    html::push_html(&mut body, events);
    error.map_or(Ok(body), Err)
}
