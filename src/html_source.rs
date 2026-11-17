// Source ranges for explicitly marked elements in generated release documents.
// Keep unselected bytes intact, including scripts and CSP-hashed style blocks.
use super::{Meter, text};
use crate::{Result, fail};
use pcre2::bytes::Regex;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{collections::HashMap, ops::Range, sync::LazyLock};

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(
    r#"(?is)<!--.*?(?:-->|\z)|<![^>]*>|<(\/)?([a-z][a-z0-9:-]*)(?=[\s/>])((?:[^"'>]|"[^"]*"|'[^']*')*)>"#
).unwrap());
static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| Regex::new(
    r#"([^\s=/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>\x60]+)))?"#
).unwrap());

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Selector {
    tag: Option<String>,
    #[serde(default)]
    attrs: Map<String, Value>,
    #[serde(default)]
    prefixes: HashMap<String, String>,
    #[serde(default)]
    include_content: bool,
}

struct Element {
    start: usize,
    name_end: usize,
    open_end: usize,
    close_start: Option<usize>,
    end: Option<usize>,
    attrs: Map<String, Value>,
    attributes: Map<String, Value>,
}

fn parse_attributes(raw: &str, offset: usize) -> Result<(Map<String, Value>, Map<String, Value>)> {
    let mut attrs = Map::new();
    let mut ranges = Map::new();
    for capture in ATTRIBUTE.captures_iter(raw.as_bytes()) {
        let capture = capture?;
        let key = capture.get(1).unwrap();
        let name = raw[key.start()..key.end()].to_ascii_lowercase();
        if attrs.contains_key(&name) { continue; }
        let token = capture.get(0).unwrap();
        let value = (2..=4).find_map(|index| capture.get(index));
        attrs.insert(name.clone(), json!(value.map_or("", |part| &raw[part.start()..part.end()])));
        ranges.insert(name, json!({"start": offset + token.start(), "end": offset + token.end(),
            "valueStart": value.map(|part| offset + part.start()),
            "valueEnd": value.map(|part| offset + part.end())}));
    }
    Ok((attrs, ranges))
}

pub(super) fn select(args: &Value, meter: &mut Meter) -> Result<Value> {
    let source = text(&args["html"])?;
    let selector: Selector = serde_json::from_value(args["select"].clone())?;
    if selector.tag.is_none() && selector.attrs.is_empty() && selector.prefixes.is_empty() {
        return Err(fail("Expected a constrained HTML source selector"));
    }
    if selector.attrs.values().any(|value| !value.is_string() && !value.is_boolean()) {
        return Err(fail("Expected a text or presence test for an HTML attribute"));
    }
    meter.charge(source.len())?;
    let mut cursor = 0;
    let mut captures = TAG.capture_locations();
    let mut open = HashMap::<String, Vec<Option<usize>>>::new();
    let mut selected = Vec::<Element>::new();
    while let Some(token) = TAG.captures_read_at(&mut captures, source.as_bytes(), cursor)? {
        cursor = token.end();
        let Some((name_start, name_end)) = captures.get(2) else { continue };
        let tag = source[name_start..name_end].to_ascii_lowercase();
        let closing = captures.get(1).is_some();
        if closing {
            if let Some(Some(index)) = open.get_mut(&tag).and_then(Vec::pop) {
                selected[index].close_start = Some(token.start());
                selected[index].end = Some(token.end());
            }
            continue;
        }
        let void = matches!(tag.as_str(), "area" | "base" | "br" | "col" | "embed" | "hr" |
            "img" | "input" | "link" | "meta" | "param" | "source" | "track" | "wbr")
            || source[..token.end()].ends_with("/>");
        if matches!(tag.as_str(), "script" | "style" | "textarea" | "title" | "iframe" |
            "xmp" | "noembed" | "noframes") {
            // Search directly for the raw text terminator. HTML-looking text
            // inside this element may itself contain comments or open quotes.
            let close = Regex::new(&format!(r"(?i)</{}\s*>", tag))?;
            cursor = close.find_at(source.as_bytes(), cursor)?.map_or(source.len(), |end| end.start());
        }
        let mut index = None;
        if selector.tag.as_ref().is_none_or(|expected| expected == &tag) {
            let (start, end) = captures.get(3).unwrap();
            let (attrs, attributes) = parse_attributes(&source[start..end], start)?;
            let matched = selector.attrs.iter().all(|(key, expected)| match expected.as_bool() {
                Some(true) => attrs.contains_key(key),
                Some(false) => !attrs.contains_key(key),
                None => attrs.get(key) == Some(expected),
            }) && selector.prefixes.iter().all(|(key, prefix)|
                attrs.get(key).and_then(Value::as_str).is_some_and(|value| value.starts_with(prefix)));
            if matched {
                meter.charge(64 + attributes.len() * 32)?;
                index = Some(selected.len());
                selected.push(Element { start: token.start(), name_end, open_end: token.end(),
                    close_start: void.then_some(token.end()), end: void.then_some(token.end()), attrs, attributes });
            }
        }
        if !void { open.entry(tag).or_default().push(index); }
    }
    let mut results = Vec::with_capacity(selected.len());
    for element in selected {
        let (Some(close), Some(end)) = (element.close_start, element.end) else { continue };
        let mut result = json!({
            "start": element.start, "nameEnd": element.name_end, "openEnd": element.open_end, "closeStart": close,
            "end": end, "attrs": element.attrs, "attributes": element.attributes,
        });
        if selector.include_content {
            meter.charge(close - element.open_end)?;
            result["content"] = json!(&source[element.open_end..close]);
        }
        results.push(result);
    }
    Ok(json!(results))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit<'a> {
    start: usize,
    end: usize,
    #[serde(borrow)]
    value: std::borrow::Cow<'a, str>,
}

pub(super) fn edit(args: &Value, meter: &mut Meter) -> Result<Value> {
    let source = text(&args["html"])?;
    let mut changes = args["edits"].as_array().ok_or_else(|| fail("Expected HTML source edits"))?
        .iter().map(Edit::deserialize).collect::<std::result::Result<Vec<_>, _>>()?;
    meter.charge(source.len())?;
    changes.sort_by_key(|edit| (edit.start, edit.end));
    let mut result = String::with_capacity(source.len());
    let mut cursor = 0;
    for change in changes {
        if change.start < cursor || change.end < change.start || !source.is_char_boundary(change.end) {
            return Err(fail("Invalid or overlapping HTML source edits"));
        }
        let before: Range<usize> = cursor..change.start;
        result.push_str(source.get(before).ok_or_else(|| fail("Invalid HTML source edit boundary"))?);
        meter.charge(change.value.len())?;
        result.push_str(&change.value);
        cursor = change.end;
    }
    result.push_str(&source[cursor..]);
    Ok(json!(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_source_preserves_legacy_markup_around_selected_elements() {
        let before = concat!(
            "🌏<style>p:after{content:'<span data-slot></span>'}</style>",
            "<script>const x = '<!-- <span data-slot></span>';</script>",
            "<!-- <span data-slot></span> -->",
            "<SPAN title='a > b' DATA-SLOT><span>Inner</span></SPAN>",
            r#"<span data-slot=""></span>"#,
        );
        let mut meter = Meter::new(10_000);
        let slots = select(&json!({"html":before,"select":{
            "tag":"span","attrs":{"data-slot":true},"includeContent":true,
        }}), &mut meter).unwrap();
        assert_eq!(slots.as_array().unwrap().len(), 2);
        assert_eq!(slots[0]["content"], "<span>Inner</span>");
        assert_eq!(slots[0]["attrs"]["title"], "a > b");
        let updated = edit(&json!({"html":before,"edits":[
            {"start":slots[1]["start"],"end":slots[1]["end"],"value":"other"},
            {"start":slots[0]["start"],"end":slots[0]["end"],"value":"first"},
        ]}), &mut meter).unwrap();
        assert_eq!(updated, before.replace("<SPAN title='a > b' DATA-SLOT><span>Inner</span></SPAN>", "first")
            .replace("<span data-slot=\"\"></span>", "other"));
    }

    #[test]
    fn html_source_rejects_overlaps_and_partial_utf8_edits() {
        let mut meter = Meter::new(10_000);
        assert!(edit(&json!({"html":"🌏<&","edits":[
            {"start":0,"end":4,"value":""},
            {"start":0,"end":5,"value":""},
        ]}), &mut meter).is_err());
        assert!(edit(&json!({"html":"🌏<&","edits":[
            {"start":1,"end":4,"value":""},
        ]}), &mut meter).is_err());
    }
}
