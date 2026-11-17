use crate::{Result, fail, process::{Meter, numeric_input}};
use pcre2::bytes::{Regex, RegexBuilder};
use serde_json::{Map, Value, json};
use std::{cmp::Ordering, fmt::Write};

pub const ADMISSION: &str = "\0encounter.admission";

pub fn external(value: &Value) -> Result<()> {
    match value {
        Value::Array(items) => { for item in items { external(item)?; } }
        Value::Object(fields) => {
            for (key, item) in fields {
                if key.contains('\0') { return Err(fail("reserved value key")); }
                external(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn browser_value(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(browser_value),
        Value::Object(fields) => {
            fields.shift_remove(ADMISSION);
            fields.values_mut().for_each(browser_value);
        }
        _ => {}
    }
}

pub fn fields(record: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut fields: Vec<_> = record.iter().filter(|(key, _)| key.as_str() != ADMISSION).collect();
    fields.sort_by_key(|(key, _)| key.parse::<u32>().ok()
        .filter(|number| *number != u32::MAX && number.to_string() == **key).unwrap_or(u32::MAX));
    fields
}

pub fn stringify(value: &Value, space: &Value) -> Result<String> {
    fn newline(output: &mut String, indent: &str, depth: usize) {
        if !indent.is_empty() {
            output.push('\n');
            for _ in 0..depth { output.push_str(indent); }
        }
    }
    fn write(output: &mut String, value: &Value, indent: &str, depth: usize) -> Result<()> {
        if depth > 128 { return Err(fail("JSON nesting limit")); }
        match value {
            Value::Object(record) => {
                output.push('{');
                let entries = fields(record);
                for (index, (key, value)) in entries.iter().enumerate() {
                    if key.contains('\0') { return Err(fail("Nonportable JSON value [TEMPLE-V001]")); }
                    if index != 0 { output.push(','); }
                    newline(output, indent, depth + 1);
                    output.push_str(&serde_json::to_string(key)?);
                    output.push(':');
                    if !indent.is_empty() { output.push(' '); }
                    write(output, value, indent, depth + 1)?;
                }
                if !entries.is_empty() { newline(output, indent, depth); }
                output.push('}');
            }
            Value::Array(items) => {
                output.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index != 0 { output.push(','); }
                    newline(output, indent, depth + 1);
                    write(output, item, indent, depth + 1)?;
                }
                if !items.is_empty() { newline(output, indent, depth); }
                output.push(']');
            }
            Value::Number(number) => output.push_str(ryu_js::Buffer::new().format_finite(number.as_f64()
                .filter(|number| number.is_finite()).ok_or_else(|| fail("Nonportable JSON number"))?)),
            _ => output.push_str(&serde_json::to_string(value)?),
        }
        Ok(())
    }

    let indent = if let Some(text) = space.as_str() {
        String::from_utf16_lossy(&text.encode_utf16().take(10).collect::<Vec<_>>())
    } else {
        " ".repeat(space.as_f64().unwrap_or(0.0).clamp(0.0, 10.0) as usize)
    };
    let mut output = String::new();
    write(&mut output, value, &indent, 0)?;
    Ok(output)
}

fn canonical_order(value: &Value, depth: usize) -> Result<Value> {
    if depth > 64 { return Err(fail("Canonical JSON nesting limit")); }
    match value {
        Value::Object(record) => {
            let mut fields: Vec<_> = record.iter().collect();
            fields.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            let mut result = Map::new();
            for (key, value) in fields {
                if key.contains('\0') { return Err(fail("Nonportable canonical JSON key")); }
                result.insert(key.clone(), canonical_order(value, depth + 1)?);
            }
            Ok(Value::Object(result))
        }
        Value::Array(items) => Ok(Value::Array(items.iter().map(|item| canonical_order(item, depth + 1))
            .collect::<Result<Vec<_>>>()?)),
        _ => Ok(value.clone()),
    }
}

pub(crate) fn canonical_json(value: &Value) -> Result<String> {
    let mut output = stringify(&canonical_order(value, 0)?, &json!(2))?;
    output.push('\n');
    Ok(output)
}

pub(crate) fn canonical_json_compact(value: &Value) -> Result<String> {
    stringify(&canonical_order(value, 0)?, &json!(0))
}

fn regex(pattern: &str, flags: &str, long_split: bool) -> Result<Regex> {
    if pattern.len() > 8192 || flags.chars().any(|flag| !"gimsuy".contains(flag) || flags.matches(flag).count() != 1)
        || pattern.contains("(*") {
        return Err(fail("unsupported regular expression"));
    }
    // Bound PCRE2's search independently of the process instruction meter.
    let (depth, heap) = if long_split { (128_000, 32_768) } else { (10_000, 2_048) };
    let pattern = format!("(*LIMIT_MATCH=500000)(*LIMIT_DEPTH={depth})(*LIMIT_HEAP={heap}){pattern}");
    Ok(RegexBuilder::new().utf(true).caseless(flags.contains('i'))
        .multi_line(flags.contains('m')).dotall(flags.contains('s')).build(&pattern)?)
}

pub fn regex_port(name: &str, args: &Value, meter: &mut Meter) -> Result<Value> {
    let text = |key| args[key].as_str().ok_or_else(|| fail(format!("expected text field {key}")));
    let subject = text("value")?;
    let pattern = text("pattern")?;
    let flags = args["flags"].as_str().unwrap_or_default();
    meter.charge(subject.len().saturating_add(pattern.len()))?;
    let re = regex(pattern, flags, name == "text.split" && subject.len() > 40_000)?;
    let bytes = subject.as_bytes();
    if name == "text.matches" {
        return Ok(json!(re.find(bytes)?.is_some_and(|m| !flags.contains('y') || m.start() == 0)));
    }
    let mut found = Vec::new();
    let mut output = String::new();
    let mut previous = 0;
    let mut seen = 0;
    let mut units = 0;
    let mut units_at = 0;
    for hit in re.captures_iter(bytes) {
        let hit = hit?;
        let matched = hit.get(0).ok_or_else(|| fail("missing regex match"))?;
        let start = matched.start();
        let end = matched.end();
        if flags.contains('y') && start != previous { break; }
        seen += 1;
        meter.charge(1 + hit.len())?;
        if seen > 100_000 { return Err(fail("regex match limit")); }
        let groups = (1..hit.len()).map(|i| hit.get(i).map(|m| &subject[m.start()..m.end()])).collect::<Vec<_>>();
        match name {
            "text.match" | "text.matchAll" => {
                units += subject[units_at..start].encode_utf16().count();
                units_at = start;
                let observation = json!({"text": &subject[start..end], "groups": groups, "index": units});
                if name == "text.match" { return Ok(observation); }
                found.push(observation);
            }
            "text.split" => {
                if start == end && (start == previous || start == subject.len()) { continue; }
                found.push(json!(&subject[previous..start]));
                found.extend(groups.iter().map(|group| json!(group)));
            }
            "text.replace" => {
                output.push_str(&subject[previous..start]);
                replace(&mut output, text("replacement")?, subject, start, end, &groups)?;
                if output.len() > 4_000_000 { return Err(fail("regex replacement output limit")); }
                if !flags.contains('g') {
                    output.push_str(&subject[end..]);
                    return Ok(json!(output));
                }
            }
            _ => return Err(fail("unknown regex port")),
        }
        previous = end;
    }
    Ok(match name {
        "text.match" => Value::Null,
        "text.replace" => { output.push_str(&subject[previous..]); json!(output) }
        "text.split" if subject.is_empty() && re.is_match(bytes)? => json!([]),
        "text.split" => { found.push(json!(&subject[previous..])); Value::Array(found) }
        _ => Value::Array(found),
    })
}

fn replace(output: &mut String, replacement: &str, subject: &str, start: usize, end: usize, groups: &[Option<&str>]) -> Result<()> {
    let mut chars = replacement.chars().peekable();
    while let Some(ch) = chars.next() {
        if output.len() >= 4_000_000 { return Err(fail("regex replacement output limit")); }
        if ch != '$' { output.push(ch); continue; }
        let substitution = match chars.peek() {
            Some('$') => "$",
            Some('&') => &subject[start..end],
            Some('`') => &subject[..start],
            Some('\'') => &subject[end..],
            Some(ch @ '1'..='9') if (*ch as usize - '1' as usize) < groups.len() =>
                groups[*ch as usize - '1' as usize].unwrap_or_default(),
            _ => { output.push('$'); continue; }
        };
        chars.next();
        if output.len().saturating_add(substitution.len()) > 4_000_000 {
            return Err(fail("regex replacement output limit"));
        }
        output.push_str(substitution);
    }
    Ok(())
}

thread_local! {
    static COLLATOR: icu_collator::CollatorBorrowed<'static> =
        icu_collator::Collator::try_new(Default::default(), Default::default()).expect("compiled root collation data");
}

pub fn compare(left: &str, right: &str) -> Ordering { COLLATOR.with(|collator| collator.compare(left, right)) }

pub fn format_number(value: &Value, digits: &Value) -> Result<Value> {
    let number = numeric_input(value);
    let digits = digits.as_f64().unwrap_or(0.0).trunc();
    if !(0.0..=100.0).contains(&digits) { return Err(fail("number.format precision")); }
    if !number.is_finite() || number.abs() >= 1e21 {
        return Ok(json!(ryu_js::Buffer::new().format(number)));
    }
    // ECMAScript rounds the exact binary value, with halfway cases away from zero.
    let mut formatted = String::new();
    let bits = number.abs().to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let significand = (bits & ((1 << 52) - 1)) | if exponent == 0 { 0 } else { 1 << 52 };
    let shift = exponent.max(1) - 1023 - 52;
    let scaled = num_bigint::BigUint::from(significand) * num_bigint::BigUint::from(10u8).pow(digits as u32);
    let rounded = if shift >= 0 { scaled << shift as usize }
        else { (scaled + (num_bigint::BigUint::from(1u8) << (-shift - 1) as usize)) >> (-shift) as usize };
    let digits = digits as usize;
    let text = rounded.to_str_radix(10);
    if number < 0.0 { formatted.push('-'); }
    if digits == 0 { formatted.push_str(&text); }
    else if digits >= text.len() { write!(formatted, "0.{:0>digits$}", text)?; }
    else {
        let (whole, fraction) = text.split_at(text.len() - digits);
        write!(formatted, "{whole}.{fraction}")?;
    }
    Ok(json!(formatted))
}

pub fn parse_number(value: &Value, radix: Option<&Value>) -> Value {
    let number = if let Some(radix) = radix {
        let raw = crate::process::js_string(value);
        let mut text = raw.trim_start_matches(crate::process::js_space);
        let negative = text.starts_with('-');
        if let Some(unsigned) = text.strip_prefix(['+', '-']) { text = unsigned; }
        let mut radix = numeric_input(radix) as u32;
        if matches!(radix, 0 | 16) && (text.starts_with("0x") || text.starts_with("0X")) {
            radix = 16;
            text = &text[2..];
        }
        if radix == 0 { radix = 10; }
        if !(2..=36).contains(&radix) { return Value::Null; }
        let mut digits = text.chars().map_while(|ch| ch.to_digit(radix)).peekable();
        if digits.peek().is_none() { return Value::Null; }
        let result = digits.fold(0.0, |value, digit| value * f64::from(radix) + f64::from(digit));
        if negative { -result } else { result }
    } else { numeric_input(value) };
    crate::process::numeric_result(number).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_json_preserves_receipt_bytes_and_hides_admission() {
        let value: Value = serde_json::from_str(r#"{"z":0.1,"9":9,"1":1,"a":1.0}"#).unwrap();
        let mut prepared = value;
        prepared[ADMISSION] = json!("native seal");
        assert_eq!(stringify(&prepared, &Value::Null).unwrap(), r#"{"1":1,"9":9,"z":0.1,"a":1}"#);
        assert!(external(&prepared).is_err());
        browser_value(&mut prepared);
        assert!(external(&prepared).is_ok());
    }

    #[test]
    fn browser_number_and_regex_observations() {
        assert_eq!(format_number(&json!(1.125), &json!(2)).unwrap(), "1.13");
        assert_eq!(format_number(&json!(2.55), &json!(1)).unwrap(), "2.5");
        assert_eq!(parse_number(&json!("  -0xFz"), None), Value::Null);
        assert_eq!(parse_number(&json!("  -0xFz"), Some(&json!(16))), -15);
        let mut meter = Meter::new(2000);
        let found = regex_port("text.matchAll", &json!({"value":"🐚 a1 b2", "pattern":"([a-z])([0-9])"}), &mut meter).unwrap();
        assert_eq!(found[0], json!({"text":"a1","groups":["a","1"],"index":3}));
        assert_eq!(found[1], json!({"text":"b2","groups":["b","2"],"index":6}));
    }
}
