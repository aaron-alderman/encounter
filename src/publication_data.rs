// REL describes an ordered tree of portable values. The publisher renders the
// checked compatibility representation in memory for existing browser clients.
use crate::{Result, fail, rel::Facts};
use flate2::read::GzDecoder;
use std::io::{BufRead, BufReader, Read};

const MAX_REL: u64 = 400_000_000;
const MAX_OUTPUT: usize = 96_000_000;

fn row(input: &mut impl BufRead, line: &mut String) -> Result<[String; 3]> {
    line.clear();
    if input.read_line(line)? == 0 || !line.ends_with('\n') {
        return Err(fail("incomplete publication REL"));
    }
    let mut facts = Facts::parse(line)?.0;
    if facts.len() != 1 { return Err(fail("expected one publication REL tuple")); }
    Ok(facts.pop().unwrap())
}

struct Projection<R> {
    input: R,
    line: String,
    output: String,
    indent: usize,
    newline: &'static str,
}

impl<R: BufRead> Projection<R> {
    fn spacing(&mut self, depth: usize) {
        if self.indent != 0 {
            self.output.push_str(self.newline);
            self.output.extend(std::iter::repeat_n(' ', depth * self.indent));
        }
    }

    fn value(&mut self, kind: &str, value: &str, depth: usize) -> Result<()> {
        if depth > 128 || self.output.len() > MAX_OUTPUT {
            return Err(fail("publication projection exceeds its bound"));
        }
        match kind {
            "record" | "sequence" => {
                let count: usize = value.parse()?;
                if count > MAX_OUTPUT { return Err(fail("publication collection exceeds its bound")); }
                let record = kind == "record";
                self.output.push(if record { '{' } else { '[' });
                for index in 0..count {
                    if index != 0 { self.output.push(','); }
                    self.spacing(depth + 1);
                    let [key, child, value] = row(&mut self.input, &mut self.line)?;
                    if record {
                        self.output.push_str(&serde_json::to_string(&key)?);
                        self.output.push(':');
                        if self.indent != 0 { self.output.push(' '); }
                    } else if key != "" {
                        return Err(fail("sequence entries cannot have keys"));
                    }
                    self.value(&child, &value, depth + 1)?;
                }
                if count != 0 { self.spacing(depth); }
                self.output.push(if record { '}' } else { ']' });
            }
            "text" => self.output.push_str(&serde_json::to_string(value)?),
            "number" => {
                serde_json::from_str::<serde_json::Number>(value)?;
                self.output.push_str(value);
            }
            "boolean" if matches!(value, "true" | "false") => self.output.push_str(value),
            "null" if value.is_empty() => self.output.push_str("null"),
            _ => return Err(fail("unsupported publication REL value")),
        }
        Ok(())
    }
}

pub fn project(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut input = BufReader::new(GzDecoder::new(bytes).take(MAX_REL + 1));
    let mut line = String::new();
    let [subject, contract, layout] = row(&mut input, &mut line)?;
    if subject != "publication.data" || contract != "encounter/ordered-value/1" {
        return Err(fail("unsupported publication data contract"));
    }
    let (indent, newline, trailing) = match layout.as_str() {
        "compact" => (0, "\n", ""),
        "compact-lf" => (0, "\n", "\n"),
        "compact-crlf" => (0, "\r\n", "\r\n"),
        "pretty" => (2, "\n", ""),
        "pretty-lf" => (2, "\n", "\n"),
        "pretty-crlf" => (2, "\r\n", "\r\n"),
        _ => return Err(fail("unsupported publication data layout")),
    };
    let [key, kind, value] = row(&mut input, &mut line)?;
    if !key.is_empty() { return Err(fail("publication root cannot have a key")); }
    let mut projection = Projection { input, line, output: String::new(), indent, newline };
    projection.value(&kind, &value, 0)?;
    if !projection.input.fill_buf()?.is_empty() || projection.output.len() > MAX_OUTPUT {
        return Err(fail("publication data closure or size differs"));
    }
    projection.output.push_str(trailing);
    Ok(projection.output.into_bytes())
}
