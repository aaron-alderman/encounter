// Bounded UTF-8 CSV parsing. Mapping, normalization and validation belong to the caller.
use crate::{Result, fail};
use serde_json::{Value, json};

#[derive(PartialEq)]
enum Field { Start, Plain, Quoted, Closed }

pub fn read(source: &str) -> Result<Value> {
    if source.len() > 24 * 1024 { return Err(fail("CSV: File exceeds 24 KiB.")); }
    let mut input = source.strip_prefix('\u{feff}').unwrap_or(source).chars().peekable();
    let mut rows = Vec::new();
    let mut cells = Vec::new();
    let mut value = String::new();
    let mut field = Field::Start;
    let (mut line, mut start_line) = (1, 1);
    while let Some(ch) = input.next() {
        if field == Field::Quoted {
            match ch {
                '"' if input.peek() == Some(&'"') => { input.next(); value.push('"'); }
                '"' => field = Field::Closed,
                '\n' => { line += 1; value.push(ch); }
                _ => value.push(ch),
            }
            continue;
        }
        match ch {
            '"' if field == Field::Start => field = Field::Quoted,
            ',' | '\n' | '\r' => {
                cells.push(std::mem::take(&mut value));
                if cells.len() > 16 { return Err(fail(format!("CSV line {start_line}: Too many columns."))); }
                field = Field::Start;
                if ch != ',' {
                    if ch == '\r' && input.next() != Some('\n') {
                        return Err(fail(format!("CSV line {line}: Expected CRLF.")));
                    }
                    rows.push(json!({"line":start_line,"cells":std::mem::take(&mut cells)}));
                    if rows.len() > 101 { return Err(fail("CSV: Too many rows.")); }
                    line += 1;
                    start_line = line;
                }
            }
            _ if field == Field::Closed || ch == '"' || ch == '\0' =>
                return Err(fail(format!("CSV line {line}: Invalid field quoting or character."))),
            _ => { field = Field::Plain; value.push(ch); }
        }
    }
    if field == Field::Quoted { return Err(fail(format!("CSV line {start_line}: Unclosed quote."))); }
    if field != Field::Start || !cells.is_empty() {
        cells.push(value);
        if rows.len() >= 101 || cells.len() > 16 { return Err(fail("CSV: Too many rows or columns.")); }
        rows.push(json!({"line":start_line,"cells":cells}));
    }
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_cells_and_physical_line_coordinates() {
        let rows = read("\u{feff}id,name\r\nE-1,\"Maya, \"\"M\"\"\r\nChen\"\r\nE-2,Sam").unwrap();
        assert_eq!(rows, json!([
            {"line":1,"cells":["id","name"]},
            {"line":2,"cells":["E-1","Maya, \"M\"\r\nChen"]},
            {"line":4,"cells":["E-2","Sam"]}
        ]));
        assert!(read("id,\"open").is_err());
        assert!(read("id,\"closed\"suffix").is_err());
        assert!(read(&"x".repeat(24 * 1024 + 1)).is_err());
    }
}
