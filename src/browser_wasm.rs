//! Browser lowering for straight-line Encounter processes with scalar values.
use super::{Expr, Step, block, fail, lines, Result};
use crate::rel::{self, Facts};
use std::{cell::RefCell, collections::{BTreeMap, BTreeSet}};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scalar { Boolean, Number, Text }
use Scalar::{Boolean, Number, Text};

const MAX_EXPORTS: usize = 128;
const PAGE_BYTES: usize = 65_536;
const TEXT_UNITS: usize = 128;
const MAX_TEXT_EQUALITY_UNITS: usize = 4096;
const TEXT_EQUALITY_EXPORT: &str = "textEqualityUnits";

impl Scalar {
    fn parse(name: &str) -> Result<Self> {
        match name {
            "Boolean" => Ok(Boolean),
            "Number" => Ok(Number),
            "Text" => Ok(Text),
            _ => Err(fail(format!("unsupported browser Wasm type {name}"))),
        }
    }

    fn wasm(self) -> u8 {
        match self { Boolean => 0x7f, Number => 0x7c, Text => 0x7e }
    }
}

fn unsigned(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        out.push(if value == 0 { byte } else { byte | 128 });
        if value == 0 { break; }
    }
}

fn sized(bytes: &[u8], out: &mut Vec<u8>) {
    unsigned(bytes.len(), out);
    out.extend(bytes);
}

fn positive_constant(opcode: u8, mut value: u64, code: &mut Vec<u8>) {
    code.push(opcode);
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        let done = value == 0 && byte & 64 == 0;
        code.push(if done { byte } else { byte | 128 });
        if done { break; }
    }
}

fn section(id: u8, body: &[u8], module: &mut Vec<u8>) {
    module.push(id);
    sized(body, module);
}

#[derive(Default)]
struct TextLiterals {
    handles: BTreeMap<String, u64>,
    bytes: Vec<u8>,
}

impl TextLiterals {
    fn intern(&mut self, text: &str) -> Result<u64> {
        if let Some(&handle) = self.handles.get(text) { return Ok(handle); }
        let units = text.encode_utf16();
        let length = units.clone().count() * 2;
        if length > TEXT_UNITS * 2 { return Err(fail("browser Wasm text literal exceeds 128 code units")); }
        if self.bytes.len() + length > PAGE_BYTES { return Err(fail("browser Wasm text literal data exceeds one page")); }
        let offset = if length == 0 { 0 } else { PAGE_BYTES + self.bytes.len() };
        let handle = ((length as u64) << 32) | offset as u64;
        self.bytes.extend(units.flat_map(u16::to_le_bytes));
        self.handles.insert(text.to_owned(), handle);
        Ok(handle)
    }
}

#[derive(Clone)]
struct Locals<'a> {
    bindings: BTreeMap<&'a str, (usize, Scalar)>,
    number_scratch: usize,
    text_scratch: usize,
    text_cursor: Option<usize>,
    text_equal: usize,
    math: &'a [&'a str],
    literals: &'a RefCell<TextLiterals>,
}

fn local(opcode: u8, index: usize, code: &mut Vec<u8>) {
    code.push(opcode);
    unsigned(index, code);
}

fn number(value: f64, code: &mut Vec<u8>) {
    code.push(0x44); // f64.const
    code.extend(value.to_le_bytes());
}

fn trap_if(code: &mut Vec<u8>) {
    code.extend([0x04, 0x40, 0x00, 0x0b]); // if void, unreachable, end
}

fn assert_finite(code: &mut Vec<u8>) {
    code.push(0x99); // f64.abs
    number(f64::MAX, code);
    code.extend([0x65, 0x45]); // f64.le, i32.eqz
    trap_if(code);
}

fn finite_result(locals: &Locals<'_>, code: &mut Vec<u8>) {
    local(0x22, locals.number_scratch, code); // local.tee
    assert_finite(code);
    local(0x20, locals.number_scratch, code); // local.get
}

fn text_length(index: usize, code: &mut Vec<u8>) {
    local(0x20, index, code);
    positive_constant(0x42, 32, code); // i64.const
    code.push(0x88); // i64.shr_u
}

#[derive(Clone, Copy)]
enum TextMatch { Exact, Prefix, Suffix }

fn text_literal_match(value: &Expr, literal: &str, mode: TextMatch, locals: &Locals<'_>, code: &mut Vec<u8>) -> Result<Scalar> {
    let units: Vec<_> = literal.encode_utf16().collect();
    if units.len() > TEXT_UNITS { return Err(fail("browser Wasm text literal exceeds 128 code units")); }
    operand(value, Text, locals, code)?;
    local(0x21, locals.text_scratch, code); // local.set
    let bytes = units.len() * 2;
    text_length(locals.text_scratch, code);
    positive_constant(0x42, bytes as u64, code);
    if matches!(mode, TextMatch::Exact) {
        code.push(0x51); // i64.eq
    } else {
        code.push(0x5a); // i64.ge_u
        text_length(locals.text_scratch, code);
        positive_constant(0x42, (TEXT_UNITS * 2) as u64, code);
        code.extend([0x58, 0x71]); // i64.le_u, i32.and
        text_length(locals.text_scratch, code);
        code.extend([0xa7, 0x41, 1, 0x71, 0x45, 0x71]); // require an even byte count
    }
    code.extend([0x04, Boolean.wasm(), 0x41, 1]); // if, i32.const 1
    for (index, unit) in units.into_iter().enumerate() {
        local(0x20, locals.text_scratch, code);
        code.push(0xa7); // i32.wrap_i64
        if matches!(mode, TextMatch::Suffix) {
            text_length(locals.text_scratch, code);
            positive_constant(0x42, bytes as u64, code);
            code.extend([0x7d, 0xa7, 0x6a]); // i64.sub, i32.wrap_i64, i32.add
        }
        code.extend([0x2f, 0]); // i32.load16_u with byte alignment
        unsigned(index * 2, code);
        positive_constant(0x41, u64::from(unit), code);
        code.extend([0x46, 0x71]); // i32.eq, i32.and
    }
    code.extend([0x05, 0x41, 0, 0x0b]); // else i32.const 0 end
    Ok(Boolean)
}

fn text_equal_body(limit: usize) -> Vec<u8> {
    const LENGTH: usize = 2;
    const OFFSET: usize = 3;
    const RETURN_FALSE_IF: [u8; 6] = [0x04, 0x40, 0x41, 0, 0x0f, 0x0b];
    let mut code = vec![1, 2, 0x7f]; // two i32 locals
    text_length(0, &mut code);
    text_length(1, &mut code);
    code.push(0x52); // i64.ne
    code.extend(RETURN_FALSE_IF);
    text_length(0, &mut code);
    code.push(0xa7); // i32.wrap_i64
    local(0x22, LENGTH, &mut code); // local.tee
    positive_constant(0x41, (limit * 2) as u64, &mut code);
    code.push(0x4b); // i32.gt_u
    local(0x20, LENGTH, &mut code);
    code.extend([0x41, 1, 0x71, 0x72]); // odd length or over limit
    code.extend(RETURN_FALSE_IF);
    code.extend([0x02, 0x40, 0x03, 0x40]); // block, loop
    local(0x20, OFFSET, &mut code);
    local(0x20, LENGTH, &mut code);
    code.extend([0x4f, 0x0d, 1]); // i32.ge_u, br_if out of the loop
    for input in 0..2 {
        local(0x20, input, &mut code);
        code.push(0xa7); // i32.wrap_i64
        local(0x20, OFFSET, &mut code);
        code.extend([0x6a, 0x2f, 0, 0]); // i32.add, i32.load16_u with byte alignment
    }
    code.push(0x47); // i32.ne
    code.extend(RETURN_FALSE_IF);
    local(0x20, OFFSET, &mut code);
    code.extend([0x41, 2, 0x6a]); // advance one UTF-16 code unit
    local(0x21, OFFSET, &mut code);
    code.extend([0x0c, 0, 0x0b, 0x0b, 0x41, 1, 0x0b]); // loop, end, end, return true
    code
}

type CharacterClass = Vec<(u16, u16)>;

fn invalid_pattern() -> Box<dyn std::error::Error> {
    fail("expected a browser Wasm pattern with anchors, an optional literal prefix and leading class, and a bounded character class")
}

fn character_class(class: &str) -> Result<CharacterClass> {
    let literal = |ch: char| ch.len_utf16() == 1 && !ch.is_control() && !"\\[]^-".contains(ch);
    let mut ranges = Vec::new();
    let chars: Vec<_> = class.chars().collect();
    let mut remaining = chars.as_slice();
    while let [first, rest @ ..] = remaining {
        match rest {
            ['-', last, tail @ ..]
                if first.is_ascii() && last.is_ascii() && literal(*first) && literal(*last) && first <= last =>
            {
                ranges.push((*first as u16, *last as u16));
                remaining = tail;
            }
            _ if literal(*first) || (*first == '-' && rest.is_empty()) => {
                ranges.push((*first as u16, *first as u16));
                remaining = rest;
            }
            _ => return Err(invalid_pattern()),
        }
    }
    if !(1..=16).contains(&ranges.len()) { return Err(invalid_pattern()); }
    Ok(ranges)
}

// Match a literal prefix and one optional leading class, then a bounded repeated class.
struct ClassPattern {
    prefix: Vec<CharacterClass>,
    repeated: CharacterClass,
    min: usize,
    max: usize,
}

fn class_pattern(pattern: &str) -> Result<ClassPattern> {
    let (body, count) = pattern.strip_prefix(r"\A").and_then(|s| s.strip_suffix(r"}\z"))
        .and_then(|s| s.split_once("]{")).ok_or_else(invalid_pattern)?;
    let (prefix, repeated) = body.rsplit_once('[').ok_or_else(invalid_pattern)?;
    let (literal, leading) = prefix.split_once('[').map_or((prefix, None), |(literal, leading)| (literal, Some(leading)));
    let mut prefix = Vec::new();
    for ch in literal.chars() {
        if ch.len_utf16() != 1 || ch.is_control() || r"\^$.*+?()[]{}|".contains(ch) || prefix.len() == TEXT_UNITS {
            return Err(invalid_pattern());
        }
        prefix.push(vec![(ch as u16, ch as u16)]);
    }
    if let Some(leading) = leading {
        if prefix.len() == TEXT_UNITS { return Err(invalid_pattern()); }
        prefix.push(character_class(leading.strip_suffix(']').ok_or_else(invalid_pattern)?)?);
    }
    let prefix_length = prefix.len();
    let (min, max) = count.split_once(',').unwrap_or((count, count));
    let bound = |n: &str| n.parse::<usize>().ok()
        .filter(|&value| value <= TEXT_UNITS - prefix_length && n.bytes().all(|byte| byte.is_ascii_digit()))
        .map(|value| value + prefix_length).ok_or_else(invalid_pattern);
    let (min, max) = (bound(min)?, bound(max)?);
    if min > max { return Err(invalid_pattern()); }
    Ok(ClassPattern { prefix, repeated: character_class(repeated)?, min, max })
}

fn class_membership(ranges: &[(u16, u16)], load: impl Fn(&mut Vec<u8>), code: &mut Vec<u8>) {
    code.extend([0x41, 0]); // accumulated membership false
    for &(first, last) in ranges {
        load(code);
        positive_constant(0x41, u64::from(first), code);
        if first == last {
            code.push(0x46); // i32.eq
        } else {
            code.push(0x4f); // i32.ge_u
            load(code);
            positive_constant(0x41, u64::from(last), code);
            code.extend([0x4d, 0x71]); // i32.le_u, i32.and
        }
        code.push(0x72); // i32.or
    }
}

fn text_class_match(value: &Expr, pattern: &str, locals: &Locals<'_>, code: &mut Vec<u8>) -> Result<Scalar> {
    let ClassPattern { prefix, repeated, min, max } = class_pattern(pattern)?;
    let cursor = locals.text_cursor.ok_or_else(|| fail("missing browser Wasm pattern cursor"))?;
    operand(value, Text, locals, code)?;
    local(0x21, locals.text_scratch, code);
    text_length(locals.text_scratch, code);
    positive_constant(0x42, (min * 2) as u64, code);
    code.push(0x5a); // i64.ge_u
    text_length(locals.text_scratch, code);
    positive_constant(0x42, (max * 2) as u64, code);
    code.extend([0x58, 0x71]); // i64.le_u, i32.and
    text_length(locals.text_scratch, code);
    code.extend([0xa7, 0x41, 1, 0x71, 0x45, 0x71]); // require an even byte count
    code.extend([0x04, Boolean.wasm(), 0x41, 0]); // if result i32, reset cursor
    local(0x21, cursor, code);
    let load = |code: &mut Vec<u8>| {
        local(0x20, locals.text_scratch, code);
        code.push(0xa7); // i32.wrap_i64
        local(0x20, cursor, code);
        code.extend([0x6a, 0x2f, 0, 0]); // i32.add, i32.load16_u
    };
    code.extend([0x02, Boolean.wasm()]); // block result i32
    for (index, class) in prefix.iter().enumerate() {
        code.extend([0x41, 0]); // branch value false
        class_membership(class, load, code);
        code.extend([0x45, 0x0d, 0, 0x1a]); // reject this character
        positive_constant(0x41, ((index + 1) * 2) as u64, code);
        local(0x21, cursor, code);
    }
    code.extend([0x03, 0x40, 0x41, 1]); // loop, branch value true
    local(0x20, cursor, code);
    text_length(locals.text_scratch, code);
    code.extend([0xa7, 0x4f, 0x0d, 1, 0x1a]); // return true at the end
    code.extend([0x41, 0]); // branch value false
    class_membership(&repeated, load, code);
    code.extend([0x45, 0x0d, 1, 0x1a]); // return false for a nonmember
    local(0x20, cursor, code);
    code.extend([0x41, 2, 0x6a]);
    local(0x21, cursor, code);
    code.extend([0x0c, 0, 0x0b, 0x00, 0x0b, 0x05, 0x41, 0, 0x0b]); // loop, else false
    Ok(Boolean)
}

fn expression(expr: &Expr, locals: &Locals<'_>, code: &mut Vec<u8>) -> Result<Scalar> {
    match expr {
        Expr::Literal(value) if value.is_number() => {
            number(value.as_f64().ok_or_else(|| fail("invalid Wasm number"))?, code);
            Ok(Number)
        }
        Expr::Literal(value) if value.is_boolean() => {
            code.extend([0x41, u8::from(value == true)]); // i32.const
            Ok(Boolean)
        }
        Expr::Literal(value) if value.is_string() => {
            let literal = value.as_str().expect("string literal");
            positive_constant(0x42, locals.literals.borrow_mut().intern(literal)?, code);
            Ok(Text)
        }
        Expr::Ref(path) if path.len() == 1 => {
            let &(index, kind) = locals.bindings.get(path[0].as_str()).ok_or_else(|| fail("unknown Wasm local"))?;
            local(0x20, index, code); // local.get
            Ok(kind)
        }
        Expr::Apply(name, args) => match (name.as_str(), args.as_slice()) {
            ("if", [condition, yes, no]) => {
                operand(condition, Boolean, locals, code)?;
                let mut selected = Vec::new();
                let kind = expression(yes, locals, &mut selected)?;
                code.extend([0x04, kind.wasm()]); // if
                code.extend(selected);
                code.push(0x05); // else
                operand(no, kind, locals, code)?;
                code.push(0x0b); // end
                Ok(kind)
            }
            ("eq", [left, right]) => {
                if let Expr::Literal(value) = left && let Some(literal) = value.as_str() {
                    return text_literal_match(right, literal, TextMatch::Exact, locals, code);
                }
                if let Expr::Literal(value) = right && let Some(literal) = value.as_str() {
                    return text_literal_match(left, literal, TextMatch::Exact, locals, code);
                }
                let kind = expression(left, locals, code)?;
                operand(right, kind, locals, code)?;
                match kind {
                    Number => code.push(0x61), // f64.eq
                    Boolean => code.push(0x46), // i32.eq
                    Text => {
                        code.push(0x10); // call
                        unsigned(locals.text_equal, code);
                    }
                }
                Ok(Boolean)
            }
            ("add", [left, right]) => {
                operand(left, Number, locals, code)?;
                operand(right, Number, locals, code)?;
                code.push(0xa0); // f64.add
                finite_result(locals, code);
                Ok(Number)
            }
            ("at", [Expr::Apply(list, entries), index]) if list == "list" => {
                literal_lookup(entries, index, locals, code)
            }
            ("not", [value]) => {
                operand(value, Boolean, locals, code)?;
                code.push(0x45); // i32.eqz
                Ok(Boolean)
            }
            ("and", args) if args.len() <= 32 => {
                for arg in args {
                    operand(arg, Boolean, locals, code)?;
                    code.extend([0x04, Boolean.wasm()]); // if
                }
                code.extend([0x41, 1]); // i32.const 1
                for _ in args {
                    code.extend([0x05, 0x41, 0, 0x0b]); // else i32.const 0 end
                }
                Ok(Boolean)
            }
            _ => Err(fail(format!("unsupported browser Wasm expression {name}"))),
        },
        _ => Err(fail("expected a scalar browser Wasm expression")),
    }
}

fn literal_lookup(entries: &[Expr], index: &Expr, locals: &Locals<'_>, code: &mut Vec<u8>) -> Result<Scalar> {
    if !(1..=32).contains(&entries.len()) {
        return Err(fail("expected 1 to 32 literals in a browser Wasm lookup"));
    }
    let literal_type = |expr: &Expr| match expr {
        Expr::Literal(value) if value.is_number() => Some(Number),
        Expr::Literal(value) if value.is_boolean() => Some(Boolean),
        Expr::Literal(value) if value.is_string() => Some(Text),
        _ => None,
    };
    let kind = literal_type(&entries[0]).filter(|kind| entries.iter().all(|value| literal_type(value) == Some(*kind)))
        .ok_or_else(|| fail("expected homogeneous Number, Boolean, or Text literals for browser Wasm lookup"))?;
    operand(index, Number, locals, code)?;
    local(0x21, locals.number_scratch, code); // local.set
    for (position, entry) in entries.iter().enumerate() {
        local(0x20, locals.number_scratch, code);
        number(position as f64, code);
        code.extend([0x61, 0x04, kind.wasm()]); // f64.eq, if
        operand(entry, kind, locals, code)?;
        code.push(0x05); // else
    }
    code.push(0x00); // a missing value cannot cross the scalar ABI
    code.extend(std::iter::repeat_n(0x0b, entries.len())); // end
    Ok(kind)
}

fn operand(expr: &Expr, kind: Scalar, locals: &Locals<'_>, code: &mut Vec<u8>) -> Result<()> {
    if expression(expr, locals, code)? != kind { return Err(fail("browser Wasm operand type mismatch")); }
    Ok(())
}

fn math_arity(name: &str) -> Result<usize> {
    match name {
        "sin" | "cos" => Ok(1),
        "hypot" | "remainder" => Ok(2),
        _ => Err(fail(format!("unsupported browser Wasm math import {name}"))),
    }
}

fn calculate(args: &Expr, locals: &Locals<'_>, code: &mut Vec<u8>) -> Result<Scalar> {
    let Expr::Record(fields) = args else { return Err(fail("expected literal Wasm calculation")); };
    let [(operation, Expr::Literal(name)), (values, Expr::Apply(list, operands))] = fields.as_slice()
        else { return Err(fail("expected Wasm calculation operation and values")); };
    if operation != "operation" || values != "values" || list != "list" {
        return Err(fail("invalid Wasm calculation fields"));
    }
    if let Some(index) = locals.math.iter().position(|operation| Some(*operation) == name.as_str()) {
        if operands.len() != math_arity(locals.math[index])? { return Err(fail("invalid Wasm calculation arity")); }
        for expr in operands { operand(expr, Number, locals, code)?; }
        code.push(0x10); // call
        unsigned(index, code);
        finite_result(locals, code);
        return Ok(Number);
    }
    let (arity, opcode, output) = match name.as_str() {
        Some("less") => (2, 0x63, Boolean), // f64.lt
        Some("lessEqual") => (2, 0x65, Boolean), // f64.le
        Some("subtract") => (2, 0xa1, Number), // f64.sub
        Some("multiply") => (2, 0xa2, Number), // f64.mul
        Some("divide") => (2, 0xa3, Number), // f64.div
        Some("ceil") => (1, 0x9b, Number), // f64.ceil
        Some("floor") => (1, 0x9c, Number), // f64.floor
        Some("abs") => (1, 0x99, Number), // f64.abs
        Some("min") => (2, 0xa4, Number), // f64.min
        Some("max") => (2, 0xa5, Number), // f64.max
        _ => return Err(fail("unsupported browser Wasm calculation")),
    };
    if operands.len() != arity { return Err(fail("invalid Wasm calculation arity")); }
    for expr in operands { operand(expr, Number, locals, code)?; }
    code.push(opcode);
    if output == Number { finite_result(locals, code); }
    Ok(output)
}

type Parameters<'a> = Vec<(&'a str, Scalar)>;
type PureCalls<'a> = BTreeMap<&'a str, (usize, &'a [(&'a str, Scalar)], Scalar)>;

enum Output<'a> {
    Scalar(Scalar),
    Record(Parameters<'a>),
}

impl<'a> Output<'a> {
    fn parse(fields: Vec<&'a str>) -> Result<Self> {
        if let [kind] = fields.as_slice() { return Ok(Self::Scalar(Scalar::parse(kind)?)); }
        if !(2..=8).contains(&fields.len()) { return Err(fail("expected one scalar or 2 to 8 Wasm result fields")); }
        let mut names = BTreeSet::new();
        let fields = fields.into_iter().map(|field| {
            let (name, kind) = field.split_once(':').ok_or_else(|| fail("expected name:Type for Wasm result field"))?;
            if !identifier(name) || !names.insert(name) { return Err(fail("invalid or duplicate Wasm result field")); }
            Ok((name, Scalar::parse(kind)?))
        }).collect::<Result<_>>()?;
        Ok(Self::Record(fields))
    }
}

struct BrowserFunction<'a> {
    export: Option<&'a str>,
    process: &'a str,
    line: usize,
    params: Parameters<'a>,
    output: Output<'a>,
    steps: Vec<Step>,
}

impl BrowserFunction<'_> {
    fn helper_result(&self) -> Option<Scalar> {
        let Output::Scalar(kind) = self.output else { return None; };
        let straight_line = self.steps.iter().all(|step| match step {
            Step::Let(_, _) | Step::Call(_) => true,
            Step::Port { name, .. } => matches!(name.as_str(), "number.calculate" | "text.matches"),
            _ => false,
        });
        (straight_line && !self.params.iter().any(|(name, _)| *name == "result")).then_some(kind)
    }
}

fn check_call_budget(file: &str, entries: &[BrowserFunction<'_>]) -> Result<()> {
    const MAX_CALL_DEPTH: usize = 96;
    const MAX_EXPANDED_STEPS: usize = 16_384;

    #[derive(Clone, Copy, Default)]
    struct Cost { depth: usize, steps: usize }

    struct CallGraph<'a, 'b> {
        file: &'a str,
        callable: BTreeMap<&'b str, &'a BrowserFunction<'b>>,
        visiting: BTreeSet<&'b str>,
        complete: BTreeMap<&'b str, Cost>,
    }

    impl<'b> CallGraph<'_, 'b> {
        fn visit(&mut self, entry: &BrowserFunction<'b>) -> Result<Cost> {
            if let Some(&cost) = self.complete.get(entry.process) { return Ok(cost); }
            if !self.visiting.insert(entry.process) {
                return Err(self.error(entry, "recursive browser Wasm helper call"));
            }
            let cost = self.measure(&entry.steps)?;
            if cost.depth > MAX_CALL_DEPTH || cost.steps > MAX_EXPANDED_STEPS {
                return Err(self.error(entry, "browser Wasm expanded helper call budget exceeded"));
            }
            self.visiting.remove(entry.process);
            self.complete.insert(entry.process, cost);
            Ok(cost)
        }

        fn measure(&mut self, steps: &[Step]) -> Result<Cost> {
            let mut cost = Cost { depth: 0, steps: steps.len() };
            for step in steps {
                let nested = match step {
                    Step::Call(name) => {
                        let Some(&target) = self.callable.get(name.as_str()) else { continue; };
                        let mut nested = self.visit(target)?;
                        nested.depth += 1;
                        nested
                    }
                    Step::When(_, body) => self.measure(body)?,
                    Step::Port { name, .. } if name == "text.matches" => Cost { depth: 0, steps: TEXT_UNITS },
                    _ => continue,
                };
                cost.depth = cost.depth.max(nested.depth);
                cost.steps = cost.steps.saturating_add(nested.steps);
            }
            Ok(cost)
        }

        fn error(&self, entry: &BrowserFunction<'_>, message: &str) -> Box<dyn std::error::Error> {
            fail(format!("{}:{}: {}: {message}", self.file, entry.line, entry.process))
        }
    }

    let callable = entries.iter().filter(|entry| entry.helper_result().is_some())
        .map(|entry| (entry.process, entry)).collect();
    let mut graph = CallGraph { file, callable, visiting: BTreeSet::new(), complete: BTreeMap::new() };
    for entry in entries {
        graph.visit(entry)?;
    }
    Ok(())
}

fn statements<'a>(steps: &'a [Step], locals: &mut Locals<'a>, calls: &PureCalls<'_>,
    types: &mut Vec<Scalar>, code: &mut Vec<u8>, inside_when: bool) -> Result<()>
{
    for step in steps {
        let (name, kind) = match step {
            Step::Port { name, args, into } if name == "number.calculate" => (into.as_str(), calculate(args, locals, code)?),
            Step::Port { name, args, into } if name == "text.matches" => {
                let Expr::Record(fields) = args else { return Err(fail("expected browser Wasm pattern arguments")); };
                let [(value_key, value), (pattern_key, Expr::Literal(pattern))] = fields.as_slice()
                    else { return Err(fail("expected browser Wasm text value and pattern literal")); };
                if value_key != "value" || pattern_key != "pattern" { return Err(fail("invalid browser Wasm pattern fields")); }
                let pattern = pattern.as_str().ok_or_else(|| fail("expected a browser Wasm text pattern"))?;
                (into.as_str(), text_class_match(value, pattern, locals, code)?)
            }
            Step::Port { name, args, into } if matches!(name.as_str(), "text.startsWith" | "text.endsWith") => {
                let Expr::Record(fields) = args else { return Err(fail("expected literal Wasm text match arguments")); };
                let [(value_key, value), (search_key, Expr::Literal(search))] = fields.as_slice()
                    else { return Err(fail("expected Wasm text value and search literal")); };
                if value_key != "value" || search_key != "search" {
                    return Err(fail("invalid Wasm text match fields"));
                }
                let literal = search.as_str().ok_or_else(|| fail("expected a Wasm text search literal"))?;
                let mode = if name == "text.startsWith" { TextMatch::Prefix } else { TextMatch::Suffix };
                (into.as_str(), text_literal_match(value, literal, mode, locals, code)?)
            }
            Step::Let(name, expr) => (name.as_str(), expression(expr, locals, code)?),
            Step::Call(process) => {
                let &(index, params, output) = calls.get(process.as_str())
                    .ok_or_else(|| fail(format!("browser Wasm call needs a declared straight-line scalar helper: {process}")))?;
                for &(name, expected) in params {
                    let &(index, kind) = locals.bindings.get(name)
                        .ok_or_else(|| fail(format!("missing browser Wasm call input {name}")))?;
                    if kind != expected { return Err(fail(format!("browser Wasm call input type differs for {name}"))); }
                    local(0x20, index, code);
                }
                code.push(0x10); // call
                unsigned(index, code);
                ("result", output)
            }
            Step::When(condition, body) => {
                operand(condition, Boolean, locals, code)?;
                code.extend([0x04, 0x40]); // if void
                statements(body, &mut locals.clone(), calls, types, code, true)?;
                code.push(0x0b); // end
                continue;
            }
            _ => return Err(fail("unsupported browser Wasm statement")),
        };
        let prior = locals.bindings.get(name).copied();
        let index = match prior {
            Some((index, previous)) if previous == kind => index,
            Some(_) if inside_when || !matches!(step, Step::Call(_)) => {
                return Err(fail(format!("browser Wasm local type changes for {name}")));
            }
            _ => {
                let index = locals.number_scratch + 2 + usize::from(locals.text_cursor.is_some()) + types.len();
                locals.bindings.insert(name, (index, kind));
                types.push(kind);
                index
            }
        };
        local(0x21, index, code); // local.set
    }
    Ok(())
}

fn result_operand(expr: &Expr, kind: Scalar, locals: &Locals<'_>, code: &mut Vec<u8>) -> Result<()> {
    operand(expr, kind, locals, code)?;
    if kind == Text {
        local(0x21, locals.text_scratch, code); // local.set
        text_length(locals.text_scratch, code);
        positive_constant(0x42, (TEXT_UNITS * 2) as u64, code);
        code.push(0x56); // i64.gt_u
        text_length(locals.text_scratch, code);
        code.extend([0xa7, 0x41, 1, 0x71, 0x72]); // overlong or odd byte count
        trap_if(code);
        local(0x20, locals.text_scratch, code);
    }
    Ok(())
}

fn function(steps: &[Step], params: &[(&str, Scalar)], output: &Output<'_>, calls: &PureCalls<'_>,
    text_equal: usize, math: &[&str], literals: &RefCell<TextLiterals>) -> Result<Vec<u8>>
{
    let Some((Step::Let(result, returned), steps)) = steps.split_last()
        else { return Err(fail("browser Wasm process requires a final result")); };
    if result != "result" { return Err(fail("browser Wasm process requires a final result")); }
    fn has_pattern(steps: &[Step]) -> bool {
        steps.iter().any(|step| match step {
            Step::Port { name, .. } => name == "text.matches",
            Step::When(_, body) => has_pattern(body),
            _ => false,
        })
    }
    let mut locals = Locals {
        bindings: params.iter().enumerate().map(|(index, &(name, kind))| (name, (index, kind))).collect(),
        number_scratch: params.len(),
        text_scratch: params.len() + 1,
        text_cursor: has_pattern(steps).then_some(params.len() + 2),
        text_equal,
        math,
        literals,
    };
    let mut code = Vec::new();
    for (index, &(_, kind)) in params.iter().enumerate() {
        match kind {
            Number => {
                local(0x20, index, &mut code);
                assert_finite(&mut code);
            }
            Boolean => {
                local(0x20, index, &mut code);
                code.extend([0x41, 1, 0x4b]); // i32.const 1, i32.gt_u
                trap_if(&mut code);
            }
            Text => {
                local(0x20, index, &mut code);
                code.extend([0xa7, 0xad]); // i32.wrap_i64, i64.extend_i32_u
                text_length(index, &mut code);
                code.push(0x7c); // i64.add
                local(0x22, locals.text_scratch, &mut code); // keep the end offset
                code.extend([0x3f, 0, 0xad]); // memory.size, i64.extend_i32_u
                positive_constant(0x42, 16, &mut code);
                code.extend([0x86, 0x56]); // pages to bytes, i64.gt_u
                local(0x20, index, &mut code);
                code.push(0xa7); // i32.wrap_i64
                positive_constant(0x41, PAGE_BYTES as u64, &mut code);
                code.push(0x49); // offset before the literal page
                local(0x20, locals.text_scratch, &mut code);
                positive_constant(0x42, PAGE_BYTES as u64, &mut code);
                code.extend([0x56, 0x71, 0x72]); // reject a span across the page boundary
                trap_if(&mut code);
            }
        }
    }
    let mut types = Vec::new();
    statements(steps, &mut locals, calls, &mut types, &mut code, false)?;
    match output {
        Output::Scalar(kind) => result_operand(returned, *kind, &locals, &mut code)?,
        Output::Record(fields) => {
            let Expr::Record(values) = returned else { return Err(fail("expected a browser Wasm result record")); };
            if values.len() != fields.len() { return Err(fail("browser Wasm result record field count differs")); }
            for &(name, kind) in fields {
                let (_, value) = values.iter().find(|(field, _)| field == name)
                    .ok_or_else(|| fail(format!("missing browser Wasm result field {name}")))?;
                result_operand(value, kind, &locals, &mut code)?;
            }
        }
    }
    let mut declarations = Vec::new();
    unsigned(types.len() + 2 + usize::from(locals.text_cursor.is_some()), &mut declarations);
    declarations.extend([1, Number.wasm(), 1, Text.wasm()]);
    if locals.text_cursor.is_some() { declarations.extend([1, 0x7f]); }
    for kind in types { declarations.extend([1, kind.wasm()]); }
    declarations.extend(code);
    declarations.push(0x0b); // end
    Ok(declarations)
}

pub(crate) fn countdown() -> Result<Vec<u8>> {
    let declaration = Facts::parse(include_str!("../browser/countdown.rel"))?;
    let (bytes, _) = compile(&declaration, include_str!("../browser/countdown.encounter"))?;
    Ok(bytes)
}

pub(crate) fn assurance() -> Result<Vec<u8>> {
    let declaration = Facts::parse(include_str!("../browser/assurance.rel"))?;
    let (bytes, _) = compile(&declaration, include_str!("../browser/assurance.encounter"))?;
    Ok(bytes)
}

pub(crate) fn interaction() -> Result<Vec<u8>> {
    let declaration = Facts::parse(include_str!("../browser/interaction.rel"))?;
    let (bytes, _) = compile(&declaration, include_str!("../browser/interaction.encounter"))?;
    Ok(bytes)
}

pub(crate) fn guest_console_script() -> Result<&'static str> {
    static SCRIPT: std::sync::OnceLock<std::result::Result<String, String>> = std::sync::OnceLock::new();
    SCRIPT.get_or_init(|| {
        embedded_script("encounterGuestConsoleWasm", include_str!("../browser/guest-console.rel"),
            include_str!("../browser/guest-console.encounter"), include_str!("workspace/guest_console.mjs"))
            .map_err(|error| error.to_string())
    }).as_deref().map_err(|error| fail(error.clone()))
}

pub(crate) fn aster_frame_script(module: &[u8]) -> String {
    classic_script(wasm_script("encounterAsterFrameWasm", module, include_str!("workspace/aster_frame_bridge.js")))
}

fn classic_script(script: String) -> String {
    format!("(() => {{\n{script}\n}})();\n")
}

pub(crate) fn browser_policy_script(body: &str, compatibility: Option<(&str, &str)>) -> String {
    match compatibility {
        Some((legacy, fallback)) =>
            format!("{legacy}\nconst selectBrowserPolicy = (module, name) => module ?? ({fallback});\n{body}"),
        None => format!("const selectBrowserPolicy = module => module;\n{body}"),
    }
}

pub(crate) fn mobile_script(module: Option<&[u8]>) -> Result<String> {
    const BODY: &str = include_str!("workspace/mobile_runtime.mjs");
    if let Some(bytes) = module {
        return Ok(wasm_script("encounterMobileWasm", bytes, &browser_policy_script(BODY, None)));
    }
    let script = browser_policy_script(BODY, Some((
        include_str!("workspace/mobile_runtime_legacy.mjs"), "encounterLegacyMobile")));
    embedded_script("encounterMobileWasm", include_str!("../browser/mobile.rel"),
        include_str!("../browser/mobile.encounter"), &script)
}

pub(crate) fn mobile_worker_script(module: Option<&[u8]>) -> String {
    const BODY: &str = include_str!("workspace/mobile_worker.mjs");
    if let Some(bytes) = module {
        return wasm_script("encounterMobileWorkerWasm", bytes, &browser_policy_script(BODY, None));
    }
    let script = browser_policy_script(BODY, Some((
        include_str!("workspace/mobile_worker_legacy.mjs"), "encounterLegacyMobileWorker")));
    format!("const encounterMobileWorkerWasm = null;\n{BOOTSTRAP}\n{script}")
}

pub(crate) fn temple_script(module: Option<&[u8]>, presentation: &serde_json::Value) -> Result<String> {
    const BODY: &str = include_str!("workspace/temple_startup.mjs");
    let body = format!("const templePresentation = {};\n{BODY}", serde_json::to_string(presentation)?);
    if let Some(bytes) = module {
        return Ok(wasm_script("encounterTempleWasm", bytes, &browser_policy_script(&body, None)));
    }
    let script = browser_policy_script(&body, Some((
        include_str!("workspace/temple_startup_legacy.mjs"), "encounterLegacyTemple")));
    embedded_script("encounterTempleWasm", include_str!("../browser/temple.rel"),
        include_str!("../browser/temple.encounter"), &script)
}

pub(crate) fn temple_assurance_script(module: Option<&[u8]>) -> String {
    const BODY: &str = concat!(include_str!("assurance_updates.mjs"), "\nexport { refreshAssuranceList };\n");
    if let Some(bytes) = module {
        return wasm_script("encounterAssuranceWasm", bytes, &browser_policy_script(BODY, None));
    }
    let script = browser_policy_script(BODY, Some((include_str!("browser_assurance_legacy.mjs"), "encounterLegacyAssurance")));
    format!("{BOOTSTRAP}\n{script}")
}

pub(crate) const STANDALONE_CATALOG_CONTRACT: &str = "encounter/standalone-browser-wasm/1";

const CANVAS_SOURCES: [(&str, &str); 2] = [
    ("canvas.rel", include_str!("../browser/canvas.rel")),
    ("canvas.encounter", include_str!("../browser/canvas.encounter")),
];
const LIVE_EVENTS_SOURCES: [(&str, &str); 2] = [
    ("live-events.rel", include_str!("../browser/live-events.rel")),
    ("live-events.encounter", include_str!("../browser/live-events.encounter")),
];
const PREVIEW_SOURCES: [(&str, &str); 2] = [
    ("preview.rel", include_str!("../browser/preview.rel")),
    ("preview.encounter", include_str!("../browser/preview.encounter")),
];
pub(crate) const STANDALONE_MODULES: [(&str, [(&str, &str); 2]); 3] = [
    ("canvas", CANVAS_SOURCES),
    ("live-events", LIVE_EVENTS_SOURCES),
    ("preview", PREVIEW_SOURCES),
];

pub(crate) fn live_events_script(pin: Option<&crate::browser_release::ClientWasmPin>) -> Result<String> {
    client_script(pin, "encounterLiveEventsWasm", LIVE_EVENTS_SOURCES, include_str!("events-client.js"), (include_str!("events-client-legacy.js"), "encounterLegacyLiveEvents"))
}

pub(crate) fn canvas_script(pin: Option<&crate::browser_release::ClientWasmPin>) -> Result<String> {
    const BODY: &str = concat!(include_str!("canvas-painter.js"), "\n", include_str!("canvas-client.js"));
    if let Some(pin) = pin {
        let script = format!("const canvasNumbersAllowed = (...values) => values.every(Number.isFinite);\n\
            const canvasTimelinePolicy = policy => policy;\n{BODY}");
        return Ok(classic_script(wasm_script("encounterCanvasWasm", &pin.read(&CANVAS_SOURCES)?, &browser_policy_script(&script, None))));
    }
    let legacy = concat!(include_str!("canvas-controls-legacy.js"), "\n",
        "const canvasNumbersAllowed = () => true;\n",
        "const canvasTimelinePolicy = (policy, values) => values.every(value => typeof value !== 'number' || Number.isFinite(value))\n",
        "  ? policy : encounterLegacyCanvasControls;\n");
    let script = browser_policy_script(BODY, Some((legacy, "encounterLegacyCanvasControls")));
    embedded_script("encounterCanvasWasm", CANVAS_SOURCES[0].1, CANVAS_SOURCES[1].1, &script).map(classic_script)
}

fn client_script(pin: Option<&crate::browser_release::ClientWasmPin>, binding: &str,
    sources: [(&str, &str); 2], script: &str, compatibility: (&str, &str)) -> Result<String>
{
    if let Some(pin) = pin {
        return Ok(classic_script(wasm_script(binding, &pin.read(&sources)?, &browser_policy_script(script, None))));
    }
    embedded_script(binding, sources[0].1, sources[1].1, &browser_policy_script(script, Some(compatibility))).map(classic_script)
}

pub(crate) fn preview_script(pin: Option<&crate::browser_release::ClientWasmPin>) -> Result<String> {
    client_script(pin, "encounterPreviewWasm", PREVIEW_SOURCES, include_str!("preview-context.js"), (include_str!("preview-context-legacy.js"), "encounterLegacyPreview"))
}

fn embedded_script(binding: &str, declaration: &str, source: &str, script: &str) -> Result<String> {
    let (bytes, _) = compile(&Facts::parse(declaration)?, source)?;
    Ok(wasm_script(binding, &bytes, script))
}

fn wasm_script(binding: &str, bytes: &[u8], script: &str) -> String {
    use base64ct::{Base64, Encoding};
    format!("\"use strict\";\nconst {binding} = '{}';\n{BOOTSTRAP}\n{script}", Base64::encode_string(bytes))
}

pub(crate) const BOOTSTRAP: &str = include_str!("browser_wasm_bootstrap.mjs");

fn identifier(name: &str) -> bool {
    name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && name.len() <= 64
}

pub(crate) fn compile(declaration: &Facts, source: &str) -> Result<(Vec<u8>, String)> {
    if declaration.one("wasm", "contract")? != "encounter/browser-wasm/1" {
        return Err(fail("unsupported browser Wasm contract"));
    }
    let file = declaration.one("wasm", "source")?;
    let mut declarations = BTreeSet::new();
    let mut helpers = BTreeSet::new();
    let mut uses_text = false;
    for [subject, predicate, value] in &declaration.0 {
        match (subject.as_str(), predicate.as_str()) {
            ("wasm", "contract" | "source" | "math" | "textEqualityUnits") => {}
            ("wasm", _) => return Err(fail("unsupported browser Wasm declaration field")),
            (name, "entry" | "helper" | "parameter" | "result") if identifier(name) => {
                declarations.insert(name);
                if predicate == "helper" { helpers.insert(name); }
                uses_text |= matches!(predicate.as_str(), "parameter" | "result")
                    && (value == "Text" || value.ends_with(":Text"));
            }
            _ => return Err(fail(format!("unsupported browser Wasm declaration field {subject}.{predicate}"))),
        }
    }
    let export_count = declarations.len() - helpers.len();
    if !(1..=MAX_EXPORTS).contains(&export_count) {
        return Err(fail(format!("expected 1 to {MAX_EXPORTS} browser Wasm exports")));
    }
    if helpers.len() > 64 { return Err(fail("expected at most 64 private browser Wasm helpers")); }
    let exports = |name| declarations.contains(name) && !helpers.contains(name);
    let memory_export = exports("memory");
    let text_equality = declaration.values("wasm", "textEqualityUnits");
    let text_equality_limit = match text_equality.as_slice() {
        [] => TEXT_UNITS,
        [value] if uses_text && !exports(TEXT_EQUALITY_EXPORT) => {
            let limit = value.parse::<usize>()?;
            if !(TEXT_UNITS..=MAX_TEXT_EQUALITY_UNITS).contains(&limit) {
                return Err(fail("Browser Wasm text equality requires a limit from 128 to 4096 code units"));
            }
            limit
        }
        _ => return Err(fail("Expected one browser Wasm text equality limit and an available export")),
    };
    let processes = lines(source).map_err(|error| fail(format!("{file}: {error}")))?;
    let mut source_map = format!("(\"wasm\", \"source\", {})\n", rel::quote(file));
    let mut math = declaration.values("wasm", "math");
    math.sort_unstable();
    if math.windows(2).any(|pair| pair[0] == pair[1]) { return Err(fail("duplicate browser Wasm math import")); }
    let imported = math.len();
    let text_equal = imported + declarations.len();
    let mut types = Vec::new();
    let mut imports = Vec::new();
    unsigned(imported, &mut imports);
    for (index, name) in math.iter().enumerate() {
        let arity = math_arity(name)?;
        types.extend([0x60, arity as u8]); // function type with f64 parameters
        types.extend(std::iter::repeat_n(Number.wasm(), arity));
        types.extend([1, Number.wasm()]);
        sized(b"encounter.math", &mut imports);
        sized(name.as_bytes(), &mut imports);
        imports.push(0); // function import
        unsigned(index, &mut imports);
    }
    let mut functions = Vec::new();
    let mut bodies = Vec::new();
    let mut names = Vec::new();
    let literals = RefCell::new(TextLiterals::default());
    let mut entries = Vec::new();
    let mut admitted = BTreeSet::new();
    for name in declarations {
        let private = helpers.contains(name);
        if private && !declaration.values(name, "entry").is_empty() {
            return Err(fail(format!("browser Wasm function {name} cannot be both an entry and a helper")));
        }
        let process = declaration.one(name, if private { "helper" } else { "entry" })?;
        if !admitted.insert(process) { return Err(fail(format!("duplicate browser Wasm process binding {process}"))); }
        let result = Output::parse(declaration.values(name, "result"))?;
        let mut param_names = BTreeSet::new();
        let params = declaration.values(name, "parameter").into_iter().map(|spec| {
            let (name, kind) = spec.split_once(':').ok_or_else(|| fail("expected name:Type for Wasm parameter"))?;
            if !identifier(name) || !param_names.insert(name) { return Err(fail("invalid or duplicate browser Wasm parameter")); }
            Ok((name, Scalar::parse(kind)?))
        }).collect::<Result<Vec<_>>>()?;
        if params.len() > 16 { return Err(fail("browser Wasm parameter limit exceeded")); }
        let body = processes.get(process).ok_or_else(|| fail(format!("{file}: missing browser Wasm process {process}")))?;
        let header = format!("process {process}:");
        let line = source.lines().position(|line| line.trim() == header).unwrap_or_default() + 1;
        let steps = block(body, &mut 0, 2, false)
            .map_err(|error| fail(format!("{file}:{line}: {process}: {error}")))?;
        let entry = BrowserFunction {export: (!private).then_some(name), process, line, params, output: result, steps};
        if private && entry.helper_result().is_none() {
            return Err(fail(format!("{file}:{line}: {process}: expected a straight-line scalar browser Wasm helper")));
        }
        entries.push(entry);
    }
    check_call_budget(file, &entries)?;
    let calls: PureCalls<'_> = entries.iter().enumerate()
        .filter_map(|(index, entry)| entry.helper_result()
            .map(|kind| (entry.process, (imported + index, entry.params.as_slice(), kind))))
        .collect();
    for (index, entry) in entries.iter().enumerate() {
        let BrowserFunction {export, process, line, params, output, steps} = entry;
        types.push(0x60);
        unsigned(params.len(), &mut types);
        types.extend(params.iter().map(|(_, kind)| kind.wasm()));
        match output {
            Output::Scalar(kind) => types.extend([1, kind.wasm()]),
            Output::Record(fields) => {
                unsigned(fields.len(), &mut types);
                types.extend(fields.iter().map(|(_, kind)| kind.wasm()));
            }
        }
        unsigned(imported + index, &mut functions);
        let function = function(steps, params, output, &calls, text_equal, &math, &literals)
            .map_err(|error| fail(format!("{file}:{line}: {process}: {error}")))?;
        sized(&function, &mut bodies);
        if let Some(export) = export {
            sized(export.as_bytes(), &mut names);
            names.push(0); // function export
            unsigned(imported + index, &mut names);
            source_map.push_str(&format!("({}, \"entry\", {})\n({}, \"line\", \"{line}\")\n",
                rel::quote(export), rel::quote(process), rel::quote(export)));
            if matches!(output, Output::Record(_)) {
                for field in declaration.values(export, "result") {
                    source_map.push_str(&format!("({}, \"result\", {})\n", rel::quote(export), rel::quote(field)));
                }
            }
        }
    }
    let literals = literals.into_inner();
    uses_text |= !literals.handles.is_empty();
    if uses_text && memory_export { return Err(fail("browser Wasm Text reserves the memory export")); }
    if uses_text {
        types.extend([0x60, 2, Text.wasm(), Text.wasm(), 1, Boolean.wasm()]);
        unsigned(text_equal, &mut functions);
        sized(&text_equal_body(text_equality_limit), &mut bodies);
        sized(b"memory", &mut names);
        names.extend([2, 0]); // memory export, index 0
    }
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    let defined = entries.len() + usize::from(uses_text);
    let mut type_section = Vec::new();
    unsigned(imported + defined, &mut type_section);
    type_section.extend(types);
    section(1, &type_section, &mut module);
    if imported > 0 { section(2, &imports, &mut module); }
    let mut function_section = Vec::new();
    unsigned(defined, &mut function_section);
    function_section.extend(functions);
    section(3, &function_section, &mut module);
    if uses_text {
        let pages = if literals.bytes.is_empty() { 1 } else { 2 };
        section(5, &[1, 1, pages, pages], &mut module);
    }
    if !text_equality.is_empty() {
        let mut globals = vec![1, 0x7f, 0]; // one immutable i32
        positive_constant(0x41, text_equality_limit as u64, &mut globals);
        globals.push(0x0b);
        section(6, &globals, &mut module);
        sized(TEXT_EQUALITY_EXPORT.as_bytes(), &mut names);
        names.extend([3, 0]); // global export, index 0
    }
    let mut export_section = Vec::new();
    unsigned(export_count + usize::from(uses_text) + usize::from(!text_equality.is_empty()), &mut export_section);
    export_section.extend(names);
    section(7, &export_section, &mut module);
    let mut code_section = Vec::new();
    unsigned(defined, &mut code_section);
    code_section.extend(bodies);
    section(10, &code_section, &mut module);
    if !literals.bytes.is_empty() {
        let mut data = vec![1, 0]; // one active segment in the default memory
        positive_constant(0x41, PAGE_BYTES as u64, &mut data);
        data.push(0x0b); // end of the offset expression
        sized(&literals.bytes, &mut data);
        section(11, &data, &mut module);
    }
    Ok((module, source_map))
}
