use crate::model::*;
use memchr::memchr2;

/// Parse JSON and return one region per string *value* (inner bytes, excluding
/// the quotes), tagged with the key it sits under. Returns None when the input
/// isn't JSON we can walk, so the caller can fall back to a plaintext region.
///
/// Only string values become regions, so keys and structural bytes are never
/// masked and the output re-parses as valid JSON.
/// Bound recursion so pathological nesting returns None (graceful plaintext
/// fallback) instead of overflowing the stack, which would abort the process.
const MAX_DEPTH: usize = 128;

pub fn parse_json_regions(raw: &str) -> Option<Vec<Region>> {
    parse_json_regions_with(raw, JsonRegionMode::Json, false)
}

pub fn parse_ndjson_regions(raw: &str) -> Option<Vec<Region>> {
    parse_ndjson_regions_with(raw, false)
}

pub(crate) fn parse_json_analysis_regions(raw: &str) -> Option<Vec<Region>> {
    parse_json_regions_with(raw, JsonRegionMode::Json, true)
}

pub(crate) fn parse_ndjson_analysis_regions(raw: &str) -> Option<Vec<Region>> {
    parse_ndjson_regions_with(raw, true)
}

pub(crate) fn parse_tool_result_analysis_regions(raw: &str) -> Option<Vec<Region>> {
    parse_json_regions_with(raw, JsonRegionMode::ToolResult, true)
}

fn parse_ndjson_regions_with(raw: &str, include_primitives: bool) -> Option<Vec<Region>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut saw_line = false;
    while start <= raw.len() {
        let line_end = raw[start..]
            .find('\n')
            .map_or(raw.len(), |offset| start + offset);
        let end = line_end
            .checked_sub(1)
            .filter(|idx| raw.as_bytes().get(*idx) == Some(&b'\r'))
            .unwrap_or(line_end);
        let line = &raw[start..end];
        if !line.trim().is_empty() {
            saw_line = true;
            let mut regions =
                parse_json_regions_with(line, JsonRegionMode::Json, include_primitives)?;
            for region in &mut regions {
                region.span.start += start;
                region.span.end += start;
            }
            out.extend(regions);
        }
        if line_end == raw.len() {
            break;
        }
        start = line_end + 1;
    }
    saw_line.then_some(out)
}

pub fn parse_tool_result_regions(raw: &str) -> Option<Vec<Region>> {
    parse_json_regions_with(raw, JsonRegionMode::ToolResult, false)
}

fn parse_json_regions_with(
    raw: &str,
    mode: JsonRegionMode,
    include_primitives: bool,
) -> Option<Vec<Region>> {
    let mut p = Parser {
        b: raw.as_bytes(),
        i: 0,
        out: Vec::new(),
        mode,
        include_primitives,
    };
    if p.b.starts_with(&[0xef, 0xbb, 0xbf]) {
        p.i = 3;
    }
    p.skip_ws();
    p.value(None, Vec::new(), 0)?;
    p.skip_ws();
    if p.i != p.b.len() {
        return None;
    }
    Some(p.out)
}

#[derive(Clone, Copy)]
enum JsonRegionMode {
    Json,
    ToolResult,
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    out: Vec<Region>,
    mode: JsonRegionMode,
    include_primitives: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while self
            .b
            .get(self.i)
            .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.i += 1;
        }
    }

    fn value(&mut self, key: Option<String>, hints: Vec<String>, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(key, hints, depth + 1),
            b'"' => {
                let range = self.string_range()?;
                self.out.push(Region {
                    span: range,
                    ctx: Context {
                        path: None,
                        key,
                        hints,
                        kind: RegionKind::JsonValue,
                        format: self.format(),
                    },
                });
                Some(())
            }
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            _ => self.number(key, hints),
        }
    }

    fn object(&mut self, depth: usize) -> Option<()> {
        self.i += 1; // '{'
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Some(());
        }
        let mut sibling_name: Option<String> = None;
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return None;
            }
            let (key_range, key) = self.string()?;
            if matches!(self.mode, JsonRegionMode::ToolResult) {
                self.out.push(Region {
                    span: key_range,
                    ctx: Context {
                        path: None,
                        key: None,
                        hints: Vec::new(),
                        kind: RegionKind::JsonKey,
                        format: self.format(),
                    },
                });
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return None;
            }
            self.i += 1;
            self.skip_ws();
            if key.eq_ignore_ascii_case("name") && self.peek() == Some(b'"') {
                let (range, value) = self.string()?;
                sibling_name = Some(value);
                self.out.push(Region {
                    span: range,
                    ctx: Context {
                        path: None,
                        key: Some(key),
                        hints: Vec::new(),
                        kind: RegionKind::JsonValue,
                        format: self.format(),
                    },
                });
            } else {
                let hints = if key.eq_ignore_ascii_case("value") {
                    sibling_name.iter().cloned().collect()
                } else {
                    Vec::new()
                };
                self.value(Some(key), hints, depth)?;
            }
            self.skip_ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, key: Option<String>, hints: Vec<String>, depth: usize) -> Option<()> {
        self.i += 1; // '['
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Some(());
        }
        loop {
            // Array elements inherit the array's key as their context.
            self.value(key.clone(), hints.clone(), depth)?;
            self.skip_ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    /// Returns the inner byte range and inner text. Assumes the current byte is `"`.
    /// Escapes are scanned but not decoded; the inner text is the raw slice.
    fn string(&mut self) -> Option<(ByteRange, String)> {
        let range = self.string_range()?;
        let raw = std::str::from_utf8(&self.b[range.start..range.end]).ok()?;
        let text = decode_json_string(raw)?;
        Some((range, text))
    }

    fn string_range(&mut self) -> Option<ByteRange> {
        self.i += 1; // opening quote
        let start = self.i;
        loop {
            let off = memchr2(b'"', b'\\', self.b.get(self.i..)?)?;
            self.i += off;
            match self.b[self.i] {
                b'"' => {
                    let end = self.i;
                    self.i += 1; // closing quote
                    return Some(ByteRange::new(start, end));
                }
                b'\\' => self.skip_escape()?,
                _ => unreachable!("memchr2 only returns quote or backslash"),
            }
        }
    }

    fn skip_escape(&mut self) -> Option<()> {
        self.i += 1; // backslash
        match *self.b.get(self.i)? {
            b'u' => {
                if self.i + 5 > self.b.len() {
                    return None;
                }
                self.i += 5;
            }
            _ => self.i += 1,
        }
        Some(())
    }

    fn literal(&mut self, lit: &[u8]) -> Option<()> {
        if self.b.get(self.i..)?.starts_with(lit) {
            self.i += lit.len();
            Some(())
        } else {
            None
        }
    }

    fn number(&mut self, key: Option<String>, hints: Vec<String>) -> Option<()> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while self
            .b
            .get(self.i)
            .is_some_and(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            self.i += 1;
        }
        if self.i == start {
            None
        } else {
            if self.include_primitives {
                self.out.push(Region {
                    span: ByteRange::new(start, self.i),
                    ctx: Context {
                        path: None,
                        key,
                        hints,
                        kind: RegionKind::JsonValue,
                        format: self.format(),
                    },
                });
            }
            Some(())
        }
    }

    fn format(&self) -> Kind {
        match self.mode {
            JsonRegionMode::Json => Kind::Json,
            JsonRegionMode::ToolResult => Kind::ToolResult,
        }
    }
}

fn decode_json_string(raw: &str) -> Option<String> {
    if !raw.as_bytes().contains(&b'\\') {
        return Some(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let mut value = 0u32;
                for _ in 0..4 {
                    value = value.checked_mul(16)?;
                    value += chars.next()?.to_digit(16)?;
                }
                if (0xd800..=0xdbff).contains(&value) {
                    if chars.next()? != '\\' || chars.next()? != 'u' {
                        return None;
                    }
                    let mut low = 0u32;
                    for _ in 0..4 {
                        low = low.checked_mul(16)?;
                        low += chars.next()?.to_digit(16)?;
                    }
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return None;
                    }
                    let scalar = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00);
                    out.push(char::from_u32(scalar)?);
                } else {
                    out.push(char::from_u32(value)?);
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_values_with_keys() {
        let raw = r#"{"a":"x","n":1,"o":{"b":"y"},"arr":["z"]}"#;
        let regions = parse_json_regions(raw).unwrap();
        let got: Vec<(Option<&str>, &str)> = regions
            .iter()
            .map(|r| (r.ctx.key.as_deref(), &raw[r.span.start..r.span.end]))
            .collect();
        assert_eq!(
            got,
            [(Some("a"), "x"), (Some("b"), "y"), (Some("arr"), "z")]
        );
    }

    #[test]
    fn utf8_bom_does_not_force_plaintext_fallback() {
        let raw = "\u{feff}{\"password\":\"hunter2\"}";
        let regions = parse_json_regions(raw).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].ctx.key.as_deref(), Some("password"));
    }

    #[test]
    fn escaped_keys_are_decoded_for_context() {
        let raw = r#"{"pass\u0077ord":"hunter2"}"#;
        let regions = parse_json_regions(raw).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].ctx.key.as_deref(), Some("password"));
        assert_eq!(&raw[regions[0].span.start..regions[0].span.end], "hunter2");
    }

    #[test]
    fn name_value_objects_feed_sibling_hints() {
        let raw = r#"{"headers":[{"name":"Authorization","value":"Bearer abc123"}]}"#;
        let regions = parse_json_regions(raw).unwrap();
        let value = regions
            .iter()
            .find(|r| &raw[r.span.start..r.span.end] == "Bearer abc123")
            .unwrap();
        assert_eq!(value.ctx.key.as_deref(), Some("value"));
        assert_eq!(value.ctx.hints, ["Authorization"]);
    }

    #[test]
    fn ndjson_extracts_string_values_with_line_offsets() {
        let raw = "{\"password\":\"hunter2\"}\r\n{\"token\":\"abc123\"}\n";
        let regions = parse_ndjson_regions(raw).unwrap();
        let got = regions
            .iter()
            .map(|r| (r.ctx.key.as_deref(), &raw[r.span.start..r.span.end]))
            .collect::<Vec<_>>();
        assert_eq!(
            got,
            [(Some("password"), "hunter2"), (Some("token"), "abc123")]
        );
    }

    #[test]
    fn analysis_regions_include_numeric_values_with_key_context() {
        let raw = r#"{"otp":100482,"name":"demo"}"#;
        let regions = parse_json_analysis_regions(raw).unwrap();
        let got = regions
            .iter()
            .map(|r| (r.ctx.key.as_deref(), &raw[r.span.start..r.span.end]))
            .collect::<Vec<_>>();
        assert_eq!(got, [(Some("otp"), "100482"), (Some("name"), "demo")]);
    }

    #[test]
    fn tool_result_extracts_keys_and_string_values() {
        let raw = r#"{"sk-ABCDEFGHIJKLMNOPQRSTUVWX":{"password":"hunter2"},"ok":1}"#;
        let regions = parse_tool_result_regions(raw).unwrap();
        let got: Vec<(RegionKind, Option<&str>, &str)> = regions
            .iter()
            .map(|r| {
                (
                    r.ctx.kind,
                    r.ctx.key.as_deref(),
                    &raw[r.span.start..r.span.end],
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (RegionKind::JsonKey, None, "sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
                (RegionKind::JsonKey, None, "password"),
                (RegionKind::JsonValue, Some("password"), "hunter2"),
                (RegionKind::JsonKey, None, "ok"),
            ]
        );
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_json_regions("{bad").is_none());
    }

    #[test]
    fn deep_nesting_returns_none_not_abort() {
        let deep = format!("{}true{}", "[".repeat(50_000), "]".repeat(50_000));
        assert!(parse_json_regions(&deep).is_none());
    }

    proptest::proptest! {
        // Arbitrary input must never panic, and any region must stay in bounds
        // on char boundaries.
        #[test]
        fn parse_never_panics_and_in_bounds(s in proptest::prelude::any::<String>()) {
            if let Some(regions) = parse_json_regions(&s) {
                for r in regions {
                    proptest::prop_assert!(r.span.end <= s.len());
                    proptest::prop_assert!(s.is_char_boundary(r.span.start));
                    proptest::prop_assert!(s.is_char_boundary(r.span.end));
                }
            }
        }
    }
}
