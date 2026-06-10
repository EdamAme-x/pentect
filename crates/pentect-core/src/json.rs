use crate::model::*;

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
    let mut p = Parser { b: raw.as_bytes(), i: 0, out: Vec::new() };
    p.skip_ws();
    p.value(None, 0)?;
    p.skip_ws();
    if p.i != p.b.len() {
        return None;
    }
    Some(p.out)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    out: Vec<Region>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn value(&mut self, key: Option<String>, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(key, depth + 1),
            b'"' => {
                let (range, _) = self.string()?;
                self.out.push(Region {
                    span: range,
                    ctx: Context {
                        path: None,
                        key,
                        kind: RegionKind::JsonValue,
                        format: Kind::Json,
                    },
                });
                Some(())
            }
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            _ => self.number(),
        }
    }

    fn object(&mut self, depth: usize) -> Option<()> {
        self.i += 1; // '{'
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Some(());
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return None;
            }
            let (_, key) = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return None;
            }
            self.i += 1;
            self.value(Some(key), depth)?;
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

    fn array(&mut self, key: Option<String>, depth: usize) -> Option<()> {
        self.i += 1; // '['
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Some(());
        }
        loop {
            // Array elements inherit the array's key as their context.
            self.value(key.clone(), depth)?;
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
        self.i += 1; // opening quote
        let start = self.i;
        while let Some(c) = self.peek() {
            match c {
                b'\\' => {
                    self.i += 1;
                    match self.peek()? {
                        b'u' => self.i += 5,
                        _ => self.i += 1,
                    }
                }
                b'"' => {
                    let end = self.i;
                    self.i += 1; // closing quote
                    let text = std::str::from_utf8(&self.b[start..end]).ok()?.to_string();
                    return Some((ByteRange::new(start, end), text));
                }
                _ => self.i += 1,
            }
        }
        None
    }

    fn literal(&mut self, lit: &[u8]) -> Option<()> {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            Some(())
        } else {
            None
        }
    }

    fn number(&mut self) -> Option<()> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            self.i += 1;
        }
        if self.i == start {
            None
        } else {
            Some(())
        }
    }
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
        assert_eq!(got, [(Some("a"), "x"), (Some("b"), "y"), (Some("arr"), "z")]);
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
}
