use crate::model::*;

/// HAR nests deeply (log.entries[].request.headers[]...), so the depth cap is far
/// above JSON's typical use and independent of the decode-depth cap. The node cap
/// bounds a pathological file; exceeding either fails safe (None -> plaintext).
const MAX_DEPTH: usize = 256;
const MAX_NODES: usize = 5_000_000;

/// Parse a HAR (which is JSON) into one region per string value, preserving valid
/// JSON/HAR on output. Header/cookie/query-string entries (`{ "name": N, "value":
/// V }`) tag V's region with key=N and the right kind, so key-anchored detection
/// fires on `Authorization`/`Cookie`/... even when the value isn't vendor-shaped.
/// Every other string value is still covered (immediate key), so nothing leaks.
/// Returns None when the input isn't walkable JSON, so the caller falls back.
pub fn parse_har_regions(raw: &str) -> Option<Vec<Region>> {
    let mut p = Har {
        b: raw.as_bytes(),
        i: 0,
        out: Vec::new(),
        nodes: 0,
    };
    p.skip_ws();
    p.value(None, RegionKind::JsonValue, 0)?;
    p.skip_ws();
    if p.i != p.b.len() {
        return None;
    }
    Some(p.out)
}

struct Har<'a> {
    b: &'a [u8],
    i: usize,
    out: Vec<Region>,
    nodes: usize,
}

impl Har<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn push(&mut self, span: ByteRange, key: Option<String>, kind: RegionKind) {
        self.out.push(Region {
            span,
            ctx: Context {
                path: None,
                key,
                kind,
                format: Kind::Har,
            },
        });
    }

    fn value(&mut self, key: Option<String>, kind: RegionKind, depth: usize) -> Option<()> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'{' => self.object(kind, depth + 1),
            b'[' => self.array(key, depth + 1),
            b'"' => {
                let range = self.string()?.0;
                self.push(range, key, RegionKind::JsonValue);
                Some(())
            }
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            _ => self.number(),
        }
    }

    /// `pair_kind` is the kind to give a HAR `{name, value}` entry's value when
    /// this object is an element of a headers/cookies/queryString array.
    fn object(&mut self, pair_kind: RegionKind, depth: usize) -> Option<()> {
        self.i += 1; // '{'
                     // Buffer string fields so the `value` field can borrow the sibling `name`
                     // regardless of field order; non-string fields recurse inline.
        let mut string_fields: Vec<(String, ByteRange)> = Vec::new();
        let mut name_text: Option<String> = None;
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
            let (_, fkey) = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return None;
            }
            self.i += 1;
            self.skip_ws();
            if self.peek() == Some(b'"') {
                let (range, text) = self.string()?;
                if fkey == "name" {
                    name_text = Some(text);
                }
                string_fields.push((fkey, range));
            } else {
                self.value(Some(fkey), RegionKind::JsonValue, depth)?;
            }
            self.skip_ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    break;
                }
                _ => return None,
            }
        }

        let is_pair = matches!(
            pair_kind,
            RegionKind::Header | RegionKind::Cookie | RegionKind::Url
        ) && name_text.is_some()
            && string_fields.iter().any(|(k, _)| k == "value");
        for (fkey, range) in string_fields {
            if is_pair && fkey == "value" {
                self.push(range, name_text.clone(), pair_kind);
            } else {
                self.push(range, Some(fkey), RegionKind::JsonValue);
            }
        }
        Some(())
    }

    fn array(&mut self, key: Option<String>, depth: usize) -> Option<()> {
        self.i += 1; // '['
        let elem_kind = match key.as_deref() {
            Some("headers") => RegionKind::Header,
            Some("cookies") => RegionKind::Cookie,
            Some("queryString") => RegionKind::Url,
            _ => RegionKind::JsonValue,
        };
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Some(());
        }
        loop {
            self.value(None, elem_kind, depth)?;
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

    /// Inner byte range and inner text; assumes the current byte is `"`. Escapes
    /// are scanned but not decoded (the inner text is the raw slice).
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
        (self.i != start).then_some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyed(raw: &str) -> Vec<(Option<String>, RegionKind, String)> {
        parse_har_regions(raw)
            .unwrap()
            .into_iter()
            .map(|r| {
                (
                    r.ctx.key,
                    r.ctx.kind,
                    raw[r.span.start..r.span.end].to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn header_cookie_query_values_keyed_by_name() {
        let raw = r#"{"log":{"entries":[{"request":{
            "headers":[{"name":"Authorization","value":"Bearer xyz"}],
            "cookies":[{"name":"sid","value":"abc123"}],
            "queryString":[{"name":"token","value":"qtok"}]
        }}]}}"#;
        let got = keyed(raw);
        assert!(got.contains(&(
            Some("Authorization".into()),
            RegionKind::Header,
            "Bearer xyz".into()
        )));
        assert!(got.contains(&(Some("sid".into()), RegionKind::Cookie, "abc123".into())));
        assert!(got.contains(&(Some("token".into()), RegionKind::Url, "qtok".into())));
    }

    #[test]
    fn non_har_string_values_still_covered() {
        // A plain string value gets its immediate key, so nothing is missed.
        let got = keyed(r#"{"note":"hello"}"#);
        assert_eq!(
            got,
            [(Some("note".into()), RegionKind::JsonValue, "hello".into())]
        );
    }

    #[test]
    fn output_is_only_values_so_har_stays_valid() {
        // Keys/structure are never regions, so masking values keeps valid JSON.
        let raw = r#"{"headers":[{"name":"X","value":"y"}]}"#;
        let regions = parse_har_regions(raw).unwrap();
        for r in &regions {
            let slice = &raw[r.span.start..r.span.end];
            assert!(!slice.contains('"'), "region spans a quote: {slice}");
        }
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_har_regions("{bad").is_none());
    }

    proptest::proptest! {
        #[test]
        fn never_panics_and_in_bounds(s in proptest::prelude::any::<String>()) {
            if let Some(regions) = parse_har_regions(&s) {
                for r in regions {
                    proptest::prop_assert!(r.span.end <= s.len());
                    proptest::prop_assert!(s.is_char_boundary(r.span.start));
                    proptest::prop_assert!(s.is_char_boundary(r.span.end));
                }
            }
        }
    }
}
