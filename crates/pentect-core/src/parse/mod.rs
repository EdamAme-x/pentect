use crate::model::*;

mod json;

/// Turns raw input into value regions. Injected per `Kind`; the engine falls
/// back to whole-input plaintext when no parser matches or one returns None.
pub trait Parser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>>;
}

pub struct TextParser;

impl Parser for TextParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        Some(vec![Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: None,
                hints: Vec::new(),
                kind: RegionKind::PlainText,
                format: Kind::Text,
            },
        }])
    }
}

pub struct JsonParser;

impl Parser for JsonParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        json::parse_json_regions(raw)
    }
}

pub struct NdjsonParser;

impl Parser for NdjsonParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        json::parse_ndjson_regions(raw)
    }
}

pub struct ToolResultParser;

impl Parser for ToolResultParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        json::parse_tool_result_regions(raw)
    }
}

/// Parses `.env` / KEY=VALUE lines into one region per value, tagged with its
/// key, so key-anchored detection works on the highest-yield leak format. Keys,
/// `=`, quotes, comments, and newlines stay outside regions and are preserved.
pub struct EnvParser;

impl Parser for EnvParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        let mut regions = Vec::new();
        let mut pos = 0;
        while pos < raw.len() {
            let line_end = raw[pos..].find('\n').map_or(raw.len(), |i| pos + i);
            if let Some((key, span)) = parse_env_line(raw, pos, line_end) {
                regions.push(Region {
                    span,
                    ctx: Context {
                        path: None,
                        key: Some(key),
                        hints: Vec::new(),
                        kind: RegionKind::Body,
                        format: Kind::Env,
                    },
                });
            }
            pos = line_end + 1;
        }
        Some(regions)
    }
}

/// Returns (key, value byte range) for a `KEY=VALUE` line, or None for blank,
/// comment, or keyless lines.
fn parse_env_line(raw: &str, start: usize, end: usize) -> Option<(String, ByteRange)> {
    let line = raw[start..end].trim_end_matches('\r');
    let bom = if start == 0 && line.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };
    let after_bom = &line[bom..];
    let lead = after_bom.len() - after_bom.trim_start().len();
    let body = &after_bom[lead..];
    if body.is_empty() || body.starts_with('#') {
        return None;
    }
    // Optional `export ` prefix.
    let body_off = bom
        + lead
        + body
            .strip_prefix("export ")
            .map_or(0, |rest| body.len() - rest.len());
    let after_export = &line[body_off..];

    let eq = after_export.find('=')?;
    let key = after_export[..eq].trim();
    if key.is_empty() || !key.chars().all(is_key_char) {
        return None;
    }

    // Value starts after '=' and any spaces/tabs.
    let val_rel = body_off + eq + 1;
    let val_part = &line[val_rel..];
    let skip = val_part.len() - val_part.trim_start_matches([' ', '\t']).len();
    let vstart = val_rel + skip;
    let value = &line[vstart..];

    let (inner_start, inner_end) = match value.chars().next() {
        Some('"') => {
            let after = &value[1..];
            let close = closing_double_quote(after).unwrap_or(after.len());
            (vstart + 1, vstart + 1 + close)
        }
        Some('\'') => {
            let after = &value[1..];
            let close = after.find('\'').map_or(after.len(), |i| i);
            (vstart + 1, vstart + 1 + close)
        }
        _ => (vstart, vstart + value.trim_end().len()),
    };
    if inner_end <= inner_start {
        return None;
    }
    Some((
        key.to_string(),
        ByteRange::new(start + inner_start, start + inner_end),
    ))
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

fn closing_double_quote(value: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(index),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(raw: &str) -> Vec<(Option<String>, String)> {
        EnvParser
            .parse(raw)
            .unwrap()
            .into_iter()
            .map(|r| (r.ctx.key, raw[r.span.start..r.span.end].to_string()))
            .collect()
    }

    #[test]
    fn extracts_values_with_keys() {
        let raw =
            "# comment\nexport API_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=\"hunter2\"\nEMPTY=\n";
        assert_eq!(
            parsed(raw),
            [
                (Some("API_KEY".into()), "AKIAIOSFODNN7EXAMPLE".into()),
                (Some("DB_PASSWORD".into()), "hunter2".into()),
            ]
        );
    }

    #[test]
    fn quotes_and_comments_stay_outside_regions() {
        let raw = "TOKEN='abc'\n";
        let r = EnvParser.parse(raw).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(&raw[r[0].span.start..r[0].span.end], "abc"); // no quotes
    }

    #[test]
    fn utf8_bom_does_not_hide_first_env_key() {
        let raw = "\u{feff}AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        assert_eq!(
            parsed(raw),
            [(
                Some("AWS_ACCESS_KEY_ID".into()),
                "AKIAIOSFODNN7EXAMPLE".into()
            )]
        );
    }

    #[test]
    fn double_quoted_values_skip_escaped_quotes() {
        let raw = "DB_PASSWORD=\"abc\\\"def\"\n";
        assert_eq!(
            parsed(raw),
            [(Some("DB_PASSWORD".into()), "abc\\\"def".into())]
        );
    }
}
