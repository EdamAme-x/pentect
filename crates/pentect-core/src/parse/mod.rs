use crate::model::*;

mod json;

/// Turns raw input into value regions. Injected per `Kind`; the engine falls
/// back to whole-input plaintext when no parser matches or one returns None.
pub trait Parser: Send + Sync {
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
        let mut regions = json::parse_json_regions(raw)?;
        mark_json_secret_schema(raw, &mut regions);
        Some(regions)
    }
}

fn mark_json_secret_schema(raw: &str, regions: &mut [Region]) {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(raw) else {
        return;
    };
    let mut secret_keys = std::collections::HashSet::new();
    if document
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("secret"))
    {
        for container in ["data", "stringData"] {
            if let Some(values) = document
                .get(container)
                .and_then(serde_json::Value::as_object)
            {
                secret_keys.extend(values.keys().cloned());
            }
        }
    }
    collect_terraform_sensitive_keys(&document, &mut secret_keys);
    if secret_keys.is_empty() {
        return;
    }
    for region in regions {
        if region
            .ctx
            .key
            .as_ref()
            .is_some_and(|key| secret_keys.contains(key))
        {
            region.ctx.hints.push("pentect:secret-value".to_string());
        }
    }
}

fn collect_terraform_sensitive_keys(
    value: &serde_json::Value,
    out: &mut std::collections::HashSet<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(sensitive) = map.get("sensitive_values") {
                collect_true_leaf_keys(sensitive, out);
            }
            for child in map.values() {
                collect_terraform_sensitive_keys(child, out);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_terraform_sensitive_keys(child, out);
            }
        }
        _ => {}
    }
}

fn collect_true_leaf_keys(value: &serde_json::Value, out: &mut std::collections::HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if child == &serde_json::Value::Bool(true) {
                    out.insert(key.clone());
                } else {
                    collect_true_leaf_keys(child, out);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_true_leaf_keys(child, out);
            }
        }
        _ => {}
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

pub(crate) fn analysis_regions_for_kind(raw: &str, kind: &Kind) -> Option<Vec<Region>> {
    match kind {
        Kind::Json | Kind::Har => json::parse_json_analysis_regions(raw),
        Kind::Ndjson => json::parse_ndjson_analysis_regions(raw),
        Kind::ToolResult => json::parse_tool_result_analysis_regions(raw),
        _ => None,
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
            if let Some((key, span, next)) = parse_env_multiline(raw, pos, line_end) {
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
                pos = next;
                continue;
            }
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

fn parse_env_multiline(
    raw: &str,
    start: usize,
    line_end: usize,
) -> Option<(String, ByteRange, usize)> {
    let header = raw[start..line_end].trim().trim_start_matches('\u{feff}');
    let (key, delimiter) = header.split_once("<<")?;
    let key = key.trim();
    let delimiter = delimiter.trim();
    if key.is_empty()
        || delimiter.is_empty()
        || delimiter.chars().any(char::is_whitespace)
        || !key.chars().all(is_key_char)
    {
        return None;
    }
    let value_start = line_end.checked_add(1)?;
    let mut pos = value_start;
    while pos <= raw.len() {
        let end = raw[pos..].find('\n').map_or(raw.len(), |i| pos + i);
        if raw[pos..end].trim_end_matches('\r') == delimiter {
            let mut value_end = pos;
            if raw[..value_end].ends_with("\r\n") {
                value_end -= 2;
            } else if raw[..value_end].ends_with('\n') {
                value_end -= 1;
            }
            if value_end <= value_start {
                return None;
            }
            return Some((
                key.to_string(),
                ByteRange::new(value_start, value_end),
                end.saturating_add(1),
            ));
        }
        if end == raw.len() {
            break;
        }
        pos = end + 1;
    }
    None
}

/// Parses line-oriented structured configuration without declaring every value
/// sensitive. Detectors decide which values to mask from their key/path. The
/// one exception is a Kubernetes `kind: Secret` document, where values directly
/// below `data` and `stringData` are secret by schema.
pub struct StructuredParser {
    schema: StructuredSchema,
}

#[derive(Clone, Copy)]
enum StructuredSchema {
    Generic,
    Aws,
    Kubeconfig,
    Npm,
    Pypi,
}

impl StructuredParser {
    pub fn generic() -> Self {
        Self {
            schema: StructuredSchema::Generic,
        }
    }

    pub fn aws() -> Self {
        Self {
            schema: StructuredSchema::Aws,
        }
    }

    pub fn kubeconfig() -> Self {
        Self {
            schema: StructuredSchema::Kubeconfig,
        }
    }

    pub fn npm() -> Self {
        Self {
            schema: StructuredSchema::Npm,
        }
    }

    pub fn pypi() -> Self {
        Self {
            schema: StructuredSchema::Pypi,
        }
    }

    fn is_schema_secret_key(&self, key: &str) -> bool {
        match self.schema {
            StructuredSchema::Generic => false,
            StructuredSchema::Aws => matches!(
                key.to_ascii_lowercase().as_str(),
                "aws_access_key_id" | "aws_secret_access_key" | "aws_session_token"
            ),
            StructuredSchema::Kubeconfig => matches!(
                key.to_ascii_lowercase().as_str(),
                "token" | "password" | "client-key-data"
            ),
            StructuredSchema::Npm => matches!(key, "AUTH_TOKEN" | "PASSWORD" | "AUTH"),
            StructuredSchema::Pypi => key.eq_ignore_ascii_case("password"),
        }
    }

    fn format(&self) -> Kind {
        let name = match self.schema {
            StructuredSchema::Generic => "structured",
            StructuredSchema::Aws => "structured:aws",
            StructuredSchema::Kubeconfig => "structured:kubeconfig",
            StructuredSchema::Npm => "structured:npm",
            StructuredSchema::Pypi => "structured:pypi",
        };
        Kind::Other(name.to_string())
    }
}

impl Parser for StructuredParser {
    fn parse(&self, raw: &str) -> Option<Vec<Region>> {
        let kubernetes_secret = raw.lines().any(|line| {
            let line = line.trim();
            line.strip_prefix("kind:")
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("secret"))
        });
        let mut regions = Vec::new();
        let mut yaml_stack: Vec<(usize, String)> = Vec::new();
        let mut ini_section: Option<String> = None;
        let mut pos = 0usize;

        while pos < raw.len() {
            let line_end = raw[pos..].find('\n').map_or(raw.len(), |i| pos + i);
            let line = raw[pos..line_end].trim_end_matches('\r');
            let trimmed = line.trim();
            if trimmed.is_empty() {
                pos = line_end.saturating_add(1);
                continue;
            }
            if trimmed.starts_with(['#', ';']) {
                push_plain_structured_line(&mut regions, pos, line, self.format());
                pos = line_end.saturating_add(1);
                continue;
            }
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                ini_section = Some(trimmed[1..trimmed.len() - 1].trim().to_string());
                yaml_stack.clear();
                pos = line_end.saturating_add(1);
                continue;
            }

            let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
            let body_offset = indent + usize::from(line[indent..].starts_with("- ")) * 2;
            let body = &line[body_offset..];
            let Some((separator, separator_len)) = structured_separator(body) else {
                push_plain_structured_line(&mut regions, pos, line, self.format());
                pos = line_end.saturating_add(1);
                continue;
            };
            let raw_key = body[..separator].trim().trim_matches(['"', '\'']);
            if raw_key.is_empty() {
                push_plain_structured_line(&mut regions, pos, line, self.format());
                pos = line_end.saturating_add(1);
                continue;
            }
            let key = semantic_structured_key(raw_key);
            let value_offset = body_offset + separator + separator_len;
            let value_part = &line[value_offset..];
            let leading = value_part.len() - value_part.trim_start_matches([' ', '\t']).len();
            let value = &value_part[leading..];

            while yaml_stack.last().is_some_and(|(level, _)| *level >= indent) {
                yaml_stack.pop();
            }
            let mut path = yaml_stack
                .iter()
                .map(|(_, key)| key.as_str())
                .collect::<Vec<_>>();
            if let Some(section) = ini_section.as_deref() {
                path.insert(0, section);
            }
            path.push(&key);
            let path_string = path.join(".");

            if value.is_empty() {
                yaml_stack.push((indent, key));
                pos = line_end.saturating_add(1);
                continue;
            }

            let parent_is_kubernetes_secret_data = kubernetes_secret
                && yaml_stack
                    .last()
                    .is_some_and(|(_, parent)| matches!(parent.as_str(), "data" | "stringData"));
            let mut hints = Vec::new();
            if parent_is_kubernetes_secret_data {
                hints.push("pentect:secret-value".to_string());
            }
            if self.is_schema_secret_key(&key) {
                hints.push("pentect:secret-value".to_string());
            }

            let scalar_start = pos + value_offset + leading;
            let scalar_span = if is_yaml_block_indicator(value) {
                let Some(span) = yaml_block_span(raw, line_end.saturating_add(1), indent) else {
                    pos = line_end.saturating_add(1);
                    continue;
                };
                span
            } else {
                structured_scalar_span(raw, scalar_start, scalar_start + value.len())
            };
            if !scalar_span.is_empty() {
                regions.push(Region {
                    span: scalar_span,
                    ctx: Context {
                        path: Some(path_string),
                        key: Some(key),
                        hints,
                        kind: RegionKind::JsonValue,
                        format: self.format(),
                    },
                });
            }
            pos = line_end.saturating_add(1);
        }
        Some(regions)
    }
}

fn push_plain_structured_line(regions: &mut Vec<Region>, start: usize, line: &str, format: Kind) {
    if line.is_empty() {
        return;
    }
    regions.push(Region {
        span: ByteRange::new(start, start + line.len()),
        ctx: Context {
            path: None,
            key: None,
            hints: Vec::new(),
            kind: RegionKind::PlainText,
            format,
        },
    });
}

pub(crate) fn looks_like_dotenv_document(raw: &str) -> bool {
    let mut assignments = 0usize;
    let mut meaningful = 0usize;
    let mut pos = 0usize;
    while pos < raw.len() {
        let line_end = raw[pos..].find('\n').map_or(raw.len(), |i| pos + i);
        let trimmed = raw[pos..line_end].trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            meaningful += 1;
            if let Some((key, _)) = parse_env_line(raw, pos, line_end) {
                let mut chars = key.chars();
                let strict_env_key = chars
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase() || ch == '_')
                    && chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_');
                if strict_env_key {
                    assignments += 1;
                }
            }
        }
        pos = line_end.saturating_add(1);
    }
    assignments >= 2 && assignments == meaningful
}

fn structured_separator(value: &str) -> Option<(usize, usize)> {
    let equals = value.find('=').map(|index| (index, 1));
    let colon = value.char_indices().find_map(|(index, ch)| {
        (ch == ':'
            && value[index + 1..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace))
        .then_some((index, 1))
    });
    match (equals, colon) {
        (Some(a), Some(b)) => Some(if a.0 < b.0 { a } else { b }),
        (Some(found), None) | (None, Some(found)) => Some(found),
        (None, None) => None,
    }
}

fn semantic_structured_key(key: &str) -> String {
    if key.starts_with("//") {
        if let Some((_, auth_key)) = key.rsplit_once(':') {
            return match auth_key.trim_start_matches('_') {
                "authToken" => "AUTH_TOKEN".to_string(),
                "password" => "PASSWORD".to_string(),
                "auth" => "AUTH".to_string(),
                other => other.to_string(),
            };
        }
    }
    key.to_string()
}

fn structured_scalar_span(raw: &str, start: usize, end: usize) -> ByteRange {
    let value = &raw[start..end];
    let (mut inner_start, mut inner_end) = (start, end);
    if let Some(quote @ ('"' | '\'')) = value.chars().next() {
        inner_start += quote.len_utf8();
        let after = &value[quote.len_utf8()..];
        let closing = if quote == '"' {
            closing_double_quote(after)
        } else {
            after.find('\'')
        };
        inner_end = closing.map_or(end, |index| inner_start + index);
    } else if let Some(comment) = value.char_indices().find_map(|(index, ch)| {
        (ch == '#'
            && index > 0
            && value[..index]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace))
        .then_some(index)
    }) {
        inner_end = start + value[..comment].trim_end().len();
    }
    ByteRange::new(inner_start, inner_end)
}

fn is_yaml_block_indicator(value: &str) -> bool {
    matches!(value.trim(), "|" | "|-" | "|+" | ">" | ">-" | ">+")
}

fn yaml_block_span(raw: &str, mut pos: usize, parent_indent: usize) -> Option<ByteRange> {
    let start = pos;
    let mut end = pos;
    while pos < raw.len() {
        let line_end = raw[pos..].find('\n').map_or(raw.len(), |i| pos + i);
        let line = raw[pos..line_end].trim_end_matches('\r');
        if !line.trim().is_empty() {
            let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
            if indent <= parent_indent {
                break;
            }
            end = line_end;
        }
        pos = line_end.saturating_add(1);
    }
    (end > start).then_some(ByteRange::new(start, end))
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
    let mut body_off = bom + lead;
    let mut body = &line[body_off..];
    if body.is_empty() || body.starts_with('#') {
        return None;
    }

    // Tolerate common dotenv/shell spellings without making arbitrary prose an
    // assignment: `export KEY=...`, `set KEY=...`, and `$env:KEY=...`.
    if let Some(rest) =
        strip_env_command_prefix(body, "export").or_else(|| strip_env_command_prefix(body, "set"))
    {
        body_off += body.len() - rest.len();
        body = rest;
    }
    if let Some(rest) = body.strip_prefix("$env:") {
        body_off += body.len() - rest.len();
        body = rest;
    }

    let (separator, separator_len) = env_separator(body)?;
    let key = body[..separator].trim();
    if key.is_empty() || !key.chars().all(is_key_char) {
        return None;
    }

    // Value starts after the separator and any spaces/tabs.
    let val_rel = body_off + separator + separator_len;
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
        _ => {
            let comment = inline_env_comment_start(value).unwrap_or(value.len());
            (vstart, vstart + value[..comment].trim_end().len())
        }
    };
    if inner_end <= inner_start {
        return None;
    }
    Some((
        key.to_string(),
        ByteRange::new(start + inner_start, start + inner_end),
    ))
}

fn strip_env_command_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = value.strip_prefix(prefix)?;
    let trimmed = rest.trim_start_matches([' ', '\t']);
    (trimmed.len() < rest.len()).then_some(trimmed)
}

fn env_separator(value: &str) -> Option<(usize, usize)> {
    if let Some(eq) = value.find('=') {
        return Some((eq, 1));
    }
    value.char_indices().find_map(|(index, ch)| {
        if ch != ':' {
            return None;
        }
        value[index + ch.len_utf8()..]
            .chars()
            .next()
            .is_some_and(|next| next == ' ' || next == '\t')
            .then_some((index, ch.len_utf8()))
    })
}

fn inline_env_comment_start(value: &str) -> Option<usize> {
    value.char_indices().find_map(|(index, ch)| {
        (ch == '#'
            && (index == 0
                || value[..index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace)))
        .then_some(index)
    })
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
    fn tolerates_spacing_prefixes_inline_comments_and_colons() {
        let raw = concat!(
            "  export\tAPI_KEY = abc=def # keep this comment\r\n",
            "set LOWER.name='quoted # value' # trailing\n",
            "$env:PS_TOKEN = xyz#part\n",
            "ODD_KEY: colon value # trailing\n",
        );
        assert_eq!(
            parsed(raw),
            [
                (Some("API_KEY".into()), "abc=def".into()),
                (Some("LOWER.name".into()), "quoted # value".into()),
                (Some("PS_TOKEN".into()), "xyz#part".into()),
                (Some("ODD_KEY".into()), "colon value".into()),
            ]
        );
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

    #[test]
    fn github_environment_multiline_value_is_one_region() {
        let raw = "JSON_RESPONSE<<EOF\n{\"token\":\"abc\"}\nsecond line\nEOF\nMODE=dev\n";
        assert_eq!(
            parsed(raw),
            [
                (
                    Some("JSON_RESPONSE".into()),
                    "{\"token\":\"abc\"}\nsecond line".into()
                ),
                (Some("MODE".into()), "dev".into()),
            ]
        );
    }

    #[test]
    fn dotenv_content_sniff_is_strict_and_order_independent() {
        assert!(looks_like_dotenv_document("API_KEY=abc\nMODE=dev\n"));
        assert!(looks_like_dotenv_document(
            "# comment\nMODE=dev\nAPI_KEY=abc\n"
        ));
        assert!(!looks_like_dotenv_document("example=value\n"));
        assert!(!looks_like_dotenv_document(
            "API_KEY=abc\nthis is ordinary prose\n"
        ));
        assert!(!looks_like_dotenv_document("lower=value\nOTHER=value\n"));
    }

    #[test]
    fn structured_parser_preserves_keys_paths_quotes_and_comments() {
        let raw = concat!(
            "[pypi]\n",
            "repository = https://upload.pypi.org/legacy/\n",
            "password = \"pypi-token\" # keep\n",
            "//registry.npmjs.org/:_authToken=npm-token\n",
        );
        let regions = StructuredParser::generic().parse(raw).unwrap();
        let values = regions
            .iter()
            .map(|region| {
                (
                    region.ctx.path.clone().unwrap(),
                    region.ctx.key.clone().unwrap(),
                    raw[region.span.start..region.span.end].to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            [
                (
                    "pypi.repository".into(),
                    "repository".into(),
                    "https://upload.pypi.org/legacy/".into()
                ),
                (
                    "pypi.password".into(),
                    "password".into(),
                    "pypi-token".into()
                ),
                (
                    "pypi.AUTH_TOKEN".into(),
                    "AUTH_TOKEN".into(),
                    "npm-token".into()
                ),
            ]
        );
    }

    #[test]
    fn kubernetes_secret_data_is_schema_marked() {
        let raw = concat!(
            "apiVersion: v1\n",
            "kind: Secret\n",
            "metadata:\n  name: app\n",
            "stringData:\n  DB_PASSWORD: plain\n",
            "data:\n  API_TOKEN: YWJj\n",
        );
        let regions = StructuredParser::generic().parse(raw).unwrap();
        let marked = regions
            .iter()
            .filter(|region| {
                region
                    .ctx
                    .hints
                    .iter()
                    .any(|hint| hint == "pentect:secret-value")
            })
            .map(|region| region.ctx.key.as_deref().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(marked, ["DB_PASSWORD", "API_TOKEN"]);
    }

    #[test]
    fn yaml_block_scalar_is_kept_as_one_value() {
        let raw = "client-key-data: |\n  line-one\n  line-two\nnext: public\n";
        let regions = StructuredParser::generic().parse(raw).unwrap();
        assert_eq!(
            &raw[regions[0].span.start..regions[0].span.end],
            "  line-one\n  line-two"
        );
    }

    #[test]
    fn structured_comments_and_unknown_lines_still_reach_normal_detectors() {
        let raw = "# api_token: abcdefghijklmnopqrstuvwxyz\nunknown directive value\n";
        let regions = StructuredParser::generic().parse(raw).unwrap();
        assert_eq!(regions.len(), 2);
        assert!(regions
            .iter()
            .all(|region| region.ctx.kind == RegionKind::PlainText));
        assert_eq!(
            &raw[regions[0].span.start..regions[0].span.end],
            "# api_token: abcdefghijklmnopqrstuvwxyz"
        );
    }

    proptest::proptest! {
        #[test]
        fn structured_parse_never_panics_and_spans_are_valid(raw in proptest::prelude::any::<String>()) {
            for region in StructuredParser::generic().parse(&raw).unwrap_or_default() {
                proptest::prop_assert!(region.span.start <= region.span.end);
                proptest::prop_assert!(region.span.end <= raw.len());
                proptest::prop_assert!(raw.is_char_boundary(region.span.start));
                proptest::prop_assert!(raw.is_char_boundary(region.span.end));
            }
        }
    }
}
