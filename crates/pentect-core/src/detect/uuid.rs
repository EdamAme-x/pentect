use super::Detector;
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, RegionKind, Span};
use crate::normalize::NormalizedView;

/// Detects UUID/GUID identifiers only when nearby structure says the value is an
/// identifier slot. Bare UUID-shaped values are intentionally left alone.
pub struct UuidDetector;

impl Detector for UuidDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 36 <= text.len() {
            let end = pos + 36;
            if !text.is_char_boundary(pos) || !text.is_char_boundary(end) {
                pos += 1;
                continue;
            }
            if is_uuid_layout(&text[pos..end])
                && has_uuid_boundary(text.as_bytes(), pos, end)
                && !is_placeholder_uuid(&text[pos..end])
                && is_uuid_anchored(text, pos, &view.region.ctx)
            {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(pos, end)),
                    category: Category::Secret,
                    label: labels::UUID.to_string(),
                    confidence: Confidence::Medium,
                    source: DetectorId::Uuid,
                });
                pos = end;
            } else {
                pos += 1;
            }
        }
        out
    }
}

fn is_uuid_layout(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
}

fn has_uuid_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|idx| bytes.get(idx))
        .is_some_and(|b| b.is_ascii_hexdigit() || *b == b'-');
    let after = bytes
        .get(end)
        .is_some_and(|b| b.is_ascii_hexdigit() || *b == b'-');
    !before && !after
}

fn is_placeholder_uuid(value: &str) -> bool {
    // Nil, near-nil, and obviously patterned UUIDs are conventional sentinels
    // in fixtures and generated cloud docs, not issued credential-adjacent
    // identifiers.
    let mut counts = [0usize; 16];
    let mut total = 0usize;
    for b in value.bytes().filter(|b| *b != b'-') {
        let normalized = b.to_ascii_lowercase();
        let idx = match normalized {
            b'0'..=b'9' => (normalized - b'0') as usize,
            b'a'..=b'f' => (normalized - b'a' + 10) as usize,
            _ => return false,
        };
        counts[idx] += 1;
        total += 1;
    }
    let unique = counts.iter().filter(|count| **count > 0).count();
    let dominant = counts.iter().copied().max().unwrap_or(0);
    unique == 1 || (total == 32 && dominant >= 30) || is_patterned_placeholder_uuid(value)
}

fn is_patterned_placeholder_uuid(value: &str) -> bool {
    let groups = value
        .split('-')
        .filter(|group| !group.is_empty())
        .collect::<Vec<_>>();
    if groups.len() != 5 {
        return false;
    }
    let compact = groups.join("").to_ascii_lowercase();
    let repeated_group_chars = groups
        .iter()
        .filter(|group| group.len() >= 4 && group.bytes().all(|b| b == group.as_bytes()[0]))
        .map(|group| group.len())
        .sum::<usize>();
    let repeated_group_count = groups
        .iter()
        .filter(|group| group.len() >= 4 && group.bytes().all(|b| b == group.as_bytes()[0]))
        .count();
    let (sequence_total, sequence_longest) = monotonic_hex_sequence_score(&compact);
    sequence_total >= 24
        || (sequence_total >= 16 && sequence_longest >= 6)
        || (repeated_group_count >= 3 && repeated_group_chars + sequence_total >= 24)
}

fn monotonic_hex_sequence_score(value: &str) -> (usize, usize) {
    const ASC: &[u8] = b"0123456789abcdef";
    const DESC: &[u8] = b"fedcba9876543210";
    let asc = monotonic_hex_sequence_score_for(value.as_bytes(), ASC);
    let desc = monotonic_hex_sequence_score_for(value.as_bytes(), DESC);
    (asc.0 + desc.0, asc.1.max(desc.1))
}

fn monotonic_hex_sequence_score_for(value: &[u8], order: &[u8]) -> (usize, usize) {
    let mut total = 0usize;
    let mut longest = 0usize;
    let mut i = 0usize;
    while i < value.len() {
        let mut best = 0usize;
        for start in 0..order.len() {
            let mut len = 0usize;
            while i + len < value.len()
                && start + len < order.len()
                && value[i + len] == order[start + len]
            {
                len += 1;
            }
            best = best.max(len);
        }
        if best >= 3 {
            total += best;
            longest = longest.max(best);
            i += best;
        } else {
            i += 1;
        }
    }
    (total, longest)
}

fn is_uuid_anchored(text: &str, start: usize, ctx: &crate::model::Context) -> bool {
    if ctx
        .key
        .as_deref()
        .is_some_and(|key| has_uuid_anchor_name(key) || is_uuid_example_slot_name(key))
        || ctx.hints.iter().any(|hint| has_uuid_anchor_name(hint))
    {
        return true;
    }
    if matches!(ctx.kind, RegionKind::Cookie | RegionKind::Header)
        && ctx.key.as_deref().is_some_and(has_identifier_slot_name)
    {
        return true;
    }
    local_anchor_before_uuid(text, start)
        || local_example_slot_before_uuid(text, start)
        || local_uuid_collection_context(text, start)
        || local_uuid_argument_list_context(text, start)
        || local_sql_insert_uuid_context(text, start)
        || local_uri_query_uuid_context(text, start)
        || local_yaml_identifier_list_context(text, start)
}

fn local_anchor_before_uuid(text: &str, start: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let mut window_start = start.saturating_sub(96).max(line_start);
    while window_start < start && !text.is_char_boundary(window_start) {
        window_start += 1;
    }
    let prefix = text[window_start..start].trim_end();
    if prefix.is_empty() {
        return false;
    }
    let has_assignment = prefix
        .chars()
        .next_back()
        .is_some_and(|ch| matches!(ch, '=' | ':' | '/' | '\\' | '"' | '\'' | '{' | '('))
        || prefix.rfind(['=', ':', '/', '\\']).is_some();
    has_assignment
        && (immediate_slot_name_before_value(prefix).is_some_and(has_uuid_anchor_name)
            || has_uuid_anchor_name(prefix)
            || arn_resource_anchor_before_uuid(prefix)
            || path_collection_anchor_before_uuid(prefix))
}

fn arn_resource_anchor_before_uuid(prefix: &str) -> bool {
    // AWS ARNs encode resource identifiers after a resource type separator,
    // e.g. `arn:aws:kms:...:key/<uuid>` or `...:task/<uuid>`. The UUID is a
    // structured resource handle even when the surrounding JSON key is `KeyId`.
    let prefix = prefix.trim_end_matches(|ch: char| {
        ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | '(' | '[' | '{')
    });
    if !(prefix.ends_with('/') || prefix.ends_with(':')) {
        return false;
    }
    let Some(arn_start) = prefix.rfind("arn:") else {
        return false;
    };
    let arn_tail = &prefix[arn_start..prefix.len() - 1];
    let segment_start = arn_tail.rfind(['/', ':']).map_or(0, |pos| pos + 1);
    let segment = &arn_tail[segment_start..];
    (2..=48).contains(&segment.len())
        && segment.bytes().any(|b| b.is_ascii_alphabetic())
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn path_collection_anchor_before_uuid(prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches(|ch: char| {
        ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | '(' | '[' | '{')
    });
    if !(prefix.ends_with('/') || prefix.ends_with('\\')) {
        return false;
    }
    let without_slash = &prefix[..prefix.len() - 1];
    let segment_start = without_slash
        .rfind(['/', '\\', '?', '&', '#'])
        .map_or(0, |pos| pos + 1);
    let segment = without_slash[segment_start..].trim_matches(|ch: char| {
        ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | ':' | '=')
    });
    let normalized = normalize_identifier(segment);
    let parts = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts
        .last()
        .is_some_and(|part| part.len() >= 3 && part.ends_with('s') && *part != "https")
}

fn local_example_slot_before_uuid(text: &str, start: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let mut window_start = start.saturating_sub(96).max(line_start);
    while window_start < start && !text.is_char_boundary(window_start) {
        window_start += 1;
    }
    let prefix = text[window_start..start].trim_end();
    let Some(slot) = immediate_slot_name_before_value(prefix) else {
        return false;
    };
    is_uuid_example_slot_name(slot)
}

fn local_uuid_collection_context(text: &str, start: usize) -> bool {
    let (line_start, line_end) = line_bounds(text, start);
    if !line_is_uuid_item(&text[line_start..line_end]) {
        return false;
    }
    let (window_start, window_end) = nearby_line_window(text, line_start, line_end, 10);
    let window = &text[window_start..window_end];
    let uuid_item_lines = window
        .lines()
        .filter(|line| line_is_uuid_item(line))
        .take(3)
        .count();
    uuid_item_lines >= 3 && window.lines().any(collection_boundary_line)
}

fn line_bounds(text: &str, pos: usize) -> (usize, usize) {
    let line_start = text[..pos].rfind('\n').map_or(0, |idx| idx + 1);
    let line_end = text[pos..].find('\n').map_or(text.len(), |idx| pos + idx);
    (line_start, line_end)
}

fn local_uuid_argument_list_context(text: &str, start: usize) -> bool {
    let (line_start, line_end) = line_bounds(text, start);
    let line = &text[line_start..line_end];
    if !(line.contains(',') && (line.contains('(') || line.contains('['))) {
        return false;
    }
    let mut count = 0usize;
    let mut pos = 0usize;
    while pos + 36 <= line.len() {
        let end = pos + 36;
        if line.is_char_boundary(pos)
            && line.is_char_boundary(end)
            && is_uuid_layout(&line[pos..end])
            && has_uuid_boundary(line.as_bytes(), pos, end)
            && !is_placeholder_uuid(&line[pos..end])
        {
            count += 1;
            if count >= 2 {
                return true;
            }
            pos = end;
        } else {
            pos += 1;
        }
    }
    false
}

fn local_sql_insert_uuid_context(text: &str, start: usize) -> bool {
    let (line_start, line_end) = line_bounds(text, start);
    let line = &text[line_start..line_end];
    let lower = line.to_ascii_lowercase();
    let Some(insert_pos) = lower.find("insert into") else {
        return false;
    };
    let Some(values_pos) = lower.find("values") else {
        return false;
    };
    let uuid_pos = start - line_start;
    if uuid_pos <= values_pos {
        return false;
    }
    let Some(columns_open) = lower[insert_pos..values_pos]
        .find('(')
        .map(|pos| insert_pos + pos)
    else {
        return false;
    };
    let Some(columns_close) = lower[columns_open + 1..values_pos]
        .rfind(')')
        .map(|pos| columns_open + 1 + pos)
    else {
        return false;
    };
    let Some(values_open) = lower[values_pos..uuid_pos]
        .find('(')
        .map(|pos| values_pos + pos)
    else {
        return false;
    };
    let value_index = lower[values_open + 1..uuid_pos]
        .bytes()
        .filter(|b| *b == b',')
        .count();
    let columns = lower[columns_open + 1..columns_close]
        .split(',')
        .map(|column| column.trim().trim_matches(['"', '\'', '`', '[', ']']))
        .collect::<Vec<_>>();
    columns
        .get(value_index)
        .is_some_and(|column| is_uuid_sql_column_name(column))
}

fn is_uuid_sql_column_name(column: &str) -> bool {
    let name = normalize_identifier(column);
    (name.len() <= 48 && name.ends_with("id")) || name == "uuid" || name.ends_with("_uuid")
}

fn nearby_line_window(
    text: &str,
    mut line_start: usize,
    mut line_end: usize,
    max_lines_each_side: usize,
) -> (usize, usize) {
    for _ in 0..max_lines_each_side {
        if line_start == 0 {
            break;
        }
        line_start = text[..line_start - 1].rfind('\n').map_or(0, |idx| idx + 1);
    }
    for _ in 0..max_lines_each_side {
        if line_end >= text.len() {
            break;
        }
        line_end = text[line_end + 1..]
            .find('\n')
            .map_or(text.len(), |idx| line_end + 1 + idx);
    }
    (line_start, line_end)
}

fn line_is_uuid_item(line: &str) -> bool {
    let line = line.trim();
    let quote = match line.as_bytes().first() {
        Some(b'"') => '"',
        Some(b'\'') => '\'',
        _ => return false,
    };
    let Some(value_start) = line.char_indices().nth(1).map(|(idx, _)| idx) else {
        return false;
    };
    let value_end = value_start + 36;
    if value_end > line.len() || !line.is_char_boundary(value_end) {
        return false;
    }
    if !is_uuid_layout(&line[value_start..value_end]) {
        return false;
    }
    let rest = line[value_end..].trim_start();
    let Some(rest) = rest.strip_prefix(quote) else {
        return false;
    };
    let rest = rest.trim_start();
    rest.is_empty() || rest == ","
}

fn collection_boundary_line(line: &str) -> bool {
    let line = line.trim();
    line.ends_with('[') || line == "]" || line == "],"
}

fn immediate_slot_name_before_value(prefix: &str) -> Option<&str> {
    let prefix = prefix.trim_end();
    let sep = prefix.rfind(['=', ':'])?;
    let before_sep = prefix[..sep].trim_end();
    if before_sep.is_empty() || before_sep.ends_with("://") {
        return None;
    }
    let before_sep = before_sep.trim_end_matches(['"', '\'', '`']);
    let start = before_sep
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .map_or(0, |pos| pos + 1);
    let candidate = before_sep[start..].trim_matches(['"', '\'', '`']);
    let head = before_sep[..start].trim_end();
    if head
        .chars()
        .next_back()
        .is_some_and(|ch| !matches!(ch, '{' | '[' | '(' | ',' | '"' | '\'' | '`'))
    {
        return source_declared_identifier_before_value(before_sep);
    }
    (!candidate.is_empty()).then_some(candidate)
}

fn source_declared_identifier_before_value(before_sep: &str) -> Option<&str> {
    // Source declarations often include visibility/type words before the actual
    // slot name (`public static final String resource = "..."`). The UUID
    // belongs to the final identifier, not to the whole declaration prefix.
    let before_sep = before_sep.trim_end().trim_end_matches(['"', '\'', '`']);
    let start = before_sep
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .map_or(0, |pos| pos + 1);
    let candidate = before_sep[start..].trim_matches(['"', '\'', '`']);
    let head = before_sep[..start].trim_end();
    if candidate.is_empty() || head.is_empty() || !source_declaration_prefix(head) {
        return None;
    }
    Some(candidate)
}

fn source_declaration_prefix(head: &str) -> bool {
    let normalized = normalize_identifier(head);
    normalized.split('_').any(|part| {
        matches!(
            part,
            "const"
                | "final"
                | "let"
                | "var"
                | "val"
                | "static"
                | "readonly"
                | "public"
                | "private"
                | "protected"
                | "string"
                | "str"
        )
    })
}

fn local_uri_query_uuid_context(text: &str, start: usize) -> bool {
    let (line_start, line_end) = line_bounds(text, start);
    let line = &text[line_start..line_end];
    let uuid_pos = start - line_start;
    let prefix = &line[..uuid_pos];
    let Some(eq_pos) = prefix.rfind('=') else {
        return false;
    };
    let name_start = prefix[..eq_pos]
        .rfind(['?', '&', ';'])
        .map_or(0, |pos| pos + 1);
    let name = prefix[name_start..eq_pos].trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return false;
    }
    has_uuid_anchor_name(name)
}

fn local_yaml_identifier_list_context(text: &str, start: usize) -> bool {
    let (line_start, line_end) = line_bounds(text, start);
    let line = &text[line_start..line_end];
    if !line_is_uuid_list_item(line) {
        return false;
    }
    let item_indent = line.bytes().take_while(|b| b.is_ascii_whitespace()).count();
    let mut cursor = line_start;
    for _ in 0..8 {
        if cursor == 0 {
            return false;
        }
        let prev_end = cursor - 1;
        let prev_start = text[..prev_end].rfind('\n').map_or(0, |idx| idx + 1);
        let prev = &text[prev_start..prev_end];
        cursor = prev_start;
        let trimmed = prev.trim();
        if trimmed.is_empty() {
            continue;
        }
        let prev_indent = prev.bytes().take_while(|b| b.is_ascii_whitespace()).count();
        if prev_indent >= item_indent {
            continue;
        }
        let Some(key) = trimmed.strip_suffix(':') else {
            return false;
        };
        let key = key.trim_matches(['"', '\'']);
        return has_uuid_anchor_name(key);
    }
    false
}

fn line_is_uuid_list_item(line: &str) -> bool {
    let line = line.trim();
    let Some(rest) = line.strip_prefix('-') else {
        return false;
    };
    let rest = rest.trim_start();
    let value = rest.trim_end_matches(',').trim_matches(['"', '\'']);
    value.len() == 36 && is_uuid_layout(value) && !is_placeholder_uuid(value)
}

fn has_uuid_anchor_name(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    if normalized.is_empty() {
        return false;
    }
    if is_public_key_identifier_slot(&normalized) {
        return false;
    }
    let compact = normalized.replace('_', "");
    matches!(
        compact.as_str(),
        "uuid"
            | "guid"
            | "uid"
            | "jti"
            | "sid"
            | "id"
            | "clientid"
            | "tenantid"
            | "resource"
            | "resourceid"
            | "externalid"
            | "sessionid"
            | "username"
            | "virtualhost"
            | "folder"
            | "request"
            | "requestid"
            | "raceid"
            | "volumehandle"
            | "kid"
            | "state"
            | "code"
            | "order"
            | "lineage"
            | "token"
            | "authtoken"
            | "refreshtoken"
            | "accesstoken"
            | "devicecode"
            | "accesspolicyid"
            | "migrationguid"
    ) || compact.contains("uuid")
        || compact.contains("guid")
        // A UUID may be the value of a larger same-line slot such as
        // `name="client_id" value="..."` or `authorization_uri=.../<uuid>`.
        // Require established identifier/URI slot phrases rather than masking
        // arbitrary UUID-looking prose.
        || has_identifier_phrase(&normalized, &["client", "id"])
        || has_identifier_phrase(&normalized, &["tenant", "id"])
        || has_identifier_phrase(&normalized, &["resource", "id"])
        || has_identifier_phrase(&normalized, &["correlation", "id"])
        || has_identifier_phrase(&normalized, &["external", "id"])
        || has_identifier_phrase(&normalized, &["session", "id"])
        || has_identifier_phrase(&normalized, &["user", "id"])
        || has_identifier_phrase(&normalized, &["actor", "id"])
        || has_identifier_phrase(&normalized, &["device", "code"])
        || has_identifier_phrase(&normalized, &["auth", "token"])
        || has_identifier_phrase(&normalized, &["refresh", "token"])
        || has_identifier_phrase(&normalized, &["access", "token"])
        || has_identifier_phrase(&normalized, &["access", "policy", "id"])
        || has_identifier_phrase(&normalized, &["authorization", "uri"])
        || has_identifier_phrase(&normalized, &["authorization", "url"])
        || has_identifier_phrase(&normalized, &["metadata", "address"])
        || has_identifier_phrase(&normalized, &["metadata", "url"])
        || has_identifier_phrase(&normalized, &["u", "i", "d"])
        || has_identifier_phrase(&normalized, &["j", "t", "i"])
        || normalized
            .split('_')
            .any(|part| matches!(part, "uuid" | "guid" | "uid" | "jti" | "sid" | "resource"))
        || has_identifier_slot_name(value)
}

fn is_uuid_example_slot_name(value: &str) -> bool {
    // Schema/OpenAPI examples commonly carry concrete sample identifiers under
    // `example`/`examples`. Keep this out of `has_uuid_anchor_name`, because
    // free-form documentation can contain the prose phrase "for example".
    let normalized = normalize_identifier(value);
    matches!(normalized.as_str(), "example" | "examples")
        || normalized.ends_with("_example")
        || normalized.ends_with("_examples")
}

fn is_public_key_identifier_slot(normalized: &str) -> bool {
    // `key_id`/`KeyId` identifies a public key or managed-key resource. The
    // associated UUID is lookup metadata, while the secret is the key material
    // or token signed by that key. Keep JWT `kid` and client/tenant IDs on the
    // positive path; this only covers the explicit key-id phrase.
    normalized == "key_id"
        || normalized.ends_with("_key_id")
        || normalized.ends_with("_key_ids")
        || normalized.contains("_key_id_")
}

fn has_identifier_phrase(name: &str, phrase: &[&str]) -> bool {
    let parts = name
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    phrase.len() <= parts.len() && parts.windows(phrase.len()).any(|window| window == phrase)
}

fn has_identifier_slot_name(value: &str) -> bool {
    let raw = value.trim().trim_matches(|ch: char| {
        ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | ':' | '=')
    });
    if raw
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .next()
        .is_some_and(|slot| {
            let upper = slot.to_ascii_uppercase();
            upper.ends_with("_ID") || upper.ends_with("_IDS")
        })
    {
        return true;
    }
    let normalized = normalize_identifier(value);
    normalized == "id"
        || normalized.ends_with("_id")
        || normalized.ends_with("_ids")
        || normalized.ends_with("_sid")
        || normalized.ends_with("_guid")
        || normalized.ends_with("_uuid")
}

fn normalize_identifier(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_sep = false;
    let chars = value.chars().collect::<Vec<_>>();
    for (idx, ch) in chars.iter().copied().enumerate() {
        if ch.is_ascii_alphanumeric() {
            let prev = idx.checked_sub(1).and_then(|i| chars.get(i)).copied();
            let next = chars.get(idx + 1).copied();
            let starts_word = ch.is_ascii_uppercase()
                && !out.is_empty()
                && !prev_sep
                && (prev.is_some_and(|prev| prev.is_ascii_lowercase() || prev.is_ascii_digit())
                    || (prev.is_some_and(|prev| prev.is_ascii_uppercase())
                        && next.is_some_and(|next| next.is_ascii_lowercase())));
            if starts_word {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn hits(raw: &str) -> Vec<String> {
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        UuidDetector
            .detect(&view)
            .into_iter()
            .map(|span| raw[span.range.start..span.range.end].to_string())
            .collect()
    }

    #[test]
    fn masks_anchored_uuid_slots() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        for raw in [
            format!(r#"clientId = "{uuid}";"#),
            format!(r#""tenant_id": "{uuid}""#),
            format!(r#"external_id: {uuid}"#),
            format!(r#"kid: '{uuid}'"#),
            format!(r#"uid: "{uuid}""#),
            format!(r#"claimUID: "{uuid}""#),
            format!(r#"jti: "{uuid}""#),
            format!(r#"sid: "{uuid}""#),
            format!(r#""example": "{uuid}""#),
            format!(r#""schema_examples": ["{uuid}"]"#),
            format!(r#"folder: "{uuid}""#),
            format!(r#"request: "{uuid}""#),
            format!(r#"VolumeHandle: "{uuid}""#),
            format!(r#"RACE_ID = "{uuid}""#),
            format!(r#"code={uuid}&grant_type=authorization_code"#),
            format!(r#"state = "{uuid}""#),
            format!(r#"resource = "{uuid}""#),
            format!(r#"SERVICE_ACCOUNT_ID={uuid}"#),
            format!(r#"username: {uuid}"#),
            format!(r#"// User ID: {uuid}"#),
            format!(r#"// Actor ID: uaa-user:{uuid}"#),
            format!(r#"virtualHost: {uuid}"#),
            format!(r#"domainID: "{uuid}""#),
            format!(r#"DEVICE_CODE = "{uuid}""#),
            format!(r#"TEST_DEVICE_CODE = "{uuid}""#),
            format!(r#"SetAuthToken("{uuid}")."#),
            format!(
                r#"authorization_uri=https://login.example/authorize?resource={uuid}&response_type=code"#
            ),
            format!(r#"redirect_uri=https://example.test/cb&client_id={uuid}"#),
            format!(r#"mux.HandleFunc("/zones/{uuid}/records", handler)"#),
            format!(r#"authorization_uri=https://login.example/{uuid}"#),
            format!(r#"KeyArn = "arn:aws:kms:us-east-2:111122223333:key/{uuid}""#),
            format!(r#"task = "arn:aws:ecs:us-west-1:123456789123:task/{uuid}""#),
            format!(r#"<input type=\"hidden\" name=\"client_id\" value=\"{uuid}\" />"#),
            format!(r#"INSERT INTO users (name, user_id, role) VALUES ('a', {uuid}, 'admin');"#),
            format!(r#"public static final String DefaultResource = "{uuid}";"#),
            format!(
                r#"Assert.assertEquals("https://login.example/authorize?resource={uuid}&response_type=code")"#
            ),
            format!(r#"INSERT INTO cycling.cyclist_mv (cid,name) VALUES ({uuid},'Alex');"#),
            format!("headers:\n  X-Request-Id:\n    - {uuid}\n"),
            format!("headers:\n  X-Correlation-Id:\n    - \"{uuid}\",\n"),
        ] {
            assert_eq!(hits(&raw), vec![uuid.to_string()], "{raw}");
        }
        let uuid2 = "650e8400-e29b-41d4-a716-446655440001";
        assert_eq!(
            hits(&format!(r#"call("{uuid}", "{uuid2}", other)"#)),
            vec![uuid.to_string(), uuid2.to_string()]
        );
        let collection = r#"{
  "order": [
    "550e8400-e29b-41d4-a716-446655440000",
    "650e8400-e29b-41d4-a716-446655440001",
    "750e8400-e29b-41d4-a716-446655440002"
  ]
}"#;
        assert_eq!(
            hits(collection),
            vec![
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                "650e8400-e29b-41d4-a716-446655440001".to_string(),
                "750e8400-e29b-41d4-a716-446655440002".to_string(),
            ]
        );
        let random_collection = r#"{
  "order": [
    "a3c06711-df97-c6ce-ddc7-e7bc4fa3909b",
    "fb6ee58b-8fe0-6dcd-91ff-664b7ad9c6e7",
    "a4245388-8054-a8fe-36fc-4c5425003af2"
  ]
}"#;
        assert_eq!(
            hits(random_collection),
            vec![
                "a3c06711-df97-c6ce-ddc7-e7bc4fa3909b".to_string(),
                "fb6ee58b-8fe0-6dcd-91ff-664b7ad9c6e7".to_string(),
                "a4245388-8054-a8fe-36fc-4c5425003af2".to_string(),
            ]
        );
    }

    #[test]
    fn leaves_bare_uuid_unmasked() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert!(hits(&format!("see {uuid} later")).is_empty());
        assert!(hits(&format!(r#"link "/share/{uuid}""#)).is_empty());
        assert!(hits(&format!(r#"For example: {uuid}"#)).is_empty());
        assert!(hits(&format!(r#""object": "clsid:{uuid}""#)).is_empty());
        assert!(hits(&format!(r#"Get-NdrComProxy -Clsid "{uuid}""#)).is_empty());
        assert!(hits(&format!(r#"KeyId = "{uuid}""#)).is_empty());
        assert!(hits(&format!(r#"TargetKeyId = "{uuid}""#)).is_empty());
        assert!(hits(&format!("values:\n  - {uuid}\n")).is_empty());
        assert!(hits(&format!("headers:\n  Etag:\n    - {uuid}\n")).is_empty());
        assert!(hits(&format!("[\"{uuid}\"]")).is_empty());
        assert!(hits(&format!(
            "[\n  \"{uuid}\",\n  \"650e8400-e29b-41d4-a716-446655440001\"\n]"
        ))
        .is_empty());
    }

    #[test]
    fn leaves_nil_and_sentinel_uuids_unmasked() {
        for uuid in [
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "00000000-0000-0000-0000-000000000001",
            "10000000-0000-0000-0000-000000000000",
            "1234abcd-12ab-34cd-56ef-1234567890ab",
            "12345678-1234-1234-1234-123456789012",
            "87654321-4321-4321-4321-210987654321",
            "abcd1234-abcd-1234-abcd-1234abcd1234",
            "abcdef66-7777-8888-9999-000000fedcba",
        ] {
            assert!(hits(&format!("client_id = {uuid}")).is_empty(), "{uuid}");
        }
        for uuid in [
            "a3c06711-df97-c6ce-ddc7-e7bc4fa3909b",
            "fb6ee58b-8fe0-6dcd-91ff-664b7ad9c6e7",
            "abcd12f2-46da-4fdb-b8d5-fbd4c466928f",
        ] {
            assert_eq!(hits(&format!("client_id = {uuid}")), vec![uuid], "{uuid}");
        }
    }
}
