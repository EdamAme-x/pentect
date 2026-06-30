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
    // Nil and near-nil UUIDs are conventional sentinels in fixtures and tests,
    // not issued credential-adjacent identifiers.
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
    unique == 1 || (total == 32 && dominant >= 30)
}

fn is_uuid_anchored(text: &str, start: usize, ctx: &crate::model::Context) -> bool {
    if ctx.key.as_deref().is_some_and(has_uuid_anchor_name)
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
    has_assignment && has_uuid_anchor_name(prefix)
}

fn has_uuid_anchor_name(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    if normalized.is_empty() {
        return false;
    }
    let compact = normalized.replace('_', "");
    matches!(
        compact.as_str(),
        "uuid"
            | "guid"
            | "clsid"
            | "id"
            | "clientid"
            | "tenantid"
            | "resourceid"
            | "externalid"
            | "sessionid"
            | "accesspolicyid"
            | "migrationguid"
    ) || compact.contains("uuid")
        || compact.contains("guid")
        || compact.contains("clsid")
        || normalized
            .split('_')
            .any(|part| matches!(part, "uuid" | "guid" | "clsid"))
        || has_identifier_slot_name(&normalized)
}

fn has_identifier_slot_name(value: &str) -> bool {
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
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && !out.is_empty() && !prev_sep {
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
            format!(r#"#define MYPC_CLSID "::{{{uuid}}}""#),
        ] {
            assert_eq!(hits(&raw), vec![uuid.to_string()], "{raw}");
        }
    }

    #[test]
    fn leaves_bare_uuid_unmasked() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert!(hits(&format!("see {uuid} later")).is_empty());
    }

    #[test]
    fn leaves_nil_and_sentinel_uuids_unmasked() {
        for uuid in [
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "00000000-0000-0000-0000-000000000001",
            "10000000-0000-0000-0000-000000000000",
        ] {
            assert!(hits(&format!("client_id = {uuid}")).is_empty(), "{uuid}");
        }
    }
}
