use crate::model::*;
use crate::normalize::n_id_cow;
use crate::placeholder::{render_placeholder, IdentityHasher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A piece of the rendered output: literal source text, or a masked placeholder
/// with its metadata. Walking these lets a UI colour-code without byte-offset
/// math, so emoji/CJK can't misalign a highlight. The segment texts concatenate
/// back to `masked` exactly (property-tested).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RenderSegment {
    Literal {
        text: String,
    },
    Masked {
        text: String,
        label: Label,
        category: Category,
        confidence: Confidence,
    },
}

impl RenderSegment {
    pub fn text(&self) -> &str {
        match self {
            RenderSegment::Literal { text } | RenderSegment::Masked { text, .. } => text,
        }
    }
}

pub struct Rendered {
    pub masked: String,
    /// Literal/masked pieces in order; `masked` is their concatenation.
    pub segments: Vec<RenderSegment>,
    /// placeholder -> first-seen original bytes.
    pub map: HashMap<String, String>,
    /// Placeholders that two distinct values hashed to (would mis-restore).
    pub collisions: Vec<String>,
}

// Render granularity is shape-driven: a value that parses as an email splits its
// local part and domain into separate hashes joined by a literal `@`, so
// same-domain addresses still aggregate (a model can tell two users share an org
// without seeing the addresses) — regardless of category. Other structured
// values, such as internal URLs, are split by detectors before rendering. We
// never keep value prefixes, so there is no separate "whole vs hash-only" mode.

/// Split an email into (local, domain), or None unless it is a single-`@` address
/// with a dotted, alphabetic-TLD domain — so a value that merely contains `@`
/// (e.g. a password `p@ssw0rd`) is not split.
fn split_email(v: &str) -> Option<(&str, &str)> {
    let at = v.find('@')?;
    let (local, domain) = (&v[..at], &v[at + 1..]);
    let tld = domain.rsplit('.').next().unwrap_or("");
    if local.is_empty()
        || domain.contains('@')
        || !domain.contains('.')
        || tld.len() < 2
        || !tld.bytes().all(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    Some((local, domain))
}

/// Replace each span with a placeholder. Same identity yields the same
/// placeholder, keeping the whole document consistent. Exact character length is
/// disclosed only when opted in.
pub fn render(raw: &str, key: &[u8; 32], mut spans: Vec<Span>, disclose_length: bool) -> Rendered {
    spans.sort_by_key(|s| s.range.start);
    let hasher = IdentityHasher::new(key);
    let mut segments: Vec<RenderSegment> =
        Vec::with_capacity(spans.len().saturating_mul(2).saturating_add(1));
    let mut masked = String::with_capacity(raw.len());
    let mut map: HashMap<String, String> = HashMap::new();
    let mut placeholder_cache: HashMap<(String, String, Option<u32>), String> = HashMap::new();
    let mut collisions = Vec::new();
    let mut cursor = 0usize;

    for s in &spans {
        // Spans are already non-overlapping; this is just defensive.
        if s.range.start < cursor {
            continue;
        }
        push_literal(&mut segments, &mut masked, &raw[cursor..s.range.start]);
        let val = &raw[s.range.start..s.range.end];

        match should_split_email(s).then(|| split_email(val)).flatten() {
            // Mask each side under the same label; the `@` stays literal so
            // restore reconstructs the address from the two mappings.
            Some((local, domain)) => {
                let local_len = disclose_length.then(|| local.chars().count() as u32);
                let domain_len = disclose_length.then(|| domain.chars().count() as u32);
                push_masked(
                    &mut segments,
                    &mut masked,
                    &hasher,
                    s,
                    local,
                    local_len,
                    &mut map,
                    &mut placeholder_cache,
                    &mut collisions,
                );
                push_literal(&mut segments, &mut masked, "@");
                push_masked(
                    &mut segments,
                    &mut masked,
                    &hasher,
                    s,
                    domain,
                    domain_len,
                    &mut map,
                    &mut placeholder_cache,
                    &mut collisions,
                );
            }
            None => {
                let len = if disclose_length {
                    Some(val.chars().count() as u32)
                } else {
                    None
                };
                push_masked(
                    &mut segments,
                    &mut masked,
                    &hasher,
                    s,
                    val,
                    len,
                    &mut map,
                    &mut placeholder_cache,
                    &mut collisions,
                );
            }
        }
        cursor = s.range.end;
    }
    push_literal(&mut segments, &mut masked, &raw[cursor..]);

    Rendered {
        masked,
        segments,
        map,
        collisions,
    }
}

fn should_split_email(span: &Span) -> bool {
    !(span.source == DetectorId::Plugin && span.label == "EMAIL")
}

fn push_literal(segments: &mut Vec<RenderSegment>, masked: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    masked.push_str(text);
    segments.push(RenderSegment::Literal { text: text.into() });
}

#[allow(clippy::too_many_arguments)]
fn push_masked(
    segments: &mut Vec<RenderSegment>,
    masked: &mut String,
    hasher: &IdentityHasher,
    span: &Span,
    val: &str,
    len: Option<u32>,
    map: &mut HashMap<String, String>,
    placeholder_cache: &mut HashMap<(String, String, Option<u32>), String>,
    collisions: &mut Vec<String>,
) {
    let segment = masked_seg(hasher, span, val, len, map, placeholder_cache, collisions);
    masked.push_str(segment.text());
    segments.push(segment);
}

/// Build a masked segment for `val`, recording its mapping and noting a collision
/// if a different value already claimed the placeholder.
fn masked_seg(
    hasher: &IdentityHasher,
    span: &Span,
    val: &str,
    len: Option<u32>,
    map: &mut HashMap<String, String>,
    placeholder_cache: &mut HashMap<(String, String, Option<u32>), String>,
    collisions: &mut Vec<String>,
) -> RenderSegment {
    let cache_key = (span.label.clone(), val.to_string(), len);
    let ph = match placeholder_cache.get(&cache_key) {
        Some(ph) => ph.clone(),
        None => {
            let hash = hasher.hash(&n_id_cow(val));
            let ph = render_placeholder(&span.label, &hash, len);
            if record(map, &ph, val) {
                collisions.push(ph.clone());
            }
            placeholder_cache.insert(cache_key, ph.clone());
            ph
        }
    };
    RenderSegment::Masked {
        text: ph,
        label: span.label.clone(),
        category: span.category,
        confidence: span.confidence,
    }
}

/// Insert a placeholder->value mapping. Returns true on collision: the
/// placeholder already maps to a *different* value (same value is the expected
/// identity case). On collision the first mapping is kept and restore would
/// mis-expand the second, so the caller surfaces it rather than failing silently.
fn record(map: &mut HashMap<String, String>, ph: &str, val: &str) -> bool {
    match map.get(ph) {
        Some(existing) => existing != val,
        None => {
            map.insert(ph.to_string(), val.to_string());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_flags_collision_only_on_different_value() {
        let mut map = HashMap::new();
        assert!(!record(&mut map, "<<X_aa>>", "alice")); // first
        assert!(!record(&mut map, "<<X_aa>>", "alice")); // same value, identity
        assert!(record(&mut map, "<<X_aa>>", "bob")); // collision
        assert_eq!(map["<<X_aa>>"], "alice"); // first mapping kept
    }

    fn email_span(start: usize, end: usize) -> Span {
        Span {
            range: ByteRange::new(start, end),
            category: Category::Pii,
            label: "IDENTITY".into(),
            confidence: Confidence::Medium,
            source: DetectorId::Rule,
        }
    }

    #[test]
    fn same_value_twice_is_no_collision() {
        let key = [9u8; 32];
        let raw = "a@b.com x a@b.com";
        let spans = vec![email_span(0, 7), email_span(10, 17)];
        let r = render(raw, &key, spans, false);
        // Email splits into local + domain, so two distinct mappings; the
        // repeat is the identity case, not a collision.
        assert_eq!(r.map.len(), 2);
        assert!(r.collisions.is_empty());
    }

    #[test]
    fn email_split_masks_local_and_domain_separately() {
        let key = [1u8; 32];
        let raw = "alice@example.com";
        let r = render(raw, &key, vec![email_span(0, raw.len())], false);
        // Two placeholders joined by a literal '@'.
        assert_eq!(r.masked.matches("<<IDENTITY_").count(), 2, "{}", r.masked);
        assert!(r.masked.contains(">>@<<"), "{}", r.masked);
        assert_eq!(
            crate::recovery::restore(&r.masked, &crate::recovery::Recovery::seal(r.map, &key))
                .unwrap(),
            raw
        );
    }

    #[test]
    fn same_domain_aggregates_across_addresses() {
        let key = [2u8; 32];
        let raw = "alice@corp.com bob@corp.com";
        let spans = vec![email_span(0, 14), email_span(15, 27)];
        let r = render(raw, &key, spans, false);
        // Distinct local placeholders, one shared domain placeholder.
        let domain_phs: std::collections::HashSet<_> = r
            .masked
            .split('@')
            .skip(1)
            .map(|s| s.split(">>").next().unwrap())
            .collect();
        assert_eq!(
            domain_phs.len(),
            1,
            "same domain must share a placeholder: {}",
            r.masked
        );
    }

    #[test]
    fn non_email_values_are_not_split() {
        let key = [3u8; 32];
        // No '@', and '@' without a dotted domain (a password) — neither splits.
        for raw in ["4111111111111111", "p@ssw0rd"] {
            let span = Span {
                range: ByteRange::new(0, raw.len()),
                category: Category::Secret,
                label: "SECRET".into(),
                confidence: Confidence::High,
                source: DetectorId::Rule,
            };
            let r = render(raw, &key, vec![span], false);
            assert_eq!(r.masked.matches("<<").count(), 1, "{}", r.masked);
        }
    }

    #[test]
    fn segments_concatenate_to_masked() {
        let key = [5u8; 32];
        let raw = "to alice@example.com now";
        let r = render(raw, &key, vec![email_span(3, 20)], false);
        let joined: String = r.segments.iter().map(RenderSegment::text).collect();
        assert_eq!(joined, r.masked);
    }

    #[test]
    fn email_renders_as_literal_masked_literal_masked_literal() {
        let key = [6u8; 32];
        let raw = "to alice@example.com now";
        let r = render(raw, &key, vec![email_span(3, 20)], false);
        let kinds: Vec<&str> = r
            .segments
            .iter()
            .map(|s| match s {
                RenderSegment::Literal { .. } => "lit",
                RenderSegment::Masked { .. } => "mask",
            })
            .collect();
        assert_eq!(
            kinds,
            ["lit", "mask", "lit", "mask", "lit"],
            "{:?}",
            r.segments
        );
    }
}
