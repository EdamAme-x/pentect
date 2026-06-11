use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

/// Header names that carry credentials *by protocol definition* — a closed,
/// RFC-defined, ASCII set, not an open-vocabulary guess. Compared lowercased.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Masks values that are sensitive by their *structural position* in a known
/// format, not by guessing an arbitrary key name: a cookie value (carries session
/// state) or a credential-bearing HTTP header. Bounded and protocol-grounded.
/// Open-vocabulary, multilingual key sensitivity (`password`=`パスワード`=…) is a
/// model's job (ML sidecar), not core's — core does not enumerate key names.
pub struct StructuralDetector;

impl Detector for StructuralDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty() || is_benign_value(view.text()) {
            return vec![];
        }
        let fire = match region.ctx.kind {
            RegionKind::Cookie => true,
            RegionKind::Header => region
                .ctx
                .key
                .as_deref()
                .is_some_and(|k| SENSITIVE_HEADERS.contains(&k.to_ascii_lowercase().as_str())),
            _ => false,
        };
        if !fire {
            return vec![];
        }
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label: labels::SECRET.to_string(),
            // Medium so a specific vendor rule keeps its label where it overlaps,
            // while structural still beats raw entropy.
            confidence: Confidence::Medium,
            source: DetectorId::Structural,
        }]
    }
}

/// Values that are never secrets even in a sensitive position: empty, JSON
/// literals, or an already-rendered placeholder (idempotency).
fn is_benign_value(v: &str) -> bool {
    let t = v.trim();
    t.is_empty()
        || matches!(t, "true" | "false" | "null")
        || (t.starts_with("<<") && t.ends_with(">>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(kind: RegionKind, key: Option<&str>, value: &str) -> bool {
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: key.map(str::to_string),
                kind,
                format: Kind::Har,
            },
        };
        !StructuralDetector
            .detect(&NormalizedView::build(&region, &raw))
            .is_empty()
    }

    #[test]
    fn cookie_values_fire_by_structure() {
        assert!(fires(RegionKind::Cookie, Some("anyname"), "sessabc123"));
        assert!(fires(RegionKind::Cookie, None, "x"));
    }

    #[test]
    fn sensitive_headers_fire_benign_headers_do_not() {
        assert!(fires(RegionKind::Header, Some("Authorization"), "Bearer x"));
        assert!(fires(RegionKind::Header, Some("cookie"), "a=b"));
        assert!(!fires(
            RegionKind::Header,
            Some("Content-Type"),
            "application/json"
        ));
        assert!(!fires(RegionKind::Header, Some("Accept"), "*/*"));
    }

    #[test]
    fn arbitrary_keys_are_not_guessed() {
        // The whole point: open-vocabulary key names are NOT enumerated here.
        assert!(!fires(RegionKind::JsonValue, Some("password"), "hunter2"));
        assert!(!fires(RegionKind::Body, Some("db_password"), "hunter2"));
    }

    #[test]
    fn benign_values_skipped() {
        assert!(!fires(RegionKind::Cookie, None, ""));
        assert!(!fires(
            RegionKind::Cookie,
            None,
            "<<SECRET_0123456789abcdef>>"
        ));
    }
}
