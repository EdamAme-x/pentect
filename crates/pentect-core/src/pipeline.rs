use crate::detect::DetectorSet;
use crate::json;
use crate::merge::merge;
use crate::model::*;
use crate::normalize::NormalizedView;
use crate::policy::{Action, Policy};
use crate::recovery::Recovery;
use crate::render::render;
use crate::sweep::identity_sweep;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// `key` is the HMAC key for identity hashing; the adapter generates and
/// persists it.
#[derive(Clone, Debug)]
pub struct Config {
    pub key: [u8; 32],
    pub locale: String,
}

impl Config {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, locale: "en".into() }
    }
    /// Fixed key for tests and demos only.
    pub fn insecure_testing() -> Self {
        Self::new([7u8; 32])
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    pub masked_count: usize,
}

/// Carries the local-only recovery map, so it is intentionally not serializable.
pub struct MaskResult {
    pub masked: String,
    pub recovery: Recovery,
    pub spans: Vec<Span>,
    pub summary: Summary,
}

pub fn mask(input: Input, config: &Config) -> MaskResult {
    let ir = parse(input);
    mask_ir(ir, config)
}

/// Core primitive: an adapter can build the same Ir and call this directly.
pub fn mask_ir(ir: Ir, config: &Config) -> MaskResult {
    let detectors = DetectorSet::builtin();
    let policy = Policy::default();

    let mut spans = Vec::new();
    for region in &ir.regions {
        let view = NormalizedView::build(region, &ir.raw);
        spans.extend(detectors.run(&view));
    }

    // Classify before merge so an allowlist can retract false candidates before
    // overlaps are resolved (slice 1 only emits Mask).
    spans.retain(|s| matches!(policy.classify(s), Action::Mask(_)));

    let merged = merge(spans, &ir.protected);
    let swept = identity_sweep(&ir.raw, merged, &ir.protected, &ir.regions);
    let rendered = render(&ir.raw, &config.key, swept.clone());

    let summary = Summary { masked_count: rendered.map.len() };
    MaskResult {
        masked: rendered.masked,
        recovery: Recovery { map: rendered.map },
        spans: swept,
        summary,
    }
}

fn parse(input: Input) -> Ir {
    let Input { kind, data: raw } = input;
    let protected = scan_placeholders(&raw);
    // JSON yields one region per string value (keys/structure stay unmasked);
    // anything else is a single plaintext region.
    let regions = match &kind {
        Kind::Json => json::parse_json_regions(&raw)
            .unwrap_or_else(|| vec![plaintext_region(raw.len(), Kind::Json)]),
        other => vec![plaintext_region(raw.len(), other.clone())],
    };
    Ir { raw, regions, protected }
}

fn plaintext_region(len: usize, format: Kind) -> Region {
    Region {
        span: ByteRange::new(0, len),
        ctx: Context {
            path: None,
            key: None,
            kind: RegionKind::PlainText,
            format,
        },
    }
}

/// Freeze existing `<<LABEL_hash>>` placeholders so re-masking is a no-op.
fn scan_placeholders(raw: &str) -> Vec<ByteRange> {
    let re = Regex::new(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}>>").expect("placeholder regex compiles");
    re.find_iter(raw)
        .map(|m| ByteRange::new(m.start(), m.end()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::restore;
    use proptest::prelude::*;

    fn m(s: &str) -> MaskResult {
        mask(Input { kind: Kind::Text, data: s.to_string() }, &Config::insecure_testing())
    }
    fn mj(s: &str) -> MaskResult {
        mask(Input { kind: Kind::Json, data: s.to_string() }, &Config::insecure_testing())
    }

    #[test]
    fn reversible_idempotent_deterministic() {
        for x in ["", "hi there", "key sk-ABCDEFGHIJKLMNOPQRSTUVWX end", "a@b.com x a@b.com"] {
            let r = m(x);
            assert_eq!(restore(&r.masked, &r.recovery).unwrap(), x);
            assert_eq!(m(&r.masked).masked, r.masked);
            assert_eq!(m(x).masked, r.masked);
        }
    }

    #[test]
    fn global_identity_no_survivor() {
        let r = m("a@b.com mid a@b.com");
        assert!(!r.masked.contains("a@b.com"), "{}", r.masked);
        assert_eq!(r.recovery.map.len(), 1);
    }

    #[test]
    fn distinct_values_distinct_placeholders() {
        let r = m("AKIAIOSFODNN7EXAMPLE AKIA0000000000000000");
        assert_eq!(r.recovery.map.len(), 2, "{}", r.masked);
    }

    #[test]
    fn masks_through_zero_width() {
        let r = m("key AKIA\u{200b}IOSFODNN7EXAMPLE end");
        assert!(r.masked.contains("<<AWS_AKID_"), "{}", r.masked);
        assert!(!r.masked.contains('\u{200b}'), "{}", r.masked);
    }

    #[test]
    fn json_structure_preserved() {
        let input = r#"{"user":"alice@example.com","db_password":"hunter2pass","note":"hello world"}"#;
        let r = mj(input);
        let v: serde_json::Value = serde_json::from_str(&r.masked).expect("masked output is valid JSON");
        let o = v.as_object().unwrap();
        assert!(o["db_password"].as_str().unwrap().starts_with("<<")); // suspicious key
        assert!(o["user"].as_str().unwrap().starts_with("<<")); // email rule
        assert_eq!(o["note"].as_str().unwrap(), "hello world"); // benign, untouched
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    proptest! {
        // Charset excludes `<` and `>` to avoid injecting placeholder syntax.
        #[test]
        fn prop_reversible(s in "[a-zA-Z0-9 @._:/-]{0,160}") {
            let r = m(&s);
            prop_assert_eq!(restore(&r.masked, &r.recovery).unwrap(), s);
        }

        #[test]
        fn prop_idempotent(s in "[a-zA-Z0-9 @._:/-]{0,160}") {
            let once = m(&s).masked;
            prop_assert_eq!(m(&once).masked, once);
        }
    }
}
