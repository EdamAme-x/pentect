use crate::detect::DetectorSet;
use crate::merge::merge;
use crate::model::*;
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
        spans.extend(detectors.run(region, &ir.raw));
    }

    // Classify before merge so an allowlist can retract false candidates before
    // overlaps are resolved (slice 1 only emits Mask).
    spans.retain(|s| matches!(policy.classify(s), Action::Mask(_)));

    let merged = merge(spans, &ir.protected);
    let swept = identity_sweep(&ir.raw, merged, &ir.protected);
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
    // slice 1: the whole input is a single plaintext region.
    let raw = input.data;
    let protected = scan_placeholders(&raw);
    let ctx = Context {
        path: None,
        key: None,
        kind: RegionKind::PlainText,
        format: input.kind,
    };
    let regions = vec![Region {
        span: ByteRange::new(0, raw.len()),
        ctx,
    }];
    Ir { raw, regions, protected }
}

/// Freeze existing `<<LABEL_hash>>` placeholders so re-masking is a no-op.
fn scan_placeholders(raw: &str) -> Vec<ByteRange> {
    let re = Regex::new(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}>>").expect("placeholder regex compiles");
    re.find_iter(raw)
        .map(|m| ByteRange::new(m.start(), m.end()))
        .collect()
}
