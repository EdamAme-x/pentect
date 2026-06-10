use crate::detect::{DecodeDetector, Detector, EntropyDetector, RuleDetector, SuspiciousKeyDetector};
use crate::guard::{OverMaskGuard, ShapeGuard};
use crate::merge::merge;
use crate::model::*;
use crate::normalize::NormalizedView;
use crate::parse::{JsonParser, Parser, TextParser};
use crate::policy::{is_context_free, Action, MaskAll, Policy, Profile, ProfilePolicy};
use crate::recovery::Recovery;
use crate::render::render;
use crate::sweep::identity_sweep;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Per-call parameters (not behaviour). `key` is the HMAC key for identity
/// hashing; the adapter generates and persists it.
#[derive(Clone, Debug)]
pub struct Config {
    pub key: [u8; 32],
    pub locale: String,
    /// Opt-in coarse length disclosure for opaque blobs (off by default).
    pub disclose_length: bool,
}

impl Config {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, locale: "en".into(), disclose_length: false }
    }
    /// Fixed key for tests and demos only.
    pub fn insecure_testing() -> Self {
        Self::new([7u8; 32])
    }
}

/// A span surfaced to the user without masking (value-free).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResidualNote {
    pub range: ByteRange,
    pub category: Category,
    pub source: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    pub masked_count: usize,
    /// Opaque candidates that were warned about rather than masked (no value).
    #[serde(default)]
    pub residual: Vec<ResidualNote>,
    /// Placeholders that two distinct values collided on (restore would be wrong
    /// for the second). Practically never with a 64-bit keyed hash, but surfaced
    /// instead of silently corrupting reversibility.
    #[serde(default)]
    pub collisions: Vec<String>,
}

/// Carries the local-only recovery map, so it is intentionally not serializable.
pub struct MaskResult {
    pub masked: String,
    pub recovery: Recovery,
    pub spans: Vec<Span>,
    pub summary: Summary,
}

/// Composition root. Holds the injected roles (parsers, detectors, policy); the
/// merge -> sweep -> render core is fixed because it carries the invariants.
pub struct Engine {
    parsers: Vec<(Kind, Box<dyn Parser>)>,
    fallback: Box<dyn Parser>,
    detectors: Vec<Box<dyn Detector>>,
    policy: Box<dyn Policy>,
    /// Spares benign shapes from context-free over-masking (see ShapeGuard).
    guard: Option<Box<dyn OverMaskGuard>>,
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::new()
    }

    /// Standard stack tuned for a profile. Power users can still build a fully
    /// custom Engine via `builder()`.
    pub fn with_profile(profile: Profile) -> Self {
        let k = profile.knobs();
        Engine::builder()
            .parser(Kind::Json, Box::new(JsonParser))
            .detector(Box::new(RuleDetector::builtin()))
            .detector(Box::new(EntropyDetector::with(k.entropy_min_len, k.entropy_threshold)))
            .detector(Box::new(
                DecodeDetector::builtin().with_opaque(k.mask_unknown_codec, k.min_opaque_run),
            ))
            .detector(Box::new(SuspiciousKeyDetector))
            .policy(Box::new(ProfilePolicy::new(profile)))
            .guard(Box::new(ShapeGuard::builtin()))
            .build()
    }

    pub fn mask(&self, input: Input, config: &Config) -> MaskResult {
        let ir = self.parse(input);
        self.mask_ir(ir, config)
    }

    /// An adapter can build the same `Ir` and call this directly.
    pub fn mask_ir(&self, ir: Ir, config: &Config) -> MaskResult {
        let mut spans = Vec::new();
        for region in &ir.regions {
            let view = NormalizedView::build(region, &ir.raw);
            for d in &self.detectors {
                spans.extend(d.detect(&view));
            }
        }

        // Classify per span. The guard may retract a context-free candidate
        // (benign shape), but never an anchored one, so an anchored Mask
        // overlapping a benign-shaped value is never suppressed before merge.
        let mut to_mask = Vec::new();
        let mut residual = Vec::new();
        for s in spans {
            let ctx_free = is_context_free(&s);
            if ctx_free {
                if let Some(g) = &self.guard {
                    if g.benign(&ir.raw[s.range.start..s.range.end]) {
                        continue;
                    }
                }
            }
            match self.policy.classify(&s) {
                Action::Mask(_) => to_mask.push(s),
                Action::Warn => residual.push(ResidualNote {
                    range: s.range,
                    category: s.category,
                    source: s.source,
                }),
                Action::Keep | Action::Drop => {}
            }
        }

        let merged = merge(to_mask, &ir.protected);
        let swept = identity_sweep(&ir.raw, merged, &ir.protected, &ir.regions);
        let rendered = render(&ir.raw, &config.key, swept.clone(), config.disclose_length);

        let summary =
            Summary { masked_count: rendered.map.len(), residual, collisions: rendered.collisions };
        MaskResult {
            masked: rendered.masked,
            recovery: Recovery { map: rendered.map },
            spans: swept,
            summary,
        }
    }

    fn parse(&self, input: Input) -> Ir {
        let Input { kind, data: raw } = input;
        let protected = scan_placeholders(&raw);
        let regions = self
            .parsers
            .iter()
            .find(|(k, _)| *k == kind)
            .and_then(|(_, p)| p.parse(&raw))
            .or_else(|| self.fallback.parse(&raw))
            .unwrap_or_default();
        Ir { raw, regions, protected }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Engine::builder()
            .parser(Kind::Json, Box::new(JsonParser))
            .detector(Box::new(RuleDetector::builtin()))
            .detector(Box::new(EntropyDetector::default()))
            .detector(Box::new(DecodeDetector::builtin()))
            .detector(Box::new(SuspiciousKeyDetector))
            .policy(Box::new(MaskAll))
            .build()
    }
}

pub struct EngineBuilder {
    parsers: Vec<(Kind, Box<dyn Parser>)>,
    detectors: Vec<Box<dyn Detector>>,
    policy: Option<Box<dyn Policy>>,
    guard: Option<Box<dyn OverMaskGuard>>,
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self { parsers: Vec::new(), detectors: Vec::new(), policy: None, guard: None }
    }
    pub fn parser(mut self, kind: Kind, parser: Box<dyn Parser>) -> Self {
        self.parsers.push((kind, parser));
        self
    }
    pub fn detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }
    pub fn policy(mut self, policy: Box<dyn Policy>) -> Self {
        self.policy = Some(policy);
        self
    }
    pub fn guard(mut self, guard: Box<dyn OverMaskGuard>) -> Self {
        self.guard = Some(guard);
        self
    }
    pub fn build(self) -> Engine {
        Engine {
            parsers: self.parsers,
            fallback: Box::new(TextParser),
            detectors: self.detectors,
            policy: self.policy.unwrap_or_else(|| Box::new(MaskAll)),
            guard: self.guard,
        }
    }
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Freeze existing `<<LABEL_hash>>` placeholders so re-masking is a no-op.
fn scan_placeholders(raw: &str) -> Vec<ByteRange> {
    let re = Regex::new(r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{16}(?:_len[0-9]+)?>>")
        .expect("placeholder regex compiles");
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
        Engine::default().mask(Input { kind: Kind::Text, data: s.to_string() }, &Config::insecure_testing())
    }
    fn mj(s: &str) -> MaskResult {
        Engine::default().mask(Input { kind: Kind::Json, data: s.to_string() }, &Config::insecure_testing())
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
    fn opt_in_length_for_opaque_only() {
        let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh"; // ~29 chars, high entropy
        let input = format!("blob {blob} end");
        let on = Config { disclose_length: true, ..Config::insecure_testing() };
        let r = Engine::default().mask(Input { kind: Kind::Text, data: input.clone() }, &on);
        assert!(r.masked.contains("<<LIKELY_SECRET_") && r.masked.contains("_len"), "{}", r.masked);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);

        let r2 = m(&input);
        assert!(!r2.masked.contains("_len"), "{}", r2.masked);
    }

    #[test]
    fn masks_through_zero_width() {
        let r = m("key AKIA\u{200b}IOSFODNN7EXAMPLE end");
        assert!(r.masked.contains("<<AWS_AKID_"), "{}", r.masked);
        assert!(!r.masked.contains('\u{200b}'), "{}", r.masked);
    }

    #[test]
    fn base64_wrapped_secret_gets_specific_label() {
        use data_encoding::BASE64;
        let once = BASE64.encode(b"AKIAIOSFODNN7EXAMPLE");
        let twice = BASE64.encode(once.as_bytes());
        for enc in [once, twice] {
            let input = format!("payload {enc} tail");
            let r = m(&input);
            assert!(r.masked.contains("<<AWS_AKID_"), "{}", r.masked);
            assert!(!r.masked.contains(&enc), "{}", r.masked);
            assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
        }
    }

    #[test]
    fn decode_unwrap_handles_multiple_codecs() {
        use data_encoding::{BASE32, HEXLOWER};
        let secret = b"AKIAIOSFODNN7EXAMPLE";
        for enc in [HEXLOWER.encode(secret), BASE32.encode(secret)] {
            let r = m(&format!("blob {enc} end"));
            assert!(r.masked.contains("<<AWS_AKID_"), "codec failed for {enc}: {}", r.masked);
        }
    }

    #[test]
    fn masks_through_percent_encoding() {
        let r = m("key sk%2DABCDEFGHIJKLMNOPQRSTUVWX end");
        assert!(r.masked.contains("<<OPENAI_API_KEY_"), "{}", r.masked);
        assert!(!r.masked.contains("%2D"), "{}", r.masked);
    }

    #[test]
    fn unwraps_base64_gzip() {
        use data_encoding::BASE64;
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(b"secret AKIAIOSFODNN7EXAMPLE here").unwrap();
        let enc = BASE64.encode(&e.finish().unwrap());
        let r = m(&format!("body {enc} end"));
        assert!(r.masked.contains("<<AWS_AKID_"), "{}", r.masked);
    }

    #[test]
    fn json_structure_preserved() {
        let input = r#"{"user":"alice@example.com","db_password":"hunter2pass","note":"hello world"}"#;
        let r = mj(input);
        let v: serde_json::Value = serde_json::from_str(&r.masked).expect("masked output is valid JSON");
        let o = v.as_object().unwrap();
        assert!(o["db_password"].as_str().unwrap().starts_with("<<"));
        assert!(o["user"].as_str().unwrap().starts_with("<<"));
        assert_eq!(o["note"].as_str().unwrap(), "hello world");
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn custom_engine_can_drop_detectors() {
        // DI: an engine with no detectors masks nothing.
        let engine = Engine::builder().policy(Box::new(MaskAll)).build();
        let r = engine.mask(Input::text("token sk-ABCDEFGHIJKLMNOPQRSTUVWX"), &Config::insecure_testing());
        assert_eq!(r.summary.masked_count, 0, "{}", r.masked);
    }

    fn mp(profile: Profile, s: &str) -> MaskResult {
        Engine::with_profile(profile).mask(Input::text(s), &Config::insecure_testing())
    }

    #[test]
    fn context_free_entropy_follows_profile() {
        let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh"; // high entropy, no anchor
        let input = format!("blob {blob} end");
        // Strict masks it; Balanced warns (kept in output, surfaced in residual).
        assert!(!mp(Profile::Strict, &input).masked.contains(blob));
        let bal = mp(Profile::Balanced, &input);
        assert!(bal.masked.contains(blob), "{}", bal.masked);
        assert_eq!(bal.summary.residual.len(), 1);
        assert!(mp(Profile::Dev, &input).masked.contains(blob)); // kept
    }

    #[test]
    fn anchored_secret_masks_under_every_profile() {
        for p in [Profile::Strict, Profile::Balanced, Profile::Dev, Profile::Paranoid] {
            let r = mp(p, "key AKIAIOSFODNN7EXAMPLE end");
            assert!(r.masked.contains("<<AWS_AKID_"), "{p:?}: {}", r.masked);
        }
    }

    #[test]
    fn guard_spares_uuid_unless_anchored() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        // Bare UUID survives even Paranoid (benign shape).
        assert!(mp(Profile::Paranoid, &format!("id {uuid} x")).masked.contains(uuid));
        // Under a sensitive key it is anchored, so it masks.
        let j = format!("{{\"session_token\":\"{uuid}\"}}");
        let r = Engine::with_profile(Profile::Balanced)
            .mask(Input { kind: Kind::Json, data: j }, &Config::insecure_testing());
        assert!(!r.masked.contains(uuid), "{}", r.masked);
    }

    #[test]
    fn paranoid_masks_opaque_blob() {
        use data_encoding::BASE64;
        let bytes: Vec<u8> = (0u8..24).map(|n| n.wrapping_mul(37).wrapping_add(11)).collect();
        let enc = BASE64.encode(&bytes);
        let input = format!("payload {enc} end");
        assert!(mp(Profile::Balanced, &input).masked.contains(&enc)); // untouched
        assert!(mp(Profile::Paranoid, &input).masked.contains("<<OPAQUE_BLOB_"));
    }

    #[test]
    fn aggressive_engine_masks_uuid() {
        // --aggressive == ProfilePolicy(Paranoid) + NoGuard.
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let engine = Engine::builder()
            .detector(Box::new(EntropyDetector::with(20, 2.8)))
            .policy(Box::new(ProfilePolicy::new(Profile::Paranoid)))
            .guard(Box::new(crate::guard::NoGuard))
            .build();
        let r = engine.mask(Input::text(&format!("id {uuid} x")), &Config::insecure_testing());
        assert!(!r.masked.contains(uuid), "{}", r.masked);
    }

    #[test]
    fn reversible_under_all_profiles() {
        let input = "key AKIAIOSFODNN7EXAMPLE and a@b.com and Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
        for p in [Profile::Strict, Profile::Balanced, Profile::Dev, Profile::Paranoid] {
            let r = mp(p, input);
            assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input, "{p:?}");
        }
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
