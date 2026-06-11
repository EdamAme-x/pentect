mod merge;
mod render;
mod sweep;

use crate::detect::{
    CardDetector, DecodeDetector, Detector, EntropyDetector, PemDetector, RuleDetector,
    StructuralDetector,
};
use crate::model::*;
use crate::normalize::NormalizedView;
use crate::parse::{EnvParser, HarParser, JsonParser, Parser, TextParser};
use crate::policy::guard::{NoGuard, OverMaskGuard, ShapeGuard};
use crate::policy::{
    is_context_free, Action, MaskAll, Policy, Profile, ProfileKnobs, ProfilePolicy,
};
use crate::recovery::Recovery;
use merge::merge;
use regex::Regex;
use render::render;
pub use render::RenderSegment;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use sweep::identity_sweep;

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
        Self {
            key,
            locale: "en".into(),
            disclose_length: false,
        }
    }
    /// Fixed key for tests and demos only.
    pub fn insecure_testing() -> Self {
        Self::new([7u8; 32])
    }
    /// Fresh key from the OS CSPRNG. For one-way (mask-only) use a per-run key is
    /// fine: the cloud side cannot recompute the hash. Reproducing a mask across
    /// runs requires persisting this key (an adapter concern).
    #[cfg(feature = "rand-key")]
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("OS CSPRNG unavailable");
        Self::new(key)
    }
}

/// Something flagged but left unmasked (value-free). Reports *what* was warned
/// about, not *where*: this is part of the serializable Summary, so it carries no
/// raw byte offset (which would disclose the position and exact length of the
/// flagged content).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResidualNote {
    pub category: Category,
    pub source: DetectorId,
}

/// One masked value, for reporting. Carries *what* was masked (label/category/
/// detector), never *where*: a raw input offset would not map to `masked` anyway
/// and would disclose each secret's position.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaskedItem {
    pub category: Category,
    pub label: Label,
    pub confidence: Confidence,
    pub source: DetectorId,
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
    /// The requested format parser failed and we fell back to plaintext, so key
    /// context is lost and structure is not guaranteed. Not set for Text input.
    #[serde(default)]
    pub parser_fallback: bool,
}

/// Carries the local-only recovery map, so it is intentionally not serializable.
pub struct MaskResult {
    pub masked: String,
    pub recovery: Recovery,
    /// Literal/masked pieces of `masked`, in order, for index-free visualization.
    pub segments: Vec<RenderSegment>,
    /// What was masked (no raw offsets); see `MaskedItem`.
    pub items: Vec<MaskedItem>,
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
    /// Labels to suppress (a deployment turning a built-in detector off, e.g.
    /// "don't mask IPs here"). Filtered before classify, so it overrides any
    /// detector regardless of which one produced the span.
    disabled: std::collections::HashSet<String>,
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::new()
    }

    /// Standard stack tuned for a profile. Power users can still build a fully
    /// custom Engine via `builder()`.
    pub fn with_profile(profile: Profile) -> Self {
        Engine::builder()
            .standard_stack(profile.knobs())
            .policy(Box::new(ProfilePolicy::new(profile)))
            .guard(Box::new(ShapeGuard::builtin()))
            .build()
    }

    /// Like `with_profile` but with the benign-shape guard disabled — the
    /// "mask everything, even UUIDs/hashes" escape hatch (`--aggressive`). Output
    /// is then mostly unusable for reasoning, but every mask stays reversible.
    pub fn with_profile_unguarded(profile: Profile) -> Self {
        Engine::builder()
            .standard_stack(profile.knobs())
            .policy(Box::new(ProfilePolicy::new(profile)))
            .guard(Box::new(NoGuard))
            .build()
    }

    /// Standard profile stack plus user rule packs (loaded from TOML). Each
    /// pack's rules run as additional detectors on top of the built-ins;
    /// `aggressive` disables the benign-shape guard.
    pub fn with_profile_and_packs(
        profile: Profile,
        packs: Vec<crate::pack::Pack>,
        aggressive: bool,
    ) -> Self {
        let mut builder = Engine::builder().standard_stack(profile.knobs());
        for pack in packs {
            builder = builder
                .detector(Box::new(pack.rules))
                .disable_labels(pack.disable);
        }
        let guard: Box<dyn OverMaskGuard> = if aggressive {
            Box::new(NoGuard)
        } else {
            Box::new(ShapeGuard::builtin())
        };
        builder
            .policy(Box::new(ProfilePolicy::new(profile)))
            .guard(guard)
            .build()
    }

    pub fn mask(&self, input: Input, config: &Config) -> MaskResult {
        let (ir, fell_back) = self.parse(input);
        let mut result = self.mask_ir(ir, config);
        result.summary.parser_fallback = fell_back;
        result
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
        if !self.disabled.is_empty() {
            spans.retain(|s| !self.disabled.contains(&s.label));
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
                Action::Mask => to_mask.push(s),
                Action::Warn => residual.push(ResidualNote {
                    category: s.category,
                    source: s.source,
                }),
                Action::Keep | Action::Drop => {}
            }
        }

        let merged = merge(to_mask, &ir.protected);
        let swept = identity_sweep(&ir.raw, merged, &ir.protected, &ir.regions);
        let rendered = render(&ir.raw, &config.key, swept.clone(), config.disclose_length);

        // parser_fallback is set by mask(); mask_ir takes a ready-made Ir.
        let summary = Summary {
            masked_count: rendered.map.len(),
            residual,
            collisions: rendered.collisions,
            parser_fallback: false,
        };
        let items = swept
            .into_iter()
            .map(|s| MaskedItem {
                category: s.category,
                label: s.label,
                confidence: s.confidence,
                source: s.source,
            })
            .collect();
        MaskResult {
            masked: rendered.masked,
            recovery: Recovery::seal(rendered.map, &config.key),
            segments: rendered.segments,
            items,
            summary,
        }
    }

    /// Returns the Ir and whether a *requested* format parser failed (so we fell
    /// back to plaintext). Text input has no registered parser, so it is never a
    /// fallback.
    fn parse(&self, input: Input) -> (Ir, bool) {
        let Input { kind, data: raw } = input;
        let protected = scan_placeholders(&raw);
        let (regions, fell_back) = match self.parsers.iter().find(|(k, _)| *k == kind) {
            Some((_, p)) => match p.parse(&raw) {
                Some(regions) => (regions, false),
                None => (self.fallback.parse(&raw).unwrap_or_default(), true),
            },
            None => (self.fallback.parse(&raw).unwrap_or_default(), false),
        };
        (
            Ir {
                raw,
                regions,
                protected,
            },
            fell_back,
        )
    }
}

impl Default for Engine {
    fn default() -> Self {
        Engine::builder()
            .standard_stack(Profile::Strict.knobs())
            .policy(Box::new(MaskAll))
            .build()
    }
}

pub struct EngineBuilder {
    parsers: Vec<(Kind, Box<dyn Parser>)>,
    detectors: Vec<Box<dyn Detector>>,
    policy: Option<Box<dyn Policy>>,
    guard: Option<Box<dyn OverMaskGuard>>,
    disabled: std::collections::HashSet<String>,
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
            detectors: Vec::new(),
            policy: None,
            guard: None,
            disabled: std::collections::HashSet::new(),
        }
    }
    /// Register the canonical parser + detector set tuned for `knobs`. The single
    /// definition of the standard stack, so no path (profile, default, aggressive)
    /// can silently miss a parser or detector.
    pub fn standard_stack(self, knobs: ProfileKnobs) -> Self {
        self.parser(Kind::Json, Box::new(JsonParser))
            .parser(Kind::Env, Box::new(EnvParser))
            .parser(Kind::Har, Box::new(HarParser))
            .detector(Box::new(RuleDetector::builtin()))
            .detector(Box::new(CardDetector))
            .detector(Box::new(PemDetector::default()))
            .detector(Box::new(EntropyDetector::with(
                knobs.entropy_min_len,
                knobs.entropy_threshold,
            )))
            .detector(Box::new(
                DecodeDetector::builtin()
                    .with_opaque(knobs.mask_unknown_codec, knobs.min_opaque_run),
            ))
            .detector(Box::new(StructuralDetector))
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
    /// Suppress these labels (turn off built-in or pack detectors by name).
    pub fn disable_labels(mut self, labels: impl IntoIterator<Item = String>) -> Self {
        self.disabled.extend(labels);
        self
    }
    pub fn build(self) -> Engine {
        Engine {
            parsers: self.parsers,
            fallback: Box::new(TextParser),
            detectors: self.detectors,
            policy: self.policy.unwrap_or_else(|| Box::new(MaskAll)),
            guard: self.guard,
            disabled: self.disabled,
        }
    }
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Hash width comes from the renderer so the freeze pattern can't drift from
    // what we emit.
    let w = crate::placeholder::HASH_HEX_WIDTH;
    Regex::new(&format!(
        r"<<[A-Z][A-Z0-9_]*_[0-9a-f]{{{w}}}(?:_len[0-9]+)?>>"
    ))
    .expect("placeholder regex compiles")
});

/// Freeze existing `<<LABEL_hash>>` placeholders so re-masking is a no-op.
fn scan_placeholders(raw: &str) -> Vec<ByteRange> {
    PLACEHOLDER_RE
        .find_iter(raw)
        .map(|m| ByteRange::new(m.start(), m.end()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::restore;
    use proptest::prelude::*;

    fn m(s: &str) -> MaskResult {
        Engine::default().mask(
            Input {
                kind: Kind::Text,
                data: s.to_string(),
            },
            &Config::insecure_testing(),
        )
    }
    fn mj(s: &str) -> MaskResult {
        Engine::default().mask(
            Input {
                kind: Kind::Json,
                data: s.to_string(),
            },
            &Config::insecure_testing(),
        )
    }

    #[test]
    fn reversible_idempotent_deterministic() {
        for x in [
            "",
            "hi there",
            "key sk-ABCDEFGHIJKLMNOPQRSTUVWX end",
            "a@b.com x a@b.com",
        ] {
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
        // Email splits into local + domain, so both occurrences share two
        // mappings (not one): the point is no plaintext address survives.
        assert_eq!(r.recovery.len(), 2);
    }

    #[test]
    fn distinct_values_distinct_placeholders() {
        let r = m("AKIAIOSFODNN7EXAMPLE AKIA0000000000000000");
        assert_eq!(r.recovery.len(), 2, "{}", r.masked);
    }

    #[test]
    fn opt_in_length_for_opaque_only() {
        let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh"; // ~29 chars, high entropy
        let input = format!("blob {blob} end");
        let on = Config {
            disclose_length: true,
            ..Config::insecure_testing()
        };
        let r = Engine::default().mask(
            Input {
                kind: Kind::Text,
                data: input.clone(),
            },
            &on,
        );
        assert!(
            r.masked.contains("<<LIKELY_SECRET_") && r.masked.contains("_len"),
            "{}",
            r.masked
        );
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);

        let r2 = m(&input);
        assert!(!r2.masked.contains("_len"), "{}", r2.masked);
    }

    #[test]
    fn length_disclosed_for_opaque_blob_too() {
        use data_encoding::BASE64;
        let bytes: Vec<u8> = (0u8..24)
            .map(|n| n.wrapping_mul(37).wrapping_add(11))
            .collect();
        let input = format!("payload {} end", BASE64.encode(&bytes));
        let on = Config {
            disclose_length: true,
            ..Config::insecure_testing()
        };
        let r = Engine::with_profile(Profile::Paranoid).mask(Input::text(&input), &on);
        assert!(
            r.masked.contains("<<OPAQUE_BLOB_") && r.masked.contains("_len"),
            "{}",
            r.masked
        );
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
            assert!(
                r.masked.contains("<<AWS_AKID_"),
                "codec failed for {enc}: {}",
                r.masked
            );
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
        // Detectable-by-value secrets (core no longer guesses arbitrary keys); a
        // benign string stays untouched and the output re-parses as JSON.
        let input =
            r#"{"user":"alice@example.com","api_key":"AKIAIOSFODNN7EXAMPLE","note":"hello world"}"#;
        let r = mj(input);
        let v: serde_json::Value =
            serde_json::from_str(&r.masked).expect("masked output is valid JSON");
        let o = v.as_object().unwrap();
        assert!(o["api_key"].as_str().unwrap().starts_with("<<"));
        assert!(o["user"].as_str().unwrap().starts_with("<<"));
        assert_eq!(o["note"].as_str().unwrap(), "hello world");
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn report_names_what_was_masked_without_offsets() {
        let r = m("key AKIAIOSFODNN7EXAMPLE here");
        // The report carries the label/category but no raw position, so a
        // consumer learns what was masked, not where the secret sat.
        assert!(r.items.iter().any(|i| i.label == "AWS_AKID"));
        assert_eq!(r.items.len(), r.summary.masked_count);
    }

    // Categorized recall corpus. CORE_FLOOR = what the deterministic core must
    // catch by value/structure (hard-asserted, so recall can't silently
    // regress). SIDECAR_GAP = categories that need the semantic ML layer (names,
    // addresses, weak/keyed values, multilingual, locale IDs); recorded, not
    // asserted — that is the honest boundary, not a core failure. Secret-shaped
    // samples are split with concat! so no contiguous secret literal exists.
    const CORE_FLOOR: &[(&str, &str)] = &[
        ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        (concat!("sk", "-ABCDEFGHIJKLMNOPQRSTUVWX"), "openai_api_key"),
        (
            concat!("ghp", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            "github_token",
        ),
        (concat!("sk", "_live_ABCDEFGHIJ1234567890"), "stripe_key"),
        (
            concat!("AIza", "SyA1234567890abcdefghijklmnopqrstuv0"),
            "google_api_key",
        ),
        (
            concat!("npm", "_abcdefghijklmnopqrstuvwxyz0123456789"),
            "npm_token",
        ),
        ("4242424242424242", "credit_card_luhn"),
        ("alice@example.com", "email"),
        ("Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh", "high_entropy_token"),
        (
            "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----",
            "private_key_pem",
        ),
    ];
    // Checksum-validated national / financial IDs (deterministic core; this is
    // where we match/exceed Presidio). Each sample passes its real checksum.
    const CHECKSUM_FLOOR: &[(&str, &str)] = &[
        ("1234567893", "us_npi"),
        ("00123456782", "it_vat"),
        ("130458623", "ca_sin"),
        ("021000021", "us_aba_routing"),
        ("AB1234563", "us_dea"),
        ("GB82WEST12345698765432", "iban"),
        ("9434767016", "uk_nhs"),
        ("44051401359", "pl_pesel"),
        ("123456782", "au_tfn"),
        ("9001011123459", "kr_rrn"),
        ("12345678Z", "es_nif"),
        ("X1234567L", "es_nie"),
        ("86095742719", "de_tax_id"),
        ("S1234567D", "sg_nric_fin"),
        ("51824753556", "au_abn"),
        ("2951234577", "au_medicare"),
        ("234567890124", "in_aadhaar"),
        ("123456789018", "jp_my_number"),
        ("11144477735", "br_cpf"),
        ("11222333000181", "br_cnpj"),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc_address"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "btc_bech32"),
        ("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "eth_address"),
        ("219-09-9998", "us_ssn"),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "bip39_mnemonic",
        ),
        ("2001:db8::8a2e:370:7334", "ipv6"),
    ];
    const SIDECAR_GAP: &[(&str, &str)] = &[
        ("John Smith", "person_name"),
        ("山田太郎", "person_name_ja"),
        (
            "1600 Amphitheatre Parkway, Mountain View CA",
            "street_address",
        ),
        ("hunter2", "weak_password_value"),
    ];

    #[test]
    fn recall_corpus_core_floor_holds() {
        for (sample, label) in CORE_FLOOR.iter().chain(CHECKSUM_FLOOR) {
            assert!(
                !m(sample).items.is_empty(),
                "core recall floor regressed on {label}: {sample:?}"
            );
        }
        // Sanity: the corpus exercises the floor and the known sidecar gap.
        assert!(CORE_FLOOR.len() + CHECKSUM_FLOOR.len() >= 30 && SIDECAR_GAP.len() >= 4);
        let gap_hit: Vec<&str> = SIDECAR_GAP
            .iter()
            .filter(|(s, _)| !m(s).items.is_empty())
            .map(|(_, l)| *l)
            .collect();
        eprintln!(
            "recall corpus: floor {}/{} caught; sidecar_gap incidentally caught: {gap_hit:?}",
            CORE_FLOOR.len() + CHECKSUM_FLOOR.len(),
            CORE_FLOOR.len() + CHECKSUM_FLOOR.len()
        );
    }

    // === Benchmark vs Presidio and Azure AI Language PII ===
    // The two standing goals: surpass Presidio and surpass Azure. We measure it
    // entity-by-entity. Each entry is classified:
    //   Core    — deterministic (pattern/checksum); core MUST catch it (asserted).
    //   Sidecar — semantic / NER (person, location, org, nationality, address,
    //             age, person-type): no closed pattern exists, so a deterministic
    //             core genuinely cannot reach these — Presidio's spaCy NER does,
    //             and on these it beats us until the ML sidecar lands. Honest
    //             concession, not a free pass. Recorded, not asserted.
    //   Todo    — deterministic but not implemented yet; the remaining gap to
    //             close for full deterministic parity. Recorded, not asserted.
    // "Surpassed" on the deterministic axis = every Core caught AND we add
    // entities neither vendor has (see EXCLUSIVE). Todo count is the honest
    // distance to zero-gap; Sidecar is conceded to the sidecar by design.
    #[derive(PartialEq, Clone, Copy)]
    enum Cov {
        Core,
        Sidecar,
        Todo,
    }
    use Cov::{Core, Sidecar, Todo};

    // Microsoft Presidio predefined recognizers (entity, sample, classification).
    const PRESIDIO: &[(&str, &str, Cov)] = &[
        ("CREDIT_CARD", "4242424242424242", Core),
        ("CRYPTO", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Core),
        ("IBAN_CODE", "GB82WEST12345698765432", Core),
        ("IP_ADDRESS(v4)", "192.168.1.1", Core),
        ("IP_ADDRESS(v6)", "2001:db8::8a2e:370:7334", Core),
        ("EMAIL_ADDRESS", "alice@example.com", Core),
        ("PHONE_NUMBER", "(415) 555-0132", Core),
        ("US_SSN", "219-09-9998", Core),
        ("US_ITIN", "900-70-1234", Core),
        ("US_NPI", "1234567893", Core),
        ("US_PASSPORT", "C12345678", Core),
        ("MEDICAL_LICENSE(DEA)", "AB1234563", Core),
        ("UK_NHS", "9434767016", Core),
        ("UK_NINO", "AB123456C", Core),
        ("ES_NIF", "12345678Z", Core),
        ("ES_NIE", "X1234567L", Core),
        ("IT_VAT_CODE", "00123456782", Core),
        ("PL_PESEL", "44051401359", Core),
        ("SG_NRIC_FIN", "S1234567D", Core),
        ("AU_ABN", "51824753556", Core),
        ("AU_TFN", "123456782", Core),
        ("AU_MEDICARE", "2951234577", Core),
        ("IN_PAN", "ABCPK1234L", Core),
        ("IN_AADHAAR", "234567890124", Core),
        ("FI_HETU", "131052-308T", Core),
        ("IT_FISCAL_CODE", "RSSMRA85T10A562S", Core),
        ("US_DRIVER_LICENSE", "driver's license D1234567", Core),
        ("US_BANK_NUMBER", "account number 1234567890", Core),
        ("URL", "https://example.com/x", Core),
        // Deterministic (Presidio uses a regex), but deferred: masking every date
        // floods. A real gap, not a sidecar concession — hence Todo, not Sidecar.
        ("DATE_TIME", "January 5, 1990", Todo),
        ("PERSON", "John Smith", Sidecar),
        ("LOCATION", "Mountain View", Sidecar),
        ("NRP", "British", Sidecar),
        ("ORGANIZATION", "Acme Corporation", Sidecar),
    ];

    // Azure AI Language PII entity categories (representative; ~200 total, the
    // bulk being per-country ID variants of the patterns covered below).
    const AZURE: &[(&str, &str, Cov)] = &[
        ("CreditCardNumber", "4242424242424242", Core),
        ("ABARoutingNumber", "021000021", Core),
        ("SWIFTCode", "DEUTDEFF", Core),
        ("IBAN", "GB82WEST12345698765432", Core),
        ("Email", "alice@example.com", Core),
        ("IPAddress", "192.168.1.1", Core),
        ("PhoneNumber", "(415) 555-0132", Core),
        ("USSocialSecurityNumber", "219-09-9998", Core),
        ("USITIN", "900-70-1234", Core),
        ("USDEANumber", "AB1234563", Core),
        ("USPassportNumber", "C12345678", Core),
        ("UKNationalInsuranceNumber", "AB123456C", Core),
        ("UKNHSNumber", "9434767016", Core),
        ("SpainDNI", "12345678Z", Core),
        ("SpainNIE", "X1234567L", Core),
        ("ItalyVAT", "00123456782", Core),
        ("PolandPESEL", "44051401359", Core),
        ("GermanyTaxId", "86095742719", Core),
        ("NetherlandsBSN", "111222333", Core),
        ("SingaporeNRIC", "S1234567D", Core),
        ("AustraliaTFN", "123456782", Core),
        ("AustraliaABN", "51824753556", Core),
        ("IndiaPAN", "ABCPK1234L", Core),
        ("IndiaAadhaar", "234567890124", Core),
        ("JapanMyNumber", "123456789018", Core),
        ("KoreaRRN", "9001011123459", Core),
        ("BrazilCPF", "11144477735", Core),
        ("BrazilCNPJ", "11222333000181", Core),
        ("CanadaSIN", "130458623", Core),
        ("EUVAT", "DE136695976", Core),
        ("USDriversLicense", "driver's license D1234567", Core),
        ("USBankAccountNumber", "account number 1234567890", Core),
        ("ItalyFiscalCode", "RSSMRA85T10A562S", Core),
        ("URL", "https://example.com/x", Core),
        ("FrenchINSEE", "180047509112556", Todo),
        ("DateTime", "2025-06-11", Todo),
        ("Age", "35 years old", Sidecar),
        (
            "Address",
            "1600 Amphitheatre Parkway, Mountain View CA",
            Sidecar,
        ),
        ("Person", "John Smith", Sidecar),
        ("PersonType", "doctor", Sidecar),
        ("Organization", "Microsoft", Sidecar),
    ];

    // Deterministic entities Pentect catches that NEITHER Presidio nor Azure has
    // a recognizer for — where we strictly exceed both. (Samples are public
    // addresses / non-secret shapes; vendor API keys are covered in rule.rs.)
    const EXCLUSIVE: &[(&str, &str)] = &[
        ("ETH_ADDRESS", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
        ("BTC_BECH32", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        (
            "BIP39_MNEMONIC",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        ("MAC_ADDRESS", "00:1A:2B:3C:4D:5E"),
        ("DB_CONNECTION_STRING", "postgresql://admin:s3cr3t@db.host:5432/sales"),
    ];

    #[test]
    fn surpass_benchmark_presidio_and_azure() {
        for (name, table) in [("Presidio", PRESIDIO), ("Azure", AZURE)] {
            let caught = |s: &str| !m(s).items.is_empty();
            let core: Vec<_> = table.iter().filter(|(_, _, c)| *c == Core).collect();
            let todo: Vec<_> = table.iter().filter(|(_, _, c)| *c == Todo).collect();
            let sidecar: Vec<_> = table.iter().filter(|(_, _, c)| *c == Sidecar).collect();

            // The goal, asserted: every deterministic entity is caught.
            let core_missed: Vec<&str> = core
                .iter()
                .filter(|(_, s, _)| !caught(s))
                .map(|(e, _, _)| *e)
                .collect();
            assert!(
                core_missed.is_empty(),
                "{name}: deterministic recognizer(s) not caught (regression): {core_missed:?}"
            );

            let det_total = core.len() + todo.len();
            eprintln!(
                "vs {name}: deterministic {}/{} covered; sidecar/NER {} (out of core scope); remaining deterministic gap: {:?}",
                core.len(),
                det_total,
                sidecar.len(),
                todo.iter().map(|(e, _, _)| *e).collect::<Vec<_>>(),
            );
        }
        for (label, sample) in EXCLUSIVE {
            assert!(
                caught_exclusive(sample),
                "exclusive entity regressed: {label}"
            );
        }
        eprintln!(
            "Pentect-exclusive (beyond both vendors): {:?}",
            EXCLUSIVE.iter().map(|(l, _)| *l).collect::<Vec<_>>()
        );
    }

    fn caught_exclusive(s: &str) -> bool {
        !m(s).items.is_empty()
    }

    #[test]
    fn custom_engine_can_drop_detectors() {
        // DI: an engine with no detectors masks nothing.
        let engine = Engine::builder().policy(Box::new(MaskAll)).build();
        let r = engine.mask(
            Input::text("token sk-ABCDEFGHIJKLMNOPQRSTUVWX"),
            &Config::insecure_testing(),
        );
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
        for p in [
            Profile::Strict,
            Profile::Balanced,
            Profile::Dev,
            Profile::Paranoid,
        ] {
            let r = mp(p, "key AKIAIOSFODNN7EXAMPLE end");
            assert!(r.masked.contains("<<AWS_AKID_"), "{p:?}: {}", r.masked);
        }
    }

    #[test]
    fn guard_spares_uuid_unless_anchored() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        // Bare UUID survives even Paranoid (benign shape).
        assert!(mp(Profile::Paranoid, &format!("id {uuid} x"))
            .masked
            .contains(uuid));
        // As a cookie value it is anchored by structure, so it masks despite the
        // benign shape (the guard only retracts context-free guesses).
        let har = format!(
            r#"{{"log":{{"entries":[{{"request":{{"cookies":[{{"name":"sid","value":"{uuid}"}}]}}}}]}}}}"#
        );
        let r = Engine::with_profile(Profile::Balanced).mask(
            Input {
                kind: Kind::Har,
                data: har,
            },
            &Config::insecure_testing(),
        );
        assert!(!r.masked.contains(uuid), "{}", r.masked);
    }

    #[test]
    fn paranoid_masks_opaque_blob() {
        use data_encoding::BASE64;
        let bytes: Vec<u8> = (0u8..24)
            .map(|n| n.wrapping_mul(37).wrapping_add(11))
            .collect();
        let enc = BASE64.encode(&bytes);
        let input = format!("payload {enc} end");
        assert!(mp(Profile::Balanced, &input).masked.contains(&enc)); // untouched
        assert!(mp(Profile::Paranoid, &input)
            .masked
            .contains("<<OPAQUE_BLOB_"));
    }

    #[test]
    fn aggressive_engine_masks_uuid() {
        // --aggressive == ProfilePolicy(Paranoid) + NoGuard.
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let engine = Engine::builder()
            .detector(Box::new(EntropyDetector::with(20, 2.8)))
            .policy(Box::new(ProfilePolicy::new(Profile::Paranoid)))
            .guard(Box::new(crate::policy::guard::NoGuard))
            .build();
        let r = engine.mask(
            Input::text(format!("id {uuid} x")),
            &Config::insecure_testing(),
        );
        assert!(!r.masked.contains(uuid), "{}", r.masked);
    }

    #[cfg(feature = "rand-key")]
    #[test]
    fn generated_keys_differ_and_are_nonzero() {
        let a = Config::generate().key;
        let b = Config::generate().key;
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn malformed_json_flags_parser_fallback() {
        let ok = Engine::default().mask(
            Input {
                kind: Kind::Json,
                data: "{\"a\":\"x\"}".into(),
            },
            &Config::insecure_testing(),
        );
        assert!(!ok.summary.parser_fallback);
        let bad = Engine::default().mask(
            Input {
                kind: Kind::Json,
                data: "{not valid json".into(),
            },
            &Config::insecure_testing(),
        );
        assert!(bad.summary.parser_fallback);
        // Text input is never a "fallback".
        let txt = Engine::default().mask(Input::text("hi"), &Config::insecure_testing());
        assert!(!txt.summary.parser_fallback);
    }

    #[test]
    fn reversible_under_all_profiles() {
        let input = "key AKIAIOSFODNN7EXAMPLE and a@b.com and Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
        for p in [
            Profile::Strict,
            Profile::Balanced,
            Profile::Dev,
            Profile::Paranoid,
        ] {
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

        // mask() must never panic on arbitrary input, and stay reversible.
        #[test]
        fn prop_arbitrary_never_panics_and_reversible(s in any::<String>()) {
            let r = m(&s);
            prop_assert_eq!(restore(&r.masked, &r.recovery).unwrap(), s);
        }

        // No-survivor: a known secret placed at token boundaries never appears
        // verbatim in the masked output, under any profile.
        #[test]
        fn prop_no_survivor_all_profiles(
            pre in "[a-z ]{0,20}",
            mid in "[a-z ]{1,20}",
            post in "[a-z ]{0,20}",
        ) {
            let secret = "AKIAIOSFODNN7EXAMPLE";
            let input = format!("{pre} {secret} {mid} {secret} {post}");
            for p in [Profile::Strict, Profile::Balanced, Profile::Dev, Profile::Paranoid] {
                let r = Engine::with_profile(p).mask(Input::text(&input), &Config::insecure_testing());
                prop_assert!(!r.masked.contains(secret), "{p:?} left a survivor: {}", r.masked);
            }
        }
    }

    #[test]
    fn pem_private_key_masked_under_default_profile() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANBgkqh\nkiG9w0BAQEFAASCAT\n-----END RSA PRIVATE KEY-----";
        let input = format!("here is the key:\n{pem}\nthanks");
        let r = Engine::with_profile(Profile::Balanced)
            .mask(Input::text(&input), &Config::insecure_testing());
        assert!(r.masked.contains("<<PRIVATE_KEY_"), "{}", r.masked);
        assert!(!r.masked.contains("MIIBVAIBADANBgkqh"), "{}", r.masked);
        // Armor preserved so the model knows what was masked.
        assert!(
            r.masked.contains("-----BEGIN RSA PRIVATE KEY-----"),
            "{}",
            r.masked
        );
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn unguarded_keeps_full_stack_parsers_and_detectors() {
        // Regression: the --aggressive path must not drop EnvParser or PemDetector.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANBgkqh\nkiG9w0BAQEFAASCAT\n-----END RSA PRIVATE KEY-----";
        let r = Engine::with_profile_unguarded(Profile::Paranoid)
            .mask(Input::text(pem), &Config::insecure_testing());
        assert!(
            r.masked.contains("<<PRIVATE_KEY_"),
            "pem still masked: {}",
            r.masked
        );

        let env = Engine::with_profile_unguarded(Profile::Paranoid).mask(
            Input {
                kind: Kind::Env,
                data: "DB_KEY=AKIAIOSFODNN7EXAMPLE\n".into(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            !env.masked.contains("AKIAIOSFODNN7EXAMPLE"),
            "env value still masked: {}",
            env.masked
        );
    }

    #[test]
    fn env_value_masked_by_value_structure_preserved() {
        let raw = "export DB_KEY=AKIAIOSFODNN7EXAMPLE\nNOTE=hello world\n";
        let r = Engine::with_profile(Profile::Balanced).mask(
            Input {
                kind: Kind::Env,
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        // The value is masked because it *looks* like a secret (vendor shape),
        // not because of its key; a benign value is untouched.
        assert!(!r.masked.contains("AKIAIOSFODNN7EXAMPLE"), "{}", r.masked);
        assert!(r.masked.contains("NOTE=hello world"), "{}", r.masked);
        // Structure preserved: key, =, newlines intact.
        assert!(r.masked.contains("export DB_KEY=<<"), "{}", r.masked);
    }

    #[test]
    fn no_survivor_in_json_values() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let input = format!("{{\"a\":\"{secret}\",\"b\":\"see {secret} here\"}}");
        let r = Engine::with_profile(Profile::Balanced).mask(
            Input {
                kind: Kind::Json,
                data: input,
            },
            &Config::insecure_testing(),
        );
        assert!(!r.masked.contains(secret), "{}", r.masked);
    }
}
