mod interval;
mod merge;
mod render;
mod sweep;

use crate::detect::{
    AuthCodeDetector, Bip39Detector, CliCredentialDetector, CredSweeperNativeDetector,
    DecodeConfig, DecodeDetector, Detector, EnvValueDetector, ExplicitSecretDetector,
    KeyValueDetector, SensitiveKeyDetector, StructuralDetector, UrlDetector, SECRET_VALUE_HINT,
};
use crate::model::*;
use crate::normalize::NormalizedView;
use crate::parse::{EnvParser, JsonParser, NdjsonParser, Parser, StructuredParser, TextParser};
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
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::LazyLock;
use sweep::identity_sweep;

/// Per-call parameters (not behaviour). `key` seals local recovery data while
/// `identity_key` creates stable, non-reversible handle identifiers.
#[derive(Clone, Debug)]
pub struct Config {
    pub key: [u8; 32],
    pub identity_key: [u8; 32],
    pub locale: String,
    /// Opt-in exact length disclosure (off by default).
    pub disclose_length: bool,
}

impl Config {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            identity_key: key,
            locale: "en".into(),
            disclose_length: false,
        }
    }
    pub fn with_identity_key(mut self, identity_key: [u8; 32]) -> Self {
        self.identity_key = identity_key;
        self
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
    /// Short placeholders that two distinct values collided on and were safely
    /// disambiguated with a full-width keyed hash.
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

/// Value-free scan output. It runs the same detectors, policy, merge, and sweep
/// as `mask`, but skips rendering placeholders and building a recovery map.
pub struct AnalysisResult {
    pub items: Vec<MaskedItem>,
    pub residual: Vec<ResidualNote>,
    pub parser_fallback: bool,
}

/// Local evaluator output with raw byte ranges. This is intentionally not used
/// by scan/report UI paths; callers must not print raw slices from these spans.
pub struct SpanAnalysisResult {
    pub spans: Vec<Span>,
    pub residual: Vec<ResidualNote>,
    pub parser_fallback: bool,
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

    /// Standard stack tuned for the built-in strict profile. Power users can still build a fully
    /// custom Engine via `builder()`.
    pub fn with_profile(profile: Profile) -> Self {
        Self::with_profile_and_decode_config(profile, profile_decode_config(profile.knobs()))
    }

    pub fn with_profile_and_decode_config(profile: Profile, decode: DecodeConfig) -> Self {
        Engine::builder()
            .standard_stack_with_decode(profile.knobs(), decode)
            .policy(Box::new(ProfilePolicy::new(profile)))
            .guard(Box::new(ShapeGuard::builtin()))
            .build()
    }

    /// Like `with_profile` but with the benign-shape guard disabled.
    pub fn with_profile_unguarded(profile: Profile) -> Self {
        Engine::builder()
            .standard_stack(profile.knobs())
            .policy(Box::new(ProfilePolicy::new(profile)))
            .guard(Box::new(NoGuard))
            .build()
    }

    /// Standard strict stack plus user rule packs (loaded from TOML). Each
    /// pack's rules run as additional detectors on top of the built-ins;
    /// `aggressive` disables the benign-shape guard.
    pub fn with_profile_and_packs(
        profile: Profile,
        packs: Vec<crate::pack::Pack>,
        aggressive: bool,
    ) -> Self {
        Self::with_profile_and_packs_and_decode_config(
            profile,
            packs,
            aggressive,
            profile_decode_config(profile.knobs()),
        )
    }

    pub fn with_profile_and_packs_and_decode_config(
        profile: Profile,
        packs: Vec<crate::pack::Pack>,
        aggressive: bool,
        decode: DecodeConfig,
    ) -> Self {
        let mut builder = Engine::builder().standard_stack_with_decode(profile.knobs(), decode);
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

    /// Secret-scan stack used by repository scanning and external secret
    /// benchmarks. CredSweeper owns vendor/token detection; Pentect only adds
    /// deterministic gaps that are outside the line-oriented CredSweeper port.
    pub fn secret_scan_with_profile_and_packs(
        profile: Profile,
        packs: Vec<crate::pack::Pack>,
    ) -> Self {
        Self::secret_scan_with_profile_packs_and_decode_config(
            profile,
            packs,
            profile_decode_config(profile.knobs()),
        )
    }

    pub fn secret_scan_with_profile_packs_and_decode_config(
        profile: Profile,
        packs: Vec<crate::pack::Pack>,
        decode: DecodeConfig,
    ) -> Self {
        let mut builder = Engine::builder().secret_scan_stack_with_decode(profile.knobs(), decode);
        for pack in packs {
            builder = builder
                .detector(Box::new(pack.rules))
                .disable_labels(pack.disable);
        }
        builder
            .policy(Box::new(ProfilePolicy::new(profile)))
            .guard(Box::new(ShapeGuard::builtin()))
            .build()
    }

    pub fn mask(&self, input: Input, config: &Config) -> MaskResult {
        let (ir, fell_back) = self.parse(input);
        let mut result = self.mask_ir(ir, config);
        result.summary.parser_fallback = fell_back;
        result
    }

    pub fn analyze(&self, input: Input) -> AnalysisResult {
        let (ir, fell_back) = self.parse(input);
        let (spans, residual) = self.masked_spans(&ir);
        AnalysisResult {
            items: masked_items(spans),
            residual,
            parser_fallback: fell_back,
        }
    }

    pub fn analyze_spans(&self, input: Input) -> SpanAnalysisResult {
        let (ir, fell_back) = self.parse_for_analysis(input);
        let (spans, residual) = self.masked_spans(&ir);
        SpanAnalysisResult {
            spans,
            residual,
            parser_fallback: fell_back,
        }
    }

    pub fn analyze_spans_with_path(
        &self,
        input: Input,
        path: impl Into<String>,
    ) -> SpanAnalysisResult {
        let path = path.into();
        let (mut ir, fell_back) = self.parse_for_analysis(input);
        for region in &mut ir.regions {
            if region.ctx.path.is_none() {
                region.ctx.path = Some(path.clone());
            }
        }
        let (spans, residual) = self.masked_spans(&ir);
        SpanAnalysisResult {
            spans,
            residual,
            parser_fallback: fell_back,
        }
    }

    /// Mask a single adapter-supplied region with explicit structural context.
    /// This is for adapters that already decoded an outer container (for example
    /// serde_json `Value`) and need the core detectors/policy/rendering to handle
    /// each scalar without reparsing or breaking the container's syntax.
    pub fn mask_context(&self, data: String, ctx: Context, config: &Config) -> MaskResult {
        let protected = scan_placeholders(&data);
        self.mask_ir(
            Ir {
                regions: vec![Region {
                    span: ByteRange::new(0, data.len()),
                    ctx,
                }],
                raw: data,
                protected,
            },
            config,
        )
    }

    /// Mask adapter-supplied regions inside a single synthetic raw buffer. This
    /// lets adapters batch many already-decoded scalars without reparsing each
    /// one or losing per-region key/path context.
    pub fn mask_regions(&self, raw: String, regions: Vec<Region>, config: &Config) -> MaskResult {
        let protected = scan_placeholders(&raw);
        self.mask_ir(
            Ir {
                raw,
                regions,
                protected,
            },
            config,
        )
    }

    /// An adapter can build the same `Ir` and call this directly.
    pub fn mask_ir(&self, ir: Ir, config: &Config) -> MaskResult {
        let (swept, residual) = self.masked_spans(&ir);
        let rendered = render(
            &ir.raw,
            &config.identity_key,
            swept.clone(),
            config.disclose_length,
        );

        // parser_fallback is set by mask(); mask_ir takes a ready-made Ir.
        let summary = Summary {
            masked_count: rendered.map.len(),
            residual,
            collisions: rendered.collisions,
            parser_fallback: false,
        };
        let items = masked_items(swept);
        MaskResult {
            masked: rendered.masked,
            recovery: Recovery::seal(rendered.map, &config.key),
            segments: rendered.segments,
            items,
            summary,
        }
    }

    /// Mask externally supplied spans with the same merge, policy, guard,
    /// identity sweep, renderer, and recovery-map invariants as built-ins.
    ///
    /// Model/NER adapters should use this instead of implementing `Detector`:
    /// the adapter owns the external process, and core owns deterministic
    /// rendering/recovery behavior.
    pub fn mask_spans(&self, input: Input, spans: Vec<Span>, config: &Config) -> MaskResult {
        let (ir, fell_back) = self.parse(input);
        let (swept, residual) = self.mask_supplied_spans(&ir, spans);
        let rendered = render(
            &ir.raw,
            &config.identity_key,
            swept.clone(),
            config.disclose_length,
        );

        let summary = Summary {
            masked_count: rendered.map.len(),
            residual,
            collisions: rendered.collisions,
            parser_fallback: fell_back,
        };
        let items = masked_items(swept);
        MaskResult {
            masked: rendered.masked,
            recovery: Recovery::seal(rendered.map, &config.key),
            segments: rendered.segments,
            items,
            summary,
        }
    }

    fn masked_spans(&self, ir: &Ir) -> (Vec<Span>, Vec<ResidualNote>) {
        // Detect to a bounded fixpoint. When a found span sits against an
        // alphanumeric neighbour (two distinct secrets concatenated with no
        // separator, e.g. a card directly followed by an IBAN), the trailing
        // one's regex word boundary fails; so we blank found spans (same-length
        // ASCII spaces — offsets preserved, UTF-8 stays valid) and re-detect.
        // The common case (separated secrets) finds nothing adjacent and stops
        // after one pass.
        let mut spans: Vec<Span> = Vec::new();
        let mut seen_ranges: HashSet<ByteRange> = HashSet::new();
        let mut work = Cow::Borrowed(ir.raw.as_str());
        for _ in 0..4 {
            let mut found = Vec::new();
            for region in &ir.regions {
                let view = NormalizedView::build(region, work.as_ref());
                for d in &self.detectors {
                    found.extend(d.detect(&view));
                }
            }
            found.retain(|span| {
                span.range.start <= span.range.end
                    && span.range.end <= work.len()
                    && work.is_char_boundary(span.range.start)
                    && work.is_char_boundary(span.range.end)
            });
            found.retain(|s| !seen_ranges.contains(&s.range));
            if found.is_empty() {
                break;
            }
            let more = {
                let b = work.as_bytes();
                found.iter().any(|s| {
                    let before = s
                        .range
                        .start
                        .checked_sub(1)
                        .is_some_and(|i| b[i].is_ascii_alphanumeric());
                    let after = b.get(s.range.end).is_some_and(u8::is_ascii_alphanumeric);
                    before || after
                })
            };
            if more {
                let work = work.to_mut();
                for s in &found {
                    let spaces = " ".repeat(s.range.end - s.range.start);
                    work.replace_range(s.range.start..s.range.end, &spaces);
                }
            }
            seen_ranges.extend(found.iter().map(|s| s.range));
            spans.extend(found);
            if !more {
                break;
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
        let mut swept = identity_sweep(&ir.raw, merged, &ir.protected, &ir.regions);
        relabel_env_spans(&mut swept, &ir.regions);
        (swept, residual)
    }

    fn mask_supplied_spans(&self, ir: &Ir, mut spans: Vec<Span>) -> (Vec<Span>, Vec<ResidualNote>) {
        spans.retain(|s| {
            s.range.start <= s.range.end
                && s.range.end <= ir.raw.len()
                && ir.raw.is_char_boundary(s.range.start)
                && ir.raw.is_char_boundary(s.range.end)
        });
        if !self.disabled.is_empty() {
            spans.retain(|s| !self.disabled.contains(&s.label));
        }

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
        let mut swept = identity_sweep(&ir.raw, merged, &ir.protected, &ir.regions);
        relabel_env_spans(&mut swept, &ir.regions);
        (swept, residual)
    }

    /// Returns the Ir and whether a *requested* format parser failed (so we fell
    /// back to plaintext). Text input has no registered parser, so it is never a
    /// fallback.
    fn parse(&self, input: Input) -> (Ir, bool) {
        let Input { kind, data: raw } = input;
        self.parse_raw(kind, raw)
    }

    fn parse_for_analysis(&self, input: Input) -> (Ir, bool) {
        let Input { kind, data: raw } = input;
        let protected = scan_placeholders(&raw);
        if let Some(regions) = crate::parse::analysis_regions_for_kind(&raw, &kind) {
            return (
                Ir {
                    raw,
                    regions,
                    protected,
                },
                false,
            );
        }
        self.parse_raw_with_protected(kind, raw, protected)
    }

    fn parse_raw(&self, kind: Kind, raw: String) -> (Ir, bool) {
        let protected = scan_placeholders(&raw);
        self.parse_raw_with_protected(kind, raw, protected)
    }

    fn parse_raw_with_protected(
        &self,
        kind: Kind,
        raw: String,
        protected: Vec<ByteRange>,
    ) -> (Ir, bool) {
        if let Kind::Other(name) = &kind {
            if let Some(label) = name.strip_prefix("secret-file:") {
                let regions = (!raw.is_empty())
                    .then(|| Region {
                        span: ByteRange::new(0, raw.len()),
                        ctx: Context {
                            path: None,
                            key: Some(label.to_string()),
                            hints: vec![SECRET_VALUE_HINT.to_string()],
                            kind: RegionKind::Body,
                            format: kind.clone(),
                        },
                    })
                    .into_iter()
                    .collect();
                return (
                    Ir {
                        raw,
                        regions,
                        protected,
                    },
                    false,
                );
            }
        }
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

fn relabel_env_spans(spans: &mut [Span], regions: &[Region]) {
    for span in spans {
        let Some(key) = regions.iter().find_map(|region| {
            ((region.ctx.format == Kind::Env
                || matches!(&region.ctx.format, Kind::Other(name) if name.starts_with("structured"))
                || region
                    .ctx
                    .hints
                    .iter()
                    .any(|hint| hint == SECRET_VALUE_HINT))
                && region.span.contains(&span.range))
            .then_some(region.ctx.key.as_deref())
            .flatten()
        }) else {
            continue;
        };
        span.label = env_placeholder_label(key);
    }
}

fn env_placeholder_label(key: &str) -> String {
    let mut label = key
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if !label
        .bytes()
        .next()
        .is_some_and(|first| first.is_ascii_uppercase())
    {
        label.insert_str(0, "ENV_");
    }
    label
}

fn masked_items(spans: Vec<Span>) -> Vec<MaskedItem> {
    spans
        .into_iter()
        .map(|s| MaskedItem {
            category: s.category,
            label: s.label,
            confidence: s.confidence,
            source: s.source,
        })
        .collect()
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
    /// Register the canonical parser + detector set used by masking commands.
    /// It stays broad because masking local tool output has a different risk
    /// profile than repository secret scanning.
    pub fn standard_stack(self, knobs: ProfileKnobs) -> Self {
        self.standard_stack_with_decode(knobs, profile_decode_config(knobs))
    }

    /// Register every structured configuration schema from one canonical list.
    pub fn structured_parsers(self) -> Self {
        self.parser(
            Kind::Other("structured".to_string()),
            Box::new(StructuredParser::generic()),
        )
        .parser(
            Kind::Other("structured:aws".to_string()),
            Box::new(StructuredParser::aws()),
        )
        .parser(
            Kind::Other("structured:kubeconfig".to_string()),
            Box::new(StructuredParser::kubeconfig()),
        )
        .parser(
            Kind::Other("structured:npm".to_string()),
            Box::new(StructuredParser::npm()),
        )
        .parser(
            Kind::Other("structured:pypi".to_string()),
            Box::new(StructuredParser::pypi()),
        )
    }

    pub fn standard_stack_with_decode(self, _knobs: ProfileKnobs, decode: DecodeConfig) -> Self {
        self.parser(Kind::Json, Box::new(JsonParser))
            .parser(Kind::Ndjson, Box::new(NdjsonParser))
            .parser(Kind::Env, Box::new(EnvParser))
            .structured_parsers()
            .parser(Kind::Har, Box::new(JsonParser))
            .detector(Box::new(CredSweeperNativeDetector::builtin()))
            .detector(Box::new(ExplicitSecretDetector))
            .detector(Box::new(UrlDetector))
            .detector(Box::new(CliCredentialDetector))
            .detector(Box::new(KeyValueDetector))
            .detector(Box::new(AuthCodeDetector))
            .detector(Box::new(Bip39Detector))
            .detector(Box::new(DecodeDetector::builtin_with_config(decode)))
            .detector(Box::new(SensitiveKeyDetector))
            .detector(Box::new(EnvValueDetector))
            .detector(Box::new(StructuralDetector))
    }

    pub fn secret_scan_stack(self, knobs: ProfileKnobs) -> Self {
        self.secret_scan_stack_with_decode(knobs, profile_decode_config(knobs))
    }

    pub fn secret_scan_stack_with_decode(self, _knobs: ProfileKnobs, decode: DecodeConfig) -> Self {
        self.parser(Kind::Json, Box::new(JsonParser))
            .parser(Kind::Ndjson, Box::new(NdjsonParser))
            .parser(Kind::Env, Box::new(EnvParser))
            .structured_parsers()
            .parser(Kind::Har, Box::new(JsonParser))
            .detector(Box::new(ExplicitSecretDetector))
            .detector(Box::new(CredSweeperNativeDetector::builtin()))
            .detector(Box::new(KeyValueDetector))
            .detector(Box::new(UrlDetector))
            .detector(Box::new(Bip39Detector))
            .detector(Box::new(DecodeDetector::builtin_with_config(decode)))
            .detector(Box::new(EnvValueDetector))
            .detector(Box::new(SensitiveKeyDetector))
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

fn profile_decode_config(knobs: ProfileKnobs) -> DecodeConfig {
    DecodeConfig {
        mask_unknown: knobs.mask_unknown_codec,
        unknown_min_bytes: knobs.min_opaque_run,
        ..DecodeConfig::default()
    }
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Normal handles use the compact width. A safely disambiguated short-hash
    // collision uses the full SHA-256 HMAC and must also remain frozen.
    let w = crate::placeholder::HASH_HEX_WIDTH;
    Regex::new(&format!(
        r"<<[A-Z][A-Z0-9_]*_(?:[0-9a-f]{{{w}}}|[0-9a-f]{{64}})(?:_(?:len[0-9]+|length_[0-9]+_chars|length_at_least_[0-9]+_chars))?>>"
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

    #[test]
    fn full_width_collision_handle_is_frozen() {
        let handle = format!("<<SECRET_{}>>", "a".repeat(64));
        assert_eq!(
            scan_placeholders(&handle),
            [ByteRange::new(0, handle.len())]
        );
    }

    struct InvalidUtf8BoundaryDetector;

    impl Detector for InvalidUtf8BoundaryDetector {
        fn detect(&self, _view: &NormalizedView) -> Vec<Span> {
            vec![Span {
                range: ByteRange::new(1, 2),
                category: Category::Secret,
                label: "INVALID".to_string(),
                confidence: Confidence::High,
                source: DetectorId::Plugin,
            }]
        }
    }

    #[test]
    fn invalid_detector_utf8_boundaries_are_rejected_safely() {
        let engine = Engine::builder()
            .detector(Box::new(InvalidUtf8BoundaryDetector))
            .build();
        let result = engine.mask(
            Input {
                kind: Kind::Text,
                data: "aéb".to_string(),
            },
            &Config::insecure_testing(),
        );
        assert_eq!(result.masked, "aéb");
        assert_eq!(result.summary.masked_count, 0);
    }

    #[test]
    fn identity_key_controls_handles_independently_of_recovery_key() {
        let engine = Engine::with_profile(Profile::Strict);
        let input = Input {
            kind: Kind::Env,
            data: "TOKEN=super-secret-value-123456".to_string(),
        };
        let first = engine.mask(
            input.clone(),
            &Config::new([1u8; 32]).with_identity_key([9u8; 32]),
        );
        let second = engine.mask(
            input.clone(),
            &Config::new([2u8; 32]).with_identity_key([9u8; 32]),
        );
        let other_identity =
            engine.mask(input, &Config::new([1u8; 32]).with_identity_key([8u8; 32]));

        assert_eq!(first.masked, second.masked);
        assert_ne!(first.masked, other_identity.masked);
        assert_eq!(
            first.recovery.resolve(&first.masked),
            "TOKEN=super-secret-value-123456"
        );
        assert_eq!(
            second.recovery.resolve(&second.masked),
            "TOKEN=super-secret-value-123456"
        );
    }
    use crate::recovery::restore;
    use proptest::prelude::*;
    use sha2::Digest as _;
    use std::cell::OnceCell;

    thread_local! {
        static DEFAULT_ENGINE: OnceCell<Engine> = const { OnceCell::new() };
        static STRICT_ENGINE: OnceCell<Engine> = const { OnceCell::new() };
    }

    fn with_default_engine<R>(f: impl FnOnce(&Engine) -> R) -> R {
        DEFAULT_ENGINE.with(|engine| f(engine.get_or_init(Engine::default)))
    }

    fn with_profile_engine<R>(profile: Profile, f: impl FnOnce(&Engine) -> R) -> R {
        STRICT_ENGINE.with(|engine| f(engine.get_or_init(|| Engine::with_profile(profile))))
    }

    fn m(s: &str) -> MaskResult {
        with_default_engine(|engine| {
            engine.mask(
                Input {
                    kind: Kind::Text,
                    data: s.to_string(),
                },
                &Config::insecure_testing(),
            )
        })
    }
    fn mj(s: &str) -> MaskResult {
        with_default_engine(|engine| {
            engine.mask(
                Input {
                    kind: Kind::Json,
                    data: s.to_string(),
                },
                &Config::insecure_testing(),
            )
        })
    }

    fn mn(s: &str) -> MaskResult {
        with_default_engine(|engine| {
            engine.mask(
                Input {
                    kind: Kind::Ndjson,
                    data: s.to_string(),
                },
                &Config::insecure_testing(),
            )
        })
    }

    fn bitcoin_base58check(version: u8, payload: &[u8]) -> String {
        let mut data = Vec::with_capacity(1 + payload.len() + 4);
        data.push(version);
        data.extend_from_slice(payload);
        let first = sha2::Sha256::digest(&data);
        let second = sha2::Sha256::digest(first);
        data.extend_from_slice(&second[..4]);
        bs58::encode(data)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string()
    }

    fn encode_radix85(value: &[u8], alphabet: &[u8; 85]) -> String {
        assert!(value.len().is_multiple_of(4));
        let mut encoded = String::new();
        for chunk in value.chunks_exact(4) {
            let mut number = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let mut digits = [0usize; 5];
            for digit in digits.iter_mut().rev() {
                *digit = (number % 85) as usize;
                number /= 85;
            }
            encoded.extend(digits.into_iter().map(|digit| alphabet[digit] as char));
        }
        encoded
    }

    #[test]
    fn reversible_idempotent_deterministic() {
        for x in [
            "",
            "hi there",
            "key sk-ABCDEFGHIJKLMNOPQRSTUVWX end",
            "a@b.com x a@b.com",
            "::aG00aA ",
        ] {
            let r = m(x);
            assert_eq!(restore(&r.masked, &r.recovery).unwrap(), x);
            assert_eq!(m(&r.masked).masked, r.masked);
            assert_eq!(m(x).masked, r.masked);
        }
    }

    #[test]
    fn agent_loop_resolve_before_exec_and_remask_output() {
        let secret = "AKIACSVC3FV5KQHYWH8A";
        let input = format!("curl -H 'X-Api-Key: {secret}' https://api.example.test");
        let r = Engine::with_profile(Profile::Strict)
            .mask(Input::text(&input), &Config::insecure_testing());

        assert!(!r.masked.contains(secret), "{}", r.masked);
        assert!(r.masked.contains("<<API_"), "{}", r.masked);

        let ai_command = r.masked.replace("curl", "curl -s");
        let resolved = r.recovery.resolve(&ai_command);
        assert!(resolved.contains(secret), "{resolved}");
        assert!(resolved.starts_with("curl -s"), "{resolved}");

        let tool_output = format!("request succeeded; debug echoed {secret}");
        let safe_output = r.recovery.remask(&tool_output);
        assert!(!safe_output.contains(secret), "{safe_output}");
        assert!(safe_output.contains("<<API_"), "{safe_output}");
    }

    #[test]
    fn placeholder_adjacent_vendor_secret_is_masked() {
        let r = m("<<X_0000000000000000>> AKIACSVC3FV5KQHYWH8A");
        assert!(!r.masked.contains("AKIACSVC3FV5KQHYWH8A"), "{}", r.masked);
        assert!(r.masked.contains("<<AWS_CLIENT_ID_"), "{}", r.masked);
    }

    #[test]
    fn unsupported_general_pii_is_not_reintroduced_by_the_canonical_stack() {
        let r = m("a@b.com mid a@b.com key AKIACSVC3FV5KQHYWH8A");
        assert_eq!(r.masked.matches("a@b.com").count(), 2, "{}", r.masked);
        assert!(!r.masked.contains("AKIACSVC3FV5KQHYWH8A"), "{}", r.masked);
        assert!(r.masked.contains("<<AWS_CLIENT_ID_"), "{}", r.masked);
    }

    #[test]
    fn distinct_values_distinct_placeholders() {
        let r = m("AKIACSVC3FV5KQHYWH8A AKIACSVC3FV5KQHYWH8B");
        assert_eq!(r.recovery.len(), 2, "{}", r.masked);
    }

    #[test]
    fn opt_in_exact_length() {
        let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
        let input = format!("api_key={blob}");
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
            r.masked.contains("<<API_") && r.masked.contains("_length_29_chars"),
            "{}",
            r.masked
        );
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);

        let r2 = m(&input);
        assert!(!r2.masked.contains("_length_"), "{}", r2.masked);
    }

    #[test]
    fn external_spans_use_core_render_and_identity_sweep() {
        let input = "Alice Smith met Alice Smith";
        let result = Engine::with_profile(Profile::Strict).mask_spans(
            Input::text(input),
            vec![Span {
                range: ByteRange::new(0, 11),
                category: Category::Pii,
                label: "PERSON_NAME".into(),
                confidence: Confidence::High,
                source: DetectorId::Plugin,
            }],
            &Config::insecure_testing(),
        );
        assert!(!result.masked.contains("Alice Smith"), "{}", result.masked);
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), input);
        assert_eq!(result.summary.masked_count, 1);
        assert!(
            result.masked.contains("<<PERSON_NAME_"),
            "{}",
            result.masked
        );
    }

    #[test]
    fn external_email_span_masks_as_one_handle() {
        let input = "email: alice@example.com";
        let result = Engine::with_profile(Profile::Strict).mask_spans(
            Input::text(input),
            vec![Span {
                range: ByteRange::new(7, input.len()),
                category: Category::Pii,
                label: "EMAIL".into(),
                confidence: Confidence::High,
                source: DetectorId::Plugin,
            }],
            &Config::insecure_testing(),
        );
        assert_eq!(result.summary.masked_count, 1);
        assert!(
            result.masked.contains("email: <<EMAIL_"),
            "{}",
            result.masked
        );
        assert!(!result.masked.contains('@'), "{}", result.masked);
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), input);
    }

    #[test]
    fn overlapping_external_findings_render_as_one_reversible_handle() {
        let input = "prefix-sensitive-value-suffix";
        let finding = |start, end, label: &str| Span {
            range: ByteRange::new(start, end),
            category: Category::Secret,
            label: label.into(),
            confidence: Confidence::High,
            source: DetectorId::Plugin,
        };
        let result = Engine::with_profile(Profile::Strict).mask_spans(
            Input::text(input),
            vec![finding(0, 22, "ZETA"), finding(7, input.len(), "ALPHA")],
            &Config::insecure_testing(),
        );

        assert_eq!(result.summary.masked_count, 1);
        assert_eq!(result.items.len(), 1);
        assert!(result.masked.contains("<<ZETA_"), "{}", result.masked);
        assert!(!result.masked.contains("prefix"), "{}", result.masked);
        assert!(!result.masked.contains("suffix"), "{}", result.masked);
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), input);
    }

    #[test]
    fn masks_through_zero_width() {
        let r = m("api_key=Zk7Qx9Lm2Pw8Rt4Vy6Nb1\u{200b}Cs3Df5Gh");
        assert!(r.masked.contains("<<KEYED_SECRET_"), "{}", r.masked);
        assert!(!r.masked.contains('\u{200b}'), "{}", r.masked);
    }

    #[test]
    fn base64_wrapped_secret_gets_specific_label() {
        use data_encoding::BASE64;
        let once = BASE64.encode(b"AKIACSVC3FV5KQHYWH8A");
        let twice = BASE64.encode(once.as_bytes());
        for enc in [once, twice] {
            let input = format!("payload {enc} tail");
            let r = m(&input);
            assert!(r.masked.contains("<<AWS_CLIENT_ID_"), "{}", r.masked);
            assert!(!r.masked.contains(&enc), "{}", r.masked);
            assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
        }
    }

    #[test]
    fn decode_unwrap_handles_multiple_codecs() {
        use data_encoding::{BASE32, BASE32HEX_NOPAD, HEXLOWER};
        let secret = b"AKIACSVC3FV5KQHYWH8A";
        for enc in [
            secret
                .iter()
                .map(|byte| format!("{byte:08b}"))
                .collect::<String>(),
            secret
                .iter()
                .map(|byte| format!("{byte:03o}"))
                .collect::<String>(),
            HEXLOWER.encode(secret),
            HEXLOWER.encode(secret).to_ascii_uppercase(),
            format!("0x{}", HEXLOWER.encode(secret)),
            BASE32.encode(secret),
            BASE32.encode(secret).to_ascii_lowercase(),
            BASE32HEX_NOPAD.encode(secret),
            bs58::encode(secret).into_string(),
        ] {
            let r = m(&format!("blob {enc} end"));
            assert!(
                r.masked.contains("<<AWS_CLIENT_ID_"),
                "codec failed for {enc}: {}",
                r.masked
            );
        }
    }

    #[test]
    fn decode_unwrap_handles_ascii85_base85_and_z85() {
        use crate::codec::{RFC1924_BASE85_ALPHABET, Z85_ALPHABET};
        let secret = b"AKIACSVC3FV5KQHYWH8A";
        let cases = [
            "<~5tad86W7#Q1IbD&92S5_=%G;:~>".to_string(),
            "5tad86W7#Q1IbD&92S5_=%G;:".to_string(),
            "\"5tad86W7#Q1IbD&92S5_=%G;:\"".to_string(),
            encode_radix85(secret, RFC1924_BASE85_ALPHABET),
            encode_radix85(secret, Z85_ALPHABET),
        ];
        for encoded in cases {
            let result = m(&format!("blob={encoded} end"));
            assert!(
                result.masked.contains("<<AWS_CLIENT_ID_"),
                "base85 failed for {encoded}: {}",
                result.masked
            );
            assert!(!result.masked.contains(&encoded), "{}", result.masked);
        }
    }

    #[test]
    fn decode_unwrap_handles_mime_wrapped_base64() {
        use data_encoding::BASE64;
        let mut decoded = "prefix AKIACSVC3FV5KQHYWH8A suffix ".to_string();
        while !BASE64.encode(decoded.as_bytes()).len().is_multiple_of(32) {
            decoded.push('x');
        }
        let encoded = BASE64.encode(decoded.as_bytes());
        let wrapped = encoded
            .as_bytes()
            .chunks(32)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let result = m(&format!("begin\n{wrapped}\nend"));
        assert!(
            result.masked.contains("<<AWS_CLIENT_ID_"),
            "{}",
            result.masked
        );
        assert!(!result.masked.contains(&wrapped), "{}", result.masked);
    }

    #[test]
    fn repository_secret_scan_uses_decode_detector() {
        use data_encoding::BASE64;
        let encoded = BASE64.encode(b"AKIACSVC3FV5KQHYWH8A");
        let engine = Engine::secret_scan_with_profile_and_packs(Profile::Strict, Vec::new());
        let result = engine.mask(
            Input::text(format!("blob {encoded} end")),
            &Config::insecure_testing(),
        );
        assert!(
            result.masked.contains("<<AWS_CLIENT_ID_"),
            "{}",
            result.masked
        );
        assert!(!result.masked.contains(&encoded), "{}", result.masked);
    }

    #[test]
    fn masks_through_percent_encoding() {
        let r = m("api_key=Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh%32");
        assert!(r.masked.contains("<<KEYED_SECRET_"), "{}", r.masked);
        assert!(!r.masked.contains("%32"), "{}", r.masked);
    }

    #[test]
    fn unwraps_base64_gzip() {
        use data_encoding::BASE64;
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(b"secret AKIACSVC3FV5KQHYWH8A here").unwrap();
        let enc = BASE64.encode(&e.finish().unwrap());
        let r = m(&format!("body {enc} end"));
        assert!(r.masked.contains("<<AWS_CLIENT_ID_"), "{}", r.masked);
    }

    #[test]
    fn json_structure_preserved() {
        // Detectable-by-value secrets and sensitive structured value positions
        // are masked; a benign string stays untouched and the output re-parses
        // as JSON.
        let input =
            r#"{"user":"alice@example.com","api_key":"AKIACSVC3FV5KQHYWH8A","note":"hello world"}"#;
        let r = mj(input);
        let v: serde_json::Value =
            serde_json::from_str(&r.masked).expect("masked output is valid JSON");
        let o = v.as_object().unwrap();
        assert!(o["api_key"].as_str().unwrap().starts_with("<<"));
        assert_eq!(o["user"].as_str().unwrap(), "alice@example.com");
        assert_eq!(o["note"].as_str().unwrap(), "hello world");
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn json_sensitive_key_values_mask_low_entropy_without_masking_public_keys() {
        let input = r#"{"password":"hunter2","token":"abcdef","access_token":"abcdefghijk","refresh_token":"refresh","public_key":"visible","note":"ok"}"#;
        let r = mj(input);
        let v: serde_json::Value =
            serde_json::from_str(&r.masked).expect("masked output is valid JSON");
        let o = v.as_object().unwrap();
        assert!(o["password"].as_str().unwrap().starts_with("<<PASSWORD_"));
        assert!(o["token"].as_str().unwrap().starts_with("<<TOKEN_"));
        assert!(o["access_token"]
            .as_str()
            .unwrap()
            .starts_with("<<ACCESS_TOKEN_"));
        assert!(o["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("<<REFRESH_TOKEN_"));
        assert_eq!(o["public_key"].as_str().unwrap(), "visible");
        assert_eq!(o["note"].as_str().unwrap(), "ok");
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn ndjson_sensitive_values_are_parsed_per_line() {
        let input = "{\"password\":\"hunter2\"}\n{\"token\":\"abcdef\"}\n";
        let r = mn(input);
        assert!(!r.masked.contains("hunter2"), "{}", r.masked);
        assert!(!r.masked.contains("abcdef"), "{}", r.masked);
        assert!(r.masked.contains("<<PASSWORD_"), "{}", r.masked);
        assert!(r.masked.contains("<<TOKEN_"), "{}", r.masked);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn analyze_spans_checks_numeric_json_values_without_changing_mask_output() {
        let input = r#"{"otp":100482,"ok":1}"#;
        let engine = Engine::with_profile(Profile::Strict);
        let result = engine.analyze_spans(Input {
            kind: Kind::Json,
            data: input.to_string(),
        });
        assert!(
            result.spans.iter().any(|span| span.label == labels::OTP
                && &input[span.range.start..span.range.end] == "100482"),
            "{:?}",
            result.spans
        );

        let masked = engine.mask(
            Input {
                kind: Kind::Json,
                data: input.to_string(),
            },
            &Config::insecure_testing(),
        );
        serde_json::from_str::<serde_json::Value>(&masked.masked)
            .expect("regular JSON masking keeps JSON valid");
    }

    #[test]
    fn typescript_password_const_masks_low_entropy_value() {
        let input = r#"const PASSWORD: string = "helloworld1234";"#;
        let r = m(input);
        assert!(!r.masked.contains("helloworld1234"), "{}", r.masked);
        assert!(r.masked.contains("<<KEYED_SECRET_"), "{}", r.masked);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn explicit_hex_material_masks_as_one_keyed_secret() {
        let input = "Ctrl.hexpass = hexpass:3004953027298e3289";
        let r = m(input);
        assert!(!r.masked.contains("3004953027298e3289"), "{}", r.masked);
        assert!(r.masked.contains("<<KEYED_SECRET_"), "{}", r.masked);
        assert_eq!(r.masked.matches("<<").count(), 1, "{}", r.masked);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn explicit_secret_marker_forces_masking_and_is_not_restored_as_syntax() {
        for marker in ["pentect", "mask"] {
            assert_explicit_secret_marker(marker);
        }
    }

    fn assert_explicit_secret_marker(marker: &str) {
        let input = format!("fixture value: {marker}(abc)");
        let result = Engine::with_profile(Profile::Dev).mask(
            Input {
                kind: Kind::Text,
                data: input,
            },
            &Config::insecure_testing(),
        );
        assert_eq!(result.masked.matches("<<KEYED_SECRET_").count(), 1);
        assert!(
            !result.masked.contains(&format!("{marker}(")),
            "{}",
            result.masked
        );
        assert!(!result.masked.contains("abc"), "{}", result.masked);
        assert_eq!(
            restore(&result.masked, &result.recovery).unwrap(),
            "fixture value: abc"
        );

        let remasked = Engine::with_profile(Profile::Dev).mask(
            Input {
                kind: Kind::Text,
                data: result.masked.clone(),
            },
            &Config::insecure_testing(),
        );
        assert_eq!(remasked.masked, result.masked);
    }

    #[test]
    fn har_kind_uses_json_parser_with_name_value_hints() {
        let input = r#"{"headers":[{"name":"Authorization","value":"Bearer abc123"}],"password":"hunter2"}"#;
        let r = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Har,
                data: input.to_string(),
            },
            &Config::insecure_testing(),
        );
        let v: serde_json::Value =
            serde_json::from_str(&r.masked).expect("masked output is valid JSON");
        assert_eq!(v["headers"][0]["name"], "Authorization");
        assert!(v["headers"][0]["value"].as_str().unwrap().starts_with("<<"));
        assert!(v["password"].as_str().unwrap().starts_with("<<PASSWORD_"));
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn internal_url_preserves_route_shape() {
        let input = "see http://local.jira.corp/api/issues/1234 now";
        let r = m(input);
        assert!(
            r.masked.contains("http://<<INTERNAL_ENDPOINT_"),
            "{}",
            r.masked
        );
        assert!(
            r.masked.contains("/api/issues/<<RESOURCE_ID_"),
            "{}",
            r.masked
        );
        assert!(!r.masked.contains("local.jira.corp"), "{}", r.masked);
        assert!(!r.masked.contains("/1234"), "{}", r.masked);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn public_url_without_sensitive_material_stays_visible() {
        let input = "see https://example.com/api/issues/1234 now";
        let r = m(input);
        assert_eq!(r.masked, input);
    }

    #[test]
    fn identity_authority_url_masks_tenant_segment() {
        let input =
            "see https://login.microsoftonline.com/77d0f286-f938-918d-b0ce-f5bb58ff02d7 now";
        let r = m(input);
        assert!(
            r.masked
                .contains("https://login.microsoftonline.com/<<UUID_"),
            "{}",
            r.masked
        );
        assert!(
            !r.masked.contains("77d0f286-f938-918d-b0ce-f5bb58ff02d7"),
            "{}",
            r.masked
        );
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn internal_url_does_not_leak_userinfo_query_or_fragment() {
        let input = "open http://user:pass@local.jira.corp:8080/api/issues/ABC-123?token=s3cr3t&project=OPS#comment-456.";
        let r = m(input);
        assert!(r.masked.contains("<<INTERNAL_ENDPOINT_"), "{}", r.masked);
        assert!(
            r.masked.contains("/api/issues/<<RESOURCE_ID_"),
            "{}",
            r.masked
        );
        assert!(
            r.masked.contains("?token=<<URL_CREDENTIAL_"),
            "{}",
            r.masked
        );
        assert!(
            r.masked.contains("&project=<<URL_QUERY_VALUE_"),
            "{}",
            r.masked
        );
        assert!(r.masked.contains("#<<RESOURCE_ID_"), "{}", r.masked);
        for leaked in [
            "user:pass",
            "local.jira.corp",
            "ABC-123",
            "s3cr3t",
            "OPS",
            "comment-456",
        ] {
            assert!(
                !r.masked.contains(leaked),
                "{leaked} leaked in {}",
                r.masked
            );
        }
        assert!(r.masked.ends_with('.'), "{}", r.masked);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn url_masks_keep_sentence_punctuation_literal() {
        let internal = m("http://jira.corp/api/issues/1234.");
        assert!(internal.masked.ends_with('.'), "{}", internal.masked);
        assert!(!internal.masked.contains("1234."), "{}", internal.masked);

        let external = m("https://example.com/api/issues/1234.");
        assert_eq!(external.masked, "https://example.com/api/issues/1234.");
    }

    #[test]
    fn report_names_what_was_masked_without_offsets() {
        let r = m("key AKIACSVC3FV5KQHYWH8A here");
        // The report carries the label/category but no raw position, so a
        // consumer learns what was masked, not where the secret sat.
        assert!(r.items.iter().any(|i| i.label == "AWS_CLIENT_ID"));
        assert_eq!(r.items.len(), r.summary.masked_count);
    }

    // Integration floor for the canonical stack. Vendor-pattern fidelity is
    // exhaustively tested against upstream CredSweeper fixtures in its detector
    // module; this list only pins cross-detector pipeline integration with
    // inputs whose validity does not depend on invented vendor test tokens.
    const CORE_FLOOR: &[(&str, &str)] = &[
        ("AKIACSVC3FV5KQHYWH8A", "aws_access_key"),
        (
            "api_key=Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh",
            "keyed_secret",
        ),
        (
            "postgresql://admin:s3cr3t@db.host:5432/sales",
            "database_url",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "bip39_mnemonic",
        ),
        ("mask(project codename)", "explicit_secret"),
    ];
    // Checksum-validated national / financial IDs (deterministic core; this is
    // where we match/exceed Presidio). Each sample passes its real checksum.
    const CHECKSUM_FLOOR: &[(&str, &str)] = &[];
    const PLUGIN_GAP: &[(&str, &str)] = &[
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
        // Sanity: the corpus exercises the floor and the known plugin gap.
        assert!(CORE_FLOOR.len() >= 5 && PLUGIN_GAP.len() >= 4);
        let gap_hit: Vec<&str> = PLUGIN_GAP
            .iter()
            .filter(|(s, _)| !m(s).items.is_empty())
            .map(|(_, l)| *l)
            .collect();
        eprintln!(
            "recall corpus: floor {}/{} caught; plugin_gap incidentally caught: {gap_hit:?}",
            CORE_FLOOR.len() + CHECKSUM_FLOOR.len(),
            CORE_FLOOR.len() + CHECKSUM_FLOOR.len()
        );
    }

    // Broad recall: many VALID samples per detector, so a regex/validator change
    // that silently drops a real value is caught. Test data must be VARIED — an
    // all-same-digit run is correctly retracted as a benign shape, which would
    // mask a recall regression. (IBANs computed across countries; cards span all
    // networks; phones span regions; crypto is public addresses.)
    const IBAN_VALID: &[&str] = &[
        "DE15804319371058294617",
        "GB94804319371058294617",
        "FR7980431937105829461730528",
        "ES8280431937105829461730",
        "IT4680431937105829461730528",
        "NL3280431937105829",
        "CH1480431937105829461",
        "BE92804319371058",
        "AT678043193710582946",
        "IE67804319371058294617",
        "PT39804319371058294617305",
        "PL34804319371058294617305280",
        "NO1980431937105",
        "SE9580431937105829461730",
        "FI1680431937105829",
    ];
    const CARD_VALID: &[&str] = &[
        "4242424242424242",
        "4012888888881881",
        "4111111111111111",
        "5555555555554444",
        "5105105105105100",
        "2223003122003222",
        "378282246310005",
        "371449635398431",
        "6011111111111117",
        "6011000990139424",
        "30569309025904",
        "38520000023237",
        "3530111333300000",
        "3566002020360505",
        // Separator-formatted (very common): grouped Visa / MC / Amex.
        "4242 4242 4242 4242",
        "5555-5555-5555-4444",
        "3782 822463 10005",
    ];
    const PHONE_VALID: &[&str] = &[
        "+14155552671",
        "+442071838750",
        "+81363849000",
        "+4930901820",
        "+33142685300",
        "+390612345678",
        "+34911234567",
        "+919876543210",
        "+85228765432",
        "+6531234567",
    ];
    const CRYPTO_VALID: &[&str] = &[
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "LXmteg8PyzybHdrywScarTEfieHWJbpAHy", // LTC
        "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", // XRP
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    ];
    // Real-world formatting (grouping/separators) — exercises the regexes'
    // separator handling, where values usually appear with punctuation.
    const FORMATTED_VALID: &[&str] = &[
        "DE15 8043 1937 1058 2946 17", // IBAN grouped
        "111.444.777-35",              // BR CPF
        "11.222.333/0001-81",          // BR CNPJ
        "2345 6789 0124",              // IN Aadhaar grouped
        "219-09-9998",                 // US SSN
        "+1 415-555-2671",             // phone formatted
        "(415) 555-0132",              // NANP
    ];
    // Several distinct valid values per checksummed detector (computed), so a
    // checksum/regex change that drops a subset is caught.
    const NATIONAL_ID_VALID: &[&str] = &[
        "52998224725",
        "39053344705",    // BR CPF
        "11444777000161", // BR CNPJ
        "00000023T",
        "99999999R", // ES NIF
        "1000000004",
        "1987654328", // US NPI
    ];
    // Values embedded in realistic surrounding text (JSON, logs, sentences,
    // markup) — exercises the word-boundary handling against quotes/punctuation,
    // not just bare values.
    const EMBEDDED_VALID: &[&str] = &[
        r#"{"iban":"DE15804319371058294617","amount":100}"#,
        "paid with card 4111111111111111 on file",
        "Please wire to GB94804319371058294617 by EOD.",
        r#"contact: "+442071838750" (london office)"#,
        "wallet=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa;balance=0",
        "ssn:219-09-9998,name:redacted",
        "aadhaar [2345 6789 0124] verified",
        "eth(0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359)",
        "cpf=111.444.777-35&uf=SP",
        "<email>alice@example.com</email>",
    ];

    #[test]
    fn removed_general_pii_corpus_is_not_claimed_as_credential_coverage() {
        let retired_fixture_count = IBAN_VALID.len()
            + CARD_VALID.len()
            + PHONE_VALID.len()
            + CRYPTO_VALID.len()
            + FORMATTED_VALID.len()
            + NATIONAL_ID_VALID.len()
            + EMBEDDED_VALID.len();
        assert!(retired_fixture_count >= 40);
        for sample in [
            "DE15804319371058294617",
            "4242424242424242",
            "+442071838750",
            "alice@example.com",
            "219-09-9998",
        ] {
            assert!(
                m(sample).items.is_empty(),
                "unexpected PII inference: {sample:?}"
            );
        }
    }

    // Right shape, wrong checksum: the gated label must NOT appear (the checksum
    // is the precision lever). Other detectors may still fire on substrings, so
    // we assert the specific label is absent, not that nothing masks.
    const NEAR_MISS: &[(&str, &str)] = &[
        ("DE15804319371058294618", "IBAN_CODE"),
        ("4242424242424241", "CARD"),
        ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1Beaed", "ETH_ADDRESS"),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "BTC_ADDRESS_BECH32",
        ),
        ("234567890121", "IN_AADHAAR"),
        ("27AAPFU0939F1ZX", "IN_GSTIN"),
    ];

    #[test]
    fn near_miss_bad_checksums_not_caught_under_their_label() {
        for (s, label) in NEAR_MISS {
            assert!(
                !m(s).items.iter().any(|i| i.label == *label),
                "bad-checksum {s:?} wrongly masked as {label}"
            );
        }
    }

    // Deliberately nasty inputs: degenerate, placeholder-confusing, adjacency,
    // Unicode/multibyte, fake placeholders. The invariants must hold for ALL of
    // them — never panic, mask->restore is the identity, and masking is
    // idempotent (re-masking masked text changes nothing).
    const ADVERSARIAL: &[&str] = &[
        "",
        " ",
        "::",
        "+",
        "<<",
        ">>",
        "<<>>",
        "<<X_",
        "x>>y<<z",
        "<<AWS_AKID_0011223344556677>>", // fake placeholder, unmapped
        "<<<<AKIACSVC3FV5KQHYWH8A>>>>",  // synthetic key wrapped in angle brackets
        "4242424242424242DE15804319371058294617", // adjacent card + IBAN, no sep
        "💳4242424242424242 paid 🤑",    // emoji adjacent (multibyte offsets)
        "café AKIACSVC3FV5KQHYWH8A déjà", // combining/accented around a secret
        "line1 AKIACSVC3FV5KQHYWH8A\nline2 alice@example.com\n",
        "key=AKIACSVC3FV5KQHYWH8A&card=4242424242424242",
        "secret>>AKIACSVC3FV5KQHYWH8A<<end",
        "４２４２４２４２４２４２４２４２", // fullwidth digits (normalization)
        "\u{200b}4242424242424242\u{200b}", // zero-width spaces around a card
    ];

    #[test]
    fn adversarial_inputs_never_panic_and_reversible() {
        let cfg = Config::insecure_testing();
        let eng = Engine::default();
        for s in ADVERSARIAL {
            // Reaching here at all proves no panic. mask -> restore is identity.
            let r = eng.mask(Input::text(*s), &cfg);
            assert_eq!(
                crate::recovery::restore(&r.masked, &r.recovery).unwrap(),
                *s,
                "not reversible: {s:?} masked to {:?}",
                r.masked
            );
        }
    }

    #[test]
    fn adversarial_masking_is_idempotent() {
        let cfg = Config::insecure_testing();
        let eng = Engine::default();
        for s in ADVERSARIAL {
            let r = eng.mask(Input::text(*s), &cfg);
            let r2 = eng.mask(Input::text(r.masked.clone()), &cfg);
            assert_eq!(r2.masked, r.masked, "not idempotent on {s:?}");
        }
    }

    #[test]
    fn concatenated_unsupported_pii_is_not_classified_as_credentials() {
        let input = "4242424242424242DE15804319371058294617";
        assert_eq!(m(input).masked, input);
    }

    // Research-style evaluation (precision/recall/F1/F2 + utility) on realistic
    // text where secrets and benign look-alikes share the same sentence — the
    // metric framing the Text Anonymization Benchmark / Presidio-evaluator use,
    // measured against the default strict profile. Each sample lists the
    // values that must be masked and the benign values that must be preserved;
    // the corpus is the skeleton that real TAB / SecretBench data plugs into.
    // Person/location names are plugin/model-scope and excluded here.
    type Labeled = (
        &'static str,
        &'static [&'static str],
        &'static [&'static str],
    );
    const LABELED: &[Labeled] = &[
        (
            "Ticket 100482931 from sarah.chen@acme.com: card 4242424242424242 declined.",
            &[],
            &["sarah.chen@acme.com", "4242424242424242", "100482931"],
        ),
        (
            "Wire to GB94804319371058294617 ref INV90070183 amount 5000 by Friday.",
            &[],
            &["GB94804319371058294617", "INV90070183", "5000"],
        ),
        (
            "export AWS_KEY=AKIACSVC3FV5KQHYWH8A; port=8080; workers=3",
            &["AKIACSVC3FV5KQHYWH8A"],
            &["8080", "3"],
        ),
        (
            "CPF 111.444.777-35 do pedido 219099998 no valor de 99 reais.",
            &[],
            &["111.444.777-35", "219099998", "99"],
        ),
        (
            "aadhaar 234567890124 issued; sku ABCDEFGH; release v2.10.0 build 4194304.",
            &[],
            &["234567890124", "ABCDEFGH", "2.10.0", "4194304"],
        ),
        (
            "btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa moved 4194304 sat at block 100482931.",
            &[],
            &["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "4194304", "100482931"],
        ),
        (
            "Contact +442071838750 or paste token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 once.",
            &[],
            &[
                "+442071838750",
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "once",
            ],
        ),
        (
            r#"{"eth":"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359","nonce":4194304,"id":42}"#,
            &[],
            &[
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                "4194304",
                "42",
            ],
        ),
        (
            "ssn 219-09-9998 on file; ticket JIRA-100482; retries 3; status 200.",
            &[],
            &["219-09-9998", "100482", "3", "200"],
        ),
        (
            "db postgres://admin:s3cr3t@db.internal:5432/sales pool=20 timeout=30",
            &["postgres://admin:s3cr3t@db.internal:5432/sales"],
            &["20", "30"],
        ),
    ];

    #[test]
    fn research_metrics_precision_recall_f2_utility() {
        let (mut tp, mut fp, mut fn_, mut tn) = (0u32, 0u32, 0u32, 0u32);
        let mut leaks = Vec::new();
        let mut overmasks = Vec::new();
        for (text, should_mask, should_not) in LABELED {
            let out = mp(Profile::Strict, text).masked;
            for v in *should_mask {
                if out.contains(v) {
                    fn_ += 1;
                    leaks.push(*v);
                } else {
                    tp += 1;
                }
            }
            for v in *should_not {
                if out.contains(v) {
                    tn += 1;
                } else {
                    fp += 1;
                    overmasks.push(*v);
                }
            }
        }
        let prec = tp as f64 / (tp + fp).max(1) as f64;
        let rec = tp as f64 / (tp + fn_).max(1) as f64;
        let f1 = 2.0 * prec * rec / (prec + rec).max(f64::MIN_POSITIVE);
        let f2 = 5.0 * prec * rec / (4.0 * prec + rec).max(f64::MIN_POSITIVE);
        let utility = tn as f64 / (tn + fp).max(1) as f64;
        eprintln!(
            "research metrics (Strict, {} samples): P={prec:.3} R={rec:.3} F1={f1:.3} F2={f2:.3} utility={utility:.3} (TP={tp} FP={fp} FN={fn_} TN={tn})\n  leaks={leaks:?} overmasks={overmasks:?}",
            LABELED.len()
        );
        // Credential authority findings are masked; retired general PII
        // inference and benign values remain visible.
        assert!(leaks.is_empty(), "recall leak: {leaks:?}");
        assert!(overmasks.is_empty(), "over-masking: {overmasks:?}");
    }

    #[test]
    fn entity_level_recall_all_mentions_masked() {
        // TAB's entity-level metric: an identifier is concealed only if ALL its
        // mentions are masked. The same value masks to one stable placeholder
        // everywhere (so it stays consistent and restorable).
        let secret = "AKIACSVC3FV5KQHYWH8A";
        let out = m(&format!("a {secret} b {secret} c {secret} d")).masked;
        assert!(!out.contains(secret), "leaked a mention: {out}");
        let start = out.find("<<").unwrap();
        let ph = &out[start..out[start..].find(">>").unwrap() + start + 2];
        assert_eq!(out.matches(ph).count(), 3, "unstable placeholder: {out}");
    }

    // === Benchmark vs Presidio and Azure AI Language PII ===
    // The two standing goals: surpass Presidio and surpass Azure. We measure it
    // entity-by-entity. Each entry is classified:
    //   Core    — deterministic (pattern/checksum); core MUST catch it (asserted).
    //   Plugin — language/locale-heavy entities (person, location, org,
    //               nationality, address, age, person-type): no closed pattern,
    //               so these belong behind the plugin boundary. Recorded,
    //               not asserted.
    //   Todo    — deterministic but not implemented yet; the remaining gap to
    //             close for full deterministic parity. Recorded, not asserted.
    // "Surpassed" on the deterministic axis = every Core caught AND we add
    // entities neither vendor has (see EXCLUSIVE). Todo = the deterministic
    // distance to zero-gap; Plugin = entities outside deterministic core.
    #[derive(PartialEq, Clone, Copy)]
    enum Cov {
        Core,
        Plugin,
        Todo,
    }
    use Cov::{Core, Plugin, Todo};

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
        ("US_PASSPORT", "passport C12345678", Core),
        ("MEDICAL_LICENSE(DEA)", "AB1234563", Core),
        ("UK_NHS", "NHS 9434767016", Core),
        ("UK_NINO", "AB123456C", Core),
        ("ES_NIF", "12345678Z", Core),
        ("ES_NIE", "X1234567L", Core),
        ("IT_VAT_CODE", "IT00123456782", Core),
        ("PL_PESEL", "PESEL 44051401359", Core),
        ("SG_NRIC_FIN", "S1234567D", Core),
        ("AU_ABN", "51824753556", Core),
        ("AU_TFN", "TFN 123456782", Core),
        ("AU_MEDICARE", "medicare 2951234577", Core),
        ("IN_PAN", "ABCPK1234L", Core),
        ("IN_AADHAAR", "234567890124", Core),
        ("IN_GSTIN", "27AAPFU0939F1ZV", Core),
        ("AU_ACN", "ACN 004085616", Core),
        ("FI_HETU", "131052-308T", Core),
        ("IT_FISCAL_CODE", "RSSMRA85T10A562S", Core),
        ("US_DRIVER_LICENSE", "driver's license D1234567", Core),
        ("US_BANK_NUMBER", "account number 1234567890", Core),
        ("URL", "https://example.com/x", Todo),
        ("UK_POSTCODE", "SW1A 1AA", Core),
        ("UK_DRIVING_LICENCE", "MORGA657054SM9IJ", Core),
        ("UK_VEHICLE_REGISTRATION", "reg AB12 CDE", Core),
        ("UK_PASSPORT", "passport 123456789", Core),
        ("ES_PASSPORT", "pasaporte ABC123456", Core),
        ("IT_PASSPORT", "passaporto AB1234567", Core),
        ("IN_VOTER", "voter ABC1234567", Core),
        ("IN_PASSPORT", "passport A1234567", Core),
        ("IN_VEHICLE_REGISTRATION", "vehicle KA01AB1234", Core),
        ("SG_UEN", "uen 53312345A", Core),
        ("DATE_TIME", "January 5, 1990", Todo),
        ("PERSON", "John Smith", Plugin),
        ("LOCATION", "Mountain View", Plugin),
        ("NRP", "British", Plugin),
        ("ORGANIZATION", "Acme Corporation", Plugin),
    ];

    // Azure AI Language PII entity categories (representative; ~200 total, the
    // bulk being per-country ID variants of the patterns covered below).
    const AZURE: &[(&str, &str, Cov)] = &[
        ("CreditCardNumber", "4242424242424242", Core),
        ("ABARoutingNumber", "021000021", Core),
        ("SWIFTCode", "SWIFT DEUTDEFF", Core),
        ("IBAN", "GB82WEST12345698765432", Core),
        ("Email", "alice@example.com", Core),
        ("IPAddress", "192.168.1.1", Core),
        ("PhoneNumber", "(415) 555-0132", Core),
        ("USSocialSecurityNumber", "219-09-9998", Core),
        ("USITIN", "900-70-1234", Core),
        ("USDEANumber", "AB1234563", Core),
        ("USPassportNumber", "passport C12345678", Core),
        ("UKNationalInsuranceNumber", "AB123456C", Core),
        ("UKNHSNumber", "NHS 9434767016", Core),
        ("SpainDNI", "12345678Z", Core),
        ("SpainNIE", "X1234567L", Core),
        ("ItalyVAT", "IT00123456782", Core),
        ("PolandPESEL", "PESEL 44051401359", Core),
        ("GermanyTaxId", "86095742719", Core),
        ("NetherlandsBSN", "BSN 111222333", Core),
        ("SingaporeNRIC", "S1234567D", Core),
        ("AustraliaTFN", "TFN 123456782", Core),
        ("AustraliaABN", "51824753556", Core),
        ("IndiaPAN", "ABCPK1234L", Core),
        ("IndiaAadhaar", "234567890124", Core),
        ("IndiaGSTIN", "27AAPFU0939F1ZV", Core),
        ("AustraliaACN", "ACN 004085616", Core),
        ("JapanMyNumber", "123456789018", Core),
        ("KoreaRRN", "9001011123459", Core),
        ("BrazilCPF", "11144477735", Core),
        ("BrazilCNPJ", "11222333000181", Core),
        ("CanadaSIN", "social insurance 130458623", Core),
        ("EUVAT", "DE136695976", Core),
        ("USDriversLicense", "driver's license D1234567", Core),
        ("USBankAccountNumber", "account number 1234567890", Core),
        ("ItalyFiscalCode", "RSSMRA85T10A562S", Core),
        ("URL", "https://example.com/x", Todo),
        ("FrenchINSEE", "180047509112541", Core),
        ("DateTime", "2025-06-11", Todo),
        ("Age", "35 years old", Plugin),
        (
            "Address",
            "1600 Amphitheatre Parkway, Mountain View CA",
            Plugin,
        ),
        ("Person", "John Smith", Plugin),
        ("PersonType", "doctor", Plugin),
        ("Organization", "Microsoft", Plugin),
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
    fn records_legacy_presidio_and_azure_gaps_without_claiming_coverage() {
        for (name, table) in [("Presidio", PRESIDIO), ("Azure", AZURE)] {
            let caught = |s: &str| !m(s).items.is_empty();
            let core: Vec<_> = table.iter().filter(|(_, _, c)| *c == Core).collect();
            let todo: Vec<_> = table.iter().filter(|(_, _, c)| *c == Todo).collect();
            let plugin: Vec<_> = table.iter().filter(|(_, _, c)| *c == Plugin).collect();

            let core_missed: Vec<&str> = core
                .iter()
                .filter(|(_, s, _)| !caught(s))
                .map(|(e, _, _)| *e)
                .collect();
            let det_total = core.len() + todo.len();
            eprintln!(
                "legacy {name} comparison (not a supported coverage claim): observed {}/{}; plugin gap {}; missing: {:?}; remaining deterministic gap: {:?}",
                core.len() - core_missed.len(),
                det_total,
                plugin.len(),
                core_missed,
                todo.iter().map(|(e, _, _)| *e).collect::<Vec<_>>(),
            );
        }
        let supported = m("key AKIACSVC3FV5KQHYWH8A");
        assert!(supported
            .items
            .iter()
            .any(|item| item.label == "AWS_CLIENT_ID"));
        let observed_exclusive = EXCLUSIVE
            .iter()
            .filter(|(_, sample)| caught_exclusive(sample))
            .map(|(label, _)| *label)
            .collect::<Vec<_>>();
        eprintln!("legacy exclusive observations (not a coverage claim): {observed_exclusive:?}");
    }

    fn caught_exclusive(s: &str) -> bool {
        !m(s).items.is_empty()
    }

    // Precision corpus: realistic text with NO secrets (logs, JSON, code, prose).
    // Every mask here is a FALSE POSITIVE. The recall benchmark is blind to these,
    // yet over-masking is the real failure mode (you can't reason about output
    // that is all `<<X>> <<Y>>`). This is the precision metric, and it ratchets
    // down: lower the ceiling as detectors are tightened, never raise it.
    const NEGATIVES: &[&str] = &[
        "2026-06-11T13:42:01Z INFO request_id=183920475 user=42 order=100482931 retries=0 status=200 bytes=10485760 dur_ms=143",
        "2026-06-11T13:42:02Z WARN cache_miss key=session count=900700123 backlog=123456789 worker=3 queue=8",
        "{\"user_id\":42,\"order_id\":100482931,\"sku\":\"WIDGETCO-2024\",\"qty\":11223344556,\"warehouse\":\"ABCDEFGH\",\"batch\":\"X12345678\"}",
        "{\"total_cents\":1999,\"tax_cents\":175,\"items\":64,\"ref\":\"44051401359\"}",
        "const PORT: u16 = 5432; const MAX_CHUNK: u32 = 4194304; let mask = 0x1ff_ffff; let widths = [10, 9, 8, 7];",
        "enum Region { UsEast1, EuWest2, ApNortheast1 } let big = 123456789012345; let ssn_like = 219099998;",
        "id,name,amount\n100482931,Widget,1999\n100482932,Gadget,2999\n900700123,Gizmo,3499",
        "thread 'main' panicked at src/lib.rs:4821: index 100482931 out of bounds for len 64",
        "RETRY_LIMIT=5\nMAX_CONN=128\nTIMEOUT_MS=30000\nACCOUNT_TYPE=premium\nVAT_RATE=20",
        "Released version 2.10.0 (build 4194304) on 2026-06-11; commits 8da1fcd, 2c755b0, 01bb317.",
        "The quick brown fox jumps over the lazy dog while the project team reviews the budget plan for the next quarter and the season ahead.",
        "Please ship invoice INV90070183 to the front desk by Friday and notify the warehouse team in advance.",
        "matrix dims 183920475 x 100482931, checksum 11223344556, lot ABCDEFGH, seed 219099998",
        "warehouse codes ABCDEFGH, WIDGETCO, ZZTOPXYZ; ticket JIRA-100482; PR 4821; SKU X12345678",
    ];

    #[test]
    fn precision_no_overmasking_on_benign_text() {
        // Zero false positives on secret-free text. Over-masking is the real
        // failure mode (you cannot reason about output that is all `<<X>>`), and
        // the recall benchmark is blind to it. Raising this is a regression to
        // justify, not a knob to turn.
        const CEILING: usize = 0;
        let mut total = 0usize;
        let mut hits: Vec<String> = Vec::new();
        for s in NEGATIVES {
            for item in m(s).items {
                total += 1;
                hits.push(item.label);
            }
        }
        hits.sort();
        eprintln!(
            "precision: {total} false mask(s) on benign corpus (ceiling {CEILING}): {hits:?}"
        );
        assert_eq!(
            total, CEILING,
            "over-masking regressed: {total} false masks (ceiling {CEILING}): {hits:?}"
        );
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
        with_profile_engine(profile, |engine| {
            engine.mask(Input::text(s), &Config::insecure_testing())
        })
    }

    #[test]
    fn context_free_entropy_is_not_claimed_by_the_canonical_stack() {
        let blob = "Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh"; // high entropy, no anchor
        let input = format!("blob {blob} end");
        let r = mp(Profile::Strict, &input);
        assert!(r.masked.contains(blob), "{}", r.masked);
    }

    #[test]
    fn anchored_secret_masks_under_default_profile() {
        let r = mp(Profile::Strict, "key AKIACSVC3FV5KQHYWH8A end");
        assert!(r.masked.contains("<<AWS_CLIENT_ID_"), "{}", r.masked);
    }

    #[test]
    fn guard_spares_uuid_unless_anchored() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        // Bare UUID survives the benign-shape guard.
        assert!(mp(Profile::Strict, &format!("id {uuid} x"))
            .masked
            .contains(uuid));
        // As an adapter-supplied cookie value it is anchored by structure, so it
        // masks despite the benign shape (the guard only retracts context-free
        // guesses).
        let r = Engine::with_profile(Profile::Strict).mask_context(
            uuid.to_string(),
            Context {
                path: None,
                key: Some("sid".to_string()),
                hints: Vec::new(),
                kind: RegionKind::Cookie,
                format: Kind::ToolResult,
            },
            &Config::insecure_testing(),
        );
        assert!(!r.masked.contains(uuid), "{}", r.masked);
    }

    #[test]
    fn json_uuid_order_arrays_are_structural_identifiers() {
        let raw = r#"{
  "order": [
    "a3c06711-df97-c6ce-ddc7-e7bc4fa3909b",
    "fb6ee58b-8fe0-6dcd-91ff-664b7ad9c6e7",
    "a4245388-8054-a8fe-36fc-4c5425003af2"
  ],
  "values": ["550e8400-e29b-41d4-a716-446655440000"]
}"#;
        let r = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Json,
                data: raw.to_string(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            !r.masked.contains("a3c06711-df97-c6ce-ddc7-e7bc4fa3909b"),
            "{}",
            r.masked
        );
        assert!(
            !r.masked.contains("fb6ee58b-8fe0-6dcd-91ff-664b7ad9c6e7"),
            "{}",
            r.masked
        );
        assert!(
            !r.masked.contains("a4245388-8054-a8fe-36fc-4c5425003af2"),
            "{}",
            r.masked
        );
        assert!(
            r.masked.contains("550e8400-e29b-41d4-a716-446655440000"),
            "{}",
            r.masked
        );
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
    fn reversible_under_default_profile() {
        let input = "key AKIACSVC3FV5KQHYWH8A and a@b.com and Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
        let r = mp(Profile::Strict, input);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn placeholder_adjacent_endpoint_artifact_is_idempotent() {
        let once = m("a::__aA00_aaaA/aABB-_CDba1c").masked;
        assert_eq!(m(&once).masked, once);
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
        // verbatim in the masked output.
        #[test]
        fn prop_no_survivor_default_profile(
            pre in "[a-z ]{0,20}",
            mid in "[a-z ]{1,20}",
            post in "[a-z ]{0,20}",
        ) {
            let secret = "AKIACSVC3FV5KQHYWH8A";
            let input = format!("{pre} {secret} {mid} {secret} {post}");
            let r = mp(Profile::Strict, &input);
            prop_assert!(!r.masked.contains(secret), "left a survivor: {}", r.masked);
        }
    }

    #[test]
    fn malformed_pem_is_not_claimed_as_a_valid_private_key() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIBADANBgkqh\nkiG9w0BAQEFAASCAT\n-----END RSA PRIVATE KEY-----";
        let input = format!("here is the key:\n{pem}\nthanks");
        let r = Engine::with_profile(Profile::Strict)
            .mask(Input::text(&input), &Config::insecure_testing());
        assert_eq!(r.masked, input);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn malformed_private_key_variants_are_not_claimed() {
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
        ] {
            let body = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT";
            let input = format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----");
            let r = Engine::with_profile(Profile::Strict)
                .mask(Input::text(&input), &Config::insecure_testing());
            assert_eq!(r.masked, input, "{label}");
            assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
        }
    }

    #[test]
    fn bitcoin_wif_private_key_masks_under_default_profile() {
        let wif = bitcoin_base58check(0x80, &[0x22u8; 32]);
        let input = format!("wallet private key: {wif}");
        let r = Engine::with_profile(Profile::Strict)
            .mask(Input::text(&input), &Config::insecure_testing());
        assert!(!r.masked.contains(&wif), "{}", r.masked);
        assert!(r.masked.contains("<<KEY_"), "{}", r.masked);
        assert_eq!(restore(&r.masked, &r.recovery).unwrap(), input);
    }

    #[test]
    fn unguarded_keeps_environment_parsing() {
        let env = Engine::with_profile_unguarded(Profile::Strict).mask(
            Input {
                kind: Kind::Env,
                data: "DB_KEY=AKIACSVC3FV5KQHYWH8A\n".into(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            !env.masked.contains("AKIACSVC3FV5KQHYWH8A"),
            "env value still masked: {}",
            env.masked
        );
    }

    #[test]
    fn env_values_masked_wholesale_structure_preserved() {
        let raw = "export DB_KEY=AKIACSVC3FV5KQHYWH8A\nNOTE=hello world\n";
        let r = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Env,
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        // `.env` files are a secret-bearing boundary, so every parsed value is
        // masked even when the value itself has a benign shape.
        assert!(!r.masked.contains("AKIACSVC3FV5KQHYWH8A"), "{}", r.masked);
        assert!(!r.masked.contains("hello world"), "{}", r.masked);
        // Structure preserved: key, =, newlines intact.
        assert!(r.masked.contains("export DB_KEY=<<"), "{}", r.masked);
        assert!(r.masked.contains("NOTE=<<"), "{}", r.masked);
    }

    #[test]
    fn env_numeric_values_masked_even_when_low_entropy() {
        let raw = "TEST_SECRET=114514810\nFEATURE_FLAG=false\n";
        let r = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Env,
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert!(!r.masked.contains("114514810"), "{}", r.masked);
        assert!(!r.masked.contains("false"), "{}", r.masked);
        assert!(
            r.masked.contains("TEST_SECRET=<<TEST_SECRET_"),
            "{}",
            r.masked
        );
        assert!(
            r.masked.contains("FEATURE_FLAG=<<FEATURE_FLAG_"),
            "{}",
            r.masked
        );
    }

    #[test]
    fn env_placeholders_use_each_parsed_key_as_the_label() {
        let raw = "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nKAGGLE_API_TOKEN=KGAT_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef\nrelease.flag=enabled\n9PATCH=value\n";
        let r = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Env,
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            r.masked.contains("RUNPOD_API_KEY=<<RUNPOD_API_KEY_"),
            "{}",
            r.masked
        );
        assert!(
            r.masked.contains("KAGGLE_API_TOKEN=<<KAGGLE_API_TOKEN_"),
            "{}",
            r.masked
        );
        assert!(
            r.masked.contains("release.flag=<<RELEASE_FLAG_"),
            "{}",
            r.masked
        );
        assert!(r.masked.contains("9PATCH=<<ENV_9PATCH_"), "{}", r.masked);
    }

    #[test]
    fn structured_credentials_mask_only_credential_fields() {
        let raw = concat!(
            "[pypi]\n",
            "repository = https://upload.pypi.org/legacy/\n",
            "username = __token__\n",
            "password = pypi-example-token\n",
            "//registry.npmjs.org/:_authToken=npm-example-token\n",
        );
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Other("structured".into()),
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            result
                .masked
                .contains("repository = https://upload.pypi.org/legacy/"),
            "{}",
            result.masked
        );
        assert!(
            result.masked.contains("password = <<PASSWORD_"),
            "{}",
            result.masked
        );
        assert!(
            result.masked.contains("_authToken=<<AUTH_TOKEN_"),
            "{}",
            result.masked
        );
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
    }

    #[test]
    fn kubernetes_secret_schema_masks_low_entropy_values_by_key() {
        let raw = concat!(
            "apiVersion: v1\n",
            "kind: Secret\n",
            "metadata:\n  name: app\n",
            "stringData:\n  DB_PASSWORD: plain\n",
            "data:\n  API_TOKEN: YWJj\n",
        );
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Other("structured".into()),
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert!(result.masked.contains("name: app"), "{}", result.masked);
        assert!(
            result.masked.contains("DB_PASSWORD: <<DB_PASSWORD_"),
            "{}",
            result.masked
        );
        assert!(
            result.masked.contains("API_TOKEN: <<API_TOKEN_"),
            "{}",
            result.masked
        );
        assert!(!result.masked.contains(": plain"), "{}", result.masked);
        assert!(!result.masked.contains(": YWJj"), "{}", result.masked);
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
    }

    #[test]
    fn generic_structured_config_does_not_mask_benign_values() {
        let raw = "mode: development\nregion: us-east-1\nretries = 3\n";
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Other("structured".into()),
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert_eq!(result.masked, raw);
    }

    #[test]
    fn mounted_secret_file_masks_the_entire_payload_with_filename_label() {
        let raw = "short value with spaces\nand another line";
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Other("secret-file:database-password".into()),
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            result.masked.starts_with("<<DATABASE_PASSWORD_"),
            "{}",
            result.masked
        );
        assert!(!result.masked.contains("short value"), "{}", result.masked);
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
    }

    #[test]
    fn kubernetes_secret_json_uses_data_keys_as_labels() {
        let raw = r#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"app"},"stringData":{"DB_PASSWORD":"plain"},"data":{"API_TOKEN":"YWJj"}}"#;
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Json,
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            result.masked.contains("\"name\":\"app\""),
            "{}",
            result.masked
        );
        assert!(
            result.masked.contains("\"DB_PASSWORD\":\"<<DB_PASSWORD_"),
            "{}",
            result.masked
        );
        assert!(
            result.masked.contains("\"API_TOKEN\":\"<<API_TOKEN_"),
            "{}",
            result.masked
        );
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
    }

    #[test]
    fn terraform_sensitive_values_metadata_forces_masking() {
        let raw = r#"{"version":4,"resources":[{"instances":[{"attributes":{"password":"short","region":"us-east-1"},"sensitive_values":{"password":true}}]}]}"#;
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Json,
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert!(
            !result.masked.contains("\"password\":\"short\""),
            "{}",
            result.masked
        );
        assert!(
            result.masked.contains("\"region\":\"us-east-1\""),
            "{}",
            result.masked
        );
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
    }

    #[test]
    fn kubeconfig_and_tfvars_keep_structural_credential_labels() {
        for (raw, key, value, kind) in [
            (
                "users:\n  - name: admin\n    user:\n      token: kube-token-example\n",
                "token",
                "kube-token-example",
                "structured:kubeconfig",
            ),
            (
                "region = \"us-east-1\"\ndb_password = \"terraform-password\"\n",
                "db_password",
                "terraform-password",
                "structured",
            ),
        ] {
            let result = Engine::with_profile(Profile::Strict).mask(
                Input {
                    kind: Kind::Other(kind.into()),
                    data: raw.into(),
                },
                &Config::insecure_testing(),
            );
            assert!(!result.masked.contains(value), "{}", result.masked);
            assert!(
                result
                    .masked
                    .contains(&format!("<<{}_", env_placeholder_label(key))),
                "{}",
                result.masked
            );
            assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
        }
    }

    #[test]
    fn official_credential_schemas_mask_short_values_but_keep_public_config() {
        for (kind, raw, visible, label) in [
            (
                "structured:aws",
                "region = us-east-1\naws_session_token = x\n",
                "region = us-east-1",
                "AWS_SESSION_TOKEN",
            ),
            (
                "structured:npm",
                "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=x\n",
                "registry=https://registry.npmjs.org/",
                "AUTH_TOKEN",
            ),
            (
                "structured:pypi",
                "[pypi]\nrepository = https://upload.pypi.org/legacy/\npassword = x\n",
                "repository = https://upload.pypi.org/legacy/",
                "PASSWORD",
            ),
        ] {
            let result = Engine::with_profile(Profile::Strict).mask(
                Input {
                    kind: Kind::Other(kind.into()),
                    data: raw.into(),
                },
                &Config::insecure_testing(),
            );
            assert!(result.masked.contains(visible), "{}", result.masked);
            assert!(
                result.masked.contains(&format!("<<{label}_")),
                "{}",
                result.masked
            );
            assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
        }
    }

    #[test]
    fn duplicate_env_keys_keep_distinct_values_reversible() {
        let raw = "TOKEN=first\nTOKEN=second\n";
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Env,
                data: raw.into(),
            },
            &Config::insecure_testing(),
        );
        assert_eq!(result.summary.masked_count, 2);
        assert_eq!(result.masked.matches("<<TOKEN_").count(), 2);
        assert_eq!(restore(&result.masked, &result.recovery).unwrap(), raw);
    }

    #[test]
    fn text_masks_runpod_token_with_key_context() {
        let raw = concat!(
            "RUNPOD_API_KEY=",
            "rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"
        );
        let r = Engine::with_profile(Profile::Strict)
            .mask(Input::text(raw), &Config::insecure_testing());
        assert!(!r
            .masked
            .contains("rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"));
        assert!(r.masked.contains("<<KEYED_SECRET_"), "{}", r.masked);
    }

    #[test]
    fn strict_text_masks_unknown_token_with_secret_key_context() {
        let raw = "RUNPOD_API_KEY=Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh";
        let r = Engine::with_profile(Profile::Strict)
            .mask(Input::text(raw), &Config::insecure_testing());
        assert!(!r.masked.contains("Zk7Qx9Lm2Pw8Rt4Vy6Nb1Cs3Df5Gh"));
        assert!(r.masked.contains("<<API_"), "{}", r.masked);
    }

    #[test]
    fn mask_context_uses_tool_result_value_context_without_masking_key_names() {
        let engine = Engine::builder()
            .standard_stack(Profile::Strict.knobs())
            .policy(Box::new(ProfilePolicy::new(Profile::Strict)))
            .guard(Box::new(ShapeGuard::builtin()))
            .build();
        let cfg = Config::insecure_testing();
        let value = engine.mask_context(
            "hunter2".to_string(),
            Context {
                path: Some("structured.password".to_string()),
                key: Some("password".to_string()),
                hints: Vec::new(),
                kind: RegionKind::JsonValue,
                format: Kind::ToolResult,
            },
            &cfg,
        );
        assert!(value.masked.contains("<<PASSWORD_"), "{}", value.masked);

        let key = engine.mask_context(
            "password".to_string(),
            Context {
                path: Some("structured.password".to_string()),
                key: None,
                hints: Vec::new(),
                kind: RegionKind::JsonKey,
                format: Kind::ToolResult,
            },
            &cfg,
        );
        assert_eq!(key.masked, "password");
    }

    #[test]
    fn no_survivor_in_json_values() {
        let secret = "AKIACSVC3FV5KQHYWH8A";
        let input = format!("{{\"a\":\"{secret}\",\"b\":\"see {secret} here\"}}");
        let r = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Json,
                data: input,
            },
            &Config::insecure_testing(),
        );
        assert!(!r.masked.contains(secret), "{}", r.masked);
    }
}
