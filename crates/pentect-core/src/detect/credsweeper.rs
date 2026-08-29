use super::credsweeper_ml::{self, MlInput, RuleSeverity};
use super::Detector;
use crate::model::{
    ByteRange, Category, Confidence, Context, DetectorId, Kind, Region, RegionKind, Span,
};
use crate::normalize::NormalizedView;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use crypto_bigint::BoxedUint;
use crypto_primes::{is_prime, Flavor};
use data_encoding::{BASE32, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};
use fancy_regex::Regex as FancyRegex;
use num_bigint::BigUint;
use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
use pkcs1::{der::Decode, RsaPrivateKey};
use pkcs8::der::{
    asn1::{AnyRef, OctetStringRef, UintRef},
    Reader, Tag, Tagged,
};
use pkcs8::PrivateKeyInfoRef;
use regex::Regex as RustRegex;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, OnceLock};

const SECRET_CONFIG_JSON: &str =
    include_str!("../../vendors/credsweeper-assets/secret/config.json");
const ML_CONFIG_JSON: &str =
    include_str!("../../vendors/credsweeper-assets/ml_model/ml_config.json");
const ML_MODEL_ONNX: &[u8] =
    include_bytes!("../../vendors/credsweeper-assets/ml_model/ml_model.onnx");
const MORPHEME_CHECKLIST: &str =
    include_str!("../../vendors/credsweeper-assets/common/morpheme_checklist.txt");
const KEYWORD_CHECKLIST: &str =
    include_str!("../../vendors/credsweeper-assets/common/keyword_checklist.txt");

include!(concat!(env!("OUT_DIR"), "/credsweeper_rules.rs"));

static BUILTIN: LazyLock<CredSweeperNativeDetector> = LazyLock::new(|| {
    CredSweeperNativeDetector::compile_builtin().expect("embedded CredSweeper assets compile")
});
static BUILTIN_STATS: LazyLock<CredSweeperNativeStats> =
    LazyLock::new(|| audit_builtin_stats().expect("embedded CredSweeper assets compile"));
static REGEX_WARMED: OnceLock<()> = OnceLock::new();
static CREDSWEEPER_BASE64: LazyLock<data_encoding::Encoding> = LazyLock::new(|| {
    let mut specification = BASE64.specification();
    // Python's base64.b64decode(validate=True), used by CredSweeper, validates
    // the alphabet and padding but accepts non-zero unused trailing bits.
    specification.check_trailing_bits = false;
    specification
        .encoding()
        .expect("CredSweeper-compatible base64 specification")
});
static CREDSWEEPER_BASE32: LazyLock<data_encoding::Encoding> = LazyLock::new(|| {
    let mut specification = BASE32.specification();
    // Python's base64.b32decode, used by CredSweeper, accepts non-zero unused
    // trailing bits after otherwise valid alphabet and padding checks.
    specification.check_trailing_bits = false;
    specification
        .encoding()
        .expect("CredSweeper-compatible base32 specification")
});

#[derive(Clone)]
pub struct CredSweeperNativeDetector {
    rules: Vec<NativeRule>,
    line_prefilter: LineRulePrefilter,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredSweeperNativeStats {
    pub total_rules: usize,
    pub total_patterns: usize,
    pub compiled_patterns: usize,
    pub rust_regex_patterns: usize,
    pub fancy_regex_patterns: usize,
    pub translated_patterns: usize,
    pub enabled_patterns: usize,
    pub ml_gated_patterns: usize,
    pub unsupported_patterns: usize,
    pub total_filter_invocations: usize,
    pub unsupported_filter_invocations: usize,
    pub unsupported_filter_types: Vec<String>,
    pub ml_rules: usize,
    pub rules_yaml_bytes: usize,
    pub secret_config_json_bytes: usize,
    pub ml_config_json_bytes: usize,
    pub ml_model_onnx_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct CredSweeperWarmUpTimings {
    pub regexes: std::time::Duration,
    pub ml: std::time::Duration,
    pub verification: std::time::Duration,
    pub total: std::time::Duration,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CredSweeperFilterProbe {
    pub filter: String,
    pub value: Option<String>,
    pub line: String,
    pub value_start: usize,
    pub value_end: usize,
    #[serde(default)]
    pub variable: Option<String>,
    #[serde(default)]
    pub separator: Option<String>,
    #[serde(default)]
    pub wrap: Option<String>,
    #[serde(default)]
    pub value_leftquote: Option<String>,
    #[serde(default)]
    pub value_rightquote: Option<String>,
    #[serde(default)]
    pub previous: Option<String>,
    #[serde(default)]
    pub next: Option<String>,
    #[serde(default)]
    pub file_type: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub line_index: usize,
}

impl CredSweeperFilterProbe {
    pub fn is_filtered(&self) -> bool {
        let Some(value) = self.value.as_deref() else {
            return true;
        };
        let candidate = Candidate {
            start: self.value_start,
            end: self.value_end,
            match_end: self.value_end,
            value,
            variable_start: None,
            variable_end: None,
            variable: self.variable.as_deref(),
            separator: self.separator.as_deref(),
            wrap: self.wrap.as_deref(),
            value_leftquote: self.value_leftquote.as_deref(),
            value_rightquote: self.value_rightquote.as_deref(),
            line_data: Vec::new(),
        };
        let target = if self.target.is_empty() {
            &self.line
        } else {
            &self.target
        };
        let context = CandidateLineContext {
            start: 0,
            line: &self.line,
            previous: self.previous.as_deref(),
            next: self.next.as_deref(),
            file_type: &self.file_type,
            target,
            line_index: self.line_index,
        };
        !accept_filter_list(
            value,
            std::slice::from_ref(&self.filter),
            &candidate,
            &context,
            self.value_start,
            self.value_end,
        )
    }
}

#[derive(Clone, Debug)]
pub struct CredSweeperNativeFinding {
    pub range: ByteRange,
    pub rule_name: String,
    pub label: String,
    pub severity: String,
    pub confidence: Confidence,
    pub confidence_name: String,
    pub ml_probability: Option<f64>,
    pub value: String,
    pub value_start: usize,
    pub value_end: usize,
    pub variable: Option<String>,
    pub variable_start: Option<usize>,
    pub variable_end: Option<usize>,
    pub line_data: Vec<CredSweeperNativeRelatedFinding>,
}

impl CredSweeperNativeFinding {
    fn span(&self) -> Span {
        Span {
            range: self.range,
            category: Category::Secret,
            label: self.label.clone(),
            confidence: self.confidence,
            source: DetectorId::CredSweeper,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CredSweeperNativeRelatedFinding {
    pub range: ByteRange,
    pub value: String,
    pub value_start: usize,
    pub value_end: usize,
    pub variable: Option<String>,
    pub variable_start: Option<usize>,
    pub variable_end: Option<usize>,
}

#[derive(Clone)]
struct NativeRule {
    rule_name: String,
    label: String,
    severity: RuleSeverity,
    confidence: Confidence,
    min_line_len: usize,
    required_substrings: Vec<String>,
    filter_types: Vec<String>,
    targets: Vec<String>,
    ml_validated: bool,
    patterns: Vec<NativePattern>,
}

#[derive(Clone)]
struct NativePattern {
    matcher: PatternMatcher,
    value_capture: bool,
}

#[derive(Clone)]
enum PatternMatcher {
    Deferred(Arc<DeferredRegex>),
    Special(SpecialMatcher),
}

struct DeferredRegex {
    source: String,
    keyword_source: Option<String>,
    compiled: OnceLock<Option<CompiledRegex>>,
    compiled_keyword: OnceLock<Option<FancyRegex>>,
}

enum CompiledRegex {
    Rust(RustRegex),
    Fancy(FancyRegex),
}

#[derive(Clone)]
enum SpecialMatcher {
    AwsMulti,
    AlibabaMulti,
    GoogleMulti,
    Jwk,
    PemPrivateKey,
    Base64PrivateKey,
    Uuid,
}

impl CredSweeperNativeDetector {
    pub fn builtin() -> Self {
        BUILTIN.clone()
    }

    /// Compile deferred upstream patterns before a caller starts a bounded
    /// operation timer. Clones of the built-in detector share these caches.
    pub fn warm_up(&self) {
        let _ = self.warm_up_timed();
    }

    /// Warm cached detector state and return value-free phase timings.
    pub fn warm_up_timed(&self) -> CredSweeperWarmUpTimings {
        let total_started = std::time::Instant::now();
        // Regex OnceLocks are process-wide through the shared BUILTIN Arcs.
        // Compile independent rules in parallel, while the caller initializes
        // its thread-local ML validator. Cap workers to avoid turning startup
        // into a memory spike on large CI hosts.
        let (regexes, ml) = if REGEX_WARMED.get().is_some() {
            let ml_started = std::time::Instant::now();
            credsweeper_ml::warm_up();
            (std::time::Duration::ZERO, ml_started.elapsed())
        } else {
            std::thread::scope(|scope| {
                let regexes = scope.spawn(|| {
                    let started = std::time::Instant::now();
                    REGEX_WARMED.get_or_init(|| {
                        let workers = std::thread::available_parallelism()
                            .map_or(1, usize::from)
                            .min(8)
                            .min(self.rules.len().max(1));
                        let chunk_size = self.rules.len().div_ceil(workers);
                        std::thread::scope(|workers_scope| {
                            for rules in self.rules.chunks(chunk_size) {
                                workers_scope.spawn(move || {
                                    for rule in rules {
                                        for pattern in &rule.patterns {
                                            if let PatternMatcher::Deferred(regex) =
                                                &pattern.matcher
                                            {
                                                let _ = regex.compiled();
                                                let _ = regex.compiled_keyword();
                                            }
                                        }
                                    }
                                });
                            }
                        });
                    });
                    started.elapsed()
                });
                let ml_started = std::time::Instant::now();
                credsweeper_ml::warm_up();
                let ml = ml_started.elapsed();
                (
                    regexes.join().expect("CredSweeper regex warm-up worker"),
                    ml,
                )
            })
        };
        let verification_started = std::time::Instant::now();
        let sample = "AKIACSVC3FV5KQHYWH8A";
        let region = Region {
            span: ByteRange::new(0, sample.len()),
            ctx: Context {
                path: None,
                key: None,
                hints: Vec::new(),
                kind: RegionKind::PlainText,
                format: Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, sample);
        let _ = self.detect_findings(&view);
        CredSweeperWarmUpTimings {
            regexes,
            ml,
            verification: verification_started.elapsed(),
            total: total_started.elapsed(),
        }
    }

    pub fn builtin_stats() -> &'static CredSweeperNativeStats {
        &BUILTIN_STATS
    }

    pub fn rule_name_for_label(&self, label: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.label == label)
            .map(|rule| rule.rule_name.as_str())
    }

    fn compile_builtin() -> Result<Self, String> {
        let raw_rules = generated_raw_rules();
        let mut rules = Vec::new();
        for raw in &raw_rules {
            let values = raw.values.as_deref().unwrap_or_default();
            let use_ml = raw.use_ml.unwrap_or(false);
            let mut patterns = Vec::new();
            if raw.kind.as_deref() == Some("pattern") {
                if let Some(matcher) = translated_pattern(&raw.name) {
                    patterns.push(NativePattern {
                        matcher: PatternMatcher::Special(matcher),
                        value_capture: true,
                    });
                } else {
                    for pattern in values {
                        patterns.push(NativePattern {
                            matcher: PatternMatcher::deferred(pattern),
                            value_capture: has_named_capture(pattern, "value"),
                        });
                    }
                }
            } else if raw.kind.as_deref() == Some("keyword") {
                for value in values {
                    patterns.push(NativePattern {
                        matcher: PatternMatcher::deferred_keyword(keyword_pattern(value), value),
                        value_capture: true,
                    });
                }
            } else {
                match translated_rule(raw) {
                    Some(matcher) => {
                        patterns.push(NativePattern {
                            matcher: PatternMatcher::Special(matcher),
                            value_capture: true,
                        });
                    }
                    None => continue,
                }
            }
            if patterns.is_empty() {
                continue;
            }
            rules.push(NativeRule {
                rule_name: raw.name.clone(),
                label: normalize_label(&raw.name),
                severity: map_severity(raw.severity.as_deref()),
                confidence: map_confidence(raw.confidence.as_deref()),
                min_line_len: raw.min_line_len.unwrap_or(0),
                required_substrings: raw
                    .required_substrings
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                filter_types: raw
                    .filter_type
                    .as_ref()
                    .map(FilterList::items)
                    .unwrap_or_default(),
                targets: raw.target.clone().unwrap_or_default(),
                ml_validated: use_ml,
                patterns,
            });
        }
        let line_prefilter = LineRulePrefilter::build(&rules)?;
        Ok(Self {
            line_prefilter,
            rules,
        })
    }
}

fn audit_builtin_stats() -> Result<CredSweeperNativeStats, String> {
    let raw_rules = generated_raw_rules();
    let mut stats = CredSweeperNativeStats {
        total_rules: raw_rules.len(),
        total_patterns: 0,
        compiled_patterns: 0,
        rust_regex_patterns: 0,
        fancy_regex_patterns: 0,
        translated_patterns: 0,
        enabled_patterns: 0,
        ml_gated_patterns: 0,
        unsupported_patterns: 0,
        total_filter_invocations: 0,
        unsupported_filter_invocations: 0,
        unsupported_filter_types: Vec::new(),
        ml_rules: raw_rules
            .iter()
            .filter(|rule| rule.use_ml.unwrap_or(false))
            .count(),
        rules_yaml_bytes: GENERATED_RULES_YAML_BYTES,
        secret_config_json_bytes: SECRET_CONFIG_JSON.len(),
        ml_config_json_bytes: ML_CONFIG_JSON.len(),
        ml_model_onnx_bytes: ML_MODEL_ONNX.len(),
    };
    for raw in &raw_rules {
        for filter in raw
            .filter_type
            .as_ref()
            .map(FilterList::items)
            .unwrap_or_default()
        {
            stats.total_filter_invocations += 1;
            if !filter_has_native_handler(&filter) {
                stats.unsupported_filter_invocations += 1;
                stats
                    .unsupported_filter_types
                    .push(filter_name(&filter).to_string());
            }
        }
        let values = raw.values.as_deref().unwrap_or_default();
        stats.total_patterns += values.len();
        let mut enabled_for_rule = 0;
        match raw.kind.as_deref() {
            Some("pattern") => {
                for pattern in values {
                    match compile_pattern(pattern) {
                        Ok(PatternMatcher::Deferred(regex)) => {
                            match regex
                                .compiled
                                .get()
                                .expect("audit compiles regex")
                                .as_ref()
                                .expect("compile_pattern stores a compiled regex")
                            {
                                CompiledRegex::Rust(_) => stats.rust_regex_patterns += 1,
                                CompiledRegex::Fancy(_) => stats.fancy_regex_patterns += 1,
                            }
                            stats.compiled_patterns += 1;
                            enabled_for_rule += 1;
                        }
                        Ok(PatternMatcher::Special(_)) => unreachable!(),
                        Err(_) if translated_pattern(&raw.name).is_some() => {
                            stats.translated_patterns += 1;
                            enabled_for_rule += 1;
                        }
                        Err(_) => stats.unsupported_patterns += 1,
                    }
                }
            }
            Some("keyword") => {
                for keyword in values {
                    if compile_keyword_pattern(keyword).is_ok() {
                        stats.fancy_regex_patterns += 1;
                        stats.compiled_patterns += 1;
                        enabled_for_rule += 1;
                    } else {
                        stats.unsupported_patterns += 1;
                    }
                }
            }
            _ if translated_rule(raw).is_some() => {
                stats.translated_patterns += values.len();
                enabled_for_rule += values.len();
            }
            _ => stats.unsupported_patterns += values.len(),
        }
        stats.enabled_patterns += enabled_for_rule;
        if raw.use_ml.unwrap_or(false) {
            stats.ml_gated_patterns += enabled_for_rule;
        }
    }
    stats.unsupported_filter_types.sort();
    stats.unsupported_filter_types.dedup();
    Ok(stats)
}

fn filter_name(filter: &str) -> &str {
    filter.split_once('(').map_or(filter, |(name, _)| name)
}

fn line_git_binary_filtered(line: &str) -> bool {
    let line = line.trim();
    let bytes = line.as_bytes();
    if bytes.len() > 66 || bytes.len() < 7 || !(bytes.len() - 1).is_multiple_of(5) {
        return false;
    }
    let size = match bytes[0] {
        b'A'..=b'Z' => usize::from(bytes[0] - 64),
        b'a'..=b'z' => usize::from(bytes[0] - 70),
        _ => return false,
    };
    const BASE85: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    bytes[1..].iter().all(|byte| BASE85.contains(byte)) && (bytes.len() - 1) / 5 * 4 == size
}

fn line_uue_part_filtered(
    line: &str,
    previous_line: Option<&str>,
    next_line: Option<&str>,
) -> bool {
    if line.is_empty() {
        return true;
    }
    if !is_uue_max_line(line) {
        return false;
    }
    previous_line.is_some_and(is_uue_max_line) || next_line.is_some_and(is_uue_max_line)
}

fn is_uue_max_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() == 61
        && bytes[0] == b'M'
        && bytes[1..].iter().all(|byte| (b'!'..=b'`').contains(byte))
}

fn filter_has_native_handler(filter: &str) -> bool {
    matches!(
        filter_name(filter),
        "LineGitBinaryCheck"
            | "LineSpecificKeyCheck"
            | "LineUUEPartCheck"
            | "ValueAllowlistCheck"
            | "ValueArrayDictionaryCheck"
            | "ValueAtlassianTokenCheck"
            | "ValueBase64EncodedPem"
            | "ValueBase64KeyCheck"
            | "ValueBase64PartCheck"
            | "ValueAzureTokenCheck"
            | "ValueBase32DataCheck"
            | "ValueBech32Check"
            | "ValueBasicAuthCheck"
            | "ValueBlocklistCheck"
            | "ValueCamelCaseCheck"
            | "ValueDictionaryKeywordCheck"
            | "ValueDiscordBotCheck"
            | "ValueEntropyBase36Check"
            | "ValueEntropyBase32Check"
            | "ValueEntropyBase64Check"
            | "ValueFilePathCheck"
            | "ValueHexNumberCheck"
            | "ValueGrafanaCheck"
            | "ValueGrafanaServiceCheck"
            | "ValueGitHubCheck"
            | "ValueJsonWebKeyCheck"
            | "ValueJsonWebTokenCheck"
            | "ValueJfrogTokenCheck"
            | "ValueLastWordCheck"
            | "ValueLengthCheck"
            | "ValueMethodCheck"
            | "ValueNotPartEncodedCheck"
            | "ValueNotAllowedPatternCheck"
            | "ValueMorphemesCheck"
            | "ValueNumberCheck"
            | "ValuePatternCheck"
            | "ValueSealedSecretCheck"
            | "ValueSimilarityCheck"
            | "ValueStringTypeCheck"
            | "ValueSplitKeywordCheck"
            | "ValueTokenBase32Check"
            | "ValueTokenBase36Check"
            | "ValueTokenCheck"
    )
}

impl CredSweeperNativeDetector {
    pub fn detect_findings(&self, view: &NormalizedView) -> Vec<CredSweeperNativeFinding> {
        if !view.is_identity() {
            let raw_view = view.raw_detection_view();
            return self.detect_findings(&raw_view);
        }
        let text = view.text();
        let mut out = Vec::new();
        let mut ml_pending = Vec::new();
        let mut seen_rules = vec![false; self.rules.len()];
        let mut rule_candidates = Vec::new();
        let ml_path = credsweeper_ml::ml_path(view.region.ctx.path.as_deref());
        let ml_file_type = credsweeper_ml::ml_file_type(view.region.ctx.path.as_deref());
        let push_ctx = PushMatchCtx {
            view,
            path: &ml_path,
            file_type: &ml_file_type,
        };
        let whole_text_ctx = CandidateLineContext {
            start: 0,
            line: text,
            previous: None,
            next: None,
            file_type: &ml_file_type,
            target: text,
            line_index: 0,
        };
        let lines = LineRanges::new(text).collect::<Vec<_>>();
        for rule in &self.rules {
            if !rule_available_for_code_scan(rule) {
                continue;
            }
            if !has_whole_text_matcher(rule) {
                continue;
            }
            if text.len() < rule.min_line_len {
                continue;
            }
            for pattern in &rule.patterns {
                if let PatternMatcher::Special(matcher) = &pattern.matcher {
                    for candidate in matcher.find_whole_text(text) {
                        if candidate.line_data.is_empty() {
                            let _ = push_match(
                                &mut ml_pending,
                                &push_ctx,
                                rule,
                                &whole_text_ctx,
                                &candidate,
                            );
                        } else {
                            let (localized, physical_ctx) = localize_whole_text_candidate(
                                &candidate,
                                &lines,
                                &ml_file_type,
                                &whole_text_ctx,
                            );
                            let _ = push_match(
                                &mut ml_pending,
                                &push_ctx,
                                rule,
                                &physical_ctx,
                                &localized,
                            );
                        }
                    }
                }
            }
        }
        for (line_index, &(line_start, line)) in lines.iter().enumerate() {
            let line_body = line.trim_end_matches(['\r', '\n']);
            let previous_line = line_index
                .checked_sub(1)
                .and_then(|index| lines.get(index))
                .map(|(_, line)| line.trim_end_matches(['\r', '\n']));
            let next_line = lines
                .get(line_index + 1)
                .map(|(_, line)| line.trim_end_matches(['\r', '\n']));
            let line_ctx = CandidateLineContext {
                start: line_start,
                line: line_body,
                previous: previous_line,
                next: next_line,
                file_type: &ml_file_type,
                target: text,
                line_index,
            };
            let line_lower = LazyLower::new(line_body);
            self.line_prefilter
                .collect(&line_lower, &mut seen_rules, &mut rule_candidates);
            for &rule_index in &rule_candidates {
                let rule = &self.rules[rule_index];
                if line_body.len() < rule.min_line_len {
                    continue;
                }
                for pattern in &rule.patterns {
                    if matches!(
                        &pattern.matcher,
                        PatternMatcher::Special(matcher) if matcher.is_whole_text()
                    ) {
                        continue;
                    }
                    match &pattern.matcher {
                        PatternMatcher::Deferred(regex) => {
                            const MIN_DATA_LEN: usize = 8;
                            let mut offsets = vec![(0usize, line_body.len())];
                            let mut seen_offsets = BTreeSet::new();
                            while let Some((offset_start, offset_end)) = offsets.pop() {
                                if !seen_offsets.insert((offset_start, offset_end))
                                    || offset_start >= offset_end
                                    || offset_end > line_body.len()
                                {
                                    continue;
                                }
                                let mut candidates = regex.find(
                                    &line_body[offset_start..offset_end],
                                    pattern.value_capture,
                                );
                                for candidate in &mut candidates {
                                    candidate.shift(offset_start);
                                }
                                candidates.sort_by_key(|candidate| {
                                    (
                                        candidate.variable_start.unwrap_or(candidate.start),
                                        candidate.start,
                                        candidate.end,
                                    )
                                });
                                let mut bypass = None;
                                for candidate in candidates {
                                    let had_bypass = bypass.is_some();
                                    if let Some((bypass_start, _)) = bypass.take() {
                                        let bypass_end = candidate
                                            .variable_start
                                            .filter(|start| 0 < *start)
                                            .unwrap_or(candidate.start);
                                        if bypass_start < bypass_end
                                            && MIN_DATA_LEN < bypass_end - bypass_start
                                        {
                                            offsets.push((bypass_start, bypass_end));
                                        }
                                    }
                                    let sanitized_value = sanitize_value_capture(
                                        line_ctx.line,
                                        push_ctx.file_type,
                                        &candidate,
                                    );
                                    let accepted = push_match(
                                        &mut ml_pending,
                                        &push_ctx,
                                        rule,
                                        &line_ctx,
                                        &candidate,
                                    );
                                    if !accepted {
                                        let bypass_start = candidate
                                            .variable_end
                                            .filter(|end| offset_start < *end)
                                            .unwrap_or(candidate.end);
                                        bypass = Some((bypass_start, offset_end));
                                    } else if !had_bypass
                                        && MIN_DATA_LEN < sanitized_value.end
                                        && candidate
                                            .match_end
                                            .checked_sub(sanitized_value.end)
                                            .is_some_and(|remaining| MIN_DATA_LEN < remaining)
                                    {
                                        // CredSweeper retries the tail of a successful regex
                                        // match when the match consumed another potentially
                                        // valuable assignment (for example, two OAuth fields
                                        // in one quoted response body).
                                        bypass = Some((sanitized_value.end, offset_end));
                                    }
                                }
                                if let Some((bypass_start, bypass_end)) = bypass {
                                    if bypass_start < bypass_end {
                                        offsets.push((bypass_start, bypass_end));
                                    }
                                }
                            }
                        }
                        PatternMatcher::Special(matcher) => {
                            for m in matcher.find(line_body) {
                                let _ = push_match(&mut ml_pending, &push_ctx, rule, &line_ctx, &m);
                            }
                        }
                    }
                }
            }
            clear_seen_rules(&rule_candidates, &mut seen_rules);
        }
        push_ml_accepted(&mut out, &ml_pending);
        dedupe_findings(out)
    }
}

impl Detector for CredSweeperNativeDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let spans = self
            .detect_findings(view)
            .into_iter()
            .map(|finding| finding.span())
            .collect();
        dedupe_spans(spans)
    }
}

impl PatternMatcher {
    fn deferred(source: impl Into<String>) -> Self {
        Self::Deferred(Arc::new(DeferredRegex {
            source: source.into(),
            keyword_source: None,
            compiled: OnceLock::new(),
            compiled_keyword: OnceLock::new(),
        }))
    }

    fn deferred_keyword(source: impl Into<String>, keyword: impl Into<String>) -> Self {
        Self::Deferred(Arc::new(DeferredRegex {
            source: source.into(),
            keyword_source: Some(keyword.into()),
            compiled: OnceLock::new(),
            compiled_keyword: OnceLock::new(),
        }))
    }
}

impl DeferredRegex {
    fn compiled(&self) -> Option<&CompiledRegex> {
        self.compiled
            .get_or_init(|| {
                RustRegex::new(&self.source)
                    .map(CompiledRegex::Rust)
                    .or_else(|_| FancyRegex::new(&self.source).map(CompiledRegex::Fancy))
                    .ok()
            })
            .as_ref()
    }

    fn find<'a>(&self, text: &'a str, value_capture: bool) -> Vec<Candidate<'a>> {
        let mut out = match self.compiled() {
            Some(CompiledRegex::Rust(regex)) => regex
                .captures_iter(text)
                .filter_map(|captures| rust_candidate(&captures, value_capture))
                .collect(),
            Some(CompiledRegex::Fancy(regex)) => regex
                .captures_iter(text)
                .filter_map(Result::ok)
                .filter_map(|captures| fancy_candidate(&captures, text, value_capture))
                .map(|candidate| keyword_get_default_candidate(text, candidate))
                .collect(),
            None => Vec::new(),
        };
        if self.source.contains("IDENTIFIED") && self.source.contains(r"SET\s{1,8}PASSWORD") {
            out.extend(sql_identified_password_candidates(text));
        }
        if let Some(keyword) = self.compiled_keyword() {
            // Python's `regex` engine starts the keyword variable capture at
            // the later unquoted alternative in constructs such as
            // `String("id"), Key: String("secret")`. `fancy_regex` can keep
            // the earlier closing quote and produce `"), Key` instead. Use
            // the trailing identifier when the capture contains one unmatched
            // quote; a genuinely quoted variable contains both quote marks.
            for index in 0..out.len() {
                let reused_previous_rightquote = out[index]
                    .variable_start
                    .is_some_and(|start| out[..index].iter().any(|previous| previous.end == start));
                if reused_previous_rightquote {
                    repair_fancy_keyword_variable(&mut out[index]);
                }
                repair_nested_keyword_assignment(text, &mut out[index], keyword);
                repair_fancy_unquoted_method_preference(&mut out[index]);
                repair_quoted_comparison_variable(text, &mut out[index]);
                repair_percent_bracket_variable(&mut out[index]);
                repair_auth_scheme_value(&mut out[index]);
                repair_dictionary_key_value(&mut out[index]);
                repair_unquoted_escaped_tail(text, &mut out[index]);
            }
            out.retain(|candidate| keyword_key_right_within_upstream_limit(candidate, keyword));
            let initial_len = out.len();
            let initial_ranges = out
                .iter()
                .map(|candidate| (candidate.start, candidate.end))
                .collect::<BTreeSet<_>>();
            let initial_nonempty_variables = out
                .iter()
                .filter(|candidate| {
                    !candidate.value.is_empty()
                        && candidate.separator == Some(":")
                        && (candidate.wrap.is_none()
                            && !matches!(
                                candidate.separator,
                                Some("!=") | Some("==") | Some("!==") | Some("===") | Some("=~")
                            )
                            || keyword_candidate_is_complete(text, candidate))
                })
                .filter_map(|candidate| candidate.variable_start.zip(candidate.variable_end))
                .collect::<BTreeSet<_>>();
            let initial_consumed_ranges = out
                .iter()
                .filter(|candidate| {
                    !candidate.value.is_empty()
                        && candidate
                            .variable
                            .is_none_or(|variable| !variable.to_ascii_lowercase().contains("%5d"))
                })
                .filter_map(|candidate| {
                    candidate.variable_start.map(|start| (start, candidate.end))
                })
                .collect::<Vec<_>>();
            out.extend(keyword_set_call_candidates(text, keyword));
            out.extend(keyword_set_directive_candidates(text, keyword));
            out.extend(keyword_define_call_candidates(text, keyword));
            out.extend(keyword_directive_candidates(text, keyword));
            out.extend(keyword_percent_bracket_candidates(text, keyword));
            out.extend(keyword_url_candidates(text, keyword));
            let structured = keyword_structured_candidates(text, keyword, &out)
                .into_iter()
                .filter(|candidate| {
                    !out.iter().any(|existing| {
                        existing.start == candidate.start && existing.end == candidate.end
                    })
                })
                .collect::<Vec<_>>();
            let repaired_empty_matches = structured
                .iter()
                .filter(|repaired| {
                    out.iter().any(|existing| {
                        existing.value.is_empty()
                            && existing.variable_start == repaired.variable_start
                            && existing.variable_end == repaired.variable_end
                    })
                })
                .map(|candidate| (candidate.start, candidate.end, candidate.variable_start))
                .collect::<Vec<_>>();
            out.retain(|candidate| {
                !repaired_empty_matches
                    .iter()
                    .any(|(start, end, variable_start)| {
                        (candidate.variable_start == *variable_start && candidate.value.is_empty())
                            || (candidate.variable_start != *variable_start
                                && candidate
                                    .variable_start
                                    .is_some_and(|nested| *start <= nested)
                                && candidate.end <= *end)
                    })
            });
            out.extend(structured);
            for candidate in &mut out {
                repair_nested_keyword_assignment(text, candidate, keyword);
                repair_quoted_comparison_variable(text, candidate);
                repair_percent_bracket_variable(candidate);
                repair_auth_scheme_value(candidate);
                repair_dictionary_key_value(candidate);
                repair_unquoted_escaped_tail(text, candidate);
            }
            out = out
                .into_iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    (index < initial_len
                        || (!initial_ranges.contains(&(candidate.start, candidate.end))
                            && !candidate
                                .variable_start
                                .zip(candidate.variable_end)
                                .is_some_and(|range| initial_nonempty_variables.contains(&range))
                            && !candidate.variable_start.is_some_and(|start| {
                                initial_consumed_ranges.iter().any(
                                    |(initial_start, initial_end)| {
                                        *initial_start < start && candidate.end <= *initial_end
                                    },
                                )
                            })))
                    .then_some(candidate)
                })
                .collect();
            out.retain(|candidate| keyword_key_right_within_upstream_limit(candidate, keyword));
        }
        out
    }

    fn compiled_keyword(&self) -> Option<&FancyRegex> {
        let source = self.keyword_source.as_ref()?;
        self.compiled_keyword
            .get_or_init(|| FancyRegex::new(&format!("(?is:{source})")).ok())
            .as_ref()
    }
}

fn repair_percent_bracket_variable(candidate: &mut Candidate<'_>) {
    let Some(variable) = candidate.variable else {
        return;
    };
    let lower = variable.to_ascii_lowercase();
    let Some(relative) = lower.rfind("%5b") else {
        return;
    };
    let shift = relative + 3;
    candidate.variable = variable.get(shift..);
    candidate.variable_start = candidate.variable_start.map(|start| start + shift);
}

fn repair_quoted_comparison_variable<'a>(text: &'a str, candidate: &mut Candidate<'a>) {
    if !matches!(
        candidate.separator,
        Some("!=") | Some("==") | Some("!==") | Some("===") | Some("=~")
    ) {
        return;
    }
    let Some(variable_start) = candidate.variable_start else {
        return;
    };
    let Some((quote_start, _)) = text[..variable_start]
        .char_indices()
        .rev()
        .find(|(_, ch)| matches!(ch, '\'' | '"' | '`'))
    else {
        return;
    };
    let expanded_start = quote_start + 1;
    let Some(expanded) = text.get(expanded_start..candidate.variable_end.unwrap_or(variable_start))
    else {
        return;
    };
    let prefix = &expanded[..variable_start.saturating_sub(expanded_start)];
    if !prefix.contains(')')
        || !prefix.contains('(')
        || expanded.len() > 80
        || expanded.chars().any(|ch| {
            matches!(
                ch,
                ':' | '=' | '"' | '\'' | '`' | '}' | '<' | '>' | '\\' | '/' | '&' | '?'
            )
        })
    {
        return;
    }
    candidate.variable_start = Some(expanded_start);
    candidate.variable = Some(expanded);
}

fn repair_dictionary_key_value(candidate: &mut Candidate<'_>) {
    if candidate.wrap.is_none_or(|wrap| wrap.trim() != "{") {
        return;
    }
    let Some(quote) = candidate.value.chars().next() else {
        return;
    };
    if !matches!(quote, '\'' | '"' | '`') {
        return;
    }
    let quote_len = quote.len_utf8();
    let quote_slice = &candidate.value[..quote_len];
    let Some(relative_end) = candidate.value[quote_len..].find(quote) else {
        return;
    };
    // CredSweeper's quoted-value branch requires at least four characters.
    // Short dictionary keys such as JWK's `kty` therefore backtrack into the
    // wrapped-value branch and keep the complete object.
    if relative_end < 4 {
        return;
    }
    let local_end = quote_len + relative_end;
    if !candidate.value[local_end + quote_len..]
        .trim_start()
        .starts_with(':')
    {
        return;
    }
    candidate.start += quote_len;
    candidate.end = candidate.start + relative_end;
    candidate.value = &candidate.value[quote_len..local_end];
    candidate.value_leftquote = Some(quote_slice);
    candidate.value_rightquote = Some(quote_slice);
}

fn repair_unquoted_escaped_tail<'a>(text: &'a str, candidate: &mut Candidate<'a>) {
    if candidate.value_leftquote.is_some() || candidate.value_rightquote.is_some() {
        return;
    }
    let mut end = candidate.end;
    loop {
        let slash_start = end;
        while text.as_bytes().get(end) == Some(&b'\\') && end - slash_start < 8 {
            end += 1;
        }
        if end == slash_start {
            break;
        }
        let Some(ch) = text.get(end..).and_then(|tail| tail.chars().next()) else {
            break;
        };
        if matches!(ch, '\'' | '"' | '`') {
            break;
        }
        end += ch.len_utf8();
    }
    if candidate.end < end {
        candidate.end = end;
        candidate.value = &text[candidate.start..end];
    }
}

fn repair_auth_scheme_value(candidate: &mut Candidate<'_>) {
    let lower = candidate.value.to_ascii_lowercase();
    for scheme in [
        "oauth ",
        "bot ",
        "basic ",
        "bearer ",
        "apikey ",
        "accesskey ",
        "ssws ",
        "ntlm ",
        "token ",
    ] {
        if lower.starts_with(scheme) && candidate.value.len() > scheme.len() + 3 {
            candidate.start += scheme.len();
            candidate.value = &candidate.value[scheme.len()..];
            return;
        }
    }
}

fn repair_nested_keyword_assignment<'a>(
    text: &'a str,
    candidate: &mut Candidate<'a>,
    keyword: &FancyRegex,
) {
    let Some(current_variable_end) = candidate.variable_end else {
        return;
    };
    let Some(prefix) = text.get(current_variable_end..candidate.start) else {
        return;
    };
    let Some(separator_relative) = prefix.rfind('=') else {
        return;
    };
    let separator_start = current_variable_end + separator_relative;
    if separator_start <= current_variable_end {
        return;
    }
    let mut variable_start = separator_start;
    while let Some(index) = variable_start.checked_sub(1) {
        let byte = text.as_bytes()[index];
        if matches!(byte, b':' | b'"' | b'\'' | b'`' | b',' | b';') {
            break;
        }
        variable_start = index;
    }
    while text
        .as_bytes()
        .get(variable_start)
        .is_some_and(u8::is_ascii_whitespace)
    {
        variable_start += 1;
    }
    let mut variable_end = separator_start;
    while variable_end > variable_start && text.as_bytes()[variable_end - 1].is_ascii_whitespace() {
        variable_end -= 1;
    }
    let Some(variable) = text.get(variable_start..variable_end) else {
        return;
    };
    let lower = variable.to_ascii_lowercase();
    let has_auth_scheme = [
        "oauth ",
        "basic ",
        "bearer ",
        "apikey ",
        "accesskey ",
        "ssws ",
        "ntlm ",
        "token ",
    ]
    .iter()
    .any(|scheme| lower.starts_with(scheme));
    let Some(keyword_match) = keyword.find(variable).ok().flatten() else {
        return;
    };
    if variable.is_empty() || !has_auth_scheme {
        return;
    }
    let scheme_end = variable.find(char::is_whitespace).unwrap_or(variable.len());
    if keyword_match.start() >= scheme_end {
        let local_start = variable[..keyword_match.start()]
            .char_indices()
            .rev()
            .find_map(|(index, ch)| ch.is_whitespace().then_some(index + ch.len_utf8()))
            .unwrap_or(0);
        variable_start += local_start;
    }
    let variable = &text[variable_start..variable_end];
    candidate.variable_start = Some(variable_start);
    candidate.variable_end = Some(variable_end);
    candidate.variable = Some(variable);
    candidate.separator = text.get(separator_start..separator_start + 1);
}

fn keyword_key_right_within_upstream_limit(
    candidate: &Candidate<'_>,
    keyword: &FancyRegex,
) -> bool {
    let Some(variable) = candidate.variable else {
        return true;
    };
    if variable.trim_end().ends_with('%')
        && variable.contains('/')
        && variable.contains(['\'', '"', '`'])
    {
        return false;
    }
    keyword
        .find_iter(variable)
        .filter_map(Result::ok)
        .any(|matched| variable.len().saturating_sub(matched.end()) <= 80)
}

fn repair_fancy_unquoted_method_preference(candidate: &mut Candidate<'_>) {
    if candidate.value_leftquote.is_some() || candidate.value_rightquote.is_some() {
        return;
    }
    let Some(wrap) = candidate.wrap else {
        return;
    };
    if wrap.as_ptr() as usize + wrap.len() != candidate.value.as_ptr() as usize {
        return;
    }
    let method = wrap.trim();
    if !method.ends_with('(')
        || !method[..method.len() - 1]
            .chars()
            .any(|ch| ch.is_ascii_alphabetic())
        || candidate.start < wrap.len()
    {
        return;
    }
    let method_start =
        candidate.start - wrap.len() + wrap.len().saturating_sub(wrap.trim_start().len());
    candidate.start = method_start;
    candidate.end = method_start + method.len();
    candidate.value = method;
    candidate.wrap = None;
}

fn keyword_define_call_candidates<'a>(text: &'a str, keyword: &FancyRegex) -> Vec<Candidate<'a>> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    for matched in keyword.find_iter(text).filter_map(Result::ok) {
        let Some(define_start) = lower[..matched.start()].rfind("define(") else {
            continue;
        };
        if define_start > 0 && text.as_bytes()[define_start - 1].is_ascii_alphanumeric() {
            continue;
        }
        let variable_start = define_start + "define(".len();
        let Some(comma_relative) = text[matched.end()..].find(',') else {
            continue;
        };
        let variable_end = matched.end() + comma_relative;
        if variable_end.saturating_sub(variable_start) > 80 {
            continue;
        }
        let separator_start = variable_end;
        let mut separator_end = separator_start + 1;
        while text
            .as_bytes()
            .get(separator_end)
            .is_some_and(u8::is_ascii_whitespace)
        {
            separator_end += 1;
        }
        let Some(&quote) = text
            .as_bytes()
            .get(separator_end)
            .filter(|byte| matches!(byte, b'\'' | b'"' | b'`'))
        else {
            continue;
        };
        let quote_start = separator_end;
        let value_start = quote_start + 1;
        let mut value_end = value_start;
        let mut escaped = false;
        while let Some(&byte) = text.as_bytes().get(value_end) {
            if byte == quote && !escaped {
                break;
            }
            escaped = byte == b'\\' && !escaped;
            if byte != b'\\' {
                escaped = false;
            }
            value_end += 1;
        }
        if text.as_bytes().get(value_end) != Some(&quote)
            || value_end.saturating_sub(value_start) < 4
        {
            continue;
        }
        out.push(Candidate {
            start: value_start,
            end: value_end,
            match_end: value_end,
            value: &text[value_start..value_end],
            variable_start: Some(variable_start),
            variable_end: Some(variable_end),
            variable: Some(&text[variable_start..variable_end]),
            separator: Some(&text[separator_start..separator_end]),
            wrap: None,
            value_leftquote: Some(&text[quote_start..quote_start + 1]),
            value_rightquote: Some(&text[value_end..value_end + 1]),
            line_data: Vec::new(),
        });
    }
    out
}

fn sql_identified_password_candidates(text: &str) -> Vec<Candidate<'_>> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(relative) = lower[search..].find("identified") {
        let identified = search + relative;
        let Some(variable_start) = ["create", "alter", "insert", "update", "set"]
            .into_iter()
            .filter_map(|verb| lower[..identified].rfind(verb))
            .max()
        else {
            search = identified + "identified".len();
            continue;
        };
        let mut cursor = identified + "identified".len();
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if lower[cursor..].starts_with("with") {
            cursor += "with".len();
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(u8::is_ascii_whitespace)
            {
                cursor += 1;
            }
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
            {
                cursor += 1;
            }
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(u8::is_ascii_whitespace)
            {
                cursor += 1;
            }
        }
        let keyword_len = if lower[cursor..].starts_with("by") || lower[cursor..].starts_with("as")
        {
            2
        } else {
            search = identified + "identified".len();
            continue;
        };
        let variable_end = cursor + keyword_len;
        cursor = variable_end;
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        let wrap_start = cursor;
        let wrap = if text.as_bytes().get(cursor) == Some(&b'(') {
            cursor += 1;
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(u8::is_ascii_whitespace)
            {
                cursor += 1;
            }
            Some(&text[wrap_start..cursor])
        } else {
            None
        };
        let (value_start, value_end, left, right) = if let Some(&quote) = text
            .as_bytes()
            .get(cursor)
            .filter(|byte| matches!(byte, b'\'' | b'"' | b'`'))
        {
            if cursor > 0 && text.as_bytes().get(cursor - 1) == Some(&b'\\') {
                search = identified + "identified".len();
                continue;
            }
            let quote_start = cursor;
            cursor += 1;
            let value_start = cursor;
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(|byte| *byte != quote)
            {
                cursor += 1;
            }
            if text.as_bytes().get(cursor) != Some(&quote) {
                search = identified + "identified".len();
                continue;
            }
            (
                value_start,
                cursor,
                Some(&text[quote_start..quote_start + 1]),
                Some(&text[cursor..cursor + 1]),
            )
        } else {
            let value_start = cursor;
            while let Some(&byte) = text.as_bytes().get(cursor) {
                if byte == b'\\'
                    && text
                        .as_bytes()
                        .get(cursor + 1)
                        .is_some_and(|next| !matches!(*next, b'\'' | b'"' | b'`'))
                {
                    cursor += 2;
                    continue;
                }
                if byte.is_ascii_whitespace()
                    || matches!(byte, b'\'' | b'"' | b'`' | b',' | b';' | b'\\')
                {
                    break;
                }
                cursor += 1;
            }
            (value_start, cursor, None, None)
        };
        if (3..=80).contains(&value_end.saturating_sub(value_start)) {
            out.push(Candidate {
                start: value_start,
                end: value_end,
                match_end: value_end,
                value: &text[value_start..value_end],
                variable_start: Some(variable_start),
                variable_end: Some(variable_end),
                variable: Some(&text[variable_start..variable_end]),
                separator: None,
                wrap,
                value_leftquote: left,
                value_rightquote: right,
                line_data: Vec::new(),
            });
        }
        search = identified + "identified".len();
    }
    out
}

fn keyword_set_directive_candidates<'a>(text: &'a str, keyword: &FancyRegex) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    for matched in keyword.find_iter(text).filter_map(Result::ok) {
        let before_keyword = &text[..matched.start()];
        let lower = before_keyword.to_ascii_lowercase();
        let Some(variable_start) = lower
            .rmatch_indices("set")
            .find_map(|(directive_start, _)| {
                let directive_end = directive_start + 3;
                if (directive_start > 0
                    && text.as_bytes()[directive_start - 1].is_ascii_alphanumeric())
                    || !text
                        .as_bytes()
                        .get(directive_end)
                        .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'-')
                {
                    return None;
                }
                let between = &text[directive_end..matched.start()];
                if !between.chars().all(|ch| {
                    ch.is_alphanumeric()
                        || ch.is_whitespace()
                        || matches!(ch, '_' | '[' | ']' | '$' | '.' | '-')
                }) {
                    return None;
                }
                let variable_start = if between.starts_with('-') {
                    directive_end
                } else {
                    directive_end + between.len().saturating_sub(between.trim_start().len())
                };
                if text[variable_start..matched.start()]
                    .chars()
                    .any(char::is_whitespace)
                {
                    return None;
                }
                (variable_start <= matched.start()).then_some(variable_start)
            })
        else {
            continue;
        };

        let tail_end = text[matched.end()..]
            .find(['\r', '\n'])
            .map_or(text.len(), |relative| matched.end() + relative);
        let tail = text[matched.end()..tail_end].trim_end();
        let Some(separator_relative) = tail.rfind(char::is_whitespace) else {
            continue;
        };
        let separator_start = matched.end() + separator_relative;
        let separator_end = separator_start
            + tail[separator_relative..]
                .len()
                .saturating_sub(tail[separator_relative..].trim_start().len());
        let value_start = separator_end;
        let mut value_end = value_start;
        while text.as_bytes().get(value_end).is_some_and(|byte| {
            !byte.is_ascii_whitespace()
                && !matches!(*byte, b'"' | b'\'' | b'`' | b',' | b';' | b'\\')
        }) {
            value_end += 1;
        }
        if value_end.saturating_sub(value_start) < 4 {
            continue;
        }
        out.push(Candidate {
            start: value_start,
            end: value_end,
            match_end: value_end,
            value: &text[value_start..value_end],
            variable_start: Some(variable_start),
            variable_end: Some(separator_start),
            variable: Some(&text[variable_start..separator_start]),
            separator: Some(&text[separator_start..separator_end]),
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        });
    }
    out
}

fn keyword_url_candidates<'a>(text: &'a str, keyword: &FancyRegex) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    for matched in keyword.find_iter(text).filter_map(Result::ok) {
        let mut separator_start = matched.end();
        while separator_start.saturating_sub(matched.end()) <= 80 {
            if text.as_bytes().get(separator_start) == Some(&b'=')
                || text
                    .get(separator_start..separator_start.saturating_add(3))
                    .is_some_and(|value| value.eq_ignore_ascii_case("%3D"))
            {
                break;
            }
            if text
                .get(separator_start..separator_start.saturating_add(3))
                .is_some_and(|value| value.eq_ignore_ascii_case("%26"))
            {
                separator_start = text.len();
                break;
            }
            if text.as_bytes().get(separator_start).is_none_or(|byte| {
                byte.is_ascii_whitespace()
                    || matches!(
                        *byte,
                        b'&' | b';' | b'?' | b'"' | b'\'' | b'`' | b',' | b'\\'
                    )
            }) {
                separator_start = text.len();
                break;
            }
            separator_start += 1;
        }
        if separator_start >= text.len() {
            continue;
        }
        if separator_start.saturating_sub(matched.end()) > 80 {
            continue;
        }
        let separator_end = if text.as_bytes().get(separator_start) == Some(&b'=') {
            separator_start + 1
        } else {
            separator_start + 3
        };
        if text
            .as_bytes()
            .get(separator_end)
            .is_some_and(|byte| matches!(*byte, b'[' | b'(' | b'{'))
        {
            continue;
        }
        let mut value_end = separator_end;
        while value_end < text.len() {
            if text.as_bytes().get(value_end).is_some_and(|byte| {
                byte.is_ascii_whitespace()
                    || matches!(*byte, b';' | b'"' | b'\'' | b'`' | b',' | b'\\')
            }) {
                break;
            }
            value_end += 1;
        }
        if value_end.saturating_sub(separator_end) < 4 {
            continue;
        }

        let mut variable_start = matched.start();
        while let Some(index) = variable_start.checked_sub(1) {
            if variable_start >= 3
                && text
                    .get(variable_start - 3..variable_start)
                    .is_some_and(|value| value.eq_ignore_ascii_case("%26"))
            {
                break;
            }
            let byte = text.as_bytes()[index];
            if byte.is_ascii_whitespace() || matches!(byte, b'&' | b';' | b'?' | b':' | b'=') {
                break;
            }
            variable_start = index;
        }
        if text.as_bytes().get(separator_start) == Some(&b'=')
            && variable_start != 0
            && !text
                .as_bytes()
                .get(variable_start)
                .is_some_and(|byte| matches!(*byte, b'\'' | b'"' | b'`'))
        {
            continue;
        }
        out.push(Candidate {
            start: separator_end,
            end: value_end,
            match_end: value_end,
            value: &text[separator_end..value_end],
            variable_start: Some(variable_start),
            variable_end: Some(separator_start),
            variable: Some(&text[variable_start..separator_start]),
            separator: Some(&text[separator_start..separator_end]),
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        });
    }
    out
}

fn repair_fancy_keyword_variable(candidate: &mut Candidate<'_>) {
    let Some(variable) = candidate.variable else {
        return;
    };
    let Some(quote) = variable.chars().next() else {
        return;
    };
    if !matches!(quote, '\'' | '"' | '`') || variable.matches(quote).count() != 1 {
        return;
    }
    let Some(variable_start) = candidate.variable_start else {
        return;
    };
    let Some(local_end) = variable.char_indices().rev().find_map(|(index, ch)| {
        (ch.is_alphanumeric() || ch == '_').then_some(index + ch.len_utf8())
    }) else {
        return;
    };
    let local_start = variable[..local_end]
        .char_indices()
        .rev()
        .find_map(|(index, ch)| {
            (!(ch.is_alphanumeric() || ch == '_')).then_some(index + ch.len_utf8())
        })
        .unwrap_or(0);
    if local_start == 0 || local_start == local_end {
        return;
    }
    let start = variable_start + local_start;
    candidate.variable_start = Some(start);
    candidate.variable_end = Some(start + local_end - local_start);
    candidate.variable = Some(&variable[local_start..local_end]);
}

fn keyword_get_default_candidate<'a>(text: &'a str, candidate: Candidate<'a>) -> Candidate<'a> {
    let wrap = candidate.wrap.unwrap_or_default().to_ascii_lowercase();
    if !(wrap.contains(".get") || wrap.contains("getenv")) {
        return candidate;
    }
    let Some(key_quote) = candidate.value_leftquote else {
        return candidate;
    };
    if key_quote.len() != 1 || candidate.value_rightquote != Some(key_quote) {
        return candidate;
    }
    let Some(mut tail) = text.get(candidate.end..) else {
        return candidate;
    };
    let Some(after_key_quote) = tail.strip_prefix(key_quote) else {
        return candidate;
    };
    tail = after_key_quote.trim_start();
    if let Some(after_comma) = tail.strip_prefix(',') {
        tail = after_comma.trim_start();
        if tail.to_ascii_lowercase().starts_with("default") {
            tail = &tail["default".len()..];
            tail = tail.trim_start();
            let Some(after_equals) = tail.strip_prefix('=') else {
                return candidate;
            };
            tail = after_equals.trim_start();
        }
    } else if let Some(after_paren) = tail.strip_prefix(')') {
        tail = after_paren.trim_start();
        if tail.len() < 2 || !tail[..2].eq_ignore_ascii_case("or") {
            return candidate;
        }
        tail = tail[2..].trim_start();
    } else {
        return candidate;
    }

    let prefix_len = text.len() - tail.len();
    let mut chars = tail.char_indices();
    let Some((_, quote)) = chars.next() else {
        return candidate;
    };
    if !matches!(quote, '\'' | '"' | '`') {
        let value_end_local = tail
            .find(|ch: char| ch.is_whitespace() || matches!(ch, ')' | ']' | '}' | ',' | ';'))
            .unwrap_or(tail.len());
        if value_end_local == 0 {
            return candidate;
        }
        return Candidate {
            start: prefix_len,
            end: prefix_len + value_end_local,
            match_end: prefix_len + candidate.match_end,
            value: &text[prefix_len..prefix_len + value_end_local],
            variable_start: candidate.variable_start,
            variable_end: candidate.variable_end,
            variable: candidate.variable,
            separator: candidate.separator,
            wrap: candidate.wrap,
            value_leftquote: None,
            value_rightquote: None,
            line_data: candidate.line_data,
        };
    }
    let value_start_local = quote.len_utf8();
    let mut escaped = false;
    let mut value_end_local = None;
    for (index, ch) in tail[value_start_local..].char_indices() {
        if ch == quote && !escaped {
            value_end_local = Some(value_start_local + index);
            break;
        }
        escaped = ch == '\\' && !escaped;
        if ch != '\\' {
            escaped = false;
        }
    }
    let Some(value_end_local) = value_end_local else {
        return candidate;
    };
    let value_start = prefix_len + value_start_local;
    let value_end = prefix_len + value_end_local;
    Candidate {
        start: value_start,
        end: value_end,
        match_end: candidate.match_end,
        value: &text[value_start..value_end],
        variable_start: candidate.variable_start,
        variable_end: candidate.variable_end,
        variable: candidate.variable,
        separator: candidate.separator,
        wrap: candidate.wrap,
        value_leftquote: Some(&text[prefix_len..prefix_len + quote.len_utf8()]),
        value_rightquote: Some(&text[value_end..value_end + quote.len_utf8()]),
        line_data: candidate.line_data,
    }
}

fn keyword_set_call_candidates<'a>(text: &'a str, keyword: &FancyRegex) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    for matched in keyword.find_iter(text).filter_map(Result::ok) {
        let prefix = &text[..matched.start()];
        let directive_start = prefix
            .char_indices()
            .rev()
            .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
            .last()
            .map(|(index, _)| index)
            .unwrap_or(prefix.len());
        let directive = &prefix[directive_start..];
        if !directive.to_ascii_lowercase().ends_with("set") {
            continue;
        }
        let mut cursor = matched.end();
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            cursor += 1;
        }
        let variable_end = cursor;
        cursor += text[cursor..]
            .len()
            .saturating_sub(text[cursor..].trim_start().len());
        if text.as_bytes().get(cursor) != Some(&b'(') {
            continue;
        }
        let separator_start = cursor;
        cursor += 1;
        cursor += text[cursor..]
            .len()
            .saturating_sub(text[cursor..].trim_start().len());
        let Some(&quote) = text.as_bytes().get(cursor) else {
            continue;
        };
        if !matches!(quote, b'\'' | b'"' | b'`') {
            continue;
        }
        let quote_start = cursor;
        cursor += 1;
        let value_start = cursor;
        let mut escaped = false;
        while let Some(&byte) = text.as_bytes().get(cursor) {
            if byte == quote && !escaped {
                break;
            }
            escaped = byte == b'\\' && !escaped;
            if byte != b'\\' {
                escaped = false;
            }
            cursor += 1;
        }
        if text.as_bytes().get(cursor) != Some(&quote) || cursor - value_start < 4 {
            continue;
        }
        out.push(Candidate {
            start: value_start,
            end: cursor,
            match_end: cursor,
            value: &text[value_start..cursor],
            variable_start: Some(matched.start()),
            variable_end: Some(variable_end),
            variable: Some(&text[matched.start()..variable_end]),
            separator: Some(&text[separator_start..separator_start + 1]),
            wrap: None,
            value_leftquote: Some(&text[quote_start..quote_start + 1]),
            value_rightquote: Some(&text[cursor..cursor + 1]),
            line_data: Vec::new(),
        });
    }
    out
}

fn keyword_directive_candidates<'a>(text: &'a str, keyword: &FancyRegex) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    for matched in keyword.find_iter(text).filter_map(Result::ok) {
        let prefix = &text[..matched.start()];
        let trimmed = prefix.trim_end_matches(char::is_whitespace);
        let Some((directive_start, directive_name)) = ["#define", "%define", "%global", "define"]
            .into_iter()
            .filter_map(|name| {
                let start = trimmed.len().checked_sub(name.len())?;
                trimmed
                    .as_bytes()
                    .get(start..)
                    .is_some_and(|suffix| suffix.eq_ignore_ascii_case(name.as_bytes()))
                    .then_some((start, name))
            })
            .next()
        else {
            continue;
        };
        if directive_name == "define"
            && directive_start > 0
            && text.as_bytes()[directive_start - 1].is_ascii_alphanumeric()
        {
            continue;
        }

        let mut variable_end = matched.end();
        while text
            .as_bytes()
            .get(variable_end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            variable_end += 1;
        }
        let separator_start = variable_end;
        let mut cursor = variable_end;
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if separator_start == cursor {
            continue;
        }
        let separator_end = cursor;

        let wrap_start = cursor;
        let wrap_close = match text.as_bytes().get(cursor) {
            Some(b'{') => Some(b'}'),
            Some(b'[') => Some(b']'),
            Some(b'(') => Some(b')'),
            _ => None,
        };
        if wrap_close.is_some() {
            cursor += 1;
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(u8::is_ascii_whitespace)
            {
                cursor += 1;
            }
        }

        let (value_start, value_end, left_quote, right_quote) = if let Some(&quote) = text
            .as_bytes()
            .get(cursor)
            .filter(|byte| matches!(byte, b'\'' | b'"' | b'`'))
        {
            let quote_start = cursor;
            cursor += 1;
            let value_start = cursor;
            let mut escaped = false;
            while let Some(&byte) = text.as_bytes().get(cursor) {
                if byte == quote && !escaped {
                    break;
                }
                escaped = byte == b'\\' && !escaped;
                if byte != b'\\' {
                    escaped = false;
                }
                cursor += 1;
            }
            if text.as_bytes().get(cursor) != Some(&quote) {
                continue;
            }
            (
                value_start,
                cursor,
                Some(&text[quote_start..quote_start + 1]),
                Some(&text[cursor..cursor + 1]),
            )
        } else {
            let value_start = cursor;
            if let Some(close) = wrap_close {
                while text
                    .as_bytes()
                    .get(cursor)
                    .is_some_and(|byte| *byte != close)
                {
                    cursor += 1;
                }
            } else {
                while text.as_bytes().get(cursor).is_some_and(|byte| {
                    !byte.is_ascii_whitespace()
                        && !matches!(*byte, b'\'' | b'"' | b'`' | b',' | b';' | b'\\' | b'&')
                }) {
                    cursor += 1;
                }
            }
            (value_start, cursor, None, None)
        };
        if value_end.saturating_sub(value_start) < 4 {
            continue;
        }

        out.push(Candidate {
            start: value_start,
            end: value_end,
            match_end: value_end,
            value: &text[value_start..value_end],
            variable_start: Some(matched.start()),
            variable_end: Some(variable_end),
            variable: Some(&text[matched.start()..variable_end]),
            separator: Some(&text[separator_start..separator_end]),
            wrap: wrap_close.map(|_| &text[wrap_start..wrap_start + 1]),
            value_leftquote: left_quote,
            value_rightquote: right_quote,
            line_data: Vec::new(),
        });
    }
    out
}

fn keyword_percent_bracket_candidates<'a>(
    text: &'a str,
    keyword: &FancyRegex,
) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    for matched in keyword.find_iter(text).filter_map(Result::ok) {
        let Some(prefix_start) = matched.start().checked_sub(3) else {
            continue;
        };
        let Some(prefix) = text.get(prefix_start..matched.start()) else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case("%5B") {
            continue;
        }
        let mut variable_end = matched.end();
        while text
            .as_bytes()
            .get(variable_end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            variable_end += 1;
        }
        let Some(encoded_close) = text.get(variable_end..variable_end + 3) else {
            continue;
        };
        if !encoded_close.eq_ignore_ascii_case("%5D") {
            continue;
        }
        variable_end += 3;
        if text.as_bytes().get(variable_end) != Some(&b'=') {
            continue;
        }
        let value_start = variable_end + 1;
        let mut value_end = value_start;
        while text.as_bytes().get(value_end).is_some_and(|byte| {
            !byte.is_ascii_whitespace()
                && !matches!(*byte, b'&' | b'"' | b'\'' | b'`' | b',' | b';' | b'\\')
        }) {
            value_end += 1;
        }
        if value_end.saturating_sub(value_start) < 4 {
            continue;
        }
        out.push(Candidate {
            start: value_start,
            end: value_end,
            match_end: value_end,
            value: &text[value_start..value_end],
            variable_start: Some(matched.start()),
            variable_end: Some(variable_end),
            variable: Some(&text[matched.start()..variable_end]),
            separator: Some(&text[variable_end..variable_end + 1]),
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        });
    }
    out
}

fn keyword_structured_candidates<'a>(
    text: &'a str,
    keyword: &FancyRegex,
    existing: &[Candidate<'a>],
) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    for matched in keyword.find_iter(text).filter_map(Result::ok) {
        if existing.iter().any(|candidate| {
            let Some(variable_start) = candidate.variable_start else {
                return false;
            };
            let variable_end = candidate.variable_end.unwrap_or(variable_start);
            if variable_end <= matched.start() && matched.end() <= candidate.end {
                return true;
            }
            variable_start <= matched.start()
                && matched.end() <= variable_end
                && keyword_candidate_is_complete(text, candidate)
        }) {
            continue;
        }

        let mut variable_start = matched.start();
        while let Some(index) = variable_start.checked_sub(1) {
            let byte = text.as_bytes()[index];
            if byte == b'\\'
                && text
                    .as_bytes()
                    .get(variable_start)
                    .is_some_and(|next| matches!(*next, b'n' | b'r' | b't'))
            {
                variable_start += 1;
                break;
            }
            if byte.is_ascii_whitespace() || matches!(byte, b',' | b'{' | b'(' | b':' | b'=') {
                break;
            }
            if byte == b'['
                && text
                    .as_bytes()
                    .get(variable_start)
                    .is_some_and(|next| matches!(*next, b'\'' | b'"' | b'`'))
            {
                break;
            }
            variable_start = index;
        }
        if let Some((quote_start, _)) = text[..matched.start()]
            .char_indices()
            .rev()
            .find(|(_, ch)| matches!(ch, '\'' | '"' | '`'))
        {
            let quoted_prefix = &text[quote_start + 1..matched.start()];
            if quoted_prefix.chars().all(|ch| {
                ch.is_alphanumeric()
                    || ch.is_whitespace()
                    || matches!(ch, '_' | '[' | ']' | '$' | '.' | '-')
            }) {
                variable_start = quote_start;
            }
        }
        let mut separator_start = matched.end();
        while text.as_bytes().get(separator_start).is_some_and(|byte| {
            !matches!(
                *byte,
                b':' | b'=' | b'!' | b'\n' | b';' | b',' | b'{' | b'('
            )
        }) && separator_start.saturating_sub(matched.end()) <= 80
        {
            separator_start += 1;
        }
        if !text
            .as_bytes()
            .get(separator_start)
            .is_some_and(|byte| matches!(*byte, b':' | b'=' | b'!' | b'('))
            || separator_start.saturating_sub(matched.end()) > 80
        {
            continue;
        }
        if text.as_bytes().get(separator_start) == Some(&b'!')
            && text.as_bytes().get(separator_start + 1) != Some(&b'=')
        {
            continue;
        }
        if text.as_bytes().get(separator_start) == Some(&b':')
            && text.as_bytes().get(separator_start + 1) == Some(&b':')
        {
            continue;
        }
        let key_right = &text[matched.end()..separator_start];
        if let Some(quote_index) = key_right.find(['\'', '"', '`']) {
            let after_quote = key_right[quote_index..].trim();
            if !after_quote.chars().all(|ch| matches!(ch, '\'' | '"' | '`')) {
                continue;
            }
        }
        let mut variable_end = separator_start;
        if text.as_bytes().get(separator_start) == Some(&b'(') {
            let mut method_start = separator_start;
            while let Some(index) = method_start.checked_sub(1) {
                if !text.as_bytes()[index].is_ascii_alphanumeric() && text.as_bytes()[index] != b'_'
                {
                    break;
                }
                method_start = index;
            }
            let method = &text[method_start..separator_start];
            if method.len() <= 3 || !method[..3].eq_ignore_ascii_case("set") {
                continue;
            }
            {
                // Python's keyword regex cannot cross the opening parenthesis before a
                // setter name.  Therefore `auth` in `appAuthData.setAppKey(...)` is not
                // a candidate for the Key match that begins in `setAppKey`.
                if matched.start() < method_start + 3 {
                    continue;
                }
                variable_start = method_start + 3;
                variable_end = separator_start;
            }
        }
        let mut typed_annotation = false;
        let mut separator_end = ["!==", "===", ":=", "!=", "==", "=~", "=>", ":", "="]
            .into_iter()
            .find(|operator| text[separator_start..].starts_with(operator))
            .map_or(separator_start + 1, |operator| {
                separator_start + operator.len()
            });
        if text.as_bytes().get(separator_start) == Some(&b':') {
            let annotation_start = separator_start + 1;
            if let Some(relative) = text[annotation_start..].find('=') {
                let assignment = annotation_start + relative;
                let annotation = &text[annotation_start..assignment];
                if !annotation.trim().is_empty()
                    && annotation.chars().all(|ch| {
                        ch.is_alphanumeric()
                            || ch.is_whitespace()
                            || matches!(ch, '_' | '.' | '?' | '<' | '>' | '[' | ']' | ',')
                    })
                {
                    separator_start = assignment;
                    separator_end = assignment + 1;
                    typed_annotation = true;
                }
            }
        }
        if text.as_bytes().get(separator_start) == Some(&b'=') {
            let mut escaped = separator_end;
            while text.as_bytes().get(escaped) == Some(&b'\\')
                && escaped.saturating_sub(separator_end) < 8
            {
                escaped += 1;
            }
            if text
                .get(escaped..escaped.saturating_add(8))
                .is_some_and(|tail| tail.eq_ignore_ascii_case("u0026gt;"))
            {
                separator_end = escaped + 8;
            } else if text
                .get(separator_end..separator_end.saturating_add(6))
                .is_some_and(|tail| tail.eq_ignore_ascii_case("%26gt;"))
            {
                separator_end += 6;
            }
        }
        let mut cursor = separator_end;
        skip_keyword_whitespace(text, &mut cursor);

        let prefix_start = cursor;
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        {
            cursor += 1;
        }
        let prefix = &text[prefix_start..cursor];
        let valid_prefix = matches!(
            prefix.to_ascii_lowercase().as_str(),
            "" | "b" | "r" | "br" | "rb" | "u" | "t" | "f" | "rf" | "fr" | "l"
        );
        if valid_prefix {
            let mut quote_index = cursor;
            while text.as_bytes().get(quote_index) == Some(&b'\\')
                && quote_index.saturating_sub(cursor) < 8
            {
                quote_index += 1;
            }
            if let Some(&quote) = text
                .as_bytes()
                .get(quote_index)
                .filter(|byte| matches!(byte, b'\'' | b'"' | b'`'))
            {
                let quote_start = cursor;
                let quote_end = quote_index + 1;
                cursor = quote_end;
                let value_start = cursor;
                if quote_index == quote_start
                    && text.as_bytes().get(value_start) == Some(&b'\\')
                    && text.as_bytes().get(value_start + 1) == Some(&quote)
                {
                    continue;
                }
                if quote_index > quote_start {
                    let left_quote = &text[quote_start..quote_end];
                    cursor = text[value_start..]
                        .find(left_quote)
                        .map_or(text.len(), |relative| value_start + relative);
                } else {
                    let mut escaped = false;
                    while let Some(&byte) = text.as_bytes().get(cursor) {
                        if byte == quote && !escaped {
                            break;
                        }
                        escaped = byte == b'\\' && !escaped;
                        if byte != b'\\' {
                            escaped = false;
                        }
                        cursor += 1;
                    }
                }
                let tail = text
                    .get(cursor.saturating_add(quote_end - quote_start)..)
                    .unwrap_or_default()
                    .trim_start();
                let method_chain_tail = tail.strip_prefix('.').is_some_and(|tail| {
                    let method_end = tail
                        .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                        .unwrap_or(tail.len());
                    method_end > 0 && tail[method_end..].starts_with('(')
                });
                let comparison_block_tail = matches!(
                    text.get(separator_start..separator_end),
                    Some("!=") | Some("==") | Some("!==") | Some("===") | Some("=~")
                ) && tail.starts_with('{');
                let plain_quote_has_safe_tail = prefix.is_empty()
                    && (tail.is_empty()
                        || tail.starts_with([';', ',', ')', ']', '}'])
                        || tail.starts_with("//")
                        || tail.starts_with('#')
                        || method_chain_tail
                        || comparison_block_tail)
                    || !prefix.is_empty()
                    || typed_annotation;
                if text
                    .get(cursor..)
                    .is_some_and(|tail| tail.starts_with(&text[quote_start..quote_end]))
                    && cursor > value_start
                    && plain_quote_has_safe_tail
                {
                    out.push(Candidate {
                        start: value_start,
                        end: cursor,
                        match_end: cursor,
                        value: &text[value_start..cursor],
                        variable_start: Some(variable_start),
                        variable_end: Some(variable_end),
                        variable: Some(&text[variable_start..variable_end]),
                        separator: Some(&text[separator_start..separator_end]),
                        wrap: None,
                        value_leftquote: Some(&text[quote_start..quote_end]),
                        value_rightquote: Some(&text[cursor..cursor + quote_end - quote_start]),
                        line_data: Vec::new(),
                    });
                    continue;
                }
            }
        }

        {
            if let Some((quote_start, quote)) = text[prefix_start..]
                .char_indices()
                .take_while(|(index, _)| *index <= 256)
                .find_map(|(index, ch)| {
                    matches!(ch, '\'' | '"' | '`').then_some((prefix_start + index, ch))
                })
            {
                let wrap = &text[prefix_start..quote_start];
                let safe_wrap = wrap.trim_end().ends_with('(')
                    && wrap.chars().all(|ch| {
                        ch.is_alphanumeric()
                            || ch.is_whitespace()
                            || matches!(
                                ch,
                                '_' | '.'
                                    | '$'
                                    | ':'
                                    | '-'
                                    | '<'
                                    | '>'
                                    | '['
                                    | ']'
                                    | '('
                                    | ')'
                                    | '{'
                            )
                    });
                if safe_wrap {
                    let value_start = quote_start + quote.len_utf8();
                    let mut value_end = value_start;
                    let mut escaped = false;
                    while let Some(ch) = text[value_end..].chars().next() {
                        if ch == quote && !escaped {
                            break;
                        }
                        escaped = ch == '\\' && !escaped;
                        if ch != '\\' {
                            escaped = false;
                        }
                        value_end += ch.len_utf8();
                    }
                    if text[value_end..].starts_with(quote) && value_start < value_end {
                        out.push(Candidate {
                            start: value_start,
                            end: value_end,
                            match_end: value_end,
                            value: &text[value_start..value_end],
                            variable_start: Some(variable_start),
                            variable_end: Some(variable_end),
                            variable: Some(&text[variable_start..variable_end]),
                            separator: Some(&text[separator_start..separator_end]),
                            wrap: Some(wrap),
                            value_leftquote: Some(&text[quote_start..value_start]),
                            value_rightquote: Some(&text[value_end..value_end + quote.len_utf8()]),
                            line_data: Vec::new(),
                        });
                        continue;
                    }
                }
            }
        }

        cursor = prefix_start;
        let wrap_start = cursor;
        let mut last_open = None;
        loop {
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(u8::is_ascii_whitespace)
            {
                cursor += 1;
            }
            if text.as_bytes().get(cursor) == Some(&b'[')
                && text.as_bytes().get(cursor + 1) == Some(&b']')
            {
                cursor += 2;
                continue;
            }
            if let Some(&open) = text
                .as_bytes()
                .get(cursor)
                .filter(|byte| matches!(byte, b'[' | b'(' | b'{'))
            {
                last_open = Some(open);
                cursor += 1;
                continue;
            }
            let word_start = cursor;
            while text.as_bytes().get(cursor).is_some_and(|byte| {
                byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b':' | b'-' | b'>')
            }) {
                cursor += 1;
            }
            if word_start < cursor && last_open.is_none() {
                continue;
            }
            cursor = word_start;
            break;
        }
        let Some(open) = last_open else {
            continue;
        };
        let close = match open {
            b'[' => b']',
            b'(' => b')',
            b'{' => b'}',
            _ => unreachable!(),
        };
        let value_start = cursor;
        while text
            .as_bytes()
            .get(cursor)
            .is_some_and(|byte| *byte != close)
        {
            cursor += 1;
        }
        if cursor.saturating_sub(value_start) < 16 {
            continue;
        }
        out.push(Candidate {
            start: value_start,
            end: cursor,
            match_end: cursor,
            value: &text[value_start..cursor],
            variable_start: Some(variable_start),
            variable_end: Some(variable_end),
            variable: Some(&text[variable_start..variable_end]),
            separator: Some(&text[separator_start..separator_end]),
            wrap: Some(&text[wrap_start..value_start]),
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        });
    }
    out
}

fn keyword_candidate_is_complete(text: &str, candidate: &Candidate<'_>) -> bool {
    if candidate.value.is_empty() {
        return false;
    }
    if let Some(rightquote) = candidate.value_rightquote {
        let tail = text
            .get(candidate.end.saturating_add(rightquote.len())..)
            .unwrap_or_default()
            .trim_start();
        let method_chain_tail = tail.strip_prefix('.').is_some_and(|tail| {
            let method_end = tail
                .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .unwrap_or(tail.len());
            method_end > 0 && tail[method_end..].starts_with('(')
        });
        return tail.is_empty()
            || tail.starts_with([';', ',', ')', ']', '}'])
            || tail.starts_with("//")
            || tail.starts_with('#')
            || method_chain_tail;
    }
    if candidate.wrap.is_none() {
        return false;
    }
    let Some(open) = candidate
        .wrap
        .and_then(|wrap| wrap.chars().rev().find(|ch| matches!(ch, '[' | '(' | '{')))
    else {
        return true;
    };
    let close = match open {
        '[' => ']',
        '(' => ')',
        '{' => '}',
        _ => unreachable!(),
    };
    candidate.value.trim_end().ends_with(close)
        || text
            .get(candidate.end..)
            .is_some_and(|tail| tail.trim_start().starts_with(close))
}

fn skip_keyword_whitespace(text: &str, cursor: &mut usize) {
    loop {
        let before = *cursor;
        while text
            .as_bytes()
            .get(*cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            *cursor += 1;
        }
        let mut escaped = *cursor;
        while text.as_bytes().get(escaped) == Some(&b'\\') && escaped.saturating_sub(*cursor) < 8 {
            escaped += 1;
        }
        if escaped > *cursor
            && text
                .as_bytes()
                .get(escaped)
                .is_some_and(|byte| matches!(*byte, b'n' | b'r' | b't'))
        {
            *cursor = escaped + 1;
        }
        if *cursor == before {
            break;
        }
    }
}

fn rust_candidate<'a>(
    captures: &regex::Captures<'a>,
    value_capture: bool,
) -> Option<Candidate<'a>> {
    let value = if value_capture {
        captures.name("value")
    } else {
        captures.get(0)
    }?;
    let variable = captures.name("variable");
    let separator = captures.name("separator");
    let wrap = captures.name("wrap");
    let value_leftquote = captures.name("value_leftquote");
    let value_rightquote = captures.name("value_rightquote");
    Some(Candidate {
        start: value.start(),
        end: value.end(),
        match_end: captures.get(0).map_or(value.end(), |matched| matched.end()),
        value: value.as_str(),
        variable_start: variable.as_ref().map(|m| m.start()),
        variable_end: variable.as_ref().map(|m| m.end()),
        variable: variable.map(|m| m.as_str()),
        separator: separator.map(|m| m.as_str()),
        wrap: wrap.map(|m| m.as_str()),
        value_leftquote: value_leftquote.map(|m| m.as_str()),
        value_rightquote: value_rightquote.map(|m| m.as_str()),
        line_data: Vec::new(),
    })
}

fn fancy_candidate<'a>(
    captures: &fancy_regex::Captures<'a>,
    text: &'a str,
    value_capture: bool,
) -> Option<Candidate<'a>> {
    let value = if value_capture {
        captures.name("value")
    } else {
        captures.get(0)
    }?;
    let variable = captures.name("variable");
    let separator = captures.name("separator");
    let wrap = captures.name("wrap");
    let value_leftquote = captures.name("value_leftquote");
    let value_rightquote = captures.name("value_rightquote");
    // Python's `re` returns the closing backreference captured by the official
    // keyword pattern. `fancy_regex` can match the same conditional expression
    // while leaving that nested capture unset. Recover it only for keyword
    // matches when the exact left-quote bytes follow the value in the input.
    let (value_end, recovered_rightquote) = if let Some(right) = value_rightquote {
        (value.end(), Some(right.as_str()))
    } else if captures.name("keyword").is_some() {
        let recovered = value_leftquote.as_ref().and_then(|left_match| {
            let left = left_match.as_str();
            let overlap = (0..left.len()).rev().find_map(|overlap| {
                let quote_start = value.end().checked_sub(overlap)?;
                let consumed = text.get(quote_start..value.end())?;
                let remaining = left.get(overlap..)?;
                (consumed == left.get(..overlap)?
                    && text.get(value.end()..)?.starts_with(remaining))
                .then(|| (quote_start, &text[quote_start..quote_start + left.len()]))
            });
            overlap.or_else(|| {
                let stopped_on_other_quote = !value.as_str().is_empty()
                    && left.chars().count() == 1
                    && text[value.end()..].chars().next().is_some_and(|next| {
                        matches!(next, '\'' | '"' | '`') && !left.starts_with(next)
                    });
                if !(value.as_str().ends_with("\\n")
                    || value.as_str().ends_with("\\r")
                    || stopped_on_other_quote)
                {
                    return None;
                }
                let tail = text.get(value.end()..)?;
                tail.match_indices(left).find_map(|(relative, _)| {
                    let quote_start = value.end() + relative;
                    if left.len() == 1 {
                        let preceding_slashes = text[..quote_start]
                            .bytes()
                            .rev()
                            .take_while(|byte| *byte == b'\\')
                            .count();
                        if preceding_slashes % 2 == 1 {
                            return None;
                        }
                    }
                    Some((quote_start, &text[quote_start..quote_start + left.len()]))
                })
            })
        });
        recovered.map_or_else(
            || {
                if text.get(value.end()..) == Some("\\") {
                    (value.end(), text.get(value.end()..))
                } else {
                    (value.end(), None)
                }
            },
            |(end, right)| (end, Some(right)),
        )
    } else {
        (value.end(), None)
    };
    if captures.name("keyword").is_some()
        && value_leftquote.is_some()
        && recovered_rightquote.is_none()
        && value_end < text.len()
        && text.get(value_end..) != Some("\\")
    {
        return None;
    }
    Some(Candidate {
        start: value.start(),
        end: value_end,
        match_end: captures.get(0).map_or(value.end(), |matched| matched.end()),
        value: &text[value.start()..value_end],
        variable_start: variable.as_ref().map(|m| m.start()),
        variable_end: variable.as_ref().map(|m| m.end()),
        variable: variable.map(|m| m.as_str()),
        separator: separator.map(|m| m.as_str()),
        wrap: wrap.map(|m| m.as_str()),
        value_leftquote: value_leftquote.map(|m| m.as_str()),
        value_rightquote: recovered_rightquote,
        line_data: Vec::new(),
    })
}

#[derive(Clone)]
struct Candidate<'a> {
    start: usize,
    end: usize,
    match_end: usize,
    value: &'a str,
    variable_start: Option<usize>,
    variable_end: Option<usize>,
    variable: Option<&'a str>,
    separator: Option<&'a str>,
    wrap: Option<&'a str>,
    value_leftquote: Option<&'a str>,
    value_rightquote: Option<&'a str>,
    line_data: Vec<CandidateLineData<'a>>,
}

impl Candidate<'_> {
    fn shift(&mut self, offset: usize) {
        self.start += offset;
        self.end += offset;
        self.match_end += offset;
        self.variable_start = self.variable_start.map(|start| start + offset);
        self.variable_end = self.variable_end.map(|end| end + offset);
        for line_data in &mut self.line_data {
            line_data.start += offset;
            line_data.end += offset;
            line_data.variable_start = line_data.variable_start.map(|start| start + offset);
            line_data.variable_end = line_data.variable_end.map(|end| end + offset);
        }
    }
}

#[derive(Clone)]
struct LineRulePrefilter {
    always_rules: Vec<usize>,
    ascii_ac: Option<AhoCorasick>,
    ascii_rules_by_pattern: Vec<Vec<usize>>,
    unicode_ac: Option<AhoCorasick>,
    unicode_rules_by_pattern: Vec<Vec<usize>>,
}

impl LineRulePrefilter {
    fn build(rules: &[NativeRule]) -> Result<Self, String> {
        let mut always_rules = Vec::new();
        let mut ascii_by_literal: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut unicode_by_literal: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (rule_index, rule) in rules.iter().enumerate() {
            if !rule_available_for_code_scan(rule) || !has_line_matcher(rule) {
                continue;
            }
            if rule.required_substrings.is_empty()
                || rule.required_substrings.iter().any(String::is_empty)
            {
                always_rules.push(rule_index);
                continue;
            }
            for literal in &rule.required_substrings {
                let by_literal = if literal.is_ascii() {
                    &mut ascii_by_literal
                } else {
                    &mut unicode_by_literal
                };
                by_literal
                    .entry(literal.clone())
                    .or_default()
                    .push(rule_index);
            }
        }
        let (ascii_ac, ascii_rules_by_pattern) = build_line_prefilter_ac(ascii_by_literal, true)?;
        let (unicode_ac, unicode_rules_by_pattern) =
            build_line_prefilter_ac(unicode_by_literal, false)?;
        Ok(Self {
            always_rules,
            ascii_ac,
            ascii_rules_by_pattern,
            unicode_ac,
            unicode_rules_by_pattern,
        })
    }

    fn collect(&self, line_lower: &LazyLower<'_>, seen_rules: &mut [bool], out: &mut Vec<usize>) {
        out.clear();
        for &rule_index in &self.always_rules {
            seen_rules[rule_index] = true;
            out.push(rule_index);
        }
        if let Some(ac) = &self.ascii_ac {
            collect_prefilter_matches(
                ac,
                &self.ascii_rules_by_pattern,
                line_lower.original,
                seen_rules,
                out,
            );
        }
        if !line_lower.original.is_ascii() {
            if let Some(ac) = &self.unicode_ac {
                collect_prefilter_matches(
                    ac,
                    &self.unicode_rules_by_pattern,
                    line_lower.as_lower(),
                    seen_rules,
                    out,
                );
            }
        }
        out.sort_unstable();
    }
}

fn build_line_prefilter_ac(
    by_literal: BTreeMap<String, Vec<usize>>,
    ascii_case_insensitive: bool,
) -> Result<(Option<AhoCorasick>, Vec<Vec<usize>>), String> {
    let mut patterns = Vec::new();
    let mut rules_by_pattern = Vec::new();
    for (literal, rules) in by_literal {
        patterns.push(literal);
        rules_by_pattern.push(rules);
    }
    if patterns.is_empty() {
        return Ok((None, rules_by_pattern));
    }
    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(ascii_case_insensitive)
        .build(&patterns)
        .map_err(|e| format!("credsweeper line prefilter: {e}"))?;
    Ok((Some(ac), rules_by_pattern))
}

fn collect_prefilter_matches(
    ac: &AhoCorasick,
    rules_by_pattern: &[Vec<usize>],
    haystack: &str,
    seen_rules: &mut [bool],
    out: &mut Vec<usize>,
) {
    for m in ac.find_overlapping_iter(haystack) {
        for &rule_index in &rules_by_pattern[m.pattern().as_usize()] {
            if !seen_rules[rule_index] {
                seen_rules[rule_index] = true;
                out.push(rule_index);
            }
        }
    }
}

fn clear_seen_rules(rule_indices: &[usize], seen_rules: &mut [bool]) {
    for &rule_index in rule_indices {
        seen_rules[rule_index] = false;
    }
}

#[derive(Clone, Copy)]
struct CandidateLineData<'a> {
    start: usize,
    end: usize,
    value: &'a str,
    variable_start: Option<usize>,
    variable_end: Option<usize>,
    variable: Option<&'a str>,
}

impl SpecialMatcher {
    fn find<'a>(&self, line: &'a str) -> Vec<Candidate<'a>> {
        match self {
            Self::AwsMulti | Self::AlibabaMulti | Self::GoogleMulti | Self::Jwk => Vec::new(),
            Self::PemPrivateKey => pem_private_key_candidates(line),
            Self::Base64PrivateKey => base64_private_key_candidates(line),
            Self::Uuid => uuid_candidates(line),
        }
    }

    fn is_whole_text(&self) -> bool {
        matches!(
            self,
            Self::AwsMulti
                | Self::AlibabaMulti
                | Self::GoogleMulti
                | Self::Jwk
                | Self::PemPrivateKey
        )
    }

    fn find_whole_text<'a>(&self, text: &'a str) -> Vec<Candidate<'a>> {
        match self {
            Self::AwsMulti => aws_multi_candidates(text),
            Self::AlibabaMulti => alibaba_multi_candidates(text),
            Self::GoogleMulti => google_multi_candidates(text),
            Self::Jwk => jwk_multi_candidates(text),
            Self::PemPrivateKey => pem_private_key_block_candidates(text),
            _ => Vec::new(),
        }
    }
}

fn has_whole_text_matcher(rule: &NativeRule) -> bool {
    rule.patterns.iter().any(|pattern| {
        matches!(
            &pattern.matcher,
            PatternMatcher::Special(matcher) if matcher.is_whole_text()
        )
    })
}

fn has_line_matcher(rule: &NativeRule) -> bool {
    rule.patterns.iter().any(|pattern| {
        !matches!(
            &pattern.matcher,
            PatternMatcher::Special(matcher) if matcher.is_whole_text()
        )
    })
}

fn translated_pattern(rule_name: &str) -> Option<SpecialMatcher> {
    match rule_name {
        "BASE64 Private Key" => Some(SpecialMatcher::Base64PrivateKey),
        "UUID" => Some(SpecialMatcher::Uuid),
        _ => None,
    }
}

fn uuid_candidates(line: &str) -> Vec<Candidate<'_>> {
    static UUID: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
        )
        .expect("linear CredSweeper UUID regex")
    });
    static LEFT_BOUNDARY: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r"(?:/|[^\\0-9A-Za-z+_-]|\\[0abfnrtv]|(?:%|\\x)[0-9A-Fa-f]{2}|\\[0-7]{3}|\\[Uu][0-9A-Fa-f]{4}|\x1B\[[0-9;]{0,80}m)$",
        )
        .expect("CredSweeper UUID left boundary")
    });
    UUID.find_iter(line)
        .filter(|matched| {
            let prefix_start = clamp_to_char_boundary(line, matched.start().saturating_sub(96));
            (matched.start() == 0 || LEFT_BOUNDARY.is_match(&line[prefix_start..matched.start()]))
                && line.as_bytes().get(matched.end()).is_none_or(|byte| {
                    !byte.is_ascii_alphanumeric() && !matches!(*byte, b'_' | b'+' | b'-')
                })
        })
        .map(|matched| Candidate {
            start: matched.start(),
            end: matched.end(),
            match_end: matched.end(),
            value: matched.as_str(),
            variable_start: None,
            variable_end: None,
            variable: None,
            separator: None,
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        })
        .collect()
}

fn translated_rule(raw: &RawRule) -> Option<SpecialMatcher> {
    match raw.kind.as_deref()? {
        "multi" => match raw.name.as_str() {
            "AWS Multi" => Some(SpecialMatcher::AwsMulti),
            "Alibaba Multi" => Some(SpecialMatcher::AlibabaMulti),
            "Google Multi" => Some(SpecialMatcher::GoogleMulti),
            "JWK" => Some(SpecialMatcher::Jwk),
            _ => None,
        },
        "pem_key" => (raw.name == "PEM Private Key").then_some(SpecialMatcher::PemPrivateKey),
        _ => None,
    }
}

fn compile_pattern(pattern: &str) -> Result<PatternMatcher, ()> {
    match RustRegex::new(pattern) {
        Ok(regex) => Ok(PatternMatcher::Deferred(Arc::new(DeferredRegex {
            source: pattern.to_string(),
            keyword_source: None,
            compiled: OnceLock::from(Some(CompiledRegex::Rust(regex))),
            compiled_keyword: OnceLock::new(),
        }))),
        Err(_) => FancyRegex::new(pattern)
            .map(|regex| {
                PatternMatcher::Deferred(Arc::new(DeferredRegex {
                    source: pattern.to_string(),
                    keyword_source: None,
                    compiled: OnceLock::from(Some(CompiledRegex::Fancy(regex))),
                    compiled_keyword: OnceLock::new(),
                }))
            })
            .map_err(|_| ()),
    }
}

fn compile_keyword_pattern(keyword: &str) -> Result<FancyRegex, ()> {
    FancyRegex::new(&keyword_pattern(keyword)).map_err(|_| ())
}

fn has_named_capture(pattern: &str, name: &str) -> bool {
    pattern.contains(&format!("(?P<{name}>")) || pattern.contains(&format!("(?<{name}>"))
}

fn keyword_pattern(keyword: &str) -> String {
    [
        r#"(?is)"#,
        r#"(?P<directive>(?:(?:[#%]define|define(?=(\s|\\{1,8}[tnr])*\()|%global)(?:\s?\(|\s|\\{1,8}[tnr]){1,8}|\bset(?=\b|\w*(\s|\\{1,8}[tnr])*\()))?"#,
        r#"(?:\\[nrt]|(\\\\*u00|%)[0-9a-f]{2}|\s)*"#,
        r#"(?P<variable>((["'`]{1,8}[^:="'`}<>\\/&?]*|[^:="'`}<>\s()\\/&?;,%]*)"#,
        &format!(r#"(?P<keyword>{keyword})"#),
        r#"[^%:="'`<>({?!&;\n]{0,80})(&(quot|apos|#3[49]);|(\\\\*u00|%)[0-9a-f]{2}|["'`])*)"#,
        r#"(?(directive)|(\s|\\{1,8}[tnr])*\]?(\s|\\{1,8}[tnr])*)"#,
        r#"(?P<separator>:(\s[a-z]{3,9}[?]?\s)?=|:(?!:)|=(>|&gt;|(\\\\*u00|%)26gt;)|!==|!=|===|==|=~|=|(?(directive)(,|\\t|\s|\((?!\))){1,80}|%3d))"#,
        r#"(\s|\\{1,8}[tnr])*"#,
        r#"(?P<wrap>(((\s|\\{1,8}[tnr]|new|byte|char|string|\[\]){1,8})?(?P<get>([_a-z][0-9a-z_.\[\]]*\.)get|(os\.)?getenv)?([0-9a-z_.]|::|-(>|&gt;))*\s*(\[(?!\])|\((?!\))|\{(?!\}))(\s|\\{1,8}[tnr])*(?(get)('[^']{1,31}'|"[^"]{1,31}")\s*(,|\)\s*or)\s*|)([0-9a-z_]{1,32}\s*[:=]\s*)?){1,8})?"#,
        r#"(((b|r|br|rb|u|t|f|rf|fr|l|@)(?=(\\*["'`])))?"#,
        r#"(?P<value_leftquote>((?P<esq>\\{1,8})?(["'`]|&(quot|apos|#3[49]);)){1,4}))?"#,
        r#"(\s?(oauth|bot|basic|bearer|apikey|accesskey|ssws|ntlm|token)\s)?"#,
        r#"(?P<value>(?(value_leftquote)((?!(?P=value_leftquote))(?(esq)((?!(?P=esq)(["'`]|&(quot|apos|#3[49]);)).)|((?!(?P=value_leftquote)).)))|(?!&(quot|apos|#3[49]);)(\\{1,8}([ tnr]|[^\s"'`])|(?P<url_esc>%[0-9a-f]{2})|(?(url_esc)[^\s"'`,;\\&]|[^\s"'`,;\\]))){4,8000}|(<[^>]{4,8000}>)|(\$?\({1,3}[^)]{4,8000}\){1,3})|(\$?\{{1,3}[^}]{4,8000}\}{1,3})|(?(wrap)(?(value_leftquote)(?!\\(?P=value_leftquote))|[^\]\)\}]){16,8000}))"#,
        r#"(?(value_leftquote)(?P<value_rightquote>(?<!\\)(?P=value_leftquote)|\\$|(?<=[0-9a-z+_/-])$)|(?(wrap)(\]|\)|\}|;|\\|$)))"#,
    ]
    .concat()
}

fn aws_multi_candidates(text: &str) -> Vec<Candidate<'_>> {
    static AWS_ID: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r"(?:^|/|[^\\0-9A-Za-z+_-]|\\[0abfnrtv]|(?:%|\\x)[0-9A-Fa-f]{2}|\\[0-7]{3}|\\[Uu][0-9A-Fa-f]{4}|\x1B\[[0-9;]{0,80}m)(?P<value>A(KIA|SIA)[0-9A-Z]{16})",
        )
        .expect("aws multi id regex")
    });
    static AWS_SECRET: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r"(?:^|/|[^\\0-9A-Za-z+_-]|\\[0abfnrtv]|(?:%|\\x)[0-9A-Fa-f]{2}|\\[0-7]{3}|\\[Uu][0-9A-Fa-f]{4}|\x1B\[[0-9;]{0,80}m)(?P<value>[0-9A-Za-z/+]{40,44})",
        )
        .expect("aws multi secret regex")
    });

    multi_pattern_candidates(
        text,
        &AWS_ID,
        |line_start, line, anchor| {
            let local_start = anchor.start - line_start;
            let local_end = anchor.end - line_start;
            !value_pattern_filtered(anchor.value, None)
                && !morphemes_filtered(anchor.value, None)
                && !base64_part_filtered(line, anchor.value, local_start, local_end)
                && !line
                    .as_bytes()
                    .get(local_end)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        },
        |line_start, line, anchor| {
            regex_line_data(line_start, line, &AWS_SECRET)
                .into_iter()
                .filter(|part| {
                    let local_start = part.start - line_start;
                    let local_end = part.end - line_start;
                    has_upper_lower_digit_or_aws_symbol(part.value)
                        && !line
                            .as_bytes()
                            .get(local_end)
                            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(*b, b'/' | b'+'))
                        && !multi_value_filtered(line, part, anchor.value, local_start, local_end)
                        && !base64_part_filtered(line, part.value, local_start, local_end)
                })
                .collect()
        },
    )
}

fn alibaba_multi_candidates(text: &str) -> Vec<Candidate<'_>> {
    static ALIBABA_ID: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r"(?:^|/|[^\\0-9A-Za-z+_-]|\\[0abfnrtv]|(?:%|\\x)[0-9A-Fa-f]{2}|\\[0-7]{3}|\\[Uu][0-9A-Fa-f]{4}|\x1B\[[0-9;]{0,80}m)(?P<value>LTAI[0-9A-Za-z]{12,20})",
        )
        .expect("alibaba multi id regex")
    });
    static ALIBABA_SECRET: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r"(?:^|/|[^\\0-9A-Za-z+_-]|\\[0abfnrtv]|(?:%|\\x)[0-9A-Fa-f]{2}|\\[0-7]{3}|\\[Uu][0-9A-Fa-f]{4}|\x1B\[[0-9;]{0,80}m)(?P<value>[0-9A-Za-z/+]{30})",
        )
        .expect("alibaba multi secret regex")
    });

    multi_pattern_candidates(
        text,
        &ALIBABA_ID,
        |line_start, line, anchor| {
            let local_start = anchor.start - line_start;
            let local_end = anchor.end - line_start;
            !value_pattern_filtered(anchor.value, None)
                && !morphemes_filtered(anchor.value, None)
                && !base64_part_filtered(line, anchor.value, local_start, local_end)
                && !line
                    .as_bytes()
                    .get(local_end)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'+' | b'-'))
        },
        |line_start, line, anchor| {
            regex_line_data(line_start, line, &ALIBABA_SECRET)
                .into_iter()
                .filter(|part| {
                    let local_start = part.start - line_start;
                    let local_end = part.end - line_start;
                    has_upper_lower_digit_or_aws_symbol(part.value)
                        && !line
                            .as_bytes()
                            .get(local_end)
                            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(*b, b'/' | b'+'))
                        && !multi_value_filtered(line, part, anchor.value, local_start, local_end)
                        && !base64_part_filtered(line, part.value, local_start, local_end)
                })
                .collect()
        },
    )
}

fn google_multi_candidates(text: &str) -> Vec<Candidate<'_>> {
    static GOOGLE_CLIENT_ID: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"(?P<value>[0-9]{3,80}-[0-9a-z_]{32}\.apps\.googleusercontent\.com)")
            .expect("google client id regex")
    });
    static GOOGLE_SECRET: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"\b(?P<value>GOCSPX-[0-9A-Za-z_-]{28}|[0-9A-Za-z_-]{24,80})\b")
            .expect("google multi secret regex")
    });

    multi_pattern_candidates(
        text,
        &GOOGLE_CLIENT_ID,
        |_, _, anchor| !value_pattern_filtered(anchor.value, None),
        |line_start, line, anchor| {
            regex_line_data(line_start, line, &GOOGLE_SECRET)
                .into_iter()
                .filter(|part| {
                    let local_start = part.start - line_start;
                    let local_end = part.end - line_start;
                    (part.value.starts_with("GOCSPX-")
                        || has_upper_lower_digit_or_google_symbol(part.value))
                        && !multi_value_filtered(line, part, anchor.value, local_start, local_end)
                })
                .collect()
        },
    )
}

fn multi_pattern_candidates<'a>(
    text: &'a str,
    anchor_regex: &RustRegex,
    anchor_accept: impl Fn(usize, &'a str, CandidateLineData<'a>) -> bool,
    second_parts: impl Fn(usize, &'a str, CandidateLineData<'a>) -> Vec<CandidateLineData<'a>>,
) -> Vec<Candidate<'a>> {
    // Mirrors CredSweeper MultiPattern: anchor on the first pattern, then scan
    // same/nearby lines for the second pattern and report the second value.
    let lines = LineRanges::new(text)
        .map(|(start, line)| (start, line.trim_end_matches(['\r', '\n'])))
        .collect::<Vec<_>>();
    let mut anchors = Vec::new();
    for (idx, (line_start, line)) in lines.iter().enumerate() {
        for part in regex_line_data(*line_start, line, anchor_regex) {
            let local_start = part.start - *line_start;
            let local_end = part.end - *line_start;
            if anchor_accept(*line_start, line, part)
                && !line_specific_key_filtered(line, local_start, local_end)
            {
                anchors.push((idx, part));
            }
        }
    }
    if anchors.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (anchor_idx, anchor) in anchors {
        for line_idx in jwk_multi_search_positions(anchor_idx, &lines) {
            let Some((line_start, line)) = lines.get(line_idx).copied() else {
                continue;
            };
            let parts = second_parts(line_start, line, anchor);
            let Some(main) = parts.first().copied() else {
                continue;
            };
            let mut line_data = Vec::with_capacity(1 + parts.len());
            line_data.push(anchor);
            line_data.extend(parts);
            out.push(Candidate {
                start: main.start,
                end: main.end,
                match_end: main.end,
                value: main.value,
                variable_start: main.variable_start,
                variable_end: main.variable_end,
                variable: main.variable,
                separator: None,
                wrap: None,
                value_leftquote: None,
                value_rightquote: None,
                line_data,
            });
            break;
        }
    }
    out
}

fn regex_line_data<'a>(
    line_start: usize,
    line: &'a str,
    regex: &RustRegex,
) -> Vec<CandidateLineData<'a>> {
    regex
        .captures_iter(line)
        .filter_map(|captures| {
            let value = captures.name("value")?;
            let variable = captures.name("variable");
            Some(CandidateLineData {
                start: line_start + value.start(),
                end: line_start + value.end(),
                value: value.as_str(),
                variable_start: variable.as_ref().map(|m| line_start + m.start()),
                variable_end: variable.as_ref().map(|m| line_start + m.end()),
                variable: variable.map(|m| m.as_str()),
            })
        })
        .collect()
}

fn multi_value_filtered(
    line: &str,
    part: &CandidateLineData<'_>,
    anchor_value: &str,
    local_start: usize,
    local_end: usize,
) -> bool {
    value_search_filtered(anchor_value, part.value)
        || value_pattern_filtered(part.value, None)
        || morphemes_filtered(part.value, None)
        || line_specific_key_filtered(line, local_start, local_end)
}

fn jwk_multi_candidates(text: &str) -> Vec<Candidate<'_>> {
    static JWK_KTY: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r#"['"]?\b(?P<variable>kty)[^0-9A-Za-z_-]{1,8}(RSA|EC|oct)\b['"]?"#)
            .expect("jwk kty regex")
    });

    let lines = LineRanges::new(text)
        .map(|(start, line)| (start, line.trim_end_matches(['\r', '\n'])))
        .collect::<Vec<_>>();
    let kty_matches = lines
        .iter()
        .enumerate()
        .flat_map(|(idx, (line_start, line))| {
            JWK_KTY.captures_iter(line).filter_map(move |captures| {
                let value = captures.get(0)?;
                let variable = captures.name("variable");
                Some((
                    idx,
                    CandidateLineData {
                        start: *line_start + value.start(),
                        end: *line_start + value.end(),
                        value: value.as_str(),
                        variable_start: variable.as_ref().map(|m| *line_start + m.start()),
                        variable_end: variable.as_ref().map(|m| *line_start + m.end()),
                        variable: variable.map(|m| m.as_str()),
                    },
                ))
            })
        })
        .collect::<Vec<_>>();
    if kty_matches.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (kty_idx, kty) in kty_matches {
        for line_idx in jwk_multi_search_positions(kty_idx, &lines) {
            let Some((line_start, line)) = lines.get(line_idx).copied() else {
                continue;
            };
            let private_parts = jwk_private_line_data(line_start, line, kty.value);
            let Some(main) = private_parts.first().copied() else {
                continue;
            };
            let mut line_data = Vec::with_capacity(1 + private_parts.len());
            line_data.push(kty);
            line_data.extend(private_parts);
            out.push(Candidate {
                start: main.start,
                end: main.end,
                match_end: main.end,
                value: main.value,
                variable_start: main.variable_start,
                variable_end: main.variable_end,
                variable: main.variable,
                separator: None,
                wrap: None,
                value_leftquote: None,
                value_rightquote: None,
                line_data,
            });
            break;
        }
    }
    out
}

fn jwk_private_line_data<'a>(
    line_start: usize,
    line: &'a str,
    anchor_value: &str,
) -> Vec<CandidateLineData<'a>> {
    static JWK_PRIVATE_VALUE: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r#"(?P<variable>\b[dk])[^0-9A-Za-z_-]{1,8}(?P<value>[0-9A-Za-z_-]{22,8000})"#,
        )
        .expect("jwk private value regex")
    });

    JWK_PRIVATE_VALUE
        .captures_iter(line)
        .filter_map(|captures| {
            let value = captures.name("value")?;
            if line
                .as_bytes()
                .get(value.end())
                .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'='))
            {
                return None;
            }
            if value_search_filtered(anchor_value, value.as_str())
                || value_pattern_filtered(value.as_str(), None)
                || morphemes_filtered(value.as_str(), None)
            {
                return None;
            }
            let variable = captures.name("variable");
            Some(CandidateLineData {
                start: line_start + value.start(),
                end: line_start + value.end(),
                value: value.as_str(),
                variable_start: variable.as_ref().map(|m| line_start + m.start()),
                variable_end: variable.as_ref().map(|m| line_start + m.end()),
                variable: variable.map(|m| m.as_str()),
            })
        })
        .collect()
}

fn value_search_filtered(anchor_value: &str, candidate_value: &str) -> bool {
    if anchor_value.len() < candidate_value.len() {
        candidate_value.contains(anchor_value)
    } else {
        anchor_value.contains(candidate_value)
    }
}

fn jwk_multi_search_positions(line_idx: usize, lines: &[(usize, &str)]) -> Vec<usize> {
    const MAX_SEARCH_MARGIN: usize = 10;

    if line_idx >= lines.len() {
        return Vec::new();
    }
    let mut priority_positions = vec![(0usize, line_idx)];
    let mut priority_forward = MAX_SEARCH_MARGIN;
    let mut priority_backward = MAX_SEARCH_MARGIN * 2;
    for margin in 1..=MAX_SEARCH_MARGIN {
        if let Some(forward_idx) = line_idx
            .checked_add(margin)
            .filter(|idx| *idx < lines.len())
        {
            let diff = curly_diff(lines[forward_idx].1, b'}', b'{');
            priority_forward += MAX_SEARCH_MARGIN * (1 + diff);
            priority_positions.push((priority_forward, forward_idx));
        }
        if let Some(backward_idx) = line_idx.checked_sub(margin) {
            let diff = curly_diff(lines[backward_idx].1, b'{', b'}');
            priority_backward += MAX_SEARCH_MARGIN * (1 + diff);
            priority_positions.push((priority_backward, backward_idx));
        }
    }
    priority_positions.sort();
    priority_positions
        .into_iter()
        .map(|(_, line_idx)| line_idx)
        .collect()
}

fn curly_diff(line: &str, positive: u8, negative: u8) -> usize {
    const MAX_LINE_LENGTH: usize = 8000;
    let mut diff = 0isize;
    for byte in line.bytes().take(MAX_LINE_LENGTH) {
        if byte == positive {
            diff += 1;
        } else if byte == negative {
            diff -= 1;
        }
    }
    diff.max(0) as usize
}

fn pem_private_key_candidates(line: &str) -> Vec<Candidate<'_>> {
    let Some(begin) = line.find("-----BEGIN") else {
        return Vec::new();
    };
    let Some(end_rel) = line[begin..].find("KEY-----") else {
        return Vec::new();
    };
    let end = begin + end_rel + "KEY-----".len();
    let value = &line[begin..end];
    if is_private_key_armor_header(value) {
        vec![Candidate {
            start: begin,
            end,
            match_end: end,
            value,
            variable_start: None,
            variable_end: None,
            variable: None,
            separator: None,
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        }]
    } else {
        Vec::new()
    }
}

fn is_private_key_armor_header(header: &str) -> bool {
    !header.contains("ENCRYPTED")
        && header.contains("KEY")
        && (header.contains("PRIVATE") || header.contains("PGP SECRET KEY BLOCK"))
}

fn pem_private_key_block_candidates(text: &str) -> Vec<Candidate<'_>> {
    const MAX_PEM_LENGTH: usize = 4 * 8000;

    let mut out = Vec::new();
    let mut search_start = 0usize;
    while let Some(begin_rel) = text[search_start..].find("-----BEGIN") {
        let begin = search_start + begin_rel;
        let header_search = begin + "-----BEGIN".len();
        let header_window_end =
            clamp_to_char_boundary(text, (header_search + MAX_PEM_LENGTH).min(text.len()));
        let Some(header_close_rel) = text[header_search..header_window_end].find("-----") else {
            break;
        };
        let header_end = header_search + header_close_rel + "-----".len();
        let header = &text[begin..header_end];
        if !is_private_key_armor_header(header) {
            search_start = header_end;
            continue;
        }

        let end_limit = clamp_to_char_boundary(text, (begin + MAX_PEM_LENGTH).min(text.len()));
        let Some(end_rel) = text[header_end..end_limit].find("-----END") else {
            search_start = header_end;
            continue;
        };
        let end_begin = header_end + end_rel;
        let end_header_search = end_begin + "-----END".len();
        let Some(end_close_rel) = text[end_header_search..end_limit].find("-----") else {
            search_start = header_end;
            continue;
        };
        let end = end_header_search + end_close_rel + "-----".len();
        let block = &text[begin..end];
        if valid_pem_private_key_block(block) {
            let line_data = pem_private_key_line_data(text, begin, header_end, end);
            out.push(Candidate {
                start: begin,
                end,
                match_end: end,
                value: block,
                variable_start: None,
                variable_end: None,
                variable: None,
                separator: None,
                wrap: None,
                value_leftquote: None,
                value_rightquote: None,
                line_data,
            });
        }
        search_start = end;
    }
    out
}

fn pem_private_key_line_data(
    text: &str,
    begin: usize,
    header_end: usize,
    end: usize,
) -> Vec<CandidateLineData<'_>> {
    let mut out = Vec::new();
    for (line_start, line) in LineRanges::new(text) {
        let line = line.trim_end_matches(['\r', '\n']);
        let line_end = line_start + line.len();
        if line_end <= begin || end <= line_start {
            continue;
        }
        if out.is_empty() {
            if end <= line_end {
                out.push(CandidateLineData {
                    start: begin,
                    end,
                    value: &text[begin..end],
                    variable_start: None,
                    variable_end: None,
                    variable: None,
                });
                break;
            }
            out.push(CandidateLineData {
                start: begin,
                end: header_end,
                value: &text[begin..header_end],
                variable_start: None,
                variable_end: None,
                variable: None,
            });
            continue;
        }

        let line = &text[line_start..line_end.min(end)];
        let sanitized = sanitize_pem_line(line, 5);
        if sanitized.contains("-----END") {
            if let Some(marker_start) = line.find("-----END") {
                let payload = sanitize_pem_line(&line[..marker_start], 5);
                if !payload.is_empty() && payload.bytes().all(is_pem_base64_byte) {
                    if let Some(local_start) = line[..marker_start].find(&payload) {
                        let start = line_start + local_start;
                        out.push(CandidateLineData {
                            start,
                            end: start + payload.len(),
                            value: &text[start..start + payload.len()],
                            variable_start: None,
                            variable_end: None,
                            variable: None,
                        });
                        continue;
                    }
                }
            }
        }
        let valuable = sanitized.contains("-----END")
            || (!sanitized.is_empty() && sanitized.bytes().all(is_pem_base64_byte));
        let (start, value_end) = if valuable {
            let Some(local_start) = line.find(&sanitized) else {
                continue;
            };
            let start = line_start + local_start;
            (start, start + sanitized.len())
        } else {
            (line_start, line_end)
        };
        out.push(CandidateLineData {
            start,
            end: value_end,
            value: &text[start..value_end],
            variable_start: None,
            variable_end: None,
            variable: None,
        });
    }
    out
}

fn valid_pem_private_key_block(block: &str) -> bool {
    let mut text = block.to_string();
    while text.contains("\\\\") {
        text = text.replace("\\\\", "\\");
    }
    text = text
        .replace("\\r\\n", "\n")
        .replace("\\r", "\n")
        .replace("\\n", "\n")
        .replace("\\t", "\t");

    let mut key_data = String::new();
    let mut saw_end = false;
    let is_openpgp = block.contains("-----BEGIN PGP ");
    let mut in_openpgp_headers = is_openpgp;
    for line in text.lines() {
        let line = sanitize_pem_line(line, 5);
        if line.contains("-----BEGIN") {
            continue;
        }
        if in_openpgp_headers {
            if line.is_empty() {
                in_openpgp_headers = false;
                continue;
            }
            if is_openpgp_armor_header(&line) {
                continue;
            }
            in_openpgp_headers = false;
        }
        if line.is_empty()
            || line.contains("Proc-Type")
            || line.contains("Version")
            || line.contains("DEK-Info")
        {
            continue;
        }
        if line.contains("-----END") {
            saw_end = true;
            break;
        }
        if !line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return false;
        }
        key_data.push_str(&line);
    }
    saw_end && pem_payload_is_valid(block, &key_data)
}

fn is_openpgp_armor_header(line: &str) -> bool {
    let Some((name, _)) = line.split_once(':') else {
        return false;
    };
    matches!(
        name.trim(),
        "Version" | "Comment" | "MessageID" | "Hash" | "Charset"
    )
}

fn asn1_size(data: &[u8]) -> Option<usize> {
    if data.len() < 2 || data[0] != 0x30 {
        return None;
    }
    let first = data[1];
    if first == 0x80 {
        return data.ends_with(&[0, 0]).then_some(data.len());
    }
    if first > 0x80 {
        let byte_len = usize::from(first & 0x7f);
        let length_end = 2usize.checked_add(byte_len)?;
        if byte_len > 4 || data.len() < length_end {
            return None;
        }
        let length = data[2..length_end]
            .iter()
            .try_fold(0usize, |length, byte| {
                length.checked_shl(8)?.checked_add(usize::from(*byte))
            })?;
        let total = length.checked_add(length_end)?;
        return (data.len() >= total).then_some(total);
    }
    let total = usize::from(first) + 2;
    (data.len() >= total).then_some(total)
}

fn pem_payload_is_valid(header: &str, value: &str) -> bool {
    if header.contains("PGP") {
        return shannon_entropy(value) >= 4.5;
    }
    let Some(decoded) = decode_base64_like_upstream(value) else {
        return false;
    };
    if header.contains("OPENSSH") {
        return decoded.len() > 32 && !decoded.windows(6).any(|window| window == b"bcrypt");
    }
    asn1_size(&decoded) == Some(decoded.len())
}

fn value_base64_encoded_pem_filtered(value: &str) -> bool {
    let Some(decoded) = decode_base64_like_upstream(value) else {
        return true;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return true;
    };
    let mut pem = String::new();
    for line in text.lines() {
        if pem.is_empty() {
            let Some(begin) = line.find("-----BEGIN") else {
                continue;
            };
            let header = &line[begin..line.len().min(begin + 8000)];
            if !header.contains("PRIVATE")
                || !header.contains("KEY")
                || header.contains("ENCRYPTED")
            {
                continue;
            }
            pem.push_str(header);
        } else {
            pem.push('\n');
            pem.push_str(line);
        }
        if line.contains("-----END") {
            if valid_pem_private_key_block(&pem) {
                return false;
            }
            pem.clear();
        }
    }
    true
}

enum CredSweeperPrivateKey {
    Rsa,
    SupportedNonRsa,
}

fn rsa_private_key_is_valid(data: &[u8]) -> bool {
    let Ok(key) = RsaPrivateKey::from_der(data) else {
        return false;
    };
    let one = BigUint::from(1_u8);
    let modulus = BigUint::from_bytes_be(key.modulus.as_bytes());
    let public_exponent = BigUint::from_bytes_be(key.public_exponent.as_bytes());
    let private_exponent = BigUint::from_bytes_be(key.private_exponent.as_bytes());
    let prime1 = BigUint::from_bytes_be(key.prime1.as_bytes());
    let prime2 = BigUint::from_bytes_be(key.prime2.as_bytes());
    let mut primes = vec![prime1.clone(), prime2.clone()];
    if public_exponent <= one || private_exponent <= one || primes.iter().any(|prime| prime <= &one)
    {
        return false;
    }
    // SHA-1 OAEP with CredSweeper's 20-byte probe needs a 62-byte modulus.
    if key.modulus.as_bytes().len() < 62 {
        return false;
    }
    let exponent_product = &private_exponent * &public_exponent;
    if BigUint::from_bytes_be(key.exponent1.as_bytes()) != &private_exponent % (&prime1 - &one)
        || BigUint::from_bytes_be(key.exponent2.as_bytes()) != &private_exponent % (&prime2 - &one)
        || (BigUint::from_bytes_be(key.coefficient.as_bytes()) * &prime2) % &prime1 != one
    {
        return false;
    }
    let mut prime_product = &prime1 * &prime2;
    if let Some(other_primes) = key.other_prime_infos {
        for info in other_primes {
            let prime = BigUint::from_bytes_be(info.prime.as_bytes());
            if prime <= one
                || BigUint::from_bytes_be(info.exponent.as_bytes())
                    != &private_exponent % (&prime - &one)
                || (BigUint::from_bytes_be(info.coefficient.as_bytes()) * &prime_product) % &prime
                    != one
            {
                return false;
            }
            prime_product *= &prime;
            primes.push(prime);
        }
    }
    prime_product == modulus
        && primes
            .iter()
            .all(|prime| &exponent_product % (prime - &one) == one)
        && primes.iter().all(|prime| {
            let bytes = prime.to_bytes_be();
            is_prime(
                Flavor::Any,
                &BoxedUint::from_be_slice_vartime(bytes.as_slice()),
            )
        })
}

fn der_positive_integer(data: &[u8]) -> bool {
    AnyRef::try_from(data)
        .and_then(|value| value.decode_as::<UintRef<'_>>())
        .is_ok_and(|value| !value.is_empty() && value.as_bytes().iter().any(|byte| *byte != 0))
}

fn rfc8410_private_key(info: &PrivateKeyInfoRef<'_>, expected_len: usize) -> bool {
    if info.algorithm.parameters.is_some() {
        return false;
    }
    AnyRef::try_from(info.private_key.as_bytes())
        .and_then(|value| value.decode_as::<&OctetStringRef>())
        .is_ok_and(|key| key.as_bytes().len() == expected_len)
}

fn parameter_children(params: AnyRef<'_>) -> Option<Vec<AnyRef<'_>>> {
    params
        .sequence(|reader| {
            let mut children = Vec::new();
            while !reader.is_finished() {
                children.push(reader.decode::<AnyRef<'_>>()?);
            }
            Ok::<_, pkcs8::der::Error>(children)
        })
        .ok()
}

fn any_positive_integer(value: AnyRef<'_>) -> bool {
    value.decode_as::<UintRef<'_>>().is_ok_and(|integer| {
        !integer.is_empty() && integer.as_bytes().iter().any(|byte| *byte != 0)
    })
}

fn dsa_parameters_valid(params: AnyRef<'_>) -> bool {
    parameter_children(params).is_some_and(|children| {
        children.len() == 3 && children.into_iter().all(any_positive_integer)
    })
}

fn dh_parameters_valid(params: AnyRef<'_>) -> bool {
    parameter_children(params).is_some_and(|children| {
        (2..=3).contains(&children.len()) && children.into_iter().all(any_positive_integer)
    })
}

fn dhx_validation_parameters_valid(value: AnyRef<'_>) -> bool {
    parameter_children(value).is_some_and(|children| {
        children.len() == 2
            && children[0].tag() == Tag::BitString
            && any_positive_integer(children[1])
    })
}

fn dhx_parameters_valid(params: AnyRef<'_>) -> bool {
    parameter_children(params).is_some_and(|children| {
        if !(3..=5).contains(&children.len())
            || !children[..3].iter().copied().all(any_positive_integer)
        {
            return false;
        }
        match &children[3..] {
            [] => true,
            [fourth] => any_positive_integer(*fourth) || dhx_validation_parameters_valid(*fourth),
            [fourth, fifth] => {
                any_positive_integer(*fourth) && dhx_validation_parameters_valid(*fifth)
            }
            _ => false,
        }
    })
}

fn integer_key_with_parameters(
    info: &PrivateKeyInfoRef<'_>,
    parameters_valid: fn(AnyRef<'_>) -> bool,
) -> bool {
    info.algorithm.parameters.is_some_and(parameters_valid)
        && der_positive_integer(info.private_key.as_bytes())
}

fn load_pkcs8_private_key(data: &[u8]) -> Option<CredSweeperPrivateKey> {
    let info = PrivateKeyInfoRef::try_from(data).ok()?;
    match info.algorithm.oid.to_string().as_str() {
        // rsaEncryption and RSASSA-PSS. OpenSSL validates the embedded PKCS#1
        // structure for both before CredSweeper performs its RSA probe.
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10"
            if rsa_private_key_is_valid(info.private_key.as_bytes()) =>
        {
            Some(CredSweeperPrivateKey::Rsa)
        }
        // Keep parsing here rather than accepting a recognized OID by itself:
        // cryptography.load_der_private_key(), used by CredSweeper, rejects
        // malformed key bodies before classifying the private-key family.
        "1.2.840.10045.2.1" => sec1::EcPrivateKey::try_from(info.private_key.as_bytes())
            .ok()
            .filter(|key| !key.private_key.is_empty())
            .and(info.algorithm.parameters.as_ref())
            .filter(|params| params.tag() == Tag::ObjectIdentifier)
            .map(|_| CredSweeperPrivateKey::SupportedNonRsa),
        "1.2.840.10040.4.1" if integer_key_with_parameters(&info, dsa_parameters_valid) => {
            Some(CredSweeperPrivateKey::SupportedNonRsa)
        }
        "1.2.840.113549.1.3.1" if integer_key_with_parameters(&info, dh_parameters_valid) => {
            Some(CredSweeperPrivateKey::SupportedNonRsa)
        }
        "1.2.840.10046.2.1" if integer_key_with_parameters(&info, dhx_parameters_valid) => {
            Some(CredSweeperPrivateKey::SupportedNonRsa)
        }
        "1.3.101.110" if rfc8410_private_key(&info, 32) => {
            Some(CredSweeperPrivateKey::SupportedNonRsa)
        }
        "1.3.101.111" if rfc8410_private_key(&info, 56) => {
            Some(CredSweeperPrivateKey::SupportedNonRsa)
        }
        "1.3.101.112" if rfc8410_private_key(&info, 32) => {
            Some(CredSweeperPrivateKey::SupportedNonRsa)
        }
        "1.3.101.113" if rfc8410_private_key(&info, 57) => {
            Some(CredSweeperPrivateKey::SupportedNonRsa)
        }
        _ => None,
    }
}

fn load_der_private_key(data: &[u8]) -> Option<CredSweeperPrivateKey> {
    if rsa_private_key_is_valid(data) {
        return Some(CredSweeperPrivateKey::Rsa);
    }
    if let Some(key) = load_pkcs8_private_key(data) {
        return Some(key);
    }
    // Raw import stores an unlinked private key and its certificate under the
    // same friendly name. The certificate is inserted last and can overwrite
    // the key entry. Relaxed import links matching local-key IDs while still
    // retaining unmatched private keys, matching CredSweeper's load_pk probe.
    let store = KeyStore::from_pkcs12(data, "", Pkcs12ImportPolicy::Relaxed).ok()?;
    let (_, chain) = store.private_key_chain()?;
    load_pkcs8_private_key(chain.key().as_der())
}

fn private_key_is_valid(key: &CredSweeperPrivateKey) -> bool {
    match key {
        CredSweeperPrivateKey::Rsa => true,
        CredSweeperPrivateKey::SupportedNonRsa => true,
    }
}

fn value_base64_key_filtered(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut cleaned = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && bytes
                .get(index + 1)
                .is_some_and(|byte| matches!(byte, b't' | b'n' | b'r' | b'v' | b'f'))
        {
            index += 2;
            continue;
        }
        let Some(ch) = value[index..].chars().next() else {
            break;
        };
        index += ch.len_utf8();
        if !matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c') {
            cleaned.push(ch);
        }
    }
    cleaned = cleaned
        .replace("'+'", "")
        .replace("\"+\"", "")
        .replace("%2B", "+")
        .replace("%2F", "/")
        .replace("%3D", "=")
        .replace(['"', '\'', '\\'], "");
    let Some(key) = decode_base64_standard_like_upstream(&cleaned) else {
        return true;
    };
    load_der_private_key(&key).is_none_or(|key| !private_key_is_valid(&key))
}

fn decode_base64_standard_like_upstream(value: &str) -> Option<Vec<u8>> {
    // Python's base64.b64decode(validate=False), used by
    // ValueBase64KeyCheck, discards bytes outside the standard alphabet.
    // The rule's broad capture intentionally includes source punctuation.
    let mut value = value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        .map(char::from)
        .collect::<String>();
    while value.ends_with('=') {
        value.pop();
    }
    if !value.len().is_multiple_of(4) {
        value.extend(std::iter::repeat_n('=', 4 - value.len() % 4));
    }
    BASE64.decode(value.as_bytes()).ok()
}

fn sanitize_pem_line(line: &str, recurse: usize) -> String {
    if recurse == 0 {
        return line.to_string();
    }
    let mut line = line.trim().to_string();
    while line.contains("\\\\") {
        line = line.replace("\\\\", "\\");
    }
    line = line
        .replace("\\r\\n", "\n")
        .replace("\\r", "\n")
        .replace("\\n", "\n")
        .replace("\\t", "\t");
    while line.starts_with("// ") || line.starts_with("//\t") {
        line = line[3..].to_string();
    }
    while line.starts_with("/// ") || line.starts_with("///\t") {
        line = line[4..].to_string();
    }
    while line.starts_with("/*") {
        line = line[2..].to_string();
    }
    while line.ends_with("*/") {
        line.truncate(line.len().saturating_sub(2));
    }
    while line.ends_with('\\') {
        line.pop();
    }
    if line.starts_with('+')
        && line
            .as_bytes()
            .get(1)
            .is_some_and(|b| !is_pem_base64_byte(*b))
    {
        line = line[1..].to_string();
    }
    if line.ends_with('+')
        && line
            .as_bytes()
            .get(line.len().saturating_sub(2))
            .is_some_and(|b| !is_pem_base64_byte(*b))
    {
        line.pop();
    }
    let trimmed = line
        .trim_matches(|ch: char| ch.is_whitespace() || "\\'\"`;,[]#*!".contains(ch))
        .to_string();
    if trimmed != line
        || trimmed.bytes().any(|b| {
            matches!(
                b,
                b'\\' | b'\'' | b'"' | b'`' | b';' | b',' | b'[' | b']' | b'#' | b'*' | b'!'
            )
        })
    {
        return sanitize_pem_line(&trimmed, recurse - 1);
    }
    trimmed
}

fn is_pem_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn base64_private_key_candidates(line: &str) -> Vec<Candidate<'_>> {
    fn tail_forbidden(ch: char) -> bool {
        matches!(
            ch,
            '!' | '#'
                | '$'
                | '&'
                | '('
                | ')'
                | '*'
                | '-'
                | '.'
                | ':'
                | ';'
                | '<'
                | '='
                | '>'
                | '?'
                | '@'
                | '['
                | ']'
                | '^'
                | '_'
                | '{'
                | '|'
                | '}'
                | '~'
        )
    }

    let mut out = Vec::new();
    let mut search_start = 0usize;
    while let Some(relative) = line[search_start..].find("MII") {
        let start = search_start + relative;
        let Some(prefix) = line.as_bytes().get(start..start + 12) else {
            break;
        };
        let fourth = prefix[3];
        if !(fourth.is_ascii_uppercase() || matches!(fourth, b'a'..=b'f'))
            || !prefix[4..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'+'))
        {
            search_start = start + 3;
            continue;
        }

        let tail_start = start + 12;
        let mut tail_chars = 0usize;
        let mut end = tail_start;
        for (relative, ch) in line[tail_start..].char_indices() {
            if tail_forbidden(ch) || tail_chars == 8000 {
                break;
            }
            tail_chars += 1;
            end = tail_start + relative + ch.len_utf8();
        }
        if tail_chars < 8 {
            search_start = start + 3;
            continue;
        }
        out.push(Candidate {
            start,
            end,
            match_end: end,
            value: &line[start..end],
            variable_start: None,
            variable_end: None,
            variable: None,
            separator: None,
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        });
        search_start = end;
    }
    out
}

fn clamp_to_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

struct PendingMlFinding {
    finding: CredSweeperNativeFinding,
    input: MlInput,
    requires_ml: bool,
}

struct PushMatchCtx<'view, 'data> {
    view: &'view NormalizedView<'view>,
    path: &'data str,
    file_type: &'data str,
}

#[derive(Clone)]
struct CandidateLineContext<'a> {
    start: usize,
    line: &'a str,
    previous: Option<&'a str>,
    next: Option<&'a str>,
    file_type: &'a str,
    target: &'a str,
    line_index: usize,
}

fn sanitize_variable_capture(
    line: &str,
    variable: &str,
    start: usize,
    end: usize,
) -> Option<(String, usize, usize)> {
    // Mirrors CredSweeper LineData.sanitize_variable so keyword rules compare
    // against the same key text after syntax punctuation has been trimmed.
    if start >= end {
        return None;
    }
    let mut sanitized = variable.to_string();
    let original = sanitized.clone();
    let mut previous_len = 0usize;
    while !sanitized.is_empty() && previous_len != sanitized.len() {
        previous_len = sanitized.len();
        sanitized = sanitized
            .trim_matches(|ch: char| {
                ch.is_whitespace() || matches!(ch, ',' | '\'' | '"' | '-' | ';')
            })
            .to_string();
        if sanitized.ends_with('\\') {
            sanitized.pop();
        }
        if sanitized.starts_with('{') && line.get(end..).is_some_and(|tail| tail.contains('}')) {
            sanitized.remove(0);
        }
    }
    if sanitized.is_empty() {
        return None;
    }
    let offset = original.find(&sanitized)?;
    let sanitized_start = start + offset;
    let sanitized_end = sanitized_start + sanitized.len();
    Some((sanitized, sanitized_start, sanitized_end))
}

struct SanitizedValue<'a> {
    value: &'a str,
    start: usize,
    end: usize,
}

fn sanitize_value_capture<'a>(
    line: &'a str,
    file_type: &str,
    candidate: &Candidate<'a>,
) -> SanitizedValue<'a> {
    // Mirrors CredSweeper LineData.sanitize_value for regex captures whose
    // value spans syntax around the actual secret.
    let mut out = SanitizedValue {
        value: candidate.value,
        start: candidate.start,
        end: candidate.end,
    };
    if out.value.is_empty() {
        return out;
    }

    // Python's conditional right-quote capture may use a terminal backslash
    // as the closing delimiter when an escaped source line is rescanned in a
    // bounded offset. `fancy_regex` can leave that delimiter in `value`; it is
    // syntax, not part of the credential.
    if candidate.value_rightquote == Some("\\") && out.value.ends_with('\\') {
        out.end -= 1;
        out.value = &out.value[..out.value.len() - 1];
    } else if candidate.value_leftquote.is_none()
        && candidate.value_rightquote.is_none()
        && out.value.ends_with('\\')
        && line
            .get(out.end..)
            .and_then(|tail| tail.chars().next())
            .is_some_and(|next| matches!(next, '\'' | '"' | '`'))
    {
        // The supplemental matcher can leave the escape prefix of an encoded
        // closing quote in the value. Python's keyword regex assigns it to the
        // conditional right-quote capture instead.
        out.end -= 1;
        out.value = &out.value[..out.value.len() - 1];
    }

    if candidate.value_leftquote.is_none() && candidate.value_rightquote.is_none() {
        out = sanitize_unicode_quotes(out);
    }

    if candidate.variable.is_none()
        || is_well_quoted_value(
            candidate.value_leftquote,
            candidate.value_rightquote,
            out.value,
            line,
            file_type,
        )
    {
        return out;
    }

    out = clean_url_parameters(line, candidate, out);
    out = clean_bash_parameters(candidate, out);
    out = clean_toml_parameters(line, out);
    clean_tag_parameters(line, out)
}

fn sanitize_unicode_quotes(mut value: SanitizedValue<'_>) -> SanitizedValue<'_> {
    while let (Some(first), Some(last)) = (value.value.chars().next(), value.value.chars().last()) {
        let first_code = first as u32;
        let last_code = last as u32;
        let matching_single =
            (0x2018..=0x201B).contains(&first_code) && (0x2018..=0x201B).contains(&last_code);
        let matching_double =
            (0x201C..=0x201F).contains(&first_code) && (0x201C..=0x201F).contains(&last_code);
        if !matching_single && !matching_double {
            break;
        }
        let first_len = first.len_utf8();
        let last_len = last.len_utf8();
        if value.value.len() < first_len + last_len {
            break;
        }
        value.start += first_len;
        value.end -= last_len;
        value.value = &value.value[first_len..value.value.len() - last_len];
    }
    value
}

fn is_well_quoted_value(
    left: Option<&str>,
    right: Option<&str>,
    value: &str,
    line: &str,
    file_type: &str,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) if left == right => true,
        (Some(left), Some(right)) => {
            let left_quote = quote_from_left_capture(left);
            let right_quote = quote_from_right_capture(right);
            left_quote.is_some_and(|left_quote| {
                right_quote.is_some_and(|right_quote| left_quote == right_quote)
                    || (right == "\\" && line.ends_with('\\'))
            })
        }
        (Some(left), None) => {
            ((value.ends_with('\\')) && line.ends_with('\\'))
                || file_type == ".php"
                || left.matches('"').count() == 3
                || left.matches('\'').count() == 3
        }
        _ => false,
    }
}

fn quote_from_left_capture(value: &str) -> Option<char> {
    if value.chars().count() == 1 {
        value.chars().next()
    } else {
        value
            .chars()
            .next_back()
            .filter(|ch| matches!(ch, '"' | '\'' | '`'))
    }
}

fn quote_from_right_capture(value: &str) -> Option<char> {
    if value.chars().count() == 1 {
        value.chars().next()
    } else {
        value.chars().find(|ch| matches!(ch, '"' | '\'' | '`'))
    }
}

fn clean_url_parameters<'a>(
    line: &'a str,
    candidate: &Candidate<'a>,
    mut value: SanitizedValue<'a>,
) -> SanitizedValue<'a> {
    let Some(variable) = candidate.variable else {
        return value;
    };
    if variable.ends_with("://") || !is_url_part(line, candidate, value.value) {
        return value;
    }
    let mut cut = value.value.len();
    for delimiter in ['&', ';', '#'] {
        if let Some(pos) = value.value[..cut].find(delimiter) {
            cut = cut.min(pos);
        }
    }
    static URL_UNICODE_SPLIT: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"(?i)\\u00(0000)?(21|23|24|26|27|28|29|2a|2b|2c|2f|3a|3b|3d|3f|40|5b|5d)")
            .expect("url unicode split regex")
    });
    if let Some(m) = URL_UNICODE_SPLIT.find(&value.value[..cut]) {
        cut = cut.min(m.start());
    }
    let escaped_separator = candidate
        .separator
        .is_some_and(|separator| separator.eq_ignore_ascii_case("%3D"));
    if escaped_separator {
        static URL_PERCENT_SPLIT: LazyLock<RustRegex> = LazyLock::new(|| {
            RustRegex::new(r"(?i)%(21|23|24|26|27|28|29|2a|2b|2c|2f|3a|3b|3d|3f|40|5b|5d)")
                .expect("url percent split regex")
        });
        if let Some(m) = URL_PERCENT_SPLIT.find(&value.value[..cut]) {
            cut = cut.min(m.start());
        }
    }
    value.end = value.start + cut;
    value.value = &line[value.start..value.end];
    value
}

fn is_url_part(line: &str, candidate: &Candidate<'_>, value: &str) -> bool {
    let mut url_part = false;
    if candidate.start <= line.len() {
        let before_value = &line[..candidate.start];
        let mut find_pos = 0usize;
        let mut url_pos = None;
        while let Some(rel) = before_value[find_pos..].find("://") {
            let pos = find_pos + rel;
            url_pos = Some(pos);
            find_pos = pos + 3;
        }
        if let Some(pos) = url_pos.filter(|pos| 3 <= *pos) {
            let scheme = &before_value[pos - 3..pos];
            url_part = scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                && !line[pos + 3..candidate.start].chars().any(|ch| {
                    ch.is_whitespace()
                        || matches!(
                            ch,
                            '"' | '<' | '>' | '[' | ']' | '^' | '~' | '`' | '{' | '|' | '}'
                        )
                });
        }
    }
    if let Some(variable_start) = candidate.variable_start.filter(|start| *start > 0) {
        url_part |= line
            .as_bytes()
            .get(variable_start - 1)
            .is_some_and(|b| matches!(*b, b'?' | b'&'));
    }
    static URL_VALUE_PATTERN: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r#"^[^\s&;"<>\[\]^~`{|}]+[&;][^\s=;"<>\[\]^~`{|}]{3,80}=[^\s;&="<>\[\]^~`{|}]{1,80}"#,
        )
        .expect("url value pattern regex")
    });
    url_part
        || URL_VALUE_PATTERN.is_match(value)
        || candidate
            .separator
            .is_some_and(|separator| separator.eq_ignore_ascii_case("%3D"))
}

fn clean_bash_parameters<'a>(
    candidate: &Candidate<'a>,
    mut value: SanitizedValue<'a>,
) -> SanitizedValue<'a> {
    if candidate
        .variable
        .is_some_and(|variable| variable.starts_with('-'))
    {
        static BASH_PARAM_SPLIT: LazyLock<RustRegex> = LazyLock::new(|| {
            RustRegex::new(r"\s+(\-|\||\>|\w+?\>|\&)").expect("bash parameter split regex")
        });
        if let Some(m) = BASH_PARAM_SPLIT.find(value.value) {
            value.end = value.start + m.start();
            value.value = &value.value[..m.start()];
        }
    }
    if !value.value.contains(' ') && (value.value.contains("\\n") || value.value.contains("\\r")) {
        static LINE_ENDINGS: LazyLock<RustRegex> =
            LazyLock::new(|| RustRegex::new(r"\\{1,8}[nr]").expect("line ending split regex"));
        if let Some(m) = LINE_ENDINGS.find(value.value) {
            value.end = value.start + m.start();
            value.value = &value.value[..m.start()];
        }
    }
    value
}

fn clean_toml_parameters<'a>(line: &str, mut value: SanitizedValue<'a>) -> SanitizedValue<'a> {
    loop {
        let Some(last) = value.value.chars().next_back() else {
            return value;
        };
        let Some(left) = (match last {
            '}' => Some('{'),
            ']' => Some('['),
            ')' => Some('('),
            _ => None,
        }) else {
            return value;
        };
        let line_before_value = line.get(..value.start).unwrap_or_default();
        if value.value.contains(left)
            || line_before_value.matches(left).count() <= line_before_value.matches(last).count()
        {
            return value;
        }
        value.end -= last.len_utf8();
        value.value = &value.value[..value.value.len() - last.len_utf8()];
    }
}

fn clean_tag_parameters<'a>(line: &str, mut value: SanitizedValue<'a>) -> SanitizedValue<'a> {
    while value.value.ends_with('>') {
        let Some(closing_tag_pos) = value.value.rfind("</") else {
            break;
        };
        let tag = &value.value[closing_tag_pos + 2..value.value.len() - 1];
        let opening_tag_prefix = format!("<{tag}");
        if value.value.contains(&opening_tag_prefix)
            || !line[..value.start].contains(&opening_tag_prefix)
        {
            break;
        }
        value.end = value.start + closing_tag_pos;
        value.value = &value.value[..closing_tag_pos];
    }
    value
}

fn push_match(
    ml_pending: &mut Vec<PendingMlFinding>,
    ctx: &PushMatchCtx<'_, '_>,
    rule: &NativeRule,
    line_ctx: &CandidateLineContext<'_>,
    candidate: &Candidate<'_>,
) -> bool {
    let sanitized_value = sanitize_value_capture(line_ctx.line, ctx.file_type, candidate);
    let range = ctx.view.to_raw(ByteRange::new(
        line_ctx.start + sanitized_value.start,
        line_ctx.start + sanitized_value.end,
    ));
    if range.is_empty() {
        return false;
    }
    let sanitized_variable = candidate
        .variable
        .zip(candidate.variable_start.zip(candidate.variable_end))
        .and_then(|(variable, (start, end))| {
            let url_variable = candidate
                .separator
                .filter(|separator| separator.eq_ignore_ascii_case("%3D"))
                .map(|_| {
                    variable
                        .rsplit('&')
                        .next()
                        .unwrap_or(variable)
                        .rsplit('?')
                        .next()
                        .unwrap_or(variable)
                        .rsplit(';')
                        .next()
                        .unwrap_or(variable)
                })
                .unwrap_or(variable);
            let sanitized = sanitize_variable_capture(line_ctx.line, url_variable, start, end)?;
            if url_variable != variable && sanitized.0 == url_variable {
                Some((sanitized.0, start, end))
            } else {
                Some(sanitized)
            }
        });
    let filter_candidate = Candidate {
        start: sanitized_value.start,
        end: sanitized_value.end,
        match_end: candidate.match_end,
        value: sanitized_value.value,
        variable_start: sanitized_variable.as_ref().map(|(_, start, _)| *start),
        variable_end: sanitized_variable.as_ref().map(|(_, _, end)| *end),
        variable: sanitized_variable
            .as_ref()
            .map(|(variable, _, _)| variable.as_str()),
        separator: candidate.separator,
        wrap: candidate.wrap,
        value_leftquote: candidate.value_leftquote,
        value_rightquote: candidate.value_rightquote,
        line_data: candidate.line_data.clone(),
    };
    if !accept_value(
        sanitized_value.value,
        rule,
        &filter_candidate,
        line_ctx,
        sanitized_value.start,
        sanitized_value.end,
    ) {
        return false;
    }
    let finding = CredSweeperNativeFinding {
        range,
        rule_name: rule.rule_name.clone(),
        label: rule.label.clone(),
        severity: severity_name(rule.severity).to_string(),
        confidence: rule.confidence,
        confidence_name: confidence_name(rule.confidence).to_string(),
        ml_probability: None,
        value: sanitized_value.value.to_string(),
        value_start: sanitized_value.start,
        value_end: sanitized_value.end,
        variable: sanitized_variable
            .as_ref()
            .map(|(variable, _, _)| variable.clone()),
        variable_start: sanitized_variable.as_ref().map(|(_, start, _)| *start),
        variable_end: sanitized_variable.as_ref().map(|(_, _, end)| *end),
        line_data: candidate
            .line_data
            .iter()
            .map(|line_data| CredSweeperNativeRelatedFinding {
                // Multi-pattern matchers retain whole-text coordinates for
                // every related physical line. Adding the primary line start
                // here would shift both the anchor and secondary value twice.
                range: ctx
                    .view
                    .to_raw(ByteRange::new(line_data.start, line_data.end)),
                value: line_data.value.to_string(),
                value_start: line_data.start,
                value_end: line_data.end,
                variable: line_data.variable.map(str::to_string),
                variable_start: line_data.variable_start,
                variable_end: line_data.variable_end,
            })
            .collect(),
    };
    let variable = sanitized_variable
        .as_ref()
        .map(|(variable, _, _)| variable.as_str())
        .unwrap_or_default();
    let ml_primary = candidate.line_data.first().map(|primary| {
        let text = ctx.view.text();
        let line_start = text[..primary.start]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        let line_end = text[primary.start..]
            .find('\n')
            .map_or(text.len(), |relative| primary.start + relative);
        (
            text[line_start..line_end]
                .trim_end_matches('\r')
                .to_string(),
            primary.value.to_string(),
            primary.start - line_start,
            primary.end - line_start,
            primary.variable.unwrap_or_default().to_string(),
            primary
                .variable_start
                .map(|start| (start - line_start) as isize)
                .unwrap_or(-2),
            primary
                .variable_end
                .map(|end| (end - line_start) as isize)
                .unwrap_or(-2),
            text[..line_start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1,
        )
    });
    let (
        ml_line,
        ml_value,
        ml_value_start,
        ml_value_end,
        ml_variable,
        ml_variable_start,
        ml_variable_end,
        ml_line_num,
    ) = ml_primary.unwrap_or_else(|| {
        (
            line_ctx.line.to_string(),
            sanitized_value.value.to_string(),
            sanitized_value.start,
            sanitized_value.end,
            variable.to_string(),
            sanitized_variable
                .as_ref()
                .map(|(_, start, _)| *start as isize)
                .unwrap_or(-2),
            sanitized_variable
                .as_ref()
                .map(|(_, _, end)| *end as isize)
                .unwrap_or(-2),
            line_ctx.line_index + 1,
        )
    });
    ml_pending.push(PendingMlFinding {
        finding,
        input: MlInput {
            line: ml_line,
            value: ml_value,
            variable: ml_variable,
            value_start: ml_value_start,
            value_end: ml_value_end,
            variable_start: ml_variable_start,
            variable_end: ml_variable_end,
            path: ctx.path.to_string(),
            line_num: ml_line_num,
            file_type: ctx.file_type.to_string(),
            rule_name: rule.rule_name.clone(),
            severity: rule.severity,
        },
        requires_ml: rule.ml_validated,
    });
    true
}

fn localize_whole_text_candidate<'a>(
    candidate: &Candidate<'a>,
    lines: &[(usize, &'a str)],
    file_type: &'a str,
    fallback: &CandidateLineContext<'a>,
) -> (Candidate<'a>, CandidateLineContext<'a>) {
    let Some((line_index, &(line_start, line))) = lines
        .iter()
        .enumerate()
        .rev()
        .find(|(_, (start, _))| *start <= candidate.start)
    else {
        return (candidate.clone(), fallback.clone());
    };
    let previous = line_index
        .checked_sub(1)
        .and_then(|index| lines.get(index))
        .map(|(_, line)| line.trim_end_matches(['\r', '\n']));
    let next = lines
        .get(line_index + 1)
        .map(|(_, line)| line.trim_end_matches(['\r', '\n']));
    let mut localized = candidate.clone();
    localized.start = localized.start.saturating_sub(line_start);
    localized.end = localized.end.saturating_sub(line_start);
    localized.variable_start = localized
        .variable_start
        .map(|start| start.saturating_sub(line_start));
    localized.variable_end = localized
        .variable_end
        .map(|end| end.saturating_sub(line_start));
    (
        localized,
        CandidateLineContext {
            start: line_start,
            line: line.trim_end_matches(['\r', '\n']),
            previous,
            next,
            file_type,
            target: fallback.target,
            line_index,
        },
    )
}

fn push_ml_accepted(out: &mut Vec<CredSweeperNativeFinding>, pending: &[PendingMlFinding]) {
    let mut used = vec![false; pending.len()];
    for i in 0..pending.len() {
        if used[i] {
            continue;
        }
        let mut group_indices = Vec::new();
        let mut group_inputs = Vec::new();
        for j in i..pending.len() {
            if !used[j] && same_ml_group(&pending[i].input, &pending[j].input) {
                used[j] = true;
                group_indices.push(j);
                group_inputs.push(&pending[j].input);
            }
        }
        let has_ml = group_indices.iter().any(|idx| pending[*idx].requires_ml);
        let ml_score = has_ml.then(|| credsweeper_ml::score_group(&group_inputs));
        let accepted = ml_score
            .map(|(score, threshold)| score >= threshold)
            .unwrap_or(true);
        for idx in group_indices {
            if !pending[idx].requires_ml || accepted {
                let mut finding = pending[idx].finding.clone();
                if pending[idx].requires_ml {
                    finding.ml_probability = ml_score.map(|(score, _)| f64::from(score));
                }
                out.push(finding);
            }
        }
    }
}

fn same_ml_group(a: &MlInput, b: &MlInput) -> bool {
    a.path == b.path
        && a.line_num == b.line_num
        && a.value_start == b.value_start
        && a.value_end == b.value_end
}

struct RawRule {
    name: String,
    severity: Option<String>,
    confidence: Option<String>,
    kind: Option<String>,
    values: Option<Vec<String>>,
    min_line_len: Option<usize>,
    required_substrings: Option<Vec<String>>,
    filter_type: Option<FilterList>,
    use_ml: Option<bool>,
    target: Option<Vec<String>>,
}

enum FilterList {
    One(String),
    Many(Vec<String>),
}

impl FilterList {
    fn items(&self) -> Vec<String> {
        let raw = match self {
            Self::One(item) => vec![item.clone()],
            Self::Many(items) => items.clone(),
        };
        raw.into_iter()
            .flat_map(|item| expand_filter_group(&item))
            .collect()
    }
}

fn expand_filter_group(name: &str) -> Vec<String> {
    let filters: &[&str] = match name {
        "GeneralPattern" => &["LineSpecificKeyCheck", "ValuePatternCheck"],
        "TokenPattern" => &[
            "ValueMorphemesCheck",
            "ValueNumberCheck",
            "ValueCamelCaseCheck",
            "ValuePatternCheck",
        ],
        "GeneralKeyword" => &[
            "ValueAllowlistCheck",
            "ValueArrayDictionaryCheck",
            "ValueBlocklistCheck",
            "ValueCamelCaseCheck",
            "ValueFilePathCheck",
            "ValueHexNumberCheck",
            "ValueLastWordCheck",
            "ValueMethodCheck",
            "ValueSimilarityCheck",
            "ValueStringTypeCheck",
            "ValueTokenCheck",
            "ValuePatternCheck",
            "ValueNotAllowedPatternCheck",
            "ValueDictionaryKeywordCheck",
            "ValueSealedSecretCheck",
        ],
        "PasswordKeyword" => &[
            "ValueAllowlistCheck",
            "ValueArrayDictionaryCheck",
            "ValueBlocklistCheck",
            "ValueCamelCaseCheck",
            "ValueFilePathCheck",
            "ValueHexNumberCheck",
            "ValueLastWordCheck",
            "ValueMethodCheck",
            "ValueSimilarityCheck",
            "ValueStringTypeCheck",
            "ValueTokenCheck",
            "ValuePatternCheck",
            "ValueNotAllowedPatternCheck",
            "ValueLengthCheck(4,64)",
            "ValueSplitKeywordCheck",
            "ValueSealedSecretCheck",
            "LineGitBinaryCheck",
            "LineUUEPartCheck",
        ],
        "UrlCredentialsGroup" => &[
            "ValueAllowlistCheck",
            "ValueArrayDictionaryCheck",
            "ValueBlocklistCheck",
            "ValueCamelCaseCheck",
            "ValueFilePathCheck",
            "ValueLastWordCheck",
            "ValueMethodCheck",
            "ValueStringTypeCheck",
            "ValueNotAllowedPatternCheck",
            "ValueTokenCheck",
            "ValueLengthCheck(4,80)",
            "ValuePatternCheck",
        ],
        "WeirdBase36Token" => &[
            "ValueMorphemesCheck(1)",
            "ValuePatternCheck",
            "ValueNumberCheck",
            "ValueTokenBase36Check",
            "ValueEntropyBase36Check",
        ],
        _ => return vec![name.to_string()],
    };
    filters.iter().map(|filter| (*filter).to_string()).collect()
}

struct LineRanges<'a> {
    text: &'a str,
    offset: usize,
}

impl<'a> LineRanges<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, offset: 0 }
    }
}

impl<'a> Iterator for LineRanges<'a> {
    type Item = (usize, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.text.len() {
            return None;
        }
        let start = self.offset;
        let rest = &self.text[start..];
        let len = rest.find('\n').map_or(rest.len(), |idx| idx + 1);
        self.offset += len;
        Some((start, &self.text[start..start + len]))
    }
}

struct LazyLower<'a> {
    original: &'a str,
    lower: std::cell::OnceCell<String>,
}

impl<'a> LazyLower<'a> {
    fn new(original: &'a str) -> Self {
        Self {
            original,
            lower: std::cell::OnceCell::new(),
        }
    }

    fn as_lower(&self) -> &str {
        self.lower.get_or_init(|| {
            if self.original.is_ascii() {
                self.original.to_ascii_lowercase()
            } else {
                self.original.to_lowercase()
            }
        })
    }
}

fn rule_available_for_code_scan(rule: &NativeRule) -> bool {
    rule.targets.iter().any(|target| target == "code")
}

fn accept_value(
    value: &str,
    rule: &NativeRule,
    candidate: &Candidate<'_>,
    line_ctx: &CandidateLineContext<'_>,
    value_start: usize,
    value_end: usize,
) -> bool {
    let value = value.trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == '`');
    if value.len() < 4 {
        return false;
    }
    accept_filter_list(
        value,
        &rule.filter_types,
        candidate,
        line_ctx,
        value_start,
        value_end,
    )
}

fn accept_filter_list(
    value: &str,
    filters: &[String],
    candidate: &Candidate<'_>,
    line_ctx: &CandidateLineContext<'_>,
    value_start: usize,
    value_end: usize,
) -> bool {
    let line = line_ctx.line;
    let well_quoted = candidate_is_well_quoted(candidate, value, line, line_ctx.file_type);
    for filter in filters {
        if filter == "LineGitBinaryCheck" && line_git_binary_filtered(line) {
            return false;
        }
        if filter == "LineUUEPartCheck"
            && line_uue_part_filtered(line, line_ctx.previous, line_ctx.next)
        {
            return false;
        }
        if filter == "LineSpecificKeyCheck"
            && line_specific_key_filtered(line, value_start, value_end)
        {
            return false;
        }
        if filter == "ValueAllowlistCheck"
            && value_allowlist_filtered(value, candidate, well_quoted)
        {
            return false;
        }
        if filter == "ValueArrayDictionaryCheck"
            && value_array_dictionary_filtered(value, candidate, well_quoted)
        {
            return false;
        }
        if filter == "ValueAtlassianTokenCheck" && value_atlassian_token_filtered(value) {
            return false;
        }
        if filter == "ValueBase64EncodedPem" && value_base64_encoded_pem_filtered(value) {
            return false;
        }
        if filter == "ValueBase64KeyCheck" && value_base64_key_filtered(value) {
            return false;
        }
        if filter == "ValueBase64PartCheck"
            && value_base64_part_filtered(value, line, value_start, value_end)
        {
            return false;
        }
        if filter == "ValueAzureTokenCheck" && value_azure_token_filtered(value) {
            return false;
        }
        if filter == "ValueBase32DataCheck" && value_base32_data_filtered(value) {
            return false;
        }
        if filter == "ValueBech32Check" && value_bech32_filtered(value) {
            return false;
        }
        if filter == "ValueBlocklistCheck" && value_blocklist_filtered(value) {
            return false;
        }
        if filter == "ValueDiscordBotCheck" && value_discord_bot_filtered(value) {
            return false;
        }
        if filter == "ValueGrafanaCheck" && value_grafana_filtered(value) {
            return false;
        }
        if filter == "ValueGrafanaServiceCheck" && value_grafana_service_filtered(value) {
            return false;
        }
        if filter == "ValueGitHubCheck" && value_github_filtered(value) {
            return false;
        }
        if filter == "ValueHexNumberCheck" && value_hex_number_filtered(value) {
            return false;
        }
        if filter == "ValueJsonWebKeyCheck" && value_json_web_key_filtered(value) {
            return false;
        }
        if filter == "ValueJsonWebTokenCheck" && value_json_web_token_filtered(value) {
            return false;
        }
        if filter == "ValueJfrogTokenCheck" && value_jfrog_token_filtered(value) {
            return false;
        }
        if filter == "ValueLastWordCheck" && value_last_word_filtered(value, well_quoted) {
            return false;
        }
        if filter.starts_with("ValueLengthCheck") {
            let (min_len, max_len) = parse_filter_length_range(filter).unwrap_or((4, 8000));
            if value_length_filtered(value, min_len, max_len) {
                return false;
            }
        }
        if filter == "ValueMethodCheck" && value_method_filtered(value, well_quoted) {
            return false;
        }
        if filter == "ValueNotAllowedPatternCheck"
            && value_not_allowed_pattern_filtered(value, well_quoted)
        {
            return false;
        }
        if filter == "ValueNotPartEncodedCheck"
            && value_not_part_encoded_filtered(line_ctx.previous, line_ctx.next)
        {
            return false;
        }
        if filter == "ValueSimilarityCheck" && value_similarity_filtered(value, candidate.variable)
        {
            return false;
        }
        if filter == "ValueStringTypeCheck"
            && value_string_type_filtered(value, candidate, line_ctx)
        {
            return false;
        }
        if filter == "ValueSplitKeywordCheck" && value_split_keyword_filtered(value) {
            return false;
        }
        if filter == "ValueTokenCheck" && value_token_filtered(value, well_quoted) {
            return false;
        }
        if filter == "ValueTokenBase32Check" && value_token_base_filtered(value, TokenBase::Base32)
        {
            return false;
        }
        if filter == "ValueTokenBase36Check" && value_token_base_filtered(value, TokenBase::Base36)
        {
            return false;
        }
        if filter == "ValueBasicAuthCheck" && !is_basic_auth_token68(value) {
            return false;
        }
        if filter.starts_with("ValuePatternCheck")
            && value_pattern_filtered(value, parse_filter_usize_arg(filter))
        {
            return false;
        }
        if filter.starts_with("ValueMorphemesCheck")
            && morphemes_filtered(value, parse_filter_usize_arg(filter))
        {
            return false;
        }
        if filter == "ValueDictionaryKeywordCheck" && dictionary_keyword_filtered(value) {
            return false;
        }
        if filter == "ValueNumberCheck" && number_filtered(value) {
            return false;
        }
        if filter == "ValueCamelCaseCheck" && camel_case_filtered(value, well_quoted) {
            return false;
        }
        if filter == "ValueEntropyBase36Check" && entropy_base36_filtered(value) {
            return false;
        }
        if filter == "ValueEntropyBase32Check" && entropy_base32_filtered(value) {
            return false;
        }
        if filter == "ValueEntropyBase64Check" && entropy_base64_filtered(value) {
            return false;
        }
        if filter == "ValueSealedSecretCheck" && value_sealed_secret_filtered(value, line_ctx) {
            return false;
        }
    }
    if filters
        .iter()
        .any(|filter| filter.contains("ValueFilePathCheck"))
        && value_file_path_filtered(value, candidate.separator)
    {
        return false;
    }
    true
}

fn candidate_is_well_quoted(
    candidate: &Candidate<'_>,
    value: &str,
    line: &str,
    file_type: &str,
) -> bool {
    let left = candidate.value_leftquote.unwrap_or_default();
    let right = candidate.value_rightquote.unwrap_or_default();
    if !left.is_empty() && !right.is_empty() {
        if left == right {
            return true;
        }
        let left_quote = if left.len() == 1 {
            left.chars().next()
        } else {
            left.chars().last().filter(|quote| "\"'`".contains(*quote))
        };
        let right_quote = if right.len() == 1 {
            right.chars().next()
        } else {
            right.chars().find(|quote| "\"'`".contains(*quote))
        };
        return left_quote.is_some()
            && ((right_quote.is_some() && left_quote == right_quote)
                || (candidate.value_rightquote == Some("\\") && line.ends_with('\\')));
    }
    if !left.is_empty() {
        return ((candidate.value_rightquote == Some("\\") || value.ends_with('\\'))
            && line.ends_with('\\'))
            || file_type == ".php"
            || left.matches('"').count() == 3
            || left.matches('\'').count() == 3;
    }
    false
}

fn value_array_dictionary_filtered(
    value: &str,
    candidate: &Candidate<'_>,
    well_quoted: bool,
) -> bool {
    if well_quoted {
        return false;
    }
    let wrap = candidate.wrap.unwrap_or_default();
    if wrap.to_ascii_lowercase().contains("byte") {
        return false;
    }
    static ARRAY_OR_DICTIONARY_CALL: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r#"\[['\"]?[^,]+['\"]?]"#).expect("CredSweeper array/dictionary call regex")
    });
    ARRAY_OR_DICTIONARY_CALL.is_match(value) || wrap.ends_with('[') || wrap.ends_with('(')
}

fn value_base32_data_filtered(value: &str) -> bool {
    if !value.bytes().any(|byte| byte.is_ascii_digit())
        || !value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return true;
    }
    let mut padded = value.to_string();
    if !padded.len().is_multiple_of(8) {
        padded.extend(std::iter::repeat_n('=', 8 - padded.len() % 8));
    }
    CREDSWEEPER_BASE32
        .decode(padded.as_bytes())
        .map_or(true, |decoded| ascii_entropy_filtered(&decoded))
}

fn value_bech32_filtered(value: &str) -> bool {
    let value = value.to_lowercase();
    if value.chars().any(|ch| !(33..=126).contains(&(ch as u32))) {
        return true;
    }
    let Some(separator) = value.rfind('1') else {
        return true;
    };
    if !(1..=83).contains(&separator) || separator + 7 > value.len() {
        return true;
    }
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let Some(data) = value[separator + 1..]
        .chars()
        .map(|ch| CHARSET.find(ch).map(|index| index as u8))
        .collect::<Option<Vec<_>>>()
    else {
        return true;
    };
    if data.len() <= 6 {
        return true;
    }
    bech32_polymod(&value[..separator], &data) != 1
}

fn bech32_polymod(hrp: &str, data: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1u32;
    let values = hrp
        .bytes()
        .map(|byte| byte >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|byte| byte & 31))
        .chain(data.iter().copied());
    for value in values {
        let top = checksum >> 25;
        checksum = (checksum & 0x01ff_ffff) << 5 ^ u32::from(value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if ((top >> index) & 1) != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn ascii_entropy_filtered(data: &[u8]) -> bool {
    if data.len() < 9 || data.iter().all(u8::is_ascii) {
        return true;
    }
    let mut cells = [0usize; 256];
    for byte in data {
        cells[usize::from(*byte)] += 1;
    }
    let mut entropy = 0.0;
    let step = 256.0 / data.len() as f64;
    let (mut left, mut right) = (0.0, step);
    while left < 256.0 {
        let start = left as usize;
        let end = (right as usize).min(256);
        let count = cells[start..end].iter().sum::<usize>();
        let probability = count as f64 / data.len() as f64;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
        left = right;
        right += step;
    }
    entropy < minimum_data_entropy(data.len())
}

fn minimum_data_entropy(len: usize) -> f64 {
    match len {
        16 => 1.669_736_717_803_48,
        20 => 2.077_235_445_408_31,
        32 => 3.253_928_031_846_02,
        40 => 3.648_535_670_648_67,
        64 => 4.577_569_336_880_35,
        384 => 7.39,
        512 => 7.55,
        9..=63 => {
            let x = (len - 8) as f64;
            ((0.000_016_617_804 * x - 0.002_695_077) * x + 0.170_393) * x + 0.4
        }
        65..=383 => 1.095_884 * ((len - 8) as f64).log2() - 1.901_56,
        385..=511 => {
            let log = (len as f64).log2();
            -0.112_158_51 * log * log + 2.343_034_84 * log - 4.446_623_7
        }
        _ => 0.0,
    }
}

fn value_allowlist_filtered(value: &str, candidate: &Candidate<'_>, well_quoted: bool) -> bool {
    // Mirrors CredSweeper ValueAllowlistCheck: these are syntax/template
    // expressions, not credential material.
    if value_allowlist_common_patterns()
        .iter()
        .any(|pattern| pattern.is_match(value))
    {
        return true;
    }
    if well_quoted {
        value_allowlist_quoted_patterns()
            .iter()
            .any(|pattern| pattern.is_match(value))
    } else {
        let wrapped;
        let value = if let Some(wrap) = candidate.wrap {
            wrapped = format!("{wrap}{value}");
            wrapped.as_str()
        } else {
            value
        };
        value_allowlist_unquoted_patterns()
            .iter()
            .any(|pattern| pattern.is_match(value))
    }
}

fn value_allowlist_common_patterns() -> &'static [RustRegex] {
    static PATTERNS: LazyLock<Vec<RustRegex>> = LazyLock::new(|| {
        [
            r"(?i)^ENC\(.*\)",
            r"(?i)^ENC\[.*\]",
            r"(?i)^\$\{(\*|[0-9]+|[a-z_].*)\}",
            r"(?i)^\$[0-9]+(\s|$)",
            r"(?i)^\$\$[a-z_]+(\^%[0-9a-z_]+)?",
            r"(?i)^#\{.+\}",
            r"(?i)^\{\{.+\}\}",
            r"(?i)^.*@@@hl@@@(암호|비번|PW|PASS)@@@endhl@@@",
        ]
        .into_iter()
        .map(|pattern| RustRegex::new(pattern).expect("static CredSweeper allowlist regex"))
        .collect()
    });
    &PATTERNS
}

fn value_allowlist_quoted_patterns() -> &'static [RustRegex] {
    static PATTERNS: LazyLock<Vec<RustRegex>> = LazyLock::new(|| {
        [
            r"(?i)^\$[a-z_][0-9a-z_]+((::|->|\.)[a-z_]|\[|$)",
            r"(?i)^\$\([^)]+\)",
            r"(?i)^.*\*\*\*",
        ]
        .into_iter()
        .map(|pattern| RustRegex::new(pattern).expect("static CredSweeper quoted allowlist regex"))
        .collect()
    });
    &PATTERNS
}

fn value_allowlist_unquoted_patterns() -> &'static [RustRegex] {
    static PATTERNS: LazyLock<Vec<RustRegex>> = LazyLock::new(|| {
        [
            r"(?i)^[~a-z0-9_]+((\.|->)[a-z0-9_]+)+\(.*$",
            r"(?i)^\$[a-z_][0-9a-z_]+((::|->|\.)[a-z_]|\[|$)",
            r"(?i)^\$\([.0-9a-z_-]+",
            r"(?i)^.*\*\*\*\*\*",
        ]
        .into_iter()
        .map(|pattern| {
            RustRegex::new(pattern).expect("static CredSweeper unquoted allowlist regex")
        })
        .collect()
    });
    &PATTERNS
}

fn value_blocklist_filtered(value: &str) -> bool {
    const NOT_ALLOWED: &[&str] = &[
        "true",
        "false",
        "null",
        "none",
        "bearer",
        "string",
        "value",
        "undefined",
        "uuid",
    ];
    let lower = value.to_ascii_lowercase();
    NOT_ALLOWED
        .iter()
        .any(|word| lower.contains(word) && (*word).len() as f64 / lower.len().max(1) as f64 >= 0.7)
}

fn value_hex_number_filtered(value: &str) -> bool {
    let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    (1..=16).contains(&hex.len()) && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_base64_like_upstream(value: &str) -> Option<Vec<u8>> {
    let mut value = value
        .chars()
        .filter(|ch| !matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c'))
        .collect::<String>();
    while value.ends_with('=') {
        value.pop();
    }
    if !value.len().is_multiple_of(4) {
        value.extend(std::iter::repeat_n('=', 4 - value.len() % 4));
    }
    if value.contains(['-', '_']) {
        // Python's altchars mode accepts both the standard and URL-safe
        // alphabet in one value. Translate only the URL-safe alternatives.
        value = value.replace('-', "+").replace('_', "/");
    }
    CREDSWEEPER_BASE64.decode(value.as_bytes()).ok()
}

fn json_is_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Array(value) => !value.is_empty(),
        serde_json::Value::Object(value) => !value.is_empty(),
    }
}

fn json_contains_python(value: &serde_json::Value, key: &str) -> Option<bool> {
    match value {
        serde_json::Value::Object(value) => Some(value.contains_key(key)),
        serde_json::Value::Array(value) => Some(
            value
                .iter()
                .any(|item| item.as_str().is_some_and(|item| item == key)),
        ),
        serde_json::Value::String(value) => Some(value.contains(key)),
        _ => None,
    }
}

fn value_azure_token_filtered(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return true;
    };
    let Some(header) = decode_base64_like_upstream(header)
        .and_then(|value| serde_json::from_slice::<serde_json::Value>(&value).ok())
    else {
        return true;
    };
    if !["alg", "typ", "kid"]
        .iter()
        .all(|key| json_contains_python(&header, key) == Some(true))
    {
        return true;
    }
    let Some(payload) = decode_base64_like_upstream(payload)
        .and_then(|value| serde_json::from_slice::<serde_json::Value>(&value).ok())
    else {
        return true;
    };
    if !["iss", "exp", "iat"]
        .iter()
        .all(|key| json_contains_python(&payload, key) == Some(true))
    {
        return true;
    }
    shannon_entropy(signature) < minimum_base64_entropy(signature.len())
}

fn value_discord_bot_filtered(value: &str) -> bool {
    let Some(separator) = value.find('.') else {
        return true;
    };
    let Some(id) = decode_base64_like_upstream(&value[..separator]) else {
        return true;
    };
    let Ok(id) = std::str::from_utf8(&id) else {
        return true;
    };
    let Ok(id) = id.trim().parse::<u128>() else {
        return true;
    };
    let entropy_part = &value[separator..];
    id < 1000 || shannon_entropy(entropy_part) < minimum_base64_entropy(entropy_part.len())
}

fn value_grafana_filtered(value: &str) -> bool {
    let (encoded, keys): (&str, &[&str]) = if let Some(encoded) = value.strip_prefix("glc_") {
        (encoded, &["o", "n", "k", "m"])
    } else {
        (value, &["n", "k", "id"])
    };
    let Some(payload) = decode_base64_like_upstream(encoded)
        .and_then(|value| serde_json::from_slice::<serde_json::Value>(&value).ok())
    else {
        return true;
    };
    !json_is_truthy(&payload)
        || !keys
            .iter()
            .all(|key| json_contains_python(&payload, key) == Some(true))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn atlassian_struct_filtered(value: &str) -> bool {
    let Some(decoded) = decode_base64_like_upstream(value) else {
        return true;
    };
    let Some(delimiter) = decoded.iter().position(|byte| *byte == b':') else {
        return true;
    };
    if !(1..=20).contains(&delimiter) {
        return true;
    }
    let integer = decoded[..delimiter]
        .iter()
        .map(|byte| char::from(*byte))
        .collect::<String>();
    let normalized = integer.trim().replace('_', "");
    let Ok(integer) = normalized.parse::<i128>() else {
        return true;
    };
    integer < 1000 || ascii_entropy_filtered(&decoded[delimiter + 1..])
}

fn atlassian_crc32_struct_filtered(value: &str) -> bool {
    if !value.is_ascii() || value.len() < 8 {
        return true;
    }
    let Ok(checksum) = u32::from_str_radix(&value[value.len() - 8..], 16) else {
        return true;
    };
    checksum != crc32(&value.as_bytes()[..value.len() - 8])
}

fn value_atlassian_token_filtered(value: &str) -> bool {
    if let Some(value) = value.strip_prefix("BBDC-") {
        return atlassian_struct_filtered(value);
    }
    if value.starts_with("AT") {
        let mut value = value.to_string();
        while value.contains("\\=") || value.contains("%3d") || value.contains("%3D") {
            value = value.replace('\\', "");
            value = value.replace("%3d", "=");
            value = value.replace("%3D", "=");
        }
        return atlassian_crc32_struct_filtered(&value);
    }
    atlassian_struct_filtered(value)
}

fn decode_base62_integer(value: &str) -> Option<u64> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    value.bytes().try_fold(0u64, |output, byte| {
        let digit = ALPHABET.iter().position(|item| *item == byte)? as u64;
        output.checked_mul(62)?.checked_add(digit)
    })
}

fn value_github_filtered(value: &str) -> bool {
    let github_prefix = value.starts_with("gh") && value.as_bytes().get(3) == Some(&b'_');
    if !(github_prefix || value.starts_with("npm_")) || value.len() < 10 || !value.is_ascii() {
        return true;
    }
    let token_end = value.len() - 6;
    let Some(checksum) = decode_base62_integer(&value[token_end..]) else {
        return true;
    };
    u64::from(crc32(&value.as_bytes()[4..token_end])) != checksum
}

fn base58_decoded_length(value: &str) -> Option<usize> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let leading_zeroes = value.bytes().take_while(|byte| *byte == b'1').count();
    let mut little_endian = Vec::<u8>::new();
    for byte in value.bytes() {
        let mut carry = ALPHABET.iter().position(|item| *item == byte)? as u32;
        for output in &mut little_endian {
            carry += u32::from(*output) * 58;
            *output = carry as u8;
            carry >>= 8;
        }
        while carry != 0 {
            little_endian.push(carry as u8);
            carry >>= 8;
        }
    }
    Some(leading_zeroes + little_endian.len())
}

fn value_jfrog_token_filtered(value: &str) -> bool {
    if value.starts_with("cmVmdGtuO") {
        let Some(decoded) = decode_base64_like_upstream(value) else {
            return true;
        };
        let Ok(decoded) = std::str::from_utf8(&decoded) else {
            return true;
        };
        static IDENTITY: LazyLock<RustRegex> = LazyLock::new(|| {
            RustRegex::new(r"^reftkn:\d+:\d+:[\w_/+\-]+")
                .expect("static JFrog identity token regex")
        });
        if IDENTITY.is_match(decoded) {
            return false;
        }
    }
    if value.starts_with("AKCp") && base58_decoded_length(value) == Some(54) {
        return false;
    }
    true
}

fn is_base64_standard_or_backslash(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'\\')
}

fn base64_hunk_matches(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 4000 {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'+' | b'/' | b'=') {
            index += 1;
            continue;
        }
        if bytes[index] != b'\\' {
            return false;
        }
        let start = index;
        while index < bytes.len() && bytes[index] == b'\\' && index - start < 8 {
            index += 1;
        }
        if index == bytes.len()
            || !matches!(
                bytes[index],
                b'0' | b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v'
            )
        {
            return false;
        }
        index += 1;
    }
    true
}

fn sample_stdev(values: &[f64], mean: f64) -> f64 {
    (values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / (values.len() - 1) as f64)
        .sqrt()
}

fn value_base64_part_filtered(
    value: &str,
    line: &str,
    value_start: usize,
    value_end: usize,
) -> bool {
    if value_start > line.len()
        || value_end > line.len()
        || value_start > value_end
        || !line.is_char_boundary(value_start)
        || !line.is_char_boundary(value_end)
    {
        return false;
    }
    let len_value = value.len();
    if len_value == 0 {
        return false;
    }
    let bytes = line.as_bytes();
    let adjacent = (value_start == 0 && line.len() >= 2 * len_value)
        || (value_start > 0 && matches!(bytes[value_start - 1], b'/' | b'+' | b'\\' | b'%'))
        || (value_end > 0
            && value_end < line.len()
            && matches!(bytes[value_end], b'/' | b'+' | b'\\' | b'%'));
    if !adjacent {
        return false;
    }
    if value.contains(['-', '_']) {
        return false;
    }
    let left_start = value_start.saturating_sub(len_value);
    let right_end = line.len().min(value_end.saturating_add(len_value));
    let hunk = &line[left_start..right_end];
    if right_end - left_start == 3 * len_value {
        if base64_hunk_matches(hunk) {
            return true;
        }
    } else if right_end - left_start >= 2 * len_value
        && hunk.bytes().all(is_base64_standard_or_backslash)
    {
        return true;
    }
    let left_part = line[left_start..value_start]
        .bytes()
        .rev()
        .take_while(|byte| is_base64_standard_or_backslash(*byte))
        .map(char::from)
        .collect::<String>();
    let right_part = line[value_end..right_end]
        .bytes()
        .take_while(|byte| is_base64_standard_or_backslash(*byte))
        .map(char::from)
        .collect::<String>();
    let left_entropy = shannon_entropy(&left_part);
    let value_entropy = shannon_entropy(value);
    let right_entropy = shannon_entropy(&right_part);
    let common = format!("{left_part}{value}{right_part}");
    let common_entropy = shannon_entropy(&common);
    if minimum_base64_entropy(common.len()) < common_entropy {
        return true;
    }
    let minimum = minimum_base64_entropy(len_value);
    let data = if left_entropy != 0.0 && right_entropy != 0.0 {
        [
            left_entropy,
            value_entropy,
            right_entropy,
            minimum,
            common_entropy,
        ]
    } else if left_entropy != 0.0 {
        [
            left_entropy,
            value_entropy,
            minimum,
            minimum,
            common_entropy,
        ]
    } else if right_entropy != 0.0 {
        [
            value_entropy,
            right_entropy,
            minimum,
            minimum,
            common_entropy,
        ]
    } else {
        return false;
    };
    let average = data.iter().sum::<f64>() / data.len() as f64;
    let average_minimum = average - 1.1 * sample_stdev(&data, average);
    (left_entropy == 0.0
        || average_minimum < left_entropy
        || (left_entropy < value_entropy && value_entropy < right_entropy))
        && (right_entropy == 0.0
            || average_minimum < right_entropy
            || (right_entropy < value_entropy && value_entropy < left_entropy))
}

fn encoded_adjacent_line_filtered(line: &str, before: bool) -> Option<bool> {
    static BEFORE: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(concat!(
            r"^(?:^|[^A-Za-z0-9]+)(?P<val>",
            r"(?:[A-Za-z0-9_-]{4}){16,64}|(?:[A-Za-z0-9+/]{4}){16,64}",
            r")(?:[^=A-Za-z0-9+/|_-]+|$)"
        ))
        .expect("static preceding encoded-data regex")
    });
    static AFTER: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(concat!(
            r"^(?:^|[^A-Za-z0-9]+)(?P<val>",
            r"(?:[A-Za-z0-9=_-]{4}){4,64}|(?:[A-Za-z0-9=+/]{4}){4,64}",
            r")(?:[^=A-Za-z0-9+/|_-]+|$)"
        ))
        .expect("static following encoded-data regex")
    });
    let value = if before { &BEFORE } else { &AFTER }
        .captures(line)?
        .name("val")?
        .as_str();
    Some(
        !value.starts_with('/')
            || !morphemes_filtered_with_threshold(&value.to_lowercase(), 2)
            || value.ends_with('='),
    )
}

fn value_not_part_encoded_filtered(previous: Option<&str>, next: Option<&str>) -> bool {
    previous
        .and_then(|line| encoded_adjacent_line_filtered(line, true))
        .or_else(|| next.and_then(|line| encoded_adjacent_line_filtered(line, false)))
        .unwrap_or(false)
}

fn value_grafana_service_filtered(value: &str) -> bool {
    if !value.is_ascii() || value.len() < 46 {
        return true;
    }
    let checksum = &value.as_bytes()[38..];
    if checksum.len() != 8 {
        return true;
    }
    let mut checksum_bytes = [0u8; 4];
    for (output, digits) in checksum_bytes.iter_mut().zip(checksum.chunks_exact(2)) {
        let Some(high) = (digits[0] as char).to_digit(16) else {
            return true;
        };
        let Some(low) = (digits[1] as char).to_digit(16) else {
            return true;
        };
        *output = ((high << 4) | low) as u8;
    }
    u32::from_le_bytes(checksum_bytes) != crc32(&value.as_bytes()[..37])
}

fn value_json_web_key_filtered(value: &str) -> bool {
    let Some(data) = decode_base64_like_upstream(value) else {
        return true;
    };
    !(data.windows(6).any(|window| window == br#""kty":"#)
        && ((data.windows(5).any(|window| window == br#""oct""#)
            && data.windows(4).any(|window| window == br#""k":"#))
            || ((data.windows(4).any(|window| window == br#""EC""#)
                || data.windows(5).any(|window| window == br#""RSA""#))
                && data.windows(4).any(|window| window == br#""d":"#))))
}

fn value_json_web_token_filtered(value: &str) -> bool {
    const HEADER_KEYS: &[&str] = &[
        "kid", "x5u", "x5t", "x5t#S256", "typ", "cty", "crit", "alg", "enc", "zip", "jku", "jwk",
        "x5c", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "iss", "sub", "aud", "b64", "ppt",
        "url", "nonce", "svt",
    ];
    const PAYLOAD_KEYS: &[&str] = &[
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "kty", "use", "key_ops", "alg", "enc",
        "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "x", "y", "d", "n", "e", "p",
        "q", "dp", "dq", "qi", "oth", "k", "crv", "ext", "crit", "keys", "id", "role", "token",
        "secret", "password", "nonce",
    ];
    let (mut header, mut payload, mut signature) = (false, false, false);
    for part in value.split('.') {
        let Some(data) = decode_base64_like_upstream(part) else {
            return true;
        };
        if part.starts_with("eyJ") {
            let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) else {
                return true;
            };
            let Some(object) = json.as_object() else {
                return true;
            };
            if !header {
                header = object.keys().any(|key| HEADER_KEYS.contains(&key.as_str()));
            } else if !payload {
                payload = object
                    .keys()
                    .any(|key| PAYLOAD_KEYS.contains(&key.as_str()));
            }
        } else if header && payload && !signature {
            let bit_length = part.len().checked_ilog2().map_or(0, |value| value + 1);
            let threshold = if bit_length <= 4 {
                1
            } else {
                bit_length as usize - 3
            };
            signature = !ascii_entropy_filtered(&data)
                && !morphemes_filtered_with_threshold(&part.to_lowercase(), threshold);
        } else {
            break;
        }
    }
    !(header && payload && signature)
}

fn value_last_word_filtered(value: &str, well_quoted: bool) -> bool {
    value.chars().count() < 16 && !well_quoted && value.ends_with(':')
}

fn value_length_filtered(value: &str, min_len: usize, max_len: usize) -> bool {
    !(min_len..=max_len).contains(&value.chars().count())
}

fn parse_filter_length_range(filter: &str) -> Option<(usize, usize)> {
    let start = filter.find('(')? + 1;
    let end = filter[start..].find(')')? + start;
    let mut values = filter[start..end].split(',').map(str::trim);
    let min_len = values.next()?.parse().ok()?;
    let max_len = values.next()?.parse().ok()?;
    (values.next().is_none()).then_some((min_len, max_len))
}

fn value_method_filtered(value: &str, well_quoted: bool) -> bool {
    if well_quoted {
        return false;
    }
    static METHOD: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"^[~.\->:0-9A-Za-z_]+\(.*\)").expect("CredSweeper method-call regex")
    });
    value.contains("function") || METHOD.is_match(value)
}

fn value_not_allowed_pattern_filtered(value: &str, well_quoted: bool) -> bool {
    if well_quoted {
        return false;
    }
    static NOT_ALLOWED: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r"(?i)(?:[<>\[\]{}]\s+|\\u00(?:26|3c)gt;?(?:\s|\\+[nrt])?|^\s*\\|^\s*\\n\s*)$",
        )
        .expect("CredSweeper not-allowed value regex")
    });
    NOT_ALLOWED.is_match(value)
}

fn value_similarity_filtered(value: &str, variable: Option<&str>) -> bool {
    let Some(variable) = variable.filter(|variable| !variable.is_empty()) else {
        return false;
    };
    if value.is_empty() {
        return false;
    }
    let variable = variable.to_lowercase();
    let value = value.to_lowercase();
    let variable_len = variable.chars().count();
    let value_len = value.chars().count();
    if value_len <= variable_len {
        if variable.contains(&value) {
            return true;
        }
    } else if 4 <= variable_len && value.contains(&variable) {
        return true;
    }
    0.75 < sequence_matcher_ratio(&variable, &value)
}

fn sequence_matcher_ratio(a: &str, b: &str) -> f64 {
    let a = a.chars().collect::<Vec<_>>();
    let b = b.chars().collect::<Vec<_>>();
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let mut b2j = BTreeMap::<char, Vec<usize>>::new();
    for (index, ch) in b.iter().copied().enumerate() {
        b2j.entry(ch).or_default().push(index);
    }
    if b.len() >= 200 {
        let popularity_limit = b.len() / 100 + 1;
        b2j.retain(|_, positions| positions.len() <= popularity_limit);
    }

    let mut pending = vec![(0usize, a.len(), 0usize, b.len())];
    let mut blocks = Vec::new();
    while let Some((alo, ahi, blo, bhi)) = pending.pop() {
        let (i, j, size) = sequence_longest_match(&a, &b, &b2j, alo, ahi, blo, bhi);
        if size == 0 {
            continue;
        }
        blocks.push((i, j, size));
        if alo < i && blo < j {
            pending.push((alo, i, blo, j));
        }
        if i + size < ahi && j + size < bhi {
            pending.push((i + size, ahi, j + size, bhi));
        }
    }
    blocks.sort_unstable();
    let mut merged: Vec<(usize, usize, usize)> = Vec::new();
    for (i, j, size) in blocks {
        if let Some((last_i, last_j, last_size)) = merged.last_mut() {
            if *last_i + *last_size == i && *last_j + *last_size == j {
                *last_size += size;
                continue;
            }
        }
        merged.push((i, j, size));
    }
    let matched = merged.iter().map(|(_, _, size)| size).sum::<usize>();
    2.0 * matched as f64 / (a.len() + b.len()) as f64
}

fn sequence_longest_match(
    a: &[char],
    b: &[char],
    b2j: &BTreeMap<char, Vec<usize>>,
    alo: usize,
    ahi: usize,
    blo: usize,
    bhi: usize,
) -> (usize, usize, usize) {
    let (mut best_i, mut best_j, mut best_size) = (alo, blo, 0usize);
    let mut previous = BTreeMap::<usize, usize>::new();
    for (i, ch) in a.iter().enumerate().take(ahi).skip(alo) {
        let mut current = BTreeMap::new();
        if let Some(positions) = b2j.get(ch) {
            for &j in positions {
                if j < blo {
                    continue;
                }
                if bhi <= j {
                    break;
                }
                let size = previous.get(&j.wrapping_sub(1)).copied().unwrap_or(0) + 1;
                current.insert(j, size);
                if size > best_size {
                    (best_i, best_j, best_size) = (i + 1 - size, j + 1 - size, size);
                }
            }
        }
        previous = current;
    }
    while best_i > alo && best_j > blo && a[best_i - 1] == b[best_j - 1] {
        best_i -= 1;
        best_j -= 1;
        best_size += 1;
    }
    while best_i + best_size < ahi
        && best_j + best_size < bhi
        && a[best_i + best_size] == b[best_j + best_size]
    {
        best_size += 1;
    }
    (best_i, best_j, best_size)
}

fn value_token_filtered(value: &str, well_quoted: bool) -> bool {
    if well_quoted {
        return false;
    }
    let chars = value.chars().collect::<Vec<_>>();
    let split = chars.iter().enumerate().find_map(|(index, ch)| {
        if matches!(
            ch,
            ';' | '(' | ')' | '{' | '}' | '<' | '>' | '[' | ']' | '`'
        ) {
            return Some(index);
        }
        if *ch == ' '
            && (index == 0 || python_word_char(chars[index - 1]))
            && (index + 1 == chars.len() || python_word_char(chars[index + 1]))
        {
            return Some(index);
        }
        None
    });
    split.is_some_and(|token_len| token_len < 5)
}

fn value_string_type_filtered(
    value: &str,
    candidate: &Candidate<'_>,
    line_ctx: &CandidateLineContext<'_>,
) -> bool {
    if candidate_url_part(candidate, line_ctx.line) || multibyte_literal(value) {
        return false;
    }
    if !source_file_requires_quotes(line_ctx.file_type)
        || line_is_comment(line_ctx.line)
        || is_well_quoted_value(
            candidate.value_leftquote,
            candidate.value_rightquote,
            candidate.value,
            line_ctx.line,
            line_ctx.file_type,
        )
        || candidate_has_outer_quotes(candidate, line_ctx.line)
        || value.starts_with(|ch: char| ch.is_ascii_digit())
        || !candidate
            .separator
            .is_some_and(|separator| separator.contains('='))
    {
        return false;
    }
    true
}

fn value_split_keyword_filtered(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower
        .split_whitespace()
        .any(|word| keyword_checklist_by_length().contains(&word))
}

fn source_file_requires_quotes(file_type: &str) -> bool {
    matches!(
        file_type,
        ".cs"
            | ".cc"
            | ".php"
            | ".tf"
            | ".kt"
            | ".go"
            | ".ipynb"
            | ".ts"
            | ".java"
            | ".js"
            | ".py"
            | ".cpp"
            | ".c"
            | ".h"
            | ".hpp"
    )
}

fn line_is_comment(line: &str) -> bool {
    const COMMENT_STARTS: &[&str] = &[
        "//", "* ", "# ", "/*", "<!––", "%{", "%", "...", "(*", "--", "--[[", "#=",
    ];
    let line = line.trim();
    COMMENT_STARTS.iter().any(|start| line.starts_with(start))
}

fn candidate_has_outer_quotes(candidate: &Candidate<'_>, line: &str) -> bool {
    let left = candidate
        .variable_start
        .filter(|start| *start > 0)
        .and_then(|start| line.get(..start))
        .and_then(|prefix| prefix.chars().find(|ch| matches!(ch, '"' | '\'' | '`')));
    let right = line
        .get(candidate.end..)
        .and_then(|suffix| suffix.chars().find(|ch| matches!(ch, '"' | '\'' | '`')));
    left.is_some() && left == right
}

fn multibyte_literal(value: &str) -> bool {
    static MULTIBYTE: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"(?i)((0x)?[0-9a-f]{1,16}[UL]*)(\s*,\s*((0x)?[0-9a-f]{1,16}[UL]*)){3}")
            .expect("CredSweeper multibyte literal regex")
    });
    MULTIBYTE.is_match(value)
}

fn candidate_url_part(candidate: &Candidate<'_>, line: &str) -> bool {
    let line_before_value = line.get(..candidate.start).unwrap_or_default();
    let scheme = line_before_value.rfind("://").is_some_and(|position| {
        let prefix = &line_before_value[..position];
        let scheme_part = prefix.chars().rev().take(3).collect::<Vec<_>>();
        scheme_part.len() == 3
            && scheme_part
                .iter()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
            && !line_before_value[position + 3..]
                .chars()
                .any(url_forbidden_char)
    });
    let query_variable = candidate
        .variable_start
        .filter(|start| *start > 0)
        .and_then(|start| line.get(..start))
        .and_then(|prefix| prefix.chars().last())
        .is_some_and(|ch| matches!(ch, '?' | '&'));
    static URL_VALUE: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(
            r#"^[^\s&;"<>\[\]^~`{|}]+[&;][^\s=;"<>\[\]^~`{|}]{3,80}=[^\s;&="<>\[\]^~`{|}]{1,80}"#,
        )
        .expect("CredSweeper URL value regex")
    });
    scheme
        || query_variable
        || URL_VALUE.is_match(candidate.value)
        || line
            .get(candidate.start..)
            .is_some_and(|tail| URL_VALUE.is_match(tail))
        || candidate
            .separator
            .is_some_and(|separator| separator.eq_ignore_ascii_case("%3D"))
}

fn url_forbidden_char(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '"' | '<' | '>' | '[' | ']' | '^' | '~' | '`' | '{' | '|' | '}'
        )
}

fn python_word_char(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

#[derive(Clone, Copy)]
enum TokenBase {
    Base32,
    Base36,
}

fn value_token_base_filtered(value: &str, base: TokenBase) -> bool {
    let Some((hop, deviation)) = keyboard_hop_stats(value) else {
        return false;
    };
    let Some(((hop_mean, hop_dev), (dev_mean, dev_dev))) = token_base_range(value.len(), base)
    else {
        return false;
    };
    let Some(ppf) = token_base_ppf(value.len()) else {
        return false;
    };
    let hop_range = (hop_mean - ppf * hop_dev)..=(hop_mean + ppf * hop_dev);
    let deviation_range = (dev_mean - ppf * dev_dev)..=(dev_mean + ppf * dev_dev);
    !(hop_range.contains(&hop) && deviation_range.contains(&deviation))
}

fn keyboard_hop_stats(value: &str) -> Option<(f64, f64)> {
    let normalized = value.chars().map(keyboard_normalize).collect::<String>();
    let chars = normalized.chars().collect::<Vec<_>>();
    if chars.len() < 3 {
        return None;
    }
    let mut hops = Vec::with_capacity(chars.len() - 1);
    for pair in chars.windows(2) {
        let (ax, ay, az) = keyboard_coordinates(pair[0])?;
        let (bx, by, bz) = keyboard_coordinates(pair[1])?;
        hops.push(((ax - bx).abs() + (ay - by).abs() + (az - bz).abs()) as f64 / 2.0);
    }
    let mean = hops.iter().sum::<f64>() / hops.len() as f64;
    let variance =
        hops.iter().map(|hop| (hop - mean).powi(2)).sum::<f64>() / (hops.len() - 1) as f64;
    Some((mean, variance.sqrt()))
}

fn keyboard_normalize(ch: char) -> char {
    match ch {
        '~' => '`',
        '!' => '1',
        '@' => '2',
        '#' => '3',
        '$' => '4',
        '%' => '5',
        '^' => '6',
        '&' => '7',
        '*' => '8',
        '(' => '9',
        ')' => '0',
        '_' => '-',
        '+' => '=',
        '{' => '[',
        '}' => ']',
        '|' => '\\',
        ':' => ';',
        '"' => '\'',
        '<' => ',',
        '>' => '.',
        '?' => '/',
        _ => ch.to_ascii_lowercase(),
    }
}

fn keyboard_coordinates(ch: char) -> Option<(isize, isize, isize)> {
    const ROWS: &[&str] = &[
        "`1234567890-=",
        "\0qwertyuiop[]\\",
        "\0\0asdfghjkl;'",
        "\0\0zxcvbnm,./",
    ];
    for (row, keys) in ROWS.iter().enumerate() {
        if let Some(raw_x) = keys.find(ch) {
            let x = raw_x as isize - (row / 2) as isize;
            let z = row as isize;
            return Some((x, -(z + x), z));
        }
    }
    None
}

fn token_base_ppf(len: usize) -> Option<f64> {
    Some(match len {
        8 => 2.616_197_46,
        10 => 2.486_856_59,
        15 => 2.340_252_71,
        16 => 2.323_702_90,
        20 => 2.276_149_96,
        24 => 2.246_095_86,
        25 => 2.240_235_15,
        32 => 2.210_252_77,
        40 => 2.189_615_71,
        50 => 2.173_552_82,
        64 => 2.159_812_41,
        _ => return None,
    })
}

type TokenRange = ((f64, f64), (f64, f64));

fn token_base_range(len: usize, base: TokenBase) -> Option<TokenRange> {
    Some(match (base, len) {
        (TokenBase::Base32, 8) => (
            (3.480934, 0.8482364556537906),
            (1.9280820731422028, 0.5833143826506801),
        ),
        (TokenBase::Base32, 10) => (
            (3.4801753333333334, 0.7508676237320747),
            (1.9558544090983234, 0.5119385414964345),
        ),
        (TokenBase::Base32, 15) => (
            (3.4803549285714284, 0.603220270918794),
            (1.9896690734372564, 0.40640877687972476),
        ),
        (TokenBase::Base32, 16) => (
            (3.4798649333333334, 0.5837818960141307),
            (1.9938368543943692, 0.392547066949958),
        ),
        (TokenBase::Base32, 20) => (
            (3.4809878947368422, 0.518785674729997),
            (2.0058661928593517, 0.34692788889724946),
        ),
        (TokenBase::Base32, 24) => (
            (3.480511086956522, 0.4726670109337228),
            (2.0131379532992537, 0.31476354168931936),
        ),
        (TokenBase::Base32, 25) => (
            (3.480877375, 0.4626150412368404),
            (2.0147828593929953, 0.3075894753390553),
        ),
        (TokenBase::Base32, 32) => (
            (3.4809023548387095, 0.4072672632996217),
            (2.0231609118646867, 0.2700344059876962),
        ),
        (TokenBase::Base32, 40) => (
            (3.4801929743589746, 0.36361457820793436),
            (2.027858606807074, 0.2401498396303172),
        ),
        (TokenBase::Base32, 50) => (
            (3.4798551224489795, 0.323708167297437),
            (2.0318808048208794, 0.2138098551294688),
        ),
        (TokenBase::Base32, 64) => (
            (3.4805990476190476, 0.28572156450556774),
            (2.035756800745673, 0.18815721535870078),
        ),
        (TokenBase::Base36, 8) => (
            (3.7190542428571427, 0.8995506118495411),
            (2.066095086865182, 0.609210293352161),
        ),
        (TokenBase::Base36, 10) => (
            (3.719109611111111, 0.7956463384852813),
            (2.0946299036665494, 0.5322004874842623),
        ),
        (TokenBase::Base36, 15) => (
            (3.719274257142857, 0.6401989313894239),
            (2.129437216268589, 0.42108786288993155),
        ),
        (TokenBase::Base36, 16) => (
            (3.7192072666666665, 0.6188627491757901),
            (2.1336109506109366, 0.4064699817331141),
        ),
        (TokenBase::Base36, 20) => (
            (3.719249815789474, 0.5506473627709657),
            (2.145293932511567, 0.3591543917048417),
        ),
        (TokenBase::Base36, 24) => (
            (3.7191934304347827, 0.50051922802262),
            (2.152858549996053, 0.3252064160191062),
        ),
        (TokenBase::Base36, 25) => (
            (3.7192351583333334, 0.4904181410613897),
            (2.1543202565038735, 0.31823801389315026),
        ),
        (TokenBase::Base36, 32) => (
            (3.7190408419354837, 0.4315967526660196),
            (2.1620321219700767, 0.2788634701820312),
        ),
        (TokenBase::Base36, 40) => (
            (3.7191682666666668, 0.3852248727988986),
            (2.16746680811131, 0.24802261318501675),
        ),
        (TokenBase::Base36, 50) => (
            (3.718913744897959, 0.3436564880405547),
            (2.1715676118603806, 0.22070510537297627),
        ),
        (TokenBase::Base36, 64) => (
            (3.7190009761904763, 0.30325954360127116),
            (2.1751172797904093, 0.1942582237461476),
        ),
        _ => return None,
    })
}

fn parse_filter_usize_arg(filter: &str) -> Option<usize> {
    let start = filter.find('(')? + 1;
    let end = filter[start..].find(')')? + start;
    filter[start..end].parse().ok()
}

fn is_basic_auth_token68(value: &str) -> bool {
    let token = value.trim();
    if token.len() < 8
        || token.len() % 4 == 1
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
    {
        return false;
    }
    let padded = match token.len() % 4 {
        0 => Cow::Borrowed(token),
        2 => Cow::Owned(format!("{token}==")),
        3 => Cow::Owned(format!("{token}=")),
        _ => return false,
    };
    let bytes = padded.as_bytes();
    let decoded = BASE64
        .decode(bytes)
        .or_else(|_| BASE64URL.decode(bytes))
        .or_else(|_| BASE64_NOPAD.decode(token.as_bytes()))
        .or_else(|_| BASE64URL_NOPAD.decode(token.as_bytes()));
    let Ok(decoded) = decoded else {
        return false;
    };
    let Some(colon) = decoded.iter().position(|b| *b == b':') else {
        return false;
    };
    0 < colon && colon + 4 < decoded.len() && std::str::from_utf8(&decoded).is_ok()
}

fn morphemes_filtered(value: &str, threshold: Option<usize>) -> bool {
    let threshold = threshold.unwrap_or_else(|| {
        let bit_length = value
            .chars()
            .count()
            .checked_ilog2()
            .map_or(0, |value| value + 1);
        (bit_length as usize).saturating_sub(4).max(1)
    });
    morphemes_filtered_with_threshold(value, threshold)
}

fn morphemes_filtered_with_threshold(value: &str, threshold: usize) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut matches = 0usize;
    static MORPHEMES: LazyLock<std::collections::BTreeSet<&'static str>> =
        LazyLock::new(|| MORPHEME_CHECKLIST.split_whitespace().collect());
    for morpheme in MORPHEMES.iter() {
        if lower.contains(morpheme) {
            matches += 1;
            if threshold < matches {
                return true;
            }
        }
    }
    false
}

fn dictionary_keyword_filtered(value: &str) -> bool {
    let mut lower = value.to_ascii_lowercase();
    for keyword in keyword_checklist_by_length() {
        while let Some(pos) = lower.find(keyword) {
            lower.replace_range(pos..pos + keyword.len(), &"\x7F".repeat(keyword.len()));
            let marked = lower.as_bytes().iter().filter(|b| **b == 0x7F).count();
            if (marked as f64 / lower.len().max(1) as f64) > 0.33 {
                return true;
            }
        }
    }
    false
}

fn keyword_checklist_by_length() -> &'static Vec<&'static str> {
    static KEYWORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        let mut words = KEYWORD_CHECKLIST.split_whitespace().collect::<Vec<_>>();
        words.sort_by_key(|word| std::cmp::Reverse(word.len()));
        words
    });
    &KEYWORDS
}

fn number_filtered(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.len() < 22 {
        let hex = lower
            .strip_prefix("0x")
            .unwrap_or(&lower)
            .trim_end_matches(['u', 'l']);
        if !hex.is_empty() && hex.len() <= 128 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true;
        }
    }
    let decimal = lower.trim_start_matches('-').trim_end_matches(['u', 'l']);
    !decimal.is_empty() && decimal.len() <= 20 && decimal.bytes().all(|b| b.is_ascii_digit())
}

fn camel_case_filtered(value: &str, is_well_quoted: bool) -> bool {
    if is_well_quoted {
        return false;
    }
    static CAMEL_CASE: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"^(?:[a-z]+(?:[A-Z][a-z]+)+|[A-Z][a-z]+(?:[A-Z][a-z]+)+)$")
            .expect("CredSweeper camel-case regex")
    });
    CAMEL_CASE.is_match(value) && morphemes_filtered_with_threshold(&value.to_ascii_lowercase(), 1)
}

fn value_pattern_filtered(value: &str, pattern_len: Option<usize>) -> bool {
    const DEFAULT_PATTERN_LEN: usize = 4;
    const MIN_DATA_LEN: usize = 8;
    const MAX_PATTERN_BIT_LENGTH: usize = 13;
    let value_len = value.chars().count();
    let bit_length = if value_len == 0 {
        0
    } else {
        value_len.ilog2() as usize + 1
    };
    let bit_length = bit_length.max(DEFAULT_PATTERN_LEN);
    if MAX_PATTERN_BIT_LENGTH < bit_length {
        return false;
    }
    let threshold = pattern_len.unwrap_or(bit_length.max(DEFAULT_PATTERN_LEN));
    if value_len < threshold {
        return true;
    }
    if repeated_or_sequence_pattern(value, threshold, MIN_DATA_LEN <= threshold) {
        return true;
    }
    if 2 * threshold <= value_len
        && duple_pattern_filtered(value, threshold, MIN_DATA_LEN <= threshold)
    {
        return true;
    }
    false
}

fn repeated_or_sequence_pattern(
    value: &str,
    threshold: usize,
    ignore_base64_a_slash: bool,
) -> bool {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() < threshold {
        return false;
    }
    let mut equal = 1usize;
    let mut ascending = 1usize;
    let mut descending = 1usize;
    for pair in chars.windows(2) {
        if pair[0] == pair[1]
            && !pair[0].is_whitespace()
            && !(ignore_base64_a_slash && matches!(pair[0], 'A' | '/' | '_'))
        {
            equal += 1;
        } else {
            equal = 1;
        }
        if (pair[1] as u32).wrapping_sub(pair[0] as u32) == 1 {
            ascending += 1;
        } else {
            ascending = 1;
        }
        if (pair[0] as u32).wrapping_sub(pair[1] as u32) == 1 {
            descending += 1;
        } else {
            descending = 1;
        }
        if equal >= threshold || ascending >= threshold || descending >= threshold {
            return true;
        }
    }
    false
}

fn duple_pattern_filtered(value: &str, threshold: usize, ignore_base64_a_slash: bool) -> bool {
    let even = value
        .chars()
        .enumerate()
        .filter_map(|(idx, ch)| (idx % 2 == 0).then_some(ch))
        .collect::<String>();
    if !repeated_or_sequence_pattern(&even, threshold, ignore_base64_a_slash) {
        return false;
    }
    let odd = value
        .chars()
        .enumerate()
        .filter_map(|(idx, ch)| (idx % 2 == 1).then_some(ch))
        .collect::<String>();
    repeated_or_sequence_pattern(&odd, threshold, ignore_base64_a_slash)
}

fn entropy_base36_filtered(value: &str) -> bool {
    let len = value.chars().count();
    let min = match len {
        15 => 3.374,
        10..=25 => 0.731_566_857 * (len as f64).log2() + 0.474_132,
        26.. => 3.9,
        _ => 0.0,
    };
    min == 0.0 || shannon_entropy(value) < min
}

fn entropy_base32_filtered(value: &str) -> bool {
    let len = value.chars().count();
    let min = match len {
        8..=16 => 0.805_692_36 * (len as f64).log2() + 0.134_397_34,
        17..=32 => 0.663_504_81 * (len as f64).log2() + 0.711_438_62,
        33.. => 4.04,
        _ => 0.0,
    };
    min == 0.0 || min > shannon_entropy(value)
}

fn minimum_base64_entropy(len: usize) -> f64 {
    match len {
        12..=17 => 0.915 * (len as f64).log2() - 0.047,
        18..=34 => 0.767 * (len as f64).log2() + 0.5677,
        35..=64 => 0.944 * (len as f64).log2() - 0.009 * len as f64 - 0.04,
        65..=255 => 0.621 * (len as f64).log2() - 0.003 * len as f64 + 1.54,
        256.. => 6.0 - 64.0 / len as f64,
        _ => 0.0,
    }
}

fn entropy_base64_filtered(value: &str) -> bool {
    let min = minimum_base64_entropy(value.chars().count());
    min == 0.0 || shannon_entropy(value) < min
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::BTreeMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }
    let len = value.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn value_sealed_secret_filtered(value: &str, context: &CandidateLineContext<'_>) -> bool {
    let sealed_shape = (value.starts_with("Ag") && value.len() > 700)
        || (value.starts_with("AQ") && value.len() > 350);
    if !sealed_shape
        || !value
            .as_bytes()
            .get(2)
            .is_some_and(|byte| (b'A'..=b'D').contains(byte))
    {
        return false;
    }
    let from = context.line_index.saturating_sub(100);
    let to = context.line_index.saturating_add(100);
    let mut sealed_secret = false;
    let mut encrypted_data = false;
    let mut bitnami = false;
    for line in context
        .target
        .lines()
        .enumerate()
        .skip(from)
        .take(to.saturating_sub(from))
        .map(|(_, line)| &line[..clamp_to_char_boundary(line, line.len().min(8000))])
    {
        sealed_secret |= line.contains("SealedSecret");
        encrypted_data |= line.contains("encryptedData");
        bitnami |= line.contains("bitnami");
        if sealed_secret && encrypted_data && bitnami {
            return true;
        }
    }
    false
}

fn has_upper_lower_digit_or_aws_symbol(value: &str) -> bool {
    value.chars().any(|ch| ch.is_ascii_uppercase())
        && value.chars().any(|ch| ch.is_ascii_lowercase())
        && value
            .chars()
            .any(|ch| ch.is_ascii_digit() || matches!(ch, '/' | '+'))
}

fn has_upper_lower_digit_or_google_symbol(value: &str) -> bool {
    value.chars().any(|ch| ch.is_ascii_uppercase())
        && value.chars().any(|ch| ch.is_ascii_lowercase())
        && value
            .chars()
            .any(|ch| ch.is_ascii_digit() || matches!(ch, '_' | '-'))
}

fn line_specific_key_filtered(line: &str, value_start: usize, value_end: usize) -> bool {
    static NOT_ALLOWED: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"(?i)example|\benc[\(\[]|\btrue\b|\bfalse\b")
            .expect("line specific key regex")
    });
    const ML_HUNK: usize = 64;
    let start = floor_char_boundary(line, value_start.saturating_sub(ML_HUNK));
    let end = ceil_char_boundary(line, (value_end + ML_HUNK).min(line.len()));
    NOT_ALLOWED.is_match(&line[start..end])
}

fn floor_char_boundary(text: &str, mut idx: usize) -> usize {
    idx = idx.min(text.len());
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(text: &str, mut idx: usize) -> usize {
    idx = idx.min(text.len());
    while idx < text.len() && !text.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn base64_part_filtered(line: &str, value: &str, value_start: usize, value_end: usize) -> bool {
    if value_start == 0 && line.len() < 2 * value.len() {
        return false;
    }
    let touches_base64_delimiter = value_start == 0
        || line
            .as_bytes()
            .get(value_start.saturating_sub(1))
            .is_some_and(|b| matches!(b, b'/' | b'+' | b'\\' | b'%'))
        || (0 < value_end
            && value_end < line.len()
            && line
                .as_bytes()
                .get(value_end)
                .is_some_and(|b| matches!(b, b'/' | b'+' | b'\\' | b'%')));
    if !touches_base64_delimiter || value.contains(['-', '_']) {
        return false;
    }

    let left_start = value_start.saturating_sub(value.len());
    let right_end = (value_end + value.len()).min(line.len());
    let hunk = &line[floor_char_boundary(line, left_start)..ceil_char_boundary(line, right_end)];
    hunk.len() >= 2 * value.len()
        && hunk
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\\'))
}

fn dedupe_findings(mut findings: Vec<CredSweeperNativeFinding>) -> Vec<CredSweeperNativeFinding> {
    findings.sort_by(|a, b| {
        (
            a.range.start,
            a.range.end,
            a.rule_name.as_str(),
            a.value_start,
            a.value_end,
            a.variable_start,
            a.variable_end,
        )
            .cmp(&(
                b.range.start,
                b.range.end,
                b.rule_name.as_str(),
                b.value_start,
                b.value_end,
                b.variable_start,
                b.variable_end,
            ))
            .then_with(|| compare_native_line_data(&a.line_data, &b.line_data))
    });
    findings.dedup_by(|a, b| {
        a.range == b.range
            && a.rule_name == b.rule_name
            && a.value_start == b.value_start
            && a.value_end == b.value_end
            && a.variable_start == b.variable_start
            && a.variable_end == b.variable_end
            && same_native_line_data(&a.line_data, &b.line_data)
    });
    findings
}

fn compare_native_line_data(
    a: &[CredSweeperNativeRelatedFinding],
    b: &[CredSweeperNativeRelatedFinding],
) -> Ordering {
    for (left, right) in a.iter().zip(b) {
        let cmp = (
            left.range.start,
            left.range.end,
            left.value_start,
            left.value_end,
            left.variable_start,
            left.variable_end,
        )
            .cmp(&(
                right.range.start,
                right.range.end,
                right.value_start,
                right.value_end,
                right.variable_start,
                right.variable_end,
            ));
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    a.len().cmp(&b.len())
}

fn same_native_line_data(
    a: &[CredSweeperNativeRelatedFinding],
    b: &[CredSweeperNativeRelatedFinding],
) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(left, right)| {
            left.range == right.range
                && left.value_start == right.value_start
                && left.value_end == right.value_end
                && left.variable_start == right.variable_start
                && left.variable_end == right.variable_end
        })
}

fn dedupe_spans(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| b.cmp_strength(a));
    let mut kept: Vec<Span> = Vec::new();
    'span: for span in spans {
        for existing in &kept {
            if !ranges_overlap(span.range, existing.range) {
                continue;
            }
            if is_generic_label(&span.label) && !is_generic_label(&existing.label) {
                continue 'span;
            }
            if span.range == existing.range {
                continue 'span;
            }
        }
        kept.push(span);
    }
    kept.sort_by_key(|span| (span.range.start, span.range.end, span.label.clone()));
    kept
}

fn ranges_overlap(a: ByteRange, b: ByteRange) -> bool {
    a.start < b.end && b.start < a.end
}

fn is_generic_label(label: &str) -> bool {
    matches!(
        label,
        "DOC_GET"
            | "DOC_CREDENTIALS"
            | "SECRET_PAIR"
            | "PASSWD_PAIR"
            | "IP_ID_PASSWORD_TRIPLE"
            | "ID_PAIR_PASSWD_PAIR"
            | "ID_PASSWD_PAIR"
            | "API"
            | "AUTH"
            | "CREDENTIAL"
            | "KEY"
            | "NONCE"
            | "PASSWORD"
            | "SALT"
            | "SECRET"
            | "TOKEN"
    )
}

fn value_file_path_filtered(value: &str, separator: Option<&str>) -> bool {
    let bit_length = value
        .chars()
        .count()
        .checked_ilog2()
        .map_or(0, |value| value + 1);
    let threshold = if bit_length < 6 {
        1
    } else {
        bit_length as usize - 4
    };
    let mut unix = value.contains('/');
    if unix
        && (value.contains("://")
            || value.starts_with("~/")
            || value.starts_with("./")
            || value.contains("../")
            || value.contains("/..")
            || (value.starts_with("//") && separator == Some(":")))
    {
        return morphemes_filtered_with_threshold(&value.to_lowercase(), threshold);
    }
    if unix
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        let minimum = minimum_base64_entropy(value.chars().count());
        let entropy = shannon_entropy(value);
        unix = if minimum == 0.0 || minimum > entropy {
            value.matches('/').count() > 1
        } else {
            false
        };
    }
    let windows = value.contains(":\\");
    if !(unix || windows) {
        return false;
    }
    const UNIX_UNUSUAL: &str = "\t\n\r!@`&*<>+=;,~^:\\";
    const WINDOWS_UNUSUAL: &str = "\t\n\r!$@`&*(){}<>+=;,~^";
    let unusual = if unix { UNIX_UNUSUAL } else { WINDOWS_UNUSUAL };
    !value.chars().any(|ch| unusual.contains(ch))
        && unix != windows
        && morphemes_filtered_with_threshold(&value.to_lowercase(), threshold)
}

fn map_confidence(confidence: Option<&str>) -> Confidence {
    match confidence {
        Some("strong") => Confidence::High,
        Some("moderate") => Confidence::Medium,
        Some("weak") => Confidence::Low,
        _ => Confidence::Medium,
    }
}

fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "strong",
        Confidence::Medium => "moderate",
        Confidence::Low => "weak",
    }
}

fn map_severity(severity: Option<&str>) -> RuleSeverity {
    match severity {
        Some("critical") => RuleSeverity::Critical,
        Some("high") => RuleSeverity::High,
        Some("low") => RuleSeverity::Low,
        Some("info") => RuleSeverity::Info,
        _ => RuleSeverity::Medium,
    }
}

fn severity_name(severity: RuleSeverity) -> &'static str {
    match severity {
        RuleSeverity::Critical => "critical",
        RuleSeverity::High => "high",
        RuleSeverity::Medium => "medium",
        RuleSeverity::Low => "low",
        RuleSeverity::Info => "info",
    }
}

fn normalize_label(rule: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in rule.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    let label = out.trim_matches('_');
    if label.is_empty() {
        "CREDSWEEPER".to_string()
    } else {
        label.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;
    use p12_keystore::{Certificate, KeyStoreEntry, PrivateKey, PrivateKeyChain};

    fn rsa_pkcs8_fixture() -> Vec<u8> {
        BASE64
            .decode(b"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALT7bjP4S78u42idmuYyxhZrAini+XRpVhl+PMWKFyhZm+Xm2w+Yb9K6T1Ve9s3NwoxLqZDkXH8t0VGMfMxQfyIYfcTDqjXlg2p2BhdnZ59NeB+OrGw8hI4IaqPs371xVxXzE/v7LMRrIKmVra/i+lu+KVtIrsUfFoqx+gMUEsOBAgMBAAECgYANK3K0g2/3pJDVzwozkCRMA1Nv+t1ONFAYoNAJS+gtfn/Stf7g3qXcfsRBIRzykvOCRAs9yPBWLN5bgc6fC4iEskccmvVGntEyKkkNzF39CNjLBX8nlJkFTY7LxDDSjCj9LCZp343yTvV8tsChXE1+eMoeBE/K/1EmTP/GkacDVQJBAOK1Dt3kEF2ygi7bzILSUWPqk0XNt9kAnNsKMFhp/9CzwM87Zt6fEbG4tyffv7qcUj4jsSXn0h8pXKrnDTBUppMCQQDMXeTBp1td2R8POAe3cyRtL4H2aHGESBgeLhUM1STopdZyneixavl6xb5YsJGvOCav0cQziRffOjsr1zzio0YbAkBmg58UYWOxKt5JWCTzZy1ctB8ianLfErLbLZFM+amu8wmV6/OJaX6z0aYoxrnJJZTe+n7JeDmA09BOi6pgF3c3AkEAy58Z1+F55W35xl4bQitVNfzJzsuNnzF95kQf8SNFnQ/vNVAkkvF1FWCFITT8UsrtsOyeQoLr6BzK7AmOvnnT1QJAW8Pdg05dND79yAjMnowqcvsJEoi6nD1wN9Iq5CrHcGrRLV26vH5a+O1J6Zlz7UdEe6XpJ6mxax1UjICw4AXAOA==")
            .expect("PKCS#8 RSA fixture")
    }

    fn rsa_fixture_der() -> Vec<u8> {
        let pkcs8 = rsa_pkcs8_fixture();
        PrivateKeyInfoRef::try_from(pkcs8.as_slice())
            .expect("PKCS#8 fixture")
            .private_key
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn private_key_loader_accepts_pkcs1_and_pkcs8_rsa() {
        let pkcs1 = rsa_fixture_der();
        let pkcs8 = rsa_pkcs8_fixture();
        assert!(load_der_private_key(&pkcs1).is_some());
        assert!(load_der_private_key(&pkcs8).is_some());
    }

    #[test]
    fn private_key_loader_rejects_malformed_rsa_der() {
        let mut pkcs1 = rsa_fixture_der();
        pkcs1.truncate(pkcs1.len() / 2);
        assert!(load_der_private_key(&pkcs1).is_none());

        let mut invalid_crt = rsa_fixture_der();
        *invalid_crt.last_mut().expect("RSA coefficient") ^= 1;
        assert!(load_der_private_key(&invalid_crt).is_none());
    }

    #[test]
    fn private_key_loader_accepts_empty_password_pkcs12() {
        let pkcs8 = rsa_pkcs8_fixture();
        let chain = PrivateKeyChain::new(
            [1_u8, 2, 3, 4].as_slice(),
            PrivateKey::from_der(&pkcs8).expect("private key"),
            [],
        );
        let mut store = KeyStore::new();
        store.add_entry("test", KeyStoreEntry::PrivateKeyChain(chain));
        let p12 = store.writer("").write().expect("PKCS#12 fixture");
        let key = load_der_private_key(&p12).expect("load PKCS#12");
        assert!(private_key_is_valid(&key));
    }

    #[test]
    fn private_key_loader_keeps_pkcs12_keys_that_share_a_certificate_alias() {
        let ed25519 = data_encoding::HEXLOWER
            .decode(b"302e020100300506032b65700422042017ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85")
            .expect("Ed25519 PKCS#8 fixture");
        let certificate = BASE64
            .decode(b"MIIBWDCCAQqgAwIBAgIUJHqHxlYUeJLW/OvjdnQXBwy/eWswBQYDK2VwMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTI2MDYxOTA2MjA1OFoXDTI4MDUxOTA2MjA1OFowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wKjAFBgMrZXADIQBZeSuQJmHBhe6U7x4GDBUMK4INE8VxqP311K/ejllcnaNqMGgwCQYDVR0TBAIwADAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCwYDVR0PBAQDAgOIMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBSw1lXZ6Gnm3DuRtrFmcWOZEYxdqjAFBgMrZXADQQCicT1reAXWy/i58EABJ2n2zNYdeKP1jyvjlUwzm81sZbNfeaqYNjJoYAK1EBiCW0PGfFIuS++1od7w56YgV+EO")
            .expect("X.509 fixture");
        let certificate = Certificate::from_der(&certificate).expect("certificate");
        let alias = certificate.subject().to_owned();
        let chain = PrivateKeyChain::new(
            [1_u8, 2, 3, 4].as_slice(),
            PrivateKey::from_der(&ed25519).expect("private key"),
            [certificate],
        );
        let mut store = KeyStore::new();
        store.add_entry(&alias, KeyStoreEntry::PrivateKeyChain(chain));
        let p12 = store.writer("").write().expect("PKCS#12 fixture");
        let raw =
            KeyStore::from_pkcs12(&p12, "", Pkcs12ImportPolicy::Raw).expect("raw PKCS#12 import");
        assert!(
            raw.private_key_chain().is_none(),
            "fixture must reproduce the same-alias overwrite"
        );

        let key = load_der_private_key(&p12).expect("load PKCS#12 key with certificate");
        assert!(private_key_is_valid(&key));
    }

    #[test]
    fn private_key_loader_validates_rfc8410_key_body() {
        // RFC 8410 section 10.3 Ed25519 PKCS#8 fixture.
        let mut ed25519 = data_encoding::HEXLOWER
            .decode(b"302e020100300506032b65700422042017ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85")
            .expect("Ed25519 fixture");
        assert!(load_der_private_key(&ed25519).is_some());

        let nested_octet = ed25519
            .windows(2)
            .rposition(|bytes| bytes == [0x04, 0x20])
            .expect("nested private-key OCTET STRING");
        ed25519[nested_octet] = 0x05;
        assert!(load_der_private_key(&ed25519).is_none());
    }

    #[test]
    fn dsa_and_dh_parameter_parsers_reject_wrong_tags_and_extra_fields() {
        let dsa = AnyRef::try_from(&[0x30, 9, 2, 1, 2, 2, 1, 3, 2, 1, 5][..]).unwrap();
        assert!(dsa_parameters_valid(dsa));
        let dsa_wrong_tag = AnyRef::try_from(&[0x30, 9, 2, 1, 2, 4, 1, 3, 2, 1, 5][..]).unwrap();
        assert!(!dsa_parameters_valid(dsa_wrong_tag));

        let dh = AnyRef::try_from(&[0x30, 6, 2, 1, 2, 2, 1, 3][..]).unwrap();
        assert!(dh_parameters_valid(dh));
        let dh_extra =
            AnyRef::try_from(&[0x30, 12, 2, 1, 2, 2, 1, 3, 2, 1, 5, 2, 1, 7][..]).unwrap();
        assert!(!dh_parameters_valid(dh_extra));

        let dhx_with_validation = AnyRef::try_from(
            &[
                0x30, 17, 2, 1, 2, 2, 1, 3, 2, 1, 5, 0x30, 6, 3, 1, 0, 2, 1, 7,
            ][..],
        )
        .unwrap();
        assert!(dhx_parameters_valid(dhx_with_validation));
    }

    #[test]
    fn embedded_assets_are_present() {
        let stats = CredSweeperNativeDetector::builtin_stats();
        assert!(stats.total_rules > 100, "{stats:?}");
        assert!(stats.total_patterns > 100, "{stats:?}");
        assert!(stats.ml_rules > 0, "{stats:?}");
        assert!(stats.rules_yaml_bytes > 40_000);
        assert!(stats.secret_config_json_bytes > 1_000);
        assert!(stats.ml_config_json_bytes > 10_000);
        assert!(stats.ml_model_onnx_bytes > 10_000_000);
    }

    #[test]
    fn detector_initialization_does_not_compile_regexes() {
        let detector = CredSweeperNativeDetector::compile_builtin().unwrap();
        let deferred = detector
            .rules
            .iter()
            .flat_map(|rule| &rule.patterns)
            .filter_map(|pattern| match &pattern.matcher {
                PatternMatcher::Deferred(regex) => Some(regex),
                PatternMatcher::Special(_) => None,
            })
            .collect::<Vec<_>>();

        assert!(!deferred.is_empty());
        assert!(deferred.iter().all(|regex| regex.compiled.get().is_none()));
    }

    #[test]
    fn warm_up_reports_value_free_phase_timings() {
        let timings = CredSweeperNativeDetector::builtin().warm_up_timed();
        eprintln!(
            "CredSweeper warm-up: regexes={:?} ml={:?} verification={:?} total={:?}",
            timings.regexes, timings.ml, timings.verification, timings.total
        );
        assert!(timings.total >= timings.regexes);
        assert!(timings.total >= timings.ml);
        assert!(timings.total >= timings.verification);
    }

    #[test]
    fn migration_coverage_is_explicit() {
        let stats = CredSweeperNativeDetector::builtin_stats();
        assert_eq!(
            stats.compiled_patterns,
            stats.rust_regex_patterns + stats.fancy_regex_patterns,
            "{stats:?}"
        );
        assert_eq!(
            stats.enabled_patterns,
            stats.compiled_patterns + stats.translated_patterns,
            "{stats:?}"
        );
        assert!(
            stats.ml_gated_patterns <= stats.enabled_patterns,
            "{stats:?}"
        );
        assert_eq!(stats.unsupported_patterns, 0, "{stats:?}");
        assert_eq!(
            stats.total_patterns,
            stats.compiled_patterns + stats.translated_patterns + stats.unsupported_patterns
        );
    }

    #[test]
    fn unsupported_filter_coverage_is_explicit() {
        let stats = CredSweeperNativeDetector::builtin_stats();
        assert!(stats.total_filter_invocations > 0, "{stats:?}");
        assert_eq!(stats.unsupported_filter_invocations, 0, "{stats:?}");
        assert!(stats.unsupported_filter_types.is_empty(), "{stats:?}");
    }

    #[test]
    fn value_azure_token_matches_official_fixtures() {
        assert!(value_azure_token_filtered("eyJungle"));
        assert!(value_azure_token_filtered(
            "eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo"
        ));
        assert!(value_azure_token_filtered(concat!(
            "eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo.",
            "eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo.",
            "eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo"
        )));
        assert!(!value_azure_token_filtered(concat!(
            "eyJhbGciOjEsInR5cCI6Miwia2lkIjozfQo.",
            "eyJpc3MiOjEsImV4cCI6MiwiaWF0IjozfQo.",
            "1234567890qwertyuiopasdfghjklzxc"
        )));
    }

    #[test]
    fn value_discord_bot_matches_upstream_fixture_and_entropy_filter() {
        assert!(!value_discord_bot_filtered(concat!(
            "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.E2-E4_.",
            "Zig9V5mpMk-JybgCFvqSfgY9EoqWjkA5O_qDje"
        )));
        assert!(value_discord_bot_filtered(
            "OTk5.abcdefghijklmnopqrstuvwxyz012345"
        ));
        assert!(value_discord_bot_filtered(concat!(
            "MTA1NDMyMTA5ODc2NTQzMjEwMA.GAxYzA.",
            "dGVzdHNpZ25hdHVyZXRlc3RzaWduYXR1cmUxMjM"
        )));
        assert!(value_discord_bot_filtered("MTIzNDU2Nzg5MA.aaaaaaaaaaaa"));
        assert!(value_discord_bot_filtered("not-a-token"));
    }

    #[test]
    fn vendor_token_rules_match_pinned_credsweeper_fixtures() {
        // Assemble the public upstream fixtures at runtime so GitHub push
        // protection does not mistake detector test data for live secrets.
        let fixtures = vec![
            (
                "DOCKER_ACCESS_TOKEN",
                ["dckr_", "pat_", "mcF-hLK_JoBxXUNJy1kU7-WSbk0"].concat(),
            ),
            (
                "DOCKER_ACCESS_TOKEN",
                ["dckr_", "oat_", "fXUgJy1nU2WSbk_0vH2S-mcF-hLKJoB-"].concat(),
            ),
            (
                "HASHICORP_VAULT_TOKEN",
                ["hvs.", "atlasv1-Z28P3STmkBQi1Y-YE7RBqu6VVyQIOq9a1eC3YFU5Elt7ToIr6OwzKAWlCTQ7N4gElXaWou6aPpOIwGCoc0"].concat(),
            ),
            (
                "HASHICORP_VAULT_TOKEN",
                ["hvb.", "atlasv1-Z28P3STmkBQi1Y-YE7RBqu6VVyQIOq9a1eC3YFU5Elt7ToIr6OwzKAWlCTQ7N4gElXaWou6aPpOIwGCoc0"].concat(),
            ),
            (
                "HASHICORP_VAULT_TOKEN",
                ["hvr.", "atlasv1-Z28P3STmkBQi1Y-YE7RBqu6VVyQIOq9a1eC3YFU5Elt7ToIr6OwzKAWlCTQ7N4gElXaWou6aPpOIwGCoc0"].concat(),
            ),
            (
                "SENTRY_ORGANIZATION_AUTH_TOKEN",
                ["sntrys_", "eyJpYXQiOjE3NDEyNjQzNTYuMDAwMCwidXJsIjoiaHR0cHM6Ly9zZW50cnkuaW8iLCJyZWdpb25fdXJsIjoiaHR0cHM6Ly91YS5zZW50cnkuaW8iLCJvcmciOiIifQ==v8D-whr2cUQK91Civi4yNoLRjC3MDZH5I2aMcs_j5GDv"].concat(),
            ),
            (
                "SENTRY_USER_AUTH_TOKEN",
                ["sntryu_", "b42e3f39e6e16d5c822ac2e6ae368a1bc24fd9678bc6a6411926acdafea59851"].concat(),
            ),
            (
                "SUPABASE_CREDENTIALS",
                ["sbp_", "7558c5a93d6f38dd038df5cc2a7c3d4d7b6bc76d"].concat(),
            ),
            (
                "SUPABASE_CREDENTIALS",
                ["sbp_", "v0_", "7558c5a93d6f38dd038df5cc2a7c3d4d7b6bc76d"].concat(),
            ),
        ];
        let detector = CredSweeperNativeDetector::builtin();

        for (expected_label, fixture) in fixtures {
            let input = format!("token={fixture}");
            let input_region = region(&input);
            let view = NormalizedView::build(&input_region, &input);
            let findings = detector.detect_findings(&view);
            assert!(
                findings
                    .iter()
                    .any(|finding| { finding.label == expected_label && finding.value == fixture }),
                "{expected_label} did not match its pinned upstream fixture: {findings:?}"
            );
        }
    }

    #[test]
    fn value_grafana_matches_official_fixtures() {
        assert!(!value_grafana_filtered(
            "glc_eyJvIjoiTyIsIm4iOiJOIiwiayI6IksiLCJtIjp7InIiOiIwIn19"
        ));
        assert!(!value_grafana_filtered("eyJrIjoiSyIsIm4iOiJOIiwiaWQiOjF9"));
        assert!(value_grafana_filtered("eyJLIjoiSyIsIm4iOiJOIiwiaWQiOjF9"));
        assert!(value_grafana_filtered("e30="));
    }

    #[test]
    fn value_grafana_service_matches_official_fixtures() {
        assert!(!value_grafana_service_filtered(
            "glsa_DuMmY-T0K3N-f0R-tHe-Te5t-CRC32Ok_770c8cda"
        ));
        assert!(value_grafana_service_filtered(
            "glpl_DuMmY-T0K3N-f0R-tHe-Te5t-CRC32Ok_770c8CdA"
        ));
        assert!(value_grafana_service_filtered("too-short"));
    }

    #[test]
    fn value_atlassian_token_matches_official_fixtures() {
        let structured = "MTIzNDU6q1bPZWwJU3DB36G7cb7k114w99VK/HKwZcYN";
        assert!(!value_atlassian_token_filtered(structured));
        assert!(!value_atlassian_token_filtered(&format!(
            "BBDC-{structured}"
        )));
        let app_password = ["ATBBMTIzNDU6q1bP", "ZWwJU3DB36G7", "378C86CF"].concat();
        assert!(!value_atlassian_token_filtered(&app_password));
        assert!(value_atlassian_token_filtered("MTJ4NDU6YXNiZHNhOjI4eWQ="));
        assert!(value_atlassian_token_filtered(
            "ATBBMTIzNDU6q1bPZWwJU3DB36G7012345678"
        ));
    }

    #[test]
    fn value_github_matches_official_fixtures() {
        assert!(!value_github_filtered(
            "gh?_00000000000000000000000000000004WZ4EQ"
        ));
        assert!(!value_github_filtered(
            "npm_00000000000000000000000000000004WZ4EQ"
        ));
        assert!(value_github_filtered(
            "hhh_00000000000000000000000000000004WZ4EQ"
        ));
        assert!(value_github_filtered(
            "npm_00000000000000000000000000000004WZAEQ"
        ));
    }

    #[test]
    fn value_jfrog_token_matches_official_samples() {
        let identity = [
            "cmVmdGtuOjAxOjAxMjM0NTY3ODk6",
            "QWJjZGVmR2hpamtsbW5vUHFyc3R1dnd4eXow",
        ]
        .concat();
        assert!(!value_jfrog_token_filtered(&identity));
        let api_key = [
            "AKCp2UNCd8uK7hQoxZnFE4PGtRHnAcBHr43",
            "HgLcj7nJmWb4JhVUqBwa2iwXszftnogpo2EVFa",
        ]
        .concat();
        assert!(!value_jfrog_token_filtered(&api_key));
        assert!(value_jfrog_token_filtered(
            "cmVmdGtuOlRoZXJlIGFyZSBub3QgdGhlIHRva2VucyB5b3UncmUgbG9va2luZyA0"
        ));
        assert!(value_jfrog_token_filtered(
            "AKCp2UNCd8uK7hQoxZnFE4PGtRHnAcBHr43HgLcj7nJmWb4JhVUqBwa2iwXszftnogpo2EVF0"
        ));
    }

    #[test]
    fn value_base64_part_matches_official_fixtures() {
        let prefix = "sha512-eGuFFw7Upda+g4p+QHvnW0RyTX/SVeJBDM/";
        let value = "gCtMARO0cLuT2HcEKnTPvhjV6aGeqrCB";
        let suffix = "/sbNop0Kszm0jsaWU4A==";
        let line = format!("{prefix}{value}{suffix}");
        assert!(value_base64_part_filtered(
            value,
            &line,
            prefix.len(),
            prefix.len() + value.len()
        ));

        let prefix = " http://localhost:8888/v1/api/get?token=";
        let value = "zUkITxodk63bDVUMwIymb3zKTxICz85zC00cv0Geline80";
        let line = format!("{prefix}{value}");
        assert!(!value_base64_part_filtered(
            value,
            &line,
            prefix.len(),
            line.len()
        ));
    }

    #[test]
    fn value_not_part_encoded_checks_adjacent_lines() {
        let encoded_before = format!("{}\n", "A1b2".repeat(16));
        let encoded_after = format!("{}\n", "C3d4".repeat(4));
        assert!(value_not_part_encoded_filtered(Some(&encoded_before), None));
        assert!(value_not_part_encoded_filtered(None, Some(&encoded_after)));
        assert!(!value_not_part_encoded_filtered(
            Some("ordinary text\n"),
            Some("more text\n")
        ));
    }

    #[test]
    fn value_base64_encoded_pem_requires_official_pem_payload_structure() {
        let mut der = vec![0x30, 0x81, 0x80];
        der.extend(std::iter::repeat_n(0x42, 128));
        let body = BASE64.encode(&der);
        let pem = format!(
            "prefix\n-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\nsuffix"
        );
        let encoded = BASE64.encode(pem.as_bytes());
        assert!(!value_base64_encoded_pem_filtered(&encoded));

        let malformed =
            BASE64.encode(b"-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----");
        assert!(value_base64_encoded_pem_filtered(&malformed));
    }

    #[test]
    fn pem_sanitize_treats_escaped_line_separators_like_credsweeper() {
        assert_eq!(
            sanitize_pem_line(r#"                "QUJDREVGRw==\n" +"#, 5),
            "QUJDREVGRw=="
        );
        assert_eq!(
            sanitize_pem_line(r#"                "\tQUJDREVGRw==\r\n" +"#, 5),
            "QUJDREVGRw=="
        );
    }

    #[test]
    fn pem_line_data_stops_at_the_candidate_end() {
        let text = "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----`)";
        let begin = text.find("-----BEGIN").unwrap();
        let header_end = text.find("-----\n").unwrap() + 5;
        let end =
            text.find("-----END PRIVATE KEY-----").unwrap() + "-----END PRIVATE KEY-----".len();
        let lines = pem_private_key_line_data(text, begin, header_end, end);
        assert_eq!(lines.last().unwrap().value, "-----END PRIVATE KEY-----");
    }

    #[test]
    fn pem_line_data_keeps_payload_before_an_inline_end_marker() {
        let raw = concat!(
            "String key = \"-----BEGIN RSA PRIVATE KEY-----\\n\"\n",
            "+ \"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\\n\" + \"-----END RSA PRIVATE KEY-----\";\n",
        );
        let begin = raw.find("-----BEGIN").expect("begin");
        let header_end = begin + "-----BEGIN RSA PRIVATE KEY-----".len();
        let end = raw.find("-----END").expect("end") + "-----END RSA PRIVATE KEY-----".len();
        let lines = pem_private_key_line_data(raw, begin, header_end, end);
        assert!(lines
            .iter()
            .any(|line| line.value == "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="));
    }

    #[test]
    fn pem_line_data_keeps_a_single_physical_line_as_one_value() {
        let text = r#"const key = "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----";"#;
        let begin = text.find("-----BEGIN").unwrap();
        let header_end = begin + "-----BEGIN PRIVATE KEY-----".len();
        let end =
            text.find("-----END PRIVATE KEY-----").unwrap() + "-----END PRIVATE KEY-----".len();
        let lines = pem_private_key_line_data(text, begin, header_end, end);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].value, &text[begin..end]);
    }

    #[test]
    fn pgp_private_key_armor_is_one_private_key_finding() {
        let mut state = 0x9e37_79b9_u32;
        let payload = (0..384)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect::<Vec<_>>();
        let encoded = BASE64.encode(&payload);

        for armor_name in ["PGP PRIVATE KEY BLOCK", "PGP SECRET KEY BLOCK"] {
            let body = encoded
                .as_bytes()
                .chunks(64)
                .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
                .collect::<Vec<_>>()
                .join("\n");
            let raw = format!(
                "-----BEGIN {armor_name}-----\nVersion: GnuPG v2\nComment: generated fixture\nMessageID: test@example.invalid\nHash: SHA256\nCharset: UTF-8\n\n{body}\n=Ab3d\n-----END {armor_name}-----"
            );
            let input_region = region(&raw);
            let view = NormalizedView::build(&input_region, &raw);
            let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
            assert!(
                findings
                    .iter()
                    .any(|finding| { finding.label == "PEM_PRIVATE_KEY" && finding.value == raw }),
                "{armor_name}: {findings:?}"
            );

            let masked = crate::Engine::with_profile(crate::Profile::Strict)
                .mask(crate::Input::text(&raw), &crate::Config::insecure_testing());
            assert_eq!(masked.summary.masked_count, 1, "{armor_name}");
            assert!(
                masked.masked.starts_with("<<PEM_PRIVATE_KEY_")
                    && !masked.masked.contains("-----BEGIN"),
                "{armor_name}: {}",
                masked.masked
            );
        }
    }

    #[test]
    fn long_json_web_token_pattern_does_not_hit_the_regex_runtime_limit() {
        let source = r"(?P<value>eyJ[=0-9A-Za-z_+/-]{15,8000}(\.[=0-9A-Za-z_+/-]{0,8000}){2,16})(?![=0-9A-Za-z_-])";
        let token = format!(
            "eyJ{}.eyJ{}.{}",
            "A".repeat(67),
            "B".repeat(663),
            "C".repeat(322)
        );
        let PatternMatcher::Deferred(regex) = compile_pattern(source).unwrap() else {
            panic!("JWT must use the deferred regex matcher");
        };
        let input = format!("{token}\"");
        let matches = regex.find(&input, true);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, token);
    }

    #[test]
    fn credsweeper_base64_accepts_python_compatible_trailing_bits_and_altchars() {
        assert_eq!(decode_base64_like_upstream("YR=="), Some(b"a".to_vec()));
        assert_eq!(
            decode_base64_like_upstream("-___"),
            decode_base64_like_upstream("+///")
        );
    }

    #[test]
    fn base64_private_key_uses_the_official_pattern_boundaries() {
        let input = r#"const key = "MIIAabcdefghABCDEFGH\nIJKLMNOP==";"#;
        let matches = base64_private_key_candidates(input);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].value.starts_with("MIIA"));
        assert!(!matches[0].value.ends_with('='));
        assert!(matches[0].value.contains("\\n"));
    }

    #[test]
    fn structured_keyword_parser_handles_typed_quoted_declarations() {
        let keyword = FancyRegex::new("(?is:token(?!ize))").unwrap();
        let value = "A".repeat(96);
        let line = format!(r#"private val api_token: String = " {value}""#);
        let candidates = keyword_structured_candidates(&line, &keyword, &[]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].variable, Some("api_token"));
        assert_eq!(candidates[0].separator, Some("="));
        assert_eq!(candidates[0].value, format!(" {value}"));

        assert!(
            keyword_structured_candidates("private val api_token: String", &keyword, &[])
                .is_empty()
        );

        let plain = format!(r#"const api_token = "{value}";"#);
        let plain_candidates = keyword_structured_candidates(&plain, &keyword, &[]);
        assert_eq!(plain_candidates.len(), 1);
        assert_eq!(plain_candidates[0].value, value);

        let ambiguous = format!(r#"const api_token = "{value}"[continued]"#);
        assert!(keyword_structured_candidates(&ambiguous, &keyword, &[]).is_empty());

        let password_keyword = FancyRegex::new("(?is:password)").unwrap();
        let array = r#"byte[]password=new byte[]{0x3,0x5,0x8,0x3,0x5,0x8};"#;
        let array_candidates = keyword_structured_candidates(array, &password_keyword, &[]);
        assert_eq!(
            array_candidates.len(),
            1,
            "{array_candidates_len}",
            array_candidates_len = array_candidates.len()
        );
        assert_eq!(array_candidates[0].value, "0x3,0x5,0x8,0x3,0x5,0x8");

        let secret_keyword = FancyRegex::new("(?is:secret)").unwrap();
        let wrapped = r#"secret := splitHexString("8ea332e7f666980cdd51651661ba02c9 3137b50508c57c1676e719f45c21635d")"#;
        let wrapped_candidates = keyword_structured_candidates(wrapped, &secret_keyword, &[]);
        assert_eq!(wrapped_candidates.len(), 1);
        assert_eq!(
            wrapped_candidates[0].value,
            "8ea332e7f666980cdd51651661ba02c9 3137b50508c57c1676e719f45c21635d"
        );
    }

    #[test]
    fn structured_keyword_does_not_reinterpret_an_escaped_opening_quote() {
        let key = FancyRegex::new("(?is:key(?!word|board|pad|name))").expect("key keyword");
        let escaped = r#"keyWithAuds := "\"\xf7\xac\xcd\x12\xf5\x83""#;
        assert!(keyword_structured_candidates(escaped, &key, &[]).is_empty());
        let region = crate::model::Region {
            span: ByteRange::new(0, escaped.len()),
            ctx: crate::model::Context {
                path: Some("test/server/key.go".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, escaped);
        assert!(!CredSweeperNativeDetector::builtin()
            .detect_findings(&view)
            .iter()
            .any(|finding| finding.rule_name == "Key"));
        let ordinary = r#"keyWithoutAuds := "\x810r-valid-secret""#;
        assert_eq!(1, keyword_structured_candidates(ordinary, &key, &[]).len());
    }

    #[test]
    fn keyword_url_candidates_match_literal_and_percent_encoded_parameters() {
        let keyword = FancyRegex::new("(?is:auth(?!ors?(?!i[tz])))").unwrap();
        let literal = r#"oauth_token=firstvalue123&oauth_token=secondvalue456&next=value"#;
        let candidates = keyword_url_candidates(literal, &keyword);
        // Literal URL tails are handled by the upstream regex retry path. The
        // supplement only starts at a line/quoted value, otherwise it would
        // scan arbitrary `?key=` text that upstream never matched.
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].variable, Some("oauth_token"));
        assert_eq!(
            sanitize_value_capture(literal, ".txt", &candidates[0]).value,
            "firstvalue123"
        );

        let encoded = "x%26oauth_nonce%3Dlqaw2384lq4946nd%26oauth_token%3Dkgwv659s32kh9kot%26y";
        let candidates = keyword_url_candidates(encoded, &keyword);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].variable, Some("oauth_nonce"));
        assert_eq!(candidates[0].separator, Some("%3D"));
        assert_eq!(
            sanitize_value_capture(encoded, ".txt", &candidates[0]).value,
            "lqaw2384lq4946nd"
        );
        assert_eq!(candidates[1].variable, Some("oauth_token"));
        assert_eq!(
            sanitize_value_capture(encoded, ".txt", &candidates[1]).value,
            "kgwv659s32kh9kot"
        );
    }

    #[test]
    fn keyword_url_candidate_does_not_cross_an_encoded_parameter_boundary() {
        let keyword = FancyRegex::new("(?is:key(?!word|board|pad|name))").expect("key keyword");
        let tail = "consumer-key%26oauth_nonce%3D0df9f35f-c894-0346-78d3-909023eb72a0";
        assert!(keyword_url_candidates(tail, &keyword).is_empty());
    }

    #[test]
    fn auth_password_url_candidate_matches_official_creddata_result() {
        let line = "\t\t\t\tquery: `auth-password=cjBxbsGugiddvw&domain-name=bar.com&host=value`,";
        let keyword = FancyRegex::new("(?is:auth(?!ors?(?!i[tz])))").unwrap();
        let candidates = keyword_url_candidates(line, &keyword);
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.value.starts_with("cjBxbsGugiddvw&"))
            .expect("official Auth URL candidate");
        assert_eq!(candidate.variable, Some("`auth-password"));
        let sanitized = sanitize_value_capture(line, ".go", candidate);
        assert_eq!((sanitized.start, sanitized.end), (26, 40));
        let line_ctx = CandidateLineContext {
            start: 0,
            line,
            previous: None,
            next: None,
            file_type: ".go",
            target: line,
            line_index: 0,
        };
        let rejected_by = expand_filter_group("GeneralKeyword")
            .into_iter()
            .filter(|filter| {
                !accept_filter_list(
                    candidate.value,
                    std::slice::from_ref(filter),
                    candidate,
                    &line_ctx,
                    candidate.start,
                    candidate.end,
                )
            })
            .collect::<Vec<_>>();

        let region = crate::model::Region {
            span: ByteRange::new(0, line.len()),
            ctx: crate::model::Context {
                path: Some("test/internal/client/56575ef0.go".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, line);
        let input = MlInput {
            line: line.to_string(),
            value: "cjBxbsGugiddvw".to_string(),
            variable: "`auth-password".to_string(),
            value_start: 26,
            value_end: 40,
            variable_start: 11,
            variable_end: 25,
            path: "test/internal/client/56575ef0.go".to_string(),
            line_num: 417,
            file_type: ".go".to_string(),
            rule_name: "Auth".to_string(),
            severity: RuleSeverity::Medium,
        };
        let (score, threshold) = credsweeper_ml::score_group_for_test(&[&input]);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        assert!(
            findings.iter().any(|finding| {
                finding.rule_name == "Auth"
                    && finding.value == "cjBxbsGugiddvw"
                    && finding.variable.as_deref() == Some("`auth-password")
            }),
            "score={score} threshold={threshold} rejected_by={rejected_by:?} {findings:?}"
        );
    }

    #[test]
    fn set_directive_candidate_matches_official_auth_comment() {
        let line = "// Example: To set auth token BC428392331C8B5CBF09CE69A885B68FDC930261582F8B8EEB43FA98C648A49A";
        let keyword = FancyRegex::new("(?is:auth(?!ors?(?!i[tz])))").unwrap();
        let candidates = keyword_set_directive_candidates(line, &keyword);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].variable, Some("auth token"));
        assert_eq!(candidates[0].separator, Some(" "));
        assert_eq!(
            candidates[0].value,
            "BC428392331C8B5CBF09CE69A885B68FDC930261582F8B8EEB43FA98C648A49A"
        );
    }

    #[test]
    fn set_directive_does_not_start_a_second_keyword_after_variable_whitespace() {
        let token = FancyRegex::new("(?is:token(?!ize))").expect("token keyword");
        let line = "// Example: To set auth token BC428392331C8B5CBF09CE69A885B68FDC930261582F8B8EEB43FA98C648A49A";
        assert!(keyword_set_directive_candidates(line, &token).is_empty());
    }

    #[test]
    fn structured_keyword_parser_matches_escaped_html_separator_and_quotes() {
        let line = r#"\"authenticity_token\"=\u0026gt;\n      \"jydi0opu6JsE0gfgzqzUkFtqeZLBhu1CvezGHV8LOfcbNtJRjjuui07mnuUggC31LVoCIXzyiSBzLLFMKHOj==\""#;
        let keyword = FancyRegex::new("(?is:auth(?!ors?(?!i[tz])))").unwrap();
        let candidates = keyword_structured_candidates(line, &keyword, &[]);
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.value.starts_with("jydi0opu6"))
            .expect("escaped official Auth candidate");
        assert_eq!(candidate.separator, Some(r#"=\u0026gt;"#));
        assert_eq!(candidate.value_leftquote, Some(r#"\""#));
        assert_eq!(candidate.value_rightquote, Some(r#"\""#));
    }

    #[test]
    fn deferred_keyword_matcher_keeps_escaped_authenticity_token_candidate() {
        let line = r#"ate as HTML\n  Parameters: {\"utf8\"=\u0026gt;\"✓\", \"authenticity_token\"=\u0026gt;\n      \"jydi0opu6JsE0gfgzqzUkFtqeZLBhu1CvezG\n       HV8LOfcbNtJRj/juui07mnuUggC31LVoCIXzyiS+BzLLFMKHOj==\",\n       \"user\"=\u0026g"#;
        let keyword = r"auth(?!ors?(?!i[tz]))";
        let matcher = DeferredRegex {
            source: keyword_pattern(keyword),
            keyword_source: Some(keyword.to_string()),
            compiled: OnceLock::new(),
            compiled_keyword: OnceLock::new(),
        };
        let candidates = matcher.find(line, true);
        let candidate = candidates
            .iter()
            .find(|candidate| {
                candidate.value.starts_with("jydi0opu6")
                    && candidate
                        .variable
                        .is_some_and(|variable| variable.contains("authenticity_token"))
            })
            .unwrap_or_else(|| {
                panic!(
                    "{:?}",
                    candidates
                        .iter()
                        .map(|candidate| (candidate.variable, candidate.value))
                        .collect::<Vec<_>>()
                )
            });
        let sanitized = sanitize_value_capture(line, ".ndjson", candidate);
        let line_ctx = CandidateLineContext {
            start: 0,
            line,
            previous: None,
            next: None,
            file_type: ".ndjson",
            target: line,
            line_index: 0,
        };
        let rejected_by = expand_filter_group("GeneralKeyword")
            .into_iter()
            .filter(|filter| {
                !accept_filter_list(
                    sanitized.value,
                    std::slice::from_ref(filter),
                    candidate,
                    &line_ctx,
                    sanitized.start,
                    sanitized.end,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            rejected_by.is_empty(),
            "rejected_by={rejected_by:?} variable={:?} separator={:?} left={:?} right={:?} value={:?}",
            candidate.variable,
            candidate.separator,
            candidate.value_leftquote,
            candidate.value_rightquote,
            candidate.value
        );
    }

    #[test]
    fn asn1_size_matches_credsweeper_length_rules() {
        assert_eq!(asn1_size(&[0x30, 0x03, 1, 2, 3]), Some(5));
        assert_eq!(asn1_size(&[0x30, 0x81, 0x02, 1, 2]), Some(5));
        assert_eq!(asn1_size(&[0x30, 0x80, 1, 2, 0, 0]), Some(6));
        assert_eq!(asn1_size(&[0x30, 0x03, 1, 2]), None);
        assert_eq!(asn1_size(&[0x31, 0x00]), None);
    }

    #[test]
    fn sealed_secret_searches_the_official_hundred_line_window() {
        let secret = format!("AgA{}", "A".repeat(698));
        let target = format!(
            "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nspec:\n  encryptedData:\n  value: {secret}\n"
        );
        let context = CandidateLineContext {
            start: 0,
            line: &secret,
            previous: None,
            next: None,
            file_type: "yaml",
            target: &target,
            line_index: 4,
        };
        assert!(value_sealed_secret_filtered(&secret, &context));

        let unrelated = CandidateLineContext {
            target: &secret,
            line_index: 0,
            ..context
        };
        assert!(!value_sealed_secret_filtered(&secret, &unrelated));
    }

    #[test]
    fn value_base64_key_loads_and_checks_private_keys() {
        let der = rsa_fixture_der();
        let encoded = BASE64.encode(&der);
        assert!(!value_base64_key_filtered(&encoded));

        let wrapped = encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\\n");
        assert!(!value_base64_key_filtered(&format!("'''{wrapped}'''")));
        assert!(value_base64_key_filtered("MIIXXXXX"));
    }

    #[test]
    fn value_base64_key_ignores_captured_source_punctuation_like_python() {
        let encoded = BASE64.encode(&rsa_fixture_der());
        assert!(!value_base64_key_filtered(&format!("{encoded}\"`,")));
    }

    #[test]
    fn value_file_path_matches_official_fixtures() {
        for value in [
            "/u5r/d3v/f1le",
            "5//0KCPafDhZvtCwqrsyiKFeDGT_0ZGHiI-E0ClIWrLC7tZ1WE5vHc4-Y2qi1IhPy3Pz5fmCe9OPIxEZUONUg7SWJF9nwQ_j2lIdXU0",
            "SDF;4s]dDe",
        ] {
            assert!(!value_file_path_filtered(value, None), "{value}");
        }
        for value in [
            "[DEPOT]/${path}/$(date)/config/credentials",
            "/mnt/x",
            "/srv/x",
            "/var/lib/",
            "~/.ssh/id_rsa",
            "../key",
            "../../log",
            "/home/user/.ssh/id_rsa",
            "../.ssh/id_rsa",
            "crackle/filepath.txt",
            "/home/user/tmp",
            "file:///Crackle/filepath/",
            "~/.custompass",
            "./sshpass.sh",
            "crackle/file.path",
            "C:\\Crackle\\filepath",
        ] {
            assert!(value_file_path_filtered(value, None), "{value}");
        }
    }

    #[test]
    fn alibaba_multi_reports_the_secret_paired_with_an_access_key_id() {
        let raw = concat!(
            "access_key_id = LTAIaB7kQ9mX2pR8vN4z\n",
            "access_key_secret = G7mQ9xL2pR8vN4kZaB6cD3fH5jT1wS\n",
        );
        let candidates = alibaba_multi_candidates(raw);

        assert!(candidates.iter().any(|candidate| {
            candidate.value == "G7mQ9xL2pR8vN4kZaB6cD3fH5jT1wS"
                && candidate
                    .line_data
                    .iter()
                    .any(|part| part.value == "LTAIaB7kQ9mX2pR8vN4z")
        }));
    }

    #[test]
    fn aws_multi_pairs_adjacent_yaml_fields_like_official_creddata() {
        let first_id = ["AKIA", "LJDBECWDLOOWXROV"].concat();
        let first_secret = ["Lplsx2J0OaHPJoG7U7kp", "bhGUvnQ7Yv3O7zN3XXus"].concat();
        let second_id = ["AKIA", "MFSEYJMNHBGBFMOZ"].concat();
        let second_secret = ["Omfzc3O7SqEDVpV7A5gc", "snRZceT4Ls7X9pL1FVxa"].concat();
        let raw = format!(
            "    accessKeyId: {first_id}\n\
             secretAccessKey: {first_secret}\n\
             mock: true\n\n\
             accessKeyId: {second_id}\n\
             secretAccessKey: {second_secret}\n",
        );
        let candidates = aws_multi_candidates(&raw);
        assert_eq!(2, candidates.len());
        assert_eq!(2, candidates[0].line_data.len());
        assert_eq!(first_id, candidates[0].line_data[0].value);
        assert_eq!(first_secret, candidates[0].line_data[1].value);

        let region = crate::model::Region {
            span: ByteRange::new(0, raw.len()),
            ctx: crate::model::Context {
                path: Some("mock/connectors.yaml".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, &raw);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        assert_eq!(
            2,
            findings
                .iter()
                .filter(|finding| finding.rule_name == "AWS Multi")
                .count(),
            "{:?}",
            findings
                .iter()
                .map(|finding| (
                    &finding.rule_name,
                    &finding.value,
                    finding.value_start,
                    finding.value_end
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn aws_multi_applies_official_filters_to_the_anchor() {
        let raw = concat!(
            "AWS_ACCESS_KEY_ID=AKIAQWERTYUIOP123456\n",
            "AWS_SECRET_ACCESS_KEY=aB3/aB3/aB3/aB3/aB3/aB3/aB3/aB3/aB3/aB3/\n",
        );

        assert!(aws_multi_candidates(raw).is_empty());
    }

    #[test]
    fn alibaba_multi_applies_official_filters_to_the_anchor() {
        let raw = concat!(
            "access_key_id = LTAI1234567890ABCDEF\n",
            "access_key_secret = G7mQ9xL2pR8vN4kZaB6cD3fH5jT1wS\n",
        );

        assert!(alibaba_multi_candidates(raw).is_empty());
    }

    #[test]
    fn google_multi_applies_official_filters_to_the_anchor() {
        let google_id = format!("123-{}.apps.googleusercontent.com", "a".repeat(32));
        let google_secret = ["GO", "CSPX-FAsZauZ28P3STmkBhqQi1Y-EsEaX"].concat();
        let raw = format!("{google_id}\n{google_secret}\n");

        assert!(google_multi_candidates(&raw).is_empty());
    }

    #[test]
    fn embedded_ml_feature_vector_matches_model() {
        assert!(credsweeper_ml::feature_width_matches_model_for_test());
    }

    #[test]
    fn value_allowlist_matches_credsweeper_code_expressions() {
        let unquoted = test_candidate("", None, None, None);
        assert!(value_allowlist_filtered(
            "xmlKey->NextSiblingElement();",
            &unquoted,
            false
        ));
        assert!(value_allowlist_filtered(
            "config.secret.value()",
            &unquoted,
            false
        ));
        assert!(value_allowlist_filtered("${SECRET_NAME}", &unquoted, false));
        assert!(!value_allowlist_filtered(
            "opaqueCredentialValue1234567890",
            &unquoted,
            false
        ));
    }

    #[test]
    fn doc_credentials_filters_method_call_values_like_credsweeper() {
        let raw = "xmlKey = xmlKey->NextSiblingElement();\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let spans = CredSweeperNativeDetector::builtin().detect(&view);
        assert!(!spans.iter().any(|span| span.label == "DOC_CREDENTIALS"));
    }

    #[test]
    fn detects_compatible_credsweeper_rule_without_python() {
        let token = concat!(
            "github_pat_",
            "rOtEBPV4Es4QuKKticlQTRBHdyjljMqognRzUEQT65E6B6lEbvdMHVYqwEXsxuwu",
            "RnOhkMFGCsCyfNgn",
        );
        let raw = format!("token={token}\n");
        let region = region(&raw);
        let view = NormalizedView::build(&region, &raw);
        let spans = CredSweeperNativeDetector::builtin().detect(&view);
        assert!(spans
            .iter()
            .any(|span| span.label == "GITHUB_FINE_GRANTED_TOKEN"));
        assert!(!spans.iter().any(|span| span.label == "DOC_CREDENTIALS"));
        assert!(spans
            .iter()
            .all(|span| span.source == DetectorId::CredSweeper));
    }

    #[test]
    fn detects_nkey_seed_like_official_credsweeper() {
        let seed = "SODOJNLHRLOMANBDDQMI3D4MW5IVBAR6ERSVYTFP2QU3EIC4JKI3MLU3OT";
        let raw = format!(r#"var oSeed = []byte("{seed}")"#);
        let detector = CredSweeperNativeDetector::builtin();
        let rule = detector
            .rules
            .iter()
            .find(|rule| rule.rule_name == "NKEY Seed")
            .unwrap();
        assert_eq!(rule.patterns.len(), 1);
        let PatternMatcher::Deferred(regex) = &rule.patterns[0].matcher else {
            panic!("NKEY Seed must use its upstream regex");
        };
        let candidates = regex.find(&raw, true);
        assert_eq!(candidates.len(), 1, "upstream pattern candidate");
        let candidate = &candidates[0];
        assert_eq!(candidate.value, seed);
        let line_ctx = CandidateLineContext {
            start: 0,
            line: &raw,
            previous: None,
            next: None,
            file_type: ".go",
            target: &raw,
            line_index: 0,
        };
        let rejected = rule
            .filter_types
            .iter()
            .filter(|filter| {
                !accept_filter_list(
                    candidate.value,
                    std::slice::from_ref(filter),
                    candidate,
                    &line_ctx,
                    candidate.start,
                    candidate.end,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            rejected.is_empty(),
            "upstream filter differences: {rejected:?}"
        );
        assert!(
            accept_value(
                candidate.value,
                rule,
                candidate,
                &line_ctx,
                candidate.start,
                candidate.end
            ),
            "upstream filters"
        );
        let mut seen = vec![false; detector.rules.len()];
        let mut selected = Vec::new();
        detector
            .line_prefilter
            .collect(&LazyLower::new(&raw), &mut seen, &mut selected);
        assert!(
            selected
                .iter()
                .any(|index| detector.rules[*index].rule_name == "NKEY Seed"),
            "line prefilter"
        );

        let region = region(&raw);
        let view = NormalizedView::build(&region, &raw);
        let findings = detector.detect_findings(&view);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_name == "NKEY Seed"),
            "{findings:?}"
        );
    }

    #[test]
    fn keyword_regex_keeps_wrapped_numeric_auth_data() {
        let raw = "authData := []byte{18, 170, 22, 142, 90, 59, 56, 77, 8, 65, 225, 157, 53,";
        let detector = CredSweeperNativeDetector::builtin();
        let rule = detector
            .rules
            .iter()
            .find(|rule| rule.rule_name == "Auth")
            .unwrap();
        let PatternMatcher::Deferred(regex) = &rule.patterns[0].matcher else {
            panic!("Auth must use its upstream keyword regex");
        };
        let compiled = regex.compiled().unwrap();
        let CompiledRegex::Fancy(compiled) = compiled else {
            panic!("Auth keyword regex requires fancy-regex");
        };
        let results = compiled.captures_iter(raw).collect::<Vec<_>>();
        assert!(
            results.iter().all(Result::is_ok),
            "keyword regex runtime error: {results:?}"
        );
        assert_eq!(results.len(), 1, "upstream keyword candidate");
        let candidates = regex.find(raw, true);
        let candidate = candidates
            .iter()
            .find(|candidate| !candidate.value.is_empty())
            .expect("structured fallback candidate");
        let line_ctx = CandidateLineContext {
            start: 0,
            line: raw,
            previous: None,
            next: None,
            file_type: ".go",
            target: raw,
            line_index: 0,
        };
        let filtered_value = candidate
            .value
            .trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == '`');
        let rejected = rule
            .filter_types
            .iter()
            .filter(|filter| {
                !accept_filter_list(
                    filtered_value,
                    std::slice::from_ref(filter),
                    candidate,
                    &line_ctx,
                    candidate.start,
                    candidate.end,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            rejected.is_empty(),
            "upstream filter differences: {rejected:?}; value={filtered_value:?}"
        );
        assert!(
            accept_value(
                candidate.value,
                rule,
                candidate,
                &line_ctx,
                candidate.start,
                candidate.end
            ),
            "upstream filters rejected candidate"
        );
    }

    #[test]
    fn general_pattern_filters_repeated_fixture_tokens_like_official_credsweeper() {
        let token = format!("github_pat_{}", "A".repeat(80));
        let raw = format!("token={token}\n");
        let region = region(&raw);
        let view = NormalizedView::build(&region, &raw);
        let spans = CredSweeperNativeDetector::builtin().detect(&view);
        assert!(spans.is_empty(), "{spans:?}");
    }

    #[test]
    fn detects_wundergraph_rule_from_v1_17_1() {
        let raw = "token=cosmo_66ebe5a6121b52c86058ecd8803ce4bb\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let spans = CredSweeperNativeDetector::builtin().detect(&view);
        assert!(
            spans.iter().any(|span| span.label == "WUNDERGRAPH_API_KEY"),
            "{spans:?}"
        );
    }

    #[test]
    fn token_pattern_filters_sequential_fixture_tokens_like_official_credsweeper() {
        let raw = "token=cosmo_0123456789abcdef0123456789abcdef\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let spans = CredSweeperNativeDetector::builtin().detect(&view);
        assert!(spans.is_empty(), "{spans:?}");
    }

    #[test]
    fn translated_credsweeper_rules_are_active() {
        let aws_id = ["AKIA", "LJDBECWDLOOWXROV"].concat();
        let aws_secret = "Lplsx2J0OaHPJoG7U7kpbhGUvnQ7Yv3O7zN3XXus".to_string();
        let google_id = format!(
            "123-{}.apps.googleusercontent.com",
            "abcdeabcdeabcdeabcdeabcdeabcdeab"
        );
        let google_secret = format!("GOCSPX-{}", "A".repeat(28));
        let jwk_secret = concat!(
            "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn5oZE5uSCI",
            "wg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3izlbkosrzjHajIcY33HBh",
        );
        let base64_key = BASE64.encode(&rsa_fixture_der());
        let raw = format!(
            "aws {aws_id} {aws_secret}\n\
             google {google_id} {google_secret}\n\
             jwk {{\"kty\":\"RSA\",\"d\":\"{jwk_secret}\"}}\n\
             -----BEGIN OPENSSH PRIVATE KEY-----\n\
             {base64_key}\n\
             -----END OPENSSH PRIVATE KEY-----\n\
             const PASSWORD: string = \"A8f3Kp9Lm2Qx7Zt4\";\n"
        );
        let region = region(&raw);
        let view = NormalizedView::build(&region, &raw);
        let labels = CredSweeperNativeDetector::builtin()
            .detect(&view)
            .into_iter()
            .map(|span| span.label)
            .collect::<Vec<_>>();
        for label in [
            "AWS_MULTI",
            "GOOGLE_MULTI",
            "JWK",
            "PEM_PRIVATE_KEY",
            "BASE64_PRIVATE_KEY",
            "PASSWORD",
        ] {
            assert!(
                labels.iter().any(|actual| actual == label),
                "{label}: {labels:?}"
            );
        }
    }

    #[test]
    fn raw_findings_keep_parallel_keyword_rules() {
        let raw =
            "DJANGO_SECRET_KEY=8GS8FNrJgo1uN08yE4yHamlUJp3mtVrY30c4i511Ll2JiDyktZplm3p5cINPX97L\n";
        let region = crate::model::Region {
            span: ByteRange::new(0, raw.len()),
            ctx: crate::model::Context {
                path: Some("conf/settings.example".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, raw);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        assert!(findings.iter().any(|finding| {
            finding.rule_name == "Secret"
                && finding.variable.as_deref() == Some("DJANGO_SECRET_KEY")
        }));
        assert!(findings.iter().any(|finding| {
            finding.rule_name == "Key" && finding.variable.as_deref() == Some("DJANGO_SECRET_KEY")
        }));
    }

    #[test]
    fn keyword_rules_rescan_multiple_assignments_in_one_regex_match() {
        let raw = "final String responseBody = \"oauth_token=vt2q56n7zhfksqaw&oauth_token_secret=lghm7395e8t6yv01\";\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        for rule in ["Auth", "Token"] {
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_name == rule
                        && finding.variable.as_deref() == Some("oauth_token_secret")
                        && finding.value == "lghm7395e8t6yv01"
                }),
                "{rule}: {findings:?}"
            );
        }
    }

    #[test]
    fn keyword_rule_keeps_method_wrapped_key_value_like_upstream() {
        let raw = "key = Base64.decode64('IxXGeq5fLHv=')\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        assert!(
            findings
                .iter()
                .any(|finding| { finding.rule_name == "Key" && finding.value == "IxXGeq5fLHv=" }),
            "{findings:?}"
        );
    }

    #[test]
    fn password_ml_matches_official_creddata_candidates() {
        for (path, raw, expected) in [
            (
                "benchmarks/CredData/data/02dfa7ec/test/a5c0c9aa.py",
                "        self.password = 'ouywdakchdmtjjva'\n",
                "ouywdakchdmtjjva",
            ),
            (
                "benchmarks/CredData/data/02dfa7ec/test/setting/e43ec22b.py",
                "        self.password = 'ufnlbbavawsdeecn'\n",
                "ufnlbbavawsdeecn",
            ),
        ] {
            let region = crate::model::Region {
                span: ByteRange::new(0, raw.len()),
                ctx: crate::model::Context {
                    path: Some(path.to_string()),
                    key: None,
                    hints: Vec::new(),
                    kind: crate::model::RegionKind::PlainText,
                    format: crate::model::Kind::Text,
                },
            };
            let view = NormalizedView::build(&region, raw);
            let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
            let detector = CredSweeperNativeDetector::builtin();
            let rule = detector
                .rules
                .iter()
                .find(|rule| rule.rule_name == "Password")
                .unwrap();
            let candidate = rule
                .patterns
                .iter()
                .flat_map(|pattern| match &pattern.matcher {
                    PatternMatcher::Deferred(regex) => {
                        regex.find(raw.trim_end(), pattern.value_capture)
                    }
                    PatternMatcher::Special(_) => Vec::new(),
                })
                .find(|candidate| candidate.value == expected)
                .unwrap();
            let line_ctx = CandidateLineContext {
                start: 0,
                line: raw.trim_end(),
                previous: None,
                next: None,
                file_type: ".py",
                target: raw,
                line_index: 0,
            };
            assert_eq!(candidate.value_leftquote, Some("'"));
            assert_eq!(candidate.value_rightquote, Some("'"));
            assert!(accept_value(
                candidate.value,
                rule,
                &candidate,
                &line_ctx,
                candidate.start,
                candidate.end,
            ));
            let input = MlInput {
                line: raw.trim_end().to_string(),
                value: expected.to_string(),
                variable: "self.password".to_string(),
                value_start: 25,
                value_end: 41,
                variable_start: 8,
                variable_end: 21,
                path: path.to_string(),
                line_num: 1,
                file_type: ".py".to_string(),
                rule_name: "Password".to_string(),
                severity: RuleSeverity::High,
            };
            let (score, threshold) = credsweeper_ml::score_group_for_test(&[&input]);
            assert!(
                score >= threshold,
                "{path}: score={score} threshold={threshold}"
            );
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_name == "Password" && finding.value == expected
                }),
                "{path}: score={score} threshold={threshold} findings={findings:?}"
            );
        }

        let raw = "        self.password = ouywdakchdmtjjva\n";
        let region = crate::model::Region {
            span: ByteRange::new(0, raw.len()),
            ctx: crate::model::Context {
                path: Some("benchmarks/CredData/data/02dfa7ec/test/a5c0c9aa.py".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, raw);
        assert!(CredSweeperNativeDetector::builtin()
            .detect_findings(&view)
            .iter()
            .all(|finding| finding.value != "ouywdakchdmtjjva"));
    }

    #[test]
    fn line_wrapped_key_matches_official_ml_decision() {
        let raw = "key_wrap = 'KJHhJKhKU7yguyuyfrtsdESffhjgkhYT\\";
        let input = MlInput {
            line: raw.to_string(),
            value: "KJHhJKhKU7yguyuyfrtsdESffhjgkhYT".to_string(),
            variable: "key_wrap".to_string(),
            value_start: 12,
            value_end: 44,
            variable_start: 0,
            variable_end: 8,
            path: "samples/nonce.py".to_string(),
            line_num: 7,
            file_type: ".py".to_string(),
            rule_name: "Key".to_string(),
            severity: RuleSeverity::High,
        };
        let (score, threshold) = credsweeper_ml::score_group_for_test(&[&input]);
        let region = crate::model::Region {
            span: ByteRange::new(0, raw.len()),
            ctx: crate::model::Context {
                path: Some("samples/nonce.py".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, raw);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        assert!(
            findings.iter().any(|finding| finding.rule_name == "Key"),
            "score={score} threshold={threshold} findings={findings:?}"
        );
    }

    #[test]
    fn shared_auth_password_value_matches_official_ml_group() {
        let line = r#"            "password : Password for authorization\n        BAIT: bace4d59-fa7e-beef-cafe-9129474bcd81","#;
        let common = |rule_name: &str, variable: &str, start: isize| {
            MlInput {
            line: line.to_string(),
            value: "bace4d59-fa7e-beef-cafe-9129474bcd81".to_string(),
            variable: variable.to_string(),
            value_start: 66,
            value_end: 102,
            variable_start: start,
            variable_end: 64,
            path: "crates/pentect-core/vendors/CredSweeper/tests/file_handler/test_text_content_provider.py".to_string(),
            line_num: 42,
            file_type: ".py".to_string(),
            rule_name: rule_name.to_string(),
            severity: RuleSeverity::Medium,
        }
        };
        let auth = common("Auth", r"authorization\n        BAIT", 37);
        let password = common("Password", r"Password for authorization\n        BAIT", 24);
        let uuid = MlInput {
            variable: String::new(),
            variable_start: -2,
            variable_end: -2,
            rule_name: "UUID".to_string(),
            severity: RuleSeverity::Info,
            ..common("UUID", "", -2)
        };
        let (score, threshold) = credsweeper_ml::score_group_for_test(&[&uuid, &auth, &password]);
        assert!(score >= threshold, "score={score} threshold={threshold}");
    }

    #[test]
    fn keyword_rules_match_official_nested_fixture_literals() {
        for (path, raw, rule_name, expected) in [
            (
                "benchmarks/CredData/891ea546/test/internal/b0187704.go",
                "\taesKey := lorawan.AES128Key{39, 156, 136, 85, 44, 13, 73, 133, 53, 33, 241, 130, 175, 21, 67, 162}",
                "Key",
                "39, 156, 136, 85, 44, 13, 73, 133, 53, 33, 241, 130, 175, 21, 67, 162",
            ),
            (
                "benchmarks/CredData/fc8343f4/test/src/conf/rest/client/a9119ede.go",
                "KeyData:[]uint8{0x5f, 0x8d, 0x8d, 0x14, 0x21, 0x49, 0x07, 0x84, 0x90, 0x54, 0x75, 0x94, 0x08, 0x5e, 0x5b, 0x3e}",
                "Key",
                "0x5f, 0x8d, 0x8d, 0x14, 0x21, 0x49, 0x07, 0x84, 0x90, 0x54, 0x75, 0x94, 0x08, 0x5e, 0x5b, 0x3e",
            ),
            (
                "benchmarks/CredData/f5e5719b/test/0204df43.go",
                "Token: protocol.StatelessResetToken{0x79, 0x18, 0x30, 0x56, 0x56, 0x76, 0x46, 0x40, 0x21, 0x25, 0xaa, 0xae, 0xdf, 0xaa, 0xab, 0xdc},",
                "Token",
                "0x79, 0x18, 0x30, 0x56, 0x56, 0x76, 0x46, 0x40, 0x21, 0x25, 0xaa, 0xae, 0xdf, 0xaa, 0xab, 0xdc",
            ),
            (
                "benchmarks/CredData/41659445/test/c7cb0c45.js",
                "    const secret = 'itnc ptx8 wk2t m3mk q4lx 7bcx vdes wrwh'.replace(/ /g, '');",
                "Secret",
                "itnc ptx8 wk2t m3mk q4lx 7bcx vdes wrwh",
            ),
            (
                "benchmarks/CredData/8f4427e8/test/internal/app/87ecff12.go",
                r#"if aws.ToString(opsapp.SslConfiguration.PrivateKey) != "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCikCm00x/ybpc9esWOwK2JcyWAj3nUwsdW6Kbq8gsf/ndYAveD\n-----END RSA PRIVATE KEY-----" {"#,
                "Key",
                "-----BEGIN RSA PRIVATE KEY-----\\nMIICXQIBAAKBgQCikCm00x/ybpc9esWOwK2JcyWAj3nUwsdW6Kbq8gsf/ndYAveD\\n-----END RSA PRIVATE KEY-----",
            ),
            (
                "benchmarks/CredData/a0cd6261/resource/7f6a3252.md",
                "aquatone-discover --set-key shodan i7bly5bt40yHHyxVY7Qws2GYfrS56xgF",
                "Key",
                "i7bly5bt40yHHyxVY7Qws2GYfrS56xgF",
            ),
            (
                "benchmarks/CredData/e72eb979/_/d272f92a.php",
                r#"define('SECRET_KEY', 'nEsh9GjtZ03|\/|g79t70k5a6zfNk71k');"#,
                "Secret",
                r#"nEsh9GjtZ03|\/|g79t70k5a6zfNk71k"#,
            ),
            (
                "benchmarks/CredData/f5e5719b/test/internal/9ebaf615.go",
                r#"secret := splitHexString("8ea332e7f666980cdd51651661ba02c9 3137b50508c57c1676e719f45c21635d")"#,
                "Secret",
                "8ea332e7f666980cdd51651661ba02c9 3137b50508c57c1676e719f45c21635d",
            ),
            (
                "benchmarks/CredData/850c2319/doc/3245bad3.md",
                r#"CREATE USER root@'hostname' IDENTIFIED BY "5q'jK3d7ca";"#,
                "SQL Password",
                "5q'jK3d7ca",
            ),
            (
                "benchmarks/CredData/efb4b495/init/c08cf4d6.sql",
                r#"\set POSTGRES_PASS L9hdg7rz"#,
                "Password",
                "L9hdg7rz",
            ),
            (
                "benchmarks/CredData/057480bf/_/16cf9f2f.cpp",
                r#"  byte Key128[16]={0x7a,0x8c,0x51,0x86,0x68,0xac,0xf5,0xe0,0xdd,0xe6,0x07,0x21,0x66,0xae,0x6d,0x8f};"#,
                "Key",
                "0x7a,0x8c,0x51,0x86,0x68,0xac,0xf5,0xe0,0xdd,0xe6,0x07,0x21,0x66,0xae,0x6d,0x8f",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/test_app.py",
                r#"            ("c.go", b'Credential: []byte{351, 266,    ,1,2,7,4,010, 100, 114, 157},', "Credential","#,
                "Credential",
                "351, 266,    ,1,2,7,4,010, 100, 114, 157",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"                '{"PWD":[{"kty":"oct","kid":"25b58GCM","k":"Xc_2A"},{"kty":"oct","kid":"09b51KW","k":"KG6wlB-6sIVQ"}]',"#,
                "Password",
                r#""kty":"oct","kid":"25b58GCM","k":"Xc_2A""#,
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"            ["byte[]password=new byte[]{0x3,0x5,0x8,0x3,0x5,0x8};", "0x3,0x5,0x8,0x3,0x5,0x8"],"#,
                "Password",
                "0x3,0x5,0x8,0x3,0x5,0x8",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/deep_scanner/test_struct_scanner.py",
                r#"            'salt': b"\t'\xDE\xAD\xBE\xEF,1\012\0","#,
                "Salt",
                r#"\t'\xDE\xAD\xBE\xEF,1\012\0"#,
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/file_handler/test_text_content_provider.py",
                r#"            "password : Password for authorization\n        BAIT: bace4d59-fa7e-beef-cafe-9129474bcd81","#,
                "Auth",
                "bace4d59-fa7e-beef-cafe-9129474bcd81",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/file_handler/test_text_content_provider.py",
                r#"            "password : Password for authorization\n        BAIT: bace4d59-fa7e-beef-cafe-9129474bcd81","#,
                "Password",
                "bace4d59-fa7e-beef-cafe-9129474bcd81",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/samples/nonce.py",
                "key_wrap = 'KJHhJKhKU7yguyuyfrtsdESffhjgkhYT\\",
                "Key",
                "KJHhJKhKU7yguyuyfrtsdESffhjgkhYT",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/filters/test_value_grafana_service_check.py",
                r#"    @pytest.mark.parametrize("line", ["glsa_DuMmY-T0K3N-f0R-tHe-Te5t-CRC32Ok_770c8cda"])"#,
                "Grafana Service Account Token",
                "glsa_DuMmY-T0K3N-f0R-tHe-Te5t-CRC32Ok_770c8cda",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/deep_scanner/test_sqlite3_scanner.py",
                r#"                                  'KEY': b'0\x82\x01=\x02\x01\x00\x02A\x00\xaf\xa2\x08\xbf\\U\xc2\xb8`\xa1'"#,
                "Key",
                r#"0\x82\x01=\x02\x01\x00\x02A\x00\xaf\xa2\x08\xbf\\U\xc2\xb8`\xa1"#,
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"                "//&user%5Bemail%5D=credsweeper%40example.com&user%5Bpassword%5D=Dmdkesfdsq452%23%40!&user%5Bpassword_","#,
                "Password",
                "Dmdkesfdsq452%23%40!",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"            ['''final String body = \"{ \\"passwords\\":\\"i0sEcReT\\\\/MwX3X\\","''', '''i0sEcReT\\\\/MwX3X'''],"#,
                "Password",
                r#"i0sEcReT\\\\/MwX3X"#,
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                "            ['password = \"3VNdhWT3oFo5I7faffKO\\n   gnK7tYBcGxhla\\n\";', '''3VNdhWT3oFo5I7faffKO\\n   gnK7tYBcGxhla\\n'''],",
                "Password",
                "3VNdhWT3oFo5I7faffKO\\n   gnK7tYBcGxhla\\n",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"            ['#define password {0x35, 0x34, 0x65, 0x9b, 0x1c, 0x2e}', '0x35, 0x34, 0x65, 0x9b, 0x1c, 0x2e'],"#,
                "Password",
                "0x35, 0x34, 0x65, 0x9b, 0x1c, 0x2e",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"            ['#define password ";,}d4s@\\on"', ";,}d4s@\\on"],"#,
                "Password",
                r#";,}d4s@\\on"#,
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"            ['%define password "CEKPET"', "CEKPET"],"#,
                "Password",
                "CEKPET",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"            ['self.setPassword("0bead47f3c5bc275ec7b5eda8a333f")', "0bead47f3c5bc275ec7b5eda8a333f"],"#,
                "Password",
                "0bead47f3c5bc275ec7b5eda8a333f",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/common/test_keyword_pattern.py",
                r#"            ['PASSWORD = os.environ.get("PASSWORD") or "at5G6zi!m"', "at5G6zi!m"],"#,
                "Password",
                "at5G6zi!m",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/rules/test_password.py",
                r#"    @pytest.fixture(params=[["password = cackle!"], ["gi_reo_gi_passwd = cackle!"], ["pwd = cackle!"]])"#,
                "Password",
                "cackle!",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/rules/test_token.py",
                r#"    @pytest.fixture(params=[["gi_reo_gi_token = @@cacklecackle_gi_reo_gi@@"]])"#,
                "Token",
                "@@cacklecackle_gi_reo_gi@@",
            ),
            (
                "crates/pentect-core/vendors/CredSweeper/tests/rules/test_token.py",
                r##"    @pytest.fixture(params=[["# gi_reo_gi_token = @@cacklecackle_gi_reo_gi@@"]])"##,
                "Token",
                "@@cacklecackle_gi_reo_gi@@",
            ),
        ] {
            let region = crate::model::Region {
                span: ByteRange::new(0, raw.len()),
                ctx: crate::model::Context {
                    path: Some(path.to_string()),
                    key: None,
                    hints: Vec::new(),
                    kind: crate::model::RegionKind::PlainText,
                    format: crate::model::Kind::Text,
                },
            };
            let view = NormalizedView::build(&region, raw);
            let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
            let detector = CredSweeperNativeDetector::builtin();
            let rule = detector
                .rules
                .iter()
                .find(|rule| rule.rule_name == rule_name)
                .unwrap();
            let line_ctx = CandidateLineContext {
                start: 0,
                line: raw,
                previous: None,
                next: None,
                file_type: ".py",
                target: raw,
                line_index: 0,
            };
            let candidates = rule
                .patterns
                .iter()
                .flat_map(|pattern| match &pattern.matcher {
                    PatternMatcher::Deferred(regex) => regex.find(raw, pattern.value_capture),
                    PatternMatcher::Special(_) => Vec::new(),
                })
                .map(|candidate| {
                    let rejected_by = rule
                        .filter_types
                        .iter()
                        .filter(|filter| {
                            !accept_filter_list(
                                candidate.value,
                                std::slice::from_ref(*filter),
                                &candidate,
                                &line_ctx,
                                candidate.start,
                                candidate.end,
                            )
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    (
                        candidate.value.to_string(),
                        candidate.variable.map(str::to_string),
                        candidate.wrap.map(str::to_string),
                        candidate.value_leftquote.map(str::to_string),
                        candidate.value_rightquote.map(str::to_string),
                        rejected_by,
                    )
                })
                .collect::<Vec<_>>();
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_name == rule_name && finding.value == expected),
                "{rule_name} {raw:?}: candidates={candidates:?} findings={findings:?}"
            );
        }
    }

    #[test]
    fn keyword_variable_capture_matches_python_regex_after_a_quoted_value() {
        let keyword = r"key(?!word|board|pad|name)";
        let matcher = DeferredRegex {
            source: keyword_pattern(keyword),
            keyword_source: Some(keyword.to_string()),
            compiled: OnceLock::new(),
            compiled_keyword: OnceLock::new(),
        };
        for (line, expected_value, expected_variable) in [
            (
                r#"wantPublicKey: PublicKey{KeyID: String("1234"), Key: String("1Zf8zJfDerdO3PeLLzDeaLdXbETXc8v+wH0HDvuc5554")}"#,
                "1Zf8zJfDerdO3PeLLzDeaLdXbETXc8v+wH0HDvuc5554",
                "Key",
            ),
            (
                r#"if key != "fully_quantize" and key != "ygyke_44k8""#,
                "ygyke_44k8",
                "key",
            ),
        ] {
            let candidates = matcher.find(line, true);
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.value == expected_value)
                .expect("official keyword value");
            assert_eq!(candidate.variable, Some(expected_variable));
        }
    }

    #[test]
    fn setter_candidates_do_not_reuse_keywords_from_the_receiver() {
        let auth = FancyRegex::new("(?i)auth(?!ors?(?!i[tz]))").expect("auth keyword");
        let key = FancyRegex::new("(?i)key(?!word|board|pad|name)").expect("key keyword");
        let line = r#"appAuthData.setAppKey("C4BE64C410A8854BF9573397A89D3C83");"#;

        assert!(keyword_structured_candidates(line, &auth, &[]).is_empty());
        let candidates = keyword_structured_candidates(line, &key, &[]);
        assert_eq!(1, candidates.len());
        assert_eq!(Some("AppKey"), candidates[0].variable);
        assert_eq!("C4BE64C410A8854BF9573397A89D3C83", candidates[0].value);

        let constructor = r#"accessToken = new DefaultOAuth2AccessToken("HqGX44nwSZ");"#;
        assert!(keyword_structured_candidates(constructor, &auth, &[]).is_empty());
    }

    #[test]
    fn structured_keyword_does_not_cross_a_quoted_expression_before_separator() {
        let api = FancyRegex::new("(?is:api(?!tal))").expect("api keyword");
        let key = FancyRegex::new("(?is:key(?!word|board|pad|name))").expect("key keyword");
        let expression = concat!(
            "bootstrapapi.JWSSignatureKeyPrefix + \"abcdef\": ",
            "\"eyJhbGciOiJIUzI1NiJ9..signature\""
        );
        assert!(keyword_structured_candidates(expression, &api, &[]).is_empty());
        assert!(keyword_structured_candidates(expression, &key, &[]).is_empty());

        let json = r#"\"api_key\": \"0123456789abcdef\""#;
        assert_eq!(1, keyword_structured_candidates(json, &key, &[]).len());
    }

    #[test]
    fn structured_keyword_enforces_the_upstream_eighty_character_key_right_limit() {
        let api = FancyRegex::new("(?is:api(?!tal))").expect("api keyword");
        let accepted = format!("api{}=\"secret-value\"", "x".repeat(80));
        let rejected = format!("api{}=\"secret-value\"", "x".repeat(81));
        assert_eq!(1, keyword_structured_candidates(&accepted, &api, &[]).len());
        assert!(keyword_structured_candidates(&rejected, &api, &[]).is_empty());
    }

    #[test]
    fn structured_keyword_does_not_restart_inside_an_existing_regex_match() {
        let key = FancyRegex::new("(?is:key(?!word|board|pad|name))").expect("key keyword");
        let line = r#"wantPublicKey: PublicKey{KeyID: nil, Key: String("2Sg8iYjAxxmI2LvUXpJjkYrMxURPc8r+dB7TJyvv1234")}"#;
        let value_start = line.find("nil").expect("outer value");
        let existing = Candidate {
            start: value_start,
            end: line.len(),
            match_end: line.len(),
            value: &line[value_start..],
            variable_start: Some(0),
            variable_end: Some("wantPublicKey".len()),
            variable: Some("wantPublicKey"),
            separator: Some(":"),
            wrap: Some(" PublicKey{"),
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        };
        let candidates = keyword_structured_candidates(line, &key, &[existing]);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.variable != Some("Key")));

        let detector = CredSweeperNativeDetector::builtin();
        let rule = detector
            .rules
            .iter()
            .find(|rule| rule.rule_name == "Key")
            .expect("Key rule");
        let PatternMatcher::Deferred(regex) = &rule.patterns[0].matcher else {
            panic!("Key must use its upstream keyword regex");
        };
        let final_candidates = regex.find(line, true);
        assert!(final_candidates
            .iter()
            .all(|candidate| candidate.variable != Some("Key")));
    }

    #[test]
    fn fancy_keyword_match_prefers_unquoted_method_value_like_python_regex() {
        let detector = CredSweeperNativeDetector::builtin();
        let rule = detector
            .rules
            .iter()
            .find(|rule| rule.rule_name == "Password")
            .expect("Password rule");
        let PatternMatcher::Deferred(pattern) = &rule.patterns[0].matcher else {
            panic!("Password must use a deferred keyword regex");
        };
        let candidates = pattern.find("\t\tpassword: function( elem ) {", true);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.value == "function("),
            "{:?}",
            candidates
                .iter()
                .map(|candidate| (
                    candidate.value,
                    candidate.start,
                    candidate.end,
                    candidate.wrap,
                    candidate.value_leftquote,
                    candidate.value_rightquote
                ))
                .collect::<Vec<_>>()
        );
        assert!(!candidates.iter().any(|candidate| candidate.value == "elem"));
    }

    #[test]
    fn get_password_does_not_promote_a_short_unquoted_default() {
        let detector = CredSweeperNativeDetector::builtin();
        let rule = detector
            .rules
            .iter()
            .find(|rule| rule.rule_name == "Password")
            .expect("Password rule");
        let PatternMatcher::Deferred(pattern) = &rule.patterns[0].matcher else {
            panic!("Password must use a deferred keyword regex");
        };
        let line = r#"passwd = keyring.get_password("pgcli", key)"#;
        let candidates = pattern.find(line, true);
        let retry = pattern.find(&line["passwd".len()..], true);
        assert!(
            !retry.iter().any(|candidate| candidate.value == "key"),
            "retry: {:?}",
            retry
                .iter()
                .map(|candidate| (candidate.value, candidate.wrap, candidate.value_leftquote))
                .collect::<Vec<_>>()
        );
        assert!(
            candidates.iter().any(|candidate| candidate.value == "key"),
            "{:?}",
            candidates
                .iter()
                .map(|candidate| (
                    candidate.value,
                    candidate.wrap,
                    candidate.value_leftquote,
                    candidate.value_rightquote
                ))
                .collect::<Vec<_>>()
        );
        assert!(!candidates
            .iter()
            .any(|candidate| candidate.value == "pgcli"));
        let region = crate::model::Region {
            span: ByteRange::new(0, line.len()),
            ctx: crate::model::Context {
                path: Some("pgcli/main.py".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, line);
        let findings = detector.detect_findings(&view);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_name == "Password"),
            "candidates={:?}; findings={:?}",
            candidates
                .iter()
                .map(|candidate| (
                    candidate.value,
                    candidate.start,
                    candidate.end,
                    candidate.variable,
                    candidate.variable_start,
                    candidate.variable_end,
                    candidate.wrap
                ))
                .collect::<Vec<_>>(),
            findings
                .iter()
                .map(|finding| (
                    &finding.rule_name,
                    &finding.value,
                    finding.value_start,
                    finding.value_end
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn keyword_directive_probe_is_unicode_safe() {
        let keyword = FancyRegex::new("(?is:pass)").expect("keyword regex");
        assert!(keyword_directive_candidates("“password = secret-value", &keyword).is_empty());
    }

    #[test]
    fn keyword_quote_recovery_does_not_extend_empty_official_capture() {
        let raw = r#"            # ['''"password = 'sec;$2`\\'[\\/*;ret';";''', '''sec;$2`\\'[\\/*;ret'''],  # todo"#;
        let region = crate::model::Region {
            span: ByteRange::new(0, raw.len()),
            ctx: crate::model::Context {
                path: Some("test_keyword_pattern.py".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, raw);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_name != "Password"),
            "{findings:?}"
        );
    }

    #[test]
    fn percent_separator_preserves_official_variable_capture_range() {
        let raw =
            r#"            ("pw.html", b'user%3Dadmin;pw%3DjakC5df5G4WL;', "pw", "jakC5df5G4WL"),"#;
        let region = crate::model::Region {
            span: ByteRange::new(0, raw.len()),
            ctx: crate::model::Context {
                path: Some("test_app.py".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, raw);
        let finding = CredSweeperNativeDetector::builtin()
            .detect_findings(&view)
            .into_iter()
            .find(|finding| finding.rule_name == "Password" && finding.value == "jakC5df5G4WL")
            .expect("official password candidate");
        assert_eq!(Some("pw"), finding.variable.as_deref());
        assert_eq!(
            (Some(25), Some(41)),
            (finding.variable_start, finding.variable_end)
        );
    }

    #[test]
    fn line_prefilter_preserves_rule_order() {
        let rules = vec![
            test_native_rule("late", &["late"]),
            test_native_rule("always", &[]),
            test_native_rule("early", &["early"]),
        ];
        let prefilter = LineRulePrefilter::build(&rules).unwrap();
        let line_lower = LazyLower::new("early late");
        let mut seen_rules = vec![false; rules.len()];
        let mut candidates = Vec::new();

        prefilter.collect(&line_lower, &mut seen_rules, &mut candidates);

        assert_eq!(candidates, vec![0, 1, 2]);
    }

    fn test_native_rule(name: &str, required_substrings: &[&str]) -> NativeRule {
        NativeRule {
            rule_name: name.to_string(),
            label: normalize_label(name),
            severity: RuleSeverity::Medium,
            confidence: Confidence::Medium,
            min_line_len: 0,
            required_substrings: required_substrings.iter().map(|s| s.to_string()).collect(),
            filter_types: Vec::new(),
            targets: vec!["code".to_string()],
            ml_validated: false,
            patterns: vec![NativePattern {
                matcher: PatternMatcher::deferred("value"),
                value_capture: true,
            }],
        }
    }

    #[test]
    fn keyword_variables_are_sanitized_like_credsweeper_line_data() {
        let raw = "oauthClientSecret = \"6FF2FD0652DCD53EA929\"\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let findings = CredSweeperNativeDetector::builtin().detect_findings(&view);
        assert!(
            findings
                .iter()
                .any(|finding| finding.value == "6FF2FD0652DCD53EA929"
                    && finding.variable.as_deref() == Some("oauthClientSecret")),
            "{findings:?}"
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.variable.as_deref() == Some("oauthClientSecret ")));
    }

    #[test]
    fn keyword_values_are_sanitized_like_credsweeper_line_data() {
        let line = concat!(
            "final String responseBody = \"",
            "oauth_token=vt2q56n7zhfksqaw&oauth_token_secret=lghm7395e8t6yv01",
            "\";"
        );
        let variable_start = line.find("oauth_token").unwrap();
        let value_start = variable_start + "oauth_token=".len();
        let value_end = line.find("\";").unwrap();
        let candidate = Candidate {
            start: value_start,
            end: value_end,
            match_end: value_end,
            value: &line[value_start..value_end],
            variable_start: Some(variable_start),
            variable_end: Some(variable_start + "oauth_token".len()),
            variable: Some("oauth_token"),
            separator: Some("="),
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        };
        let sanitized = sanitize_value_capture(line, ".java", &candidate);
        assert_eq!("vt2q56n7zhfksqaw", sanitized.value);
        assert_eq!(value_start, sanitized.start);
        assert_eq!(value_start + sanitized.value.len(), sanitized.end);

        let url = concat!(
            "https://example.invalid/file?",
            "X-Amz-Credential=AKIACSVC3FV5KQHYWH8A%2F70855094%2Ffd-oiik-3",
            "&X-Amz-Signature=f4ea32fa4c9b3ca9ba96027c87d844c6152097b95e3f479c47054bfac1ce367f",
        );
        let variable_start = url.find("X-Amz-Credential").unwrap();
        let value_start = variable_start + "X-Amz-Credential=".len();
        let candidate = Candidate {
            start: value_start,
            end: url.len(),
            match_end: url.len(),
            value: &url[value_start..],
            variable_start: Some(variable_start),
            variable_end: Some(variable_start + "X-Amz-Credential".len()),
            variable: Some("X-Amz-Credential"),
            separator: Some("="),
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        };
        let sanitized = sanitize_value_capture(url, ".json", &candidate);
        assert_eq!(
            "AKIACSVC3FV5KQHYWH8A%2F70855094%2Ffd-oiik-3",
            sanitized.value
        );
    }

    #[test]
    fn escaped_closing_quote_prefix_is_not_part_of_unquoted_value() {
        let line = r#"X-Auth-Token: 785b0e8aabf9222712ee7fb471a26014d09b4a86\""#;
        let value_start = line.find("785b0e8a").unwrap();
        let candidate = Candidate {
            start: value_start,
            end: line.len() - 1,
            match_end: line.len() - 1,
            value: &line[value_start..line.len() - 1],
            variable_start: Some(0),
            variable_end: Some("X-Auth-Token".len()),
            variable: Some("X-Auth-Token"),
            separator: Some(":"),
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        };
        let sanitized = sanitize_value_capture(line, ".txt", &candidate);
        assert_eq!("785b0e8aabf9222712ee7fb471a26014d09b4a86", sanitized.value);
        assert_eq!(line.len() - 2, sanitized.end);
    }

    #[test]
    fn dictionary_repair_backtracks_like_keyword_pattern_minimum_value_length() {
        let short_key = r#"signingKey: {"kty":"oct","k":"long-secret-value"}"#;
        let start = short_key.find('"').unwrap();
        let end = short_key.rfind('}').unwrap();
        let mut candidate = Candidate {
            start,
            end,
            match_end: end,
            value: &short_key[start..end],
            variable_start: Some(0),
            variable_end: Some("signingKey".len()),
            variable: Some("signingKey"),
            separator: Some(":"),
            wrap: Some(" {"),
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        };
        repair_dictionary_key_value(&mut candidate);
        assert_eq!(&short_key[start..end], candidate.value);

        let long_key = r#"authn_state: {"authn_request_id":"secret-value"}"#;
        let start = long_key.find('"').unwrap();
        let end = long_key.rfind('}').unwrap();
        let mut candidate = Candidate {
            start,
            end,
            match_end: end,
            value: &long_key[start..end],
            variable_start: Some(0),
            variable_end: Some("authn_state".len()),
            variable: Some("authn_state"),
            separator: Some(":"),
            wrap: Some(" {"),
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        };
        repair_dictionary_key_value(&mut candidate);
        assert_eq!("authn_request_id", candidate.value);
    }

    #[test]
    fn translated_keyword_rules_do_not_mask_plain_prose() {
        let raw = "token budget and secret capability are API design notes\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let spans = CredSweeperNativeDetector::builtin().detect(&view);
        assert!(spans.is_empty(), "{spans:?}");
    }

    #[test]
    fn unicode_quote_sanitizer_handles_single_quote_value() {
        let single = "‘";
        let sanitized = sanitize_unicode_quotes(SanitizedValue {
            value: single,
            start: 0,
            end: single.len(),
        });
        assert_eq!("‘", sanitized.value);
        assert_eq!(0, sanitized.start);
        assert_eq!(single.len(), sanitized.end);

        let quoted = "‘secret’";
        let sanitized = sanitize_unicode_quotes(SanitizedValue {
            value: quoted,
            start: 0,
            end: quoted.len(),
        });
        assert_eq!("secret", sanitized.value);
        assert_eq!("‘".len(), sanitized.start);
        assert_eq!("‘secret".len(), sanitized.end);
    }

    #[test]
    fn keyword_prefilter_is_unicode_safe() {
        for raw in [
            "`login` и `password` необходимы для автоматического получения токена при помощи\n",
            "\"Enter the secret token (optional)\": \"ป้อนสัญลักษณ์ความลับ (เป็นตัวเลือก)\",\n",
            "注:`Client-Token`具有延迟作废特性,旧`Client-Token`不会立即过期\n",
        ] {
            let region = region(raw);
            let view = NormalizedView::build(&region, raw);
            let _ = CredSweeperNativeDetector::builtin().detect(&view);
        }
    }

    #[test]
    fn value_pattern_check_matches_upstream_examples() {
        for value in [
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526",
            "c0ffeecc-dead-beef-cafe-1a2b3c4d5e6f",
            "123456ff-dead-beef-cafe-7a24ca6a903c",
            "ffffff00-dead-beef-cafe-4a25c06a902d",
            "Crackle4444",
            "Crackle1234",
            "Crackle4321",
            "@$%",
            "a5",
            "_",
            "",
        ] {
            assert!(
                value_pattern_filtered(value, None),
                "expected filtered: {value:?}"
            );
        }
        for value in ["Crackle123", "IEEE32441", "Pass..."] {
            assert!(
                !value_pattern_filtered(value, None),
                "expected accepted: {value:?}"
            );
        }
        for value in ["11223344", "010101010", "40302010"] {
            assert!(
                value_pattern_filtered(value, Some(4)),
                "expected duple filter: {value:?}"
            );
        }
    }

    #[test]
    fn value_pattern_check_only_exempts_upstream_base64_fill_characters() {
        for value in ["AAAAAAAA", "////////", "________"] {
            assert!(
                !value_pattern_filtered(value, Some(8)),
                "expected accepted: {value:?}"
            );
        }
        assert!(value_pattern_filtered("��������", Some(8)));
    }

    #[test]
    fn uuid_rule_matches_official_github_request_ids() {
        for value in [
            "07f5721e-b221-8d07-d3c2-ee771b7275bc",
            "5dc3f631-8908-9127-9ce5-530060a551b8",
            "01f9504e-f228-4e00-d3a0-fc686a1322be",
            "51a4031d-c037-2b59-f6d3-ca160e0730df",
        ] {
            let raw = format!("x-github-request-id: {value}\n");
            let region = crate::model::Region {
                span: ByteRange::new(0, raw.len()),
                ctx: crate::model::Context {
                    path: Some("replay.txt".to_string()),
                    key: None,
                    hints: Vec::new(),
                    kind: crate::model::RegionKind::PlainText,
                    format: crate::model::Kind::Text,
                },
            };
            let view = NormalizedView::build(&region, &raw);
            assert!(
                CredSweeperNativeDetector::builtin()
                    .detect_findings(&view)
                    .iter()
                    .any(|finding| finding.rule_name == "UUID" && finding.value == value),
                "{value}"
            );
        }
    }

    #[test]
    fn uuid_rule_scans_official_request_id_beyond_a_hundred_kilobytes() {
        let value = "07f5721e-b221-8d07-d3c2-ee771b7275bc";
        let mut raw = "x".repeat(116_900);
        raw.push_str(" x-github-request-id: ");
        raw.push_str(value);
        raw.push('\n');
        let region = crate::model::Region {
            span: ByteRange::new(0, raw.len()),
            ctx: crate::model::Context {
                path: Some("replay.txt".to_string()),
                key: None,
                hints: Vec::new(),
                kind: crate::model::RegionKind::PlainText,
                format: crate::model::Kind::Text,
            },
        };
        let view = NormalizedView::build(&region, &raw);
        let detector = CredSweeperNativeDetector::builtin();
        let uuid_rule = detector
            .rules
            .iter()
            .find(|rule| rule.rule_name == "UUID")
            .expect("UUID rule");
        let PatternMatcher::Special(SpecialMatcher::Uuid) = &uuid_rule.patterns[0].matcher else {
            panic!("UUID must use the linear special matcher");
        };
        let candidates = uuid_candidates(raw.trim_end());
        assert!(
            candidates.iter().any(|candidate| candidate.value == value),
            "regex candidates: {}",
            candidates.len()
        );
        assert!(detector
            .detect_findings(&view)
            .iter()
            .any(|finding| finding.rule_name == "UUID" && finding.value == value));
    }

    #[test]
    fn filter_groups_expand_in_upstream_order() {
        assert_eq!(
            expand_filter_group("GeneralPattern"),
            ["LineSpecificKeyCheck", "ValuePatternCheck"]
        );
        assert_eq!(
            expand_filter_group("TokenPattern"),
            [
                "ValueMorphemesCheck",
                "ValueNumberCheck",
                "ValueCamelCaseCheck",
                "ValuePatternCheck",
            ]
        );
        assert_eq!(expand_filter_group("GeneralKeyword").len(), 15);
        assert_eq!(expand_filter_group("PasswordKeyword").len(), 18);
        assert_eq!(expand_filter_group("UrlCredentialsGroup").len(), 12);
        assert_eq!(
            expand_filter_group("WeirdBase36Token"),
            [
                "ValueMorphemesCheck(1)",
                "ValuePatternCheck",
                "ValueNumberCheck",
                "ValueTokenBase36Check",
                "ValueEntropyBase36Check",
            ]
        );
        assert_eq!(
            expand_filter_group("ValueGitHubCheck"),
            ["ValueGitHubCheck"]
        );
    }

    #[test]
    fn value_array_dictionary_check_matches_upstream_examples() {
        for value in [
            "values[k+1:j]",
            "values[i]",
            "values[145]",
            "values[token_id]",
        ] {
            let item = test_candidate(value, None, None, None);
            assert!(
                value_array_dictionary_filtered(value, &item, false),
                "{value:?}"
            );
        }
        for value in ["passwords['user1']", "passwords('user1')", "{'root'}"] {
            let item = test_candidate(value, None, Some("'"), Some("'"));
            assert!(
                !value_array_dictionary_filtered(value, &item, true),
                "{value:?}"
            );
        }
        let byte_wrap = test_candidate("values[i]", Some("byte["), None, None);
        assert!(!value_array_dictionary_filtered(
            "values[i]",
            &byte_wrap,
            false
        ));
        let array_wrap = test_candidate("root", Some("values["), None, None);
        assert!(value_array_dictionary_filtered("root", &array_wrap, false));
        let call_wrap = test_candidate("root", Some("values("), None, None);
        assert!(value_array_dictionary_filtered("root", &call_wrap, false));
    }

    #[test]
    fn value_hex_number_check_matches_upstream_examples_and_boundaries() {
        for value in ["0xaBcd1234", "0xAbCd098765432137", "0x0", "0XfF"] {
            assert!(value_hex_number_filtered(value), "{value:?}");
        }
        for value in [
            "0xabcdI234",
            "0xabcd0987654321371",
            "abcd1234",
            "0x",
            "-0x1",
        ] {
            assert!(!value_hex_number_filtered(value), "{value:?}");
        }
    }

    #[test]
    fn value_last_word_check_matches_upstream_boundaries() {
        let short = test_candidate("value:", None, None, None);
        assert!(value_last_word_filtered(short.value, false));

        let quoted = test_candidate("value:", None, Some("\""), Some("\""));
        assert!(!value_last_word_filtered(quoted.value, true));

        let fifteen = test_candidate("12345678901234:", None, None, None);
        assert!(value_last_word_filtered(fifteen.value, false));
        let sixteen = test_candidate("123456789012345:", None, None, None);
        assert!(!value_last_word_filtered(sixteen.value, false));

        let unicode = test_candidate("秘密:", None, None, None);
        assert!(value_last_word_filtered(unicode.value, false));
    }

    #[test]
    fn value_length_check_matches_upstream_inclusive_character_bounds() {
        assert!(value_length_filtered("Cra", 4, 42));
        assert!(!value_length_filtered("Crackle", 4, 42));
        assert!(value_length_filtered(
            "CrackleCrackleCrackleCrackleCrackleCrackle123",
            4,
            42
        ));
        assert!(!value_length_filtered("秘密情報", 4, 4));
        assert!(value_length_filtered("秘密情報", 5, 8));
        assert_eq!(
            parse_filter_length_range("ValueLengthCheck(4,64)"),
            Some((4, 64))
        );
        assert_eq!(parse_filter_length_range("ValueLengthCheck(4)"), None);
    }

    #[test]
    fn value_method_check_matches_upstream_examples() {
        for value in ["Crac.method()", "Crac_function", "object->method(arg)"] {
            assert!(value_method_filtered(value, false), "{value:?}");
        }
        for value in ["CracFunction", "method(", " method()"] {
            assert!(!value_method_filtered(value, false), "{value:?}");
        }
        let quoted = test_candidate("Crac.method()", None, Some("\""), Some("\""));
        assert!(!value_method_filtered(quoted.value, true));
    }

    #[test]
    fn value_not_allowed_pattern_check_matches_upstream_examples() {
        for value in ["[{ ", "\\n", "\t\t\t\\", "\t \\n\t \t", "\\u003cgt;"] {
            assert!(
                value_not_allowed_pattern_filtered(value, false),
                "{value:?}"
            );
        }
        for value in ["secret", "[{x", "line\n"] {
            assert!(
                !value_not_allowed_pattern_filtered(value, false),
                "{value:?}"
            );
        }
        let quoted = test_candidate("\\n", None, Some("\""), Some("\""));
        assert!(!value_not_allowed_pattern_filtered(quoted.value, true));
    }

    #[test]
    fn value_similarity_check_matches_upstream_examples() {
        for (variable, value) in [
            ("password", "password1"),
            ("password", "password123"),
            ("pwd", "PWD"),
            ("password", "password=`$vc1rQ5eBW*S`"),
        ] {
            assert!(
                value_similarity_filtered(value, Some(variable)),
                "{variable:?} {value:?}"
            );
        }
        assert!(!value_similarity_filtered(
            "unrelated-secret",
            Some("password")
        ));
        assert!(!value_similarity_filtered("secret", None));
    }

    #[test]
    fn sequence_matcher_ratio_matches_python_reference_vectors() {
        for (a, b, expected) in [
            ("password", "password1", 0.941_176_470_588_235_3),
            ("password", "password123", 0.842_105_263_157_894_7),
            ("abcd", "abxcd", 0.888_888_888_888_888_8),
            ("tide", "diet", 0.25),
        ] {
            assert!((sequence_matcher_ratio(a, b) - expected).abs() < f64::EPSILON);
        }
        let a = format!("{}b", "a".repeat(210));
        let b = format!("{}c", "a".repeat(210));
        assert!((sequence_matcher_ratio(&a, &b) - 0.995_260_663_507_109).abs() < f64::EPSILON);
    }

    #[test]
    fn value_token_check_matches_upstream_split_semantics() {
        for value in ["Crac>crackle1", "my<password", "my)password", "鍵 秘密"] {
            assert!(value_token_filtered(value, false), "{value:?}");
        }
        for value in [
            "Crackle>secret",
            "password",
            "my - password",
            "words password",
        ] {
            assert!(!value_token_filtered(value, false), "{value:?}");
        }
        let quoted = test_candidate("my<password", None, Some("\""), Some("\""));
        assert!(!value_token_filtered(quoted.value, true));
    }

    #[test]
    fn value_string_type_check_matches_upstream_source_literal_rules() {
        let mut plain = test_candidate("DEAD314BEEF0CAFE", None, None, None);
        plain.variable_start = Some(0);
        plain.variable_end = Some(4);
        plain.variable = Some("pass");
        plain.separator = Some(" = ");
        let source = test_line_context("pass = DEAD314BEEF0CAFE", ".py");
        assert!(value_string_type_filtered(plain.value, &plain, &source));

        let mut numeric = test_candidate("314DEADBEEF0CAFE", None, None, None);
        numeric.separator = Some(" = ");
        assert!(!value_string_type_filtered(
            numeric.value,
            &numeric,
            &source
        ));

        let text = test_line_context("pass = DEAD314BEEF0CAFE", ".txt");
        assert!(!value_string_type_filtered(plain.value, &plain, &text));
        let comment = test_line_context("// pass = DEAD314BEEF0CAFE", ".cpp");
        assert!(!value_string_type_filtered(plain.value, &plain, &comment));

        let mut quoted = test_candidate("DEAD314BEEF0CAFE", None, Some("\""), Some("\""));
        quoted.separator = Some(" = ");
        assert!(!value_string_type_filtered(quoted.value, &quoted, &source));

        let mut bytes = test_candidate("0xae, 0x54, 0x55, 0xff", None, None, None);
        bytes.separator = Some(" = ");
        assert!(!value_string_type_filtered(bytes.value, &bytes, &source));
    }

    #[test]
    fn value_string_type_check_preserves_url_values() {
        let line = "url = https://example.invalid?password=DEAD314BEEF0CAFE";
        let value_start = line.find("DEAD").unwrap();
        let mut candidate = test_candidate(&line[value_start..], None, None, None);
        candidate.start = value_start;
        candidate.end = line.len();
        candidate.variable_start = Some(line.find("password").unwrap());
        candidate.variable_end = Some(line.find("password").unwrap() + "password".len());
        candidate.variable = Some("password");
        candidate.separator = Some("=");
        let source = test_line_context(line, ".py");
        assert!(candidate_url_part(&candidate, line));
        assert!(!value_string_type_filtered(
            candidate.value,
            &candidate,
            &source
        ));
    }

    #[test]
    fn value_split_keyword_check_matches_upstream_whitespace_rules() {
        for value in ["abstract and so on", "Any dummy lines", "unique string"] {
            assert!(value_split_keyword_filtered(value), "{value:?}");
        }
        for value in ["abstract,and_so_on", "ani dammi lwnes", "unique#string"] {
            assert!(!value_split_keyword_filtered(value), "{value:?}");
        }
        assert!(value_split_keyword_filtered("prefix\tabstract\nsuffix"));
    }

    #[test]
    fn value_entropy_base32_check_matches_upstream_examples_and_boundaries() {
        assert!(!entropy_base32_filtered("WXFES7QNTET5DQYC"));
        assert!(entropy_base32_filtered("200X300X4000X123"));
        assert!(entropy_base32_filtered("ABCDEF7"));
        for len in [8, 16, 17, 32, 33] {
            let value = (0..len)
                .map(|index| char::from(b'A' + (index % 26) as u8))
                .collect::<String>();
            let _ = entropy_base32_filtered(&value);
        }
    }

    #[test]
    fn value_base32_data_check_matches_upstream_examples() {
        for value in [
            "SUAML2GCZ7IK7E7UD4VZ7ELPZW7DK2ZNL35WSMW3IORHC3BWBSDQXUQRBU",
            "WXFES7QNTET5DQYC",
        ] {
            assert!(!value_base32_data_filtered(value), "{value:?}");
        }
        for value in [
            "PMRGSZBCHIYTEM35",
            "ABCDEFGHIJKLMNOP",
            "5555555555555555",
            "GAYDAMBQGAYDAMBQ",
            "invalid1!",
        ] {
            assert!(value_base32_data_filtered(value), "{value:?}");
        }
    }

    #[test]
    fn minimum_data_entropy_matches_upstream_fixed_points() {
        for (len, expected) in [
            (16, 1.669_736_717_803_48),
            (20, 2.077_235_445_408_31),
            (32, 3.253_928_031_846_02),
            (40, 3.648_535_670_648_67),
            (64, 4.577_569_336_880_35),
            (384, 7.39),
            (512, 7.55),
        ] {
            assert_eq!(minimum_data_entropy(len), expected);
        }
        assert_eq!(minimum_data_entropy(8), 0.0);
    }

    #[test]
    fn value_token_base32_check_matches_upstream_examples() {
        for value in ["4K26IPW7VBHMFT4D", "NAQ4BVWT", "WXFES7QNTET5DQYC"] {
            assert!(
                !value_token_base_filtered(value, TokenBase::Base32),
                "{value:?}"
            );
        }
        for value in ["OOOOOOMMMMMMMMMM", "1MZ0A9L2", "QAZXSWEDCVFRTGBN"] {
            assert!(
                value_token_base_filtered(value, TokenBase::Base32),
                "{value:?}"
            );
        }
    }

    #[test]
    fn value_token_base36_check_matches_upstream_examples() {
        for value in [
            "jvzec4y51fkrrd39czz1nfbw",
            "nf6lqy74gp53f7w08gn4l0vrk",
            "wpv1jq9xwanbn3n",
            "123456789",
        ] {
            assert!(
                !value_token_base_filtered(value, TokenBase::Base36),
                "{value:?}"
            );
        }
        for value in [
            "100x200x300x400",
            "qwertyui",
            "0o9i8u7y6t5r4e3",
            "0k9j8h7g6f5d4s3a",
            "gfkjjhgy7r457y54jfhhgvcnf",
        ] {
            assert!(
                value_token_base_filtered(value, TokenBase::Base36),
                "{value:?}"
            );
        }
    }

    #[test]
    fn value_bech32_check_matches_python_library_behavior() {
        for value in [
            "bc1qpzry6fjyzh",
            "secret1lq8verf5x28p2",
            "SeCrEt1LQ8vErF5x28P2",
        ] {
            assert!(!value_bech32_filtered(value), "{value:?}");
        }
        for value in [
            "secret1lq8verf5x28p3",
            "A12UEL5L",
            "no-separator",
            "bc1qpzry6fjyzh ",
        ] {
            assert!(value_bech32_filtered(value), "{value:?}");
        }
    }

    #[test]
    fn value_json_web_key_check_matches_upstream_examples() {
        for value in [
            "eyJrdHkiOiAib2N0IiwiayI6ICJXck13UWZvTmFIVGdYVTVmWnZSR0FEIn0=",
            "eyJrdHkiOiJSU0EiLCJkIjoiYWJjIn0=",
        ] {
            assert!(!value_json_web_key_filtered(value), "{value:?}");
        }
        for value in [
            ".",
            "eyJungle",
            "eyJrdHkiOiAib2N0IiwieCI6ICJXck13UWZvTmFIVGdYVTVmWnZSR0FEIn0=",
        ] {
            assert!(value_json_web_key_filtered(value), "{value:?}");
        }
    }

    #[test]
    fn value_json_web_token_check_matches_upstream_examples() {
        let valid = concat!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            ".e30.GFsFyGiCUIP5VHI9CEJL9thWsGjSZf1fJfarNk-LGTM"
        );
        assert!(!value_json_web_token_filtered(valid));
        for value in [
            ".",
            "eyJungle",
            "1234567890qwertyuiopasdfghjklzxc",
            "eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.eyJleHAiOjY1NTM2fQo",
            "eyJhbGciOiJSUzI1NiJ9Cg.eyJleHAiOjY1NTM2fQo.AAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(value_json_web_token_filtered(value), "{value:?}");
        }
    }

    #[test]
    fn line_git_binary_check_matches_upstream_examples() {
        for line in [
            "zxNdj)EYlS}b8JGyg7Pw=wujtWvwg9)mv+;vvr}dADtX-(^(6N+C(YT)lWLG7tdu$7",
            "HcmV?d00001",
            "  HcmV?d00001  ",
        ] {
            assert!(line_git_binary_filtered(line), "{line:?}");
        }
        for line in [
            r#"{"test":1,"pw":"sn2e8dgWwW","payload":"EYlS}b+C(YT)lWLGxNdj7Pw=w"}"#,
            "XcmV?d00001",
            "HcmV?d0000/",
            "DY8Vzw",
        ] {
            assert!(!line_git_binary_filtered(line), "{line:?}");
        }
    }

    #[test]
    fn line_uue_part_check_matches_upstream_adjacent_line_requirement() {
        let line = r#"M[@%]PW:2Z.Q?2M^S;`4G?E0C.@V&?0KY]]"H3Y@6$#I4V*R^"+B,2P6`A)UL"#;
        assert_eq!(line.len(), 61);
        assert!(!line_uue_part_filtered(line, None, None));
        assert!(line_uue_part_filtered(line, None, Some(line)));
        assert!(line_uue_part_filtered(line, Some(line), None));
        assert!(!line_uue_part_filtered(
            line,
            Some("begin 644 x3wo.bin"),
            Some("#````")
        ));
        assert!(!line_uue_part_filtered("#````", Some("#````"), None));
        assert!(line_uue_part_filtered("", None, None));

        let invalid = r#"M[@%]PW:2Z.Q?2M^S;`4G?E0C.@V&?0KY]]"H3Y@6$#I4V*R^"D+lowercase"#;
        assert!(!line_uue_part_filtered(
            invalid,
            Some(invalid),
            Some(invalid)
        ));
    }

    fn test_candidate<'a>(
        value: &'a str,
        wrap: Option<&'a str>,
        left: Option<&'a str>,
        right: Option<&'a str>,
    ) -> Candidate<'a> {
        Candidate {
            start: 0,
            end: value.len(),
            match_end: value.len(),
            value,
            variable_start: None,
            variable_end: None,
            variable: None,
            separator: None,
            wrap,
            value_leftquote: left,
            value_rightquote: right,
            line_data: Vec::new(),
        }
    }

    fn test_line_context<'a>(line: &'a str, file_type: &'a str) -> CandidateLineContext<'a> {
        CandidateLineContext {
            start: 0,
            line,
            previous: None,
            next: None,
            file_type,
            target: line,
            line_index: 0,
        }
    }

    #[test]
    fn labels_are_upper_snake() {
        assert_eq!(normalize_label("Slack Token"), "SLACK_TOKEN");
        assert_eq!(normalize_label("OTP / 2FA Secret"), "OTP_2FA_SECRET");
    }
}
