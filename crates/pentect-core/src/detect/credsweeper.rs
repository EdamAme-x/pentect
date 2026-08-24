use super::credsweeper_ml::{self, MlInput, RuleSeverity};
use super::Detector;
use crate::model::{ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use data_encoding::{BASE32, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};
use fancy_regex::Regex as FancyRegex;
use regex::Regex as RustRegex;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
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

#[derive(Clone, Debug)]
pub struct CredSweeperNativeFinding {
    pub range: ByteRange,
    pub rule_name: String,
    pub label: String,
    pub severity: String,
    pub confidence: Confidence,
    pub confidence_name: String,
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
    compiled: OnceLock<Option<CompiledRegex>>,
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
}

impl CredSweeperNativeDetector {
    pub fn builtin() -> Self {
        BUILTIN.clone()
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
                        matcher: PatternMatcher::deferred(keyword_pattern(value)),
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
    if bytes.len() > 66 || bytes.len() < 6 || !(bytes.len() - 1).is_multiple_of(5) {
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
            | "ValueBase32DataCheck"
            | "ValueBech32Check"
            | "ValueBasicAuthCheck"
            | "ValueBlocklistCheck"
            | "ValueCamelCaseCheck"
            | "ValueDictionaryKeywordCheck"
            | "ValueEntropyBase36Check"
            | "ValueEntropyBase32Check"
            | "ValueEntropyBase64Check"
            | "ValueFilePathCheck"
            | "ValueHexNumberCheck"
            | "ValueLastWordCheck"
            | "ValueLengthCheck"
            | "ValueMethodCheck"
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
        };
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
                        push_match(
                            &mut out,
                            &mut ml_pending,
                            &push_ctx,
                            rule,
                            &whole_text_ctx,
                            &candidate,
                        );
                    }
                }
            }
        }
        let lines = LineRanges::new(text).collect::<Vec<_>>();
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
                            for candidate in regex.find(line_body, pattern.value_capture) {
                                push_match(
                                    &mut out,
                                    &mut ml_pending,
                                    &push_ctx,
                                    rule,
                                    &line_ctx,
                                    &candidate,
                                );
                            }
                        }
                        PatternMatcher::Special(matcher) => {
                            for m in matcher.find(line_body) {
                                push_match(
                                    &mut out,
                                    &mut ml_pending,
                                    &push_ctx,
                                    rule,
                                    &line_ctx,
                                    &m,
                                );
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
            compiled: OnceLock::new(),
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
        match self.compiled() {
            Some(CompiledRegex::Rust(regex)) => regex
                .captures_iter(text)
                .filter_map(|captures| rust_candidate(&captures, value_capture))
                .collect(),
            Some(CompiledRegex::Fancy(regex)) => regex
                .captures_iter(text)
                .filter_map(Result::ok)
                .filter_map(|captures| fancy_candidate(&captures, value_capture))
                .collect(),
            None => Vec::new(),
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

struct Candidate<'a> {
    start: usize,
    end: usize,
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
        _ => None,
    }
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
            compiled: OnceLock::from(Some(CompiledRegex::Rust(regex))),
        }))),
        Err(_) => FancyRegex::new(pattern)
            .map(|regex| {
                PatternMatcher::Deferred(Arc::new(DeferredRegex {
                    source: pattern.to_string(),
                    compiled: OnceLock::from(Some(CompiledRegex::Fancy(regex))),
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
            let local_end = anchor.end - line_start;
            !line
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
            let local_end = anchor.end - line_start;
            !line
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
        |_, _, _| true,
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
    if value.contains("PRIVATE") && !value.contains("ENCRYPTED") {
        vec![Candidate {
            start: begin,
            end,
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
        if !header.contains("PRIVATE") || header.contains("ENCRYPTED") || !header.contains("KEY") {
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
            out.push(Candidate {
                start: begin,
                end,
                value: block,
                variable_start: None,
                variable_end: None,
                variable: None,
                separator: None,
                wrap: None,
                value_leftquote: None,
                value_rightquote: None,
                line_data: Vec::new(),
            });
        }
        search_start = end;
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
    for line in text.lines() {
        let line = sanitize_pem_line(line, 5);
        if line.is_empty()
            || line.contains("-----BEGIN")
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
    saw_end && decodes_as_pem_payload(&key_data)
}

fn sanitize_pem_line(line: &str, recurse: usize) -> String {
    if recurse == 0 {
        return line.to_string();
    }
    let mut line = line.trim().to_string();
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

fn decodes_as_pem_payload(value: &str) -> bool {
    if value.len() < 64 {
        return false;
    }
    let padded = match value.len() % 4 {
        0 => Cow::Borrowed(value),
        2 => Cow::Owned(format!("{value}==")),
        3 => Cow::Owned(format!("{value}=")),
        _ => return false,
    };
    BASE64
        .decode(padded.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(value.trim_end_matches('=').as_bytes()))
        .map_or_else(
            |_| shannon_entropy(value) >= 3.5,
            |decoded| decoded.len() > 32,
        )
}

fn is_pem_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn base64_private_key_candidates(line: &str) -> Vec<Candidate<'_>> {
    token_runs(line)
        .filter(|run| {
            run.value.len() >= 160
                && run.value.starts_with("MII")
                && is_base64ish(run.value)
                && run.value.chars().all(|ch| {
                    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_')
                })
        })
        .collect()
}

fn clamp_to_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn token_runs(line: &str) -> impl Iterator<Item = Candidate<'_>> {
    let mut runs = Vec::new();
    let mut start = None;
    for (idx, ch) in line.char_indices() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '/' | '=' | '.') {
            start.get_or_insert(idx);
        } else if let Some(s) = start.take() {
            runs.push(Candidate {
                start: s,
                end: idx,
                value: &line[s..idx],
                variable_start: None,
                variable_end: None,
                variable: None,
                separator: None,
                wrap: None,
                value_leftquote: None,
                value_rightquote: None,
                line_data: Vec::new(),
            });
        }
    }
    if let Some(s) = start {
        runs.push(Candidate {
            start: s,
            end: line.len(),
            value: &line[s..],
            variable_start: None,
            variable_end: None,
            variable: None,
            separator: None,
            wrap: None,
            value_leftquote: None,
            value_rightquote: None,
            line_data: Vec::new(),
        });
    }
    runs.into_iter()
}

struct PendingMlFinding {
    finding: CredSweeperNativeFinding,
    input: MlInput,
}

struct PushMatchCtx<'view, 'data> {
    view: &'view NormalizedView<'view>,
    path: &'data str,
    file_type: &'data str,
}

struct CandidateLineContext<'a> {
    start: usize,
    line: &'a str,
    previous: Option<&'a str>,
    next: Option<&'a str>,
    file_type: &'a str,
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
    out: &mut Vec<CredSweeperNativeFinding>,
    ml_pending: &mut Vec<PendingMlFinding>,
    ctx: &PushMatchCtx<'_, '_>,
    rule: &NativeRule,
    line_ctx: &CandidateLineContext<'_>,
    candidate: &Candidate<'_>,
) {
    let sanitized_value = sanitize_value_capture(line_ctx.line, ctx.file_type, candidate);
    let range = ctx.view.to_raw(ByteRange::new(
        line_ctx.start + sanitized_value.start,
        line_ctx.start + sanitized_value.end,
    ));
    if range.is_empty() {
        return;
    }
    if !accept_value(
        sanitized_value.value,
        rule,
        candidate,
        line_ctx,
        sanitized_value.start,
        sanitized_value.end,
    ) {
        return;
    }
    let sanitized_variable = candidate
        .variable
        .zip(candidate.variable_start.zip(candidate.variable_end))
        .and_then(|(variable, (start, end))| {
            sanitize_variable_capture(line_ctx.line, variable, start, end)
        });
    let finding = CredSweeperNativeFinding {
        range,
        rule_name: rule.rule_name.clone(),
        label: rule.label.clone(),
        severity: severity_name(rule.severity).to_string(),
        confidence: rule.confidence,
        confidence_name: confidence_name(rule.confidence).to_string(),
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
                range: ctx.view.to_raw(ByteRange::new(
                    line_ctx.start + line_data.start,
                    line_ctx.start + line_data.end,
                )),
                value: line_data.value.to_string(),
                value_start: line_data.start,
                value_end: line_data.end,
                variable: line_data.variable.map(str::to_string),
                variable_start: line_data.variable_start,
                variable_end: line_data.variable_end,
            })
            .collect(),
    };
    if rule.ml_validated {
        let variable = sanitized_variable
            .as_ref()
            .map(|(variable, _, _)| variable.as_str())
            .unwrap_or_default();
        ml_pending.push(PendingMlFinding {
            finding,
            input: MlInput {
                line: line_ctx.line.to_string(),
                value: sanitized_value.value.to_string(),
                variable: variable.to_string(),
                value_start: sanitized_value.start,
                value_end: sanitized_value.end,
                variable_start: sanitized_variable
                    .as_ref()
                    .map(|(_, start, _)| *start as isize)
                    .unwrap_or(-2),
                variable_end: sanitized_variable
                    .as_ref()
                    .map(|(_, _, end)| *end as isize)
                    .unwrap_or(-2),
                path: ctx.path.to_string(),
                file_type: ctx.file_type.to_string(),
                rule_name: rule.rule_name.clone(),
                severity: rule.severity,
            },
        });
    } else {
        out.push(finding);
    }
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
        if credsweeper_ml::accept_group(&group_inputs) {
            for idx in group_indices {
                out.push(pending[idx].finding.clone());
            }
        }
    }
}

fn same_ml_group(a: &MlInput, b: &MlInput) -> bool {
    a.path == b.path
        && a.line == b.line
        && a.value == b.value
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
    let line = line_ctx.line;
    let value = value.trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == '`');
    if value.len() < 4 || is_obvious_placeholder(value) || is_repeated_symbol(value) {
        return false;
    }
    for filter in &rule.filter_types {
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
            && value_allowlist_filtered(value, candidate_is_well_quoted(candidate))
        {
            return false;
        }
        if filter == "ValueArrayDictionaryCheck"
            && value_array_dictionary_filtered(value, candidate)
        {
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
        if filter == "ValueHexNumberCheck" && value_hex_number_filtered(value) {
            return false;
        }
        if filter == "ValueLastWordCheck" && value_last_word_filtered(value, candidate) {
            return false;
        }
        if filter.starts_with("ValueLengthCheck") {
            let (min_len, max_len) = parse_filter_length_range(filter).unwrap_or((4, 8000));
            if value_length_filtered(value, min_len, max_len) {
                return false;
            }
        }
        if filter == "ValueMethodCheck" && value_method_filtered(value, candidate) {
            return false;
        }
        if filter == "ValueNotAllowedPatternCheck"
            && value_not_allowed_pattern_filtered(value, candidate)
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
        if filter == "ValueTokenCheck" && value_token_filtered(value, candidate) {
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
        if filter == "ValueCamelCaseCheck"
            && camel_case_filtered(value, candidate_is_well_quoted(candidate))
        {
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
        if filter == "ValueSealedSecretCheck" && value_sealed_secret_filtered(value, "") {
            return false;
        }
    }
    if rule
        .filter_types
        .iter()
        .any(|filter| filter.contains("ValueFilePathCheck"))
        && looks_like_file_path(value)
    {
        return false;
    }
    true
}

fn candidate_is_well_quoted(candidate: &Candidate<'_>) -> bool {
    matches!(
        (candidate.value_leftquote, candidate.value_rightquote),
        (Some(left), Some(right)) if left == right
    )
}

fn value_array_dictionary_filtered(value: &str, candidate: &Candidate<'_>) -> bool {
    if candidate_is_well_quoted(candidate) {
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
    BASE32
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

fn value_allowlist_filtered(value: &str, is_well_quoted: bool) -> bool {
    // Mirrors CredSweeper ValueAllowlistCheck: these are syntax/template
    // expressions, not credential material.
    if value_allowlist_common_patterns()
        .iter()
        .any(|pattern| pattern.is_match(value))
    {
        return true;
    }
    let patterns = if is_well_quoted {
        value_allowlist_quoted_patterns()
    } else {
        value_allowlist_unquoted_patterns()
    };
    patterns.iter().any(|pattern| pattern.is_match(value))
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
            r"(?i)^.*@@@hl@@@.*@@@endhl@@@",
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
            r"(?i)^.*\*\*\*\*",
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
            r"(?i)^.*\*\*\*\*\*\*",
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

fn value_last_word_filtered(value: &str, candidate: &Candidate<'_>) -> bool {
    value.chars().count() < 16 && !candidate_is_well_quoted(candidate) && value.ends_with(':')
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

fn value_method_filtered(value: &str, candidate: &Candidate<'_>) -> bool {
    if candidate_is_well_quoted(candidate) {
        return false;
    }
    static METHOD: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"^[~.\->:0-9A-Za-z_]+\(.*\)").expect("CredSweeper method-call regex")
    });
    value.contains("function") || METHOD.is_match(value)
}

fn value_not_allowed_pattern_filtered(value: &str, candidate: &Candidate<'_>) -> bool {
    if candidate_is_well_quoted(candidate) {
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

fn value_token_filtered(value: &str, candidate: &Candidate<'_>) -> bool {
    if candidate_is_well_quoted(candidate) {
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
            && 0 < index
            && index + 1 < chars.len()
            && python_word_char(chars[index - 1])
            && python_word_char(chars[index + 1])
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
    let threshold = threshold
        .unwrap_or_else(|| value.len().ilog2() as usize + 1)
        .saturating_sub(4)
        .max(1);
    morphemes_filtered_with_threshold(value, threshold)
}

fn morphemes_filtered_with_threshold(value: &str, threshold: usize) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut matches = 0usize;
    for morpheme in MORPHEME_CHECKLIST.split_whitespace() {
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
    if 2 * threshold <= value_len && duple_pattern_filtered(value, threshold) {
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
        if pair[0] == pair[1] && !(ignore_base64_a_slash && matches!(pair[0], 'A' | '/' | '_')) {
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

fn duple_pattern_filtered(value: &str, threshold: usize) -> bool {
    let even = value
        .chars()
        .enumerate()
        .filter_map(|(idx, ch)| (idx % 2 == 0).then_some(ch))
        .collect::<String>();
    if !repeated_or_sequence_pattern(&even, threshold, false) {
        return false;
    }
    let odd = value
        .chars()
        .enumerate()
        .filter_map(|(idx, ch)| (idx % 2 == 1).then_some(ch))
        .collect::<String>();
    repeated_or_sequence_pattern(&odd, threshold, false)
}

fn entropy_base36_filtered(value: &str) -> bool {
    let min = match value.len() {
        15 => 3.374,
        10..=25 => 0.731_566_857 * (value.len() as f64).log2() + 0.474_132,
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

fn entropy_base64_filtered(value: &str) -> bool {
    let len = value.len();
    let min = match len {
        12..=17 => 0.915 * (len as f64).log2() - 0.047,
        18..=34 => 0.767 * (len as f64).log2() + 0.5677,
        35..=64 => 0.944 * (len as f64).log2() - 0.009 * len as f64 - 0.04,
        65..=255 => 0.621 * (len as f64).log2() - 0.003 * len as f64 + 1.54,
        256.. => 6.0 - 64.0 / len as f64,
        _ => 0.0,
    };
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

fn value_sealed_secret_filtered(value: &str, context: &str) -> bool {
    let sealed_shape = (value.starts_with("Ag") && value.len() > 700)
        || (value.starts_with("AQ") && value.len() > 350);
    sealed_shape
        && value
            .as_bytes()
            .get(2)
            .is_some_and(|b| (b'A'..=b'D').contains(b))
        && context.contains("SealedSecret")
        && context.contains("encryptedData")
        && context.contains("bitnami")
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

fn is_base64ish(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
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

fn is_obvious_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("example")
        || lower.contains("changeme")
        || lower.contains("dummy")
        || lower.contains("placeholder")
        || lower.contains("<secret")
        || lower.contains("<token")
        || lower.contains("your_")
        || lower.contains("your-")
}

fn is_repeated_symbol(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    chars.all(|ch| ch == first)
}

fn looks_like_file_path(value: &str) -> bool {
    if value.contains("://") {
        return false;
    }
    let slash_count = value.matches('/').count() + value.matches('\\').count();
    slash_count >= 2
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
        || value.contains(":\\")
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
        assert!(stats.unsupported_filter_invocations > 0, "{stats:?}");
        assert_eq!(stats.unsupported_filter_types.len(), 13, "{stats:?}");
        assert!(
            stats
                .unsupported_filter_types
                .contains(&"ValueJsonWebTokenCheck".to_string()),
            "{stats:?}"
        );
    }

    #[test]
    fn alibaba_multi_reports_the_secret_paired_with_an_access_key_id() {
        let raw = concat!(
            "access_key_id = LTAI1234567890ABCDEF\n",
            "access_key_secret = AbCdEfGhIjKlMnOpQrStUvWxYz1234\n",
        );
        let candidates = alibaba_multi_candidates(raw);

        assert!(candidates.iter().any(|candidate| {
            candidate.value == "AbCdEfGhIjKlMnOpQrStUvWxYz1234"
                && candidate
                    .line_data
                    .iter()
                    .any(|part| part.value == "LTAI1234567890ABCDEF")
        }));
    }

    #[test]
    fn embedded_ml_feature_vector_matches_model() {
        assert!(credsweeper_ml::feature_width_matches_model_for_test());
    }

    #[test]
    fn value_allowlist_matches_credsweeper_code_expressions() {
        assert!(value_allowlist_filtered(
            "xmlKey->NextSiblingElement();",
            false
        ));
        assert!(value_allowlist_filtered("config.secret.value()", false));
        assert!(value_allowlist_filtered("${SECRET_NAME}", false));
        assert!(!value_allowlist_filtered(
            "opaqueCredentialValue1234567890",
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
        let aws_id = ["AKIA", "ABCDEFGHIJKLMNOP"].concat();
        let aws_secret = "mQ7zR2pL8vN4xY6cT9bH3sK5dF1gJ0aW2eU4rI6o".to_string();
        let google_secret = format!("GOCSPX-{}", "A".repeat(28));
        let jwk_secret = concat!(
            "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn5oZE5uSCI",
            "wg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3izlbkosrzjHajIcY33HBh",
        );
        let base64_key = format!("MII{}", "A".repeat(180));
        let raw = format!(
            "aws {aws_id} {aws_secret}\n\
             google 123-abcdeabcdeabcdeabcdeabcdeabcdeab.apps.googleusercontent.com {google_secret}\n\
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
            assert!(value_array_dictionary_filtered(value, &item), "{value:?}");
        }
        for value in ["passwords['user1']", "passwords('user1')", "{'root'}"] {
            let item = test_candidate(value, None, Some("'"), Some("'"));
            assert!(!value_array_dictionary_filtered(value, &item), "{value:?}");
        }
        let byte_wrap = test_candidate("values[i]", Some("byte["), None, None);
        assert!(!value_array_dictionary_filtered("values[i]", &byte_wrap));
        let array_wrap = test_candidate("root", Some("values["), None, None);
        assert!(value_array_dictionary_filtered("root", &array_wrap));
        let call_wrap = test_candidate("root", Some("values("), None, None);
        assert!(value_array_dictionary_filtered("root", &call_wrap));
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
        assert!(value_last_word_filtered(short.value, &short));

        let quoted = test_candidate("value:", None, Some("\""), Some("\""));
        assert!(!value_last_word_filtered(quoted.value, &quoted));

        let fifteen = test_candidate("12345678901234:", None, None, None);
        assert!(value_last_word_filtered(fifteen.value, &fifteen));
        let sixteen = test_candidate("123456789012345:", None, None, None);
        assert!(!value_last_word_filtered(sixteen.value, &sixteen));

        let unicode = test_candidate("秘密:", None, None, None);
        assert!(value_last_word_filtered(unicode.value, &unicode));
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
            let item = test_candidate(value, None, None, None);
            assert!(value_method_filtered(value, &item), "{value:?}");
        }
        for value in ["CracFunction", "method(", " method()"] {
            let item = test_candidate(value, None, None, None);
            assert!(!value_method_filtered(value, &item), "{value:?}");
        }
        let quoted = test_candidate("Crac.method()", None, Some("\""), Some("\""));
        assert!(!value_method_filtered(quoted.value, &quoted));
    }

    #[test]
    fn value_not_allowed_pattern_check_matches_upstream_examples() {
        for value in ["[{ ", "\\n", "\t\t\t\\", "\t \\n\t \t", "\\u003cgt;"] {
            let item = test_candidate(value, None, None, None);
            assert!(
                value_not_allowed_pattern_filtered(value, &item),
                "{value:?}"
            );
        }
        for value in ["secret", "[{x", "line\n"] {
            let item = test_candidate(value, None, None, None);
            assert!(
                !value_not_allowed_pattern_filtered(value, &item),
                "{value:?}"
            );
        }
        let quoted = test_candidate("\\n", None, Some("\""), Some("\""));
        assert!(!value_not_allowed_pattern_filtered(quoted.value, &quoted));
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
            let item = test_candidate(value, None, None, None);
            assert!(value_token_filtered(value, &item), "{value:?}");
        }
        for value in [
            "Crackle>secret",
            "password",
            "my - password",
            "words password",
        ] {
            let item = test_candidate(value, None, None, None);
            assert!(!value_token_filtered(value, &item), "{value:?}");
        }
        let quoted = test_candidate("my<password", None, Some("\""), Some("\""));
        assert!(!value_token_filtered(quoted.value, &quoted));
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
        }
    }

    #[test]
    fn labels_are_upper_snake() {
        assert_eq!(normalize_label("Slack Token"), "SLACK_TOKEN");
        assert_eq!(normalize_label("OTP / 2FA Secret"), "OTP_2FA_SECRET");
    }
}
