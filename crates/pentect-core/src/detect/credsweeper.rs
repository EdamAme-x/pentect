use super::credsweeper_ml::{self, MlInput, RuleSeverity};
use super::Detector;
use crate::model::{ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};
use fancy_regex::Regex as FancyRegex;
use regex::Regex as RustRegex;
use serde::Deserialize;
use std::borrow::Cow;
use std::sync::LazyLock;

const RULES_YAML: &str = include_str!("../../vendors/credsweeper-assets/rules/config.yaml");
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

static BUILTIN: LazyLock<CredSweeperNativeDetector> = LazyLock::new(|| {
    CredSweeperNativeDetector::compile_builtin().expect("embedded CredSweeper assets compile")
});

#[derive(Clone)]
pub struct CredSweeperNativeDetector {
    rules: Vec<NativeRule>,
    stats: CredSweeperNativeStats,
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
    pub ml_rules: usize,
    pub rules_yaml_bytes: usize,
    pub secret_config_json_bytes: usize,
    pub ml_config_json_bytes: usize,
    pub ml_model_onnx_bytes: usize,
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
    Rust(RustRegex),
    Fancy(FancyRegex),
    Special(SpecialMatcher),
}

#[derive(Clone)]
enum SpecialMatcher {
    AwsMulti,
    GoogleMulti,
    Jwk,
    PemPrivateKey,
    Base64PrivateKey,
    Keyword(KeywordMatcher),
}

#[derive(Clone, Copy)]
enum KeywordMatcher {
    Api,
    Auth,
    Credential,
    Key,
    Nonce,
    Password,
    Salt,
    Secret,
    Token,
}

impl CredSweeperNativeDetector {
    pub fn builtin() -> Self {
        BUILTIN.clone()
    }

    pub fn builtin_stats() -> &'static CredSweeperNativeStats {
        &BUILTIN.stats
    }

    fn compile_builtin() -> Result<Self, String> {
        let raw_rules: Vec<RawRule> =
            serde_yaml::from_str(RULES_YAML).map_err(|e| format!("rules yaml: {e}"))?;
        let mut total_patterns = 0usize;
        let mut compiled_patterns = 0usize;
        let mut rust_regex_patterns = 0usize;
        let mut fancy_regex_patterns = 0usize;
        let mut translated_patterns = 0usize;
        let mut enabled_patterns = 0usize;
        let mut ml_gated_patterns = 0usize;
        let mut unsupported_patterns = 0usize;
        let mut rules = Vec::new();
        for raw in &raw_rules {
            let values = raw.values.as_deref().unwrap_or_default();
            let use_ml = raw.use_ml.unwrap_or(false);
            total_patterns += values.len();
            let mut patterns = Vec::new();
            if raw.kind.as_deref() == Some("pattern") {
                for pattern in values {
                    match compile_pattern(pattern) {
                        Ok(regex) => {
                            match &regex {
                                PatternMatcher::Rust(_) => rust_regex_patterns += 1,
                                PatternMatcher::Fancy(_) => fancy_regex_patterns += 1,
                                PatternMatcher::Special(_) => translated_patterns += 1,
                            }
                            let value_capture = regex.has_capture_name("value");
                            enabled_patterns += 1;
                            patterns.push(NativePattern {
                                matcher: regex,
                                value_capture,
                            });
                            compiled_patterns += 1;
                        }
                        Err(_) => match translated_pattern(&raw.name) {
                            Some(matcher) => {
                                translated_patterns += 1;
                                enabled_patterns += 1;
                                patterns.push(NativePattern {
                                    matcher: PatternMatcher::Special(matcher),
                                    value_capture: true,
                                });
                            }
                            None => unsupported_patterns += 1,
                        },
                    }
                }
            } else {
                match translated_rule(raw) {
                    Some(matcher) => {
                        translated_patterns += values.len();
                        enabled_patterns += values.len();
                        patterns.push(NativePattern {
                            matcher: PatternMatcher::Special(matcher),
                            value_capture: true,
                        });
                    }
                    None => unsupported_patterns += values.len(),
                }
            }
            if patterns.is_empty() {
                continue;
            }
            if use_ml {
                ml_gated_patterns += patterns.len();
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
                ml_validated: use_ml,
                patterns,
            });
        }
        Ok(Self {
            rules,
            stats: CredSweeperNativeStats {
                total_rules: raw_rules.len(),
                total_patterns,
                compiled_patterns,
                rust_regex_patterns,
                fancy_regex_patterns,
                translated_patterns,
                enabled_patterns,
                ml_gated_patterns,
                unsupported_patterns,
                ml_rules: raw_rules
                    .iter()
                    .filter(|rule| rule.use_ml.unwrap_or(false))
                    .count(),
                rules_yaml_bytes: RULES_YAML.len(),
                secret_config_json_bytes: SECRET_CONFIG_JSON.len(),
                ml_config_json_bytes: ML_CONFIG_JSON.len(),
                ml_model_onnx_bytes: ML_MODEL_ONNX.len(),
            },
        })
    }
}

impl Detector for CredSweeperNativeDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let mut out = Vec::new();
        let mut ml_pending = Vec::new();
        let ml_path = credsweeper_ml::ml_path(view.region.ctx.path.as_deref());
        let ml_file_type = credsweeper_ml::ml_file_type(view.region.ctx.path.as_deref());
        let push_ctx = PushMatchCtx {
            view,
            path: &ml_path,
            file_type: &ml_file_type,
        };
        for (line_start, line) in LineRanges::new(text) {
            let line_body = line.trim_end_matches(['\r', '\n']);
            let line_lower = LazyLower::new(line_body);
            for rule in &self.rules {
                if line_body.len() < rule.min_line_len
                    || !required_substring_present(&rule.required_substrings, &line_lower)
                {
                    continue;
                }
                for pattern in &rule.patterns {
                    match &pattern.matcher {
                        PatternMatcher::Rust(regex) => {
                            for captures in regex.captures_iter(line_body) {
                                let Some(m) = (if pattern.value_capture {
                                    captures.name("value")
                                } else {
                                    captures.get(0)
                                }) else {
                                    continue;
                                };
                                let variable = captures.name("variable");
                                let candidate = Candidate {
                                    start: m.start(),
                                    end: m.end(),
                                    value: m.as_str(),
                                    variable_start: variable.as_ref().map(|m| m.start()),
                                    variable_end: variable.as_ref().map(|m| m.end()),
                                    variable: variable.map(|m| m.as_str()),
                                };
                                push_match(
                                    &mut out,
                                    &mut ml_pending,
                                    &push_ctx,
                                    rule,
                                    line_start,
                                    line_body,
                                    &candidate,
                                );
                            }
                        }
                        PatternMatcher::Fancy(regex) => {
                            for captures in regex.captures_iter(line_body) {
                                let Ok(captures) = captures else {
                                    continue;
                                };
                                let Some(m) = (if pattern.value_capture {
                                    captures.name("value")
                                } else {
                                    captures.get(0)
                                }) else {
                                    continue;
                                };
                                let variable = captures.name("variable");
                                let candidate = Candidate {
                                    start: m.start(),
                                    end: m.end(),
                                    value: m.as_str(),
                                    variable_start: variable.as_ref().map(|m| m.start()),
                                    variable_end: variable.as_ref().map(|m| m.end()),
                                    variable: variable.map(|m| m.as_str()),
                                };
                                push_match(
                                    &mut out,
                                    &mut ml_pending,
                                    &push_ctx,
                                    rule,
                                    line_start,
                                    line_body,
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
                                    line_start,
                                    line_body,
                                    &m,
                                );
                            }
                        }
                    }
                }
            }
        }
        push_ml_accepted(&mut out, &ml_pending);
        dedupe_spans(out)
    }
}

impl PatternMatcher {
    fn has_capture_name(&self, name: &str) -> bool {
        match self {
            Self::Rust(regex) => regex
                .capture_names()
                .flatten()
                .any(|candidate| candidate == name),
            Self::Fancy(regex) => regex
                .capture_names()
                .flatten()
                .any(|candidate| candidate == name),
            Self::Special(_) => true,
        }
    }
}

struct Candidate<'a> {
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
            Self::AwsMulti => aws_multi_candidates(line),
            Self::GoogleMulti => google_multi_candidates(line),
            Self::Jwk => jwk_candidates(line),
            Self::PemPrivateKey => pem_private_key_candidates(line),
            Self::Base64PrivateKey => base64_private_key_candidates(line),
            Self::Keyword(keyword) => keyword_candidates(line, *keyword),
        }
    }
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
            "Google Multi" => Some(SpecialMatcher::GoogleMulti),
            "JWK" => Some(SpecialMatcher::Jwk),
            _ => None,
        },
        "pem_key" => (raw.name == "PEM Private Key").then_some(SpecialMatcher::PemPrivateKey),
        "keyword" => KeywordMatcher::from_rule_name(&raw.name).map(SpecialMatcher::Keyword),
        _ => None,
    }
}

impl KeywordMatcher {
    fn from_rule_name(name: &str) -> Option<Self> {
        match name {
            "API" => Some(Self::Api),
            "Auth" => Some(Self::Auth),
            "Credential" => Some(Self::Credential),
            "Key" => Some(Self::Key),
            "Nonce" => Some(Self::Nonce),
            "Password" => Some(Self::Password),
            "Salt" => Some(Self::Salt),
            "Secret" => Some(Self::Secret),
            "Token" => Some(Self::Token),
            _ => None,
        }
    }

    fn needles(self) -> &'static [&'static str] {
        match self {
            Self::Api => &["api"],
            Self::Auth => &["auth"],
            Self::Credential => &["credential"],
            Self::Key => &["key"],
            Self::Nonce => &["nonce"],
            Self::Password => &["password", "passwd", "pwd", "passphrase", "pass"],
            Self::Salt => &["salt"],
            Self::Secret => &["secret"],
            Self::Token => &["token"],
        }
    }
}

fn compile_pattern(pattern: &str) -> Result<PatternMatcher, ()> {
    match RustRegex::new(pattern) {
        Ok(regex) => Ok(PatternMatcher::Rust(regex)),
        Err(_) => FancyRegex::new(pattern)
            .map(PatternMatcher::Fancy)
            .map_err(|_| ()),
    }
}

fn aws_multi_candidates(line: &str) -> Vec<Candidate<'_>> {
    static AWS_ID: LazyLock<RustRegex> =
        LazyLock::new(|| RustRegex::new(r"A(KIA|SIA)[0-9A-Z]{16}").expect("aws id regex"));
    let ids = regex_candidates(line, &AWS_ID);
    if ids.is_empty() {
        return Vec::new();
    }
    let mut out = ids;
    out.extend(token_runs(line).filter(|run| {
        run.value.len() >= 40
            && run.value.len() <= 44
            && is_base64ish(run.value)
            && has_upper_lower_digit(run.value)
    }));
    out
}

fn google_multi_candidates(line: &str) -> Vec<Candidate<'_>> {
    static GOOGLE_CLIENT_ID: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r"[0-9]{3,80}-[0-9a-z_]{32}\.apps\.googleusercontent\.com")
            .expect("google client id regex")
    });
    static GOOGLE_SECRET: LazyLock<RustRegex> =
        LazyLock::new(|| RustRegex::new(r"GOCSPX-[0-9A-Za-z_-]{28}").expect("google secret"));
    let clients = regex_candidates(line, &GOOGLE_CLIENT_ID);
    if clients.is_empty() {
        return Vec::new();
    }
    let mut out = clients;
    out.extend(regex_candidates(line, &GOOGLE_SECRET));
    out
}

fn jwk_candidates(line: &str) -> Vec<Candidate<'_>> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains("kty")
        || !(line.contains("RSA") || line.contains("EC") || line.contains("oct"))
    {
        return Vec::new();
    }
    static JWK_PRIVATE_VALUE: LazyLock<RustRegex> = LazyLock::new(|| {
        RustRegex::new(r#"(?i)["']?[dk]["']?\s*[:=]\s*["'](?P<value>[0-9A-Za-z_-]{22,8000})["']"#)
            .expect("jwk private value regex")
    });
    capture_value_candidates(line, &JWK_PRIVATE_VALUE)
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
        }]
    } else {
        Vec::new()
    }
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

fn keyword_candidates(line: &str, keyword: KeywordMatcher) -> Vec<Candidate<'_>> {
    let lower = line.to_ascii_lowercase();
    let mut out = Vec::new();
    for needle in keyword.needles() {
        for (idx, _) in lower.match_indices(needle) {
            if !is_left_word_boundary(lower.as_bytes(), idx)
                || !is_right_word_boundary(lower.as_bytes(), idx + needle.len())
            {
                continue;
            }
            let Some((start, end)) = assignment_value_after_keyword(line, idx + needle.len())
            else {
                continue;
            };
            let value = &line[start..end];
            if is_credible_secret_value(value) {
                out.push(Candidate {
                    start,
                    end,
                    value,
                    variable_start: Some(idx),
                    variable_end: Some(idx + needle.len()),
                    variable: Some(&line[idx..idx + needle.len()]),
                });
            }
        }
    }
    out
}

fn assignment_value_after_keyword(line: &str, from: usize) -> Option<(usize, usize)> {
    let to = clamp_to_char_boundary(line, line.len().min(from + 96));
    let tail = &line[from..to];
    let eq = tail.find('=').map(|idx| from + idx);
    let colon = tail.find(':').map(|idx| from + idx);
    let sep = match (eq, colon) {
        (Some(eq), Some(colon)) if colon < eq && line[colon + 1..eq].trim().len() <= 24 => eq,
        (Some(eq), _) => eq,
        (None, Some(colon)) => colon,
        (None, None) => return None,
    };
    let mut start = sep + 1;
    let bytes = line.as_bytes();
    while start < line.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while start < line.len() && matches!(bytes[start], b'"' | b'\'' | b'`') {
        start += 1;
    }
    if start >= line.len() || bytes[start] == b'-' {
        return None;
    }
    let mut end = start;
    while end < line.len() {
        let b = bytes[end];
        if b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'`' | b',' | b';' | b')') {
            break;
        }
        end += 1;
    }
    (end > start).then_some((start, end))
}

fn clamp_to_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn regex_candidates<'a>(line: &'a str, regex: &RustRegex) -> Vec<Candidate<'a>> {
    regex
        .find_iter(line)
        .map(|m| Candidate {
            start: m.start(),
            end: m.end(),
            value: m.as_str(),
            variable_start: None,
            variable_end: None,
            variable: None,
        })
        .collect()
}

fn capture_value_candidates<'a>(line: &'a str, regex: &RustRegex) -> Vec<Candidate<'a>> {
    regex
        .captures_iter(line)
        .filter_map(|captures| captures.name("value"))
        .map(|m| Candidate {
            start: m.start(),
            end: m.end(),
            value: m.as_str(),
            variable_start: None,
            variable_end: None,
            variable: None,
        })
        .collect()
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
        });
    }
    runs.into_iter()
}

struct PendingMlSpan {
    span: Span,
    input: MlInput,
}

struct PushMatchCtx<'view, 'data> {
    view: &'view NormalizedView<'view>,
    path: &'data str,
    file_type: &'data str,
}

fn push_match(
    out: &mut Vec<Span>,
    ml_pending: &mut Vec<PendingMlSpan>,
    ctx: &PushMatchCtx<'_, '_>,
    rule: &NativeRule,
    line_start: usize,
    line: &str,
    candidate: &Candidate<'_>,
) {
    let range = ctx.view.to_raw(ByteRange::new(
        line_start + candidate.start,
        line_start + candidate.end,
    ));
    if range.is_empty() {
        return;
    }
    if !accept_value(candidate.value, rule) {
        return;
    }
    let span = Span {
        range,
        category: Category::Secret,
        label: rule.label.clone(),
        confidence: rule.confidence,
        source: DetectorId::CredSweeper,
    };
    if rule.ml_validated {
        ml_pending.push(PendingMlSpan {
            span,
            input: MlInput {
                line: line.to_string(),
                value: candidate.value.to_string(),
                variable: candidate.variable.unwrap_or_default().to_string(),
                value_start: candidate.start,
                value_end: candidate.end,
                variable_start: candidate
                    .variable_start
                    .map(|start| start as isize)
                    .unwrap_or(-2),
                variable_end: candidate.variable_end.map(|end| end as isize).unwrap_or(-2),
                path: ctx.path.to_string(),
                file_type: ctx.file_type.to_string(),
                rule_name: rule.rule_name.clone(),
                severity: rule.severity,
            },
        });
    } else {
        out.push(span);
    }
}

fn push_ml_accepted(out: &mut Vec<Span>, pending: &[PendingMlSpan]) {
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
                out.push(pending[idx].span.clone());
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

#[derive(Deserialize)]
struct RawRule {
    name: String,
    severity: Option<String>,
    confidence: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    values: Option<Vec<String>>,
    min_line_len: Option<usize>,
    required_substrings: Option<Vec<String>>,
    filter_type: Option<FilterList>,
    use_ml: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FilterList {
    One(String),
    Many(Vec<String>),
}

impl FilterList {
    fn items(&self) -> Vec<String> {
        match self {
            Self::One(item) => vec![item.clone()],
            Self::Many(items) => items.clone(),
        }
    }
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

fn required_substring_present(required: &[String], line_lower: &LazyLower<'_>) -> bool {
    if required.is_empty() {
        return true;
    }
    let lower = line_lower.as_lower();
    required.iter().any(|needle| lower.contains(needle))
}

fn accept_value(value: &str, rule: &NativeRule) -> bool {
    let value = value.trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == '`');
    if value.len() < 4 || is_obvious_placeholder(value) || is_repeated_symbol(value) {
        return false;
    }
    for filter in &rule.filter_types {
        if filter == "ValueBasicAuthCheck" && !is_basic_auth_token68(value) {
            return false;
        }
        if filter == "WeirdBase36Token" && weird_base36_token_filtered(value) {
            return false;
        }
        if filter == "GeneralKeyword"
            && (dictionary_keyword_filtered(value) || value_sealed_secret_filtered(value, ""))
        {
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
        if filter == "ValueEntropyBase36Check" && entropy_base36_filtered(value) {
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

fn weird_base36_token_filtered(value: &str) -> bool {
    morphemes_filtered_with_threshold(value, 1)
        || value_pattern_filtered(value, None)
        || number_filtered(value)
        || entropy_base36_filtered(value)
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

fn value_pattern_filtered(value: &str, pattern_len: Option<usize>) -> bool {
    const DEFAULT_PATTERN_LEN: usize = 4;
    const MIN_DATA_LEN: usize = 8;
    const MAX_PATTERN_BIT_LENGTH: usize = 13;
    let value_len = value.chars().count();
    let bit_length = value_len.ilog2() as usize + 1;
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
        if pair[0] == pair[1]
            && !(ignore_base64_a_slash
                && matches!(pair[0], 'A' | '/' | '_' | char::REPLACEMENT_CHARACTER))
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

fn is_credible_secret_value(value: &str) -> bool {
    let value = value.trim_matches(|ch: char| {
        matches!(ch, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}')
    });
    if value.len() < 8 || value.contains(char::is_whitespace) || is_obvious_placeholder(value) {
        return false;
    }
    if has_known_secret_prefix(value) {
        return true;
    }
    let has_alpha = value.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|ch| ch.is_ascii_punctuation() && !matches!(ch, '_' | '-'));
    let has_upper = value.chars().any(|ch| ch.is_ascii_uppercase());
    let has_lower = value.chars().any(|ch| ch.is_ascii_lowercase());
    (value.len() >= 8 && has_alpha && has_digit)
        || (value.len() >= 12 && has_alpha && has_symbol)
        || (value.len() >= 16 && has_upper && has_lower)
        || (value.len() >= 20 && has_alpha)
}

fn has_known_secret_prefix(value: &str) -> bool {
    [
        "AKIA",
        "ASIA",
        "AIza",
        "ghp_",
        "github_pat_",
        "glpat-",
        "sk-",
        "xox",
        "GOCSPX-",
        "hf_",
        "sk-ant-",
        "pplx-",
        "tvly-",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn is_left_word_boundary(bytes: &[u8], idx: usize) -> bool {
    bytes
        .get(idx.wrapping_sub(1))
        .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_')
}

fn is_right_word_boundary(bytes: &[u8], idx: usize) -> bool {
    bytes
        .get(idx)
        .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_')
}

fn has_upper_lower_digit(value: &str) -> bool {
    value.chars().any(|ch| ch.is_ascii_uppercase())
        && value.chars().any(|ch| ch.is_ascii_lowercase())
        && value.chars().any(|ch| ch.is_ascii_digit())
}

fn is_base64ish(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
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

fn map_severity(severity: Option<&str>) -> RuleSeverity {
    match severity {
        Some("critical") => RuleSeverity::Critical,
        Some("high") => RuleSeverity::High,
        Some("low") => RuleSeverity::Low,
        Some("info") => RuleSeverity::Info,
        _ => RuleSeverity::Medium,
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
        assert_eq!(stats.total_rules, 121);
        assert_eq!(stats.total_patterns, 125);
        assert_eq!(stats.ml_rules, 23);
        assert!(stats.rules_yaml_bytes > 40_000);
        assert!(stats.secret_config_json_bytes > 1_000);
        assert!(stats.ml_config_json_bytes > 10_000);
        assert!(stats.ml_model_onnx_bytes > 10_000_000);
    }

    #[test]
    fn migration_coverage_is_explicit() {
        let stats = CredSweeperNativeDetector::builtin_stats();
        assert_eq!(stats.rust_regex_patterns, 37, "{stats:?}");
        assert_eq!(stats.fancy_regex_patterns, 71, "{stats:?}");
        assert_eq!(stats.compiled_patterns, 108, "{stats:?}");
        assert_eq!(stats.translated_patterns, 17, "{stats:?}");
        assert_eq!(stats.enabled_patterns, 125, "{stats:?}");
        assert_eq!(stats.ml_gated_patterns, 24, "{stats:?}");
        assert_eq!(stats.unsupported_patterns, 0, "{stats:?}");
        assert_eq!(
            stats.total_patterns,
            stats.compiled_patterns + stats.translated_patterns + stats.unsupported_patterns
        );
    }

    #[test]
    fn embedded_ml_feature_vector_matches_model() {
        assert!(credsweeper_ml::feature_width_matches_model_for_test());
    }

    #[test]
    fn detects_compatible_credsweeper_rule_without_python() {
        let token = format!("github_pat_{}", "A".repeat(80));
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
    fn translated_credsweeper_rules_are_active() {
        let aws_id = ["AKIA", "ABCDEFGHIJKLMNOP"].concat();
        let aws_secret = "mQ7zR2pL8vN4xY6cT9bH3sK5dF1gJ0aW2eU4rI6o".to_string();
        let google_secret = format!("GOCSPX-{}", "A".repeat(28));
        let jwk_secret = "mQ7zR2pL8vN4xY6cT9bH3sK5dF1gJ0aW";
        let base64_key = format!("MII{}", "A".repeat(180));
        let raw = format!(
            "aws {aws_id} {aws_secret}\n\
             google 123-abcdeabcdeabcdeabcdeabcdeabcdeab.apps.googleusercontent.com {google_secret}\n\
             jwk {{\"kty\":\"RSA\",\"d\":\"{jwk_secret}\"}}\n\
             -----BEGIN OPENSSH PRIVATE KEY-----\n\
             {base64_key}\n\
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
    fn translated_keyword_rules_do_not_mask_plain_prose() {
        let raw = "token budget and secret capability are API design notes\n";
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        let spans = CredSweeperNativeDetector::builtin().detect(&view);
        assert!(spans.is_empty(), "{spans:?}");
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
    fn labels_are_upper_snake() {
        assert_eq!(normalize_label("Slack Token"), "SLACK_TOKEN");
        assert_eq!(normalize_label("OTP / 2FA Secret"), "OTP_2FA_SECRET");
    }
}
