use super::credsweeper_ml::{self, MlInput, RuleSeverity};
use super::Detector;
use crate::model::{ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};
use fancy_regex::Regex as FancyRegex;
use regex::Regex as RustRegex;
use serde::Deserialize;
use std::borrow::Cow;
use std::cmp::Ordering;
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
}

impl CredSweeperNativeDetector {
    pub fn builtin() -> Self {
        BUILTIN.clone()
    }

    pub fn builtin_stats() -> &'static CredSweeperNativeStats {
        &BUILTIN.stats
    }

    pub fn rule_name_for_label(&self, label: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.label == label)
            .map(|rule| rule.rule_name.as_str())
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
            } else if raw.kind.as_deref() == Some("keyword") {
                for value in values {
                    match compile_keyword_pattern(value) {
                        Ok(regex) => {
                            fancy_regex_patterns += 1;
                            enabled_patterns += 1;
                            patterns.push(NativePattern {
                                matcher: PatternMatcher::Fancy(regex),
                                value_capture: true,
                            });
                            compiled_patterns += 1;
                        }
                        Err(_) => unsupported_patterns += 1,
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

impl CredSweeperNativeDetector {
    pub fn detect_findings(&self, view: &NormalizedView) -> Vec<CredSweeperNativeFinding> {
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
        for rule in &self.rules {
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
                            0,
                            text,
                            &candidate,
                        );
                    }
                }
            }
        }
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
                    if matches!(
                        &pattern.matcher,
                        PatternMatcher::Special(matcher) if matcher.is_whole_text()
                    ) {
                        continue;
                    }
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
                                    line_data: Vec::new(),
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
                                    line_data: Vec::new(),
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
    line_data: Vec<CandidateLineData<'a>>,
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
            Self::AwsMulti => aws_multi_candidates(line),
            Self::GoogleMulti => google_multi_candidates(line),
            Self::Jwk => Vec::new(),
            Self::PemPrivateKey => pem_private_key_candidates(line),
            Self::Base64PrivateKey => base64_private_key_candidates(line),
        }
    }

    fn is_whole_text(&self) -> bool {
        matches!(self, Self::Jwk | Self::PemPrivateKey)
    }

    fn find_whole_text<'a>(&self, text: &'a str) -> Vec<Candidate<'a>> {
        match self {
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
        _ => None,
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

fn compile_keyword_pattern(keyword: &str) -> Result<FancyRegex, ()> {
    FancyRegex::new(&keyword_pattern(keyword)).map_err(|_| ())
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
            line_data: Vec::new(),
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

fn push_match(
    out: &mut Vec<CredSweeperNativeFinding>,
    ml_pending: &mut Vec<PendingMlFinding>,
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
    let finding = CredSweeperNativeFinding {
        range,
        rule_name: rule.rule_name.clone(),
        label: rule.label.clone(),
        severity: severity_name(rule.severity).to_string(),
        confidence: rule.confidence,
        confidence_name: confidence_name(rule.confidence).to_string(),
        value: candidate.value.to_string(),
        value_start: candidate.start,
        value_end: candidate.end,
        variable: candidate.variable.map(str::to_string),
        variable_start: candidate.variable_start,
        variable_end: candidate.variable_end,
        line_data: candidate
            .line_data
            .iter()
            .map(|line_data| CredSweeperNativeRelatedFinding {
                range: ctx.view.to_raw(ByteRange::new(
                    line_start + line_data.start,
                    line_start + line_data.end,
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
        ml_pending.push(PendingMlFinding {
            finding,
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
        assert_eq!(stats.fancy_regex_patterns, 80, "{stats:?}");
        assert_eq!(stats.compiled_patterns, 117, "{stats:?}");
        assert_eq!(stats.translated_patterns, 8, "{stats:?}");
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
