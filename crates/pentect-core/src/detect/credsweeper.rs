use super::Detector;
use crate::model::{ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;
use fancy_regex::Regex as FancyRegex;
use regex::Regex as RustRegex;
use serde::Deserialize;
use std::sync::LazyLock;

const RULES_YAML: &str = include_str!("../../vendors/credsweeper-assets/rules/config.yaml");
const SECRET_CONFIG_JSON: &str =
    include_str!("../../vendors/credsweeper-assets/secret/config.json");
const ML_CONFIG_JSON: &str =
    include_str!("../../vendors/credsweeper-assets/ml_model/ml_config.json");
const ML_MODEL_ONNX: &[u8] =
    include_bytes!("../../vendors/credsweeper-assets/ml_model/ml_model.onnx");

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
    label: String,
    confidence: Confidence,
    min_line_len: usize,
    required_substrings: Vec<String>,
    filter_types: Vec<String>,
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
                            }
                            let value_capture = regex.has_capture_name("value");
                            if use_ml {
                                ml_gated_patterns += 1;
                            } else {
                                enabled_patterns += 1;
                                patterns.push(NativePattern {
                                    matcher: regex,
                                    value_capture,
                                });
                            }
                            compiled_patterns += 1;
                        }
                        Err(_) => unsupported_patterns += 1,
                    }
                }
            } else {
                unsupported_patterns += values.len();
            }
            if patterns.is_empty() {
                continue;
            }
            rules.push(NativeRule {
                label: normalize_label(&raw.name),
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
                                push_match(
                                    &mut out,
                                    view,
                                    rule,
                                    line_start,
                                    m.start(),
                                    m.end(),
                                    m.as_str(),
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
                                push_match(
                                    &mut out,
                                    view,
                                    rule,
                                    line_start,
                                    m.start(),
                                    m.end(),
                                    m.as_str(),
                                );
                            }
                        }
                    }
                }
            }
        }
        out
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

fn push_match(
    out: &mut Vec<Span>,
    view: &NormalizedView,
    rule: &NativeRule,
    line_start: usize,
    start: usize,
    end: usize,
    value: &str,
) {
    let range = view.to_raw(ByteRange::new(line_start + start, line_start + end));
    if range.is_empty() {
        return;
    }
    if !accept_value(value, &rule.filter_types) {
        return;
    }
    out.push(Span {
        range,
        category: Category::Secret,
        label: rule.label.clone(),
        confidence: rule.confidence,
        source: DetectorId::CredSweeper,
    });
}

#[derive(Deserialize)]
struct RawRule {
    name: String,
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

fn accept_value(value: &str, filters: &[String]) -> bool {
    let value = value.trim_matches(|ch: char| ch == '"' || ch == '\'' || ch == '`');
    if value.len() < 4 || is_obvious_placeholder(value) || is_repeated_symbol(value) {
        return false;
    }
    if filters
        .iter()
        .any(|filter| filter.contains("ValueFilePathCheck"))
        && looks_like_file_path(value)
    {
        return false;
    }
    true
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
        assert_eq!(stats.enabled_patterns, 93, "{stats:?}");
        assert_eq!(stats.ml_gated_patterns, 15, "{stats:?}");
        assert_eq!(stats.unsupported_patterns, 17, "{stats:?}");
        assert_eq!(
            stats.compiled_patterns,
            stats.enabled_patterns + stats.ml_gated_patterns
        );
        assert_eq!(
            stats.total_patterns,
            stats.compiled_patterns + stats.unsupported_patterns
        );
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
    fn labels_are_upper_snake() {
        assert_eq!(normalize_label("Slack Token"), "SLACK_TOKEN");
        assert_eq!(normalize_label("OTP / 2FA Secret"), "OTP_2FA_SECRET");
    }
}
