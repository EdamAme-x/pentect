use std::sync::LazyLock;

const VALUE_PATTERNS: &str = include_str!("benign_value_patterns.txt");
const KEY_PATTERNS: &str = include_str!("benign_key_patterns.txt");
const METADATA_KEY_PATTERNS: &str = include_str!("metadata_key_patterns.txt");
const CONSTANT_COMPONENT_PATTERNS: &str = include_str!("benign_constant_components.txt");

static VALUE_MATCHER: LazyLock<PatternSet> = LazyLock::new(|| PatternSet::parse(VALUE_PATTERNS));
static KEY_MATCHER: LazyLock<PatternSet> = LazyLock::new(|| PatternSet::parse(KEY_PATTERNS));
static METADATA_KEY_MATCHER: LazyLock<PatternSet> =
    LazyLock::new(|| PatternSet::parse(METADATA_KEY_PATTERNS));
static CONSTANT_COMPONENT_MATCHER: LazyLock<PatternSet> =
    LazyLock::new(|| PatternSet::parse(CONSTANT_COMPONENT_PATTERNS));

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
    NumberedPrefix(String),
    Component(String),
}

#[derive(Clone, Debug, Default)]
struct PatternSet {
    patterns: Vec<Pattern>,
}

impl PatternSet {
    fn parse(raw: &str) -> Self {
        let patterns = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| {
                let (kind, pattern) = line.split_once(':')?;
                let pattern = normalize_identifier(pattern);
                match kind.trim() {
                    "exact" => Some(Pattern::Exact(pattern)),
                    "prefix" => Some(Pattern::Prefix(pattern)),
                    "suffix" => Some(Pattern::Suffix(pattern)),
                    "contains" => Some(Pattern::Contains(pattern)),
                    "numbered_prefix" => Some(Pattern::NumberedPrefix(pattern)),
                    "component" => Some(Pattern::Component(pattern)),
                    _ => None,
                }
            })
            .collect();
        Self { patterns }
    }

    fn matches(&self, normalized: &str) -> bool {
        self.patterns.iter().any(|pattern| match pattern {
            Pattern::Exact(pattern) => normalized == pattern,
            Pattern::Prefix(pattern) => normalized.starts_with(pattern),
            Pattern::Suffix(pattern) => normalized.ends_with(pattern),
            Pattern::Contains(pattern) => normalized.contains(pattern),
            Pattern::NumberedPrefix(pattern) => normalized
                .strip_prefix(pattern)
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())),
            Pattern::Component(pattern) => normalized.split('_').any(|part| part == pattern),
        })
    }
}

/// True only for explicit placeholder/doc-example values.
///
/// Rationale: these markers say the value is intentionally not the real secret
/// ("redacted", "removed", "your_*", "value1"). They are not entropy shortcuts
/// and do not suppress arbitrary low-entropy values.
pub(crate) fn is_placeholder_value(value: &str) -> bool {
    VALUE_MATCHER.matches(&normalize_identifier(value))
}

/// True for key names that explicitly mark public/non-secret material.
///
/// Rationale: a key named `publicKeyToken` or `non_secret` carries an explicit
/// non-secret contract. Broad sensitive words are intentionally absent from the
/// data file, so `api_key`, `token`, and `secret` still route to detectors.
pub(crate) fn is_explicitly_non_sensitive_key_name(key: &str) -> bool {
    KEY_MATCHER.matches(&normalize_identifier(key))
}

/// True for structured metadata fields whose opaque values are stable IDs.
///
/// Rationale: JSON fields like `node_id`, `sha`, and `etag` conventionally store
/// repository/API metadata identifiers. They are only used to suppress raw
/// entropy guesses; vendor rules and keyed secret detectors still run.
pub(crate) fn is_structured_metadata_key(key: &str) -> bool {
    METADATA_KEY_MATCHER.matches(&normalize_identifier(key))
}

/// True for source-code sentinel constants, not for arbitrary ALL_CAPS secrets.
///
/// Rationale: values such as `GSS_C_EMPTY_BUFFER` and `MODULE_DEFAULT` are
/// references to public program states. Values containing sensitive components
/// like `SECRET` or `TOKEN` are deliberately not suppressed here.
pub(crate) fn is_non_secret_source_constant_value(value: &str) -> bool {
    let normalized = normalize_identifier(value);
    let has_non_secret_component = CONSTANT_COMPONENT_MATCHER.matches(&normalized);
    let has_sensitive_component = normalized.split('_').any(|part| {
        matches!(
            part,
            "secret" | "token" | "password" | "passwd" | "credential" | "auth" | "key"
        )
    });
    has_non_secret_component && !has_sensitive_component
}

pub(crate) fn normalize_identifier(input: &str) -> String {
    let mut out = String::new();
    let mut prev_lower_or_digit = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && prev_lower_or_digit && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            if !out.ends_with('_') {
                out.push('_');
            }
            prev_lower_or_digit = false;
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_values_are_data_driven() {
        assert!(is_placeholder_value("your_hipchat_api_key"));
        assert!(is_placeholder_value("login_and_password_removed"));
        assert!(is_placeholder_value("CREATE_A_KEY"));
        assert!(is_placeholder_value("CLIENT-SECRET"));
        assert!(is_placeholder_value("OAUTH-TOKEN"));
        assert!(is_placeholder_value("value42"));
        assert!(is_placeholder_value("/dev/null"));
        assert!(is_placeholder_value("api.example.com"));
        assert!(is_placeholder_value("<external-data-source>"));
        assert!(!is_placeholder_value("tenant-7-trial"));
        assert!(!is_placeholder_value("letmein123"));
        assert!(!is_placeholder_value("pass"));
        assert!(!is_placeholder_value("changeme"));
        assert!(!is_placeholder_value("Test Access Token"));
        assert!(!is_placeholder_value("PROD_SECRET"));
        assert!(!is_placeholder_value("OLD_LET_ME_IN-1"));
    }

    #[test]
    fn non_secret_keys_are_explicit_only() {
        assert!(is_explicitly_non_sensitive_key_name("publicKeyToken"));
        assert!(is_explicitly_non_sensitive_key_name("non_secret"));
        assert!(!is_explicitly_non_sensitive_key_name("api_key"));
        assert!(!is_explicitly_non_sensitive_key_name("client_secret"));
    }

    #[test]
    fn metadata_keys_are_narrow() {
        assert!(is_structured_metadata_key("node_id"));
        assert!(is_structured_metadata_key("If-None-Match"));
        assert!(!is_structured_metadata_key("url"));
        assert!(!is_structured_metadata_key("token"));
    }

    #[test]
    fn source_constant_components_are_non_sensitive_only() {
        assert!(is_non_secret_source_constant_value("GSS_C_EMPTY_BUFFER"));
        assert!(is_non_secret_source_constant_value("GSS_C_NO_BUFFER"));
        assert!(is_non_secret_source_constant_value("MODULE_DEFAULT"));
        assert!(!is_non_secret_source_constant_value("PROD_SECRET_VALUE"));
        assert!(!is_non_secret_source_constant_value(
            "GCM_OAUTH_CLIENTSECRET"
        ));
    }
}
