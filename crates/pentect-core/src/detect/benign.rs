use std::sync::LazyLock;

use super::documentation::is_documentation_value;

const VALUE_PATTERNS: &str = include_str!("benign_value_patterns.txt");
const KEY_PATTERNS: &str = include_str!("benign_key_patterns.txt");
const METADATA_KEY_PATTERNS: &str = include_str!("metadata_key_patterns.txt");
const CONSTANT_COMPONENT_PATTERNS: &str = include_str!("benign_constant_components.txt");
const SOURCE_SECRET_NAME_PATTERNS: &str = include_str!("source_secret_name_patterns.txt");
const SOURCE_FIXTURE_SECRET_PATTERNS: &str = include_str!("source_fixture_secret_patterns.txt");
const STRUCTURED_KEY_NAME_COMPONENTS: &str = include_str!("structured_key_name_components.txt");

static VALUE_MATCHER: LazyLock<PatternSet> = LazyLock::new(|| PatternSet::parse(VALUE_PATTERNS));
static KEY_MATCHER: LazyLock<PatternSet> = LazyLock::new(|| PatternSet::parse(KEY_PATTERNS));
static METADATA_KEY_MATCHER: LazyLock<PatternSet> =
    LazyLock::new(|| PatternSet::parse(METADATA_KEY_PATTERNS));
static CONSTANT_COMPONENT_MATCHER: LazyLock<PatternSet> =
    LazyLock::new(|| PatternSet::parse(CONSTANT_COMPONENT_PATTERNS));
static SOURCE_SECRET_NAME_MATCHER: LazyLock<SourceSecretNameSet> =
    LazyLock::new(|| SourceSecretNameSet::parse(SOURCE_SECRET_NAME_PATTERNS));
static SOURCE_FIXTURE_SECRET_MATCHER: LazyLock<SourceFixtureSecretSet> =
    LazyLock::new(|| SourceFixtureSecretSet::parse(SOURCE_FIXTURE_SECRET_PATTERNS));
static STRUCTURED_KEY_NAME_MATCHER: LazyLock<StructuredKeyNameSet> =
    LazyLock::new(|| StructuredKeyNameSet::parse(STRUCTURED_KEY_NAME_COMPONENTS));

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

#[derive(Clone, Debug, Default)]
struct SourceSecretNameSet {
    compact: Vec<String>,
    allowed_components: Vec<String>,
    sensitive_components: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct SourceFixtureSecretSet {
    key_components: Vec<String>,
    values: Vec<FixtureValuePattern>,
}

#[derive(Clone, Debug, Default)]
struct StructuredKeyNameSet {
    components: Vec<String>,
    names: Vec<String>,
    numbered_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FixtureValuePattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
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

impl StructuredKeyNameSet {
    fn parse(raw: &str) -> Self {
        let mut set = Self::default();
        for line in raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let Some((kind, pattern)) = line.split_once(':') else {
                continue;
            };
            let pattern = normalize_identifier(pattern);
            match kind.trim() {
                "component" => set.components.push(pattern),
                "name" => set.names.push(pattern),
                "numbered_name" => set.numbered_names.push(pattern),
                _ => {}
            }
        }
        set
    }

    fn matches_name(&self, normalized: &str) -> bool {
        self.names.iter().any(|known| known == normalized)
    }

    fn matches_numbered_name(&self, normalized: &str) -> bool {
        self.numbered_names.iter().any(|known| {
            normalized
                .strip_prefix(known)
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        })
    }

    fn matches_components(&self, parts: &[&str]) -> bool {
        parts
            .iter()
            .all(|part| self.components.iter().any(|known| known == part))
    }
}

impl SourceFixtureSecretSet {
    fn parse(raw: &str) -> Self {
        let mut set = Self::default();
        for line in raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let Some((kind, pattern)) = line.split_once(':') else {
                continue;
            };
            let pattern = normalize_identifier(pattern);
            match kind.trim() {
                "key_component" => set.key_components.push(pattern),
                "value_exact" => set.values.push(FixtureValuePattern::Exact(pattern)),
                "value_prefix" => set.values.push(FixtureValuePattern::Prefix(pattern)),
                "value_suffix" => set.values.push(FixtureValuePattern::Suffix(pattern)),
                "value_contains" => set.values.push(FixtureValuePattern::Contains(pattern)),
                _ => {}
            }
        }
        set
    }

    fn matches(&self, key_name: &str, value: &str) -> bool {
        let key = normalize_identifier(key_name);
        if !key
            .split('_')
            .any(|part| self.key_components.iter().any(|known| known == part))
        {
            return false;
        }
        let value = normalize_identifier(value);
        self.values.iter().any(|pattern| match pattern {
            FixtureValuePattern::Exact(pattern) => value == *pattern,
            FixtureValuePattern::Prefix(pattern) => value.starts_with(pattern),
            FixtureValuePattern::Suffix(pattern) => value.ends_with(pattern),
            FixtureValuePattern::Contains(pattern) => value.contains(pattern),
        })
    }
}

impl SourceSecretNameSet {
    fn parse(raw: &str) -> Self {
        let mut set = Self::default();
        for line in raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let Some((kind, pattern)) = line.split_once(':') else {
                continue;
            };
            let pattern = normalize_identifier(pattern);
            match kind.trim() {
                "compact" => set.compact.push(pattern.replace('_', "")),
                "allowed_component" => set.allowed_components.push(pattern),
                "sensitive_component" => set.sensitive_components.push(pattern),
                _ => {}
            }
        }
        set
    }

    fn matches(&self, value: &str) -> bool {
        let name = normalize_identifier(value);
        if self
            .compact
            .iter()
            .any(|pattern| pattern == &name.replace('_', ""))
        {
            return true;
        }
        let parts = name
            .split('_')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        !parts.is_empty()
            && parts
                .iter()
                .any(|part| self.sensitive_components.iter().any(|known| known == part))
            && parts
                .iter()
                .all(|part| self.allowed_components.iter().any(|known| known == part))
    }
}

/// True only for explicit placeholder/doc-example values.
///
/// Rationale: these markers say the value is intentionally not the real secret
/// ("redacted", "removed", "your_*", "value1"). They are not entropy shortcuts
/// and do not suppress arbitrary low-entropy values.
pub(crate) fn is_placeholder_value(value: &str) -> bool {
    VALUE_MATCHER.matches(&normalize_identifier(value)) || is_documentation_value(value)
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

/// True for source string values that are identifier names for secret settings.
///
/// Rationale: source code and generated docs frequently store setting names such
/// as `access_token` or `clientsecret`. The caller must already prove source
/// context and identifier shape; this data-driven matcher only decides whether
/// the identifier vocabulary is a placeholder/name rather than secret material.
pub(crate) fn is_source_secret_name_reference_value(value: &str) -> bool {
    SOURCE_SECRET_NAME_MATCHER.matches(value)
}

/// True for weak/synthetic credentials only when the source key says fixture.
///
/// Rationale: values such as `pass`, `secret`, and `letmein123` can be real
/// production credentials, so they are never globally benign. They are skipped
/// only when paired with source identifiers like `expectedPassword`,
/// `MOCK_ACCESS_TOKEN`, or `fake_secret`.
pub(crate) fn is_source_fixture_secret_value(key_name: &str, value: &str) -> bool {
    SOURCE_FIXTURE_SECRET_MATCHER.matches(key_name, value)
}

/// True when a generic JSON `"key"` value names another field/config key.
///
/// Rationale: many JSON schemas use objects like `{ "key": "smtpUser" }`.
/// The value is a public identifier, not credential material. Full single-name
/// and numbered UI/reference names are allowed only from the curated data file;
/// other digit/symbol-bearing values remain detectable because real key
/// material usually has that shape.
pub(crate) fn is_structured_key_name_reference_value(value: &str) -> bool {
    let value = value.trim();
    if !(3..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return false;
    }
    let normalized = normalize_identifier(value);
    let parts = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if value.bytes().any(|b| b.is_ascii_digit()) {
        return STRUCTURED_KEY_NAME_MATCHER.matches_numbered_name(&normalized);
    }
    STRUCTURED_KEY_NAME_MATCHER.matches_name(&normalized)
        || (parts.len() >= 2 && STRUCTURED_KEY_NAME_MATCHER.matches_components(&parts))
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
        assert!(is_placeholder_value("access_token"));
        assert!(is_placeholder_value("my_password"));
        assert!(is_placeholder_value("TestAuthToken"));
        assert!(is_placeholder_value("value42"));
        assert!(is_placeholder_value("/dev/null"));
        assert!(is_placeholder_value("api.example.com"));
        assert!(is_placeholder_value("192.0.2.10"));
        assert!(is_placeholder_value("https://example.org/path"));
        assert!(is_placeholder_value("<external-data-source>"));
        assert!(!is_placeholder_value("tenant-7-trial"));
        assert!(!is_placeholder_value(
            "https://example.org/path?token=abc123"
        ));
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
        assert!(is_explicitly_non_sensitive_key_name("correlationKey"));
        assert!(is_explicitly_non_sensitive_key_name("apiKeyName"));
        assert!(is_explicitly_non_sensitive_key_name(
            "PasswordStoreDirEnvar"
        ));
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

    #[test]
    fn source_secret_name_references_are_data_driven() {
        assert!(is_source_secret_name_reference_value("access_token"));
        assert!(is_source_secret_name_reference_value("ClientSecret"));
        assert!(is_source_secret_name_reference_value("clientsecret"));
        assert!(is_source_secret_name_reference_value("TestAuthToken"));
        assert!(is_source_secret_name_reference_value("my_password"));
        assert!(!is_source_secret_name_reference_value("CustomToken"));
        assert!(!is_source_secret_name_reference_value("PROD_SECRET_VALUE"));
        assert!(!is_source_secret_name_reference_value("tenant-7-trial"));
    }

    #[test]
    fn source_fixture_secret_values_are_key_contextual() {
        assert!(is_source_fixture_secret_value("expectedPassword", "pass"));
        assert!(is_source_fixture_secret_value(
            "MOCK_ACCESS_TOKEN",
            "at-0987654321"
        ));
        assert!(is_source_fixture_secret_value(
            "expected_access_token",
            "LET_ME_IN-1"
        ));
        assert!(is_source_fixture_secret_value("fake_secret", "secret"));
        assert!(!is_source_fixture_secret_value("password", "pass"));
        assert!(!is_source_fixture_secret_value("access_token", "LET_ME_IN"));
        assert!(!is_source_fixture_secret_value(
            "expectedPassword",
            "hunter2"
        ));
    }

    #[test]
    fn structured_key_name_references_require_identifier_shape() {
        assert!(is_structured_key_name_reference_value("seedUser"));
        assert!(is_structured_key_name_reference_value("smtpDomain"));
        assert!(is_structured_key_name_reference_value("apiKey"));
        assert!(is_structured_key_name_reference_value("Authorization"));
        assert!(is_structured_key_name_reference_value("Content-Type"));
        assert!(is_structured_key_name_reference_value("grant_type"));
        assert!(is_structured_key_name_reference_value("scope"));
        assert!(is_structured_key_name_reference_value("firstName"));
        assert!(is_structured_key_name_reference_value("phoneNumber"));
        assert!(is_structured_key_name_reference_value("panel1"));
        assert!(is_structured_key_name_reference_value("fieldset1"));
        assert!(is_structured_key_name_reference_value("dataGrid12"));
        assert!(!is_structured_key_name_reference_value("password"));
        assert!(!is_structured_key_name_reference_value("secret"));
        assert!(!is_structured_key_name_reference_value("Token"));
        assert!(!is_structured_key_name_reference_value("refresh_token"));
        assert!(!is_structured_key_name_reference_value("abcDEF123456"));
        assert!(!is_structured_key_name_reference_value("sk-test-token"));
    }
}
