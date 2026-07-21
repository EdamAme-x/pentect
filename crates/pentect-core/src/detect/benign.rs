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
        parts.iter().all(|part| self.matches_component(part))
    }

    fn matches_component(&self, part: &str) -> bool {
        if self.components.iter().any(|known| known == part) {
            return true;
        }
        if let Some(stem) = part.strip_suffix('s') {
            if stem.len() >= 3 && self.components.iter().any(|known| known == stem) {
                return true;
            }
        }
        if let Some(stem) = part.strip_suffix("ies") {
            if stem.len() >= 3 {
                let singular = format!("{stem}y");
                if self.components.iter().any(|known| known == &singular) {
                    return true;
                }
            }
        }
        false
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
        if !self.matches_key_context(key_name) {
            return false;
        }
        self.matches_value(value)
    }

    fn matches_value(&self, value: &str) -> bool {
        let value = normalize_identifier(value);
        self.values.iter().any(|pattern| match pattern {
            FixtureValuePattern::Exact(pattern) => value == *pattern,
            FixtureValuePattern::Prefix(pattern) => value.starts_with(pattern),
            FixtureValuePattern::Suffix(pattern) => value.ends_with(pattern),
            FixtureValuePattern::Contains(pattern) => value.contains(pattern),
        })
    }

    fn matches_key_context(&self, key_name: &str) -> bool {
        let key = normalize_identifier(key_name);
        key.split('_')
            .any(|part| self.key_components.iter().any(|known| known == part))
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
    VALUE_MATCHER.matches(&normalize_identifier(value))
        || is_documentation_value(value)
        || is_compositional_placeholder_secret_name(value)
        || is_repeated_marker_placeholder_value(value)
        || is_masked_prefix_placeholder_value(value)
        || is_delimited_identifier_placeholder_value(value)
}

fn is_compositional_placeholder_secret_name(value: &str) -> bool {
    // Placeholder secret names often describe the slot instead of carrying the
    // credential: `my_api_key`, `some-password`, or `test-user-password`.
    // Require an explicit placeholder owner plus a credential component so
    // ordinary values such as `tenant-7-trial` and `secret1` still detect.
    if value.chars().any(char::is_whitespace) {
        return false;
    }
    let normalized = normalize_identifier(value);
    let compact = normalized.replace('_', "");
    if compact.starts_with("notareal")
        && contains_any(
            &compact,
            &["password", "passwd", "secret", "token", "key", "credential"],
        )
    {
        return true;
    }

    let parts = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2
        || !parts
            .iter()
            .any(|part| is_placeholder_secret_component(part))
    {
        return false;
    }
    let Some(first) = parts.first().copied() else {
        return false;
    };
    is_placeholder_owner_component(first)
        && parts
            .iter()
            .all(|part| is_placeholder_secret_name_component(part))
}

fn is_placeholder_owner_component(part: &str) -> bool {
    matches!(
        part,
        "my" | "some" | "test" | "sample" | "fake" | "dummy" | "example" | "not" | "notareal"
    )
}

fn is_placeholder_secret_component(part: &str) -> bool {
    matches!(
        part,
        "password" | "passwd" | "pass" | "secret" | "token" | "key" | "credential"
    )
}

fn is_placeholder_secret_name_component(part: &str) -> bool {
    is_placeholder_owner_component(part)
        || is_placeholder_secret_component(part)
        || matches!(
            part,
            "api"
                | "auth"
                | "oauth"
                | "access"
                | "consumer"
                | "client"
                | "private"
                | "public"
                | "db"
                | "database"
                | "user"
                | "value"
                | "url"
        )
}

fn is_repeated_marker_placeholder_value(value: &str) -> bool {
    // Repeated marker payloads (`xxxx`, `AAAA/AAA=AAAA`) are fixture/doc
    // sentinels. The whole value must be one repeated alphabetic marker plus
    // harmless separators, so mixed or random-looking tokens remain visible.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(4..=128).contains(&value.len()) {
        return false;
    }
    let mut marker = None;
    let mut marker_count = 0usize;
    let mut separator_count = 0usize;
    for byte in value.bytes() {
        if byte.is_ascii_alphabetic() {
            let normalized = byte.to_ascii_lowercase();
            match marker {
                Some(previous) if previous == normalized => {}
                None => marker = Some(normalized),
                _ => return false,
            }
            marker_count += 1;
        } else if matches!(byte, b'-' | b'_' | b'.' | b'+' | b'/' | b'=') {
            separator_count += 1;
        } else {
            return false;
        }
    }
    marker_count >= 4 && (separator_count > 0 || marker_count == value.len())
}

fn is_masked_prefix_placeholder_value(value: &str) -> bool {
    // Logs and docs often show irrecoverable secret previews such as
    // `ab********` or `i*******************`. They prove a value was already
    // redacted, not that reusable material is present.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let bytes = value.as_bytes();
    if !(8..=128).contains(&bytes.len()) {
        return false;
    }
    let Some(first_star) = bytes.iter().position(|b| *b == b'*') else {
        return false;
    };
    let prefix = &bytes[..first_star];
    let stars = &bytes[first_star..];
    !prefix.is_empty()
        && prefix.len() <= 8
        && prefix.iter().all(u8::is_ascii_alphanumeric)
        && stars.len() >= 6
        && stars.iter().all(|b| *b == b'*')
        && stars.len() * 2 >= bytes.len()
}

fn is_delimited_identifier_placeholder_value(value: &str) -> bool {
    // Template systems use visibly delimited replacement tokens:
    // `###ORACLE_PWD###` or `__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__`.
    // Require matching delimiter runs and an identifier-like body so real
    // punctuation-heavy passwords are not hidden.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let bytes = value.as_bytes();
    if !(8..=160).contains(&bytes.len()) {
        return false;
    }
    let marker = bytes[0];
    if marker.is_ascii_alphanumeric() || marker.is_ascii_whitespace() {
        return false;
    }
    let leading = bytes.iter().take_while(|b| **b == marker).count();
    let trailing = bytes.iter().rev().take_while(|b| **b == marker).count();
    if leading < 2 || trailing < 2 || leading + trailing >= bytes.len() {
        return false;
    }
    let body = &value[leading..value.len() - trailing];
    if body.is_empty()
        || body.bytes().any(|b| {
            b.is_ascii_whitespace()
                || !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
        })
        || !body.bytes().any(|b| b.is_ascii_alphabetic())
    {
        return false;
    }
    let normalized = normalize_identifier(body);
    let parts = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return false;
    }
    let has_placeholder_word = parts.iter().any(|part| {
        matches!(
            *part,
            "todo"
                | "your"
                | "own"
                | "generate"
                | "generated"
                | "placeholder"
                | "replace"
                | "replaced"
                | "set"
                | "change"
                | "changeme"
        )
    });
    let has_secret_word = parts.iter().any(|part| {
        matches!(
            *part,
            "key" | "pwd" | "pass" | "password" | "passwd" | "secret" | "token" | "credential"
        )
    });
    let has_placeholder_value_word = parts
        .iter()
        .any(|part| matches!(*part, "random" | "value" | "here"));
    if marker == b'_' {
        has_placeholder_word && (has_secret_word || has_placeholder_value_word)
    } else {
        has_placeholder_word || has_secret_word
    }
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

/// True for weak/synthetic fixture values, independent of the key name.
///
/// Rationale: callers must prove source/object fixture shape before using this.
/// The value list stays data-driven here so detectors do not grow ad hoc
/// benchmark strings.
pub(crate) fn is_source_fixture_secret_sample_value(value: &str) -> bool {
    SOURCE_FIXTURE_SECRET_MATCHER.matches_value(value)
}

/// True when a source identifier explicitly marks fixture/test/example context.
///
/// Rationale: some fixture credentials are weak by shape rather than by an
/// exact sentinel value. Keep the vocabulary in the shared pattern file so
/// detector code can require fixture context without duplicating word lists.
pub(crate) fn is_source_fixture_key_context(key_name: &str) -> bool {
    SOURCE_FIXTURE_SECRET_MATCHER.matches_key_context(key_name)
}

/// True for public cryptographic test-vector identifiers, not key material.
///
/// Rationale: NIST/SEC-style test vectors often label cases with values such as
/// `KAS-ECC-CDH_P-192_C0`, `ALICE_secp112r1_PUB`, `ED25519-1-PUBLIC`, and
/// RFC 7919 FFDHE group test-case names such as `ffdhe2048-1-pub`.
/// Those strings name a curve/test-case record; the actual private scalar or
/// public point appears elsewhere as bytes. The accepted syntax is deliberately
/// tied to known test-vector prefixes and named-curve families, so operational
/// names like `tenant-7-trial` and `ALICE_prod_key_2026` remain detectable.
pub(crate) fn is_crypto_test_vector_identifier_value(value: &str) -> bool {
    let value = value.trim();
    let mut parts = value.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return is_crypto_test_vector_identifier_part(first);
    };
    parts.next().is_none()
        && is_crypto_test_vector_identifier_part(first)
        && is_crypto_test_vector_identifier_part(second)
}

/// True for byte-pattern fixtures such as `000102...` or repeated-byte blocks.
///
/// Rationale: published crypto fixtures and RFC examples often use visual byte
/// sequences, repeated sentinels, or regular byte progressions to make expected
/// values auditable. Generated secrets can contain these locally, but not as
/// the whole value split into obvious runs. This is used only to suppress raw
/// entropy/keyed guesses; specific private-key and vendor validators still run.
pub(crate) fn is_synthetic_hex_test_vector_value(value: &str) -> bool {
    let value = value.trim();
    let Some(bytes) = decode_hex_literal(value) else {
        return false;
    };
    if bytes.len() < 8 {
        return false;
    }
    is_segmented_hex_fixture_bytes(&bytes)
}

fn is_crypto_test_vector_identifier_part(value: &str) -> bool {
    let value = value.trim();
    if !(5..=96).contains(&value.len())
        || value.contains("://")
        || value
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-'))
    {
        return false;
    }
    let base = strip_crypto_test_vector_public_suffix(value);
    is_nist_kas_ecc_test_case_id(base)
        || is_ffdhe_test_case_id(base)
        || is_role_named_curve_test_case_id(base)
        || is_standalone_named_curve_test_case_id(base)
        || is_edwards_test_case_id(base)
}

fn decode_hex_literal(value: &str) -> Option<Vec<u8>> {
    let bytes = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .as_bytes();
    if bytes.len() < 16
        || bytes.len() > 1024
        || !bytes.len().is_multiple_of(2)
        || !bytes.iter().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn is_segmented_hex_fixture_bytes(bytes: &[u8]) -> bool {
    let mut pos = 0;
    let mut segments = 0;
    while pos < bytes.len() {
        let repeated = same_byte_run_len(&bytes[pos..]);
        if repeated >= 4 {
            pos += repeated;
            segments += 1;
            continue;
        }
        let stepped = byte_progression_run_len(&bytes[pos..]);
        if stepped >= 8 {
            pos += stepped;
            segments += 1;
            continue;
        }
        return false;
    }
    segments > 0
}

fn same_byte_run_len(bytes: &[u8]) -> usize {
    let Some(first) = bytes.first() else {
        return 0;
    };
    bytes.iter().take_while(|byte| *byte == first).count()
}

fn byte_progression_run_len(bytes: &[u8]) -> usize {
    let Some(first) = bytes.first() else {
        return 0;
    };
    let Some(second) = bytes.get(1) else {
        return 1;
    };
    let step = i16::from(*second) - i16::from(*first);
    if step == 0 {
        return 1;
    }
    let mut len = 1;
    for pair in bytes.windows(2) {
        if i16::from(pair[1]) - i16::from(pair[0]) != step {
            break;
        }
        len += 1;
    }
    len
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn strip_crypto_test_vector_public_suffix(value: &str) -> &str {
    for suffix in [
        "-Peer-PUBLIC",
        "-peer-public",
        "-PUBLIC-Raw",
        "-public-raw",
        "-PUBLIC",
        "-public",
        "-PUB",
        "-pub",
        "-Peer",
        "-peer",
        "_PUB",
        "_pub",
        "-Raw",
        "-raw",
    ] {
        if let Some(base) = value.strip_suffix(suffix) {
            return base;
        }
    }
    value
}

fn is_nist_kas_ecc_test_case_id(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("KAS-ECC-") else {
        return false;
    };
    let Some((family, case)) = rest.rsplit_once("_C") else {
        return false;
    };
    !family.is_empty()
        && contains_nist_curve_family_marker(family)
        && !case.is_empty()
        && case.bytes().all(|b| b.is_ascii_digit())
}

fn contains_nist_curve_family_marker(value: &str) -> bool {
    // KAS-ECC CAVP identifiers use P/K/B curve family markers for prime,
    // Koblitz, and binary curves (`_P-256`, `_K-163`, `_B-233`).
    value.contains("_P-") || value.contains("_K-") || value.contains("_B-")
}

fn is_ffdhe_test_case_id(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("ffdhe") else {
        return false;
    };
    let (bits, case) = rest.split_once('-').unwrap_or((rest, ""));
    if !matches!(bits, "2048" | "3072" | "4096" | "6144" | "8192") {
        return false;
    }
    case.is_empty() || ((1..=3).contains(&case.len()) && case.bytes().all(|b| b.is_ascii_digit()))
}

fn is_role_named_curve_test_case_id(value: &str) -> bool {
    for prefix in ["ALICE_", "BOB_", "MALICE_", "Alice-", "Bob-", "Malice-"] {
        let Some(rest) = value.strip_prefix(prefix) else {
            continue;
        };
        let rest = rest.strip_prefix("cf_").unwrap_or(rest);
        return is_named_curve_test_case_suffix(rest);
    }
    false
}

fn is_standalone_named_curve_test_case_id(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if let Some(bits) = lower.strip_prefix("p-") {
        return !bits.is_empty() && bits.bytes().all(|b| b.is_ascii_digit());
    }
    is_named_curve_test_case_suffix(&lower)
        && (lower.contains("_rfc") || lower.contains("rfc") || lower.contains("brainpool"))
}

fn is_named_curve_test_case_suffix(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let known_prefix = [
        "secp",
        "sect",
        "prime",
        "c2pnb",
        "c2tnb",
        "brainpoolp",
        "wap-wsg-idm-ecid-wtls",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix));
    (known_prefix || lower == "25519" || lower == "448")
        && lower.bytes().any(|b| b.is_ascii_digit())
}

fn is_edwards_test_case_id(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some(case) = lower
        .strip_prefix("ed25519-")
        .or_else(|| lower.strip_prefix("ed448-"))
    else {
        return false;
    };
    !case.is_empty() && case.bytes().all(|b| b.is_ascii_digit())
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

/// True when a generic JSON `"key"` value is schema/UI metadata.
///
/// Rationale: some APIs use `"Key"` for tag labels, file names, or displayed
/// field names. Those are not credential bytes, but this is only safe for a
/// property literally named `key`; callers must prove that context first.
pub(crate) fn is_structured_generic_key_metadata_value(value: &str) -> bool {
    is_structured_key_name_reference_value(value)
        || is_generic_key_config_path_value(value)
        || is_generic_key_resource_name_value(value)
        || is_generic_key_label_value(value)
        || is_generic_key_file_reference_value(value)
}

/// True for i18n lookup expressions such as `$t(passwordLabel):`.
///
/// Rationale: these are localization keys rendered later by the application,
/// not credential material. The accepted syntax is deliberately narrow so
/// arbitrary `$...` passwords remain detectable.
pub(crate) fn is_localization_template_reference(value: &str) -> bool {
    let value = value.trim();
    let rest = value
        .strip_prefix("$t(")
        .or_else(|| value.strip_prefix("i18n.t("));
    let Some(rest) = rest else {
        return false;
    };
    let Some(close) = rest.find(')') else {
        return false;
    };
    let key = &rest[..close];
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        && rest[close + 1..]
            .chars()
            .all(|ch| ch.is_ascii_whitespace() || matches!(ch, ':' | '.'))
}

fn is_generic_key_config_path_value(value: &str) -> bool {
    let value = value.trim();
    if !(5..=128).contains(&value.len()) || !value.contains('.') || value.contains("://") {
        return false;
    }
    if normalize_identifier(value).split('_').any(|part| {
        matches!(
            part,
            "secret" | "password" | "passwd" | "credential" | "token" | "auth" | "private" | "key"
        )
    }) {
        return false;
    }
    value.split('.').all(|part| {
        (2..=48).contains(&part.len())
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
            && part.bytes().any(|b| b.is_ascii_lowercase())
    })
}

fn is_generic_key_resource_name_value(value: &str) -> bool {
    // Generic JSON `key` fields commonly store public label/header/resource
    // names in kebab syntax. Pure numeric parts and sensitive components are
    // excluded so low-entropy real values such as `tenant-7-trial` and
    // `sk-test-token` stay detectable. Digit-bearing platform acronyms such as
    // `k8s-app` remain metadata because they name infrastructure labels.
    let value = value.trim();
    if !(5..=96).contains(&value.len()) || !value.contains('-') {
        return false;
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'/' | b':'))
    {
        return false;
    }
    let normalized = normalize_identifier(value);
    if normalized.split('_').any(|part| {
        matches!(
            part,
            "secret" | "password" | "passwd" | "credential" | "token" | "auth" | "private" | "key"
        )
    }) {
        return false;
    }
    let parts = value
        .split(['-', '/', ':'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let has_digit = parts
        .iter()
        .any(|part| part.bytes().any(|b| b.is_ascii_digit()));
    parts.len() >= 2
        && (!has_digit
            || parts
                .iter()
                .any(|part| is_public_resource_digit_component(part)))
        && parts.iter().enumerate().all(|(idx, part)| {
            (part == &"x" && idx == 0 || (2..=32).contains(&part.len()))
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && part.bytes().any(|b| b.is_ascii_lowercase())
        })
}

fn is_public_resource_digit_component(part: &str) -> bool {
    matches!(
        part,
        "k8s" | "ipv4" | "ipv6" | "http2" | "s3" | "ec2" | "rds"
    )
}

fn is_generic_key_label_value(value: &str) -> bool {
    let value = value.trim();
    if !(3..=80).contains(&value.len()) || value.split_whitespace().count() < 2 {
        return false;
    }
    let normalized = normalize_identifier(value);
    if normalized.split('_').any(|part| {
        matches!(
            part,
            "secret" | "password" | "passwd" | "credential" | "token" | "auth" | "private" | "key"
        )
    }) {
        return false;
    }
    value.chars().all(|ch| {
        ch.is_ascii_alphabetic() || ch.is_ascii_whitespace() || matches!(ch, '-' | '\'' | '.')
    })
}

fn is_generic_key_file_reference_value(value: &str) -> bool {
    let value = value.trim();
    if !(5..=128).contains(&value.len())
        || value.contains("://")
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'@' | b'=' | b'?' | b'#'))
    {
        return false;
    }
    let Some((stem, ext)) = value.rsplit_once('.') else {
        return false;
    };
    if stem.is_empty()
        || stem.contains('/')
        || !stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return false;
    }
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "svg"
            | "ico"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "xml"
            | "txt"
            | "md"
            | "html"
            | "css"
            | "js"
            | "ts"
            | "map"
    )
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

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
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
        assert!(is_placeholder_value("something"));
        assert!(is_placeholder_value("value"));
        assert!(is_placeholder_value("whatever"));
        assert!(is_placeholder_value("dummy"));
        assert!(is_placeholder_value("ignored"));
        assert!(is_placeholder_value("fake_token"));
        assert!(is_placeholder_value("x-pack-test-password"));
        assert!(is_placeholder_value("avoid-plaintext-passwords"));
        assert!(is_placeholder_value("tftest-new-password"));
        assert!(is_placeholder_value("foobar"));
        assert!(is_placeholder_value("foo-bar"));
        assert!(is_placeholder_value("s3krit-password"));
        assert!(is_placeholder_value("TESTKEY"));
        assert!(is_placeholder_value("TESTSECRET"));
        assert!(is_placeholder_value("NEWTOKEN"));
        assert!(is_placeholder_value("privatetoken"));
        assert!(is_placeholder_value("not_my_secret"));
        assert!(!is_placeholder_value("s3krit-password2"));
        assert!(is_placeholder_value("t0k3n"));
        assert!(is_placeholder_value("notarealpassword"));
        assert!(is_placeholder_value("my_api_key"));
        assert!(is_placeholder_value("some-password"));
        assert!(is_placeholder_value("test-user-password"));
        assert!(is_placeholder_value("AAAA/AAA=AAAAAAAA"));
        assert!(is_placeholder_value("i*******************"));
        assert!(is_placeholder_value("ac******************"));
        assert!(is_placeholder_value("###ORACLE_PWD###"));
        assert!(is_placeholder_value(
            "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__"
        ));
        assert!(!is_placeholder_value("tenant-7-trial"));
        assert!(!is_placeholder_value(
            "https://example.org/path?token=abc123"
        ));
        assert!(!is_placeholder_value("letmein123"));
        assert!(!is_placeholder_value("pass"));
        assert!(!is_placeholder_value("changeme"));
        assert!(!is_placeholder_value("admin123"));
        assert!(!is_placeholder_value("Password1"));
        assert!(!is_placeholder_value("Test Access Token"));
        assert!(!is_placeholder_value("PROD_SECRET"));
        assert!(!is_placeholder_value("OLD_LET_ME_IN-1"));
        assert!(!is_placeholder_value("secret1"));
        assert!(!is_placeholder_value("my-service-token-2026"));
        assert!(!is_placeholder_value("abc***def123"));
        assert!(!is_placeholder_value("__PROD_SECRET__"));
        assert!(!is_placeholder_value("###tenant-7-trial###"));
    }

    #[test]
    fn non_secret_keys_are_explicit_only() {
        assert!(is_explicitly_non_sensitive_key_name("publicKeyToken"));
        assert!(is_explicitly_non_sensitive_key_name("non_secret"));
        assert!(is_explicitly_non_sensitive_key_name("correlationKey"));
        assert!(is_explicitly_non_sensitive_key_name("TopologyKey"));
        assert!(is_explicitly_non_sensitive_key_name("apiKeyName"));
        assert!(is_explicitly_non_sensitive_key_name("authMethod"));
        assert!(is_explicitly_non_sensitive_key_name(
            "serverHostKeyAlgorithm"
        ));
        assert!(is_explicitly_non_sensitive_key_name("passwordLastUsed"));
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
        assert!(is_source_secret_name_reference_value("bot_api_token"));
        assert!(is_source_secret_name_reference_value("private-token"));
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
        assert!(is_source_fixture_secret_value("dummyLocation", "testing"));
        assert!(is_source_fixture_secret_value("fake_secret", "secret"));
        assert!(is_source_fixture_secret_sample_value("test123"));
        assert!(is_source_fixture_secret_sample_value("default-password"));
        assert!(!is_source_fixture_secret_value("password", "pass"));
        assert!(!is_source_fixture_secret_value("access_token", "LET_ME_IN"));
        assert!(!is_source_fixture_secret_sample_value("tenant-7-trial"));
        assert!(!is_source_fixture_secret_value(
            "expectedPassword",
            "hunter2"
        ));
        assert!(is_source_fixture_key_context("examplePassword"));
        assert!(is_source_fixture_key_context("expectPassword"));
        assert!(is_source_fixture_key_context("stubToken"));
        assert!(is_source_fixture_key_context("requestSpecPassword"));
        assert!(!is_source_fixture_key_context("access_token"));
    }

    #[test]
    fn crypto_test_vector_identifiers_are_shape_gated() {
        assert!(is_crypto_test_vector_identifier_value(
            "KAS-ECC-CDH_P-192_C0"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "KAS-ECC-CDH_K-163_C0"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "KAS-ECC-CDH_B-233_C0"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "KAS-ECC-CDH_P-192_C0:KAS-ECC-CDH_P-192_C0-PUBLIC"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "ALICE_secp112r1_PUB"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "BOB_cf_brainpoolP160r1"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "Alice-25519:Alice-25519-PUBLIC"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "ED25519-1-PUBLIC-Raw"
        ));
        assert!(is_crypto_test_vector_identifier_value("ffdhe2048-1"));
        assert!(is_crypto_test_vector_identifier_value("ffdhe3072-2-pub"));
        assert!(is_crypto_test_vector_identifier_value(
            "ffdhe4096-1:ffdhe4096-1-pub"
        ));
        assert!(is_crypto_test_vector_identifier_value("ffdhe8192"));
        assert!(is_crypto_test_vector_identifier_value("P-256"));
        assert!(is_crypto_test_vector_identifier_value("P-256-Peer"));
        assert!(is_crypto_test_vector_identifier_value(
            "PRIME192V1_RFC5114:PRIME192V1_RFC5114-PUBLIC"
        ));
        assert!(is_crypto_test_vector_identifier_value(
            "SECP224R1_RFC5114-Peer"
        ));
        assert!(!is_crypto_test_vector_identifier_value("tenant-7-trial"));
        assert!(!is_crypto_test_vector_identifier_value(
            "ALICE_prod_key_2026"
        ));
        assert!(!is_crypto_test_vector_identifier_value(
            "KAS-ECC-CDH_P-192_SECRET"
        ));
        assert!(!is_crypto_test_vector_identifier_value("ffdhe1234-1"));
        assert!(!is_crypto_test_vector_identifier_value(
            "ffdhe2048-prod-key"
        ));
    }

    #[test]
    fn synthetic_hex_test_vectors_are_shape_gated() {
        assert!(is_synthetic_hex_test_vector_value(
            "000102030405060708090A0B0C0D0E0F"
        ));
        assert!(is_synthetic_hex_test_vector_value(
            "00112233445566778899AABBCCDDEEFF"
        ));
        assert!(is_synthetic_hex_test_vector_value(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ));
        assert!(!is_synthetic_hex_test_vector_value(
            "000000000000000036E5F6B5C5E06070F0EFCA96227A863E"
        ));
        assert!(!is_synthetic_hex_test_vector_value(
            "A3F19C80E4B27D51F09A6C33D8E74215"
        ));
        assert!(!is_synthetic_hex_test_vector_value(
            "ACME_SECRET_TOKEN_0123456789abcdef"
        ));
        assert!(!is_synthetic_hex_test_vector_value("tenant-7-trial"));
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
        assert!(is_structured_key_name_reference_value("Token"));
        assert!(is_structured_key_name_reference_value("refresh_token"));
        assert!(is_structured_key_name_reference_value("smsCode"));
        assert!(is_structured_key_name_reference_value("signature"));
        assert!(is_structured_key_name_reference_value("unknown"));
        assert!(is_structured_key_name_reference_value("offset"));
        assert!(is_structured_key_name_reference_value("host"));
        assert!(is_structured_key_name_reference_value("Vary"));
        assert!(is_structured_key_name_reference_value("Proxy-Connection"));
        assert!(is_structured_key_name_reference_value("X-Correlation-Id"));
        assert!(is_structured_key_name_reference_value("product_id"));
        assert!(is_structured_key_name_reference_value("user_ids"));
        assert!(is_structured_key_name_reference_value("source1"));
        assert!(is_structured_key_name_reference_value("panel1"));
        assert!(is_structured_key_name_reference_value("fieldset1"));
        assert!(is_structured_key_name_reference_value("dataGrid12"));
        assert!(is_structured_key_name_reference_value("field_values"));
        assert!(is_structured_key_name_reference_value(
            "connection_policies"
        ));
        assert!(is_structured_key_name_reference_value(
            "task_queues_statistics"
        ));
        assert!(is_structured_key_name_reference_value("table1"));
        assert!(is_structured_key_name_reference_value("checkbox2"));
        assert!(!is_structured_key_name_reference_value("password"));
        assert!(!is_structured_key_name_reference_value("secret"));
        assert!(!is_structured_key_name_reference_value("abcDEF123456"));
        assert!(!is_structured_key_name_reference_value("sk-test-token"));
    }

    #[test]
    fn generic_key_metadata_values_require_plain_metadata_shape() {
        assert!(is_structured_generic_key_metadata_value(
            "Dev Gateway Region"
        ));
        assert!(is_structured_generic_key_metadata_value("HappyFace.jpg"));
        assert!(is_structured_generic_key_metadata_value("access-project"));
        assert!(is_structured_generic_key_metadata_value("cost-center"));
        assert!(is_structured_generic_key_metadata_value(
            "clean-cilium-state"
        ));
        assert!(is_structured_generic_key_metadata_value(
            "x-amazon-apigateway-authtype"
        ));
        assert!(is_structured_generic_key_metadata_value(
            "idle_timeout.timeout_seconds"
        ));
        assert!(is_structured_generic_key_metadata_value(
            "access_logs.s3.bucket"
        ));
        assert!(is_structured_generic_key_metadata_value(
            "Access-Control-Allow-Headers"
        ));
        assert!(is_structured_generic_key_metadata_value("k8s-app"));
        assert!(is_structured_generic_key_metadata_value(
            "ovn4nfv-k8s-plugin"
        ));
        assert!(is_structured_generic_key_metadata_value("string"));
        assert!(is_structured_generic_key_metadata_value("FirstTag"));
        assert!(is_structured_generic_key_metadata_value("foo2"));
        assert!(is_structured_generic_key_metadata_value("item1"));
        assert!(is_structured_generic_key_metadata_value("step0"));
        assert!(is_structured_generic_key_metadata_value("remote_cluster"));
        assert!(is_structured_generic_key_metadata_value("schema_versions"));
        assert!(is_structured_generic_key_metadata_value("credential_lists"));
        assert!(!is_structured_generic_key_metadata_value("remote_token"));
        assert!(!is_structured_generic_key_metadata_value("cluster_secret"));
        assert!(!is_structured_generic_key_metadata_value("API Key"));
        assert!(!is_structured_generic_key_metadata_value("secret token"));
        assert!(!is_structured_generic_key_metadata_value("sk-test-token"));
        assert!(!is_structured_generic_key_metadata_value("tenant-7-trial"));
        assert!(!is_structured_generic_key_metadata_value("abcDEF123456"));
        assert!(!is_structured_generic_key_metadata_value("secret.value"));
    }

    #[test]
    fn localization_template_references_are_syntactic() {
        assert!(is_localization_template_reference(
            "$t(lockRoomPasswordUppercase):"
        ));
        assert!(is_localization_template_reference(
            "i18n.t(auth.setup.instructions)"
        ));
        assert!(!is_localization_template_reference("$topsecret123"));
        assert!(!is_localization_template_reference("$t(secret) + suffix"));
    }
}
