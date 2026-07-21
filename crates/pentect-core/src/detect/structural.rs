use super::benign::{
    is_explicitly_non_sensitive_key_name, is_localization_template_reference, is_placeholder_value,
    is_source_secret_name_reference_value, is_structured_generic_key_metadata_value,
    normalize_identifier,
};
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use std::sync::LazyLock;

static SENSITIVE_HEADERS: LazyLock<Vec<String>> =
    LazyLock::new(|| parse_sensitive_headers(include_str!("sensitive_header_names.txt")));

/// Masks values that are sensitive by protocol-defined structural position: a
/// cookie value or a credential-bearing HTTP header. Bounded and protocol-
/// grounded, so it is separate from key-name based structured value masking.
pub struct StructuralDetector;

/// `.env` value regions are masked wholesale. The parser already strips the
/// structural shell, so the core can treat every non-placeholder value as
/// secret without key-name guessing.
pub struct EnvValueDetector;

/// Masks values under explicit structured key/path context supplied by a parser.
/// It emits spans only; rendering and recovery remain the pipeline's job.
pub struct SensitiveKeyDetector;

impl Detector for StructuralDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty() || is_benign_value(view.text()) {
            return vec![];
        }
        let fire = match region.ctx.kind {
            RegionKind::Cookie => true,
            RegionKind::Header => region
                .ctx
                .key
                .as_deref()
                .is_some_and(is_sensitive_header_name),
            _ => false,
        };
        if !fire {
            return vec![];
        }
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label: labels::SECRET.to_string(),
            // Medium so a specific vendor rule keeps its label where it overlaps,
            // while structural still beats raw entropy.
            confidence: Confidence::Medium,
            source: DetectorId::Structural,
        }]
    }
}

fn parse_sensitive_headers(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_ascii_lowercase())
        .collect()
}

fn is_sensitive_header_name(header: &str) -> bool {
    // Closed list loaded from sensitive_header_names.txt. These names are
    // protocol-defined credential/cookie carriers, not arbitrary "token" words.
    let header = header.trim().to_ascii_lowercase();
    SENSITIVE_HEADERS.iter().any(|known| known == &header)
}

impl Detector for EnvValueDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty()
            || region.ctx.format != Kind::Env
            || is_rendered_placeholder(view.text())
        {
            return vec![];
        }
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label: labels::SECRET.to_string(),
            confidence: Confidence::High,
            source: DetectorId::Structural,
        }]
    }
}

impl Detector for SensitiveKeyDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let region = view.region;
        if region.span.is_empty() || is_benign_value(view.text()) {
            return vec![];
        }
        if region.ctx.kind != RegionKind::JsonValue {
            return vec![];
        }
        if is_localization_template_reference(view.text()) {
            return vec![];
        }
        if region.ctx.key.as_deref().is_some_and(|key| {
            is_ui_copy_sensitive_key(key, view.text())
                || is_structured_localization_label_value(key, view.text())
                || is_structured_token_prose(key, view.text())
                || is_structured_placeholder_value(key, view.text())
                || is_structured_secret_identifier_name(key, view.text())
                || is_structured_sensitive_name_reference(key, view.text())
                || is_structured_generic_key_weak_value(key, view.text())
                || is_structured_generic_key_name_reference(key, view.text())
                || is_structured_api_operation_value(key, view.text())
        }) {
            return vec![];
        }
        let Some(label) = sensitive_context_label(&region.ctx) else {
            return vec![];
        };
        vec![Span {
            range: region.span,
            category: Category::Secret,
            label,
            confidence: Confidence::High,
            source: DetectorId::Structural,
        }]
    }
}

fn sensitive_context_label(ctx: &Context) -> Option<String> {
    if let Some(key) = ctx.key.as_deref().filter(|key| is_sensitive_key_name(key)) {
        return Some(sensitive_label_for_key(key));
    }
    if let Some(hint) = ctx.hints.iter().find(|hint| is_sensitive_key_name(hint)) {
        return Some(sensitive_label_for_key(hint));
    }
    ctx.path
        .as_deref()?
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .find(|segment| is_sensitive_key_name(segment))
        .map(sensitive_label_for_key)
}

fn is_sensitive_key_name(key: &str) -> bool {
    let name = normalize_identifier(key);
    if is_explicitly_non_sensitive_key(&name) || is_non_credential_sensitive_word_name(&name) {
        return false;
    }
    name == "key"
        || name == "auth"
        || name == "authorization"
        || name.contains("auth_")
        || name.contains("_auth")
        || name.contains("authorization")
        || [
            "api_key",
            "apikey",
            "access_key",
            "secret",
            "token",
            "password",
            "passwd",
            "passcode",
            "private",
            "credential",
            "otp",
            "totp",
            "mfa",
            "2fa",
            "verification_code",
            "verificationcode",
            "security_code",
            "securitycode",
            "login_code",
            "logincode",
            "signin_code",
            "signincode",
            "one_time",
            "onetime",
            "session",
            "cookie",
            "jwt",
            "bearer",
        ]
        .iter()
        .any(|needle| name.contains(needle))
}

fn is_non_credential_sensitive_word_name(name: &str) -> bool {
    // Some technical names contain sensitive substrings but identify public
    // concepts: parsers/tokenizers, UI labels/tooltips, or API operation names.
    // Reject them before broad key-name matching so `tokenizer` does not become
    // `token`, while actual fields such as `access_token` still pass.
    let parts = name
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return false;
    }
    if parts
        .iter()
        .any(|part| matches!(*part, "tokenizer" | "tokenizers"))
        || has_structural_phrase(&parts, &["token", "sale"])
        || parts.last().is_some_and(|part| *part == "arn")
        || is_last_used_metadata_name(&parts)
        || has_structural_phrase(&parts, &["password", "cannot", "be", "empty"])
        || parts
            .iter()
            .any(|part| matches!(*part, "tooltip" | "label" | "title"))
    {
        return true;
    }
    is_sentence_like_key_name(&parts)
}

fn is_sentence_like_key_name(parts: &[&str]) -> bool {
    // Translation/test names can be whole sentences:
    // `log_in_with_the_admin_user_credentials_without...`. Long prose-like keys
    // are not storage fields, even if they contain `password` or `credentials`.
    parts.len() >= 8
        && parts.iter().any(|part| {
            matches!(
                *part,
                "with"
                    | "without"
                    | "the"
                    | "this"
                    | "about"
                    | "via"
                    | "before"
                    | "after"
                    | "should"
                    | "challenge"
            )
        })
}

fn is_api_operation_name(parts: &[&str]) -> bool {
    // AWS/OpenAPI model names such as `GetSecretValue`,
    // `AdminResetUserPassword`, and `ListSecrets` name operations. A concrete
    // response field under those operations can still be caught by its own key.
    let Some(first) = parts.first().copied() else {
        return false;
    };
    let verb = if first == "admin" && parts.len() >= 2 {
        parts[1]
    } else {
        first
    };
    matches!(
        verb,
        "get"
            | "list"
            | "create"
            | "delete"
            | "describe"
            | "put"
            | "update"
            | "set"
            | "reset"
            | "restore"
            | "rotate"
            | "cancel"
            | "initiate"
            | "respond"
    ) && parts
        .iter()
        .any(|part| matches!(*part, "secret" | "secrets" | "password" | "auth" | "token"))
}

fn is_structured_api_operation_value(key: &str, value: &str) -> bool {
    // Operation/model names can contain credential words (`GetSecretValue`,
    // `AdminResetUserPassword`) without carrying the secret itself. This is
    // value-aware on purpose: a field named `set_auth_token` still masks a
    // concrete value such as `hunter2`.
    let key_name = normalize_identifier(key);
    let key_parts = identifier_parts(&key_name);
    if !is_api_operation_name(&key_parts) {
        return false;
    }
    let value_name = normalize_identifier(value);
    let value_parts = identifier_parts(&value_name);
    !value_parts.is_empty() && is_api_operation_name(&value_parts)
}

fn identifier_parts(name: &str) -> Vec<&str> {
    name.split('_').filter(|part| !part.is_empty()).collect()
}

fn is_last_used_metadata_name(parts: &[&str]) -> bool {
    parts.iter().any(|part| matches!(*part, "last"))
        && parts
            .iter()
            .any(|part| matches!(*part, "used" | "authenticated" | "time"))
}

fn has_structural_phrase(parts: &[&str], phrase: &[&str]) -> bool {
    !phrase.is_empty()
        && parts.len() >= phrase.len()
        && parts
            .windows(phrase.len())
            .any(|window| window.iter().zip(phrase).all(|(part, word)| part == word))
}

fn is_ui_copy_sensitive_key(key: &str, value: &str) -> bool {
    // Translation/resource JSON often uses password/token words in UI message
    // identifiers (`incorrectPassword`, `tokenAuthFailed`,
    // `passwordNotSupportedTitle`). Those values are prose, not credentials.
    // Require both a UI-state/action component in the key and prose/localization
    // shape in the value so compact real secrets under `password` still detect.
    let name = normalize_identifier(key);
    let has_sensitive_word = name.split('_').any(|part| {
        matches!(
            part,
            "password" | "passwords" | "token" | "auth" | "authentication" | "credential"
        )
    }) || name.contains("token");
    if !has_sensitive_word {
        return false;
    }
    let has_ui_component = [
        "broken",
        "category",
        "add",
        "cancel",
        "changed",
        "current",
        "dialog",
        "forgot",
        "failed",
        "field",
        "incorrect",
        "invalid",
        "label",
        "length",
        "lock",
        "mandatory",
        "message",
        "new",
        "no",
        "not",
        "only",
        "prompt",
        "remove",
        "removed",
        "required",
        "room",
        "set",
        "setup",
        "successfully",
        "supported",
        "instruction",
        "instructions",
        "text",
        "title",
        "button",
        "advice",
        "uppercase",
        "digits",
        "matching",
    ]
    .iter()
    .any(|component| name.split('_').any(|part| part == *component));
    has_ui_component && is_prose_or_localization_value(value)
}

fn is_prose_or_localization_value(value: &str) -> bool {
    let value = value.trim();
    value.contains("$t(")
        || value.split_whitespace().count() >= 2
        || !value.is_ascii()
        || value.ends_with(['.', ':', '!', '?'])
        || is_short_ui_label_value(value)
}

fn is_short_ui_label_value(value: &str) -> bool {
    // Button/field/label/title keys often map to a single visible word such as
    // "Password". A real token/password can be low entropy too, so this helper
    // is only reached after the key has explicit UI/action components.
    (2..=32).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && !value.bytes().any(|b| b.is_ascii_digit())
        && value.chars().all(|ch| {
            ch.is_ascii_alphabetic() || ch.is_whitespace() || matches!(ch, '-' | '\'' | '_')
        })
}

fn is_structured_localization_label_value(key: &str, value: &str) -> bool {
    // Translation JSON often has bare label keys such as `token`,
    // `userPassword`, and `sessionToken`. Their values are displayed labels in
    // many languages, not credentials. This is deliberately narrower than
    // `is_ui_copy_sensitive_key`: require a label-shaped key and either a value
    // that normalizes back to the key words or a short non-ASCII display label.
    let name = normalize_identifier(key);
    if !is_localization_label_key(&name) {
        return false;
    }
    let value = value.trim();
    is_key_equivalent_display_label(&name, value) || is_short_non_ascii_display_label(value)
}

fn is_localization_label_key(name: &str) -> bool {
    let parts = identifier_parts(name);
    if parts.is_empty() {
        return false;
    }
    let has_sensitive = parts.iter().any(|part| {
        matches!(
            *part,
            "password"
                | "passwords"
                | "token"
                | "tokens"
                | "credential"
                | "credentials"
                | "auth"
                | "authentication"
        )
    });
    has_sensitive
        && (matches!(
            name,
            "password" | "token" | "user_password" | "session_token" | "lock_room_password"
        ) || parts.iter().any(|part| {
            matches!(
                *part,
                "user" | "session" | "room" | "meeting" | "lock" | "label" | "title"
            )
        }))
}

fn is_key_equivalent_display_label(key_name: &str, value: &str) -> bool {
    let value_name = normalize_identifier(value);
    if value_name.is_empty() {
        return false;
    }
    let key_parts = identifier_parts(key_name);
    let value_parts = identifier_parts(&value_name);
    !value_parts.is_empty()
        && value_parts
            .iter()
            .all(|part| key_parts.iter().any(|key_part| key_part == part))
}

fn is_short_non_ascii_display_label(value: &str) -> bool {
    let value = value.trim().trim_end_matches(':');
    (1..=72).contains(&value.chars().count())
        && !value.is_ascii()
        && !value.chars().any(|ch| ch.is_ascii_digit())
        && value.chars().all(|ch| {
            ch.is_alphabetic()
                || ch.is_whitespace()
                || matches!(ch, '-' | '\'' | ':' | '\u{200f}' | '\u{200e}')
        })
}

fn is_structured_token_prose(key: &str, value: &str) -> bool {
    // Structured token fields must contain compact token material. Fixture/UI
    // prose such as "Test Access Token" is not a usable bearer/session token.
    let name = normalize_identifier(key);
    let is_token_key = name == "token"
        || name.ends_with("_token")
        || name.contains("_token_")
        || name == "access_token"
        || name == "refresh_token"
        || name == "id_token";
    is_token_key && value.chars().any(char::is_whitespace)
}

fn is_structured_placeholder_value(_key: &str, value: &str) -> bool {
    // JSON/YAML schemas commonly put type names under sensitive-looking fields
    // (`token: string`). Do not apply a general shape gate here: explicit
    // credential keys can hold weak but usable values (`token: abcdef`,
    // `refresh_token: refresh`, `user:pass`).
    is_schema_type_placeholder(value)
}

fn is_structured_secret_identifier_name(key: &str, value: &str) -> bool {
    // `SecretId`/`secret_id` in cloud APIs identifies a secret resource. The
    // resource name (`MyTestDatabaseSecret`) is sensitive metadata at most, not
    // the secret bytes. Concrete secret values still fire under `secret`,
    // `secret_key`, or keyed detectors.
    let name = normalize_identifier(key);
    matches!(name.as_str(), "secret_id" | "secretid") && is_public_resource_identifier_value(value)
}

fn is_structured_sensitive_name_reference(key: &str, value: &str) -> bool {
    // Structured payloads sometimes contain the name of a credential field under
    // a credential-looking key (`access_token: "secret-access-token"`). Reuse
    // the source-name matcher so this stays vocabulary-driven, and require
    // separator syntax/no digits so concrete token material remains visible.
    if !is_sensitive_key_name(key) {
        return false;
    }
    let value = value.trim();
    (4..=96).contains(&value.len())
        && value.bytes().any(|b| matches!(b, b'_' | b'-'))
        && !value.bytes().any(|b| b.is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        && is_source_secret_name_reference_value(value)
}

fn is_public_resource_identifier_value(value: &str) -> bool {
    let value = value.trim();
    (3..=128).contains(&value.len())
        && !value.contains("://")
        && !value.chars().any(char::is_whitespace)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':'))
        && value.bytes().any(|b| b.is_ascii_alphabetic())
}

fn is_structured_generic_key_weak_value(key: &str, value: &str) -> bool {
    // A literal JSON `"key"` often means "field name" or "keyboard shortcut".
    // Do not let the generic word alone mask low-shape names; values with token
    // punctuation, digits plus mixed case, or sufficient length remain visible.
    if normalize_identifier(key) != "key" {
        return false;
    }
    let value = value.trim();
    is_keyboard_shortcut_value(value) || !generic_key_value_has_secret_shape(value)
}

fn is_keyboard_shortcut_value(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let parts = normalized.split('+').collect::<Vec<_>>();
    (2..=4).contains(&parts.len())
        && parts.iter().all(|part| {
            matches!(
                part.trim(),
                "ctrl"
                    | "control"
                    | "shift"
                    | "alt"
                    | "option"
                    | "cmd"
                    | "command"
                    | "meta"
                    | "win"
                    | "enter"
                    | "return"
                    | "tab"
                    | "esc"
                    | "escape"
            ) || part.trim().len() == 1 && part.trim().bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

fn generic_key_value_has_secret_shape(value: &str) -> bool {
    let value = value.trim();
    let len = value.chars().count();
    let has_upper = value.chars().any(|ch| ch.is_ascii_uppercase());
    let has_lower = value.chars().any(|ch| ch.is_ascii_lowercase());
    let has_alpha = has_upper || has_lower;
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_ascii_whitespace());
    len >= 24 || (len >= 6 && has_alpha && (has_digit || has_symbol))
}

fn is_schema_type_placeholder(value: &str) -> bool {
    matches!(
        normalize_identifier(value).as_str(),
        "string"
            | "str"
            | "number"
            | "integer"
            | "int"
            | "boolean"
            | "bool"
            | "object"
            | "array"
            | "null"
    )
}

fn is_structured_generic_key_name_reference(key: &str, value: &str) -> bool {
    // Generic JSON `"key"` fields often contain another field/config name
    // (`smtpUser`, `databaseName`). Concrete key values usually contain digits,
    // token punctuation, or entropy and remain eligible for masking.
    normalize_identifier(key) == "key" && is_structured_generic_key_metadata_value(value)
}

fn is_explicitly_non_sensitive_key(name: &str) -> bool {
    is_explicitly_non_sensitive_key_name(name)
}

fn sensitive_label_for_key(key: &str) -> String {
    if is_otp_key_name(key) {
        labels::OTP.to_string()
    } else {
        forced_label(key)
    }
}

fn is_otp_key_name(key: &str) -> bool {
    let name = normalize_key(key);
    [
        "otp",
        "totp",
        "mfa",
        "2fa",
        "passcode",
        "verification_code",
        "verificationcode",
        "security_code",
        "securitycode",
        "login_code",
        "logincode",
        "signin_code",
        "signincode",
        "one_time",
        "onetime",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

fn forced_label(key: &str) -> String {
    let mut out = String::new();
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        labels::SECRET.to_string()
    } else {
        out
    }
}

fn normalize_key(key: &str) -> String {
    let mut out = String::new();
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

/// Values that are never secrets even in a sensitive position: empty, JSON
/// literals, or an already-rendered placeholder (idempotency).
fn is_benign_value(v: &str) -> bool {
    let t = v.trim();
    t.is_empty()
        || matches!(t, "true" | "false" | "null")
        || is_rendered_placeholder(t)
        || is_version_literal(t)
        || is_documentation_placeholder(t)
}

fn is_documentation_placeholder(value: &str) -> bool {
    // Structural masking protects broad boundaries such as `.env`. We still
    // spare values that explicitly identify themselves as examples or redacted
    // placeholders; otherwise every sample config becomes a false positive wall.
    is_placeholder_value(value)
}

fn is_version_literal(value: &str) -> bool {
    let t = value
        .trim_start_matches(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '^' | '~'))
        .trim();
    if matches!(t, "*" | "latest") {
        return true;
    }
    if !(3..=96).contains(&t.len()) {
        return false;
    }
    let mut saw_digit = false;
    let mut saw_dot = false;
    for token in t.split_whitespace() {
        if matches!(token, "||" | "|" | "&&") {
            continue;
        }
        let token = token.trim_start_matches(['^', '~', '=', '<', '>']);
        if token.is_empty() || token == "*" || token.eq_ignore_ascii_case("latest") {
            continue;
        }
        if !token.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
            return false;
        }
        saw_digit = true;
        saw_dot |= token.contains('.');
        if !token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'*' | b'x' | b'X')
        }) {
            return false;
        }
    }
    saw_digit && saw_dot
}

fn is_rendered_placeholder(v: &str) -> bool {
    v.starts_with("<<") && v.ends_with(">>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(kind: RegionKind, format: Kind, key: Option<&str>, value: &str) -> bool {
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: key.map(str::to_string),
                hints: Vec::new(),
                kind,
                format,
            },
        };
        !StructuralDetector
            .detect(&NormalizedView::build(&region, &raw))
            .is_empty()
    }

    fn env_fires(key: Option<&str>, value: &str) -> bool {
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: key.map(str::to_string),
                hints: Vec::new(),
                kind: RegionKind::Body,
                format: Kind::Env,
            },
        };
        !EnvValueDetector
            .detect(&NormalizedView::build(&region, &raw))
            .is_empty()
    }

    fn sensitive_key_fires(key: Option<&str>, value: &str) -> Option<String> {
        sensitive_key_fires_with_path(None, key, value)
    }

    fn sensitive_key_fires_with_path(
        path: Option<&str>,
        key: Option<&str>,
        value: &str,
    ) -> Option<String> {
        sensitive_key_fires_with_context(path, key, &[], value)
    }

    fn sensitive_key_fires_with_context(
        path: Option<&str>,
        key: Option<&str>,
        hints: &[&str],
        value: &str,
    ) -> Option<String> {
        let raw = value.to_string();
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: path.map(str::to_string),
                key: key.map(str::to_string),
                hints: hints.iter().map(|hint| hint.to_string()).collect(),
                kind: RegionKind::JsonValue,
                format: Kind::ToolResult,
            },
        };
        SensitiveKeyDetector
            .detect(&NormalizedView::build(&region, &raw))
            .into_iter()
            .next()
            .map(|span| span.label)
    }

    #[test]
    fn cookie_values_fire_by_structure() {
        assert!(fires(
            RegionKind::Cookie,
            Kind::Har,
            Some("anyname"),
            "sessabc123"
        ));
        assert!(fires(RegionKind::Cookie, Kind::Har, None, "x"));
    }

    #[test]
    fn sensitive_headers_fire_benign_headers_do_not() {
        assert!(fires(
            RegionKind::Header,
            Kind::Har,
            Some("Authorization"),
            "Bearer x"
        ));
        assert!(fires(
            RegionKind::Header,
            Kind::Har,
            Some("Proxy-Authorization"),
            "Basic dXNlcjpwYXNz"
        ));
        assert!(fires(RegionKind::Header, Kind::Har, Some("cookie"), "a=b"));
        assert!(fires(
            RegionKind::Header,
            Kind::Har,
            Some("Set-Cookie"),
            "sid=abc"
        ));
        assert!(!fires(
            RegionKind::Header,
            Kind::Har,
            Some("Content-Type"),
            "application/json"
        ));
        assert!(!fires(RegionKind::Header, Kind::Har, Some("Accept"), "*/*"));
        assert!(!fires(
            RegionKind::Header,
            Kind::Har,
            Some("WWW-Authenticate"),
            "Bearer realm=\"example\""
        ));
    }

    #[test]
    fn arbitrary_keys_are_not_guessed() {
        // Protocol structural masking itself does not guess key names; that is
        // handled by SensitiveKeyDetector with JsonValue context.
        assert!(!fires(
            RegionKind::JsonValue,
            Kind::Har,
            Some("password"),
            "hunter2"
        ));
        assert!(!fires(
            RegionKind::Body,
            Kind::Har,
            Some("db_password"),
            "hunter2"
        ));
    }

    #[test]
    fn env_values_fire_wholesale() {
        assert!(env_fires(Some("TEST_SECRET"), "114514810"));
        assert!(env_fires(Some("USERNAME"), "alice"));
        assert!(env_fires(Some("FLAG"), "false"));
        assert!(!env_fires(Some("USERNAME"), "<<SECRET_0123456789abcdef>>"));
    }

    #[test]
    fn sensitive_key_detector_uses_explicit_key_context() {
        assert_eq!(
            sensitive_key_fires(Some("password"), "hunter2"),
            Some("PASSWORD".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("otp"), "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("verificationCode"), "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("One-time passcode"), "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(sensitive_key_fires(Some("note"), "hello"), None);
        assert_eq!(sensitive_key_fires(None, "hunter2"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "seedUser"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "smtpDomain"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "apiKey"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "Authorization"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "Content-Type"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "grant_type"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "scope"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "firstName"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "phoneNumber"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "Token"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "refresh_token"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "smsCode"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "signature"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "unknown"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "offset"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "host"), None);
        assert_eq!(sensitive_key_fires(Some("token_type"), "bearer"), None);
        assert_eq!(
            sensitive_key_fires(Some("x-amazon-apigateway-authtype"), "awsSigv4"),
            None
        );
        assert_eq!(sensitive_key_fires(Some("filler_token"), "sentinel"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "path"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "Team"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "shift+ctrl+i"), None);
        assert_eq!(
            sensitive_key_fires(Some("key"), "hunter2"),
            Some("KEY".to_string())
        );
        assert_eq!(sensitive_key_fires(Some("key"), "Vary"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "Dev Gateway Region"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "HappyFace.jpg"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "cost-center"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "panel1"), None);
        assert_eq!(sensitive_key_fires(Some("key"), "dataGrid12"), None);
        assert_eq!(
            sensitive_key_fires(Some("key"), "abcDEF123456"),
            Some("KEY".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("key"), "sk-test-token"),
            Some("KEY".to_string())
        );
        assert_eq!(
            sensitive_key_fires_with_path(Some("structured.credentials.id"), Some("id"), "abc123"),
            Some("CREDENTIALS".to_string())
        );
        assert_eq!(
            sensitive_key_fires_with_context(None, Some("value"), &["One-time passcode"], "100482"),
            Some("OTP".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("nonSecret"), "invoice INV-100482"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("public_token_label"), "visible docs"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("incorrectPassword"), "Name or password is wrong"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("tokenAuthFailedTitle"), "Authentication failed"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("passwordSetRemotely"),
                "$t(lockRoomPassword) was set remotely"
            ),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("lockRoomPassword"), "Meeting password"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("lockRoomPassword"), "Password"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("enableDialogPasswordField"), "Password"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("enterPasswordButton"), "Join"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("noPassword"), "No password is set"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("passwordDigitsOnly"), "Digits only"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("authDropboxText"), "Connect your Dropbox account"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("mandatoryNewPassword"), "New password is required"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("showPasswordAdvice"), "Show password advice"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("passwordSuccessfullyChanged"),
                "Password successfully changed"
            ),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("forgotPassword"), "Forgot your password?"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("invalidPasswordLength"), "Password length is invalid"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("passwordsNotMatching"), "Passwords do not match"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("categoryBrokenAuthentication"),
                "Broken authentication"
            ),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("title_tokensale"), "Token sale"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("password"), "$t(lockRoomPasswordUppercase):"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("2FA_AUTH_SETUP_INSTRUCTIONS"),
                "Secure your account with an additional factor. Scan the QR code."
            ),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("access_token"), "Test Access Token"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("access_token"), "secret-access-token"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("refresh_token"), "secret-refresh-token"),
            None
        );
        assert_eq!(sensitive_key_fires(Some("token"), "Token"), None);
        assert_eq!(
            sensitive_key_fires(Some("userPassword"), "user password"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("sessionToken"), "Token de la session"),
            None
        );
        assert_eq!(
            sensitive_key_fires(
                Some("userPassword"),
                "\u{30e6}\u{30fc}\u{30b6}\u{30fc}\u{30d1}\u{30b9}\u{30ef}\u{30fc}\u{30c9}"
            ),
            None
        );
        assert_eq!(sensitive_key_fires(Some("token"), "string"), None);
        assert_eq!(
            sensitive_key_fires(Some("js-tokens"), "^3.0.0 || ^4.0.0"),
            None
        );
        assert_eq!(sensitive_key_fires(Some("parse-passwd"), "~1.0.0"), None);
        assert_eq!(sensitive_key_fires(Some("tokenizer"), "standard"), None);
        assert_eq!(
            sensitive_key_fires(Some("learn_about_the_token_sale"), "Learn more"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("AdminResetUserPassword"), "ResetUserPassword"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("GetSecretValue"), "GetSecretValue"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("set_auth_token"), "hunter2"),
            Some("SET_AUTH_TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("rotate_password"), "letmein123"),
            Some("ROTATE_PASSWORD".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("SecretId"), "MyTestDatabaseSecret"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("SessionLoggerArn"), "arn:aws:logs:region:acct:log/x"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("passwordCannotBeEmpty"), "Password cannot be empty"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("passwordLastUsed"), "2026-01-01T00:00:00Z"),
            None
        );
        assert_eq!(
            sensitive_key_fires(Some("access_token"), "abcDEF123456"),
            Some("ACCESS_TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("userPassword"), "hunter2"),
            Some("USERPASSWORD".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("token"), "abcde"),
            Some("TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("access_token"), "abcdefghijk"),
            Some("ACCESS_TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("refresh_token"), "refresh"),
            Some("REFRESH_TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("refresh_token"), "refresh12345"),
            Some("REFRESH_TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("refresh_token"), "refresh-123"),
            Some("REFRESH_TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("token"), "hunter2"),
            Some("TOKEN".to_string())
        );
        assert_eq!(
            sensitive_key_fires(Some("password"), "correct horse battery staple"),
            Some("PASSWORD".to_string())
        );
    }

    #[test]
    fn benign_values_skipped() {
        assert!(!fires(RegionKind::Cookie, Kind::Har, None, ""));
        assert!(!fires(
            RegionKind::Cookie,
            Kind::Har,
            None,
            "<<SECRET_0123456789abcdef>>"
        ));
        assert_eq!(sensitive_key_fires(Some("cookie-signature"), "1.2.2"), None);
        assert_eq!(sensitive_key_fires(Some("pbkdf2-password"), "^1.0.0"), None);
        assert!(env_fires(Some("HIPCHAT_API_KEY"), "your_hipchat_api_key"));
        assert!(env_fires(Some("GRAPHITE_USER"), "username"));
        assert!(env_fires(Some("LOG_FILE"), "/dev/null"));
    }
}
