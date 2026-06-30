use super::benign::{
    is_crypto_test_vector_identifier_value, is_explicitly_non_sensitive_key_name,
    is_localization_template_reference, is_non_secret_source_constant_value, is_placeholder_value,
    is_source_fixture_secret_value, is_source_secret_name_reference_value,
    is_structured_generic_key_metadata_value,
};
use super::Detector;
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;

const MAX_KEY_CONTEXT_BYTES: usize = 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyKind {
    Strong,
    Token,
    Otp,
    Phrase,
    EncodedHex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Separator {
    Assignment,
    Colon,
    Is,
    ImplicitQuote,
}

#[derive(Clone, Copy, Debug)]
struct ValueCandidate {
    start: usize,
    end: usize,
    quoted: bool,
}

#[derive(Clone, Copy, Debug)]
struct SeparatorCandidate {
    start: usize,
    end: usize,
    kind: Separator,
}

struct ScanCtx<'a, 'view, 'out> {
    text: &'a str,
    line_start: usize,
    line_end: usize,
    view: &'view NormalizedView<'view>,
    out: &'out mut Vec<Span>,
}

/// Detects plaintext `key[:=]value`-style secrets without putting an open-ended
/// key-name capture regex in the vendor rule table. This is still deterministic:
/// a sensitive key phrase, a real separator, a value boundary, and value-shape
/// checks must all agree before only the value span is emitted.
pub struct KeyValueDetector;

impl Detector for KeyValueDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let mut out = Vec::new();
        let mut line_start = 0;

        while line_start <= text.len() {
            let line_end = text[line_start..]
                .find('\n')
                .map_or(text.len(), |offset| line_start + offset);
            scan_line(text, line_start, line_end, view, &mut out);
            if line_end == text.len() {
                break;
            }
            line_start = line_end + 1;
        }

        out
    }
}

fn scan_line(
    text: &str,
    line_start: usize,
    line_end: usize,
    view: &NormalizedView,
    out: &mut Vec<Span>,
) {
    let mut ctx = ScanCtx {
        text,
        line_start,
        line_end,
        view,
        out,
    };
    let line = &ctx.text[ctx.line_start..ctx.line_end];
    let bytes = line.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let abs = ctx.line_start + i;
        let matched = if bytes[i] == b'=' {
            let sep_end = if bytes.get(i + 1) == Some(&b'>') {
                abs + 2
            } else {
                abs + 1
            };
            if is_assignment_separator(bytes, i) {
                try_push(
                    &mut ctx,
                    SeparatorCandidate {
                        start: abs,
                        end: sep_end,
                        kind: Separator::Assignment,
                    },
                )
            } else {
                false
            }
        } else if bytes[i] == b':' {
            if is_colon_separator(bytes, i) {
                try_push(
                    &mut ctx,
                    SeparatorCandidate {
                        start: abs,
                        end: abs + 1,
                        kind: Separator::Colon,
                    },
                )
            } else {
                false
            }
        } else if is_is_separator(bytes, i) {
            try_push(
                &mut ctx,
                SeparatorCandidate {
                    start: abs,
                    end: abs + 2,
                    kind: Separator::Is,
                },
            )
        } else if matches!(bytes[i], b'"' | b'\'' | b'`')
            && i > 0
            && bytes[i - 1].is_ascii_whitespace()
            && bytes
                .get(i + 1)
                .is_some_and(|b| !matches!(b, b',' | b';' | b')' | b']' | b'}'))
        {
            try_push(
                &mut ctx,
                SeparatorCandidate {
                    start: abs,
                    end: abs,
                    kind: Separator::ImplicitQuote,
                },
            )
        } else {
            false
        };

        i += if matched { 2 } else { 1 };
    }
}

fn try_push(ctx: &mut ScanCtx<'_, '_, '_>, separator: SeparatorCandidate) -> bool {
    let left_end = trim_ascii_ws_end(ctx.text, ctx.line_start, separator.start);
    let Some(key_start) = key_context_start(ctx.text, ctx.line_start, left_end) else {
        return false;
    };
    let key = trim_key_edge(&ctx.text[key_start..left_end]);
    let semantic_key = declared_identifier_key(key).unwrap_or_else(|| key.to_string());
    let semantic_key = semantic_key.as_str();
    let key_name = normalize_key(semantic_key);
    if is_xml_key_attribute(ctx.text, ctx.line_start, separator.start, &key_name) {
        return false;
    }
    if separator.kind == Separator::Colon
        && (is_cpp_range_for_key(key) || is_cpp_range_for_left(&ctx.text[ctx.line_start..left_end]))
    {
        return false;
    }
    if separator.kind == Separator::Colon
        && is_ternary_colon(ctx.text, ctx.line_start, separator.start)
    {
        return false;
    }
    let kind = match if separator.kind == Separator::ImplicitQuote {
        trailing_sensitive_key_kind(semantic_key)
    } else {
        sensitive_key_kind(semantic_key)
    } {
        Some(kind) => kind,
        None => return false,
    };
    if separator.kind == Separator::Is && !kind.allows_is_separator() {
        return false;
    }
    if separator.kind == Separator::ImplicitQuote && !matches!(kind, KeyKind::Strong) {
        return false;
    }

    let Some(value) = parse_value(ctx.text, separator.end, ctx.line_end, kind) else {
        return false;
    };
    let raw_value = &ctx.text[value.start..value.end];
    if is_self_reference_code_value(semantic_key, raw_value) {
        return false;
    }
    if !value.quoted
        && separator.kind == Separator::Colon
        && is_unquoted_type_annotation_literal(raw_value, ctx.text, value.end, ctx.line_end)
    {
        return false;
    }
    if !value.quoted
        && is_shell_command_invocation_literal(raw_value, ctx.text, value.end, ctx.line_end)
    {
        return false;
    }
    if !value.quoted && is_camel_case_code_reference(raw_value) {
        return false;
    }
    if !value.quoted && is_code_type_or_expression(raw_value, &key_name, kind) {
        return false;
    }
    if !looks_like_secret_value(
        raw_value,
        kind,
        value.quoted,
        separator.kind,
        &key_name,
        &ctx.text[ctx.line_start..left_end],
    ) {
        return false;
    }

    ctx.out.push(Span {
        range: ctx.view.to_raw(ByteRange::new(value.start, value.end)),
        category: Category::Secret,
        label: labels::KEYED_SECRET.to_string(),
        confidence: Confidence::Medium,
        source: DetectorId::KeyValue,
    });
    true
}

impl KeyKind {
    fn allows_is_separator(self) -> bool {
        matches!(
            self,
            KeyKind::Strong | KeyKind::Otp | KeyKind::Phrase | KeyKind::EncodedHex
        )
    }
}

fn is_assignment_separator(bytes: &[u8], i: usize) -> bool {
    if bytes.get(i + 1) == Some(&b'=') {
        return false;
    }
    if i > 0
        && matches!(
            bytes[i - 1],
            b'=' | b'!' | b'<' | b'>' | b'&' | b'|' | b'+' | b'-' | b'*' | b'/' | b'%' | b'^'
        )
    {
        return false;
    }
    true
}

fn is_colon_separator(bytes: &[u8], i: usize) -> bool {
    !matches!(bytes.get(i + 1), Some(b'/') | Some(b':'))
        && (i == 0 || bytes.get(i - 1) != Some(&b':'))
}

fn is_is_separator(bytes: &[u8], i: usize) -> bool {
    bytes.get(i..i + 2) == Some(b"is")
        && i > 0
        && bytes.get(i - 1).is_some_and(u8::is_ascii_whitespace)
        && bytes.get(i + 2).is_some_and(u8::is_ascii_whitespace)
}

fn key_context_start(text: &str, line_start: usize, left_end: usize) -> Option<usize> {
    if left_end <= line_start {
        return None;
    }
    let mut min = left_end
        .saturating_sub(MAX_KEY_CONTEXT_BYTES)
        .max(line_start);
    while min < left_end && !text.is_char_boundary(min) {
        min += 1;
    }
    let window = &text[min..left_end];
    let hard = window
        .rfind(|ch: char| {
            matches!(
                ch,
                ':' | '=' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
            )
        })
        .map_or(min, |offset| min + offset + 1);
    let start = trim_ascii_ws_start(text, hard, left_end);
    (start < left_end).then_some(start)
}

fn trim_key_edge(value: &str) -> &str {
    value.trim_matches(|ch: char| {
        ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | '-' | '>')
    })
}

fn sensitive_key_kind(key: &str) -> Option<KeyKind> {
    let name = normalize_key(key);
    if name.is_empty() || is_explicitly_non_sensitive_key(&name) {
        return None;
    }
    if is_hex_encoded_sensitive_key_name(&name) {
        return Some(KeyKind::EncodedHex);
    }
    if is_otp_key_name(&name) {
        return Some(KeyKind::Otp);
    }
    if contains_any(
        &name,
        &[
            "recovery_phrase",
            "seed_phrase",
            "secret_recovery_phrase",
            "mnemonic",
        ],
    ) {
        return Some(KeyKind::Phrase);
    }
    if contains_any(
        &name,
        &[
            "access_token",
            "refresh_token",
            "id_token",
            "auth_token",
            "bearer_token",
            "session_token",
        ],
    ) || matches!(name.as_str(), "token" | "session" | "cookie" | "jwt")
        || name.ends_with("_token")
        || name.contains("_token_")
        || name == "authorization"
        || name.ends_with("_authorization")
        || name.contains("_authorization_")
    {
        return Some(KeyKind::Token);
    }
    if name == "key"
        || name.ends_with("_key")
        || name.contains("_key_")
        || name == "auth"
        || name.ends_with("_auth")
        || name.contains("_auth_")
        || contains_any(
            &name,
            &[
                "api_key",
                "apikey",
                "access_key",
                "account_key",
                "client_key_data",
                "password",
                "passwd",
                "pwd",
                "passphrase",
                "secret",
                "credential",
                "private",
                "signing_secret",
                "webhook_secret",
                "shared_secret",
                "client_secret",
            ],
        )
    {
        return Some(KeyKind::Strong);
    }
    None
}

fn trailing_sensitive_key_kind(key: &str) -> Option<KeyKind> {
    let words = key
        .split_whitespace()
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    for take in (1..=3).rev() {
        if words.len() < take {
            continue;
        }
        let candidate = words[words.len() - take..].join(" ");
        let name = normalize_key(&candidate);
        if let Some(kind) = implicit_key_name_kind(&name) {
            return Some(kind);
        }
    }
    None
}

fn implicit_key_name_kind(name: &str) -> Option<KeyKind> {
    if name.is_empty() || is_explicitly_non_sensitive_key(name) {
        return None;
    }
    if is_hex_encoded_sensitive_key_name(name) {
        return Some(KeyKind::EncodedHex);
    }
    if is_otp_key_name(name) {
        return Some(KeyKind::Otp);
    }
    if matches!(
        name,
        "recovery_phrase" | "seed_phrase" | "secret_recovery_phrase" | "mnemonic"
    ) {
        return Some(KeyKind::Phrase);
    }
    if name == "token"
        || name.ends_with("_token")
        || name == "authorization"
        || name.ends_with("_authorization")
        || name == "session"
        || name.ends_with("_session")
        || name == "cookie"
        || name.ends_with("_cookie")
        || name == "jwt"
        || name.ends_with("_jwt")
    {
        return Some(KeyKind::Token);
    }
    if name == "key"
        || name.ends_with("_key")
        || name == "auth"
        || name.ends_with("_auth")
        || name == "password"
        || name.ends_with("_password")
        || name == "passwd"
        || name.ends_with("_passwd")
        || name == "pwd"
        || name.ends_with("_pwd")
        || name == "passphrase"
        || name.ends_with("_passphrase")
        || name == "secret"
        || name.ends_with("_secret")
        || name == "credential"
        || name.ends_with("_credential")
        || name == "private"
        || name.ends_with("_private")
    {
        return Some(KeyKind::Strong);
    }
    None
}

fn parse_value(text: &str, start: usize, line_end: usize, kind: KeyKind) -> Option<ValueCandidate> {
    let mut pos = trim_ascii_ws_start(text, start, line_end);
    if pos >= line_end {
        return None;
    }

    let quote = text
        .as_bytes()
        .get(pos)
        .copied()
        .filter(|b| matches!(b, b'"' | b'\'' | b'`'));
    if let Some(quote) = quote {
        pos += 1;
        let end = find_quote_or_line_end(text, pos, line_end, quote);
        let start = trim_ascii_ws_start(text, pos, end);
        let end = trim_ascii_ws_end(text, start, end);
        if matches!(kind, KeyKind::Token | KeyKind::Strong) {
            let first_end = scan_unquoted_token_end(text, start, end);
            let first = &text[start..first_end];
            if is_auth_credential_scheme(first) {
                let credential_start = trim_ascii_ws_start(text, first_end, end);
                if credential_start < end {
                    return Some(ValueCandidate {
                        start: credential_start,
                        end,
                        quoted: false,
                    });
                }
            }
        }
        return (start < end).then_some(ValueCandidate {
            start,
            end,
            quoted: true,
        });
    }

    if matches!(kind, KeyKind::Token | KeyKind::Strong) {
        let first_end = scan_unquoted_token_end(text, pos, line_end);
        let first = &text[pos..first_end];
        if is_auth_credential_scheme(first) {
            pos = trim_ascii_ws_start(text, first_end, line_end);
            if pos >= line_end {
                return None;
            }
        }
    }

    let end = scan_unquoted_token_end(text, pos, line_end);
    let end = trim_unquoted_value_end(text, pos, end);
    (pos < end).then_some(ValueCandidate {
        start: pos,
        end,
        quoted: false,
    })
}

fn scan_unquoted_token_end(text: &str, start: usize, line_end: usize) -> usize {
    let mut end = start;
    for (offset, ch) in text[start..line_end].char_indices() {
        if ch.is_ascii_whitespace() || matches!(ch, ',' | ';' | ')' | ']' | '}') {
            break;
        }
        if ch == '&' && starts_form_param_at(text, start + offset + ch.len_utf8(), line_end) {
            break;
        }
        end = start + offset + ch.len_utf8();
    }
    end
}

fn is_auth_credential_scheme(value: &str) -> bool {
    matches_ignore_ascii_case(value, &["bearer", "basic", "token", "apikey", "api-key"])
}

fn starts_form_param_at(text: &str, start: usize, line_end: usize) -> bool {
    // In query/form bodies, `&name=` starts the next parameter. Stopping here
    // prevents `token=value&state=...` from being treated as one oversized
    // secret while still allowing the current parameter value to be judged.
    let mut pos = start;
    let bytes = text.as_bytes();
    if pos >= line_end || !bytes[pos].is_ascii_alphabetic() {
        return false;
    }
    pos += 1;
    while pos < line_end
        && (bytes[pos].is_ascii_alphanumeric() || matches!(bytes[pos], b'_' | b'-' | b'.'))
    {
        pos += 1;
    }
    pos < line_end && bytes[pos] == b'='
}

fn trim_unquoted_value_end(text: &str, start: usize, mut end: usize) -> usize {
    while start < end {
        let Some(ch) = text[start..end].chars().next_back() else {
            break;
        };
        if matches!(ch, '.' | ',' | '!' | '?' | '"' | '\'') {
            end -= ch.len_utf8();
        } else {
            break;
        }
    }
    end
}

fn find_quote_or_line_end(text: &str, start: usize, line_end: usize, quote: u8) -> usize {
    let bytes = text.as_bytes();
    let mut pos = start;
    let mut escaped = false;
    while pos < line_end {
        let b = bytes[pos];
        if escaped {
            escaped = false;
            pos += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            pos += 1;
            continue;
        }
        if b == quote {
            return pos;
        }
        pos += 1;
    }
    line_end
}

fn looks_like_secret_value(
    value: &str,
    kind: KeyKind,
    quoted: bool,
    separator: Separator,
    key_name: &str,
    source_key: &str,
) -> bool {
    let value = value.trim();
    if value.is_empty() || is_rendered_placeholder(value) || is_benign_literal(value) {
        return false;
    }
    if is_short_dotted_triplet(value) {
        return false;
    }

    let chars = value.chars().count();
    if matches!(kind, KeyKind::Otp) {
        return (4..=12).contains(&chars)
            && value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ' '));
    }

    if matches!(kind, KeyKind::Phrase) {
        return chars >= 8;
    }

    if is_format_template_literal(value, key_name)
        || is_env_lookup_template_literal(value)
        || is_cli_option_literal(value, key_name)
        || is_file_extension_literal(value, key_name)
        || is_protobuf_tag_literal(value, key_name)
        || is_key_algorithm_literal(value)
        || is_asn1_oid_der_literal(value, key_name, source_key)
        || is_crypto_test_vector_identifier_literal(value, key_name)
        || is_localized_ui_text_literal(value, key_name)
        || is_html_code_metadata_literal(value)
        || is_html_documentation_fragment_literal(value, key_name, source_key)
        || is_escaped_html_source_fragment_literal(value, source_key)
        || is_fingerprint_literal(value, key_name)
        || is_source_constant_reference_literal(value, source_key)
        || is_source_declared_name_literal(value, key_name, source_key)
        || is_source_config_name_literal(value, source_key)
        || is_source_sensitive_name_reference_literal(value, source_key)
        || is_source_fixture_secret_literal(value, key_name, source_key)
        || is_source_struct_tag_literal(value, key_name, source_key)
        || is_source_prefix_constant_literal(value, key_name)
        || is_source_variable_reference_literal(value, source_key)
        || is_source_string_fragment_literal(value, source_key)
        || is_shell_command_substitution_literal(value, source_key)
        || is_inline_code_key_value_tail_literal(value, key_name, source_key)
        || is_source_code_fragment_literal(value)
        || is_arithmetic_expression_literal(value)
        || is_localization_template_reference(value)
        || is_interpolated_string_template(value)
        || is_public_key_literal(value)
        || is_license_identifier_literal(value, key_name)
        || is_dunder_identifier_literal(value)
        || is_uppercase_constant_literal_for_generic_key(value, key_name)
        || is_generic_code_member_name_literal(value, key_name)
        || is_structured_key_name_reference_literal(value, key_name)
        || is_plain_prose_literal_for_generic_key(value, key_name)
        || is_locator_literal_for_key(value, key_name)
        || is_secret_resource_metadata_literal(value, key_name)
    {
        return false;
    }
    if is_auth_scheme_literal(value) {
        return false;
    }
    let has_alpha = value.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_ascii_whitespace());
    let has_space = value.chars().any(char::is_whitespace);

    if matches!(kind, KeyKind::EncodedHex) {
        return is_keyed_hex_secret_literal(value, key_name, kind);
    }
    if is_keyed_hex_secret_literal(value, key_name, kind) {
        return true;
    }

    if matches!(kind, KeyKind::Token) && has_space {
        // Bearer/API/session token syntaxes are compact credentials. Values
        // with whitespace such as "Test Access Token" are names or fixture
        // prose, not usable token material.
        return false;
    }

    if quoted && chars >= 4 {
        if separator == Separator::ImplicitQuote {
            return has_digit || has_symbol;
        }
        return has_digit || has_symbol || key_allows_low_entropy_literal(key_name, kind);
    }
    if !quoted && is_plain_code_identifier(value) && !has_digit {
        return false;
    }
    if chars >= 4 && has_alpha && has_digit {
        if is_plain_code_identifier(value) {
            return key_allows_low_entropy_literal(key_name, kind);
        }
        return true;
    }
    if chars >= 6 && has_symbol && (has_alpha || has_digit) {
        return true;
    }
    if matches!(kind, KeyKind::Token) {
        return chars >= 12 && !has_space;
    }
    false
}

fn is_short_dotted_triplet(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [first, second, third].iter().all(|part| {
        !part.is_empty()
            && part.len() < 12
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    })
}

fn is_rendered_placeholder(v: &str) -> bool {
    v.starts_with("<<") && v.ends_with(">>")
}

fn is_benign_literal(value: &str) -> bool {
    if is_placeholder_value(value) {
        return true;
    }
    if is_iso8601_timestamp_literal(value) {
        return true;
    }
    if is_synthetic_hex_test_vector_literal(value) {
        return true;
    }
    let normalized = normalize_key(value);
    matches!(
        normalized.as_str(),
        "" | "true" | "false" | "null" | "none" | "nil" | "undefined"
    )
}

fn is_iso8601_timestamp_literal(value: &str) -> bool {
    // Timestamp bucket keys and metadata dates can sit under fields containing
    // `key`, but a timestamp is not credential material. Keep this to strict
    // ISO calendar/date-time shapes instead of treating arbitrary dates as benign.
    let value = value.trim();
    let b = value.as_bytes();
    is_iso8601_date_literal_bytes(b) || is_iso8601_datetime_literal_bytes(b)
}

fn is_iso8601_date_literal_bytes(b: &[u8]) -> bool {
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|idx| b[*idx].is_ascii_digit())
}

fn is_iso8601_datetime_literal_bytes(b: &[u8]) -> bool {
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || ![0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|idx| b[*idx].is_ascii_digit())
    {
        return false;
    }
    let mut pos = 19;
    if b.get(pos) == Some(&b'.') {
        pos += 1;
        let fraction_start = pos;
        while b.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
        if pos == fraction_start {
            return false;
        }
    }
    if b.get(pos) == Some(&b'Z') {
        return pos + 1 == b.len();
    }
    b.len() == pos + 6
        && matches!(b[pos], b'+' | b'-')
        && b[pos + 3] == b':'
        && [pos + 1, pos + 2, pos + 4, pos + 5]
            .iter()
            .all(|idx| b[*idx].is_ascii_digit())
}

fn is_synthetic_hex_test_vector_literal(value: &str) -> bool {
    let value = value.trim();
    if is_canonical_hex_fixture_literal(value) {
        return true;
    }
    let Some(bytes) = decode_hex_literal(value) else {
        return false;
    };
    if bytes.len() < 8 {
        return false;
    }
    is_segmented_hex_fixture_bytes(&bytes)
}

fn is_keyed_hex_secret_literal(value: &str, key_name: &str, kind: KeyKind) -> bool {
    // Unquoted hex-looking secret material is syntactically indistinguishable
    // from a lower-case identifier, so it must be recovered by structure: a
    // sensitive field name plus compact hex shape. Explicit `hex*` fields and
    // key material require byte alignment; opaque `*_secret` tokens may be odd.
    let key_allows_hex = match kind {
        KeyKind::EncodedHex => is_hex_encoded_sensitive_key_name(key_name),
        KeyKind::Strong => is_hex_material_key_name(key_name),
        KeyKind::Token | KeyKind::Otp | KeyKind::Phrase => false,
    };
    if !key_allows_hex {
        return false;
    }
    let min_len = if matches!(kind, KeyKind::EncodedHex) || is_hex_encoded_salt_key_name(key_name) {
        8
    } else {
        16
    };
    let bytes = value.trim().as_bytes();
    if bytes.len() < min_len
        || bytes.len() > 128
        || !bytes.iter().all(|b| b.is_ascii_hexdigit())
        || !bytes.iter().any(u8::is_ascii_digit)
        || !bytes.iter().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'))
    {
        return false;
    }
    let requires_even_hex =
        matches!(kind, KeyKind::EncodedHex) || !has_identifier_component(key_name, "secret");
    if requires_even_hex && !bytes.len().is_multiple_of(2) {
        return false;
    }
    !is_synthetic_hex_test_vector_literal(value)
}

fn is_hex_material_key_name(name: &str) -> bool {
    name == "key"
        || has_identifier_component(name, "key")
        || has_identifier_component(name, "secret")
        || has_identifier_component(name, "credential")
        || has_identifier_component(name, "private")
}

fn is_hex_encoded_sensitive_key_name(name: &str) -> bool {
    name.split('_').any(is_hex_encoded_sensitive_component)
        || has_identifier_phrase(name, &["hex", "key"])
        || has_identifier_phrase(name, &["hex", "secret"])
        || has_identifier_phrase(name, &["hex", "salt"])
        || has_identifier_phrase(name, &["hex", "password"])
        || has_identifier_phrase(name, &["hex", "token"])
}

fn is_hex_encoded_salt_key_name(name: &str) -> bool {
    name.split('_').any(|part| part == "hexsalt") || has_identifier_phrase(name, &["hex", "salt"])
}

fn is_hex_encoded_sensitive_component(component: &str) -> bool {
    let Some(role) = component.strip_prefix("hex") else {
        return false;
    };
    matches!(
        role,
        "key" | "secret" | "salt" | "password" | "passwd" | "pwd" | "token" | "credential"
    )
}

fn decode_hex_literal(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() < 16
        || bytes.len() > 256
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
    // Standard crypto test vectors often use obvious byte runs: 000102..., the
    // reverse, or repeated bytes like e0e0e0. Real generated keys can contain
    // these locally, but not as the whole value split into such runs.
    let mut pos = 0;
    let mut segments = 0;
    while pos < bytes.len() {
        let repeated = same_byte_run_len(&bytes[pos..]);
        if repeated >= 4 {
            pos += repeated;
            segments += 1;
            continue;
        }
        let stepped = byte_step_run_len(&bytes[pos..], 1).max(byte_step_run_len(&bytes[pos..], -1));
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

fn byte_step_run_len(bytes: &[u8], step: i16) -> usize {
    if bytes.is_empty() {
        return 0;
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

fn is_canonical_hex_fixture_literal(value: &str) -> bool {
    // These visual byte/nibble patterns are common in RFC examples and
    // cryptographic fixtures; random key generation does not create them.
    let lower = value.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "0123456789abcdef",
            "fedcba9876543210",
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100",
        ],
    )
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_code_type_or_expression(value: &str, key_name: &str, kind: KeyKind) -> bool {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }
    if value.starts_with(['~', '+', '-', '*', '&'])
        || value.ends_with('(')
        || value.contains('?')
        || value.contains('[')
        || value.contains(']')
    {
        return true;
    }
    if value.starts_with(['{', '[', '(']) {
        return true;
    }
    if is_member_or_pointer_reference(value) {
        return true;
    }
    if is_plain_code_identifier(value)
        && !key_allows_low_entropy_literal(key_name, kind)
        && !is_keyed_hex_secret_literal(value, key_name, kind)
    {
        return true;
    }
    let starts_like_call = value
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && value.contains('(');
    if starts_like_call {
        return true;
    }
    let bytes = value.as_bytes();
    if !bytes.iter().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'_' | b':'
                    | b'<'
                    | b'>'
                    | b'['
                    | b']'
                    | b'&'
                    | b';'
                    | b','
                    | b'('
                    | b')'
                    | b'.'
                    | b'"'
                    | b'\''
            )
    }) {
        return false;
    }
    let has_type_punctuation = bytes
        .iter()
        .any(|b| matches!(b, b'<' | b'>' | b':' | b'[' | b']' | b'&' | b';'));
    has_type_punctuation
}

fn is_unquoted_type_annotation_literal(
    value: &str,
    text: &str,
    value_end: usize,
    line_end: usize,
) -> bool {
    // Type annotations can use sensitive parameter names (`secret:
    // Base32SecretKey`) without assigning a secret value. Require an unquoted
    // PascalCase identifier and a code delimiter after it so YAML-like
    // `api_key: Abc123Secret` still remains a candidate.
    if !is_pascal_case_type_name(value.trim()) {
        return false;
    }
    text[value_end..line_end]
        .trim_start()
        .chars()
        .next()
        .is_some_and(|ch| matches!(ch, ',' | ')' | ';' | '{' | '=' | '>'))
}

fn is_shell_command_invocation_literal(
    value: &str,
    text: &str,
    value_end: usize,
    line_end: usize,
) -> bool {
    // PowerShell commands use Verb-Noun names followed by options. Assigning
    // `$token = Get-NtToken -Primary` names a command invocation, not a token.
    if !is_powershell_command_name(value.trim()) {
        return false;
    }
    text[value_end..line_end].trim_start().starts_with('-')
}

fn is_powershell_command_name(value: &str) -> bool {
    let Some((verb, noun)) = value.split_once('-') else {
        return false;
    };
    !verb.is_empty()
        && !noun.is_empty()
        && verb.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && noun.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && verb.bytes().all(|b| b.is_ascii_alphabetic())
        && noun.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn is_pascal_case_type_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=96).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_uppercase)
        && bytes.iter().any(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn is_cpp_range_for_key(key: &str) -> bool {
    // C++ range-for uses `:` as syntax (`for (T x : xs)`), not as a
    // key/value separator. This rejects only lines whose left side is clearly a
    // `for` header.
    key.trim_start().starts_with("for ")
        || key.trim_start().starts_with("for(")
        || key.contains(" for ")
}

fn is_cpp_range_for_left(left: &str) -> bool {
    // Same rationale as `is_cpp_range_for_key`, but uses the full left side
    // because the compact key-window may start after `for (`.
    left.trim_start().starts_with("for (")
        || left.trim_start().starts_with("for(")
        || left.contains(" for (")
        || left.contains(" for(")
}

fn is_ternary_colon(text: &str, line_start: usize, colon_start: usize) -> bool {
    // C-family ternaries use `condition ? value_a : value_b`; the value arms
    // can contain sensitive words such as KEY or TOKEN while still being code
    // constants. Look back into the current statement, including a wrapped
    // previous line, and reject only when an unmatched `?` is visible.
    let mut window_start = line_start.saturating_sub(160);
    while window_start < colon_start && !text.is_char_boundary(window_start) {
        window_start += 1;
    }
    let current_before = &text[line_start..colon_start];
    if let Some(question) = current_before.rfind('?') {
        let statement_head = current_before[..question]
            .rsplit([';', '{', '}'])
            .next()
            .unwrap_or_default();
        return ternary_condition_head_is_code(statement_head)
            && is_ternary_arm_expr(&current_before[question + 1..]);
    }

    let before = &text[window_start..line_start];
    let Some(question) = before.rfind('?') else {
        return false;
    };
    if !before[question + 1..].trim().is_empty() {
        return false;
    }
    let statement_head = before[..question]
        .rsplit(['\n', ';', '{', '}'])
        .next()
        .unwrap_or_default();
    ternary_condition_head_is_code(statement_head) && is_ternary_arm_expr(current_before)
}

fn ternary_condition_head_is_code(statement_head: &str) -> bool {
    statement_head
        .bytes()
        .any(|b| matches!(b, b'=' | b'(' | b')' | b'!' | b'<' | b'>' | b'&' | b'|'))
}

fn is_ternary_arm_expr(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.contains("://") {
        return false;
    }
    value.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'_' | b':' | b'.' | b'-' | b'+' | b'*' | b'/' | b'&' | b'|' | b'(' | b')'
            )
    })
}

fn declared_identifier_key(key: &str) -> Option<String> {
    // Declarations put modifiers/types before the actual variable
    // (`private const string ApiKey = ...`). The declaration syntax itself is
    // neither secret nor benign; only the declared identifier should drive the
    // sensitive-key decision. This preserves recall for `ApiKey` while avoiding
    // false positives on non-sensitive declarations such as
    // `InstallManifestFileName`.
    let tokens = key
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.len() < 2 {
        return None;
    }
    let has_declaration_word = tokens[..tokens.len() - 1]
        .iter()
        .any(|token| is_declaration_word(token));
    if !has_declaration_word {
        return None;
    }
    let ident = tokens[tokens.len() - 1];
    (!is_declaration_word(ident)).then(|| ident.to_string())
}

fn is_declaration_word(token: &str) -> bool {
    const WORDS: &[&str] = &[
        "private",
        "public",
        "protected",
        "internal",
        "static",
        "const",
        "readonly",
        "final",
        "let",
        "var",
        "val",
        "auto",
        "constexpr",
        "override",
        "string",
        "str",
        "int",
        "uint",
        "long",
        "ulong",
        "short",
        "ushort",
        "bool",
        "boolean",
        "char",
        "double",
        "float",
        "decimal",
        "object",
    ];
    WORDS.iter().any(|word| token.eq_ignore_ascii_case(word))
}

fn is_xml_key_attribute(
    text: &str,
    line_start: usize,
    separator_start: usize,
    key_name: &str,
) -> bool {
    // XML attributes named `key` describe configuration identifiers, and
    // `publicKeyToken` is public assembly identity metadata. Treating these as
    // secret-bearing key/value assignments turns ordinary manifests into noise.
    if key_name != "key" && !key_name.ends_with("_key") && key_name != "public_key_token" {
        return false;
    }
    let left = &text[line_start..separator_start];
    let trimmed = left.trim_start();
    trimmed.starts_with('<') && !trimmed.starts_with("</")
}

fn is_auth_scheme_literal(value: &str) -> bool {
    // Authentication scheme names are protocol identifiers. They become secret
    // only when followed by credentials, which URL/header/rule detectors handle.
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "basic"
            | "digest"
            | "ntlm"
            | "negotiate"
            | "gss-negotiate"
            | "gssapi"
            | "bearer"
            | "oauth"
            | "oauth2"
            | "scram-sha-256"
    )
}

fn is_format_template_literal(value: &str, key_name: &str) -> bool {
    // Format templates are code fragments waiting for substitution, not the
    // substituted credential (`"%s"`, `"Basic {}"`, `${token}`). The detector
    // should see the runtime value or a concrete fixture value before masking.
    // Suppress only when the key/value context itself says template/format; a
    // real password may contain `%` or braces.
    let value = value.trim();
    let has_template_syntax = contains_printf_directive(value)
        || value.contains("{}")
        || value.contains("{0}")
        || value.contains("${");
    if !has_template_syntax {
        return false;
    }
    is_pure_printf_template_literal(value)
        || key_name_indicates_template_context(key_name)
        || auth_template_value(key_name, value)
}

fn is_env_lookup_template_literal(value: &str) -> bool {
    // Ansible/Jinja env lookups name where a credential will be read from:
    // `{{ lookup('env', 'OS_PASSWORD') }}`. They are not the credential value,
    // and the runtime secret remains visible to the env detector when present.
    let value = value.trim();
    if !(value.starts_with("{{") && value.ends_with("}}")) {
        return false;
    }
    let inner = value[2..value.len() - 2].trim().to_ascii_lowercase();
    inner.contains("lookup(") && (inner.contains("'env'") || inner.contains("\"env\""))
}

fn contains_printf_directive(value: &str) -> bool {
    // printf-style directives are syntax, not data. Parse the directive shape
    // instead of enumerating `%s`, `%d`, `%q`, etc., so new language-specific
    // conversion letters do not become detector exceptions.
    let bytes = value.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        if parse_printf_directive(bytes, i).is_some() {
            return true;
        }
        i += 1;
    }
    false
}

fn is_pure_printf_template_literal(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes[0] != b'%' {
        return false;
    }
    parse_printf_directive(bytes, 0).is_some_and(|end| end == bytes.len())
}

fn parse_printf_directive(bytes: &[u8], percent: usize) -> Option<usize> {
    if bytes.get(percent) != Some(&b'%') {
        return None;
    }
    let mut i = percent + 1;
    if i + 1 < bytes.len() && bytes[i].is_ascii_hexdigit() && bytes[i + 1].is_ascii_hexdigit() {
        return None;
    }
    if bytes.get(i) == Some(&b'%') {
        return None;
    }
    i = consume_printf_index(bytes, i);
    while i < bytes.len() && matches!(bytes[i], b'#' | b'0' | b'-' | b'+' | b' ' | b'.') {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    i = consume_printf_index(bytes, i);
    if i < bytes.len() && bytes[i].is_ascii_alphabetic() {
        return Some(i + 1);
    }
    None
}

fn consume_printf_index(bytes: &[u8], start: usize) -> usize {
    if bytes.get(start) != Some(&b'[') {
        return start;
    }
    let mut i = start + 1;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i > start + 1 && bytes.get(i) == Some(&b']') {
        i + 1
    } else {
        start
    }
}

fn is_cli_option_literal(value: &str, key_name: &str) -> bool {
    // Values beginning with CLI option syntax (`--timeout 300`) configure a
    // command, but only when the key name itself describes command/options
    // storage. This avoids globally suppressing real secrets that happen to
    // start with two hyphens.
    (has_identifier_component(key_name, "option")
        || has_identifier_component(key_name, "options")
        || has_identifier_component(key_name, "arg")
        || has_identifier_component(key_name, "args")
        || has_identifier_component(key_name, "flag")
        || has_identifier_component(key_name, "flags")
        || has_identifier_component(key_name, "command"))
        && value.trim_start().starts_with("--")
}

fn is_file_extension_literal(value: &str, key_name: &str) -> bool {
    // A lone file extension (`.gpg`, `.pem`) describes storage format. It can be
    // adjacent to credential-related key names, so require an explicit
    // extension/suffix/format key before suppressing it.
    if !(has_identifier_component(key_name, "extension")
        || has_identifier_component(key_name, "suffix")
        || has_identifier_component(key_name, "format"))
    {
        return false;
    }
    let value = value.trim();
    value.len() > 1
        && value.starts_with('.')
        && value[1..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn is_protobuf_tag_literal(value: &str, key_name: &str) -> bool {
    // Go protobuf struct tags encode field metadata, e.g.
    // `protobuf_key:"bytes,1,opt,name=key,proto3"`. The `name=key` token is a
    // schema field name, not key material.
    if !(has_identifier_component(key_name, "protobuf")
        && has_identifier_component(key_name, "key"))
    {
        return false;
    }
    let mut parts = value.split(',');
    let Some(wire_type) = parts.next() else {
        return false;
    };
    matches!(
        wire_type,
        "bytes" | "varint" | "fixed32" | "fixed64" | "sfixed32" | "sfixed64"
    ) && value.contains(",name=key,")
        && (value.ends_with(",proto2") || value.ends_with(",proto3"))
}

fn is_key_algorithm_literal(value: &str) -> bool {
    // Algorithm/size labels such as `RSA-2048` describe how a key should be
    // generated or interpreted. They are not the private/public key bytes.
    let value = value.trim();
    if value.eq_ignore_ascii_case("AWS4-HMAC-SHA256") {
        // AWS Signature Version 4's signing algorithm identifier is public
        // protocol metadata, not the HMAC signing key.
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "rsa-pss" | "rsa-oaep") {
        return true;
    }
    if lower
        .strip_prefix("rsa-oaep-")
        .is_some_and(|case| !case.is_empty() && case.bytes().all(|b| b.is_ascii_digit()))
    {
        return true;
    }
    let Some((algorithm, bits)) = value.split_once('-') else {
        return false;
    };
    if !matches!(
        algorithm.to_ascii_lowercase().as_str(),
        "rsa" | "dsa" | "dh"
    ) {
        return false;
    }
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    (128..=16384).contains(&bits)
}

fn is_asn1_oid_der_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // OpenSSL-style generated object tables use `OBJ_*` identifiers whose value
    // is the DER body of an ASN.1 OBJECT IDENTIFIER, written as `\xHH` octets.
    // The octets identify a public algorithm/attribute OID, not key material.
    if !(key_name.starts_with("obj_")
        || has_identifier_component(key_name, "oid")
        || source_key.trim_start().starts_with("OBJ_"))
    {
        return false;
    }
    let Some(octets) = parse_mixed_hex_escape_octets(value.trim()) else {
        return false;
    };
    // Require a multi-octet arc to avoid treating arbitrary escaped test strings
    // as metadata. Some leading ASCII control bytes are already decoded and
    // trimmed by the normalized view, so the `OBJ_*` key contract carries the
    // ASN.1 OID evidence instead of trusting the first byte alone.
    octets.len() >= 3 && octets.iter().any(|byte| *byte >= 0x80)
}

fn parse_mixed_hex_escape_octets(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == b'\\' {
            if pos + 3 >= bytes.len() || !matches!(bytes[pos + 1], b'x' | b'X') {
                return None;
            }
            let hi = hex_nibble(bytes[pos + 2])?;
            let lo = hex_nibble(bytes[pos + 3])?;
            out.push((hi << 4) | lo);
            pos += 4;
        } else if bytes[pos].is_ascii() {
            out.push(bytes[pos]);
            pos += 1;
        } else {
            return None;
        }
    }
    Some(out)
}

fn is_crypto_test_vector_identifier_literal(value: &str, key_name: &str) -> bool {
    // Published crypto test-vector files often put named test-case handles in
    // fields named `PrivateKey`, `PeerKey`, or `PrivPubKeyPair`. Values such as
    // `KAS-ECC-CDH_P-192_C0` and `ALICE_secp112r1_PUB` identify curve/test-case
    // records; they are not the private scalar or public-key bytes. Keep this
    // anchored to key-material fields and known curve/test-vector syntax so
    // operational handles such as `private_key=tenant-7-trial` still detect.
    if !has_identifier_component(key_name, "key") {
        return false;
    }
    is_crypto_test_vector_identifier_value(value)
}

fn is_localized_ui_text_literal(value: &str, key_name: &str) -> bool {
    // Translation tables and UI copy often use sensitive words in message IDs:
    // `passwordEnteredInvalid = "Invalid password for room \"%s\"."`. The
    // rendered sentence is not a password. Keep this anchored to UI-message key
    // components so real passphrases under `password` still detect.
    if !key_name_has_sensitive_component(key_name) || !key_name_has_ui_text_component(key_name) {
        return false;
    }
    let value = value.trim();
    if !(3..=240).contains(&value.len())
        || value.contains("://")
        || value.contains('=')
        || value.contains('<')
        || value.contains('>')
    {
        return false;
    }
    let has_word_boundary = value.chars().any(char::is_whitespace)
        || value.ends_with(':')
        || value.contains("%s")
        || value.contains("&thinsp;");
    has_word_boundary
        && value.chars().all(|ch| {
            ch.is_alphabetic()
                || ch.is_whitespace()
                || matches!(
                    ch,
                    ':' | ';'
                        | ','
                        | '.'
                        | '!'
                        | '?'
                        | '"'
                        | '\''
                        | '-'
                        | '_'
                        | '%'
                        | '&'
                        | '/'
                        | '\\'
                        | '('
                        | ')'
                )
        })
}

fn key_name_has_sensitive_component(key_name: &str) -> bool {
    key_name.split('_').any(|part| {
        matches!(
            part,
            "secret" | "password" | "passwd" | "pwd" | "credential" | "token" | "auth" | "key"
        )
    })
}

fn key_name_has_ui_text_component(key_name: &str) -> bool {
    key_name.split('_').any(|part| {
        matches!(
            part,
            "label"
                | "message"
                | "msg"
                | "title"
                | "text"
                | "placeholder"
                | "prompt"
                | "description"
                | "desc"
                | "error"
                | "invalid"
                | "entered"
                | "enter"
                | "protected"
                | "required"
                | "warning"
                | "hint"
                | "help"
        )
    })
}

fn is_html_code_metadata_literal(value: &str) -> bool {
    // Generated documentation often embeds public examples as `<code>...</code>`
    // inside prose stored under sensitive-looking words such as "key". Do not
    // suppress arbitrary code-tag contents; only UUIDs and non-sensitive
    // resource-name shapes are metadata here.
    let value = value.trim();
    let Some(inner) = value
        .strip_prefix("<code>")
        .and_then(|rest| rest.strip_suffix("</code>"))
    else {
        return false;
    };
    let inner = inner.trim();
    is_uuid_literal(inner)
        || (!contains_sensitive_identifier_component(inner) && is_resource_name_literal(inner))
}

fn is_html_documentation_fragment_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Generated API docs often include prose like `<p>Key: CreatedTime</p>`
    // inside long documentation strings. The scanner can see the inner `Key:`
    // as a key/value pair; the value is an HTML fragment naming a public field.
    // Require both key-name context and documentation/HTML syntax on the left.
    if !has_identifier_component(key_name, "key")
        || !source_key_has_html_documentation_shape(source_key)
    {
        return false;
    }
    let value = value.trim();
    let (head, had_html_tail) = strip_trailing_html_tag(value);
    is_documentation_metadata_key_name(head, had_html_tail)
}

fn source_key_has_html_documentation_shape(source_key: &str) -> bool {
    let lower = source_key.to_ascii_lowercase();
    lower.contains("documentation")
        || lower.contains("<p>")
        || lower.contains("<li>")
        || lower.contains("<code>")
        || lower.contains("<i>")
        || lower.contains("\\u003cp")
        || lower.contains("\\u003cli")
        || lower.contains("\\u003ccode")
        || lower.contains("\\u003cpre")
}

fn strip_trailing_html_tag(value: &str) -> (&str, bool) {
    let lower = value.to_ascii_lowercase();
    let Some(tag_start) = lower.rfind("</") else {
        return (value, false);
    };
    let Some(tag) = lower[tag_start + 2..].strip_suffix('>') else {
        return (value, false);
    };
    if !matches!(tag, "p" | "code" | "i" | "li") {
        return (value, false);
    }
    (&value[..tag_start], true)
}

fn is_documentation_metadata_key_name(value: &str, had_html_tail: bool) -> bool {
    let value = value.trim();
    if value.is_empty() || value.contains("://") {
        return false;
    }
    let cleaned = value
        .replace("<code>", "")
        .replace("</code>", "")
        .replace("<i>", "")
        .replace("</i>", "");
    let cleaned = cleaned.trim();
    if cleaned.is_empty()
        || cleaned
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'=' | b'@' | b'{' | b'}'))
        || contains_dangerous_secret_component(cleaned)
    {
        return false;
    }
    is_uppercase_public_doc_identifier(cleaned)
        || is_namespaced_public_doc_key(cleaned)
        || is_public_doc_field_name(cleaned, had_html_tail)
}

fn contains_dangerous_secret_component(value: &str) -> bool {
    normalize_key(value).split('_').any(|part| {
        matches!(
            part,
            "secret" | "password" | "passwd" | "credential" | "token" | "auth" | "private"
        )
    })
}

fn is_uppercase_public_doc_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=96).contains(&bytes.len())
        && bytes.iter().any(u8::is_ascii_alphabetic)
        && bytes.contains(&b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn is_namespaced_public_doc_key(value: &str) -> bool {
    let Some((namespace, name)) = value.split_once(':') else {
        return false;
    };
    (2..=48).contains(&namespace.len())
        && !name.is_empty()
        && namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn is_public_doc_field_name(value: &str, had_html_tail: bool) -> bool {
    if !(2..=96).contains(&value.len()) {
        return false;
    }
    let valid = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'*' | b'/'));
    if !valid || !value.bytes().any(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    had_html_tail
        || value.contains('-')
        || value.contains('_')
        || value.bytes().any(|b| b.is_ascii_uppercase())
}

fn is_escaped_html_source_fragment_literal(value: &str, source_key: &str) -> bool {
    // Saved Q&A/docs/API payloads often keep HTML as JSON-escaped strings. A
    // colon inside an embedded code block can make the scanner split a source
    // fragment as if it were `key: value`. Keep this structural: require escaped
    // HTML on the left and reject compact secret-looking payloads such as
    // `api_key: sk-test-token`.
    if !source_key_has_escaped_html_shape(source_key) {
        return false;
    }
    let value = value.trim();
    if value.is_empty() || escaped_html_value_keeps_secret_shape(value) {
        return false;
    }
    escaped_html_fragment_has_markup_or_code_syntax(value)
        || escaped_html_code_reference_literal(value)
}

fn source_key_has_escaped_html_shape(source_key: &str) -> bool {
    let lower = source_key.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "\\u003cp",
            "\\u003c/p",
            "\\u003cpre",
            "\\u003ccode",
            "\\u003c/code",
            "\\u003cli",
            "\\u0026lt",
            "&lt;",
        ],
    )
}

fn escaped_html_value_keeps_secret_shape(value: &str) -> bool {
    let candidate = strip_trailing_escaped_html_tags(value).trim();
    if !(4..=160).contains(&candidate.len()) || candidate.chars().any(char::is_whitespace) {
        return false;
    }
    let bytes = candidate.as_bytes();
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'/' | b'='))
    {
        return false;
    }
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_credential_punctuation = bytes
        .iter()
        .any(|b| matches!(b, b'-' | b'.' | b'+' | b'/' | b'='));
    has_digit || has_credential_punctuation
}

fn strip_trailing_escaped_html_tags(mut value: &str) -> &str {
    loop {
        let lower = value.to_ascii_lowercase();
        let Some(tag_start) = lower.rfind("\\u003c/") else {
            return value;
        };
        let tag = &lower[tag_start + "\\u003c/".len()..];
        let Some(tag) = tag.strip_suffix("\\u003e") else {
            return value;
        };
        if !matches!(tag, "p" | "code" | "pre" | "li" | "span" | "strong" | "em") {
            return value;
        }
        value = &value[..tag_start];
    }
}

fn escaped_html_fragment_has_markup_or_code_syntax(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if contains_any(
        &lower,
        &[
            "\\u003c",
            "\\u003e",
            "\\u0026lt",
            "\\u0026gt",
            "\\n",
            "\\r",
            "\\t",
        ],
    ) {
        return true;
    }
    value.chars().any(char::is_whitespace)
        && value.bytes().any(|b| {
            matches!(
                b,
                b'{' | b'}' | b'[' | b']' | b'(' | b')' | b';' | b',' | b'='
            )
        })
}

fn escaped_html_code_reference_literal(value: &str) -> bool {
    let value = value.trim().trim_end_matches('\\').trim_matches('"');
    if value.is_empty() || value.len() > 96 {
        return false;
    }
    if let Some(rest) = value.strip_prefix('$') {
        return is_simple_code_reference_name(rest);
    }
    if value.starts_with("@\"") || value.starts_with("];") || value.starts_with(").") {
        return true;
    }
    value
        .strip_prefix("l_")
        .or_else(|| value.strip_prefix("m_"))
        .is_some_and(is_simple_code_reference_name)
}

fn is_simple_code_reference_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'>' | b'[' | b']')
        })
}

fn is_uuid_literal(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|idx| bytes[*idx] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(idx, byte)| [8, 13, 18, 23].contains(&idx) || byte.is_ascii_hexdigit())
}

fn contains_sensitive_identifier_component(value: &str) -> bool {
    normalize_key(value).split('_').any(|part| {
        matches!(
            part,
            "secret" | "password" | "passwd" | "credential" | "token" | "auth" | "private" | "key"
        )
    })
}

fn is_fingerprint_literal(value: &str, key_name: &str) -> bool {
    // Fingerprints identify public key material. They are useful metadata but
    // are not the underlying credential, so suppress only explicit fingerprint
    // fields and a strict colon-separated hex shape.
    if !has_identifier_component(key_name, "fingerprint") {
        return false;
    }
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() >= 8
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_source_constant_reference_literal(value: &str, source_key: &str) -> bool {
    // C-family/Rust/C# assignments often put enum constants or environment
    // variable names in sensitive-looking fields:
    // `gss_buffer_desc token = GSS_C_EMPTY_BUFFER` or
    // `const string OAuthClientSecret = "GCM_OAUTH_CLIENTSECRET"`.
    // Only suppress valid all-caps identifier constants when the left side is
    // source-like and the value names a non-secret sentinel component. Plain
    // config such as `api_key=ABC_DEF_123` and source constants such as
    // `ApiKey = "PROD_SECRET_VALUE"` still detect.
    let value = value.trim();
    if !is_uppercase_identifier_constant(value) || !source_key_has_code_shape(source_key) {
        return false;
    }
    is_non_secret_source_constant_value(value)
}

fn is_source_declared_name_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Source constants often publish the name of an environment/config setting,
    // including setting names with secret words:
    // `GcmTraceSecrets = "GCM_TRACE_SECRETS"` or
    // `MsAuthFlow = "GCM_MSAUTH_FLOW"`. That string is public lookup metadata,
    // not the runtime credential. Keep this structural: require source syntax,
    // an ALL_CAPS identifier value with no digits, and a compact value name that
    // is the declared identifier or that identifier with a namespace prefix.
    if !source_key_has_code_shape(source_key) || !is_uppercase_identifier_constant(value) {
        return false;
    }
    let key_compact = key_name.replace('_', "");
    if key_compact.len() < 4 {
        return false;
    }
    let value_compact = normalize_key(value).replace('_', "");
    value_compact == key_compact || value_compact.ends_with(&key_compact)
}

fn is_uppercase_identifier_constant(value: &str) -> bool {
    let bytes = value.as_bytes();
    (4..=96).contains(&bytes.len())
        && bytes.iter().any(u8::is_ascii_alphabetic)
        && bytes.contains(&b'_')
        && !bytes.iter().any(u8::is_ascii_digit)
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn source_key_has_code_shape(source_key: &str) -> bool {
    let key = source_key.trim();
    key.contains("->")
        || key.contains("::")
        || key.contains('.')
        || key.contains('*')
        || key.contains('[')
        || key.split_whitespace().count() >= 2
}

fn is_source_config_name_literal(value: &str, source_key: &str) -> bool {
    // Constants in source code often store public config/property names or
    // routes, even when those names contain sensitive words:
    // `HttpSslCertPasswordProtected = "http.sslcertpasswordprotected"` and
    // `DataCenterPasswordReset = "/passwordreset"`. Restrict this to source-
    // shaped left sides and name/path syntax without digits or credential
    // material so real compact secrets still pass through.
    if !source_key_has_code_shape(source_key) {
        return false;
    }
    let value = value.trim();
    is_lower_dotted_config_name(value) || is_lower_route_literal(value)
}

fn is_source_sensitive_name_reference_literal(value: &str, source_key: &str) -> bool {
    // Source code often stores the *name* of a secret-bearing setting, not the
    // secret itself: `Configuration["clientsecret"]`,
    // `login_or_token="access_token"`, or docs placeholders like
    // `oauth_token = "my_token"`. Only suppress compact identifier names under
    // source-shaped left sides; arbitrary values such as `PROD_SECRET_VALUE`
    // still detect.
    if !source_key_has_code_shape(source_key) {
        return false;
    }
    let value = value.trim();
    if !(4..=64).contains(&value.len())
        || value.bytes().any(|b| b.is_ascii_digit())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return false;
    }
    is_source_secret_name_reference_value(value)
}

fn is_source_fixture_secret_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Test fixtures often assign deliberately weak credentials to variables
    // named `expectedPassword`, `MOCK_ACCESS_TOKEN`, or similar. Do not suppress
    // weak values by value alone; require source syntax plus a fixture key name.
    source_key_has_code_shape(source_key) && is_source_fixture_secret_value(key_name, value)
}

fn is_source_struct_tag_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Go-style struct tags can contain generic `key:"name,option"` metadata.
    // The backtick-delimited tag syntax proves this is a field mapping, not
    // credential material.
    if key_name != "key" || !source_key_has_struct_tag_key(source_key) {
        return false;
    }
    let value = value.trim();
    (3..=96).contains(&value.len())
        && value.contains(',')
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'-' | b',' | b'=' | b'|' | b'(' | b')' | b'[' | b']' | b':'
                )
        })
}

fn source_key_has_struct_tag_key(source_key: &str) -> bool {
    let Some((_, tail)) = source_key.rsplit_once('`') else {
        return false;
    };
    normalize_key(tail) == "key"
}

fn is_source_prefix_constant_literal(value: &str, key_name: &str) -> bool {
    // Prefix constants (`FSCRYPT_KEY_DESC_PREFIX = "fscrypt:"`) name a public
    // namespace prefix. They are adjacent to key words but do not carry key
    // material.
    if !has_identifier_component(key_name, "prefix") {
        return false;
    }
    let value = value.trim();
    let Some(prefix) = value.strip_suffix(':') else {
        return false;
    };
    (2..=48).contains(&prefix.len())
        && prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !contains_dangerous_secret_component(prefix)
}

fn is_source_variable_reference_literal(value: &str, source_key: &str) -> bool {
    // Source code often assigns a sensitive-looking argument from a variable,
    // e.g. `Authorization = l_auth` or `$token = $this->token`. The variable
    // name is not the credential bytes. Keep this to source-shaped left sides
    // and identifier/member-reference syntax; quoted strings such as
    // `password = "hunter2"` still pass through.
    source_key_has_code_shape(source_key) && is_variable_reference_literal(value.trim())
}

fn is_variable_reference_literal(value: &str) -> bool {
    let value = value.trim_end_matches('\\').trim_matches('"');
    if !(3..=96).contains(&value.len()) {
        return false;
    }
    if let Some(rest) = value.strip_prefix('$') {
        return is_simple_code_reference_name(rest);
    }
    if value
        .strip_prefix("l_")
        .or_else(|| value.strip_prefix("m_"))
        .is_some_and(is_simple_code_reference_name)
    {
        return true;
    }
    value.contains('.')
        && value.split('.').all(is_simple_code_reference_name)
        && value.bytes().any(|b| b.is_ascii_lowercase())
        && !value.bytes().any(|b| b.is_ascii_digit())
}

fn is_source_string_fragment_literal(value: &str, source_key: &str) -> bool {
    // Objective-C and generated code can expose partial string syntax when an
    // embedded line is scanned from the middle, e.g. `apiURL: @\"...\\n`.
    // A complete `@"hunter2"` can be a real hardcoded secret, so require
    // source context plus escaped line/continuation evidence.
    if !source_key_has_code_shape(source_key) {
        return false;
    }
    let value = value.trim();
    value.starts_with("@\\\"") && (value.contains("\\n") || value.ends_with('\\'))
}

fn is_shell_command_substitution_literal(value: &str, source_key: &str) -> bool {
    // Shell completions/config scripts assign keys from command substitutions:
    // `local key=$(__docker_map_key_of_current_option ...)`. The captured
    // value is the command expression, not the generated key.
    if !source_key_has_code_shape(source_key) {
        return false;
    }
    let value = value.trim();
    let Some(body) = value.strip_prefix("$(") else {
        return false;
    };
    (3..=96).contains(&body.len())
        && body
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn is_inline_code_key_value_tail_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Help text commonly documents `key=value` inside backticks. Splitting at
    // `=` leaves `value`` as a fake credential; keep this to generic key
    // context and inline-code syntax.
    if !is_generic_metadata_key_name(key_name) || !source_key.contains('`') {
        return false;
    }
    value.trim() == "value`"
}

fn is_lower_dotted_config_name(value: &str) -> bool {
    value.contains('.')
        && !value.contains("://")
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || matches!(b, b'.' | b'_' | b'-'))
        && value.bytes().any(|b| b.is_ascii_lowercase())
}

fn is_lower_route_literal(value: &str) -> bool {
    value.starts_with('/')
        && (2..=80).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || matches!(b, b'/' | b'_' | b'-'))
        && value.bytes().any(|b| b.is_ascii_lowercase())
}

fn key_name_indicates_template_context(key_name: &str) -> bool {
    has_identifier_component(key_name, "template")
        || has_identifier_component(key_name, "format")
        || has_identifier_component(key_name, "message")
        || has_identifier_component(key_name, "header")
}

fn auth_template_value(key_name: &str, value: &str) -> bool {
    if !(has_identifier_component(key_name, "auth")
        || has_identifier_component(key_name, "authorization"))
    {
        return false;
    }
    let lower = value.trim_start().to_ascii_lowercase();
    lower.starts_with("basic ") || lower.starts_with("bearer ")
}

fn is_source_code_fragment_literal(value: &str) -> bool {
    // A separator inside source text can leave the "value" as a dangling code
    // fragment (`+ expr`, `, i);`, escaped interpolation placeholders). Those
    // fragments are syntax around a future value, not the value itself.
    let value = value.trim();
    value.starts_with(',')
        || value.starts_with(';')
        || value.starts_with("\\\"{")
        || is_object_method_call_fragment(value)
        || is_braced_type_initializer_fragment(value)
        || is_braced_field_initializer_fragment(value)
        || is_minified_js_descriptor_fragment(value)
        || is_escaped_format_fragment(value)
        || is_method_chain_suffix_fragment(value)
        || is_incomplete_objc_string_fragment(value)
        || value
            .strip_prefix('+')
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

fn is_object_method_call_fragment(value: &str) -> bool {
    // A parsed value like `$this->createMock(TokenInterface::class` is a method
    // call fragment. The runtime return value may be sensitive, but the source
    // expression itself is not.
    let value = value.trim();
    value.starts_with('$') && value.contains("->") && value.contains('(')
}

fn is_braced_type_initializer_fragment(value: &str) -> bool {
    // C/Go-style source fragments such as `yaml_token_t{` are type
    // initializers. The future object may hold a token, but the type name is not
    // the token value.
    let value = value.trim();
    let Some(stem) = value.strip_suffix('{') else {
        return false;
    };
    is_source_type_name_fragment(stem)
}

fn is_braced_field_initializer_fragment(value: &str) -> bool {
    // Go/C#/JS object snippets can be cut at a nested `Key:` separator:
    // `jose.JSONWebKey{Key:` or `PublicKey{KeyID:`. That is syntax, not data.
    let value = value.trim();
    let Some(stem) = value.strip_suffix(':') else {
        return false;
    };
    let Some((ty, field)) = stem.rsplit_once('{') else {
        return false;
    };
    is_source_type_name_fragment(ty)
        && (2..=64).contains(&field.len())
        && field
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_source_type_name_fragment(stem: &str) -> bool {
    let stem = stem.trim();
    (3..=100).contains(&stem.len())
        && stem
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        && (stem.bytes().any(|b| b == b'_')
            || stem.bytes().any(|b| b.is_ascii_uppercase())
            || stem.contains('.'))
}

fn is_minified_js_descriptor_fragment(value: &str) -> bool {
    // When a long minified object descriptor has several `{key:"...", value:...}`
    // pairs on one line, a later `key:` can make the previous tail look like a
    // credential. Function descriptor syntax proves this is source code.
    let value = value.trim();
    value.contains("value:function")
        && (value.contains("},{key:") || value.contains("},{key=\"") || value.contains("},{key:\""))
}

fn is_escaped_format_fragment(value: &str) -> bool {
    // Source strings often split logging format bodies after prose
    // (`"Decrypted secret:\n\t%q"`). Escaped whitespace plus a printf directive
    // is syntax around a future value, not the value itself.
    let value = value.trim_start();
    (value.starts_with("\\n") || value.starts_with("\\r") || value.starts_with("\\t"))
        && contains_printf_directive(value)
}

fn is_method_chain_suffix_fragment(value: &str) -> bool {
    // Java/C# builder chains can be cut after a sensitive-looking label inside
    // a string, yielding fragments such as `).append(getApiKey()).append(`.
    // Require method-call punctuation so hyphenated string values stay eligible.
    let value = value.trim();
    let Some(rest) = value.strip_prefix(").").or_else(|| value.strip_prefix('.')) else {
        return false;
    };
    if !rest.contains('(') {
        return false;
    }
    rest.split('.').all(|part| {
        let Some(name_end) = part.find('(') else {
            return false;
        };
        let name = &part[..name_end];
        !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && part[name_end + 1..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b')' | b'('))
    })
}

fn is_incomplete_objc_string_fragment(value: &str) -> bool {
    // `@"..."` is Objective-C string syntax. Suppress only escaped line
    // fragments, not complete literals such as `@"hunter2"`.
    let value = value.trim();
    value.starts_with("@\\\"") && (value.contains("\\n") || value.ends_with('\\'))
}

fn is_arithmetic_expression_literal(value: &str) -> bool {
    // Numeric/key-size expressions (`128+L*64`) are source code initializers.
    // Requiring every operand to be an identifier or number keeps base64-like
    // secrets with `+` or `/` from being rejected by this code-shape rule.
    let value = value.trim();
    if value.is_empty()
        || value.contains('=')
        || value.chars().any(char::is_whitespace)
        || !value.chars().any(|ch| matches!(ch, '+' | '*' | '/'))
    {
        return false;
    }
    let mut saw_operand = false;
    for part in value.split(['+', '-', '*', '/']) {
        if part.is_empty() {
            return false;
        }
        let bytes = part.as_bytes();
        let is_number = bytes.iter().all(u8::is_ascii_digit);
        let is_ident = bytes
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if !is_number && !is_ident {
            return false;
        }
        saw_operand = true;
    }
    saw_operand
}

fn is_interpolated_string_template(value: &str) -> bool {
    // Language interpolation prefixes (`f"Bearer {jwt}"`, `rf"..."`) mean the
    // literal is a template around runtime data. Masking the prefix would not
    // remove the actual credential and creates noisy partial spans.
    let value = value.trim_start().to_ascii_lowercase();
    ["f\"", "f'", "rf\"", "rf'", "fr\"", "fr'"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn is_public_key_literal(value: &str) -> bool {
    // OpenSSH public-key values are identifiers/public material. Private keys
    // are handled by the PEM detector; masking public key blobs as KEYED_SECRET
    // makes API responses and fixtures unusably noisy.
    let value = value.trim_start();
    value.starts_with("ssh-rsa ")
        || value.starts_with("ssh-ed25519 ")
        || value.starts_with("ecdsa-sha2-")
}

fn is_license_identifier_literal(value: &str, key_name: &str) -> bool {
    // JSON APIs often use `"license": {"key": "lgpl-3.0"}`. SPDX-style
    // license identifiers are metadata, not cryptographic keys; limit this to
    // generic/license key names so real `api_key` values are unaffected.
    if key_name != "key" && !has_identifier_component(key_name, "license") {
        return false;
    }
    let value = normalize_key(value);
    let first = value.split('_').next().unwrap_or_default();
    matches!(
        first,
        "mit" | "apache" | "gpl" | "lgpl" | "agpl" | "bsd" | "mpl" | "cc0" | "unlicense"
    ) && value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_dunder_identifier_literal(value: &str) -> bool {
    // Double-underscore strings such as `__vlist__` are framework/internal
    // identifiers. They contain punctuation but have no credential structure.
    let value = value.trim();
    value.len() >= 4
        && (value.starts_with("__") || value.ends_with("__"))
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_uppercase_constant_literal_for_generic_key(value: &str, key_name: &str) -> bool {
    // Generic `key` fields are also used for enum/constant names. An all-caps
    // identifier with no digits (`DEBUG_FRAME`) is source metadata; concrete
    // sensitive names such as `api_key` still use the normal detector path.
    if !is_generic_metadata_key_name(key_name) {
        return false;
    }
    let value = value.trim();
    (4..=64).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && !value.bytes().any(|b| b.is_ascii_digit())
        && value.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
}

fn is_generic_code_member_name_literal(value: &str, key_name: &str) -> bool {
    // Transpiled/minified object descriptors use generic `key` fields to name
    // methods and private members (`{key:"_onClose", value:function...}`).
    // Suppress only identifier-shaped member names under generic key metadata;
    // concrete `api_key`/`client_secret` values still use the normal path.
    if !is_generic_metadata_key_name(key_name) {
        return false;
    }
    let value = value.trim();
    let bytes = value.as_bytes();
    if !(3..=80).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'@'))
        || !bytes.iter().any(u8::is_ascii_alphabetic)
    {
        return false;
    }
    if value.starts_with("@@") {
        return bytes[2..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_');
    }
    if bytes.first().is_some_and(|b| matches!(b, b'_' | b'$'))
        && !bytes.iter().any(u8::is_ascii_digit)
    {
        return true;
    }
    if is_camel_case_code_reference(value) {
        return true;
    }
    let mut parts = value.split('_');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(rest) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && prefix.len() >= 2
        && prefix.bytes().all(|b| b.is_ascii_uppercase())
        && rest.bytes().any(|b| b.is_ascii_lowercase())
        && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_structured_key_name_reference_literal(value: &str, key_name: &str) -> bool {
    // Keep generic `key` semantics aligned with StructuralDetector: JSON/YAML
    // schema objects often store another field/widget name under a property
    // literally called `key`.
    is_generic_metadata_key_name(key_name) && is_structured_generic_key_metadata_value(value)
}

fn is_plain_prose_literal_for_generic_key(value: &str, key_name: &str) -> bool {
    // Generic keys in messages (`FAILED_TO_RETRIEVE_GENERATED_KEY =
    // "Failed to retrieve the generated key."`) describe UI/prose text. Real
    // secrets normally have compact token/password structure; phrase detectors
    // handle seed phrases before this function is reached.
    if !is_generic_metadata_key_name(key_name) {
        return false;
    }
    let value = value.trim();
    value.split_whitespace().count() >= 3
        && !value.chars().any(|ch| ch.is_ascii_digit())
        && value.chars().all(|ch| {
            ch.is_ascii_alphabetic()
                || ch.is_ascii_whitespace()
                || matches!(ch, '\'' | '"' | '.' | ',' | ':' | ';' | '!' | '?' | '-')
        })
}

fn is_generic_metadata_key_name(key_name: &str) -> bool {
    key_name == "key"
        || has_identifier_phrase(key_name, &["generated", "key"])
        || has_identifier_phrase(key_name, &["header", "key"])
        || has_identifier_phrase(key_name, &["license", "key"])
        || has_identifier_phrase(key_name, &["public", "key"])
}

fn is_locator_literal_for_key(value: &str, key_name: &str) -> bool {
    // Endpoint/url/uri/path/host keys normally name where to ask for a token,
    // not the token. Suppress only locator-shaped values without password
    // userinfo; password-bearing URLs remain visible to URL_CREDENTIAL rules.
    let value = value.trim();
    if key_name_indicates_locator(key_name) {
        return is_path_literal(value) || is_uri_literal_without_password_userinfo(value);
    }
    key_name_indicates_sensitive_material(key_name) && is_non_secret_locator_value(value, key_name)
}

fn is_secret_resource_metadata_literal(value: &str, key_name: &str) -> bool {
    // Orchestrators and deployment manifests use `secretName`, `secret.type`,
    // and `*_secret_ref` fields to name a secret object, not to store its bytes.
    // Keep this anchored to explicit name/type/ref/namespace key phrases so
    // material fields like `client_secret` and `password` still detect weak
    // values such as `tenant-7-trial` or `pass`.
    if !key_name_indicates_secret_metadata(key_name) {
        return false;
    }
    is_resource_name_literal(value)
}

fn key_name_indicates_secret_metadata(key_name: &str) -> bool {
    has_identifier_phrase(key_name, &["secret", "name"])
        || has_identifier_phrase(key_name, &["secret", "namespace"])
        || has_identifier_phrase(key_name, &["secret", "type"])
        || has_identifier_phrase(key_name, &["secret", "ref"])
        || has_identifier_phrase(key_name, &["secret", "reference"])
        || has_identifier_phrase(key_name, &["cert", "secret", "name"])
        || has_identifier_phrase(key_name, &["certificate", "secret", "name"])
        || matches!(
            key_name,
            "secretname" | "secretnamespace" | "secrettype" | "secretref" | "secretreference"
        )
}

fn is_resource_name_literal(value: &str) -> bool {
    let value = value.trim();
    if !(3..=253).contains(&value.len())
        || value.contains("://")
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'@' | b'=' | b'{' | b'}'))
    {
        return false;
    }
    let mut has_name_char = false;
    let mut has_separator = false;
    for label in value.split(['/', '.']) {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes.first().is_some_and(|b| !b.is_ascii_alphanumeric())
            || bytes.last().is_some_and(|b| !b.is_ascii_alphanumeric())
            || !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return false;
        }
        has_name_char |= bytes.iter().any(|b| b.is_ascii_lowercase());
        has_separator |= bytes.contains(&b'-');
    }
    has_name_char && (has_separator || value.contains('/') || value.contains('.'))
}

fn key_name_indicates_locator(key_name: &str) -> bool {
    has_identifier_component(key_name, "endpoint")
        || has_identifier_component(key_name, "url")
        || has_identifier_component(key_name, "uri")
        || has_identifier_component(key_name, "path")
        || has_identifier_component(key_name, "host")
}

fn key_name_indicates_sensitive_material(key_name: &str) -> bool {
    key_name.split('_').any(|part| {
        matches!(
            part,
            "password"
                | "passwd"
                | "pwd"
                | "pass"
                | "secret"
                | "token"
                | "credential"
                | "credentials"
                | "key"
        )
    })
}

fn is_non_secret_locator_value(value: &str, key_name: &str) -> bool {
    // A path or URL stored under a sensitive-looking key can name where a secret
    // lives (`credential_list_mappings`, `token: /oauth/token`) rather than the
    // secret itself. Do not suppress webhook/signed-url keys, URLs with
    // userinfo, or query/fragment-bearing URLs where the credential may be in
    // the locator itself.
    if has_identifier_component(key_name, "webhook")
        || has_identifier_component(key_name, "hook")
        || has_identifier_component(key_name, "signed")
    {
        return false;
    }
    if is_absolute_path_literal(value) && !value.bytes().any(|b| matches!(b, b'+' | b'=' | b'@')) {
        return true;
    }
    is_uri_literal_without_password_userinfo(value) && !value.contains(['?', '#'])
}

fn is_path_literal(value: &str) -> bool {
    is_absolute_path_literal(value) || is_relative_path_literal(value)
}

fn is_absolute_path_literal(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('\\')
        || value.as_bytes().get(..3).is_some_and(|prefix| {
            prefix[0].is_ascii_alphabetic() && prefix[1] == b':' && prefix[2] == b'\\'
        })
}

fn is_relative_path_literal(value: &str) -> bool {
    // Relative API endpoints (`_apis/token/...`) are locators too, but require a
    // slash and no whitespace so ordinary prose or templated strings are not
    // hidden by this path rule.
    value.contains('/')
        && !value.contains("://")
        && !value.chars().any(char::is_whitespace)
        && value
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_uri_literal_without_password_userinfo(value: &str) -> bool {
    if !(value.contains("://") || value.starts_with("git:")) {
        return false;
    }
    !uri_has_password_userinfo(value)
}

fn uri_has_password_userinfo(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return false;
    };
    userinfo.contains(':') || userinfo.to_ascii_lowercase().contains("%3a")
}

fn is_member_or_pointer_reference(value: &str) -> bool {
    // `conn->passwd`, `obj.token`, and similar member references point at
    // program state; they are not the credential value itself.
    if !(value.contains("->") || value.contains('.')) {
        return false;
    }
    value
        .split("->")
        .flat_map(|part| part.split('.'))
        .all(is_code_reference_segment)
}

fn is_code_reference_segment(segment: &str) -> bool {
    let segment = segment.trim_matches(|ch: char| matches!(ch, '&' | '*' | '(' | ')' | '[' | ']'));
    let bytes = segment.as_bytes();
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
}

fn key_allows_low_entropy_literal(name: &str, kind: KeyKind) -> bool {
    if matches!(kind, KeyKind::Token) {
        return matches!(
            name,
            "authorization"
                | "auth_token"
                | "access_token"
                | "refresh_token"
                | "id_token"
                | "bearer_token"
                | "session_token"
                | "token"
        ) || name.ends_with("_token");
    }
    matches!(
        name,
        "api_key"
            | "apikey"
            | "access_key"
            | "account_key"
            | "client_secret"
            | "password"
            | "passwd"
            | "pwd"
            | "passphrase"
            | "secret"
            | "signing_secret"
            | "webhook_secret"
            | "shared_secret"
            | "credential"
    )
}

fn is_plain_code_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(8..=64).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        || !bytes.iter().any(u8::is_ascii_alphabetic)
        || bytes.iter().any(u8::is_ascii_uppercase)
    {
        return false;
    }
    bytes.iter().any(|b| b.is_ascii_digit() || *b == b'_')
}

fn is_self_reference_code_value(key: &str, value: &str) -> bool {
    let key_name = normalize_key(key);
    let value_name = normalize_key(value);
    if value_name.is_empty() {
        return false;
    }
    key_name == value_name
        || key_name.ends_with(&format!("_{value_name}"))
        || key_name.strip_suffix("_key").is_some_and(|prefix| {
            prefix == value_name || prefix.ends_with(&format!("_{value_name}"))
        })
}

fn is_camel_case_code_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(4..=64).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$'))
        || !bytes
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'$'))
    {
        return false;
    }
    let has_lower = bytes.iter().any(u8::is_ascii_lowercase);
    let has_upper = bytes.iter().any(u8::is_ascii_uppercase);
    let starts_lower_or_symbol = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || matches!(b, b'_' | b'$'));
    let digit_count = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    starts_lower_or_symbol && has_lower && has_upper && digit_count <= 2
}

fn normalize_key(input: &str) -> String {
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

fn is_explicitly_non_sensitive_key(name: &str) -> bool {
    is_explicitly_non_sensitive_key_name(name)
}

fn is_otp_key_name(name: &str) -> bool {
    // `otp` is too short for substring matching: ordinary identifiers such as
    // `hotpink` contain those bytes. Require an identifier component or a known
    // auth-code phrase so color names and unrelated words do not become secrets.
    has_identifier_component(name, "otp")
        || has_identifier_component(name, "totp")
        || has_identifier_component(name, "mfa")
        || has_identifier_component(name, "2fa")
        || has_identifier_component(name, "passcode")
        || has_identifier_phrase(name, &["verification", "code"])
        || has_identifier_phrase(name, &["security", "code"])
        || has_identifier_phrase(name, &["login", "code"])
        || has_identifier_phrase(name, &["signin", "code"])
        || has_identifier_phrase(name, &["sign", "in", "code"])
        || has_identifier_phrase(name, &["one", "time"])
        || matches!(
            name,
            "verificationcode" | "securitycode" | "logincode" | "signincode" | "onetime"
        )
}

fn has_identifier_component(name: &str, component: &str) -> bool {
    name.split('_').any(|part| part == component)
}

fn has_identifier_phrase(name: &str, phrase: &[&str]) -> bool {
    let parts = name
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if phrase.is_empty() || parts.len() < phrase.len() {
        return false;
    }
    parts
        .windows(phrase.len())
        .any(|window| window.iter().zip(phrase).all(|(part, word)| part == word))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn trim_ascii_ws_start(text: &str, mut start: usize, end: usize) -> usize {
    while start < end && text.as_bytes()[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn trim_ascii_ws_end(text: &str, start: usize, mut end: usize) -> usize {
    while start < end && text.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

fn matches_ignore_ascii_case(value: &str, options: &[&str]) -> bool {
    options
        .iter()
        .any(|option| value.eq_ignore_ascii_case(option))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn hits(raw: &str) -> Vec<(String, String)> {
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        KeyValueDetector
            .detect(&view)
            .into_iter()
            .map(|span| {
                (
                    span.label,
                    raw[span.range.start..span.range.end].to_string(),
                )
            })
            .collect()
    }

    fn has(raw: &str, value: &str) -> bool {
        hits(raw).iter().any(|(_, got)| got == value)
    }

    #[test]
    fn masks_structured_keyed_values_only() {
        assert!(has("password is summer-2026! for the demo", "summer-2026"));
        assert!(has("client_secret: tenant-7-trial", "tenant-7-trial"));
        assert!(has("client_secret: tenant7trial", "tenant7trial"));
        assert!(has("password=letmein123", "letmein123"));
        assert!(has("api_key=abc12345", "abc12345"));
        assert!(has("api_key=ABCDEF123456", "ABCDEF123456"));
        assert!(has(
            "Key = 7f20a9c44e5d32b8c91f0a6e2db74c18",
            "7f20a9c44e5d32b8c91f0a6e2db74c18"
        ));
        assert!(has(
            "kubeadm_certificate_key: 2508f90d8b140454cdd0295e5dd7eca3fb1e7fbcae48b40ac62aa84fec9ad829",
            "2508f90d8b140454cdd0295e5dd7eca3fb1e7fbcae48b40ac62aa84fec9ad829"
        ));
        assert!(has(
            "OVH_APPLICATION_SECRET=a0996701ccf106b90376bbead9a671140",
            "a0996701ccf106b90376bbead9a671140"
        ));
        assert!(has("-kdfopt hexkey:f19b759b190126", "f19b759b190126"));
        assert!(has("Ctrl.hexsalt = hexsalt:2c86362d", "2c86362d"));
        assert!(has(r#"key: "abcDEF123456""#, "abcDEF123456"));
        assert!(has(r#"api_key="%s-real-123""#, "%s-real-123"));
        assert!(has(r#"password="SECRET""#, "SECRET"));
        assert!(has(r#"password="PROD_SECRET""#, "PROD_SECRET"));
        assert!(has(r#"client_secret="OLD_SECRET""#, "OLD_SECRET"));
        assert!(has(
            r#"private const string ApiKey = "PROD_SECRET_VALUE";"#,
            "PROD_SECRET_VALUE"
        ));
        assert!(has(
            r#"public const string ServicePrincipalSecret = "GCM_AZREPOS_SP_SECRET";"#,
            "GCM_AZREPOS_SP_SECRET"
        ));
        assert!(has(r#"context.Token = "CustomToken";"#, "CustomToken"));
        assert!(has(r#"password = "pass""#, "pass"));
        assert!(has(r#"password = "secret""#, "secret"));
        assert!(has(r#"password = "letmein123""#, "letmein123"));
        assert!(has(r#"api_key="--real-secret-123""#, "--real-secret-123"));
        assert!(has(
            r#"private const string ApiKey = "abc12345";"#,
            "abc12345"
        ));
        assert!(has("api_key: Abc123Secret", "Abc123Secret"));
        assert!(has("api_key=Abc-2048", "Abc-2048"));
        assert!(has(r#"password="{{secret123}}""#, "{{secret123}}"));
        assert!(has(
            r#"password="redis://:secret@localhost:6379/1""#,
            "redis://:secret@localhost:6379/1"
        ));
        assert!(has("otp=100482 expires soon", "100482"));
        assert!(has("verification_code=100482", "100482"));
        assert!(has(
            "k8s secret data api-key: abcDEF123456+/==",
            "abcDEF123456+/=="
        ));
        assert!(has(
            "Authorization: Bearer eyJabcdefghijklmnop123456",
            "eyJabcdefghijklmnop123456"
        ));
        assert!(has("Authorization: Bearer abcdefgh123", "abcdefgh123"));
        assert!(has(
            r#"refresh_token="6nA7WEJ/bBBCY06IrWwAlks7""#,
            "6nA7WEJ/bBBCY06IrWwAlks7"
        ));
        assert!(has(
            r#"authorization: 'Basic Wv0dTjLryp=='"#,
            "Wv0dTjLryp=="
        ));
        assert!(has(
            r#"authorization: 'ApiKey Fy0ySzEbqm=='"#,
            "Fy0ySzEbqm=="
        ));
        assert!(has("body=\"access_token=abc12345&state=ok\"", "abc12345"));
        assert!(has(
            r#"token = "0abc0d.xyz123abc456def""#,
            "0abc0d.xyz123abc456def"
        ));
        assert!(has("dbPassword = \"hunter2\"", "hunter2"));
        assert!(has(
            "OAuth app client_secret 'tenant-7-trial'",
            "tenant-7-trial"
        ));
    }

    #[test]
    fn rejects_natural_language_and_benign_counters() {
        for raw in [
            "secret capability",
            "token budget",
            "api design",
            "password field docs",
            r#"natural language such as "secret capability" or "token budget"."#,
            r#"The secret "capability" mode is documented here."#,
            "secret: capability",
            "hotpink: 16738740,",
            "token_budget=30000",
            "public_token_label=docs",
            "port=5432 workers=4 timeout_ms=30000 status=200",
            "Authorization: Bearer docs",
            r#"authorization: "Basic docs""#,
            r#"authorization: "ApiKey docs""#,
            "jwt_like=aaa.bbb.ccc",
            "Authorization: Basic login_and_password_removed",
            "password=start_pass_downsample",
            "client_secret=tenant_trial",
            "struct SessionHandle *data = conn->data;",
            "neg_ctx->output_token_length = out_sec_buff.cbBuffer;",
            "key = app_data->perthreadkey;",
            "spnegoTokenLength = input_token.length;",
            "pwd = conn->passwd;",
            r#"auth="GSS-Negotiate";"#,
            r#"auth &= ~CURLAUTH_NTLM;"#,
            r#"if(smtpc->state == SMTP_EHLO && len >= 5 && !memcmp(line, "AUTH ", 5)) {"#,
            "for (Key* key : m_keys) {",
            "for (const Key* key : *KeyboardShortcuts::instance()) {",
            "keybit = (keytype == LIBSSH2_HOSTKEY_TYPE_RSA)?\n  LIBSSH2_KNOWNHOST_KEY_SSHRSA:LIBSSH2_KNOWNHOST_KEY_SSHDSS;",
            "let choice = ok ? ACCESS_TOKEN:REFRESH_TOKEN;",
            "data->set.ssl.password = data->set.str[STRING_TLSAUTH_PASSWORD];",
            "private const string InstallManifestFileName = \"install-manifest.json\";",
            "private const int HResultEHANDLE = -2147024890;",
            r#"<add key="Microsoft and .NET" value="true" />"#,
            r#"<assemblyIdentity name="nunit.framework" publicKeyToken="2638cd05610744eb" culture="neutral" />"#,
            "section.key=value1",
            "conn->bits.user_passwd = data->set.userpwd?1:0;",
            "*m_key = *m_keyOrig;",
            r#"self.basic_auth = "Basic {}".format(user, password)"#,
            r#"auth_header_template = "Bearer ${token}""#,
            r#"secret_format = "%s""#,
            r#"export GCM_CREDENTIAL_CACHE_OPTIONS="--timeout 300""#,
            r#"protected override string CredentialFileExtension => ".gpg";"#,
            r#"var tokenValue = "OAUTH-TOKEN";"#,
            r#"const string servicePrincipalSecret = "CLIENT-SECRET";"#,
            "gss_buffer_desc token = GSS_C_EMPTY_BUFFER;",
            "gss_buffer_desc* gss_token = GSS_C_NO_BUFFER;",
            "module_ctx->module_pwdump_column = MODULE_DEFAULT;",
            r#"TRACE(PREFIX_I "Key %i missing:", i);"#,
            r#""Git could not get credentials: " + gitCredentialOutput.Errors,"#,
            r#"uint KeyLength=128+L*64;"#,
            r#""Decrypted secret:\n\t%q","#,
            r#"string tokenEndpoint = "/oauth/token";"#,
            r#"const string sessionTokenUrl = "_apis/token/sessiontokens?api-version=1.0";"#,
            r#"authorization_uri=https://login.microsoftonline.com/tenant1"#,
            r#"var response = "id_token=my_id_token&state=protected_state&code=my_code";"#,
            r#"access_token = "Test Access Token","#,
            r#"refresh_token = "Test Refresh Token""#,
            r#"val FAILED_TO_RETRIEVE_GENERATED_KEY = "Failed to retrieve the generated key.""#,
            r#"POSTGRES_HOST_AUTH_METHOD: scram-sha-256"#,
            r#"c.key = "__vlist__" + nestedIndex;"#,
            r#"DEBUG_HEADER_KEY = "DEBUG_FRAME""#,
            r#"self.__authorizationHeader = f"Bearer {jwt}""#,
            r#"{"license": {"key": "lgpl-3.0"}}"#,
            r#"{"key":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCexample"}"#,
            r#"var correlationKey = ".xsrf";"#,
            r#"public const string IsW365EnvironmentKeyName = "IsW365Environment";"#,
            r#"public const string PasswordStoreDirEnvar = "PASSWORD_STORE_DIR";"#,
            r#"public const string GcmTraceSecrets = "GCM_TRACE_SECRETS";"#,
            r#"public const string MsAuthFlow = "GCM_MSAUTH_FLOW";"#,
            r#"public const string HttpSslCertPasswordProtected = "http.sslcertpasswordprotected";"#,
            r#"public const string DataCenterPasswordReset = "/passwordreset";"#,
            r#"o.ClientSecret = Configuration["github-token:clientsecret"];"#,
            r#"g = Github(base_url="https://host/api/v3", login_or_token="access_token")"#,
            r#"password = "my_password"  # Can be left empty if not used"#,
            r#"oauth_token = "my_token"  # Can be left empty if not used"#,
            r#"password: "$t(lockRoomPasswordUppercase):""#,
            r#"password: "i18n.t(auth.setup.instructions)""#,
            r#"openstack_password: "{{ lookup('env','OS_PASSWORD') }}""#,
            r#"vsphere_password: '{{ lookup("env", "VSPHERE_PASSWORD") }}'"#,
            r#"access_token = "TestAuthToken""#,
            r#"const string expectedAccessToken = "LET_ME_IN";"#,
            r#"const string expectedAccessToken1 = "LET_ME_IN-1";"#,
            r#"private const string MOCK_ACCESS_TOKEN = "at-0987654321";"#,
            r#"private const string MOCK_REFRESH_TOKEN = "rt-1234567809";"#,
            r#"const string expectedPassword = "letmein123";"#,
        ] {
            assert!(hits(raw).is_empty(), "{raw}: {:?}", hits(raw));
        }
    }

    #[test]
    fn keeps_plain_config_uppercase_secret_candidates() {
        assert!(has("api_key=ABC_DEF_123", "ABC_DEF_123"));
        assert!(has(
            r#"private const string ApiKey = "ABC_DEF_123";"#,
            "ABC_DEF_123"
        ));
        assert!(has(r#"key: "sk-test-token""#, "sk-test-token"));
        assert!(has(r#"key: "tenant-7-trial""#, "tenant-7-trial"));
        assert!(has(
            r#"password: "<code>sk-test-token</code>""#,
            "<code>sk-test-token</code>"
        ));
        assert!(has(r#"password = "abc%[3]s""#, "abc%[3]s"));
        assert!(has(r#"private_key = "tenant-7-trial""#, "tenant-7-trial"));
        assert!(has(
            r#"private_key = "ALICE_prod_key_2026""#,
            "ALICE_prod_key_2026"
        ));
        assert!(has(r#"key: "abc123</p>""#, "abc123</p>"));
        assert!(has(r#"api_key = "abc123,def456""#, "abc123,def456"));
        assert!(has(
            r#""documentation": "<p>Key: sk-test-token</p>""#,
            "sk-test-token</p>"
        ));
        assert!(has(
            r#"{"body":"\u003cp\u003eapi_key: sk-test-token\u003c/p\u003e"}"#,
            "sk-test-token\\u003c/p\\u003e"
        ));
        assert!(has(r#"password_prefix = "secret:""#, "secret:"));
        assert!(has(r#"api_key = "$(secret_command""#, "$(secret_command"));
        assert!(has(
            r#"password = "Correct horse battery staple!""#,
            "Correct horse battery staple!"
        ));
        assert!(has(r#"passwordLabel = "tenant-7-trial""#, "tenant-7-trial"));
    }

    #[test]
    fn rejects_source_type_annotations_and_code_initializers() {
        for raw in [
            "session: Option<String>,",
            "csrf: [u8; 32],",
            "env_names: BTreeSet<String>,",
            r#"_FASTAPI_INCLUDED_ROUTER_KEY = "included_router""#,
            "child_scope = {_FASTAPI_SCOPE_KEY: {_FASTAPI_FRONTEND_PATH_KEY: frontend_path}}",
            "cancelToken: defaultToConfig2,",
            "withCredentials: defaultToConfig2,",
            "secret: Base32SecretKey,",
            ">(secret: Base32SecretKey, options: Readonly<T>): Promise<HexString> {",
            "public decode(secret: Base32SecretKey): SecretKey {",
            r#"Attributes map[string]string `protobuf_key:"bytes,1,opt,name=key,proto3"`"#,
            r#"Level map[uint32]string `protobuf_key:"varint,1,opt,name=key,proto3"`"#,
            r#"PrivateKey = RSA-2048"#,
            r#"Key = RSA-2048"#,
            r#"PrivateKey = RSA-PSS"#,
            r#"PrivateKey=RSA-OAEP-1"#,
            r#"PrivateKey=KAS-ECC-CDH_P-192_C0"#,
            r#"PrivPubKeyPair = KAS-ECC-CDH_P-192_C0:KAS-ECC-CDH_P-192_C0-PUBLIC"#,
            r#"PeerKey=ALICE_secp112r1_PUB"#,
            r#"PrivateKey=BOB_cf_brainpoolP160r1"#,
            r#"PrivPubKeyPair = Alice-25519:Alice-25519-PUBLIC"#,
            r#"PeerKey=ED25519-1-PUBLIC-Raw"#,
            r#"PrivateKey=P-256"#,
            r#"PrivateKey=PRIME192V1_RFC5114-Peer"#,
            r#"PrivPubKeyPair = SECP224R1_RFC5114:SECP224R1_RFC5114-PUBLIC"#,
            r#"OBJ_dhKeyAgreement="\x2A\x86\x48\x86\xF7\x0D\x01\x03\x01""#,
            r#"OBJ_pkcs9_challengePassword="\x2A\x86\x48\x86\xF7\x0D\x01\x09\x07""#,
            r#"passwordEnteredInvalid: "Invalid password for room \"%s\".""#,
            r#"labelPassword: "Mot de passe&thinsp;:""#,
            r#"enterRoomPassword: "Raum \"%s\" ist durch ein Passwort geschützt.""#,
            r#"Authorization algorithm = "AWS4-HMAC-SHA256""#,
            r#"documentation: "<code>12345678-1234-1234-1234-123456789012</code>""#,
            r#"documentation: "<code>alias/aws/kinesis</code>""#,
            r#"TopologyKey: "k8s.io/zone""#,
            r#"private_key = "%[3]s""#,
            r#"sb.append("DbPassword: ").append("***Sensitive Data Redacted***").append(",");"#,
            r#"sb.append("ApiKey: ").append(getApiKey()).append(",");"#,
            r#""fluentSetterDocumentation": "/**<p>Key: CreatedTime</p>""#,
            r#""fluentSetterDocumentation": "<p>Key: tag:<i>my-tag-key</i>""#,
            r#""documentation": "<p>Allowed condition Key: resource-groups:ResourceTypeFilters""#,
            r#""documentation": "<p>If the value for the key property is OBJECT_EXTENSION or OBJECT_KEY""#,
            r#""documentation": "<p>Valid filter keys include <code>NAME_PREFIX</code>: a name prefix""#,
            r#"TrueFromOne bool `key:"yesone,string"`"#,
            r#"Mode string `key:"value,options=first|second"`"#,
            r#"Amount int `key:"value3,range=(1:5]"`"#,
            r#"FSCRYPT_KEY_DESC_PREFIX = "fscrypt:""#,
            r#"local key=$(__docker_map_key_of_current_option '--filter|-f')"#,
            r#"cmd.Flags().StringArrayVarP(&opts.RawFields, "raw-field", "f", nil, "Add a string parameter in `key=value` format")"#,
            r#"Key = 000102030405060708090A0B0C0D0E0F"#,
            r#"Key = 404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"#,
            r#"Key = 00112233445566778899AABBCCDDEEFF"#,
            r#"Key = 0123456789ABCDEFFEDCBA9876543210"#,
            r#"Key = E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0"#,
            r#"key_as_string: "2017-01-01""#,
            r#"key_as_string: "2018-07-10T05:20:00.000-06:00""#,
            r#"key_as_string: "2018-07-10T05:20:00Z""#,
            r#"aggregations.histo.buckets.3.key_as_string: "2017-01-01T08:00:00.000Z""#,
            r#"key: "Authorization""#,
            r#"key: "grant_type""#,
            r#"key: "offset""#,
            r#"key: "host""#,
            r#"key: "Vary""#,
            r#"key: "Dev Gateway Region""#,
            r#"key: "HappyFace.jpg""#,
            r#"key: "cost-center""#,
            r#"key: "clean-cilium-state""#,
            r#"key: "x-amazon-apigateway-authtype""#,
            r#"key: "panel1""#,
            r#"key: "dataGrid12""#,
            r#"secretName: kube-ovn-tls"#,
            r#"adminSecretName: cephfs-provisioner"#,
            r#"rbd_provisioner_user_secret_namespace: rbd-provisioner"#,
            r#"secret.type = "kubernetes.io/tls""#,
            r#"- "--hubble-ca-secret-name=hubble-ca-secret""#,
            r#"password: https://secrets.elastic.co:8200"#,
            r#""token": "/one/two/three""#,
            r#""credential_list_mappings": "/2010-04-01/Accounts/ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/CredentialListMappings.json""#,
            r#"$privateKey = 'file://' . __DIR__ . '/../private.key';"#,
            r#"{key:"_onClose",value:function(){}}"#,
            r#"{key:"_reset",value:function(){}}"#,
            r#"{key:"UNSAFE_componentWillReceiveProps",value:function(){}}"#,
            r#"{key:"getBase64ForTag",value:function(){}}"#,
            r#"{key:"@@iterator",value:Symbol.iterator}"#,
            r#"EnvPubKeyFingerprint: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00","#,
            r#"$token = Get-NtToken -Primary -Duplicate"#,
            r#"$token = $this->createMock(TokenInterface::class);"#,
            r#"*token = yaml_token_t{}"#,
            r#"key: Some("password".to_string()),"#,
            r#"path: Some("structured.password".to_string()),"#,
            r#"prompt: "Use secret?","#,
            "private = raw_params[:1]",
            "password = os.environ.get('PASSWORD')",
            "let mut key_hex = None;",
            "key_hex = Some(value.to_string());",
            "let key_hex = key_hex?;",
            "fn heartbeat_payload(time_ms: u128, key_hex: &str, port: Option<u16>) -> String {",
            r#"canonical_field(&mut out, "key", key_hex);"#,
            r#"let session = unique_session("forged-heartbeat-key");"#,
            "hexkey=not-a-hex-123",
            "PasswordCredentials: internal.PasswordCredentials{",
            "Key: jose.JSONWebKey{Key: j.privKey, KeyID: j.kid},",
            r#"{key:"linear",value:function(n){return n}},{key:"cubic",value:function(n){return n*n*n}}"#,
            r#"{"body":"\u003cpre\u003e\u003ccode\u003econfig(httpheader = c(\"Authorization\" = l_auth))\u003c/code\u003e\u003c/pre\u003e"}"#,
            r#"private const string Header = auth.value;"#,
            r#"{"body":"\u003cpre\u003e\u003ccode\u003e'GET /signup': {view:'signup'}\u003c/code\u003e\u003c/pre\u003e"}"#,
            r#"{"body":"\u003cpre\u003e\u003ccode\u003ecredentials: @\"apiURL\\n];\u003c/code\u003e\u003c/pre\u003e"}"#,
            "/// Bitcoin address: base58check, P2PKH (0x00, '1') or P2SH (0x05, '3').",
            "/// Bitcoin WIF private key: base58check, version 0x80.",
        ] {
            assert!(hits(raw).is_empty(), "{raw}: {:?}", hits(raw));
        }
    }

    #[test]
    fn ternary_lookback_handles_utf8_before_line() {
        let raw = format!(
            "{}\nlet choice = ok ? ACCESS_TOKEN:REFRESH_TOKEN;",
            "\u{4eba}".repeat(80)
        );
        assert!(hits(&raw).is_empty(), "{raw}: {:?}", hits(&raw));
    }

    #[test]
    fn masks_each_value_without_key_or_separator() {
        let raw = "client_secret: tenant-7-trial api_key=abcDEF123456";
        let got = hits(raw);
        assert!(got.iter().any(|(_, value)| value == "tenant-7-trial"));
        assert!(got.iter().any(|(_, value)| value == "abcDEF123456"));
        assert!(got
            .iter()
            .all(|(_, value)| !value.contains("client_secret")));
        assert!(got.iter().all(|(_, value)| !value.contains("api_key")));
    }
}
