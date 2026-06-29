use super::benign::{
    is_explicitly_non_sensitive_key_name, is_non_secret_source_constant_value,
    is_placeholder_value, is_source_fixture_secret_value, is_source_secret_name_reference_value,
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
        matches!(self, KeyKind::Strong | KeyKind::Otp | KeyKind::Phrase)
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
        return (start < end).then_some(ValueCandidate {
            start,
            end,
            quoted: true,
        });
    }

    if matches!(kind, KeyKind::Token | KeyKind::Strong) {
        let first_end = scan_unquoted_token_end(text, pos, line_end);
        let first = &text[pos..first_end];
        if matches_ignore_ascii_case(first, &["bearer", "basic", "token"]) {
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
        || is_cli_option_literal(value, key_name)
        || is_file_extension_literal(value, key_name)
        || is_source_constant_reference_literal(value, source_key)
        || is_source_config_name_literal(value, source_key)
        || is_source_sensitive_name_reference_literal(value, source_key)
        || is_source_fixture_secret_literal(value, key_name, source_key)
        || is_source_code_fragment_literal(value)
        || is_arithmetic_expression_literal(value)
        || is_interpolated_string_template(value)
        || is_public_key_literal(value)
        || is_license_identifier_literal(value, key_name)
        || is_dunder_identifier_literal(value)
        || is_uppercase_constant_literal_for_generic_key(value, key_name)
        || is_plain_prose_literal_for_generic_key(value, key_name)
        || is_locator_literal_for_key(value, key_name)
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
    let normalized = normalize_key(value);
    matches!(
        normalized.as_str(),
        "" | "true" | "false" | "null" | "none" | "nil" | "undefined"
    )
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
    if is_plain_code_identifier(value) && !key_allows_low_entropy_literal(key_name, kind) {
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
    key_name_indicates_template_context(key_name) || auth_template_value(key_name, value)
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
        i += 1;
        if i + 1 < bytes.len() && bytes[i].is_ascii_hexdigit() && bytes[i + 1].is_ascii_hexdigit() {
            i += 2;
            continue;
        }
        if bytes[i] == b'%' {
            i += 1;
            continue;
        }
        while i < bytes.len() && matches!(bytes[i], b'#' | b'0' | b'-' | b'+' | b' ' | b'.') {
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            return true;
        }
    }
    false
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
        || is_escaped_format_fragment(value)
        || value
            .strip_prefix('+')
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

fn is_escaped_format_fragment(value: &str) -> bool {
    // Source strings often split logging format bodies after prose
    // (`"Decrypted secret:\n\t%q"`). Escaped whitespace plus a printf directive
    // is syntax around a future value, not the value itself.
    let value = value.trim_start();
    (value.starts_with("\\n") || value.starts_with("\\r") || value.starts_with("\\t"))
        && contains_printf_directive(value)
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
    if !key_name_indicates_locator(key_name) {
        return false;
    }
    let value = value.trim();
    is_path_literal(value) || is_uri_literal_without_password_userinfo(value)
}

fn key_name_indicates_locator(key_name: &str) -> bool {
    has_identifier_component(key_name, "endpoint")
        || has_identifier_component(key_name, "url")
        || has_identifier_component(key_name, "uri")
        || has_identifier_component(key_name, "path")
        || has_identifier_component(key_name, "host")
}

fn is_path_literal(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with('\\')
        || value.as_bytes().get(..3).is_some_and(|prefix| {
            prefix[0].is_ascii_alphabetic() && prefix[1] == b':' && prefix[2] == b'\\'
        })
        || is_relative_path_literal(value)
}

fn is_relative_path_literal(value: &str) -> bool {
    // Relative API endpoints (`_apis/token/...`) are locators too, but require a
    // slash and no whitespace so ordinary prose or templated strings are not
    // hidden by this path rule.
    value.contains('/')
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
        assert!(has("body=\"access_token=abc12345&state=ok\"", "abc12345"));
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
            r#"public const string HttpSslCertPasswordProtected = "http.sslcertpasswordprotected";"#,
            r#"public const string DataCenterPasswordReset = "/passwordreset";"#,
            r#"o.ClientSecret = Configuration["github-token:clientsecret"];"#,
            r#"g = Github(base_url="https://host/api/v3", login_or_token="access_token")"#,
            r#"password = "my_password"  # Can be left empty if not used"#,
            r#"oauth_token = "my_token"  # Can be left empty if not used"#,
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
            "/// Bitcoin address: base58check, P2PKH (0x00, '1') or P2SH (0x05, '3').",
            "/// Bitcoin WIF private key: base58check, version 0x80.",
        ] {
            assert!(hits(raw).is_empty(), "{raw}: {:?}", hits(raw));
        }
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
