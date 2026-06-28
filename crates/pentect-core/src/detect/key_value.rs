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
    let kind = match if separator.kind == Separator::ImplicitQuote {
        trailing_sensitive_key_kind(key)
    } else {
        sensitive_key_kind(key)
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
    let key_name = normalize_key(key);
    if !value.quoted && is_self_reference_code_value(key, raw_value) {
        return false;
    }
    if !value.quoted && is_code_type_or_expression(raw_value, &key_name, kind) {
        return false;
    }
    if !looks_like_secret_value(raw_value, kind, value.quoted, separator.kind, &key_name) {
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
    if i > 0 && matches!(bytes[i - 1], b'=' | b'!' | b'<' | b'>') {
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
            "session",
            "cookie",
            "jwt",
        ],
    ) || name == "token"
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
        end = start + offset + ch.len_utf8();
    }
    end
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

    let has_alpha = value.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_ascii_whitespace());
    let has_space = value.chars().any(char::is_whitespace);

    if quoted && chars >= 4 {
        if separator == Separator::ImplicitQuote {
            return has_digit || has_symbol;
        }
        return has_digit || has_symbol || key_allows_low_entropy_literal(key_name, kind);
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
    let normalized = normalize_key(value);
    matches!(
        normalized.as_str(),
        "" | "true"
            | "false"
            | "null"
            | "none"
            | "nil"
            | "undefined"
            | "example"
            | "sample"
            | "placeholder"
            | "redacted"
            | "masked"
    )
}

fn is_code_type_or_expression(value: &str, key_name: &str, kind: KeyKind) -> bool {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
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
    let starts_like_type = value
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase());
    has_type_punctuation || starts_like_type
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
    !value_name.is_empty()
        && (key_name == value_name || key_name.ends_with(&format!("_{value_name}")))
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
    name == "nonsecret"
        || name == "non_secret"
        || name == "notsecret"
        || name == "not_secret"
        || name == "public"
        || name.starts_with("public_")
        || name.ends_with("_public")
}

fn is_otp_key_name(name: &str) -> bool {
    contains_any(
        name,
        &[
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
        ],
    )
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
        assert!(has("otp=100482 expires soon", "100482"));
        assert!(has(
            "k8s secret data api-key: abcDEF123456+/==",
            "abcDEF123456+/=="
        ));
        assert!(has(
            "Authorization: Bearer eyJabcdefghijklmnop123456",
            "eyJabcdefghijklmnop123456"
        ));
        assert!(has("Authorization: Bearer abcdefgh123", "abcdefgh123"));
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
            "token_budget=30000",
            "public_token_label=docs",
            "port=5432 workers=4 timeout_ms=30000 status=200",
            "Authorization: Bearer docs",
            "jwt_like=aaa.bbb.ccc",
        ] {
            assert!(hits(raw).is_empty(), "{raw}: {:?}", hits(raw));
        }
    }

    #[test]
    fn rejects_source_type_annotations_and_code_initializers() {
        for raw in [
            "session: Option<String>,",
            "csrf: [u8; 32],",
            "env_names: BTreeSet<String>,",
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
