use super::benign::is_structured_metadata_key;
use super::util::token_runs;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};

/// Default minimum run length before a token is entropy-eligible. Long enough to
/// skip short benign tokens (UUID segments, short ids) while catching real keys.
pub const DEFAULT_ENTROPY_MIN_LEN: usize = 24;
/// Default Shannon bits/char above which a run is opaque. base64 ciphertext sits
/// ~5-6, hex digests ~3.9; 3.2 catches those while sparing ordinary identifiers.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 3.2;

/// Flags long, high-entropy codec-alphabet runs as likely opaque secrets.
pub struct EntropyDetector {
    min_len: usize,
    threshold: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::with(DEFAULT_ENTROPY_MIN_LEN, DEFAULT_ENTROPY_THRESHOLD)
    }
}

impl EntropyDetector {
    /// `min_len` is floored at the placeholder hash width: a run shorter than the
    /// hash we would emit isn't worth masking (the placeholder would be longer
    /// than the original and just as opaque), and Shannon needs that many symbols
    /// to mean much. Idempotency on already-rendered placeholders comes from
    /// placeholder protection, not from this floor.
    pub fn with(min_len: usize, threshold: f64) -> Self {
        Self {
            min_len: min_len.max(crate::placeholder::HASH_HEX_WIDTH),
            threshold,
        }
    }
}

impl Detector for EntropyDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let mut out = Vec::new();
        for (start, end) in token_runs(text) {
            let run = &text[start..end];
            if let Some(assignment) = assignment_parts(run) {
                self.push_entropy_span(text, start + assignment.value_start, end, view, &mut out);
                continue;
            }
            self.push_entropy_span(text, start, end, view, &mut out);
        }
        out
    }
}

impl EntropyDetector {
    fn push_entropy_span(
        &self,
        text: &str,
        start: usize,
        end: usize,
        view: &NormalizedView,
        out: &mut Vec<Span>,
    ) {
        let run = &text[start..end];
        if is_slash_delimited_path_like(run) {
            for (seg_start, seg_end) in slash_segments(run, start) {
                self.push_single_entropy_span(text, seg_start, seg_end, view, out);
            }
            return;
        }
        self.push_single_entropy_span(text, start, end, view, out);
    }

    fn push_single_entropy_span(
        &self,
        text: &str,
        start: usize,
        end: usize,
        view: &NormalizedView,
        out: &mut Vec<Span>,
    ) {
        let run = &text[start..end];
        if run.len() < self.min_len
            || !entropy_candidate(run, text, start, end)
            || shannon(run.as_bytes()) < self.threshold
        {
            return;
        }
        if is_structured_metadata_value(text, start, &view.region.ctx, run)
            || is_encoded_public_metadata_value(run)
            || is_public_key_context(text, start, &view.region.ctx)
        {
            return;
        }
        out.push(Span {
            range: view.to_raw(ByteRange::new(start, end)),
            category: Category::Secret,
            label: labels::LIKELY_SECRET.to_string(),
            confidence: Confidence::Low,
            source: DetectorId::Entropy,
        });
    }
}

struct Assignment {
    value_start: usize,
}

fn assignment_parts(run: &str) -> Option<Assignment> {
    let eq = run.find('=')?;
    let key = &run[..eq];
    let value = &run[eq + 1..];
    if key.is_empty()
        || value.is_empty()
        || value.starts_with('=')
        || key.as_bytes()[0].is_ascii_digit()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return None;
    }
    Some(Assignment {
        value_start: eq + 1,
    })
}

fn entropy_candidate(run: &str, text: &str, start: usize, end: usize) -> bool {
    has_opaque_mix(run)
        && !is_assignment_name_fragment(run)
        && !is_operator_expression_fragment(run)
        && !is_slash_separated_identifier_list(run)
        && !is_code_arithmetic_constant(run)
        && !is_uppercase_constant_identifier(run)
        && !is_source_identifier_like(run, text, start, end)
        && !is_regex_character_class_fragment(text, start, end)
}

fn is_assignment_name_fragment(run: &str) -> bool {
    // Tokenization includes `=` so source attributes like
    // `horizontalHuggingPriority=` can look like one opaque run. Do not reject
    // base64 padding globally; only suppress identifier-shaped names with a
    // trailing assignment marker and no codec/digit evidence.
    let Some(name) = run.strip_suffix('=') else {
        return false;
    };
    !name.is_empty()
        && !name.bytes().any(|b| b.is_ascii_digit())
        && !name.bytes().any(|b| matches!(b, b'+' | b'/'))
        && is_source_identifier_shape(name)
}

fn is_structured_metadata_value(text: &str, start: usize, ctx: &Context, value: &str) -> bool {
    // This only retracts raw entropy guesses in structured JSON metadata fields.
    // Rationale: fields like `node_id`, `sha`, and `etag` conventionally carry
    // opaque identifiers/hashes. They are not credentials unless another
    // detector can anchor them to a sensitive key or vendor pattern.
    if !matches!(ctx.format, Kind::Json | Kind::ToolResult) {
        return false;
    }
    if value.len() < 24 {
        return false;
    }
    ctx.key.as_deref().is_some_and(is_structured_metadata_key)
        || local_json_key_before_value(text, start)
            .as_deref()
            .is_some_and(is_structured_metadata_key)
}

fn is_encoded_public_metadata_value(value: &str) -> bool {
    // GitHub GraphQL/REST `node_id` values are Base64-encoded public metadata
    // identifiers such as `010:Repository246648268` or
    // `06:Commit...:<sha>`. They often appear in saved API responses that are
    // scanned as `.txt`, outside the JSON parser's `node_id` key context. This
    // gate accepts only short printable ASCII records with GitHub's typed
    // metadata prefix shape; arbitrary Base64 secrets still reach entropy.
    let value = value.trim();
    if !(24..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='))
    {
        return false;
    }
    let Some(decoded) = decode_base64ish(value) else {
        return false;
    };
    is_github_node_id_payload(&decoded)
}

fn decode_base64ish(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    BASE64
        .decode(bytes)
        .or_else(|_| BASE64URL.decode(bytes))
        .or_else(|_| BASE64_NOPAD.decode(bytes))
        .or_else(|_| BASE64URL_NOPAD.decode(bytes))
        .ok()
}

fn is_github_node_id_payload(decoded: &[u8]) -> bool {
    if !(8..=160).contains(&decoded.len())
        || decoded
            .iter()
            .any(|b| !matches!(*b, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b':' | b'_' | b'-'))
    {
        return false;
    }
    let payload = match std::str::from_utf8(decoded) {
        Ok(payload) => payload,
        Err(_) => return false,
    };
    let mut parts = payload.split(':');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(kind_and_id) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&prefix.len()) || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(first) = kind_and_id.bytes().next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    let alpha_prefix_len = kind_and_id
        .bytes()
        .take_while(u8::is_ascii_alphabetic)
        .count();
    alpha_prefix_len >= 3
        && kind_and_id
            .bytes()
            .skip(alpha_prefix_len)
            .any(|b| b.is_ascii_digit())
}

fn local_json_key_before_value(text: &str, start: usize) -> Option<String> {
    // Some JSON fixtures are scanned as a single text region, so the region
    // context cannot expose every nested key. For entropy suppression only, read
    // the immediate `"key": "value"` shape on the same line; this does not
    // create detections and cannot suppress non-metadata keys.
    let line_start = text[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let prefix = &text[line_start..start];
    let colon = prefix.rfind(':')?;
    let before = prefix[..colon].trim_end();
    if !before.ends_with('"') {
        return None;
    }
    let key_end = before.len() - 1;
    let key_start = before[..key_end].rfind('"')? + 1;
    let key = &before[key_start..key_end];
    (!key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
    .then(|| key.to_string())
}

fn is_public_key_context(text: &str, start: usize, ctx: &Context) -> bool {
    is_public_ssh_key_context(text, start)
        || is_public_pem_body_context(text, start)
        || has_public_key_name_before_value(text, start, ctx)
}

fn is_public_ssh_key_context(text: &str, start: usize) -> bool {
    // OpenSSH authorized_keys/public-key lines start with an algorithm marker
    // (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-*`) followed by a base64 blob.
    // Entropy sees the blob as opaque, but it is public key material; private
    // PEM/OpenSSH key blocks are handled separately.
    let line_start = text[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let prefix = &text[line_start..start];
    prefix.contains("ssh-rsa ") || prefix.contains("ssh-ed25519 ") || prefix.contains("ecdsa-sha2-")
}

fn is_public_pem_body_context(text: &str, start: usize) -> bool {
    // RFC 7468 textual encodings use `-----BEGIN ...-----` armor. Base64 inside
    // PUBLIC KEY / CERTIFICATE blocks is public material; PRIVATE KEY blocks
    // must remain detectable by the PEM detector and entropy fallback.
    let mut window_start = start.saturating_sub(8192);
    while !text.is_char_boundary(window_start) {
        window_start += 1;
    }
    let before = &text[window_start..start];
    let Some(begin) = before.rfind("-----BEGIN ") else {
        return false;
    };
    if before.rfind("-----END ").is_some_and(|end| end > begin) {
        return false;
    }
    let header = &before[begin..];
    let header_end = header
        .find("-----")
        .and_then(|first| {
            header[first + 5..]
                .find("-----")
                .map(|second| first + 5 + second + 5)
        })
        .unwrap_or(header.len());
    let header = &header[..header_end.min(header.len())];
    !header.contains("PRIVATE") && (header.contains("PUBLIC KEY") || header.contains("CERTIFICATE"))
}

fn has_public_key_name_before_value(text: &str, start: usize, ctx: &Context) -> bool {
    if ctx.key.as_deref().is_some_and(is_public_key_name) {
        return true;
    }
    if local_json_key_before_value(text, start)
        .as_deref()
        .is_some_and(is_public_key_name)
    {
        return true;
    }
    local_assignment_key_before_value(text, start).is_some_and(is_public_key_name)
}

fn local_assignment_key_before_value(text: &str, start: usize) -> Option<&str> {
    let line_start = text[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let prefix = &text[line_start..start];
    let sep = prefix.rfind([':', '='])?;
    let before = prefix[..sep].trim_end();
    let key_end = before
        .rfind(|ch: char| ch.is_ascii_alphanumeric())
        .map(|pos| pos + 1)?;
    let key_start = before[..key_end]
        .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .map_or(0, |pos| pos + 1);
    let key = &before[key_start..key_end];
    (!key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
    .then_some(key)
}

fn is_public_key_name(key: &str) -> bool {
    let normalized = normalize_identifier(key);
    normalized == "pubkey"
        || normalized == "public_key"
        || normalized.contains("_public_key")
        || normalized.contains("public_key_")
        || normalized.ends_with("_pubkey")
}

fn normalize_identifier(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut prev_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && !out.is_empty() && !prev_sep {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn has_opaque_mix(run: &str) -> bool {
    let bytes = run.as_bytes();
    let has_upper = bytes.iter().any(u8::is_ascii_uppercase);
    let has_lower = bytes.iter().any(u8::is_ascii_lowercase);
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_codec_marker = bytes.iter().any(|b| matches!(b, b'+' | b'='));
    has_codec_marker || (has_upper && (has_lower || has_digit))
}

fn is_slash_delimited_path_like(run: &str) -> bool {
    run.contains('/')
        && !run.as_bytes().iter().any(|b| matches!(b, b'+' | b'='))
        && run
            .split('/')
            .filter(|segment| !segment.is_empty())
            .any(is_word_path_segment)
}

fn slash_segments(run: &str, base: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut offset = 0usize;
    run.split('/').filter_map(move |segment| {
        let start = offset;
        offset += segment.len() + 1;
        (!segment.is_empty()).then_some((base + start, base + start + segment.len()))
    })
}

fn is_word_path_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    (3..=32).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || matches!(b, b'_' | b'-'))
        && bytes.iter().any(u8::is_ascii_lowercase)
}

fn is_source_identifier_like(run: &str, text: &str, start: usize, end: usize) -> bool {
    is_source_identifier_shape(run)
        || (pascal_or_camel_identifier_like(run.as_bytes())
            && source_identifier_context(text, start, end))
}

fn is_source_identifier_shape(run: &str) -> bool {
    let bytes = run.as_bytes();
    if bytes.is_empty()
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return false;
    }
    let has_alpha = bytes.iter().any(u8::is_ascii_alphabetic);
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_separator = bytes.iter().any(|b| matches!(b, b'_' | b'-'));
    if has_alpha && !has_digit {
        return true;
    }
    if wordlike_mixed_case_identifier(bytes) {
        return true;
    }
    if has_separator && identifier_like_with_few_digits(bytes) {
        return true;
    }
    false
}

fn wordlike_mixed_case_identifier(bytes: &[u8]) -> bool {
    // Source identifiers such as `authenticationMD5Password` have a few case
    // transitions and long lowercase word runs. Random base62 tokens usually
    // alternate case more often and lack word-length lowercase stretches.
    if !(16..=80).contains(&bytes.len()) || bytes.iter().any(|b| matches!(b, b'+' | b'/' | b'=')) {
        return false;
    }
    let has_upper = bytes.iter().any(u8::is_ascii_uppercase);
    let has_lower = bytes.iter().any(u8::is_ascii_lowercase);
    let digit_count = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    if !has_upper || !has_lower || digit_count > 4 {
        return false;
    }
    let mut transitions = 0usize;
    let mut prev_case = None;
    let mut lower_run = 0usize;
    let mut max_lower_run = 0usize;
    for b in bytes {
        let case = if b.is_ascii_lowercase() {
            lower_run += 1;
            max_lower_run = max_lower_run.max(lower_run);
            Some(false)
        } else if b.is_ascii_uppercase() {
            lower_run = 0;
            Some(true)
        } else {
            lower_run = 0;
            None
        };
        if let (Some(prev), Some(case)) = (prev_case, case) {
            if prev != case {
                transitions += 1;
            }
        }
        if case.is_some() {
            prev_case = case;
        }
    }
    transitions <= 8 && max_lower_run >= 4
}

fn source_identifier_context(text: &str, start: usize, end: usize) -> bool {
    // Digit-bearing PascalCase names (`X509Certificate2Collection`) overlap
    // with base62 token shape. Suppress them only when nearby punctuation or
    // keywords make the source-code role visible.
    let line_start = text[..start].rfind('\n').map_or(0, |offset| offset + 1);
    let line_end = text[end..]
        .find('\n')
        .map_or(text.len(), |offset| end + offset);
    let before = text[line_start..start].trim_end();
    let after = text[end..line_end].trim_start();
    before.ends_with("class")
        || before.ends_with("struct")
        || before.ends_with("enum")
        || before.ends_with("type")
        || before.ends_with("new")
        || before.ends_with(':')
        || before.ends_with("::")
        || before.ends_with('<')
        || after.starts_with(['(', '<', ':', ';', ',', '{', '=', '>'])
}

fn is_uppercase_constant_identifier(run: &str) -> bool {
    // ALL_CAPS_WITH_UNDERSCORES is source-code constant syntax, not an opaque
    // credential shape. This gate is deliberately disabled for codec markers
    // (`+`, `/`, `=`) so base64-like secrets still reach entropy scoring.
    let bytes = run.as_bytes();
    if bytes.is_empty()
        || bytes.iter().any(|b| matches!(b, b'+' | b'/' | b'='))
        || !bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    {
        return false;
    }
    bytes.iter().any(u8::is_ascii_alphabetic)
        && bytes.contains(&b'_')
        && bytes.iter().filter(|b| b.is_ascii_digit()).count() <= 12
}

fn is_operator_expression_fragment(run: &str) -> bool {
    // Tokenization includes operator-adjacent text in some source lines. Runs
    // containing comparison/increment operators are expressions, not values.
    // Strip trailing `=` padding first so base64 values ending in `=`/`==` keep
    // their entropy recall.
    let run = run.trim_end_matches('=');
    run.contains("==")
        || run.contains("!=")
        || run.contains("<=")
        || run.contains(">=")
        || run.contains("=>")
        || run.contains("++")
        || run.contains("--")
}

fn is_code_arithmetic_constant(run: &str) -> bool {
    // Macro arithmetic such as `MAX_BITS-DCTSIZE2+1` is a source expression.
    // It has separators and digits, but no credential alphabet markers.
    let bytes = run.as_bytes();
    if bytes.iter().any(|b| matches!(b, b'/' | b'=')) {
        return false;
    }
    bytes.iter().any(|b| matches!(b, b'+' | b'-'))
        && bytes.contains(&b'_')
        && bytes.iter().any(u8::is_ascii_uppercase)
        && bytes.iter().all(|b| {
            b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'+')
        })
}

fn is_slash_separated_identifier_list(run: &str) -> bool {
    // Comments and enum lists often join protocol/identifier names with `/`
    // (`HTTP/SOCKS5`). They are not paths or encoded values unless codec
    // markers appear.
    run.contains('/')
        && !run.as_bytes().iter().any(|b| matches!(b, b'+' | b'='))
        && run.split('/').filter(|part| !part.is_empty()).all(|part| {
            is_source_identifier_shape(part)
                || is_uppercase_constant_identifier(part)
                || is_short_protocol_identifier(part)
        })
}

fn is_short_protocol_identifier(part: &str) -> bool {
    let bytes = part.as_bytes();
    (2..=24).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && bytes.iter().any(u8::is_ascii_alphabetic)
}

fn pascal_or_camel_identifier_like(bytes: &[u8]) -> bool {
    // Long PascalCase/camelCase runs with digits also overlap base62 tokens, so
    // the caller must prove source context before suppressing them.
    if !(16..=80).contains(&bytes.len()) || bytes.iter().any(|b| matches!(b, b'+' | b'/' | b'=')) {
        return false;
    }
    let has_upper = bytes.iter().any(u8::is_ascii_uppercase);
    let has_lower = bytes.iter().any(u8::is_ascii_lowercase);
    let digit_count = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    let sep_count = bytes.iter().filter(|b| matches!(b, b'_' | b'-')).count();
    has_upper && has_lower && (digit_count > 0 || sep_count <= 1)
}

fn identifier_like_with_few_digits(bytes: &[u8]) -> bool {
    let digit_count = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    if digit_count > 4 {
        return false;
    }
    let alpha_count = bytes.iter().filter(|b| b.is_ascii_alphabetic()).count();
    alpha_count >= digit_count.saturating_mul(4).max(12)
}

fn is_regex_character_class_fragment(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |offset| offset + 1);
    let line_end = text[end..]
        .find('\n')
        .map_or(text.len(), |offset| end + offset);
    let before = &text[line_start..start];
    let after = &text[end..line_end];
    let last_open = before.rfind('[');
    let last_close = before.rfind(']');
    last_open.is_some()
        && last_open > last_close
        && after.contains(']')
        && (run_has_range_operator(before, after) || before.contains("\\b"))
}

fn run_has_range_operator(before: &str, after: &str) -> bool {
    let window = format!("{before}{after}");
    window.contains("-z")
        || window.contains("-Z")
        || window.contains("-9")
        || window.contains("-f")
        || window.contains("-F")
}

fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    // Token runs are ASCII-only, so CJK prose never forms an entropy run even at
    // a lowered threshold.
    #[test]
    fn cjk_prose_not_flagged_as_entropy() {
        let raw = "これは日本語の散文でありパスワードではありません";
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        assert!(EntropyDetector::with(16, 2.0).detect(&v).is_empty());
    }

    // A high-entropy run shorter than the hash width is not flagged even when
    // min_len is set below it: the floor wins.
    #[test]
    fn min_len_floored_at_hash_width() {
        let raw = "x aB3xZ9qW2pL5 y"; // 12-char token, < HASH_HEX_WIDTH
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        assert!(EntropyDetector::with(8, 1.0).detect(&v).is_empty());
    }

    #[test]
    fn assignment_entropy_masks_value_not_key_prefix() {
        let raw = "RUNPOD_API_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        let spans = EntropyDetector::with(16, 2.0).detect(&v);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(
            &raw[spans[0].range.start..spans[0].range.end],
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"
        );
    }

    #[test]
    fn base64_padding_is_still_entropy_candidate() {
        let raw = "SECRET_BLOB=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB==";
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        let spans = EntropyDetector::with(24, 2.0).detect(&v);
        assert!(
            spans
                .iter()
                .any(|span| raw[span.range.start..span.range.end].ends_with("==")),
            "base64 padding must not suppress entropy: {spans:?}"
        );
    }

    #[test]
    fn benign_assignments_do_not_mask_whole_key_value_run() {
        for raw in [
            "sha=356a192b7913b04c54574d18c28d46e6395428ab",
            "SHA256=3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
            "uuid=550e8400-e29b-41d4-a716-446655440000",
            "request_id=550e8400-e29b-41d4-a716-446655440000",
            "jwt_like=aaa.bbb.ccc",
            "path=/Users/carol/work/repo",
            r"path=C:\Users\Public\Downloads\file.txt",
        ] {
            let reg = region(raw);
            let v = NormalizedView::build(&reg, raw);
            assert!(EntropyDetector::default().detect(&v).is_empty(), "{raw}");
        }
    }

    #[test]
    fn source_identifiers_are_not_entropy_candidates() {
        for raw in [
            "fn codex_uses_unverified_headless_hook_path(tool_args: &[String]) -> bool {}",
            "const PENTECT_CONTRACT_INSTRUCTIONS: &str = \"contract\";",
            "--allow-unverified-hooks",
            "DASHBOARD_HEARTBEAT_MAX_AGE",
            "clientSecretIdentifierOnly",
            "SSL_RSA_WITH_RC4_128_MD5",
            "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
            "ssl_connect_done==connssl->connecting_state",
            "MAX_CORR_BITS-DCTSIZE2+1",
            "++current_file_system_version",
            "customObjectInstantitationMethod=",
            "allowsToolTipsWhenApplicationIsInactive=",
            "horizontalHuggingPriority=",
            "type X509Certificate2Collection;",
            "HTTP/HTTP_1_0/SOCKS4/SOCKS4a/SOCKS5/SOCKS5_HOSTNAME",
            "defaultChecked/defaultSelected",
            "addEventListener/attachEvent",
        ] {
            let reg = region(raw);
            let v = NormalizedView::build(&reg, raw);
            assert!(EntropyDetector::default().detect(&v).is_empty(), "{raw}");
        }
    }

    #[test]
    fn unanchored_base62_like_runs_are_entropy_candidates() {
        let raw = "AbCdEfGhIjKlMnOp1234";
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        assert!(
            EntropyDetector::with(16, 2.0)
                .detect(&v)
                .iter()
                .any(|span| &raw[span.range.start..span.range.end] == raw),
            "mixed-case alphanumeric token should not be suppressed as a source identifier"
        );
    }

    #[test]
    fn regex_character_classes_are_not_entropy_candidates() {
        for raw in [
            r#"(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", Identifier)"#,
            r#"(r"\br[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}\b", Identifier)"#,
            r#"(r"sk-[A-Za-z0-9_-]{20,}", Secret)"#,
        ] {
            let reg = region(raw);
            let v = NormalizedView::build(&reg, raw);
            assert!(EntropyDetector::default().detect(&v).is_empty(), "{raw}");
        }
    }

    #[test]
    fn source_paths_and_lowercase_charsets_are_not_entropy_candidates() {
        for raw in [
            "core detectors/policy/rendering pipeline",
            "const BECH32_CHARSET: &[u8] = b\"qpzry9x8gf2tvdw0s3jn54khce6mua7l\";",
            "const CTRL: &[u8] = b\"023456789acdefghjklmnpqrstuvwxyz\";",
        ] {
            let reg = region(raw);
            let v = NormalizedView::build(&reg, raw);
            assert!(EntropyDetector::default().detect(&v).is_empty(), "{raw}");
        }
    }

    #[test]
    fn webhook_like_url_path_is_entropy_candidate_without_vendor_rule() {
        let raw = concat!(
            "https://example.invalid/hooks/123456789012345678/",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"
        );
        let reg = region(raw);
        let v = NormalizedView::build(&reg, raw);
        let spans = EntropyDetector::default().detect(&v);
        assert!(
            spans.iter().any(|span| {
                &raw[span.range.start..span.range.end]
                    == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"
            }),
            "{spans:?}"
        );
    }

    #[test]
    fn github_metadata_json_values_are_not_entropy_candidates() {
        let raw =
            "MDY6Q29tbWl0Mjc5MDE1Mjg2OjgxM2RhNTI4ZGE0NmVmNGNiYjI4ZDIwMThlYWE2ZDRiM2Q1NmY0MGY=";
        let region = Region {
            span: ByteRange::new(0, raw.len()),
            ctx: Context {
                path: None,
                key: Some("node_id".to_string()),
                hints: Vec::new(),
                kind: RegionKind::JsonValue,
                format: Kind::Json,
            },
        };
        let view = NormalizedView::build(&region, raw);
        assert!(EntropyDetector::default().detect(&view).is_empty());
    }

    #[test]
    fn local_json_metadata_keys_are_not_entropy_candidates() {
        for raw in [
            r#"{"node_id":"MDY6Q29tbWl0MjQ2NjQ4MjY4OmU0NGQxMWQ1NjVjMDIyNDk2NTQ0ZGQ2ZWQxZjE5YThkNzE4YzJiMGM="}"#,
            r#"{"x5c":["MIIDBTCCAe2gAwIBAgIQHJ7yHxNEM7tBeqcRTMBhhTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5leGFtcGxl"]}"#,
        ] {
            let region = Region {
                span: ByteRange::new(0, raw.len()),
                ctx: Context {
                    path: None,
                    key: None,
                    hints: Vec::new(),
                    kind: RegionKind::JsonValue,
                    format: Kind::Json,
                },
            };
            let view = NormalizedView::build(&region, raw);
            assert!(EntropyDetector::default().detect(&view).is_empty(), "{raw}");
        }
    }

    #[test]
    fn github_node_ids_in_plaintext_are_not_entropy_candidates() {
        for raw in [
            "node_id MDEwOlJlcG9zaXRvcnkyNDY2NDgyNjg=",
            "node_id MDY6Q29tbWl0MjQ2NjQ4MjY4OmU0NGQxMWQ1NjVjMDIyNDk2NTQ0ZGQ2ZWQxZjE5YThkNzE4YzJiMGM=",
            "node_id MDEyOk9yZ2FuaXphdGlvbjExMjg4OTk2",
        ] {
            let encoded = raw.split_whitespace().last().unwrap();
            assert!(is_encoded_public_metadata_value(encoded), "{encoded}");
            let reg = region(raw);
            let view = NormalizedView::build(&reg, raw);
            assert!(EntropyDetector::default().detect(&view).is_empty(), "{raw}");
        }
    }

    #[test]
    fn arbitrary_base64_secret_still_entropy_candidate() {
        let raw = "SECRET_BLOB=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdA==";
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        assert!(
            !EntropyDetector::default().detect(&view).is_empty(),
            "non-metadata base64 must still detect"
        );
    }

    #[test]
    fn public_ssh_key_blobs_are_not_entropy_candidates() {
        let raw = r#"{"key":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLOoLSVPwG1OSgVSeEXNbfIofYdxR5zs3u4PryhnamfFPYwi2vZW3ZxeI1oRcDh2VEdwGvlN5VUduKJ"}"#;
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        assert!(EntropyDetector::default().detect(&view).is_empty());
    }

    #[test]
    fn public_pem_blocks_are_not_entropy_candidates() {
        let raw = concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCD\n",
            "-----END PUBLIC KEY-----"
        );
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        assert!(EntropyDetector::default().detect(&view).is_empty());
    }

    #[test]
    fn public_pem_context_handles_utf8_before_window() {
        let raw = format!(
            "{}\n-----BEGIN PUBLIC KEY-----\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCD\n-----END PUBLIC KEY-----",
            "日本語".repeat(3000)
        );
        let reg = region(&raw);
        let view = NormalizedView::build(&reg, &raw);
        assert!(EntropyDetector::default().detect(&view).is_empty());
    }

    #[test]
    fn private_pem_blocks_still_reach_entropy_fallback() {
        let raw = concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCD\n",
            "-----END PRIVATE KEY-----"
        );
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        assert!(
            !EntropyDetector::default().detect(&view).is_empty(),
            "private-key bodies must not use public-key suppression"
        );
    }

    #[test]
    fn public_key_fields_are_not_entropy_candidates() {
        for raw in [
            r#"{"public_key":"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCD"}"#,
            r#"publicKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCD""#,
            "PublicKey=KAS-ECC-CDH_P-192_C10-Peer-PUBLIC",
        ] {
            let reg = region(raw);
            let view = NormalizedView::build(&reg, raw);
            assert!(EntropyDetector::default().detect(&view).is_empty(), "{raw}");
        }
    }

    #[test]
    fn non_public_key_blob_still_entropy_candidate() {
        let raw =
            r#"private_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCD""#;
        let reg = region(raw);
        let view = NormalizedView::build(&reg, raw);
        assert!(
            !EntropyDetector::default().detect(&view).is_empty(),
            "ordinary or private key material must still detect"
        );
    }
}
