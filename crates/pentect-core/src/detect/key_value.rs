use super::benign::{
    is_crypto_test_vector_identifier_value, is_explicitly_non_sensitive_key_name,
    is_localization_template_reference, is_non_secret_source_constant_value, is_placeholder_value,
    is_source_fixture_key_context, is_source_fixture_secret_value,
    is_source_secret_name_reference_value, is_structured_generic_key_metadata_value,
    is_synthetic_hex_test_vector_value, normalize_identifier,
};
use super::Detector;
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;
use data_encoding::BASE64;

const MAX_KEY_CONTEXT_BYTES: usize = 72;
const MAX_HEX_MATERIAL_BYTES: usize = 128;
const MAX_PREFIXED_HEX_MATERIAL_BYTES: usize = 512;
const HEX_MATERIAL_PREFIXES: &[&str] = &[
    "hexkey",
    "hexsecret",
    "hexpass",
    "hexpassword",
    "hexpasswd",
    "hexpwd",
    "hexseed",
    "hextoken",
    "hexcredential",
    "hexsalt",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyKind {
    Strong,
    Token,
    Otp,
    Phrase,
    EncodedHex,
    Salt,
    Nonce,
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
struct ParsedValueItem {
    value: ValueCandidate,
    next: usize,
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
            let sep_start = if i > 0 && bytes[i - 1] == b':' {
                abs - 1
            } else {
                abs
            };
            let sep_end = if bytes.get(i + 1) == Some(&b'>') {
                abs + 2
            } else {
                abs + 1
            };
            if is_assignment_separator(bytes, i) {
                try_push(
                    &mut ctx,
                    SeparatorCandidate {
                        start: sep_start,
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

    scan_prefixed_hex_materials(&mut ctx);
    scan_c_hex_byte_key_arrays(&mut ctx);
    scan_sensitive_call_literals(&mut ctx);
    scan_sensitive_comparison_literals(&mut ctx);
}

fn sensitive_form_helper_with_key(left: &str) -> Option<String> {
    let normalized = normalize_key(left);
    if has_identifier_phrase(&normalized, &["fill", "in"])
        && key_name_has_sensitive_component(&normalized)
    {
        Some(normalized)
    } else {
        None
    }
}

fn scan_prefixed_hex_materials(ctx: &mut ScanCtx<'_, '_, '_>) {
    let line = &ctx.text[ctx.line_start..ctx.line_end];
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if !matches!(bytes[i], b'h' | b'H') || !is_hex_prefix_start_boundary(bytes, i) {
            continue;
        }
        for prefix in HEX_MATERIAL_PREFIXES {
            let prefix_end = i + prefix.len();
            if prefix_end >= bytes.len()
                || bytes.get(prefix_end) != Some(&b':')
                || !ascii_bytes_eq_ignore_case(&bytes[i..prefix_end], prefix.as_bytes())
            {
                continue;
            }
            let material_start = prefix_end + 1;
            let mut material_end = material_start;
            while material_end < bytes.len() && bytes[material_end].is_ascii_hexdigit() {
                material_end += 1;
            }
            if !is_hex_material_end_boundary(bytes, material_end) {
                continue;
            }
            let material = &line[material_start..material_end];
            if !is_explicit_hex_material(material, MAX_PREFIXED_HEX_MATERIAL_BYTES) {
                continue;
            }
            ctx.out.push(Span {
                range: ctx.view.to_raw(ByteRange::new(
                    ctx.line_start + i,
                    ctx.line_start + material_end,
                )),
                category: Category::Secret,
                label: labels::KEYED_SECRET.to_string(),
                confidence: Confidence::High,
                source: DetectorId::KeyValue,
            });
        }
    }
}

fn scan_c_hex_byte_key_arrays(ctx: &mut ScanCtx<'_, '_, '_>) {
    let line = &ctx.text[ctx.line_start..ctx.line_end];
    let bytes = line.as_bytes();
    let mut search = 0usize;
    while search < bytes.len() {
        let Some(eq_rel) = line[search..].find('=') else {
            break;
        };
        let eq = search + eq_rel;
        let Some((name, declared_len)) = c_hex_byte_array_left(line, eq) else {
            search = eq + 1;
            continue;
        };
        if !c_hex_byte_array_key_name(&name) {
            search = eq + 1;
            continue;
        }
        let mut pos = skip_ascii_ws(bytes, eq + 1);
        if bytes.get(pos) != Some(&b'{') {
            search = eq + 1;
            continue;
        }
        pos += 1;
        let Some((value_start, value_end, count)) = parse_c_hex_byte_array(bytes, pos) else {
            search = eq + 1;
            continue;
        };
        if !matches!(count, 16 | 24 | 32) || declared_len.is_some_and(|len| len != count) {
            search = eq + 1;
            continue;
        }
        ctx.out.push(Span {
            range: ctx.view.to_raw(ByteRange::new(
                ctx.line_start + value_start,
                ctx.line_start + value_end,
            )),
            category: Category::Secret,
            label: labels::KEYED_SECRET.to_string(),
            confidence: Confidence::High,
            source: DetectorId::KeyValue,
        });
        search = value_end;
    }
}

fn scan_sensitive_call_literals(ctx: &mut ScanCtx<'_, '_, '_>) {
    let line = &ctx.text[ctx.line_start..ctx.line_end];
    let bytes = line.as_bytes();
    let mut search = 0usize;
    while search < bytes.len() {
        let Some(open_rel) = line[search..].find('(') else {
            break;
        };
        let open = search + open_rel;
        let head = line[..open].trim_end();
        let Some(call_id) = last_call_identifier(head) else {
            search = open + 1;
            continue;
        };
        let call_key = normalize_key(call_id);
        if !call_name_accepts_secret_literal(&call_key, &call_key) {
            search = open + 1;
            continue;
        }
        let Some(kind) = sensitive_key_kind(&call_key) else {
            search = open + 1;
            continue;
        };
        let args = collect_top_level_quoted_call_arguments(
            ctx.text,
            ctx.line_start + open + 1,
            ctx.line_end,
        );
        if args.is_empty() {
            search = open + 1;
            continue;
        }
        let value = if call_prefers_last_secret_argument(&call_key, &call_key) {
            *args.last().unwrap()
        } else {
            args[0]
        };
        let raw_value = &ctx.text[value.start..value.end];
        if looks_like_secret_value(
            raw_value,
            kind,
            value.quoted,
            Separator::Assignment,
            &call_key,
            head,
        ) {
            push_keyed_secret_span(ctx, value.start, value.end, Confidence::Medium);
        }
        search = open + 1;
    }
}

fn push_keyed_secret_span(
    ctx: &mut ScanCtx<'_, '_, '_>,
    start: usize,
    end: usize,
    confidence: Confidence,
) {
    let range = ctx.view.to_raw(ByteRange::new(start, end));
    if ctx.out.iter().any(|span| {
        span.range == range
            && span.source == DetectorId::KeyValue
            && span.label == labels::KEYED_SECRET
    }) {
        return;
    }
    ctx.out.push(Span {
        range,
        category: Category::Secret,
        label: labels::KEYED_SECRET.to_string(),
        confidence,
        source: DetectorId::KeyValue,
    });
}

fn scan_sensitive_comparison_literals(ctx: &mut ScanCtx<'_, '_, '_>) {
    let line = &ctx.text[ctx.line_start..ctx.line_end];
    let bytes = line.as_bytes();
    let mut search = 0usize;
    while search < bytes.len() {
        let Some(quote_rel) = line[search..].find(['"', '\'', '`']) else {
            break;
        };
        let quote_pos = ctx.line_start + search + quote_rel;
        let quote = ctx.text.as_bytes()[quote_pos];
        let value_start = quote_pos + 1;
        let value_end = find_quote_or_line_end(ctx.text, value_start, ctx.line_end, quote);
        if let Some((op_start, _op_end)) =
            comparison_operator_before(ctx.text, ctx.line_start, quote_pos)
        {
            if let Some((key_name, source_key)) =
                comparison_left_sensitive_key(ctx.text, ctx.line_start, op_start)
            {
                if let Some(kind) = sensitive_key_kind(&key_name) {
                    if !comparison_key_allows_secret_literal(&key_name, &source_key, kind) {
                        search = (value_end + 1).saturating_sub(ctx.line_start);
                        continue;
                    }
                    let value = ValueCandidate {
                        start: trim_ascii_ws_start(ctx.text, value_start, value_end),
                        end: trim_ascii_ws_end(
                            ctx.text,
                            trim_ascii_ws_start(ctx.text, value_start, value_end),
                            value_end,
                        ),
                        quoted: true,
                    };
                    if value.start < value.end {
                        let raw_value = &ctx.text[value.start..value.end];
                        if !comparison_value_allows_secret_literal(
                            raw_value,
                            kind,
                            ctx.text,
                            ctx.line_start,
                            op_start,
                        ) {
                            search = (value_end + 1).saturating_sub(ctx.line_start);
                            continue;
                        }
                        if looks_like_secret_value(
                            raw_value,
                            kind,
                            value.quoted,
                            Separator::Assignment,
                            &key_name,
                            &source_key,
                        ) {
                            push_keyed_secret_span(ctx, value.start, value.end, Confidence::Medium);
                        }
                    }
                }
            }
        }
        search = (value_end + 1).saturating_sub(ctx.line_start);
    }
}

fn comparison_operator_before(
    text: &str,
    line_start: usize,
    quote_pos: usize,
) -> Option<(usize, usize)> {
    let op_end = trim_ascii_ws_end(text, line_start, quote_pos);
    for op in ["!==", "===", "!=", "=="] {
        if let Some(op_start) = op_end.checked_sub(op.len()) {
            if text.get(op_start..op_end) == Some(op) {
                return Some((op_start, op_end));
            }
        }
    }
    None
}

fn comparison_left_sensitive_key(
    text: &str,
    line_start: usize,
    op_start: usize,
) -> Option<(String, String)> {
    let left_end = trim_ascii_ws_end(text, line_start, op_start);
    let start = key_context_start(text, line_start, left_end)?;
    let source_key = text[start..left_end].trim();
    if source_key.is_empty() {
        return None;
    }
    let semantic_key =
        declared_identifier_key(source_key).unwrap_or_else(|| source_key.to_string());
    let key_name = normalize_key(trim_key_edge(&semantic_key));
    sensitive_key_kind(&key_name)?;
    Some((key_name, source_key.to_string()))
}

fn comparison_key_allows_secret_literal(key_name: &str, source_key: &str, kind: KeyKind) -> bool {
    if has_identifier_component(&normalize_key(source_key), "typeof") {
        return false;
    }
    if matches!(kind, KeyKind::Strong) && !key_name_has_non_key_secret_component(key_name) {
        return false;
    }
    true
}

fn comparison_value_allows_secret_literal(
    value: &str,
    kind: KeyKind,
    text: &str,
    line_start: usize,
    op_start: usize,
) -> bool {
    if comparison_prefix_has_typeof(text, line_start, op_start)
        && is_common_scalar_type_name(value.trim())
    {
        return false;
    }
    if matches!(kind, KeyKind::Token) {
        return comparison_token_literal_has_material_shape(value);
    }
    true
}

fn comparison_prefix_has_typeof(text: &str, line_start: usize, op_start: usize) -> bool {
    text.get(line_start..op_start)
        .is_some_and(|prefix| has_identifier_component(&normalize_key(prefix), "typeof"))
}

fn comparison_token_literal_has_material_shape(value: &str) -> bool {
    let bytes = value.trim().as_bytes();
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_symbol = bytes
        .iter()
        .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_'));
    has_digit && (bytes.len() >= 12 || has_symbol)
}

fn c_hex_byte_array_left(line: &str, eq: usize) -> Option<(String, Option<usize>)> {
    let left = line[..eq].trim_end();
    let close = left.strip_suffix(']')?;
    let open = close.rfind('[')?;
    let declared_len = close[open + 1..].trim().parse::<usize>().ok();
    let before_bracket = close[..open].trim_end();
    let name_end = before_bracket.len();
    let name_start = before_bracket
        .char_indices()
        .rfind(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_'))
        .map_or(0, |(offset, ch)| offset + ch.len_utf8());
    let name = before_bracket[name_start..name_end].trim();
    if name.is_empty() {
        return None;
    }
    let type_context = normalize_key(&before_bracket[..name_start]);
    if !c_byte_array_type_context(&type_context) {
        return None;
    }
    Some((name.to_string(), declared_len))
}

fn c_byte_array_type_context(context: &str) -> bool {
    has_identifier_component(context, "byte")
        || has_identifier_component(context, "bytes")
        || has_identifier_component(context, "uint8")
        || has_identifier_component(context, "uint8_t")
        || has_identifier_phrase(context, &["unsigned", "char"])
}

fn c_hex_byte_array_key_name(name: &str) -> bool {
    let normalized = normalize_key(name);
    is_hex_material_key_name(&normalized)
        || normalized
            .strip_prefix("key")
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

fn parse_c_hex_byte_array(bytes: &[u8], mut pos: usize) -> Option<(usize, usize, usize)> {
    let mut first_start = None;
    let mut last_end = 0usize;
    let mut count = 0usize;
    loop {
        pos = skip_ascii_ws(bytes, pos);
        if bytes.get(pos) == Some(&b'}') {
            return first_start.map(|start| (start, last_end, count));
        }
        if count > 0 {
            if bytes.get(pos) != Some(&b',') {
                return None;
            }
            pos = skip_ascii_ws(bytes, pos + 1);
        }
        let start = pos;
        let end = parse_c_hex_byte(bytes, pos)?;
        first_start.get_or_insert(start);
        last_end = end;
        count += 1;
        pos = skip_ascii_ws(bytes, end);
        if bytes.get(pos) == Some(&b',') {
            continue;
        }
        if bytes.get(pos) == Some(&b'}') {
            return first_start.map(|start| (start, last_end, count));
        }
        return None;
    }
}

fn parse_c_hex_byte(bytes: &[u8], pos: usize) -> Option<usize> {
    if bytes.get(pos) != Some(&b'0') || !matches!(bytes.get(pos + 1), Some(b'x' | b'X')) {
        return None;
    }
    let hi = *bytes.get(pos + 2)?;
    let lo = *bytes.get(pos + 3)?;
    (hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit()).then_some(pos + 4)
}

fn skip_ascii_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

fn is_hex_prefix_start_boundary(bytes: &[u8], pos: usize) -> bool {
    pos == 0 || !bytes[pos - 1].is_ascii_alphanumeric() && !matches!(bytes[pos - 1], b'_')
}

fn is_hex_material_end_boundary(bytes: &[u8], pos: usize) -> bool {
    pos == bytes.len() || !bytes[pos].is_ascii_alphanumeric()
}

fn ascii_bytes_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(l, r)| l.eq_ignore_ascii_case(r))
}

fn try_push(ctx: &mut ScanCtx<'_, '_, '_>, separator: SeparatorCandidate) -> bool {
    let left_end = trim_ascii_ws_end(ctx.text, ctx.line_start, separator.start);
    let Some(key_start) = key_context_start(ctx.text, ctx.line_start, left_end) else {
        return false;
    };
    let key = trim_key_edge(&ctx.text[key_start..left_end]);
    let mut semantic_key = declared_identifier_key(key).unwrap_or_else(|| key.to_string());
    let mut tuple_target = None;
    if separator.kind == Separator::Assignment {
        if let Some(targets) = tuple_assignment_targets(&ctx.text[ctx.line_start..left_end]) {
            if let Some((index, target)) = tuple_assignment_sensitive_target(&targets) {
                semantic_key = target;
                tuple_target = Some((index, targets.len()));
            }
        }
    }
    if separator.kind == Separator::Colon && normalize_key(&semantic_key) == "with" {
        if let Some(form_key) = sensitive_form_helper_with_key(&ctx.text[ctx.line_start..left_end])
        {
            semantic_key = form_key;
        }
    }
    let semantic_key = semantic_key.as_str();
    let key_name = normalize_key(semantic_key);
    let mut value_key_name = key_name.clone();
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

    let Some(mut value) = parse_value(ctx.text, separator.end, ctx.line_end, kind) else {
        return false;
    };
    let mut value_from_env_fallback = false;
    if env_lookup_key_allows_literal_fallback(&key_name, kind) {
        if let Some(fallback_value) =
            parse_env_lookup_fallback_value(ctx.text, separator.end, ctx.line_end)
        {
            value = fallback_value;
            value_from_env_fallback = true;
        }
    }
    if !value_from_env_fallback {
        if let Some((call_value, call_key_name)) =
            parse_sensitive_call_literal_value(ctx.text, separator.end, ctx.line_end, &key_name)
        {
            value = call_value;
            value_key_name = call_key_name;
        }
    }
    if let Some((index, target_count)) = tuple_target {
        if let Some(tuple_value) = parse_tuple_assignment_value(
            ctx.text,
            separator.end,
            ctx.line_end,
            kind,
            index,
            target_count,
        ) {
            value = tuple_value;
        }
    }
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
    if !value.quoted
        && !is_prefixed_material_literal(raw_value, &key_name, kind)
        && !is_upper_env_compact_secret_identifier(
            raw_value,
            &key_name,
            &ctx.text[ctx.line_start..left_end],
        )
        && is_code_type_or_expression(raw_value, &key_name, kind)
    {
        return false;
    }
    if is_analysis_token_result_literal(ctx.text, ctx.line_end, &key_name, raw_value) {
        return false;
    }
    if !value.quoted
        && (is_documented_scalar_type_literal(raw_value, &ctx.text[ctx.line_start..left_end])
            || is_unquoted_alpha_prose_continuation(raw_value, ctx.text, value.end, ctx.line_end))
    {
        return false;
    }
    if !value.quoted
        && is_unquoted_code_identifier_reference_literal(
            raw_value,
            ctx.text,
            value.end,
            ctx.line_end,
            &key_name,
            &ctx.text[ctx.line_start..left_end],
            separator.kind,
        )
    {
        return false;
    }
    if is_documentation_auth_header_example_literal(
        raw_value,
        &key_name,
        &ctx.text[ctx.line_start..left_end],
        &ctx.text[value.end..ctx.line_end],
    ) {
        return false;
    }
    if !looks_like_secret_value(
        raw_value,
        kind,
        value.quoted,
        separator.kind,
        &value_key_name,
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
            KeyKind::Strong
                | KeyKind::Otp
                | KeyKind::Phrase
                | KeyKind::EncodedHex
                | KeyKind::Salt
                | KeyKind::Nonce
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
    if let Some(start) = bracketed_string_key_context_start(text, line_start, left_end) {
        return Some(start);
    }
    let mut min = left_end
        .saturating_sub(MAX_KEY_CONTEXT_BYTES)
        .max(line_start);
    while min < left_end && !text.is_char_boundary(min) {
        min += 1;
    }
    let window = &text[min..left_end];
    let hard = typed_declaration_context_start(window, min).unwrap_or_else(|| {
        window
            .rfind(is_key_context_delimiter)
            .map_or(min, |offset| min + offset + 1)
    });
    let start = trim_ascii_ws_start(text, hard, left_end);
    (start < left_end).then_some(start)
}

fn bracketed_string_key_context_start(
    text: &str,
    line_start: usize,
    left_end: usize,
) -> Option<usize> {
    let end = trim_ascii_ws_end(text, line_start, left_end);
    if end <= line_start || text.as_bytes().get(end - 1) != Some(&b']') {
        return None;
    }
    let mut min = end.saturating_sub(MAX_KEY_CONTEXT_BYTES).max(line_start);
    while min < end && !text.is_char_boundary(min) {
        min += 1;
    }
    let open = text[min..end].rfind('[').map(|offset| min + offset)?;
    let inner = text[open + 1..end - 1].trim();
    if inner.len() < 3 {
        return None;
    }
    let quote = inner.as_bytes()[0];
    if !matches!(quote, b'"' | b'\'' | b'`') || inner.as_bytes().last() != Some(&quote) {
        return None;
    }
    let key = &inner[1..inner.len() - 1];
    sensitive_key_kind(key).map(|_| open)
}

fn typed_declaration_context_start(window: &str, min: usize) -> Option<usize> {
    for (offset, _) in window.match_indices(':').rev() {
        let prefix_start = window[..offset]
            .rfind(is_key_context_delimiter)
            .map_or(0, |previous| previous + 1);
        if is_declared_type_annotation_context(&window[prefix_start..offset], &window[offset + 1..])
        {
            return Some(min + prefix_start);
        }
    }
    None
}

fn is_key_context_delimiter(ch: char) -> bool {
    matches!(
        ch,
        ':' | '=' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
    )
}

fn trim_key_edge(value: &str) -> &str {
    value.trim_matches(|ch: char| {
        ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | '-' | '>' | '[' | ']' | '#')
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
    if is_salt_key_name(&name) {
        return Some(KeyKind::Salt);
    }
    if is_nonce_key_name(&name) {
        return Some(KeyKind::Nonce);
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
            "apitoken",
            "refresh_token",
            "id_token",
            "auth_code",
            "authorization_code",
            "auth_token",
            "bearer_token",
            "session_token",
        ],
    ) || matches!(name.as_str(), "token" | "session" | "cookie" | "jwt")
        || name.ends_with("_token")
        || name.ends_with("_apitoken")
        || (name.starts_with("token_") && !has_material_metadata_modifier(&name))
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
        || name == "pass"
        || name.ends_with("_pass")
        || name.contains("_pass_")
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
    if is_salt_key_name(name) {
        return Some(KeyKind::Salt);
    }
    if is_nonce_key_name(name) {
        return Some(KeyKind::Nonce);
    }
    if matches!(
        name,
        "recovery_phrase" | "seed_phrase" | "secret_recovery_phrase" | "mnemonic"
    ) {
        return Some(KeyKind::Phrase);
    }
    if name == "token"
        || name.ends_with("_token")
        || (name.starts_with("token_") && !has_material_metadata_modifier(name))
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
        || name == "pass"
        || name.ends_with("_pass")
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
    parse_value_item(text, start, line_end, kind).map(|item| item.value)
}

fn parse_value_item(
    text: &str,
    start: usize,
    line_end: usize,
    kind: KeyKind,
) -> Option<ParsedValueItem> {
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
                    return Some(ParsedValueItem {
                        value: ValueCandidate {
                            start: credential_start,
                            end,
                            quoted: false,
                        },
                        next: (end + 1).min(line_end),
                    });
                }
            }
        }
        return (start < end).then_some(ParsedValueItem {
            value: ValueCandidate {
                start,
                end,
                quoted: true,
            },
            next: (end + 1).min(line_end),
        });
    }

    if let Some(item) = parse_option_wrapper_value(text, pos, line_end) {
        return Some(item);
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
    (pos < end).then_some(ParsedValueItem {
        value: ValueCandidate {
            start: pos,
            end,
            quoted: false,
        },
        next: end,
    })
}

fn parse_option_wrapper_value(
    text: &str,
    start: usize,
    line_end: usize,
) -> Option<ParsedValueItem> {
    // Scala/Rust Option wrappers such as `Some("secret")` are transparent
    // containers: the string literal is the credential value, while `Some` is
    // just source syntax. Only unwrap a single quoted argument followed by the
    // closing parenthesis so calls and expressions stay with the normal parser.
    let name_end = scan_ascii_identifier_end(text, start, line_end);
    if &text[start..name_end] != "Some" {
        return None;
    }
    let mut pos = trim_ascii_ws_start(text, name_end, line_end);
    if text.as_bytes().get(pos) != Some(&b'(') {
        return None;
    }
    pos += 1;
    pos = trim_ascii_ws_start(text, pos, line_end);
    let quote = text
        .as_bytes()
        .get(pos)
        .copied()
        .filter(|b| matches!(b, b'"' | b'\'' | b'`'))?;
    pos += 1;
    let end = find_quote_or_line_end(text, pos, line_end, quote);
    let value_start = trim_ascii_ws_start(text, pos, end);
    let value_end = trim_ascii_ws_end(text, value_start, end);
    if value_start >= value_end {
        return None;
    }
    let next = (end + 1).min(line_end);
    let after_quote = trim_ascii_ws_start(text, next, line_end);
    if text.as_bytes().get(after_quote) != Some(&b')') {
        return None;
    }
    Some(ParsedValueItem {
        value: ValueCandidate {
            start: value_start,
            end: value_end,
            quoted: true,
        },
        next: (after_quote + 1).min(line_end),
    })
}

fn env_lookup_key_allows_literal_fallback(key_name: &str, kind: KeyKind) -> bool {
    if !matches!(kind, KeyKind::Strong) {
        return false;
    }
    key_name_indicates_password_slot(key_name)
        || has_identifier_component(key_name, "secret")
        || has_identifier_component(key_name, "secrets")
        || has_identifier_component(key_name, "credential")
        || has_identifier_component(key_name, "credentials")
}

fn parse_env_lookup_fallback_value(
    text: &str,
    start: usize,
    line_end: usize,
) -> Option<ValueCandidate> {
    // Source often reads from an environment variable and then falls back to a
    // literal default: `PASSWORD = os.environ.get("PASSWORD") or "secret"`.
    // The env lookup expression is syntax; the fallback literal is the only
    // concrete credential material on that line.
    let window = text.get(start..line_end)?;
    let env_pos = ["process.env", "os.environ", "ENV[", "getenv"]
        .iter()
        .filter_map(|needle| window.find(needle))
        .min()?;
    let after_env = start + env_pos;
    let (op_end, _) = [
        ("||", 2usize),
        ("??", 2usize),
        (" or ", 4usize),
        (" OR ", 4usize),
    ]
    .iter()
    .filter_map(|(op, len)| {
        text[after_env..line_end]
            .find(op)
            .map(|idx| (after_env + idx + len, *op))
    })
    .min_by_key(|(end, _)| *end)?;
    let pos = trim_ascii_ws_start(text, op_end, line_end);
    let quote = text
        .as_bytes()
        .get(pos)
        .copied()
        .filter(|b| matches!(b, b'"' | b'\'' | b'`'))?;
    let value_start = pos + 1;
    let value_end = find_quote_or_line_end(text, value_start, line_end, quote);
    if value_start >= value_end {
        return None;
    }
    let trimmed_start = trim_ascii_ws_start(text, value_start, value_end);
    let trimmed_end = trim_ascii_ws_end(text, trimmed_start, value_end);
    if trimmed_start >= trimmed_end {
        return None;
    }
    let value = &text[trimmed_start..trimmed_end];
    if is_uppercase_identifier_constant(value)
        && normalize_key(value)
            .split('_')
            .any(is_sensitive_setting_name_component)
    {
        return None;
    }
    Some(ValueCandidate {
        start: trimmed_start,
        end: trimmed_end,
        quoted: true,
    })
}

fn parse_sensitive_call_literal_value(
    text: &str,
    start: usize,
    line_end: usize,
    key_name: &str,
) -> Option<(ValueCandidate, String)> {
    let mut pos = trim_ascii_ws_start(text, start, line_end);
    if text
        .get(pos..line_end)
        .is_some_and(|tail| tail.starts_with("new "))
    {
        pos = trim_ascii_ws_start(text, pos + 4, line_end);
    }
    let open = text.get(pos..line_end)?.find('(').map(|idx| pos + idx)?;
    let head = text.get(pos..open)?.trim();
    if head.is_empty() || head.contains('=') || head.contains(';') {
        return None;
    }
    let call_key = normalize_key(last_call_identifier(head)?);
    if !call_name_accepts_secret_literal(&call_key, key_name) {
        return None;
    }
    let args = collect_quoted_call_arguments(text, open + 1, line_end);
    if args.is_empty() {
        return None;
    }
    let value = if call_prefers_last_secret_argument(&call_key, key_name) {
        *args.last()?
    } else {
        args[0]
    };
    Some((value, call_key))
}

fn last_call_identifier(head: &str) -> Option<&str> {
    let head = head.trim_end();
    let (start, end) = trailing_identifier_range(head)?;
    let identifier = &head[start..end];
    if identifier != "new" {
        return Some(identifier);
    }
    let before_new = head[..start].trim_end();
    let before_new = before_new
        .strip_suffix('.')
        .or_else(|| before_new.strip_suffix("::"))?
        .trim_end();
    let (start, end) = trailing_identifier_range(before_new)?;
    Some(&before_new[start..end])
}

fn trailing_identifier_range(value: &str) -> Option<(usize, usize)> {
    let end = value.len();
    let mut chars = value.char_indices().rev();
    let (last_start, last) = chars.next()?;
    if !(last.is_ascii_alphanumeric() || last == '_') {
        return None;
    }
    let mut start = last_start;
    for (idx, ch) in chars {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            start = idx;
        } else {
            break;
        }
    }
    Some((start, end))
}

fn call_name_accepts_secret_literal(call_key: &str, _key_name: &str) -> bool {
    if call_name_is_prompt_or_lookup(call_key) {
        return false;
    }
    has_identifier_component(call_key, "otp")
        || has_identifier_component(call_key, "totp")
        || has_identifier_component(call_key, "hotp")
        || has_identifier_component(call_key, "credential")
        || has_identifier_component(call_key, "credentials")
        || (has_identifier_component(call_key, "token")
            && (has_identifier_component(call_key, "auth")
                || has_identifier_component(call_key, "oauth")
                || has_identifier_component(call_key, "access")
                || has_identifier_component(call_key, "refresh")
                || has_identifier_component(call_key, "id")))
        || (has_identifier_component(call_key, "secret")
            && (has_identifier_component(call_key, "key")
                || has_identifier_component(call_key, "token")
                || has_identifier_component(call_key, "password")))
}

fn call_name_is_prompt_or_lookup(call_key: &str) -> bool {
    call_key.split('_').any(|part| {
        matches!(
            part,
            "ask" | "get" | "lookup" | "prompt" | "read" | "request" | "scan"
        )
    })
}

fn call_prefers_last_secret_argument(call_key: &str, key_name: &str) -> bool {
    has_identifier_component(call_key, "credential")
        || has_identifier_component(key_name, "credential")
}

fn collect_quoted_call_arguments(
    text: &str,
    mut pos: usize,
    line_end: usize,
) -> Vec<ValueCandidate> {
    let bytes = text.as_bytes();
    let mut args = Vec::new();
    let mut depth = 1usize;
    while pos < line_end {
        match bytes[pos] {
            b'"' | b'\'' | b'`' => {
                let quote = bytes[pos];
                let value_start = pos + 1;
                let value_end = find_quote_or_line_end(text, value_start, line_end, quote);
                if value_start < value_end {
                    let trimmed_start = trim_ascii_ws_start(text, value_start, value_end);
                    let trimmed_end = trim_ascii_ws_end(text, trimmed_start, value_end);
                    if trimmed_start < trimmed_end {
                        args.push(ValueCandidate {
                            start: trimmed_start,
                            end: trimmed_end,
                            quoted: true,
                        });
                    }
                }
                pos = (value_end + 1).min(line_end);
            }
            b'(' => {
                depth += 1;
                pos += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                pos += 1;
            }
            _ => {
                pos += 1;
            }
        }
    }
    args
}

fn collect_top_level_quoted_call_arguments(
    text: &str,
    mut pos: usize,
    line_end: usize,
) -> Vec<ValueCandidate> {
    let bytes = text.as_bytes();
    let mut args = Vec::new();
    let mut paren_depth = 1usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while pos < line_end {
        match bytes[pos] {
            b'"' | b'\'' | b'`' => {
                let quote = bytes[pos];
                let value_start = pos + 1;
                let value_end = find_quote_or_line_end(text, value_start, line_end, quote);
                if paren_depth == 1
                    && bracket_depth == 0
                    && brace_depth == 0
                    && value_start < value_end
                {
                    let trimmed_start = trim_ascii_ws_start(text, value_start, value_end);
                    let trimmed_end = trim_ascii_ws_end(text, trimmed_start, value_end);
                    if trimmed_start < trimmed_end {
                        args.push(ValueCandidate {
                            start: trimmed_start,
                            end: trimmed_end,
                            quoted: true,
                        });
                    }
                }
                pos = (value_end + 1).min(line_end);
            }
            b'(' => {
                paren_depth += 1;
                pos += 1;
            }
            b')' => {
                paren_depth -= 1;
                if paren_depth == 0 {
                    break;
                }
                pos += 1;
            }
            b'[' => {
                bracket_depth += 1;
                pos += 1;
            }
            b']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                pos += 1;
            }
            b'{' => {
                brace_depth += 1;
                pos += 1;
            }
            b'}' => {
                brace_depth = brace_depth.saturating_sub(1);
                pos += 1;
            }
            _ => {
                pos += 1;
            }
        }
    }
    args
}

fn scan_ascii_identifier_end(text: &str, start: usize, line_end: usize) -> usize {
    let mut end = start;
    while end < line_end {
        let b = text.as_bytes()[end];
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            break;
        }
        end += 1;
    }
    end
}

fn parse_tuple_assignment_value(
    text: &str,
    start: usize,
    line_end: usize,
    kind: KeyKind,
    target_index: usize,
    target_count: usize,
) -> Option<ValueCandidate> {
    let mut pos = start;
    for index in 0..target_count {
        let item = parse_value_item(text, pos, line_end, kind)?;
        if index == target_index {
            return Some(item.value);
        }
        pos = trim_ascii_ws_start(text, item.next, line_end);
        if text.as_bytes().get(pos) != Some(&b',') {
            return None;
        }
        pos += 1;
    }
    None
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
        return ((4..=12).contains(&chars)
            && value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ' ')))
            || is_base32_otp_seed_material(value);
    }

    if matches!(kind, KeyKind::Salt) {
        return looks_like_salt_material(value, key_name);
    }

    if matches!(kind, KeyKind::Nonce) {
        return looks_like_nonce_material(value, key_name);
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
        || is_public_curve_algorithm_literal(value, key_name)
        || is_status_code_constant_literal(value, key_name)
        || is_oauth_bearer_error_code_literal(value, key_name, source_key)
        || is_numeric_metadata_key_literal(value, key_name, quoted)
        || is_public_numeric_code_constant_literal(value, key_name, source_key, quoted)
        || is_crypto_vector_field_descriptor_literal(value, key_name)
        || is_asn1_oid_der_literal(value, key_name, source_key)
        || is_asn1_obj_name_literal(value, key_name, source_key)
        || is_crypto_test_vector_identifier_literal(value, key_name)
        || is_crypto_test_vector_record_literal(value, key_name, source_key)
        || is_query_predicate_literal(value, key_name)
        || is_localized_ui_text_literal(value, key_name, source_key)
        || is_single_word_localized_ui_label_literal(value, key_name, source_key)
        || is_sensitive_display_label_literal(value, key_name)
        || is_missing_credential_name_literal(value, key_name, source_key)
        || is_xaml_key_time_literal(value, source_key)
        || is_url_query_metadata_literal(value, key_name, source_key)
        || is_html_code_metadata_literal(value)
        || is_html_documentation_fragment_literal(value, key_name, source_key)
        || is_markup_syntax_fragment_literal(value, key_name)
        || is_generic_key_placeholder_literal(value, key_name)
        || is_escaped_html_source_fragment_literal(value, source_key)
        || is_fingerprint_literal(value, key_name)
        || is_escaped_control_placeholder_literal(value, key_name)
        || is_escaped_plain_source_line_literal(value, source_key)
        || is_escaped_source_payload_fragment_literal(value, source_key)
        || is_documented_env_var_name_literal(value, key_name, source_key)
        || is_source_env_fallback_name_literal(value, key_name, source_key)
        || is_source_constant_reference_literal(value, key_name, source_key)
        || is_source_declared_name_literal(value, key_name, source_key)
        || is_source_declared_lower_name_literal(value, key_name, source_key)
        || is_source_config_name_literal(value, source_key)
        || is_self_describing_key_value_placeholder(value, key_name, source_key)
        || is_source_sensitive_name_reference_literal(value, source_key)
        || is_structured_sensitive_name_reference_literal(value, key_name)
        || is_source_fixture_secret_literal(value, key_name, source_key)
        || is_source_fixture_low_entropy_literal(value, key_name, source_key)
        || is_source_struct_tag_literal(value, key_name, source_key)
        || is_objc_dictionary_key_literal(value, source_key)
        || is_source_prefix_constant_literal(value, key_name)
        || is_source_variable_reference_literal(value, key_name, source_key, quoted)
        || is_shell_parameter_reference_literal(value, key_name, source_key)
        || is_runtime_template_reference_literal(value, key_name, source_key)
        || is_jsonpath_template_selector_literal(value, key_name)
        || is_source_string_fragment_literal(value, source_key)
        || is_source_concatenation_template_literal(value)
        || is_shell_command_substitution_literal(value, key_name, source_key)
        || is_shell_command_fragment_literal(value, key_name, source_key)
        || is_inline_code_key_value_tail_literal(value, key_name, source_key)
        || is_source_code_fragment_literal(value)
        || is_arithmetic_expression_literal(value)
        || is_localization_template_reference(value)
        || is_interpolated_string_template(value)
        || is_typed_sql_fragment_literal(value, key_name, source_key)
        || is_public_key_literal(value, key_name)
        || is_private_key_documentation_placeholder_literal(value, key_name)
        || is_license_identifier_literal(value, key_name)
        || is_dunder_identifier_literal(value)
        || is_uppercase_constant_literal_for_generic_key(value, key_name)
        || is_generic_code_member_name_literal(value, key_name)
        || is_checksum_metadata_digest_literal(value, key_name, source_key)
        || is_structured_key_name_reference_literal(value, key_name)
        || is_generic_key_identifier_metadata_literal(value, key_name)
        || is_password_validation_message_literal(value, key_name)
        || is_password_documentation_literal(value, key_name)
        || is_sensitive_slot_documentation_literal(value, key_name)
        || is_plain_prose_literal_for_generic_key(value, key_name)
        || is_locator_literal_for_key(value, key_name)
        || is_secret_resource_metadata_literal(value, key_name)
        || is_web_credentials_mode_literal(value, key_name)
        || is_package_dependency_coordinate_literal(value, source_key)
        || is_package_dependency_version_literal(value, source_key)
        || is_password_reset_duration_literal(value, key_name)
        || is_hashed_token_derivative_literal(value, key_name)
    {
        return false;
    }
    if is_auth_scheme_literal(value) {
        return false;
    }
    if !quoted && is_uppercase_constant_reference(value) {
        return false;
    }
    let has_alpha = value.chars().any(|ch| ch.is_ascii_alphabetic());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_ascii_whitespace());
    let has_space = value.chars().any(char::is_whitespace);
    if matches!(kind, KeyKind::Token) && value.contains('\'') && !has_digit {
        return false;
    }

    if matches!(kind, KeyKind::EncodedHex) {
        return is_keyed_hex_secret_literal(value, key_name, kind);
    }
    if is_keyed_hex_secret_literal(value, key_name, kind) {
        return true;
    }
    if !quoted && is_upper_env_compact_secret_identifier(value, key_name, source_key) {
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
        return has_digit
            || has_symbol
            || (is_quoted_low_entropy_literal_shape(value)
                && key_context_allows_low_entropy_literal(key_name, source_key, kind))
            || is_config_slot_low_entropy_literal(value, key_name, source_key);
    }
    if !quoted
        && chars >= 5
        && has_alpha
        && !has_digit
        && !has_symbol
        && !has_space
        && (is_config_slot_low_entropy_literal(value, key_name, source_key)
            || is_explicit_slot_low_entropy_literal(value, key_name, kind))
    {
        return true;
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

fn looks_like_salt_material(value: &str, key_name: &str) -> bool {
    if has_material_metadata_modifier(key_name) {
        return false;
    }
    let material = value.trim().strip_prefix("salt:").unwrap_or(value).trim();
    if is_keyed_hex_secret_literal(material, key_name, KeyKind::Salt) {
        return true;
    }
    let bytes = material.as_bytes();
    if !(8..=128).contains(&bytes.len())
        || bytes.iter().any(u8::is_ascii_whitespace)
        || bytes.iter().all(u8::is_ascii_digit)
        || is_material_name_reference(material, "salt")
        || !bytes.iter().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_' | b'.')
        })
    {
        return false;
    }
    let has_alpha = bytes.iter().any(u8::is_ascii_alphabetic);
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_symbol = bytes.iter().any(|b| !b.is_ascii_alphanumeric());
    has_alpha && (has_digit || has_symbol)
}

fn is_base32_otp_seed_material(value: &str) -> bool {
    // TOTP/HOTP provisioning secrets are RFC 4648 base32 strings. Requiring
    // OTP-local key/call context elsewhere lets this accept real seed lengths
    // without treating arbitrary uppercase prose as credentials.
    let value = value.trim().trim_end_matches('=');
    let bytes = value.as_bytes();
    (16..=128).contains(&bytes.len())
        && bytes.iter().all(|b| {
            b.is_ascii_uppercase()
                || b.is_ascii_digit() && matches!(*b, b'2' | b'3' | b'4' | b'5' | b'6' | b'7')
        })
        && bytes
            .iter()
            .any(|b| matches!(*b, b'2' | b'3' | b'4' | b'5' | b'6' | b'7'))
}

fn is_prefixed_material_literal(value: &str, key_name: &str, kind: KeyKind) -> bool {
    let value = value.trim();
    (matches!(kind, KeyKind::Salt) && value.starts_with("salt:"))
        || (matches!(kind, KeyKind::Nonce) && value.starts_with("nonce:"))
        || is_prefixed_hex_secret_literal(value, key_name, kind)
}

fn looks_like_nonce_material(value: &str, key_name: &str) -> bool {
    if has_material_metadata_modifier(key_name) {
        return false;
    }
    let material = value.trim().strip_prefix("nonce:").unwrap_or(value).trim();
    let bytes = material.as_bytes();
    if !(8..=128).contains(&bytes.len())
        || bytes.iter().any(u8::is_ascii_whitespace)
        || is_material_name_reference(material, "nonce")
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
    {
        return false;
    }
    if bytes.iter().all(u8::is_ascii_digit) {
        return bytes.len() <= 32;
    }
    let has_alpha = bytes.iter().any(u8::is_ascii_alphabetic);
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_symbol = bytes.iter().any(|b| !b.is_ascii_alphanumeric());
    has_alpha && (has_digit || has_symbol || has_mixed_ascii_case(bytes))
}

fn is_material_name_reference(value: &str, component: &str) -> bool {
    let name = normalize_key(value);
    !name.is_empty() && name.split('_').any(|part| part == component)
}

fn has_mixed_ascii_case(bytes: &[u8]) -> bool {
    bytes.iter().any(u8::is_ascii_lowercase) && bytes.iter().any(u8::is_ascii_uppercase)
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
    if is_repeated_placeholder_literal(value) {
        return true;
    }
    if is_nil_uuid_literal(value) {
        return true;
    }
    if is_escaped_null_literal(value) {
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

fn is_uppercase_constant_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    (4..=96).contains(&bytes.len())
        && bytes.contains(&b'_')
        && bytes.iter().any(u8::is_ascii_uppercase)
        && !bytes.iter().any(u8::is_ascii_digit)
        && bytes.iter().all(|b| b.is_ascii_uppercase() || *b == b'_')
}

fn is_repeated_placeholder_literal(value: &str) -> bool {
    // Example configs commonly use `xxxx`, `x-xxxx`, or an all-x UUID-shaped
    // string to show where the reader should paste a secret. The repeated
    // marker itself is not credential material; require every non-separator
    // byte to be the placeholder marker so real mixed tokens still detect.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(4..=128).contains(&value.len()) {
        return false;
    }
    let mut marker_count = 0usize;
    let mut separator_count = 0usize;
    let mut repeated_alpha = None;
    for byte in value.bytes() {
        match byte {
            b'x' | b'X' => marker_count += 1,
            b'-' | b'_' | b'.' => separator_count += 1,
            b if b.is_ascii_alphabetic() => match repeated_alpha {
                Some(previous) if previous == b.to_ascii_lowercase() => {}
                None => repeated_alpha = Some(b.to_ascii_lowercase()),
                _ => return false,
            },
            _ => return false,
        }
    }
    if marker_count >= 4 && (separator_count > 0 || marker_count == value.len()) {
        return true;
    }
    separator_count == 0 && marker_count == 0 && repeated_alpha.is_some() && value.len() >= 4
}

fn is_nil_uuid_literal(value: &str) -> bool {
    // RFC 4122 defines the all-zero UUID as the nil UUID. It is a sentinel or
    // placeholder value, not an issued token.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    is_uuid_literal(value) && value.bytes().all(|byte| byte == b'0' || byte == b'-')
}

fn is_escaped_null_literal(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let head = value
        .split("\\n")
        .next()
        .unwrap_or(value)
        .split("\\r")
        .next()
        .unwrap_or(value)
        .split("\\t")
        .next()
        .unwrap_or(value)
        .trim();
    head.len() < value.len()
        && matches!(
            normalize_key(head).as_str(),
            "none" | "null" | "nil" | "undefined"
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
    is_synthetic_hex_test_vector_value(value)
}

fn is_keyed_hex_secret_literal(value: &str, key_name: &str, kind: KeyKind) -> bool {
    // Unquoted hex-looking secret material is syntactically indistinguishable
    // from a lower-case identifier, so it must be recovered by structure: a
    // sensitive field name plus compact hex shape. Explicit `hex*` fields and
    // key material require byte alignment; opaque `*_secret` tokens may be odd.
    let key_allows_hex = match kind {
        KeyKind::EncodedHex => is_hex_encoded_sensitive_key_name(key_name),
        KeyKind::Strong => is_hex_material_key_name(key_name),
        KeyKind::Salt => is_salt_key_name(key_name),
        KeyKind::Token | KeyKind::Otp | KeyKind::Phrase | KeyKind::Nonce => false,
    };
    if !key_allows_hex {
        return false;
    }
    let min_len = if matches!(kind, KeyKind::EncodedHex) || is_hex_encoded_salt_key_name(key_name) {
        8
    } else {
        16
    };
    let value = value.trim();
    let prefixed = strip_hex_material_prefix(value);
    let material = prefixed.unwrap_or(value);
    let max_len = if prefixed.is_some() {
        MAX_PREFIXED_HEX_MATERIAL_BYTES
    } else {
        MAX_HEX_MATERIAL_BYTES
    };
    if !is_explicit_hex_material_with_min(material, min_len, max_len) {
        return false;
    }
    let bytes = material.as_bytes();
    let requires_even_hex =
        matches!(kind, KeyKind::EncodedHex) || !has_identifier_component(key_name, "secret");
    if requires_even_hex && !bytes.len().is_multiple_of(2) {
        return false;
    }
    !is_synthetic_hex_test_vector_literal(material)
}

fn is_prefixed_hex_secret_literal(value: &str, key_name: &str, kind: KeyKind) -> bool {
    let Some(material) = strip_hex_material_prefix(value) else {
        return false;
    };
    is_keyed_hex_secret_literal(material, key_name, kind)
}

fn strip_hex_material_prefix(value: &str) -> Option<&str> {
    let (prefix, material) = value.split_once(':')?;
    if !is_hex_material_prefix(prefix.trim()) {
        return None;
    }
    let material = material.trim();
    (!material.is_empty()).then_some(material)
}

fn is_hex_material_prefix(prefix: &str) -> bool {
    HEX_MATERIAL_PREFIXES
        .iter()
        .any(|known| prefix.eq_ignore_ascii_case(known))
}

fn is_explicit_hex_material(value: &str, max_len: usize) -> bool {
    is_explicit_hex_material_with_min(value, 8, max_len)
}

fn is_explicit_hex_material_with_min(value: &str, min_len: usize, max_len: usize) -> bool {
    let bytes = value.trim().as_bytes();
    bytes.len() >= min_len
        && bytes.len() <= max_len
        && bytes.iter().all(|b| b.is_ascii_hexdigit())
        && bytes.iter().any(u8::is_ascii_digit)
        && bytes.iter().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'))
        && !is_synthetic_hex_test_vector_literal(value)
}

fn is_status_code_constant_literal(value: &str, key_name: &str) -> bool {
    // Windows/COM error constants often include sensitive words in the public
    // enum name (`STATUS_WRONG_PASSWORD = 0xC000006A`). A fixed-width numeric
    // status/HRESULT value is not credential material. Keep this bound to
    // well-known status-code prefixes so ordinary keyed hex secrets still flow
    // through `is_keyed_hex_secret_literal`.
    is_status_code_key_name(key_name) && is_c_style_hex_u32(value.trim())
}

fn is_status_code_key_name(key_name: &str) -> bool {
    matches!(
        key_name.split('_').next().unwrap_or_default(),
        "status" | "error" | "hresult" | "nte" | "crypt"
    ) || key_name.starts_with("sec_e_")
        || key_name.starts_with("sec_i_")
        || key_name.starts_with("trust_e_")
        || key_name.starts_with("trust_s_")
}

fn is_oauth_bearer_error_code_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // RFC 6750 defines these as Bearer authentication error codes, not bearer
    // token material. Keep the suppression gated on token/auth/error context so
    // arbitrary underscored values under unrelated sensitive keys still flow
    // through the normal shape checks.
    let key = normalize_key(key_name);
    let source = normalize_key(source_key);
    let has_context = [&key, &source].iter().any(|name| {
        name.split('_').any(|part| {
            matches!(
                part,
                "token" | "auth" | "oauth" | "bearer" | "error" | "errors"
            )
        })
    });
    if !has_context {
        return false;
    }
    matches!(
        value.trim(),
        "invalid_request" | "invalid_token" | "insufficient_scope"
    )
}

fn is_public_numeric_code_constant_literal(
    value: &str,
    key_name: &str,
    source_key: &str,
    quoted: bool,
) -> bool {
    // Generated enum/error tables often contain identifiers with `key`,
    // `token`, or `password` in the public constant name:
    // `KEYCTL_CAPS0_BIG_KEY = 0x10` and `ER_TOO_LONG_KEY: "42000"`.
    // These small numeric codes are not secret material. Keep the decimal
    // quoted case to SQLSTATE-style error names only, so `password = "123456"`
    // and JSON token samples still detect.
    let value = value.trim();
    if is_sqlstate_error_constant_name(key_name, source_key) && is_sqlstate_literal(value) {
        return true;
    }
    !quoted
        && (is_small_c_style_int_literal(value) || is_small_decimal_code_literal(value))
        && (is_all_caps_source_constant_name(source_key)
            || is_pascal_case_sensitive_source_constant_name(source_key, key_name))
}

fn is_numeric_metadata_key_literal(value: &str, key_name: &str, quoted: bool) -> bool {
    // UI trees and schemas often use a property literally named `key` for a
    // stable numeric node identifier (`key: '1001'`). Key-id fields likewise
    // carry public identifiers (`ssh_key_id: "6536865"`), not key material.
    // Keep this away from `api_key`, `password`, `token`, and other material
    // fields.
    quoted
        && ((key_name == "key"
            && (is_small_decimal_code_literal(value) || is_numeric_tree_key_path_literal(value)))
            || (has_identifier_phrase(key_name, &["key", "id"])
                && is_decimal_key_id_literal(value)))
}

fn is_sqlstate_error_constant_name(key_name: &str, source_key: &str) -> bool {
    let key = source_key.trim();
    key.starts_with("ER_")
        || key_name.starts_with("er_")
        || key.starts_with("SQLSTATE_")
        || key_name.starts_with("sqlstate_")
}

fn is_sqlstate_literal(value: &str) -> bool {
    let value = value.trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    value.len() == 5 && value.bytes().all(|b| b.is_ascii_digit())
}

fn is_all_caps_source_constant_name(source_key: &str) -> bool {
    let key = source_key
        .trim()
        .trim_end_matches(',')
        .trim_end_matches(':')
        .trim();
    (4..=96).contains(&key.len())
        && key.contains('_')
        && key.bytes().any(|b| b.is_ascii_alphabetic())
        && key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn is_pascal_case_sensitive_source_constant_name(source_key: &str, key_name: &str) -> bool {
    if !(key_name_has_sensitive_component(key_name)
        || key_name_indicates_sensitive_material(key_name))
    {
        return false;
    }
    let key = source_key
        .trim()
        .trim_end_matches(',')
        .trim_end_matches(':')
        .trim();
    (6..=96).contains(&key.len())
        && key.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && key.bytes().all(|b| b.is_ascii_alphanumeric())
        && key.bytes().any(|b| b.is_ascii_lowercase())
        && key.bytes().any(|b| b.is_ascii_uppercase())
}

fn is_small_c_style_int_literal(value: &str) -> bool {
    let value = value.trim();
    let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    (1..=8).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_small_decimal_code_literal(value: &str) -> bool {
    let bytes = value.trim().as_bytes();
    (1..=6).contains(&bytes.len()) && bytes.iter().all(|b| b.is_ascii_digit())
}

fn is_numeric_tree_key_path_literal(value: &str) -> bool {
    // Frontend tree/list controls commonly serialize node positions as
    // `0-0-1`. Under a literal generic `key` this is a public UI identifier,
    // while token/password fields still use the normal numeric secret path.
    let parts = value.trim().split('-').collect::<Vec<_>>();
    (2..=8).contains(&parts.len())
        && parts
            .iter()
            .all(|part| (1..=4).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()))
}

fn is_decimal_key_id_literal(value: &str) -> bool {
    let bytes = value.trim().as_bytes();
    (1..=20).contains(&bytes.len()) && bytes.iter().all(|b| b.is_ascii_digit())
}

fn is_c_style_hex_u32(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[0] == b'0'
        && matches!(bytes[1], b'x' | b'X')
        && bytes[2..].iter().all(u8::is_ascii_hexdigit)
}

fn is_hex_material_key_name(name: &str) -> bool {
    name == "key"
        || has_identifier_component(name, "key")
        || has_identifier_component(name, "secret")
        || has_identifier_component(name, "password")
        || has_identifier_component(name, "passwd")
        || has_identifier_component(name, "pwd")
        || has_identifier_component(name, "pass")
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
        "key" | "secret" | "salt" | "pass" | "password" | "passwd" | "pwd" | "token" | "credential"
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
                    | b'|'
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
        .any(|b| matches!(b, b'<' | b'>' | b':' | b'|' | b'[' | b']' | b'&' | b';'));
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
    let value = value.trim();
    if !(is_pascal_case_type_name(value) || is_common_scalar_type_name(value)) {
        return false;
    }
    text[value_end..line_end]
        .trim_start()
        .chars()
        .next()
        .is_some_and(|ch| matches!(ch, ',' | ')' | '}' | ';' | '{' | '=' | '>' | '|'))
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

fn is_common_scalar_type_name(value: &str) -> bool {
    matches!(
        value,
        "str"
            | "string"
            | "String"
            | "bool"
            | "boolean"
            | "Boolean"
            | "number"
            | "Number"
            | "int"
            | "uint"
            | "long"
            | "float"
            | "double"
            | "byte"
            | "bytes"
            | "Bytes"
            | "Buffer"
            | "function"
            | "object"
            | "Object"
    )
}

fn is_documented_scalar_type_literal(value: &str, source_key: &str) -> bool {
    if !is_common_scalar_type_name(value.trim()) {
        return false;
    }
    let key = normalize_key(source_key);
    key.split('_').any(|part| {
        matches!(
            part,
            "param"
                | "parameter"
                | "type"
                | "typedef"
                | "property"
                | "attribute"
                | "field"
                | "column"
                | "schema"
        )
    }) || source_key.trim_start().starts_with('#')
        || source_key.trim_start().starts_with("//")
}

fn is_unquoted_alpha_prose_continuation(
    value: &str,
    text: &str,
    value_end: usize,
    line_end: usize,
) -> bool {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let rest = text[value_end..line_end].trim_start();
    if rest.is_empty()
        || rest.starts_with('#')
        || rest.starts_with("//")
        || rest.starts_with("/*")
        || rest.starts_with('\\')
    {
        return false;
    }
    rest.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
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

fn is_unquoted_code_identifier_reference_literal(
    value: &str,
    text: &str,
    value_end: usize,
    line_end: usize,
    key_name: &str,
    source_key: &str,
    separator: Separator,
) -> bool {
    // Unquoted identifiers followed by source delimiters are type names,
    // variables, struct fields, or arrow-function parameters. They name where a
    // value comes from; they are not the credential bytes themselves.
    let value = value.trim();
    if !is_source_identifier_token(value) {
        return false;
    }
    let rest = text[value_end..line_end].trim_start();
    if rest.starts_with("=>") {
        return true;
    }
    if separator == Separator::Assignment
        && (source_key_has_code_shape(source_key)
            || is_exact_password_low_entropy_slot(key_name, KeyKind::Strong))
        && rest
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, ',' | ';' | ')' | '}' | ']'))
    {
        return true;
    }
    separator == Separator::Colon
        && source_key
            .trim_start()
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_uppercase())
        && rest
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, ',' | ')' | '}'))
}

fn is_source_identifier_token(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first == '$' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
        && value.chars().any(|ch| ch.is_ascii_alphabetic())
        && value.chars().count() <= 64
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
    let key = strip_declared_type_annotation(key).unwrap_or(key);
    declared_identifier_key_without_type(key).map(str::to_string)
}

fn tuple_assignment_targets(left: &str) -> Option<Vec<String>> {
    // Python/Ruby-style tuple assignments bind each left-side identifier to the
    // value at the same right-side position. If `login, password = "u", "p"`
    // is treated as one key, the detector masks the username and misses the
    // actual password. Keep this to a plain comma-separated identifier list so
    // calls, indexes, and expressions are handled by the normal parser.
    let left = left.rsplit([';', '{', '}']).next().unwrap_or(left).trim();
    if !left.contains(',') || left.len() > 160 {
        return None;
    }
    if !left
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b',' | b' ' | b'\t'))
    {
        return None;
    }

    let mut targets = Vec::new();
    for segment in left.split(',') {
        let ident = trailing_identifier(segment.trim())?;
        if ident.is_empty() || is_declaration_word(ident) {
            return None;
        }
        targets.push(ident.to_string());
    }
    ((2..=8).contains(&targets.len())).then_some(targets)
}

fn tuple_assignment_sensitive_target(targets: &[String]) -> Option<(usize, String)> {
    let mut found = None;
    for (index, target) in targets.iter().enumerate() {
        if sensitive_key_kind(target).is_some() {
            if found.is_some() {
                return None;
            }
            found = Some((index, target.clone()));
        }
    }
    found
}

fn trailing_identifier(segment: &str) -> Option<&str> {
    segment
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .find(|part| !part.is_empty())
}

fn strip_declared_type_annotation(key: &str) -> Option<&str> {
    let (prefix, type_annotation) = key.rsplit_once(':')?;
    is_declared_type_annotation_context(prefix, type_annotation).then_some(prefix)
}

fn declared_type_annotation(key: &str) -> Option<&str> {
    let (prefix, type_annotation) = key.rsplit_once(':')?;
    is_declared_type_annotation_context(prefix, type_annotation).then_some(type_annotation.trim())
}

fn is_declared_type_annotation_context(prefix: &str, type_annotation: &str) -> bool {
    declared_identifier_key_without_type(prefix).is_some()
        && is_source_type_annotation_segment(type_annotation)
}

fn declared_identifier_key_without_type(key: &str) -> Option<&str> {
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
    (!is_declaration_word(ident)).then_some(ident)
}

fn is_source_type_annotation_segment(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 160
        || has_top_level_type_annotation_delimiter(value)
        || value
            .bytes()
            .any(|b| matches!(b, b'=' | b'"' | b'\'' | b'`' | b'{' | b'}'))
    {
        return false;
    }
    let tokens = value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return false;
    }
    let has_type_token = tokens
        .iter()
        .any(|token| is_declaration_word(token) || is_source_type_word(token));
    let has_custom_type = tokens
        .iter()
        .any(|token| token.bytes().next().is_some_and(|b| b.is_ascii_uppercase()));
    let has_type_punctuation = value
        .bytes()
        .any(|b| matches!(b, b'<' | b'>' | b'[' | b']' | b'|' | b'&' | b'.'));
    has_type_token || has_custom_type || has_type_punctuation
}

fn has_top_level_type_annotation_delimiter(value: &str) -> bool {
    let mut angle_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut paren_depth = 0usize;
    for ch in value.chars() {
        match ch {
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ',' | ';' if angle_depth == 0 && bracket_depth == 0 && paren_depth == 0 => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_source_type_word(token: &str) -> bool {
    matches_ignore_ascii_case(
        token,
        &[
            "any",
            "bigint",
            "never",
            "null",
            "number",
            "symbol",
            "undefined",
            "unknown",
            "void",
        ],
    )
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
    if is_nid_algorithm_identifier(value) {
        return true;
    }
    if value.eq_ignore_ascii_case("AWS4-HMAC-SHA256") {
        // AWS Signature Version 4's signing algorithm identifier is public
        // protocol metadata, not the HMAC signing key.
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "rsa-pss" | "rsa-oaep") {
        return true;
    }
    if let Some((left, right)) = lower.split_once(':') {
        return is_key_algorithm_literal(left) && is_key_algorithm_literal(right);
    }
    if let Some((head, suffix)) = lower.rsplit_once('-') {
        if matches!(suffix, "public" | "default") || suffix.starts_with("bad") {
            return is_key_algorithm_literal(head);
        }
    }
    if lower
        .strip_prefix("rsa-oaep-")
        .is_some_and(|case| !case.is_empty() && case.bytes().all(|b| b.is_ascii_digit()))
    {
        return true;
    }
    let mut parts = value.split('-');
    let Some(algorithm) = parts.next() else {
        return false;
    };
    let Some(bits) = parts.next() else {
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
    if !(128..=16384).contains(&bits) {
        return false;
    }
    parts.all(is_public_algorithm_suffix_part)
}

fn is_public_algorithm_suffix_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 10
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_'))
        && (part.bytes().all(|b| b.is_ascii_digit())
            || normalize_key(part)
                .split('_')
                .all(|word| matches!(word, "fips" | "fips186" | "public" | "default")))
}

fn is_nid_algorithm_identifier(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("nid_") else {
        return false;
    };
    (4..=64).contains(&rest.len())
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_'))
        && contains_any(
            rest,
            &[
                "aes", "aria", "camellia", "des", "dh", "dsa", "ecdsa", "ed25519", "rsa", "sha",
            ],
        )
}

fn is_public_curve_algorithm_literal(value: &str, key_name: &str) -> bool {
    if !has_identifier_component(key_name, "key") {
        return false;
    }
    let value = value.trim();
    if !(3..=96).contains(&value.len())
        || value.chars().any(char::is_whitespace)
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if let Some((family, bits)) = lower.split_once('-') {
        if matches!(family, "p" | "b" | "k")
            && bits
                .split('_')
                .next()
                .is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return true;
        }
    }
    (lower.starts_with("alice-") || lower.starts_with("bob-"))
        && lower.contains("-public")
        && (lower.contains("raw") || lower.contains("canonical"))
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
    octets.len() >= 3
        && (source_key.trim_start().starts_with("OBJ_") || octets.iter().any(|byte| *byte >= 0x80))
}

fn is_asn1_obj_name_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // OpenSSL object tables also map `OBJ_*` constants to public short names:
    // `OBJ_setct_AuthTokenTBS = "AuthTokenTBS"`. These are identifiers for
    // ASN.1 objects, not auth tokens. Require the explicit `OBJ_` table shape
    // and a normalized suffix match so ordinary `token = "AuthTokenTBS"` still
    // detects.
    if !(key_name.starts_with("obj_") || source_key.trim_start().starts_with("OBJ_")) {
        return false;
    }
    let value = value
        .trim()
        .trim_end_matches("\\n")
        .trim_end_matches("\\r")
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(3..=64).contains(&value.len())
        || value
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-'))
    {
        return false;
    }
    let normalized_value = normalize_key(value);
    let normalized_key = normalize_key(source_key);
    !normalized_value.is_empty() && normalized_key.ends_with(&normalized_value)
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

fn is_crypto_test_vector_record_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // CAVP/SEC/RFC crypto vector files label records with fields such as
    // `PrivateKey`, `PeerKey`, and `PrivPubKeyPair`. In those files the value
    // can be an algorithm/curve/case identifier (`Alice-secp256r1`,
    // `RSA-2048`, or `prime192v1:...`) rather than the key bytes. Keep this
    // structural: require a key-vector field, compact identifier syntax, and a
    // known public curve/algorithm marker. Operational names like
    // `ALICE_prod_key_2026` stay detectable because they lack those markers or
    // contain sensitive setting-name components.
    if !is_crypto_test_vector_record_key(key_name, source_key) {
        return false;
    }
    let value = value.trim();
    if !(4..=128).contains(&value.len())
        || value.contains("://")
        || value.chars().any(char::is_whitespace)
        || value
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-' | b':'))
    {
        return false;
    }
    if normalize_key(value)
        .split('_')
        .any(|part| matches!(part, "secret" | "token" | "password" | "credential" | "key"))
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    value.bytes().any(|b| b.is_ascii_digit())
        && contains_any(
            &lower,
            &[
                "secp",
                "sect",
                "brainpool",
                "prime",
                "c2pnb",
                "c2tnb",
                "wtls",
                "rsa",
                "dsa",
            ],
        )
}

fn is_crypto_test_vector_record_key(key_name: &str, source_key: &str) -> bool {
    let key = normalize_key(key_name);
    let source = normalize_key(source_key);
    [key.as_str(), source.as_str()].iter().any(|name| {
        matches!(
            *name,
            "private_key" | "privatekey" | "peer_key" | "peerkey" | "priv_pub_key_pair"
        )
    })
}

fn is_crypto_vector_field_descriptor_literal(value: &str, key_name: &str) -> bool {
    // OpenSSL/NIST vector manifests describe transformed record columns with
    // values such as `IV/ciphertext':plaintext:ciphertext:encdec`. In a
    // `...:key:<descriptor>` sequence, the generic `key` token is the column
    // name and the captured value is the following column descriptor, not key
    // bytes. Require multiple crypto field names and the enc/dec marker so
    // ordinary `key=tenant-7-trial` values remain visible.
    if key_name != "key" {
        return false;
    }
    let value = value.trim();
    if !(12..=128).contains(&value.len())
        || value.chars().any(char::is_whitespace)
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'/' | b':' | b'\''))
    {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    lower.contains("plaintext")
        && lower.contains("ciphertext")
        && lower.contains("encdec")
        && (lower.contains("iv/") || lower.contains("iv:") || lower.contains("output"))
}

fn is_localized_ui_text_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Translation tables and UI copy often use sensitive words in message IDs:
    // `passwordEnteredInvalid = "Invalid password for room \"%s\"."`. The
    // rendered sentence is not a password. Keep this anchored to UI-message key
    // components so real passphrases under `password` still detect. Resource
    // bundles also store escaped Unicode (`\uXXXX`) and numbered keys
    // (`ENTER_KEY_HELP#0`); treat those as display text when the key carries a
    // UI component such as `help` or `saved`. Test assertions also put field
    // error messages under sensitive field names (`errors.password =
    // "Email Taken"`); require an error/validation context for that broader
    // shape so ordinary `password = "Correct horse..."` still detects.
    if !key_name_has_sensitive_component(key_name)
        || !(key_name_has_ui_text_component(key_name)
            || source_key_has_validation_text_context(source_key))
    {
        return false;
    }
    let value = value.trim();
    if !(3..=240).contains(&value.len()) || value.contains("://") {
        return false;
    }
    localized_ui_text_has_boundary(value) && localized_ui_text_chars_are_display_safe(value)
}

fn is_single_word_localized_ui_label_literal(
    value: &str,
    key_name: &str,
    source_key: &str,
) -> bool {
    // Locale tables can store a one-word translated label under field IDs such
    // as `repeat_password: Powtórz`. Require sensitive UI-key context and a
    // non-ASCII display word so plain credentials like `password: admin` or
    // `confirm_password: hunter2` remain visible.
    if !key_name_has_sensitive_component(key_name)
        || !(key_name_has_ui_text_component(key_name)
            || source_key_has_validation_text_context(source_key))
    {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ',' | ':' | ';'));
    (2..=64).contains(&value.chars().count())
        && !value.is_ascii()
        && value.chars().all(char::is_alphabetic)
}

fn is_query_predicate_literal(value: &str, key_name: &str) -> bool {
    // ORM/API filters encode field predicates in the key
    // (`password__startswith=...`). Those values are search terms, not the
    // credential bytes. Keep exact equality out of this suppressor and do not
    // hide token-shaped values that could be copied credentials.
    if !key_name_has_sensitive_component(key_name)
        || !key_name_has_query_predicate_component(key_name)
    {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ',' | ';'));
    !value_has_strong_secret_shape(value)
}

fn key_name_has_query_predicate_component(key_name: &str) -> bool {
    key_name.split('_').any(|part| {
        matches!(
            part,
            "startswith"
                | "endswith"
                | "contains"
                | "icontains"
                | "regex"
                | "iregex"
                | "match"
                | "matches"
        )
    })
}

fn is_sensitive_display_label_literal(value: &str, key_name: &str) -> bool {
    // Form/i18n metadata often maps sensitive field IDs to the text shown to a
    // user (`password_confirmation: Password`). Suppress only label-shaped text
    // that repeats words already present in the key, so `password: hunter2`
    // and `password_confirmation: hunter2` still mask.
    if !key_name_has_sensitive_component(key_name) || !key_name_has_ui_text_component(key_name) {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ',' | ':' | ';'));
    if !(2..=96).contains(&value.chars().count())
        || value.bytes().any(|b| b.is_ascii_digit())
        || !localized_ui_text_chars_are_display_safe(value)
    {
        return false;
    }
    let normalized_key = normalize_key(key_name);
    let normalized_value = normalize_key(value);
    let key_parts = normalized_key
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let value_parts = normalized_value
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    !value_parts.is_empty()
        && value_parts
            .iter()
            .all(|part| key_parts.iter().any(|key_part| key_part == part))
}

fn value_has_strong_secret_shape(value: &str) -> bool {
    let value = value.trim();
    let bytes = value.as_bytes();
    let has_alpha = bytes.iter().any(u8::is_ascii_alphabetic);
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_symbol = bytes
        .iter()
        .any(|b| !b.is_ascii_alphanumeric() && !b.is_ascii_whitespace());
    let has_space = bytes.iter().any(u8::is_ascii_whitespace);
    (!has_space && bytes.len() >= 24)
        || (!has_space && bytes.len() >= 12 && has_alpha && has_digit && has_symbol)
}

fn is_missing_credential_name_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Error strings commonly enumerate missing credential setting names:
    // `credentials information are missing: AWS_ACCESS_KEY_ID`. The captured
    // value is the public env/config key that needs to be supplied, not the
    // secret bytes. Keep this anchored to missing-credential prose plus an
    // ALL_CAPS identifier so normal config assignments still detect.
    if !(key_name_has_sensitive_component(key_name)
        || source_key
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .map(|part| part.to_ascii_lowercase())
            .any(|part| matches!(part.as_str(), "credential" | "credentials")))
    {
        return false;
    }
    let source = source_key.to_ascii_lowercase();
    if !source.contains("missing") {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ',' | ':' | ';'));
    is_uppercase_identifier_constant(value)
}

fn localized_ui_text_has_boundary(value: &str) -> bool {
    value.chars().any(char::is_whitespace)
        || value.contains("\\u")
        || value.contains("%s")
        || value.contains("&thinsp;")
        || value.chars().any(is_localized_ui_boundary_punctuation)
}

fn localized_ui_text_chars_are_display_safe(value: &str) -> bool {
    value.chars().all(|ch| {
        !ch.is_control()
            && (ch.is_alphanumeric()
                || ch.is_whitespace()
                || ch == '\\'
                || ch == '%'
                || ch == '&'
                || is_localized_ui_sentence_punctuation(ch))
    })
}

fn is_localized_ui_sentence_punctuation(ch: char) -> bool {
    matches!(
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
            | '/'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '\u{00a1}'
            | '\u{00bf}'
            | '\u{3001}'
            | '\u{3002}'
            | '\u{ff01}'
            | '\u{ff1f}'
            | '\u{ff1a}'
            | '\u{ff1b}'
    )
}

fn is_localized_ui_boundary_punctuation(ch: char) -> bool {
    matches!(
        ch,
        ':' | ';'
            | ','
            | '.'
            | '!'
            | '?'
            | '\u{00a1}'
            | '\u{00bf}'
            | '\u{3001}'
            | '\u{3002}'
            | '\u{ff01}'
            | '\u{ff1f}'
            | '\u{ff1a}'
            | '\u{ff1b}'
    )
}

fn source_key_has_validation_text_context(source_key: &str) -> bool {
    let normalized = normalize_key(source_key);
    let mut parts = normalized.split('_').filter(|part| !part.is_empty());
    parts.any(|part| {
        matches!(
            part,
            "error"
                | "errors"
                | "expected"
                | "actual"
                | "validation"
                | "validate"
                | "message"
                | "messages"
                | "translation"
                | "translations"
                | "locale"
                | "locales"
                | "lang"
                | "i18n"
        )
    })
}

fn key_name_has_sensitive_component(key_name: &str) -> bool {
    key_name.split('_').any(|part| {
        is_numbered_password_component(part)
            || matches!(
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
                | "saved"
                | "blank"
                | "cannot"
                | "confirmation"
                | "confirm"
                | "repeat"
                | "forgot"
                | "request"
                | "reset"
                | "change"
                | "strength"
                | "short"
                | "long"
                | "longer"
                | "enough"
                | "taken"
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

fn is_xaml_key_time_literal(value: &str, source_key: &str) -> bool {
    // XAML animation timelines use `KeyTime="0:0:0.2"` to schedule keyframes.
    // The word "key" is part of the animation API, not credential material.
    let source = normalize_key(source_key);
    if !(source == "key_time" || source.ends_with("_key_time")) {
        return false;
    }
    let value = value.trim();
    (1..=24).contains(&value.len())
        && value.contains(':')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b':' | b'.'))
}

fn is_url_query_metadata_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Query strings often contain pagination and listing controls such as
    // `nextPageToken`, `pageToken`, `prefix`, and `maxResults`. These are API
    // navigation metadata, not bearer/API tokens. Keep auth-like parameters
    // (`access_token`, `id_token`, `refresh_token`) out of this path and
    // require visible URL-query syntax in the source fragment.
    if !(source_key.contains('&') || source_key.contains('?') || source_key.contains("%2")) {
        return false;
    }
    let key = normalize_key(key_name);
    if !is_url_query_navigation_key(&key) {
        return false;
    }
    let value = value
        .trim()
        .trim_end_matches("\\n")
        .trim_end_matches("\\r")
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    (1..=64).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_alphanumeric())
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'%' | b'=')
        })
}

fn is_url_query_navigation_key(key: &str) -> bool {
    let parts = key
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.windows(2).any(|window| {
        matches!(
            window,
            ["access", "token"]
                | ["id", "token"]
                | ["refresh", "token"]
                | ["auth", "token"]
                | ["bearer", "token"]
        )
    }) {
        return false;
    }
    matches!(
        key,
        "prefix" | "page_token" | "next_page_token" | "max_results" | "maxresults"
    ) || key.ends_with("_prefix")
        || key.ends_with("_page_token")
        || key.ends_with("_next_page_token")
        || key.ends_with("_max_results")
        || key.ends_with("_maxresults")
}

fn is_html_documentation_fragment_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Generated API docs often include prose like `<p>Key: CreatedTime</p>` or
    // `<li>token=1234</li>` inside long documentation strings. The scanner can
    // see the inner key/value text as a credential. Require documentation/HTML
    // syntax on the left, then keep generic `key` fields to public metadata
    // names and sensitive fields to short numeric examples.
    if !source_key_has_html_documentation_shape(source_key) {
        return false;
    }
    let value = value.trim();
    let (head, had_html_tail) = strip_trailing_html_tag(value);
    (has_identifier_component(key_name, "key")
        && is_documentation_metadata_key_name(head, had_html_tail))
        || (had_html_tail
            && key_name_has_non_key_secret_component(key_name)
            && is_short_numeric_doc_example(head))
}

fn is_documentation_auth_header_example_literal(
    value: &str,
    key_name: &str,
    source_key: &str,
    tail: &str,
) -> bool {
    // API docs often embed Markdown such as
    // `Authorization: Bearer <sample> the Authorization header...` inside a
    // `description` field. A real header line usually ends after the token;
    // require documentation field context and prose after the captured value.
    if normalize_key(key_name) != "authorization" {
        return false;
    }
    let source = source_key.to_ascii_lowercase();
    if !(source.contains("description") || source.contains("documentation")) {
        return false;
    }
    if !(source.contains("authorization")
        && (source.contains("bearer") || source.contains("basic")))
    {
        return false;
    }
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }
    let tail = trim_documentation_auth_tail_prefix(tail);
    let tail_lower = tail.to_ascii_lowercase();
    tail_lower.contains("authorization")
        || tail_lower.contains("header")
        || tail_lower.contains("endpoint")
        || tail_lower.contains("returns")
}

fn trim_documentation_auth_tail_prefix(mut tail: &str) -> &str {
    loop {
        tail = tail.trim_start_matches(['"', '\'', '`', ' ', '\t']);
        let Some(rest) = tail
            .strip_prefix("\\n")
            .or_else(|| tail.strip_prefix("\\r"))
        else {
            return tail;
        };
        tail = rest;
    }
}

fn is_markup_syntax_fragment_literal(value: &str, key_name: &str) -> bool {
    // HTML/XML snippets can be split at labels and attributes named
    // `password`, `key`, or `token`, leaving the "value" as a tag fragment
    // such as `</label>` or `type='password`. Those fragments are markup
    // syntax, not credential bytes. Keep concrete tag contents visible:
    // `<code>sk-test-token</code>` is not tag-only syntax and still detects.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if value.is_empty() || value.contains("://") {
        return false;
    }
    let compact_escaped_ws;
    let tag_value = if value.contains("\\n") || value.contains("\\r") || value.contains("\\t") {
        compact_escaped_ws = value
            .replace("\\n", "")
            .replace("\\r", "")
            .replace("\\t", "");
        compact_escaped_ws.as_str()
    } else {
        value
    };
    is_angle_bracket_placeholder_or_tag(value)
        || is_html_tag_sequence_fragment(tag_value)
        || is_html_attribute_fragment(value)
        || is_html_trailing_tag_text_fragment(value, key_name)
        || is_escaped_markup_syntax_fragment(value)
}

fn is_angle_bracket_placeholder_or_tag(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
    else {
        return false;
    };
    if inner.is_empty()
        || inner.contains(['<', '>'])
        || inner.len() > 96
        || inner.bytes().any(|b| matches!(b, b'=' | b'"' | b'\''))
    {
        return false;
    }
    let inner = inner.trim_start_matches('/');
    !inner.is_empty()
        && inner.bytes().any(|b| b.is_ascii_alphabetic())
        && inner.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b.is_ascii_whitespace()
                || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'*')
        })
}

fn is_generic_key_placeholder_literal(value: &str, key_name: &str) -> bool {
    if !has_identifier_component(key_name, "key") {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    is_pem_ellipsis_placeholder(value)
        || is_incomplete_angle_placeholder_literal(value)
        || is_braced_template_placeholder_literal(value)
}

fn is_incomplete_angle_placeholder_literal(value: &str) -> bool {
    let Some(inner) = value.strip_prefix('<') else {
        return false;
    };
    if inner.is_empty()
        || inner.contains(['<', '>'])
        || inner.len() > 96
        || inner.bytes().any(|b| matches!(b, b'=' | b'"' | b'\''))
    {
        return false;
    }
    let normalized = normalize_key(inner);
    normalized.split('_').any(|part| {
        matches!(
            part,
            "base64" | "encoded" | "placeholder" | "sample" | "example" | "key"
        )
    }) && inner.bytes().any(|b| b.is_ascii_alphabetic())
}

fn is_braced_template_placeholder_literal(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };
    (2..=48).contains(&inner.len())
        && inner.bytes().any(|b| b.is_ascii_alphabetic())
        && inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn is_html_tag_sequence_fragment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if !(lower.starts_with("</") || lower.starts_with("<tr") || lower.starts_with("<td")) {
        return false;
    }
    lower.contains('>')
        && lower.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'<' | b'>' | b'/' | b'-' | b'_' | b':' | b'=' | b'"' | b'\''
                )
        })
}

fn is_html_attribute_fragment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some((name, rest)) = lower.split_once('=') else {
        return false;
    };
    matches!(
        name.trim(),
        "type" | "class" | "for" | "name" | "id" | "value" | "href" | "data-uk-form-password"
    ) && !rest.is_empty()
        && rest.len() <= 96
        && rest
            .bytes()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
}

fn is_html_trailing_tag_text_fragment(value: &str, key_name: &str) -> bool {
    let (head, had_html_tail) = strip_trailing_html_tag(value);
    if !had_html_tail || head.is_empty() {
        return false;
    }
    let head = head.trim();
    if head.is_empty()
        || head.bytes().any(|b| b.is_ascii_digit())
        || head
            .bytes()
            .any(|b| matches!(b, b'-' | b'_' | b'/' | b'+' | b'='))
    {
        return false;
    }
    if has_identifier_component(key_name, "key") && head.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    head.bytes().all(|b| {
        b.is_ascii_alphabetic() || b.is_ascii_whitespace() || matches!(b, b'.' | b':' | b';')
    }) && (head.ends_with('.') || head.bytes().next().is_some_and(|b| b.is_ascii_uppercase()))
}

fn is_escaped_markup_syntax_fragment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if !lower.starts_with("\\u003c") || !lower.contains("\\u003e") {
        return false;
    }
    let compact = lower
        .replace("\\n", "")
        .replace("\\r", "")
        .replace("\\t", "");
    compact
        .split("\\u003e")
        .filter(|part| !part.is_empty())
        .all(is_escaped_markup_tag_head)
}

fn is_escaped_markup_tag_head(value: &str) -> bool {
    let Some(tag) = value.strip_prefix("\\u003c") else {
        return false;
    };
    let tag = tag.trim_start_matches('/');
    !tag.is_empty()
        && tag.len() <= 32
        && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
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

fn key_name_has_non_key_secret_component(key_name: &str) -> bool {
    normalize_key(key_name).split('_').any(|part| {
        matches!(
            part,
            "secret" | "password" | "passwd" | "pwd" | "credential" | "token" | "auth"
        )
    })
}

fn is_short_numeric_doc_example(value: &str) -> bool {
    let value = value.trim();
    (3..=12).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
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
    is_c_family_prefixed_source_identifier(value)
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

fn is_checksum_metadata_digest_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // `*_checksum` fields conventionally store verification digests. A key can
    // still contain a sensitive word (`harvester-token-checksum`), but the
    // digest verifies another object and is not the token itself. Keep this
    // strict to hex digest widths so arbitrary `token`/`password` values still
    // detect.
    if !(has_identifier_component(key_name, "checksum")
        || has_identifier_component(&normalize_key(source_key), "checksum"))
    {
        return false;
    }
    is_hex_digest_literal(value)
}

fn is_hex_digest_literal(value: &str) -> bool {
    let value = value.trim();
    matches!(value.len(), 32 | 40 | 64 | 96 | 128) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_hashed_token_derivative_literal(value: &str, key_name: &str) -> bool {
    if !has_identifier_component(key_name, "token")
        || !(has_identifier_component(key_name, "hash")
            || has_identifier_component(key_name, "hashed")
            || has_identifier_component(key_name, "digest"))
    {
        return false;
    }
    let value = value.trim();
    if is_hex_digest_literal(value) {
        return true;
    }
    let bytes = value.as_bytes();
    (6..=160).contains(&bytes.len())
        && bytes[0] == b'$'
        && bytes.iter().filter(|b| **b == b':').count() >= 2
        && bytes.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'$' | b':' | b'+' | b'/' | b'=' | b'.' | b'_' | b'-')
        })
}

fn is_escaped_control_placeholder_literal(value: &str, key_name: &str) -> bool {
    // Test fixtures often keep table-shaped placeholder values in escaped
    // string form, e.g. `LINE_1\nLINE_2` for a private key column or
    // `password_1\t\t` for a decrypted sample. Require literal escaped
    // control characters plus placeholder grammar; real escaped binary or
    // base64 material is not affected.
    let value = value.trim();
    if !(value.contains("\\n") || value.contains("\\t")) {
        return false;
    }
    is_numbered_line_placeholder_literal(value)
        || is_key_named_tab_placeholder_literal(value, key_name)
        || is_escaped_sensitive_key_name_fragment(value)
}

fn is_numbered_line_placeholder_literal(value: &str) -> bool {
    let parts = value.split("\\n").collect::<Vec<_>>();
    (2..=32).contains(&parts.len())
        && parts
            .iter()
            .all(|part| is_numbered_placeholder(part, "line"))
}

fn is_numbered_placeholder(value: &str, prefix: &str) -> bool {
    let normalized = normalize_key(value);
    normalized
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

fn is_key_named_tab_placeholder_literal(value: &str, key_name: &str) -> bool {
    let mut body = value;
    let mut tabs = 0usize;
    while let Some(rest) = body.strip_suffix("\\t") {
        body = rest;
        tabs += 1;
    }
    if tabs < 2 {
        return false;
    }
    let body = normalize_key(body);
    let key = normalize_key(key_name);
    body == key || is_numbered_placeholder(&body, &key)
}

fn is_escaped_sensitive_key_name_fragment(value: &str) -> bool {
    let Some((head, tail)) = value.split_once("\\n") else {
        return false;
    };
    let head = normalize_key(head);
    !head.is_empty()
        && head.split('_').any(is_sensitive_setting_name_component)
        && tail
            .split("\\t")
            .all(|part| part.is_empty() || matches!(part, "+" | "if"))
}

fn is_escaped_plain_source_line_literal(value: &str, source_key: &str) -> bool {
    // Embedded source/config payloads can leave a plain identifier followed by
    // an escaped line break (`from_admin\n`, `$value\n`). A real secret with
    // digits, punctuation, or sensitive words remains detectable.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(value.contains("\\n") || value.contains("\\r") || value.contains("\\t")) {
        return false;
    }
    let head = value
        .split("\\n")
        .next()
        .unwrap_or(value)
        .split("\\r")
        .next()
        .unwrap_or(value)
        .split("\\t")
        .next()
        .unwrap_or(value)
        .trim();
    let reference_shaped = head.starts_with('$') || head.contains('_') || head.contains("->");
    if !reference_shaped
        || !(2..=80).contains(&head.len())
        || head.bytes().any(|b| b.is_ascii_digit())
        || contains_sensitive_identifier_component(head)
    {
        return false;
    }
    let body = head.trim_start_matches('$');
    is_simple_code_reference_name(body)
        && (source_key_has_code_shape(source_key)
            || source_key_has_escaped_payload_shape(source_key)
            || head.starts_with('$')
            || head.contains('_'))
}

fn is_escaped_source_payload_fragment_literal(value: &str, source_key: &str) -> bool {
    // Saved API responses and replay files can embed source code inside JSON
    // strings. A colon inside that escaped code may make the scanner split a
    // code fragment as `password: \"Basic` or `token: client_secret\n\t`.
    // Suppress only when the left side already proves escaped payload context
    // and the captured value carries escaped string/control syntax.
    if !source_key_has_escaped_payload_shape(source_key) {
        return false;
    }
    let value = value.trim().trim_matches('"');
    if let Some(head) = escaped_quoted_payload_head(value) {
        return is_payload_fragment_head(head);
    }
    if !(value.contains("\\n") || value.contains("\\t")) {
        return false;
    }
    let head = payload_fragment_head(value);
    is_payload_fragment_head(head)
}

fn escaped_quoted_payload_head(value: &str) -> Option<&str> {
    value.strip_prefix("\\\"").map(payload_fragment_head)
}

fn payload_fragment_head(value: &str) -> &str {
    value
        .split("\\n")
        .next()
        .unwrap_or(value)
        .split("\\t")
        .next()
        .unwrap_or(value)
        .trim_matches(|ch: char| matches!(ch, '+' | '\\' | '"' | '\'' | '`' | ' '))
}

fn source_key_has_escaped_payload_shape(source_key: &str) -> bool {
    let lower = source_key.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "\\n",
            "\\t",
            "\\\"",
            "\"content\"",
            "\"patch\"",
            "\"files\"",
        ],
    )
}

fn is_payload_fragment_head(head: &str) -> bool {
    let normalized = normalize_key(head);
    normalized.is_empty()
        || matches!(
            normalized.as_str(),
            "basic" | "bearer" | "class" | "instance"
        )
        || is_source_secret_name_reference_value(&normalized)
        || is_uppercase_identifier_constant(head)
}

fn is_documented_env_var_name_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Documentation often says "credentials are passed in environment variable:
    // FOO_API_KEY". The captured RHS is the public variable name, not the secret
    // value. Require explicit env-var prose on the left plus an ALL_CAPS
    // identifier-shaped RHS so ordinary config assignments keep detecting.
    let source = source_key.to_ascii_lowercase();
    if !(source.contains("environment variable")
        || source.contains("environment variables")
        || source.contains("env var")
        || source.contains("env vars"))
    {
        return false;
    }
    if !(key_name_has_sensitive_component(key_name)
        || key_name_indicates_sensitive_material(key_name)
        || source.contains("credential")
        || source.contains("credentials"))
    {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | '<' | '>'))
        .trim_end_matches(['.', ',', ';', ':', ')', ']']);
    if !is_uppercase_public_doc_identifier(value) {
        return false;
    }
    let normalized = normalize_key(value);
    normalized
        .split('_')
        .any(|part| is_sensitive_setting_name_component(part) || matches!(part, "user" | "name"))
}

fn is_source_env_fallback_name_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Source config commonly falls back from an environment lookup to the public
    // setting name (`clientSecret: process.env.FOO_SECRET || "APP_SECRET"`).
    // That RHS is lookup metadata, not credential bytes. Keep this narrow:
    // require a sensitive key, explicit env/fallback syntax on the left, and an
    // ALL_CAPS identifier with a sensitive component but no digits.
    if !(key_name_has_sensitive_component(key_name)
        || key_name_indicates_sensitive_material(key_name))
    {
        return false;
    }
    let source = source_key.trim();
    if !(source.contains("process.env")
        || source.contains("os.environ")
        || source.contains("ENV[")
        || source.contains("getenv"))
    {
        return false;
    }
    if !(source.contains("||") || source.contains("??") || source.contains(" or ")) {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !is_uppercase_identifier_constant(value) {
        return false;
    }
    normalize_key(value)
        .split('_')
        .filter(|part| !part.is_empty())
        .any(is_sensitive_setting_name_component)
}

fn is_source_constant_reference_literal(value: &str, key_name: &str, source_key: &str) -> bool {
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
    is_non_secret_source_constant_value(value) || is_source_sensitive_setting_name(value, key_name)
}

fn is_source_sensitive_setting_name(value: &str, key_name: &str) -> bool {
    // Source declarations also store the public *name* of a credential setting,
    // e.g. `expectedTokenValue = "GITHUB_TOKEN_VALUE"` or
    // `OAuthClientSecret = "GCM_BITBUCKET_CLOUD_CLIENTSECRET"`. This is not
    // value-list based: require an ALL_CAPS identifier, a sensitive suffix, and
    // a suffix that matches the declared identifier once case/separators are
    // normalized. Short one-word suffixes like `_SECRET` are deliberately not
    // enough, because `PROD_SECRET_VALUE` can still be real config material.
    let key_compact = normalize_key(key_name).replace('_', "");
    if key_compact.len() < 8 {
        return false;
    }
    let parts = normalize_key(value)
        .split('_')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if parts.len() < 2
        || !parts
            .iter()
            .any(|part| is_sensitive_setting_name_component(part))
    {
        return false;
    }
    (0..parts.len()).any(|idx| {
        let suffix = parts[idx..].join("");
        suffix.len() >= 8
            && key_compact.ends_with(&suffix)
            && parts[idx..]
                .iter()
                .any(|part| is_sensitive_setting_name_component(part))
    })
}

fn is_sensitive_setting_name_component(part: &str) -> bool {
    matches!(
        part,
        "secret"
            | "secrets"
            | "clientsecret"
            | "token"
            | "tokens"
            | "password"
            | "passwd"
            | "credential"
            | "credentials"
            | "auth"
            | "key"
    )
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

fn is_source_declared_lower_name_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Source constants also publish lower-case setting/resource names:
    // `CONSUMER_KEY = "oauth_consumer_key"` or
    // `DELETE_KEY_SWIPE_LEFT = "gestures__delete_key_swipe_left"`.
    // The RHS is metadata when its normalized suffix matches the declared
    // identifier. Requiring source syntax, identifier separators, and no digits
    // keeps real values such as `api_key="abc123"` or `secret="tenant-7-trial"`
    // visible.
    if !source_key_has_code_shape(source_key) {
        return false;
    }
    if !(key_name_has_sensitive_component(key_name)
        || key_name_indicates_sensitive_material(key_name))
    {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(5..=128).contains(&value.len())
        || value.bytes().any(|b| b.is_ascii_digit())
        || !value.bytes().any(|b| matches!(b, b'_' | b'-' | b'.'))
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || matches!(b, b'_' | b'-' | b'.'))
    {
        return false;
    }
    let declared = normalize_key(key_name).replace('_', "");
    let value_name = normalize_key(value).replace('_', "");
    declared.len() >= 6 && value_name.ends_with(&declared)
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
        || is_c_family_prefixed_source_identifier(key)
}

fn is_c_family_prefixed_source_identifier(value: &str) -> bool {
    // C-family codebases commonly use `m_` for members and `l_` for locals.
    // When such a name is on the left side and the right side is an unquoted
    // identifier, the match is a reference assignment (`m_password = state`),
    // not the credential bytes.
    value
        .strip_prefix("m_")
        .or_else(|| value.strip_prefix("l_"))
        .is_some_and(is_simple_code_reference_name)
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

fn is_self_describing_key_value_placeholder(value: &str, key_name: &str, source_key: &str) -> bool {
    // Test/config hashes often use paired placeholder names such as
    // `my_key: "my_value"` or `opt_key: "opt_value"` to prove option plumbing.
    // Require source-shaped context and identical stems so `api_key="abc123"`
    // or `client_secret="tenant-7-trial"` still detect normally.
    let value = normalize_key(value);
    if is_compact_key_value_here_placeholder(&value, key_name) {
        return true;
    }
    if !source_key_has_code_shape(source_key) {
        return false;
    }
    let Some(stem) = key_name.strip_suffix("_key") else {
        return false;
    };
    if !(2..=32).contains(&stem.len())
        || !stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return false;
    }
    value.strip_suffix("_value") == Some(stem) || value.strip_suffix("_value_here") == Some(stem)
}

fn is_compact_key_value_here_placeholder(value: &str, key_name: &str) -> bool {
    let key_compact = key_name.replace('_', "");
    if compact_key_stem_matches_value_here(value, &key_compact) {
        return true;
    }
    for (suffix, suffix_compact) in [
        ("api_key", "apikey"),
        ("access_key", "accesskey"),
        ("secret_key", "secretkey"),
        ("client_secret", "clientsecret"),
        ("access_token", "accesstoken"),
        ("refresh_token", "refreshtoken"),
        ("auth_token", "authtoken"),
        ("token", "token"),
        ("secret", "secret"),
        ("password", "password"),
    ] {
        if (key_name == suffix
            || key_name
                .strip_suffix(suffix)
                .is_some_and(|head| head.ends_with('_')))
            && compact_key_stem_matches_value_here(value, suffix_compact)
        {
            return true;
        }
    }
    false
}

fn compact_key_stem_matches_value_here(value: &str, key_compact: &str) -> bool {
    key_compact.len() >= 4
        && matches!(
            value.strip_prefix(key_compact),
            Some("valuehere" | "_value_here")
        )
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

fn is_structured_sensitive_name_reference_literal(value: &str, key_name: &str) -> bool {
    // Structured fixtures and API payloads can store the name of another secret
    // field under a sensitive-looking slot: `token: "api_key"` or
    // `password: "api_password"`. The vocabulary remains data-driven in
    // `source_secret_name_patterns.txt`; this function only supplies the
    // structural contract missing from simple hash/object keys.
    if !key_name_has_sensitive_component(key_name) {
        return false;
    }
    let value = value.trim();
    (4..=64).contains(&value.len())
        && value.bytes().any(|b| matches!(b, b'_' | b'-'))
        && !value.bytes().any(|b| b.is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        && is_source_secret_name_reference_value(value)
}

fn is_source_fixture_secret_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Test fixtures often assign deliberately weak credentials to variables
    // named `expectedPassword`, `MOCK_ACCESS_TOKEN`, or similar. Do not suppress
    // weak values by value alone; require a fixture key name. Strong material
    // under `testPassword` still detects because the value matcher is narrow.
    is_source_fixture_secret_value(key_name, value)
        || is_source_fixture_secret_value(source_key, value)
}

fn is_source_fixture_low_entropy_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Test fixtures also use short sample credentials that are not explicit
    // placeholders (`expectedPassword = "abc123"`). Suppress only when source
    // context carries a fixture marker and the value has weak sample shape.
    // Strong mixed values such as `helloworld1234` stay visible.
    (is_source_fixture_key_context(key_name) || is_source_fixture_key_context(source_key))
        && is_weak_fixture_sample_literal(value)
}

fn is_weak_fixture_sample_literal(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ',' | ';'));
    let bytes = value.as_bytes();
    if !(4..=16).contains(&bytes.len())
        || bytes.iter().any(u8::is_ascii_whitespace)
        || value.contains("://")
    {
        return false;
    }
    let has_alpha = bytes.iter().any(u8::is_ascii_alphabetic);
    let has_digit = bytes.iter().any(u8::is_ascii_digit);
    let has_symbol = bytes.iter().any(|b| !b.is_ascii_alphanumeric());
    if has_symbol || !(has_alpha || has_digit) {
        return false;
    }
    bytes.iter().all(u8::is_ascii_digit) || (has_alpha && has_digit && bytes.len() <= 9)
}

fn is_source_struct_tag_literal(value: &str, _key_name: &str, source_key: &str) -> bool {
    // Go-style struct tags can contain generic `key:"name,option"` metadata.
    // The backtick-delimited tag syntax proves this is a field mapping, not
    // credential material. Tags also appear as simple mappings such as
    // `key:"int8_from_str"` without options; those are still schema names, not
    // secret bytes.
    if !source_key_has_struct_tag_key(source_key) {
        return false;
    }
    let value = value.trim();
    (3..=96).contains(&value.len())
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

fn is_objc_dictionary_key_literal(value: &str, source_key: &str) -> bool {
    // Objective-C collection/KVC APIs use selector fragments such as
    // `objectForKey:@"Host"` and `setObject:... forKey:@"Port"`. The string is
    // a public lookup field name, not credential material, even when the
    // surrounding object stores credentials. Keep this to compact identifier
    // keys under explicit Objective-C selector syntax.
    if !contains_any(
        source_key,
        &[
            "objectForKey",
            "forKey",
            "valueForKey",
            "willChangeValueForKey",
            "didChangeValueForKey",
        ],
    ) {
        return false;
    }
    let value = value
        .trim()
        .trim_start_matches('@')
        .trim_matches(|ch| matches!(ch, '"' | '\''));
    (3..=64).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
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

fn is_source_variable_reference_literal(
    value: &str,
    key_name: &str,
    source_key: &str,
    quoted: bool,
) -> bool {
    // Source code often assigns a sensitive-looking argument from a variable,
    // e.g. `Authorization = l_auth` or `$token = $this->token`. The variable
    // name is not the credential bytes. Keep this to source-shaped left sides
    // and identifier/member-reference syntax; quoted strings such as
    // `password = "hunter2"` still pass through.
    if is_dotted_config_secret_key(source_key, key_name) {
        return false;
    }
    if is_instance_variable_reference_literal(value.trim()) {
        return source_key_has_code_shape(source_key);
    }
    if is_variable_reference_literal(value.trim())
        || is_namespaced_variable_reference_literal(value.trim())
    {
        return source_key_has_code_shape(source_key)
            || key_name_has_sensitive_component(key_name)
            || key_name_indicates_sensitive_material(key_name);
    }
    !quoted
        && source_key_has_reference_shape(source_key)
        && is_plain_source_identifier_reference(value.trim())
}

fn source_key_has_reference_shape(source_key: &str) -> bool {
    let key = source_key.trim();
    key.contains("->")
        || key.contains("::")
        || key.contains('.')
        || key.contains('*')
        || key.contains('[')
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

fn is_instance_variable_reference_literal(value: &str) -> bool {
    let value = value.trim_matches(|ch| matches!(ch, '"' | '\''));
    let Some(rest) = value.strip_prefix('@') else {
        return false;
    };
    is_simple_code_reference_name(rest)
}

fn is_namespaced_variable_reference_literal(value: &str) -> bool {
    let value = value.trim_end_matches('\\').trim_matches('"');
    if !(5..=96).contains(&value.len()) {
        return false;
    }
    let Some(rest) = value.strip_prefix('$') else {
        return false;
    };
    let mut parts = rest.split("::");
    let Some(first) = parts.next() else {
        return false;
    };
    let mut count = 1usize;
    if !is_simple_code_reference_name(first) {
        return false;
    }
    for part in parts {
        count += 1;
        if !is_simple_code_reference_name(part) {
            return false;
        }
    }
    count >= 2
}

fn is_plain_source_identifier_reference(value: &str) -> bool {
    (3..=96).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_shell_parameter_reference_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Shell/YAML snippets often assign secret-looking fields from environment
    // variables: `password=${PASS}` or `KEY=rolling/${APP_NAME}/stable/id`.
    // The variable reference is not the credential bytes. Keep the gate to
    // assignment-like contexts and a shell parameter grammar, not value names.
    if !(source_key_has_code_shape(source_key)
        || is_generic_metadata_key_name(key_name)
        || key_name_has_sensitive_component(key_name))
    {
        return false;
    }
    let value = value.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if !(4..=160).contains(&value.len()) || !value.contains("${") {
        return false;
    }
    value.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'$' | b'{' | b'}')
    }) && contains_shell_parameter_reference(value)
}

fn contains_shell_parameter_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let Some(rel) = value[i..].find("${") else {
            return false;
        };
        let start = i + rel + 2;
        let mut end = start;
        while end < bytes.len() && bytes[end] != b'}' {
            end += 1;
        }
        if is_shell_parameter_name(&value[start..end]) {
            return true;
        }
        i = start;
    }
    false
}

fn is_shell_parameter_name(name: &str) -> bool {
    (2..=64).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn is_runtime_template_reference_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // CI, Helm/Jinja/ERB, and i18n templates can assign sensitive-looking
    // fields from runtime expressions (`password: "{{DB_PASS}}"`,
    // `key: dist-${{ hashFiles(...) }}`, `apiKey: "<%= config.api_key %>"`).
    // The literal is a reference/template, not the credential bytes. Keep this
    // to assignment-shaped contexts and require recognizable template syntax so
    // concrete values such as `password="{{secret123}}"` still detect.
    if !(source_key_has_code_shape(source_key)
        || is_generic_metadata_key_name(key_name)
        || key_name_has_sensitive_component(key_name))
    {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(4..=512).contains(&value.len()) {
        return false;
    }
    contains_mustache_template_reference(value)
        || contains_erb_template_reference(value)
        || contains_percent_brace_template_reference(value)
        || contains_dollar_template_reference(value)
}

fn is_jsonpath_template_selector_literal(value: &str, key_name: &str) -> bool {
    // Query/selector/path fields can store JSONPath-like selectors that point at
    // a secret field (`resources[*]...keys[0].secret`) while the credential is
    // still elsewhere. Require selector syntax plus a runtime template marker;
    // a plain `secret.path.value` string remains detectable.
    if !key_name_indicates_selector_context(key_name) {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(8..=512).contains(&value.len())
        || value.contains("://")
        || value.chars().any(char::is_whitespace)
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'-' | b'[' | b']' | b'*' | b'{' | b'}')
        })
    {
        return false;
    }
    has_jsonpath_selector(value) && contains_mustache_template_reference(value)
}

fn key_name_indicates_selector_context(key_name: &str) -> bool {
    has_identifier_component(key_name, "query")
        || has_identifier_component(key_name, "selector")
        || has_identifier_component(key_name, "jsonpath")
        || has_identifier_component(key_name, "path")
}

fn has_jsonpath_selector(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if bytes[pos] != b'[' {
            pos += 1;
            continue;
        }
        let Some(close_rel) = value[pos + 1..].find(']') else {
            return false;
        };
        let body = &value[pos + 1..pos + 1 + close_rel];
        if body == "*" || (!body.is_empty() && body.bytes().all(|b| b.is_ascii_digit())) {
            return true;
        }
        pos += close_rel + 2;
    }
    false
}

fn contains_mustache_template_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut search = 0usize;
    while search + 1 < bytes.len() {
        let Some(rel) = value[search..].find("{{") else {
            return false;
        };
        let start = search + rel + 2;
        let end = value[start..]
            .find("}}")
            .map_or(value.len(), |offset| start + offset);
        let body = value[start..end].trim();
        if body.is_empty() {
            return true;
        }
        if is_runtime_template_expression_body(body) {
            return true;
        }
        search = start;
    }
    false
}

fn contains_erb_template_reference(value: &str) -> bool {
    let Some(start) = value.find("<%") else {
        return false;
    };
    let body_start = start + 2;
    let end = value[body_start..]
        .find("%>")
        .map_or(value.len(), |offset| body_start + offset);
    let body = value[body_start..end]
        .trim_start_matches('=')
        .trim_start_matches('#')
        .trim();
    body.is_empty() || is_runtime_template_expression_body(body)
}

fn contains_percent_brace_template_reference(value: &str) -> bool {
    let Some(start) = value.find("%{") else {
        return false;
    };
    let body_start = start + 2;
    let end = value[body_start..]
        .find('}')
        .map_or(value.len(), |offset| body_start + offset);
    let body = value[body_start..end].trim();
    !body.is_empty() && is_runtime_template_expression_body(body)
}

fn contains_dollar_template_reference(value: &str) -> bool {
    let Some(start) = value.find("${") else {
        return false;
    };
    let body_start = start + 2;
    let end = value[body_start..]
        .find('}')
        .map_or(value.len(), |offset| body_start + offset);
    let body = value[body_start..end]
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    body.is_empty() || is_runtime_template_expression_body(body)
}

fn is_runtime_template_expression_body(body: &str) -> bool {
    if body.is_empty() || body.len() > 256 {
        return false;
    }
    if body.contains("://") {
        return false;
    }
    let has_template_operator = body.bytes().any(|b| {
        matches!(
            b,
            b'.' | b'|' | b'(' | b')' | b'/' | b'*' | b'\'' | b'"' | b':' | b'-' | b' '
        )
    });
    if has_template_operator {
        return body
            .bytes()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace());
    }
    if is_shell_parameter_name(body) {
        return true;
    }
    let normalized = normalize_key(body);
    !normalized.bytes().any(|b| b.is_ascii_digit())
        && (is_source_secret_name_reference_value(&normalized)
            || is_plain_source_identifier_reference(&normalized))
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

fn is_shell_command_substitution_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Shell completions/config scripts assign keys from command substitutions:
    // `local key=$(__docker_map_key_of_current_option ...)` or
    // `ADMIN_PASSWORD=$(rand_pwd)`. The captured value is the command
    // expression, not the generated key. Do not suppress quoted echo/printf
    // calls carrying a literal secret (`"$(echo hunter2)"`).
    if !(source_key_has_code_shape(source_key)
        || key_name_has_sensitive_component(key_name)
        || is_upper_env_secret_key(source_key))
    {
        return false;
    }
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let Some(body) = value.strip_prefix("$(") else {
        return false;
    };
    let body = body.trim().trim_end_matches(')').trim();
    if !(2..=256).contains(&body.len()) {
        return false;
    }
    let command = body.split_ascii_whitespace().next().unwrap_or(body);
    let rest = body[command.len()..].trim();
    if rest.is_empty()
        && !source_key_has_code_shape(source_key)
        && !is_upper_env_secret_key(source_key)
    {
        return false;
    }
    is_shell_command_name(command) && !shell_literal_argument_looks_secret(body, command)
}

fn is_shell_command_name(command: &str) -> bool {
    let command = command.trim();
    (2..=96).contains(&command.len())
        && command
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'.' | b'/'))
        && command
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':'))
}

fn shell_literal_argument_looks_secret(body: &str, command: &str) -> bool {
    let command_name = command
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    if !matches!(command_name.as_str(), "echo" | "printf") {
        return false;
    }
    let rest = body[command.len()..].trim();
    if rest.is_empty()
        || rest.bytes().any(|b| {
            matches!(
                b,
                b'$' | b'/'
                    | b'\\'
                    | b'|'
                    | b'<'
                    | b'>'
                    | b'*'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
                    | b'\''
                    | b'"'
                    | b'%'
            )
        })
    {
        return false;
    }
    rest.split_ascii_whitespace().any(|part| {
        let part = part.trim_matches(|ch| matches!(ch, ')' | ';' | ','));
        part.len() >= 6
            && part.bytes().any(|b| b.is_ascii_alphabetic())
            && part.bytes().any(|b| b.is_ascii_digit())
    })
}

fn is_shell_command_fragment_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Backtick command substitutions are runtime reads/generators, not stored
    // credential bytes: `APP_PASSWORD=`echo $JSON | jq ...``. Separators inside
    // those commands can also leave tail fragments such as `-f2`` from
    // `cut -d "=" -f2`. Keep literal generators like `echo hunter2` detectable.
    if !(source_key_has_code_shape(source_key)
        || key_name_has_sensitive_component(key_name)
        || is_upper_env_secret_key(source_key))
    {
        return false;
    }
    let value = value.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    is_shell_cut_option_tail_fragment(value, source_key) || is_shell_command_body_literal(value)
}

fn is_shell_cut_option_tail_fragment(value: &str, source_key: &str) -> bool {
    if !(source_key.contains('`') || source_key.contains("$(")) || !source_key.contains("cut") {
        return false;
    }
    let body = value.trim().trim_end_matches(['`', ')']).trim();
    (2..=16).contains(&body.len())
        && body.starts_with('-')
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b' '))
}

fn is_shell_command_body_literal(value: &str) -> bool {
    let body = value.trim().trim_matches('`').trim();
    if !(3..=256).contains(&body.len()) || !has_shell_expression_syntax(body) {
        return false;
    }
    let command = body.split_ascii_whitespace().next().unwrap_or(body);
    is_shell_command_name(command) && !shell_literal_argument_looks_secret(body, command)
}

fn has_shell_expression_syntax(body: &str) -> bool {
    body.contains('|')
        || body.contains('$')
        || body
            .split_ascii_whitespace()
            .skip(1)
            .any(|part| part.starts_with('-') || part.contains('/'))
}

fn is_inline_code_key_value_tail_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Help text commonly documents `key=value` inside backticks. Splitting at
    // `=` leaves `value`` as a fake credential; keep this to generic key
    // context and inline-code syntax.
    if !(is_generic_metadata_key_name(key_name) || key_name_has_sensitive_component(key_name))
        || !source_key.contains('`')
    {
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
        || is_minified_js_expression_fragment(value)
        || is_escaped_format_fragment(value)
        || is_method_chain_suffix_fragment(value)
        || is_incomplete_objc_string_fragment(value)
        || is_ruby_interpolation_fragment(value)
        || is_member_access_tail_fragment(value)
        || is_backtick_command_method_tail_fragment(value)
        || is_html_attribute_binding_fragment(value)
        || is_unary_member_access_fragment(value)
        || is_uppercase_suffix_fragment(value)
        || is_concatenation_tail_fragment(value)
        || is_assembly_register_or_address_fragment(value)
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

fn is_minified_js_expression_fragment(value: &str) -> bool {
    // Minified JavaScript often chains assignments or boolean expressions on a
    // single line. If the parser splits at a nested `key:`/`token:`, the tail can
    // look like a compact credential (`this.x=this.y=0` or `a.b||0`). Require a
    // member access plus operator syntax so ordinary `abc=def`-style values and
    // dotted tokens remain eligible.
    let value = value.trim().trim_end_matches([',', ';', ')', '}']);
    if !(4..=220).contains(&value.len())
        || value.contains("://")
        || value.chars().any(char::is_whitespace)
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'$'
                        | b'.'
                        | b'='
                        | b'!'
                        | b'|'
                        | b'&'
                        | b'?'
                        | b':'
                        | b'('
                        | b')'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b','
                        | b';'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'/'
                        | b'"'
                        | b'\''
                )
        })
    {
        return false;
    }
    let has_member_access = value.contains('.') || value.starts_with("this");
    if !has_member_access {
        return false;
    }
    value.matches('=').count() >= 2
        || value.contains("||")
        || value.contains("&&")
        || value.contains("!=")
        || value.contains("==")
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
    let Some(rest) = value
        .strip_prefix('.')
        .or_else(|| value.strip_prefix(")."))
        .or_else(|| value.trim_start_matches(')').strip_prefix('.'))
    else {
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

fn is_ruby_interpolation_fragment(value: &str) -> bool {
    // Splitting a Ruby string at `auth:`/`password:` inside interpolation can
    // leave `#{Shellwords.escape` or `#{key}_path`. That is executable syntax,
    // not the credential bytes.
    let Some(body) = value.trim().strip_prefix("#{") else {
        return false;
    };
    (2..=120).contains(&body.len())
        && body.bytes().any(|b| b.is_ascii_alphabetic())
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'.' | b':' | b'(' | b')' | b' ' | b'`' | b'}')
        })
}

fn is_member_access_tail_fragment(value: &str) -> bool {
    // Concatenated header builders can split after a sensitive header label:
    // `'PRIVATE-TOKEN: '.$auth['username']` yields `.$auth[`.
    let value = value.trim();
    value.starts_with(".$")
        && (4..=96).contains(&value.len())
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'$' | b'_' | b'[' | b']' | b'\'' | b'"')
        })
}

fn is_backtick_command_method_tail_fragment(value: &str) -> bool {
    // Ruby command interpolation such as `` `heroku auth:whoami`.strip `` may
    // be split at `auth:` and leave the command tail as a fake value.
    let value = value.trim();
    let Some(command) = value.strip_suffix("`.strip") else {
        return false;
    };
    (2..=96).contains(&command.len())
        && command
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':'))
        && command
            .split([':', '/', '.'])
            .next_back()
            .is_some_and(is_shell_command_name)
}

fn is_html_attribute_binding_fragment(value: &str) -> bool {
    // Vue/HTML snippets can split at `passwd` inside attribute bindings,
    // leaving `title="'...` as the captured value.
    let value = value.trim_start();
    (value.starts_with("title=") || value.starts_with(":title="))
        && value.contains(['"', '\''])
        && value.len() <= 160
}

fn is_unary_member_access_fragment(value: &str) -> bool {
    // UI state expressions such as `!radioLUS4U.Checked` are boolean code, not
    // password material.
    let Some(body) = value.trim().strip_prefix('!') else {
        return false;
    };
    (4..=120).contains(&body.len())
        && body.contains('.')
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'$' | b'(' | b')'))
}

fn is_uppercase_suffix_fragment(value: &str) -> bool {
    // Concatenating environment-variable names can leave suffix literals such as
    // `_PASS` or `_FILE`. These are name fragments, not values.
    let value = value.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    (3..=40).contains(&value.len())
        && value.starts_with('_')
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn is_concatenation_tail_fragment(value: &str) -> bool {
    // A key/value parser can split source concatenation such as
    // `key+"="+val` or `field+Operator+" "` at the embedded `=`. Suppress only
    // dangling source-expression tails, not complete mixed secret strings.
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('+') {
        let rest = rest.trim_end_matches([')', ';', ',']);
        return is_plain_source_identifier_reference(rest);
    }
    if !value.ends_with('+') || value.matches('+').count() < 2 {
        return false;
    }
    let body = value.trim_end_matches('+');
    let mut has_source_signal = false;
    let mut part_count = 0usize;
    for part in body.split('+') {
        part_count += 1;
        let part = part.trim();
        if part == r#"" ""# || part == "''" || part == "\"\"" {
            has_source_signal = true;
            continue;
        }
        if part.bytes().any(|byte| byte.is_ascii_uppercase()) {
            has_source_signal = true;
        }
        if !is_plain_source_identifier_reference(part) {
            return false;
        }
    }
    part_count >= 2 && has_source_signal
}

fn is_assembly_register_or_address_fragment(value: &str) -> bool {
    // Assembly templates and generated compiler tests include register names
    // and stack-address fragments in key-like rows. These are machine operands,
    // not credential material.
    let value = value.trim();
    if let Some(register) = value.strip_prefix('%') {
        return (2..=5).contains(&register.len())
            && register.bytes().any(|byte| byte.is_ascii_digit())
            && register.bytes().all(|b| b.is_ascii_alphanumeric());
    }
    let Some(offset) = value
        .strip_suffix("(%rsp)")
        .or_else(|| value.strip_suffix("(%rbp)"))
    else {
        return false;
    };
    (1..=5).contains(&offset.len()) && offset.bytes().all(|b| b.is_ascii_digit())
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

fn is_typed_sql_fragment_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Scala SQL builders commonly declare generic `key` fragments as
    // `SQLSyntax`, e.g. `val key: SQLSyntax = sqls"column_name"`. The quoted
    // text names a SQL fragment, not credential material. Keep this tied to the
    // declared type so `api_key = "..."` and string-typed secrets still detect.
    if !is_generic_metadata_key_name(key_name) {
        return false;
    }
    let Some(type_annotation) = declared_type_annotation(source_key) else {
        return false;
    };
    if normalize_key(type_annotation) != "sqlsyntax" {
        return false;
    }
    let value = value.trim_start();
    value.starts_with("sqls\"") || value.starts_with("sqls'")
}

fn is_public_key_literal(value: &str, key_name: &str) -> bool {
    // OpenSSH public-key values are identifiers/public material. Private keys
    // are handled by the PEM detector; masking public key blobs as KEYED_SECRET
    // makes API responses and fixtures unusably noisy.
    let value = value.trim_start();
    if value.starts_with("ssh-rsa ")
        || value.starts_with("ssh-ed25519 ")
        || value.starts_with("ecdsa-sha2-")
    {
        return true;
    }
    // RFC 5280 SubjectPublicKeyInfo is public key material. DER-encoded SPKI
    // often appears as a bare base64 string in constants named `publicKey`.
    // Require the key name to say public key so arbitrary base64 secrets remain
    // masked by KEYED_SECRET/entropy detectors.
    key_name_indicates_public_key(key_name) && is_der_subject_public_key_info_base64(value)
}

fn key_name_indicates_public_key(key_name: &str) -> bool {
    key_name == "pubkey"
        || key_name == "publickey"
        || has_identifier_phrase(key_name, &["public", "key"])
        || has_identifier_phrase(key_name, &["pub", "key"])
}

fn is_private_key_documentation_placeholder_literal(value: &str, key_name: &str) -> bool {
    // Private-key material has a PEM/base64 envelope. Phrase-shaped values that
    // explicitly say they are dummy/example file contents are documentation or
    // setup placeholders, not key bytes. Keep the gate on private-key slots so
    // ordinary weak passwords/passphrases are not hidden.
    if !key_name_indicates_private_key_slot(key_name) {
        return false;
    }
    let value = value.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if is_pem_ellipsis_placeholder(value) {
        return true;
    }
    if !(8..=180).contains(&value.len())
        || value.contains("-----BEGIN")
        || value.bytes().any(|b| matches!(b, b'\r' | b'\n'))
        || value.split_whitespace().count() < 3
        || !value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || ch.is_ascii_whitespace()
                || matches!(ch, '.' | ',' | '*' | '#' | '-' | '_' | '/')
        })
    {
        return false;
    }
    let normalized = normalize_key(value);
    let parts = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let has_placeholder_marker = parts.iter().any(|part| {
        matches!(
            *part,
            "your" | "dummy" | "placeholder" | "sample" | "example" | "setup" | "here"
        )
    });
    let has_key_file_marker = parts
        .iter()
        .any(|part| matches!(*part, "pem" | "file" | "content"));
    let has_value_marker = parts.contains(&"value");
    has_placeholder_marker && (has_key_file_marker || has_value_marker)
}

fn is_pem_ellipsis_placeholder(value: &str) -> bool {
    // PEM examples sometimes keep only the envelope and replace key bytes with
    // `...`. That is not parseable key material, but a real PEM body should
    // still be detected by the PEM detector and keyed-secret fallback.
    let normalized = value
        .replace("\\\\r\\\\n", "\n")
        .replace("\\\\n", "\n")
        .replace("\\\\r", "\n")
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n");
    let lines = normalized
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 3 {
        return false;
    }
    let [begin, body, end] = [lines[0], lines[1], lines[2]];
    begin.starts_with("-----BEGIN ")
        && begin.ends_with("PRIVATE KEY-----")
        && end.starts_with("-----END ")
        && end.ends_with("PRIVATE KEY-----")
        && body.chars().count() >= 3
        && body.chars().all(|ch| matches!(ch, '.' | '\u{2026}'))
}

fn key_name_indicates_private_key_slot(key_name: &str) -> bool {
    key_name == "private_key"
        || key_name == "privatekey"
        || has_adjacent_identifier_components(key_name, "private", "key")
        || has_adjacent_identifier_components(key_name, "key", "pair")
}

fn is_der_subject_public_key_info_base64(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if !(32..=2048).contains(&value.len())
        || !value.len().is_multiple_of(4)
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return false;
    }
    let Ok(der) = BASE64.decode(value.as_bytes()) else {
        return false;
    };
    der.first() == Some(&0x30) && contains_der_public_key_oid(&der) && der.contains(&0x03)
}

fn contains_der_public_key_oid(der: &[u8]) -> bool {
    const RSA_ENCRYPTION: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];
    const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    const ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
    const X25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E];
    [RSA_ENCRYPTION, EC_PUBLIC_KEY, ED25519, X25519]
        .iter()
        .any(|oid| der.windows(oid.len()).any(|window| window == *oid))
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

fn is_generic_key_identifier_metadata_literal(value: &str, key_name: &str) -> bool {
    // Generic `key` fields also hold public enum/schema identifiers such as
    // `contributor_covenant` or `short_codes`. Require a multi-component
    // identifier and reject secret-bearing components so `key: sk-test-token`
    // and digit-bearing key material stay on the detection path.
    if !is_generic_metadata_key_name(key_name) {
        return false;
    }
    let value = value.trim();
    if !(5..=80).contains(&value.len())
        || value.bytes().any(|b| b.is_ascii_digit())
        || !value.bytes().any(|b| matches!(b, b'_' | b'-'))
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'-'))
    {
        return false;
    }
    let normalized = normalize_key(value);
    let parts = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts.len() >= 2
        && parts.iter().all(|part| {
            !matches!(
                *part,
                "secret" | "password" | "passwd" | "credential" | "token" | "auth" | "private"
            )
        })
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
        || has_identifier_phrase(key_name, &["original", "key"])
        || has_identifier_phrase(key_name, &["public", "key"])
        || has_identifier_phrase(key_name, &["target", "key"])
}

fn is_password_validation_message_literal(value: &str, key_name: &str) -> bool {
    // UI/errors often put validation messages under `password` fields in tests
    // and locale files (`Invalid Password`, `wrong password`). Suppress only
    // short phrase-shaped messages that explicitly contain both a password word
    // and a validation/error word, so real passphrases such as
    // `Correct horse battery staple!` remain detectable.
    if !(has_identifier_component(key_name, "password")
        || has_identifier_component(key_name, "passwd")
        || has_identifier_component(key_name, "passphrase"))
    {
        return false;
    }
    let value = value.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if !(8..=96).contains(&value.len())
        || value.bytes().any(|b| b.is_ascii_digit())
        || !value.chars().all(|ch| {
            ch.is_ascii_alphabetic()
                || ch.is_ascii_whitespace()
                || matches!(ch, '_' | '-' | '.' | ',' | '\'' | '"')
        })
    {
        return false;
    }
    let normalized = normalize_key(value);
    let mut has_password_word = false;
    let mut has_validation_word = false;
    for part in normalized.split('_').filter(|part| !part.is_empty()) {
        has_password_word |= matches!(part, "password" | "passwd" | "passphrase");
        has_validation_word |= matches!(
            part,
            "bad"
                | "blank"
                | "expired"
                | "incorrect"
                | "invalid"
                | "missing"
                | "mismatch"
                | "required"
                | "wrong"
        );
    }
    has_password_word && has_validation_word
}

fn is_password_documentation_literal(value: &str, key_name: &str) -> bool {
    // Provider examples often store human instructions in password slots:
    // `BLUECAT_PASSWORD = "API password"` or
    // `WEDOS_WAPI_PASSWORD = "Password needs to be generated..."`.
    // Suppress only phrase-shaped values that themselves contain a password
    // word. Compact passphrases without that word remain detectable.
    if !key_name_indicates_password_slot(key_name) {
        return false;
    }
    let value = value.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if !(8..=160).contains(&value.len())
        || value.bytes().any(|b| b.is_ascii_digit())
        || value.split_whitespace().count() < 2
        || !value.chars().all(|ch| {
            ch.is_ascii_alphabetic()
                || ch.is_ascii_whitespace()
                || matches!(ch, '.' | ',' | '\'' | '"' | '-' | '/')
        })
    {
        return false;
    }
    normalize_key(value)
        .split('_')
        .any(|part| matches!(part, "pass" | "password" | "passwd" | "passphrase"))
}

fn is_sensitive_slot_documentation_literal(value: &str, key_name: &str) -> bool {
    // Provider env-var catalogs sometimes put the help text in the value column:
    // `API_KEY = "API key (only with ...)"` or
    // `CLIENT_SECRET = "Client secret, managed by ..."`. Those values describe
    // the field, not reusable material. Require prose shape plus both a
    // credential word and a documentation word so compact secrets and passphrases
    // stay detectable.
    if key_name_indicates_password_slot(key_name)
        || !(key_name_indicates_sensitive_material(key_name)
            || has_identifier_component(key_name, "api")
            || has_identifier_component(key_name, "auth")
            || has_identifier_component(key_name, "oauth"))
    {
        return false;
    }
    let value = value.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if !(8..=260).contains(&value.len())
        || value.split_whitespace().count() < 2
        || value.bytes().filter(|b| b.is_ascii_alphabetic()).count() < 6
    {
        return false;
    }
    if value.bytes().any(|b| b < 0x20 && b != b'\t') {
        return false;
    }
    let normalized = normalize_key(value);
    let mut has_credential_word = false;
    let mut has_documentation_word =
        value.contains("://") || value.contains('`') || value.contains('<') || value.contains('>');
    for part in normalized.split('_').filter(|part| !part.is_empty()) {
        has_credential_word |= matches!(
            part,
            "api"
                | "auth"
                | "authentication"
                | "client"
                | "credential"
                | "credentials"
                | "key"
                | "password"
                | "secret"
                | "token"
        );
        has_documentation_word |= matches!(
            part,
            "admin"
                | "alias"
                | "defined"
                | "disable"
                | "endpoint"
                | "field"
                | "file"
                | "generated"
                | "interface"
                | "managed"
                | "mode"
                | "name"
                | "only"
                | "payload"
                | "related"
                | "required"
                | "supported"
                | "unset"
        );
    }
    has_credential_word && has_documentation_word
}

fn key_name_indicates_password_slot(key_name: &str) -> bool {
    key_name == "pass"
        || key_name.ends_with("_pass")
        || has_password_slot_component(key_name)
        || has_identifier_component(key_name, "password")
        || has_identifier_component(key_name, "passwd")
        || has_identifier_component(key_name, "passphrase")
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
        || is_provisioner_secret_resource_key(key_name)
        || matches!(
            key_name,
            "secretname" | "secretnamespace" | "secrettype" | "secretref" | "secretreference"
        )
}

fn is_provisioner_secret_resource_key(key_name: &str) -> bool {
    // Storage provisioner config frequently uses fields like
    // `rbd_provisioner_user_secret` to point at a Kubernetes Secret object. The
    // key shape says "secret resource name"; actual secret material fields
    // such as `client_secret` do not include the provisioner component.
    has_identifier_component(key_name, "provisioner") && key_name.ends_with("_secret")
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
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(*b, b'-' | b'_'))
        {
            return false;
        }
        has_name_char |= bytes.iter().any(|b| b.is_ascii_lowercase());
        has_separator |= bytes.contains(&b'-') || bytes.contains(&b'_');
    }
    has_name_char && (has_separator || value.contains('/') || value.contains('.'))
}

fn is_web_credentials_mode_literal(value: &str, key_name: &str) -> bool {
    // The Fetch API `credentials` field is an enum controlling cookie/auth
    // inclusion behavior, not credential material. Keep this to the exact
    // plural field name and standard enum values so singular `credential`
    // assignments and arbitrary secrets still flow through.
    if key_name != "credentials" && !has_identifier_component(key_name, "credentials") {
        return false;
    }
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "same-origin" | "include" | "omit"
    )
}

fn is_package_dependency_coordinate_literal(value: &str, source_key: &str) -> bool {
    // Maven/Gradle coordinates are `group:artifact:version`. The key/value
    // scanner sees the first colon and may treat `com.google.auth` as an auth
    // key. Suppress only when the left side is a dotted package group and the
    // right side is an artifact plus a version range.
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let Some((artifact, version)) = value.rsplit_once(':') else {
        return false;
    };
    is_package_group_prefix(source_key)
        && is_package_artifact_name(artifact)
        && is_semverish_version_literal(version)
}

fn is_package_dependency_version_literal(value: &str, source_key: &str) -> bool {
    // Composer/npm lockfiles use package names as JSON keys. Names such as
    // `tymon/jwt-auth` and `phpunit/php-token-stream` contain auth/token words,
    // but the value is a dependency constraint, not credential material.
    is_package_name_literal(source_key) && is_semverish_version_literal(value)
}

fn is_package_name_literal(source_key: &str) -> bool {
    let key = source_key
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let (scope, name) = if let Some(rest) = key.strip_prefix('@') {
        let Some((scope, name)) = rest.split_once('/') else {
            return false;
        };
        (Some(scope), name)
    } else {
        let Some((scope, name)) = key.split_once('/') else {
            return false;
        };
        (Some(scope), name)
    };
    scope.is_some_and(is_package_name_segment) && is_package_name_segment(name)
}

fn is_package_name_segment(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn is_package_group_prefix(source_key: &str) -> bool {
    let Some(candidate) = source_key
        .split_whitespace()
        .next_back()
        .map(|part| part.trim_matches(|ch| matches!(ch, '"' | '\'' | '`')))
    else {
        return false;
    };
    let parts = candidate.split('.').collect::<Vec<_>>();
    parts.len() >= 2
        && parts.iter().all(|part| {
            (1..=64).contains(&part.len())
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && part.bytes().any(|b| b.is_ascii_lowercase())
        })
}

fn is_package_artifact_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().any(|b| b.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn is_semverish_version_literal(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 96 {
        return false;
    }
    let mut saw_digit = false;
    let mut saw_dot = false;
    for token in value.split_whitespace() {
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

fn is_password_reset_duration_literal(value: &str, key_name: &str) -> bool {
    // Framework config often stores reset-password expiry windows as duration
    // expressions (`reset_password_within = 6.hours`). The duration is policy
    // metadata, not the password. Require reset/within wording in the key so a
    // literal `password = 6.hours` remains visible.
    has_identifier_component(key_name, "password")
        && (has_identifier_component(key_name, "within")
            || has_identifier_component(key_name, "expiry")
            || has_identifier_component(key_name, "expiration")
            || has_identifier_component(key_name, "ttl"))
        && key_name.contains("reset")
        && is_duration_expression_literal(value)
}

fn is_duration_expression_literal(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let Some((amount, unit)) = value.split_once('.') else {
        return false;
    };
    !amount.is_empty()
        && amount.bytes().all(|b| b.is_ascii_digit())
        && matches!(
            unit,
            "second"
                | "seconds"
                | "minute"
                | "minutes"
                | "hour"
                | "hours"
                | "day"
                | "days"
                | "week"
                | "weeks"
        )
}

fn is_source_concatenation_template_literal(value: &str) -> bool {
    // Source snippets can build JSON credential fixtures with runtime
    // expressions: `"private_key_id": "` + UUID.randomUUID() or a PEM wrapper
    // around `encodedKey`. Those fragments are templates; the runtime value is
    // not present in the file. Require explicit concatenation syntax so base64
    // values containing `+` are unaffected.
    let value = value.trim();
    if !value.contains('+') || value.matches('+').count() < 2 {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    contains_any(&lower, &["uuid.", "randomuuid", ".tostring()"])
        || (value.contains("-----BEGIN ")
            && value.contains("-----END ")
            && value
                .split('+')
                .any(|part| is_code_reference_segment(part.trim())))
}

fn is_analysis_token_result_literal(
    text: &str,
    line_end: usize,
    key_name: &str,
    value: &str,
) -> bool {
    // Search/analyzer docs emit objects like
    // `{ "token": "quick", "start_offset": 0, ... }`. Here `token` means a
    // parsed word, not an auth token. Require the neighboring analyzer metadata
    // fields in the same small window so ordinary `token: abcde` still masks.
    if key_name != "token" || !is_plain_analyzer_token_text(value) {
        return false;
    }
    let after = &text[line_end..];
    let mut window_end = after.len().min(512);
    while !after.is_char_boundary(window_end) {
        window_end -= 1;
    }
    let window = &after[..window_end];
    contains_any(window, &["\"start_offset\"", "\"end_offset\""])
        && contains_any(window, &["\"position\"", "\"type\""])
}

fn is_plain_analyzer_token_text(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ','));
    (1..=64).contains(&value.len())
        && !value.chars().any(|ch| ch.is_ascii_digit())
        && value
            .chars()
            .all(|ch| ch.is_alphabetic() || matches!(ch, '_' | '-'))
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
                | "secrets"
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
                | "apitoken"
                | "refresh_token"
                | "id_token"
                | "bearer_token"
                | "session_token"
                | "token"
        ) || name.ends_with("_token")
            || name.ends_with("_apitoken");
    }
    matches!(
        name,
        "api_key"
            | "apikey"
            | "oauth_key"
            | "access_key"
            | "account_key"
            | "client_secret"
            | "pass"
            | "password"
            | "passwd"
            | "pwd"
            | "passphrase"
            | "secret"
            | "signing_secret"
            | "webhook_secret"
            | "shared_secret"
            | "credential"
    ) || has_password_slot_component(name)
        || name.ends_with("_password")
        || has_identifier_phrase(name, &["password", "confirmation"])
        || has_identifier_phrase(name, &["password", "confirm"])
        || name.ends_with("_pass")
        || name.ends_with("_passwd")
        || name.ends_with("_pwd")
        || name.ends_with("_passphrase")
}

fn key_context_allows_low_entropy_literal(key_name: &str, source_key: &str, kind: KeyKind) -> bool {
    if key_allows_low_entropy_literal(key_name, kind)
        || is_qualified_low_entropy_material_slot(key_name, kind)
        || compact_key_context_allows_low_entropy_literal(key_name, kind)
    {
        return true;
    }
    let source_name = normalize_identifier(strip_assignment_comment_prefix(source_key));
    !source_name.is_empty()
        && source_name != key_name
        && (key_allows_low_entropy_literal(&source_name, kind)
            || is_qualified_low_entropy_material_slot(&source_name, kind)
            || compact_key_context_allows_low_entropy_literal(&source_name, kind))
}

fn has_password_slot_component(name: &str) -> bool {
    name.split('_').any(is_numbered_password_component)
}

fn is_numbered_password_component(component: &str) -> bool {
    let Some(rest) = component.strip_prefix("password") else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

fn compact_key_context_allows_low_entropy_literal(name: &str, kind: KeyKind) -> bool {
    let compact = name.replace('_', "");
    if compact.len() < 4 {
        return false;
    }
    if matches!(kind, KeyKind::Token) {
        return matches!(
            compact.as_str(),
            "authorization"
                | "authtoken"
                | "accesstoken"
                | "apitoken"
                | "refreshtoken"
                | "idtoken"
                | "bearertoken"
                | "sessiontoken"
                | "token"
        ) || compact.ends_with("token");
    }
    matches!(
        compact.as_str(),
        "apikey"
            | "oauthkey"
            | "accesskey"
            | "accountkey"
            | "clientsecret"
            | "password"
            | "passwd"
            | "pwd"
            | "passphrase"
            | "secret"
            | "signingsecret"
            | "webhooksecret"
            | "sharedsecret"
            | "credential"
    ) || is_numbered_password_component(&compact)
        || compact.ends_with("password")
        || compact.ends_with("passwd")
        || compact.ends_with("passphrase")
        || compact.ends_with("secret")
        || compact.ends_with("credential")
        || compact.ends_with("apikey")
        || compact.ends_with("oauthkey")
        || compact.ends_with("accesskey")
        || compact.ends_with("accountkey")
        || compact.ends_with("keypass")
}

fn is_config_slot_low_entropy_literal(value: &str, key_name: &str, source_key: &str) -> bool {
    // Env/config files often use service-qualified secret keys with deliberately
    // weak sample values: `SMTP_PASSWORD=abcdef` or
    // `prod.db.default.password="abcdef"`. Treat only compact alphabetic
    // values in env/dotted-config key slots as credentials; prose labels,
    // type annotations, and source variables stay rejected.
    is_compact_alpha_literal(value) && is_config_secret_slot_key(key_name, source_key)
}

fn is_explicit_slot_low_entropy_literal(value: &str, key_name: &str, kind: KeyKind) -> bool {
    // Plain YAML/TOML/shell snippets often leave low-entropy sample credentials
    // unquoted (`admin_password: abcdef`). Once the key name explicitly names
    // material and the value survived source/prose suppressors, the slot is
    // stronger evidence than entropy alone.
    if is_exact_password_low_entropy_slot(key_name, kind) {
        return is_lowercase_compact_alpha_literal(value);
    }
    is_compact_alpha_literal(value) && is_qualified_low_entropy_material_slot(key_name, kind)
}

fn is_exact_password_low_entropy_slot(key_name: &str, kind: KeyKind) -> bool {
    // Plain config files commonly use the exact key `password` with short
    // generated values. Numbered form slots (`password1`, `new_password2`) are
    // the same material field in web forms; require the number to be attached
    // to one password component so `passwordless` remains metadata.
    if matches!(kind, KeyKind::Token) {
        return false;
    }
    matches!(
        key_name,
        "pass" | "password" | "passwd" | "pwd" | "passphrase"
    ) || has_password_slot_component(key_name)
}

fn is_qualified_low_entropy_material_slot(key_name: &str, kind: KeyKind) -> bool {
    if matches!(kind, KeyKind::Token) {
        return key_allows_low_entropy_literal(key_name, kind) && key_name.contains('_');
    }
    has_password_slot_component(key_name)
        || key_name.ends_with("_password")
        || key_name.ends_with("_pass")
        || key_name.ends_with("_passwd")
        || key_name.ends_with("_pwd")
        || key_name.ends_with("_passphrase")
        || key_name.ends_with("_secret")
        || key_name.ends_with("_credential")
        || key_name.ends_with("_api_key")
        || key_name.ends_with("_oauth_key")
        || key_name.ends_with("_access_key")
        || key_name.ends_with("_account_key")
}

fn is_compact_alpha_literal(value: &str) -> bool {
    let value = value.trim();
    (5..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_quoted_low_entropy_literal_shape(value: &str) -> bool {
    let value = value.trim();
    (4..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_lowercase_compact_alpha_literal(value: &str) -> bool {
    let value = value.trim();
    (5..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_lowercase())
}

fn is_config_secret_slot_key(key_name: &str, source_key: &str) -> bool {
    let source_key = source_key.trim();
    is_upper_env_secret_key(source_key) || is_dotted_config_secret_key(source_key, key_name)
}

fn is_dotted_config_secret_key(source_key: &str, key_name: &str) -> bool {
    let source_key = source_key.trim();
    source_key.matches('.').count() >= 2
        && qualified_low_entropy_secret_key_name(key_name)
        && source_key.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'-')
                || matches!(b, b'"' | b'\'' | b'`')
        })
}

fn is_upper_env_secret_key(source_key: &str) -> bool {
    let source_key = strip_assignment_comment_prefix(source_key);
    let tokens = source_key.split_whitespace().collect::<Vec<_>>();
    if tokens.len() > 1
        && !tokens[..tokens.len() - 1]
            .iter()
            .any(|token| is_env_assignment_prefix(token))
    {
        return false;
    }
    let candidate = tokens
        .last()
        .copied()
        .unwrap_or(source_key)
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    let candidate = candidate.strip_prefix("-e").unwrap_or(candidate).trim();
    let bytes = candidate.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().any(u8::is_ascii_alphabetic)
        || !bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    {
        return false;
    }
    let normalized = normalize_key(candidate);
    normalized == "pass"
        || normalized.ends_with("_pass")
        || normalized.contains("_pass_")
        || normalized.contains("password")
        || normalized.contains("passwd")
        || normalized.contains("passphrase")
        || normalized.contains("secret")
        || normalized.contains("credential")
}

fn is_upper_env_compact_secret_identifier(value: &str, key_name: &str, source_key: &str) -> bool {
    // Source identifiers and env payloads can both look like lowercase
    // alphanumeric words. A shell/env assignment with an ALL_CAPS sensitive key
    // is stronger local evidence than a source identifier reference, so recover
    // long compact values here without widening ordinary `foo_secret = var123`.
    if !is_compact_env_secret_material(value) || !is_upper_env_material_key(source_key, key_name) {
        return false;
    }
    true
}

fn is_compact_env_secret_material(value: &str) -> bool {
    let value = value.trim();
    let bytes = value.as_bytes();
    ((16..=96).contains(&bytes.len())
        && bytes.iter().any(u8::is_ascii_lowercase)
        && bytes.iter().any(u8::is_ascii_digit)
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
        || ((16..=32).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_digit))
}

fn is_upper_env_material_key(source_key: &str, key_name: &str) -> bool {
    let Some(candidate) = upper_env_key_candidate(source_key) else {
        return false;
    };
    if !is_upper_env_identifier(candidate) {
        return false;
    }
    let normalized = normalize_key(candidate);
    if normalized.is_empty() || is_explicitly_non_sensitive_key(&normalized) {
        return false;
    }
    is_upper_env_secret_key(source_key)
        || matches!(
            normalized.as_str(),
            "key" | "api_key" | "apikey" | "access_key"
        )
        || normalized.ends_with("_key")
        || normalized.contains("_key_")
        || key_name.ends_with("_key")
        || key_name.contains("_key_")
}

fn upper_env_key_candidate(source_key: &str) -> Option<&str> {
    let source_key = strip_assignment_comment_prefix(source_key);
    let tokens = source_key.split_whitespace().collect::<Vec<_>>();
    if tokens.len() > 1
        && !tokens[..tokens.len() - 1]
            .iter()
            .any(|token| is_env_assignment_prefix(token))
    {
        return None;
    }
    let candidate = tokens
        .last()
        .copied()
        .unwrap_or(source_key)
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    Some(candidate.strip_prefix("-e").unwrap_or(candidate).trim())
}

fn strip_assignment_comment_prefix(source_key: &str) -> &str {
    let source_key = source_key.trim();
    if let Some(rest) = source_key.strip_prefix('#') {
        return rest.trim_start();
    }
    if let Some(rest) = source_key.strip_prefix("//") {
        return rest.trim_start();
    }
    source_key
}

fn is_upper_env_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.iter().any(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn is_env_assignment_prefix(token: &str) -> bool {
    matches_ignore_ascii_case(token, &["export", "env", "arg", "-e", "--env"])
        || token.eq_ignore_ascii_case("config:set")
}

fn qualified_low_entropy_secret_key_name(name: &str) -> bool {
    name == "pass"
        || name.ends_with("_pass")
        || name.ends_with("_password")
        || name.ends_with("_passwd")
        || name.ends_with("_pwd")
        || name.ends_with("_passphrase")
        || name.ends_with("_secret")
        || name.ends_with("_credential")
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

fn is_salt_key_name(name: &str) -> bool {
    has_identifier_component(name, "salt") && !has_material_metadata_modifier(name)
}

fn is_nonce_key_name(name: &str) -> bool {
    has_identifier_component(name, "nonce") && !has_material_metadata_modifier(name)
}

fn has_material_metadata_modifier(name: &str) -> bool {
    name.split('_').any(|part| {
        matches!(
            part,
            "bits"
                | "byte"
                | "bytes"
                | "count"
                | "counter"
                | "default"
                | "index"
                | "len"
                | "length"
                | "limit"
                | "max"
                | "maximum"
                | "min"
                | "minimum"
                | "round"
                | "rounds"
                | "size"
                | "ttl"
                | "version"
        )
    })
}

fn has_identifier_component(name: &str, component: &str) -> bool {
    name.split('_').any(|part| part == component)
}

fn has_adjacent_identifier_components(name: &str, first: &str, second: &str) -> bool {
    let mut prev = "";
    for part in name.split('_').filter(|part| !part.is_empty()) {
        if prev == first && part == second {
            return true;
        }
        prev = part;
    }
    false
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
        assert!(has(
            "Ctrl.hexkey = hexkey:bea20b4e75a538b87d7cb48b23550e1be7946919db963f08",
            "hexkey:bea20b4e75a538b87d7cb48b23550e1be7946919db963f08"
        ));
        assert!(has(
            "Ctrl.hexsecret = hexsecret:ce84582f98ee04c6df3a6dff132c28e1ba9f16b8628ff0c0",
            "hexsecret:ce84582f98ee04c6df3a6dff132c28e1ba9f16b8628ff0c0"
        ));
        assert!(has(
            "Ctrl.hexpass = hexpass:88476859103f8069",
            "hexpass:88476859103f8069"
        ));
        assert!(has(
            "Ctrl.IKM = hexkey:af6b5b03b2ff84409ee3b1a8c608679bf7a27c21",
            "hexkey:af6b5b03b2ff84409ee3b1a8c608679bf7a27c21"
        ));
        assert!(has(
            "{ cmd => [qw{openssl kdf -keylen 16 -mac HMAC -digest SHA256 -kdfopt hexkey:d83a244d858166c3b26f63ce5ae6 -kdfopt hexinfo:348a37a27ef1282f5f020dcc -kdfopt hexsalt:1068463fbe30b63de48cfbec02eb3f38 SSKDF}]",
            "hexkey:d83a244d858166c3b26f63ce5ae6"
        ));
        let long_hex_secret = "48af2ef18e60f281bd52efddd112714c41f20056e172cca2fb1e8adb375649f39753302e5c64bbacc8d3da0234b2db9f71a25e2e12d6236607b6b2b888f36de44f4a";
        assert!(has(
            &format!("Ctrl.hexsecret = hexsecret:{long_hex_secret}"),
            &format!("hexsecret:{long_hex_secret}")
        ));
        assert!(has("-kdfopt hexkey:f19b759b190126", "f19b759b190126"));
        assert!(has("Ctrl.hexsalt = hexsalt:2c86362d", "2c86362d"));
        assert!(has(
            "-pkeyopt hexseed:867386122b455df74b29af9692a96f",
            "hexseed:867386122b455df74b29af9692a96f"
        ));
        assert!(has(
            "byte Key128[16]={0x7a,0x8c,0x51,0x86,0x68,0xac,0xf5,0xe0,0xdd,0xe6,0x07,0x21,0x66,0xae,0x6d,0x8f};",
            "0x7a,0x8c,0x51,0x86,0x68,0xac,0xf5,0xe0,0xdd,0xe6,0x07,0x21,0x66,0xae,0x6d,0x8f"
        ));
        assert!(has(
            "unsigned char session_key[24] = { 0x2e, 0x49, 0xd5, 0xa0, 0xeb, 0x0f, 0x02, 0x05, 0xb6, 0x41, 0xc1, 0x1f, 0x09, 0x82, 0x77, 0xa5, 0x54, 0xc6, 0xfc, 0xf1, 0x55, 0x5e, 0x7a, 0x7d };",
            "0x2e, 0x49, 0xd5, 0xa0, 0xeb, 0x0f, 0x02, 0x05, 0xb6, 0x41, 0xc1, 0x1f, 0x09, 0x82, 0x77, 0xa5, 0x54, 0xc6, 0xfc, 0xf1, 0x55, 0x5e, 0x7a, 0x7d"
        ));
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
        assert!(has(
            r#"const string authCode = "b18dc90098";"#,
            "b18dc90098"
        ));
        assert!(has(
            r#"final OAuth2AccessToken accessToken = new OAuth2AccessToken("k6wmh.435gxdn512994384e9e0a6h796d1i");"#,
            "k6wmh.435gxdn512994384e9e0a6h796d1i"
        ));
        assert!(has(
            r#"resty.SetAuthToken("DA916517168A7A2FBB23AA74F563E75CDE401138729A6C2BAD35BB94C568C33D");"#,
            "DA916517168A7A2FBB23AA74F563E75CDE401138729A6C2BAD35BB94C568C33D"
        ));
        assert!(has(
            r#"const secretKey = createSecretKey(Buffer.from('4d243dd6e4dc273d943d276d15485b66036a68fe2df85f508f474a5df03f22d1', 'hex'));"#,
            "4d243dd6e4dc273d943d276d15485b66036a68fe2df85f508f474a5df03f22d1"
        ));
        assert!(!has(
            r#"await auth.verifyAccessToken(validToken, { issuer: 'someonelse' });"#,
            "someonelse"
        ));
        assert!(has(r#"if ($auth['password'] === 'pyicn4') {"#, "pyicn4"));
        assert!(has(r#"assert cfg['password'] == 'phdown'"#, "phdown"));
        assert!(has(
            r#"if (username == "slowdive") and (password == "uwprbkfiw"):"#,
            "uwprbkfiw"
        ));
        assert!(!has(
            r#"if (username == "slowdive") and (password == "uwprbkfiw"):"#,
            "slowdive"
        ));
        assert!(!has(r#"token == "invalid_token""#, "invalid_token"));
        assert!(!has(r#"if (typeof password === "string") {"#, "string"));
        assert!(!has(r#"if (typeof password === "function") {"#, "function"));
        assert!(!has(r#"if (key === "v-text") {"#, "v-text"));
        assert!(!has(
            r#"if (auth_method == "gssapi-with-mic") {"#,
            "gssapi-with-mic"
        ));
        assert!(!has(
            r#"if (request.headers.token !== "unicorn") {"#,
            "unicorn"
        ));
        assert!(has(
            r#"assert token == "25320273898820##29764505m00czd7fg38107712t046dp812sjt0cc""#,
            "25320273898820##29764505m00czd7fg38107712t046dp812sjt0cc"
        ));
        assert!(has(r#"password = "pass""#, "pass"));
        assert!(has(r#"password = "secret""#, "secret"));
        assert!(has(r#"password = "letmein123""#, "letmein123"));
        assert!(has(r#"password = "0xC000006A""#, "0xC000006A"));
        assert!(has(r#"password = "0xFFFFFFFF""#, "0xFFFFFFFF"));
        assert!(has(r#"api_key="--real-secret-123""#, "--real-secret-123"));
        assert!(has(
            r#"private const string ApiKey = "abc12345";"#,
            "abc12345"
        ));
        assert!(has("api_key: Abc123Secret", "Abc123Secret"));
        assert!(has("api_key=Abc-2048", "Abc-2048"));
        assert!(has(
            r#"const string CONSUMER_KEY = "prod_consumer_key_2026";"#,
            "prod_consumer_key_2026"
        ));
        assert!(has(r#"password="{{secret123}}""#, "{{secret123}}"));
        assert!(has(
            r#"password="redis://:secret@localhost:6379/1""#,
            "redis://:secret@localhost:6379/1"
        ));
        assert!(has("otp=100482 expires soon", "100482"));
        assert!(has("verification_code=100482", "100482"));
        assert!(has(
            "otp = ROTP::TOTP.new('JBSWY3DPEHPK3PXP')",
            "JBSWY3DPEHPK3PXP"
        ));
        assert!(has(
            "otp = ROTP::HOTP.new('JBSWY3DPEHPK3PXP', counter: 7)",
            "JBSWY3DPEHPK3PXP"
        ));
        assert!(has("totp_secret: JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"));
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
        assert!(has(r#"password = Some("owlknh")"#, "owlknh"));
        assert!(has(
            r#"PASSWORD = os.environ.get("PASSWORD") or "nx33zje""#,
            "nx33zje"
        ));
        assert!(has(r#"password_confirmation: "rikufkoui""#, "rikufkoui"));
        assert!(has(
            r#"fill_in :signup_password_confirmation, with: "hvokal""#,
            "hvokal"
        ));
        assert!(has(
            r#"var newCredential = new GitCredential("alice", "frhkcwjt");"#,
            "frhkcwjt"
        ));
        assert!(has(r#"["password"] = "alpha12345""#, "alpha12345"));
        assert!(has("admin_password: alphabetic", "alphabetic"));
        assert!(has("password: zling", "zling"));
        assert!(has("password: secret", "secret"));
        assert!(has("passwd: abcde", "abcde"));
        assert!(has("EXOSCALE_API_KEY=alphabeticsecret", "alphabeticsecret"));
        assert!(has(
            r#""Apitoken": "{\"nonce\":\"ok\",\"token\":\"abc123456789\"}""#,
            r#"{\"nonce\":\"ok\",\"token\":\"abc123456789\"}"#
        ));
        assert!(has("Salt = 6D80AE51823B457A", "6D80AE51823B457A"));
        assert!(has(
            r#"salt: "2G7ZwuppkK7gpuSd8VWwTF""#,
            "2G7ZwuppkK7gpuSd8VWwTF"
        ));
        assert!(has(r#"nonce="4811859511""#, "4811859511"));
        assert!(has(
            r#"nonce="AdWNR7IiDBoR2AGjOiDTsgtQjCRQrnr1y8LiHd6XIJY""#,
            "AdWNR7IiDBoR2AGjOiDTsgtQjCRQrnr1y8LiHd6XIJY"
        ));
        assert!(has(
            r#"private final byte[] NONCE = "eznu-EMEPG""#,
            "eznu-EMEPG"
        ));
        assert!(has(
            r#"private const string CertificatePassword = "VozkqqWcexxxle";"#,
            "VozkqqWcexxxle"
        ));
        assert!(has(
            r#"const string testPassword = "vqemxShhe";"#,
            "vqemxShhe"
        ));
        assert!(has(
            r#"expected_password = "helloworld1234""#,
            "helloworld1234"
        ));
        assert!(has(r#"api_token = Some("tok-12345")"#, "tok-12345"));
        assert!(has(
            r#"authorization: 'Basic YWxpY2U6cGEzcw=='"#,
            "YWxpY2U6cGEzcw=="
        ));
        assert!(has(
            r#"headers = {"Authorization": "Basic YWxpY2U6cGEzcw=="}"#,
            "YWxpY2U6cGEzcw=="
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
        assert!(has("SMTP_PASSWORD=dbynbelpgliq", "dbynbelpgliq"));
        assert!(has("GRAPHITE_PASS=rwwjfwpb", "rwwjfwpb"));
        assert!(has(r#"APIPassword: "ocuegu""#, "ocuegu"));
        assert!(has(r#"config.APIPassword = "khhuvfuy""#, "khhuvfuy"));
        assert!(has(
            r#"EnvClientSecret: "xitnwuihawkrefsbvrqldbqgpjojntrnxspwvhuzeedz""#,
            "xitnwuihawkrefsbvrqldbqgpjojntrnxspwvhuzeedz"
        ));
        assert!(has(
            "OVH_APPLICATION_KEY=6502241089672483",
            "6502241089672483"
        ));
        assert!(has(
            "# AUTH_GITHUB_ORG_CLIENT_SECRET=85k4p0i05w7k718rp2t2nu07x1s1p5i0xzhjk2860",
            "85k4p0i05w7k718rp2t2nu07x1s1p5i0xzhjk2860"
        ));
        assert!(has(
            "# GITHUB_ENTERPRISE_ORG_KEY=mdrzfpyodu7do894h296m5",
            "mdrzfpyodu7do894h296m5"
        ));
        assert!(has(
            "GITHUB_ENTERPRISE_ORG_SECRET=vyqyswzeoedeatllsv1edmnib86q31pj2362293497",
            "vyqyswzeoedeatllsv1edmnib86q31pj2362293497"
        ));
        assert!(has(r#"const string proxyPass = "czplsfj";"#, "czplsfj"));
        assert!(has(r#"prod.db.default.password="gecrpy""#, "gecrpy"));
        assert!(has(r#"APP_WEBHOOK_SECRET="abcdefghijkl""#, "abcdefghijkl"));
        assert!(has(
            r#"const PASSWORD: string = "helloworld1234";"#,
            "helloworld1234"
        ));
        assert!(has(
            r#"const PASSWORDS: string[] = "helloworld1234";"#,
            "helloworld1234"
        ));
        assert!(has(
            r#"let apiToken: Array<string> = "abc12345";"#,
            "abc12345"
        ));
        assert!(has(
            r#"const PASSWORD: Record<string, string> = "helloworld1234";"#,
            "helloworld1234"
        ));
        assert!(has(
            r#"tokenValue := "opu1hymphgupryt72ryrdwkmnncvj4gxty10uab32uf9yh32khh98i""#,
            "opu1hymphgupryt72ryrdwkmnncvj4gxty10uab32uf9yh32khh98i"
        ));
        assert!(has(r#"passwordValue := "hunter2""#, "hunter2"));
        assert!(has(
            "OAuth app client_secret 'tenant-7-trial'",
            "tenant-7-trial"
        ));
        assert!(has(r#"credential: "hunter2""#, "hunter2"));
        assert!(has(r#"token: "quick-token-123""#, "quick-token-123"));
        assert!(has(r#"password = "6.hours""#, "6.hours"));
        assert!(has(r#"password1: "munpsmt""#, "munpsmt"));
        assert!(has(r#"new_password2: "kmyhawmjaydc""#, "kmyhawmjaydc"));
    }

    #[test]
    fn rejects_natural_language_and_benign_counters() {
        for raw in [
            "secret capability",
            "token budget",
            "api design",
            "password field docs",
            r#"when(testTerminal.readPassword("password: ")).thenReturn("password");"#,
            r#"DescribeSecret("prod/database");"#,
            "byte Block128[16]={0x7a,0x8c,0x51,0x86,0x68,0xac,0xf5,0xe0,0xdd,0xe6,0x07,0x21,0x66,0xae,0x6d,0x8f};",
            r#"natural language such as "secret capability" or "token budget"."#,
            r#"The secret "capability" mode is documented here."#,
            "secret: capability",
            "hotpink: 16738740,",
            "token_budget=30000",
            "public_token_label=docs",
            "# password field docs",
            "PUBLIC_KEY=abc1234567890123",
            "PUBLIC_KEY=1234567890123456",
            "port=5432 workers=4 timeout_ms=30000 status=200",
            "compass=abcdef",
            "Authorization: Bearer docs",
            r#"authorization: "Basic docs""#,
            r#"authorization: "ApiKey docs""#,
            "jwt_like=aaa.bbb.ccc",
            "Authorization: Basic login_and_password_removed",
            r#"[('Vary', 'Accept, Authorization, Cookie, X-GitHub-OTP'), ('ETag', 'W/"605a3ce7e4fb2cf76f450b75b1efd423"')]"#,
            r#""description": "Use `Authorization` header.\n\n> Authorization: Bearer abc123-EXAMPLE the `Authorization` header is required.""#,
            "repeat_password: Powtórz hasło",
            "confirm_password: Potwierdź moje konto",
            r#""private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n""#,
            r#"string key = CreateKey("contoso");"#,
            r#"SetKey("fieldName")"#,
            r#"fill_in :password_label, with: "Password""#,
            r#"access_token = process.env.ACCESS_TOKEN || "token1""#,
            r#"token: "api_key""#,
            r#"password: "api_password""#,
            r#"@user = create_user(password: @password, password_confirmation: @password)"#,
            "DontExpirePassword = 0x00000200,",
            "#   AES-bits-CBC:key:IV/ciphertext':plaintext:ciphertext:encdec",
            "Key = RSA-PSS:RSA-PSS-DEFAULT",
            "Key = RSA-2048-PUBLIC",
            "Key = DSA-2048-224",
            "Key = P-256_NAMED_CURVE_EXPLICIT",
            "Key = B-163",
            "Key = Bob-448-PUBLIC-Raw-NonCanonical",
            "Key = DSA-1024-FIPS186-2",
            "nid_key = NID_aes_256_cbc;",
            "key = <base64-encoded",
            "key = {BaseUrl}",
            r#"key: "cookie_store_key""#,
            r#"Key = "X-Forwarded-For""#,
            r#"key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n""#,
            r#"{'Key': 'key1', 'Value': 'value1'}"#,
            r#"String CONSUMER_KEY = "oauth_consumer_key";"#,
            r#"const val DELETE_KEY_SWIPE_LEFT = "gestures__delete_key_swipe_left""#,
            "password=start_pass_downsample",
            "client_secret=tenant_trial",
            "struct SessionHandle *data = conn->data;",
            "neg_ctx->output_token_length = out_sec_buff.cbBuffer;",
            "key = app_data->perthreadkey;",
            "spnegoTokenLength = input_token.length;",
            "passwordValue := conn.passwd",
            "tokenValue := GSS_C_EMPTY_BUFFER",
            r#"}: { provider: string, email: string, password: string }) => {"#,
            r#"const Pass = props => <span>{props.value}</span>;"#,
            "pass = empty;",
            "Passwd: password,",
            r#"hashedTokenKey := "$3:1:uFrxm43ggfw:zsN1zEFC7SvABTdR58o7yjIqfrI4cQ/HSYz3jBwwVnx5X+/ph4etGDIU9dvIYuy1IvnYUVe6a/Ar95xE+gfjhA""#,
            r#"invalidHashToken := "$-1:111:111""#,
            "token. For example: `O'Neil's` -> [ `O`, `Neil` ]. Defaults to `true`.",
            "options { tokenVocab=PainlessLexer; }",
            r#"event_key="AGENT_ACTION","#,
            r#"Token.Toolbar.Arg: "arg-toolbar","#,
            "MAX_NONCE: 5524839971, // Max nonce value",
            "salt_rounds = 12",
            "nonce_size = 16",
            "salt: password",
            "Salt = \"SodiumChloride\"",
            "Ctrl.salt = salt:saltSALTsaltSALTsaltSALTsaltSALTsalt",
            "error_code:int new_server_salt:long = BadMsgNotification;",
            r#"nonce: "placeholder""#,
            r#"String NONCE = "oauth_nonce";"#,
            "pwd = conn->passwd;",
            "m_password = state;",
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
            "dropForeignKey(table: Table|string, foreignKeyOrName: TableForeignKey|string): Promise<void>",
            "ADMIN_PASSWORD=$(rand_pwd)",
            "GITLAB_SECRETS_SECRET_KEY_BASE=long-and-random-alphanumeric-string",
            r#"passwordless: "abcdefgh""#,
            r#"errors['password1'] = 'Forbidden value.'"#,
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
            r#"CONSTELLIX_SECRET_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"#,
            r#"DESEC_TOKEN=x-xxxxxxxxxxxxxxxxxxxxxxxxxx"#,
            r#"PORKBUN_SECRET_API_KEY=xxxxxx"#,
            r#"token: "00000000-0000-0000-0000-000000000000""#,
            r#"RFC2136_TSIG_KEY="$keyname""#,
            r#"key = $insta::newkey # insta.priv.pem"#,
            r#"secret = $insta::secret"#,
            r#"// Credentials must be passed in the environment variable: ARVANCLOUD_API_KEY."#,
            r#"// Credentials must be passed in the environment variables: OTC_USER_NAME"#,
            r#"rbd_provisioner_secret: ceph-key-admin"#,
            r#"rbd_provisioner_user_secret: ceph-key-user"#,
            r#"key=field+Operator+" "+key;"#,
            r#"*e = append(*e, key+"="+val)"#,
            r#"Token = "%r14""#,
            r#"Token = "0(%rsp)""#,
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
            r#"credentials: "same-origin""#,
            r#"credentials: "include""#,
            r#"credentials: "omit""#,
            r#"it(`should set credentials: 'same-origin' on the precaching requests`, async function() {"#,
            "routing_key=task_queue",
            r#"foreign_key: "owner_id""#,
            r#"const string expectedTokenValue = "GITHUB_TOKEN_VALUE";"#,
            r#"public const string OAuthClientSecret = "GCM_BITBUCKET_CLOUD_CLIENTSECRET";"#,
            r#""privateKey": "LINE_1\nLINE_2\nLINE_2","#,
            r#""password": "password_1\t\t\t\t","#,
            r#""passphrase": "passphrase\t\t\t\t","#,
            r#"{"files":{"fail.py":{"content":"login = \"\"\npassword = \"\"\norgName = \"\""}}}"#,
            r#"{"patch":"@@ -0,0 +1,2 @@\n+client_secret\n\t\t"}"#,
            r#"{"patch":"@@ -0,0 +1 @@\n+Authorization: BEARER\n\tif token"}"#,
            r#"// User-Secrets: https://docs.asp.net/en/latest/security/app-secrets.html"#,
            r#"val FAILED_TO_RETRIEVE_GENERATED_KEY = "Failed to retrieve the generated key.""#,
            "key=this.button=this.screenY=this.screenX=this.l=0",
            "token=a.keyCode||0",
            r#"key=0!=b.indexOf("gme-")"#,
            r#"POSTGRES_HOST_AUTH_METHOD: scram-sha-256"#,
            r#"c.key = "__vlist__" + nestedIndex;"#,
            r#"s3.fog_options = { my_key: "my_value" }"#,
            r#"connection_options: { opt_key: "opt_value" }"#,
            r#"DEBUG_HEADER_KEY = "DEBUG_FRAME""#,
            r#"self.__authorizationHeader = f"Bearer {jwt}""#,
            r#"{"license": {"key": "lgpl-3.0"}}"#,
            r#"{"key": "contributor_covenant"}"#,
            r#"{"key": "short_codes"}"#,
            r#"{"key":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCexample"}"#,
            r#"key: '1001',"#,
            r#"key: '0-0-1',"#,
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
            r#":param password: string"#,
            r#":type aws_secret_access_key: string"#,
            r#"repeat_password: Repeat Password"#,
            r#"current_password: Current password"#,
            r#"password_confirmation: Password"#,
            r#"confirm_password: Confirm Password"#,
            r#"password__startswith = "pass""#,
            r#"token_regex = "bearer.*""#,
            r#"NAMESILO_API_KEY = "Client ID""#,
            r#"SERVICE_API_KEY = "API key (only with managed mode)""#,
            r#"SERVICE_CLIENT_SECRET = "Client secret, managed by the service client""#,
            r#"SERVICE_SHARED_SECRET = "shared secret related to 2FA""#,
            r#"SERVICE_AUTH_ENDPOINT = "The endpoint for service authentication""#,
            r#"SERVICE_SECRET_ACCESS_KEY = "Managed by the client (`SERVICE_SECRET_ACCESS_KEY_FILE` is not supported)""#,
            r#"ZONEEE_API_KEY=yyyyy \"#,
            r#"Query: "action=SET&api_key=apikeyvaluehere&name=example.com""#,
            r#"tmp_password:bytes = InputPaymentCredentials;"#,
            r#"bot_token = value"#,
            r#"password: "$t(lockRoomPasswordUppercase):""#,
            r#"password: "i18n.t(auth.setup.instructions)""#,
            r#"openstack_password: "{{ lookup('env','OS_PASSWORD') }}""#,
            r#"vsphere_password: '{{ lookup("env", "VSPHERE_PASSWORD") }}'"#,
            r#"password: "{{DB_PASS}}""#,
            r#"secrets_encryption_query: "resources[*].providers[0].{{kube_encryption_algorithm}}.keys[0].secret""#,
            r#"mariadb-password: "{{ .Values.db.password | b64enc }}""#,
            r#"key: "dist-${{ hashFiles('src/**/*.ts') }}-${{ runner.os }}""#,
            r#"apiKey: "<%= ShopifyApp.configuration.api_key %>""#,
            r#"password: valid_<%= schema.singular %>_password()"#,
            r#"msgs login_api_key: "Authenticating with api key %{api_key}""#,
            r#"<label>Password:</label>"#,
            r#"<tr><td>Password:</td><td><input type='password'>"#,
            r#"password: type='password"#,
            r#"password: "</label>""#,
            r#"secret: GetSecretValue</p>"#,
            r#"token: "from_admin\n""#,
            r#"key: "\u003c/p\u003e\n\n\u003cpre\u003e\u003ccode\u003e""#,
            r#"PRIVATE_KEY="$(cat ~/Downloads/*.private-key.pem)""#,
            r#"clientSecret: process.env.FACEBOOK_SECRET || 'APP_SECRET',"#,
            r#"clientSecret: process.env.TWITTER_SECRET || 'CONSUMER_SECRET',"#,
            r#"SecretName: "cool_secret","#,
            r#"KEYCTL_CAPS0_BIG_KEY = 0x10"#,
            r#"TCP_FASTOPEN_KEY = 0x21"#,
            r#"ER_TOO_LONG_KEY: "42000","#,
            r#"APP_PASSWORD=`echo $AZURE_CREDENTIALS | jq -r -c ".clientSecret"`"#,
            r#"PASS=`awk '{print $1}' $SEC_PROPERTIES_FILE | grep password | cut -d "=" -f2`"#,
            r#"ENTER_KEY_HELP#0="Adja meg titkos kulcs\u00e1t a k\u00e9tl\u00e9pcs\u0151s azonos\u00edt\u00e1s be\u00e1ll\u00edt\u00f3 oldal\u00e1r\u00f3l.";"#,
            r#"ENTER_KEY_VALUE_TOO_SHORT#0="The key value is too short.";"#,
            r#"SECRET_SAVED#0="Secret saved.";"#,
            r#"export const passwordNotLongEnough = "Password must be 6 characters or longer.";"#,
            r#"password: "Invalid Password""#,
            r#"password: "wrong password""#,
            r#"password: "None\n""#,
            r#"BLUECAT_PASSWORD = "API password""#,
            r#"WEDOS_WAPI_PASSWORD = "Password needs to be generated and IP allowed in the admin interface""#,
            r#"JOKER_PASSWORD = "Joker.com password""#,
            r#"AUTODNS_API_PASSWORD = "User Password""#,
            r#"assert.deepStrictEqual(error.errors, { email: 'Email Taken', password: 'Email Taken' });"#,
            r#"'Password cannot be blank.' => 'Password cannot be blank.'"#,
            r#"expected: "oraclecloud: some credentials information are missing: OCI_TENANCY_OCID,OCI_USER_OCID""#,
            r#"access_token = "TestAuthToken""#,
            r#"const string testPassword = "basicPass";"#,
            r#"fakeAPIKey = "asdf1234""#,
            r#"DummyPostData(csrf_token="dummytoken")"#,
            r#"const string expectedAccessToken = "LET_ME_IN";"#,
            r#"const string expectedAccessToken1 = "LET_ME_IN-1";"#,
            r#"private const string MOCK_ACCESS_TOKEN = "at-0987654321";"#,
            r#"private const string MOCK_REFRESH_TOKEN = "rt-1234567809";"#,
            r#"const string expectedPassword = "letmein123";"#,
            r#"const mockToken = "abc123";"#,
            r#"const expectedPassword = "123456";"#,
            r#"'access-token-expiration' => $this->time + 1800"#,
            r#"txtLUPassword.Enabled = !radioLUS4U.Checked;"#,
            r##"<div class="copy-pass" :title="'Password:' + file.passwd""##,
            r#"EnvPrivKeyPass = envPrivKey + "_PASS""#,
            r#"public static final String DEFAULT_PUBLIC_KEY_STRING = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKHGwq7q2RmwuRgKxBypQHw0mYu4BQZ3eMsTrdK8E6igRcxsobUC7uT0SoxIjl1WveWniCASejoQtn/BY6hVKWsCAwEAAQ==";"#,
        ] {
            assert!(hits(raw).is_empty(), "{raw}: {:?}", hits(raw));
        }
        let source_payload = r#"{"files":{"app.rs":{"content":"password: \"sk-live-123\""}}}"#;
        assert!(is_escaped_source_payload_fragment_literal(
            r#"\"Basic"#,
            source_payload
        ));
        assert!(!is_escaped_source_payload_fragment_literal(
            r#"\"sk-live-123"#,
            source_payload
        ));
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
        assert!(has(r#"password_confirmation = "hunter2""#, "hunter2"));
        assert!(has(
            r#"password__startswith = "Abc123!Longer""#,
            "Abc123!Longer"
        ));
        assert!(has(r#"password = "abc\tdef123""#, "abc\\tdef123"));
        assert!(has(r#"password = "hunter\n""#, "hunter\\n"));
        assert!(has(r#"password = "$(echo hunter2)""#, "$(echo hunter2)"));
        assert!(has(r#"clientSecret: "APP_SECRET_2026""#, "APP_SECRET_2026"));
        assert!(has(r#"password = "123456""#, "123456"));
        assert!(has(r#"token: "1234""#, "1234"));
        assert!(has(r#"PASSWORD=`echo hunter2`"#, "echo hunter2"));
        assert!(has(r#"password_help="hunter2""#, "hunter2"));
        assert!(has(
            r#"password_request="tenant-7-trial""#,
            "tenant-7-trial"
        ));
        assert!(has(
            r#"password_reset_token="tenant-7-trial""#,
            "tenant-7-trial"
        ));
        assert!(has(
            r#"private_key = "LINE_1\nA2secret""#,
            "LINE_1\\nA2secret"
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
            "secret: Base32SecretKey,",
            ">(secret: Base32SecretKey, options: Readonly<T>): Promise<HexString> {",
            "public decode(secret: Base32SecretKey): SecretKey {",
            r#"Attributes map[string]string `protobuf_key:"bytes,1,opt,name=key,proto3"`"#,
            r#"Level map[uint32]string `protobuf_key:"varint,1,opt,name=key,proto3"`"#,
            r#"Int8FromStr int8 `key:"int8_from_str"`"#,
            r#"Float64Str float64 `key:"float64_from_str"`"#,
            r#"[credentials objectForKey:@"AuthenticationScheme"]"#,
            r#"[sessionCredentials setObject:[self proxyHost] forKey:@"Host"]"#,
            r#"[self willChangeValueForKey:@"credentials"]"#,
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
            r#"PrivPubKeyPair = Alice-secp256r1:Bob-secp256r1"#,
            r#"PeerKey=Bob-prime192v1"#,
            r#"PrivateKey=ffdhe2048-1"#,
            r#"PeerKey=ffdhe3072-2-pub"#,
            r#"PrivPubKeyPair=ffdhe4096-1:ffdhe4096-1-pub"#,
            r#"<DiscreteObjectKeyFrame KeyTime="0:0:0.2" Value="{x:Static Visibility.Visible}" />"#,
            r#""fields=items%2Fname%2CnextPageToken&prefix=public/path""#,
            r#""fields=items%2Fname%2CnextPageToken&prefix=path%2Fsubfolder%2F""#,
            r#""fields=items%2Fname%2CnextPageToken&prefix=path%2F\n""#,
            r#""name%2CnextPageToken&maxResults=100 Token: fake_token\n""#,
            r#""&pageToken=NEXT_PAGE_1""#,
            r#""&pageToken=ABCD==\n""#,
            r#"OBJ_setct_AuthTokenTBS="AuthTokenTBS""#,
            r#"OBJ_setct_AuthResBaggage="\x67\x2A\x00\x08""#,
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
            "STATUS_WRONG_PASSWORD = 0xC000006A,",
            "STATUS_NO_USER_SESSION_KEY = 0xC0000202,",
            "STATUS_AUTH_TOKEN = 0xFFFFFFFF,",
            "SEC_E_INVALID_TOKEN = 0x80090308,",
            "SEC_E_NO_CREDENTIALS = 0x8009030E,",
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
            r#"ssh_key_id: "6536865""#,
            r#"'access_key_id' => '32343242'"#,
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
            r#"Key: "Proxy-Connection""#,
            r#"Key: "Proxy-Authenticate""#,
            r#"key: "X-Correlation-Id""#,
            r#""target_key": "product_id""#,
            r#""target_key": "cart_id""#,
            r#""original_key": "product_id""#,
            r#""key": "field_values""#,
            r#""key": "credential_lists""#,
            r#""key": "table1""#,
            r#""key": "checkbox2""#,
            r#"key='user_ids'"#,
            r#"def get_include_dirs(self, key='include_dirs')"#,
            r#"'key:source1'"#,
            r#"key: "Dev Gateway Region""#,
            r#"key: "HappyFace.jpg""#,
            r#"key: "cost-center""#,
            r#"key: "k8s-app""#,
            r#"key: "ovn4nfv-k8s-plugin""#,
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
            r#"password = Some(password_value)"#,
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
            "Ctrl.hexinfo = hexinfo:348a37a27ef1282f5f020dcc",
            "PasswordCredentials: internal.PasswordCredentials{",
            "Key: jose.JSONWebKey{Key: j.privKey, KeyID: j.kid},",
            r#"{key:"linear",value:function(n){return n}},{key:"cubic",value:function(n){return n*n*n}}"#,
            r#"{"body":"\u003cpre\u003e\u003ccode\u003econfig(httpheader = c(\"Authorization\" = l_auth))\u003c/code\u003e\u003c/pre\u003e"}"#,
            r#"private const string Header = auth.value;"#,
            r#"$headers[] = 'PRIVATE-TOKEN: '.$auth['username'];"#,
            r#"{"body":"\u003cpre\u003e\u003ccode\u003e'GET /signup': {view:'signup'}\u003c/code\u003e\u003c/pre\u003e"}"#,
            r#"{"body":"\u003cpre\u003e\u003ccode\u003ecredentials: @\"apiURL\\n];\u003c/code\u003e\u003c/pre\u003e"}"#,
            "/// Bitcoin address: base58check, P2PKH (0x00, '1') or P2SH (0x05, '3').",
            "/// Bitcoin WIF private key: base58check, version 0x80.",
            r#"* <li>token=1234</li>"#,
            r#"The format is `password=value` pairs."#,
            r#"privateKey: "content of your *.pem file here","#,
            r#"privateKey: "dummy value for setup, see #1512","#,
            r#"when(testTerminal.readPassword("password: ")).thenReturn("password");"#,
            r#"echo "password=${PASS}" >> ${DOMAIN_HOME}/boot.properties"#,
            r#"SEED_PASSWORD=#{Shellwords.escape Shellwords.escape(seed_password)}"#,
            r##"path_key = "#{key}_path""##,
            r##"puts "Welcome #{`heroku auth:whoami`.strip}!""##,
            r#"- ADMIN_PASSWORD=${DC_ADMIN_PWD}"#,
            r#"KEY=rolling/${APP_NAME}/stable/id"#,
            r#"api 'com.google.auth:google-auth-library-credentials:0.20.0'"#,
            r#""illuminate/auth": "^5.5","#,
            r#""tymon/jwt-auth": "1.0.*""#,
            r#""phpunit/php-token-stream": "^3.0","#,
            r#"config.reset_password_within = 6.hours"#,
            r#"RESET_PASSWORD_WITHIN=6.hours"#,
            r#"val key: SQLSyntax = sqls"column_name""#,
            r#"const PASSWORD: string, other = "helloworld1234";"#,
            r#"const PASSWORD: string; other = "helloworld1234";"#,
            r#"'  "private_key_id": "' + UUID.randomUUID().toString() + '","\n' +"#,
            r#"'  "private_key": "-----BEGIN PRIVATE KEY-----\n' + encodedKey + '\n-----END PRIVATE KEY-----\n","\n' +"#,
            r#"
{
  "tokens": [
    {
      "token": "quick",
      "start_offset": 0,
      "end_offset": 5,
      "type": "<ALPHANUM>",
      "position": 0
    }
  ]
}
"#,
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

    #[test]
    fn checksum_digest_fields_are_public_metadata() {
        let digest = "8c9a257f54763d4f3a1b02c148d9faf505c3be7f5726b27f17df5063c6fbcd7f";
        assert!(hits(&format!(
            r#""management.cattle.io/harvester-token-checksum": "{digest}""#
        ))
        .is_empty());

        let got = hits(&format!(r#""access_token": "{digest}""#));
        assert!(
            got.iter().any(|(_, value)| value == digest),
            "non-checksum token fields must still detect: {got:?}"
        );
    }

    #[test]
    fn tuple_assignment_maps_value_to_sensitive_identifier() {
        let got = hits(r#"login, password = 'python@vk.com', 'xooxeudiqi'"#);
        assert!(got.iter().any(|(_, value)| value == "xooxeudiqi"));
        assert!(got.iter().all(|(_, value)| value != "python@vk.com"));

        let got = hits(r#"password, login = 'xooxeudiqi', 'python@vk.com'"#);
        assert!(got.iter().any(|(_, value)| value == "xooxeudiqi"));
        assert!(got.iter().all(|(_, value)| value != "python@vk.com"));

        let got = hits(r#"name, api_token = "service", "tok-12345""#);
        assert!(got.iter().any(|(_, value)| value == "tok-12345"));
        assert!(got.iter().all(|(_, value)| value != "service"));
    }
}
