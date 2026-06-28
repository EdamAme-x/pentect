use super::util::token_runs;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;

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
        if run.len() >= self.min_len
            && entropy_candidate(run, text, start, end)
            && shannon(run.as_bytes()) >= self.threshold
        {
            out.push(Span {
                range: view.to_raw(ByteRange::new(start, end)),
                category: Category::Secret,
                label: labels::LIKELY_SECRET.to_string(),
                confidence: Confidence::Low,
                source: DetectorId::Entropy,
            });
        }
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
        && !is_source_identifier_like(run)
        && !is_regex_character_class_fragment(text, start, end)
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

fn is_source_identifier_like(run: &str) -> bool {
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
    if has_separator && identifier_like_with_few_digits(bytes) {
        return true;
    }
    false
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
            "const PENTECT_AGENT_INSTRUCTIONS: &str = \"contract\";",
            "--allow-unverified-hooks",
            "DASHBOARD_HEARTBEAT_MAX_AGE",
            "clientSecretIdentifierOnly",
        ] {
            let reg = region(raw);
            let v = NormalizedView::build(&reg, raw);
            assert!(EntropyDetector::default().detect(&v).is_empty(), "{raw}");
        }
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
}
