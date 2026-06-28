use super::{validate, Detector};
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;

#[derive(Default)]
pub struct Bip39Detector;

#[derive(Clone, Copy)]
struct WordToken {
    start: usize,
    end: usize,
    language_mask: u16,
}

impl Detector for Bip39Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let tokens = word_tokens(text);
        if looks_like_reference_wordlist(text, &tokens) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut covered_until = 0;

        for start in 0..tokens.len() {
            if tokens[start].start < covered_until {
                continue;
            }
            for len in [24usize, 21, 18, 15, 12] {
                let end = start + len;
                if end > tokens.len() {
                    continue;
                }
                let language_mask = tokens[start..end]
                    .iter()
                    .fold(u16::MAX, |mask, token| mask & token.language_mask);
                if language_mask == 0 {
                    continue;
                }
                let words = tokens[start..end]
                    .iter()
                    .map(|token| &text[token.start..token.end])
                    .collect::<Vec<_>>();
                let norm = ByteRange::new(tokens[start].start, tokens[end - 1].end);
                if !has_strong_boundary(text, &tokens, start, end)
                    || !has_mnemonic_evidence(text, &tokens, start, end, norm)
                    || !validate::bip39_mnemonic_window(&words)
                {
                    continue;
                }
                out.push(Span {
                    range: view.to_raw(norm),
                    category: Category::Secret,
                    label: labels::BIP39_MNEMONIC.to_string(),
                    confidence: Confidence::High,
                    source: DetectorId::Rule,
                });
                covered_until = tokens[end - 1].end;
                break;
            }
        }

        out
    }
}

fn word_tokens(text: &str) -> Vec<WordToken> {
    let mut tokens = Vec::new();
    let mut start = None;

    for (index, ch) in text.char_indices() {
        if ch.is_alphabetic() {
            start.get_or_insert(index);
            continue;
        }
        if let Some(token_start) = start.take() {
            push_token(text, token_start, index, &mut tokens);
        }
    }
    if let Some(token_start) = start {
        push_token(text, token_start, text.len(), &mut tokens);
    }

    tokens
}

fn has_strong_boundary(text: &str, tokens: &[WordToken], start: usize, end: usize) -> bool {
    let left = if start == 0 {
        true
    } else {
        is_strong_separator(&text[tokens[start - 1].end..tokens[start].start])
            || has_mnemonic_context(text, tokens[start].start)
    };
    let right = if end >= tokens.len() {
        true
    } else {
        is_strong_separator(&text[tokens[end - 1].end..tokens[end].start])
    };
    left && right
}

fn is_strong_separator(value: &str) -> bool {
    value.bytes().any(|b| {
        matches!(
            b,
            b'\n' | b'\r' | b':' | b'=' | b';' | b',' | b'.' | b'<' | b'>' | b'|'
        )
    })
}

fn has_mnemonic_evidence(
    text: &str,
    tokens: &[WordToken],
    start: usize,
    end: usize,
    range: ByteRange,
) -> bool {
    is_standalone_phrase(text, range)
        || is_numbered_list(text, tokens, start, end)
        || has_mnemonic_context(text, range.start)
}

fn is_standalone_phrase(text: &str, range: ByteRange) -> bool {
    text[..range.start].trim().is_empty() && text[range.end..].trim().is_empty()
}

fn is_numbered_list(text: &str, tokens: &[WordToken], start: usize, end: usize) -> bool {
    tokens[start..end]
        .iter()
        .enumerate()
        .all(|(offset, token)| {
            let line_start = text[..token.start]
                .rfind(['\n', '\r'])
                .map_or(0, |index| index + 1);
            let prefix = text[line_start..token.start].trim();
            matches_number_prefix(prefix, offset + 1)
        })
}

fn matches_number_prefix(prefix: &str, number: usize) -> bool {
    let number = number.to_string();
    let Some(rest) = prefix.strip_prefix(&number) else {
        return false;
    };
    matches!(rest.trim_start(), "." | ")" | ":" | "-")
}

fn has_mnemonic_context(text: &str, phrase_start: usize) -> bool {
    let mut window_start = phrase_start.saturating_sub(96);
    while window_start < phrase_start && !text.is_char_boundary(window_start) {
        window_start += 1;
    }
    let prefix = text[window_start..phrase_start].to_ascii_lowercase();
    for keyword in [
        "secret recovery phrase",
        "recovery phrase",
        "seed phrase",
        "wallet seed",
        "wallet mnemonic",
        "mnemonic",
        "wallet",
    ] {
        let Some(index) = prefix.rfind(keyword) else {
            continue;
        };
        if !keyword_boundary(&prefix, index, keyword.len()) {
            continue;
        }
        let suffix = &prefix[index + keyword.len()..];
        if context_suffix_allows_phrase(suffix) {
            return true;
        }
    }
    false
}

fn keyword_boundary(text: &str, start: usize, len: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|index| text.as_bytes().get(index))
        .copied();
    let after = text.as_bytes().get(start + len).copied();
    !before.is_some_and(is_keyword_byte) && !after.is_some_and(is_keyword_byte)
}

fn is_keyword_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn context_suffix_allows_phrase(suffix: &str) -> bool {
    let has_separator = suffix
        .chars()
        .any(|ch| matches!(ch, ':' | '=' | '\n' | '\r'));
    if has_separator
        && suffix.chars().all(|ch| {
            ch.is_ascii_whitespace() || matches!(ch, ':' | '=' | '>' | '"' | '\'' | '`' | '-')
        })
    {
        return true;
    }

    let trimmed = suffix.trim_start();
    let Some(rest) = trimmed.strip_prefix("is") else {
        return false;
    };
    let boundary = match rest.chars().next() {
        Some(ch) => ch.is_ascii_whitespace() || matches!(ch, ':' | '='),
        None => true,
    };
    boundary
        && rest.chars().all(|ch| {
            ch.is_ascii_whitespace() || matches!(ch, ':' | '=' | '>' | '"' | '\'' | '`' | '-')
        })
}

fn looks_like_reference_wordlist(text: &str, tokens: &[WordToken]) -> bool {
    if tokens.len() < 128 {
        return false;
    }
    let bip39_tokens = tokens
        .iter()
        .filter(|token| token.language_mask != 0)
        .count();
    if bip39_tokens * 100 < tokens.len() * 95 {
        return false;
    }
    let one_word_lines = tokens
        .iter()
        .filter(|token| line_contains_only_token(text, token))
        .count();
    one_word_lines * 100 >= tokens.len() * 90
}

fn line_contains_only_token(text: &str, token: &WordToken) -> bool {
    let line_start = text[..token.start]
        .rfind(['\n', '\r'])
        .map_or(0, |index| index + 1);
    let line_end = text[token.end..]
        .find(['\n', '\r'])
        .map_or(text.len(), |offset| token.end + offset);
    text[line_start..token.start].trim().is_empty() && text[token.end..line_end].trim().is_empty()
}

fn push_token(text: &str, start: usize, end: usize, tokens: &mut Vec<WordToken>) {
    let len = text[start..end].chars().count();
    if (1..=16).contains(&len) {
        let language_mask = validate::bip39_language_mask(&text[start..end]);
        tokens.push(WordToken {
            start,
            end,
            language_mask,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    fn hit_values(raw: &str) -> Vec<String> {
        let region = region(raw);
        let view = NormalizedView::build(&region, raw);
        Bip39Detector
            .detect(&view)
            .into_iter()
            .map(|span| raw[span.range.start..span.range.end].to_string())
            .collect()
    }

    #[test]
    fn detects_plain_multiline_and_numbered_seed_phrases() {
        let plain = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(hit_values(plain), vec![plain]);

        let multiline = "Recovery phrase:\nabandon abandon abandon\nabandon abandon abandon\nabandon abandon abandon\nabandon abandon about";
        assert_eq!(
            hit_values(multiline),
            vec![
                "abandon abandon abandon\nabandon abandon abandon\nabandon abandon abandon\nabandon abandon about"
            ]
        );

        let numbered = "1. abandon\n2. abandon\n3. abandon\n4. abandon\n5. abandon\n6. abandon\n7. abandon\n8. abandon\n9. abandon\n10. abandon\n11. abandon\n12. about";
        assert_eq!(
            hit_values(numbered),
            vec![
                "abandon\n2. abandon\n3. abandon\n4. abandon\n5. abandon\n6. abandon\n7. abandon\n8. abandon\n9. abandon\n10. abandon\n11. abandon\n12. about"
            ]
        );

        let labelled = "wallet seed phrase = \"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\"";
        assert_eq!(
            hit_values(labelled),
            vec![
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            ]
        );

        let prose = "seed phrase is abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(
            hit_values(prose),
            vec![
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            ]
        );

        let prose_colon = "wallet recovery phrase is: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(
            hit_values(prose_colon),
            vec![
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            ]
        );
    }

    #[test]
    fn detects_non_english_seed_phrases() {
        let japanese = "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら";
        assert_eq!(hit_values(japanese), vec![japanese]);
    }

    #[test]
    fn rejects_wrong_checksum_and_short_word_runs() {
        assert!(hit_values(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
        )
        .is_empty());
        assert!(hit_values("just three words here").is_empty());
        assert!(hit_values(
            "ordinary prose page recovery phrase abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        .is_empty());
    }

    #[test]
    fn rejects_wordlists_and_source_test_vectors() {
        assert!(hit_values(include_str!("bip39_english.txt")).is_empty());
        assert!(hit_values(
            r#"const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";"#
        )
        .is_empty());
        assert!(hit_values(
            r#"("BIP39_MNEMONIC", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")"#
        )
        .is_empty());
    }
}
