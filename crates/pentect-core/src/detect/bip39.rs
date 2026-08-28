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

struct MnemonicCandidate {
    start: usize,
    end: usize,
    boundary_score: u8,
}

impl Detector for Bip39Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let tokens = word_tokens(text);
        if looks_like_reference_wordlist(text, &tokens) {
            return Vec::new();
        }
        let mut candidates = Vec::new();

        for start in 0..tokens.len() {
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
                let Some(boundary_score) = boundary_score(text, &tokens, start, end) else {
                    continue;
                };
                if !validate::bip39_mnemonic_window(&words) {
                    continue;
                }
                candidates.push(MnemonicCandidate {
                    start,
                    end,
                    boundary_score,
                });
            }
        }

        candidates.sort_by(|left, right| {
            right
                .boundary_score
                .cmp(&left.boundary_score)
                .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
                .then_with(|| right.start.cmp(&left.start))
        });
        let mut selected = Vec::<MnemonicCandidate>::new();
        for candidate in candidates {
            if selected
                .iter()
                .any(|existing| candidate.start < existing.end && existing.start < candidate.end)
            {
                continue;
            }
            selected.push(candidate);
        }
        selected.sort_by_key(|candidate| candidate.start);
        selected
            .into_iter()
            .map(|candidate| {
                let norm =
                    ByteRange::new(tokens[candidate.start].start, tokens[candidate.end - 1].end);
                Span {
                    range: view.to_raw(norm),
                    category: Category::Secret,
                    label: labels::BIP39_MNEMONIC.to_string(),
                    confidence: Confidence::High,
                    source: DetectorId::Rule,
                }
            })
            .collect()
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

fn boundary_score(text: &str, tokens: &[WordToken], start: usize, end: usize) -> Option<u8> {
    let left = if start == 0 {
        3
    } else {
        separator_score(&text[tokens[start - 1].end..tokens[start].start])?
    };
    let right = if end >= tokens.len() {
        3
    } else {
        separator_score(&text[tokens[end - 1].end..tokens[end].start])?
    };
    Some(left + right)
}

fn separator_score(value: &str) -> Option<u8> {
    if !is_strong_separator(value) {
        return None;
    }
    Some(if value.chars().all(char::is_whitespace) {
        1
    } else {
        4
    })
}

fn is_strong_separator(value: &str) -> bool {
    (!value.is_empty() && value.chars().all(char::is_whitespace))
        || value.bytes().any(|b| {
            matches!(
                b,
                b'\n' | b'\r' | b':' | b'=' | b';' | b',' | b'.' | b'<' | b'>' | b'|'
            )
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

        for prefix in [
            "bip39: ",
            "Here is the backup phrase: ",
            "Please verify this seed: ",
            "secret phrase: ",
        ] {
            assert_eq!(hit_values(&format!("{prefix}{plain}")), vec![plain]);
        }

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

        let followed_by_prose = "seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about for wallet recovery";
        assert_eq!(
            hit_values(followed_by_prose),
            vec![
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            ]
        );

        let unlabelled_prose = "keep abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about safe and offline";
        assert_eq!(
            hit_values(unlabelled_prose),
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
    }

    #[test]
    fn rejects_reference_wordlists_but_protects_valid_source_literals() {
        assert!(hit_values(include_str!("bip39_english.txt")).is_empty());
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(
            hit_values(&format!(r#"const PHRASE: &str = "{phrase}";"#)),
            vec![phrase]
        );
        assert_eq!(
            hit_values(&format!(r#"("BIP39_MNEMONIC", "{phrase}")"#)),
            vec![phrase]
        );
    }
}
