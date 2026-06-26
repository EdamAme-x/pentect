use super::{validate, Detector};
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;

#[derive(Default)]
pub struct Bip39Detector;

#[derive(Clone, Copy)]
struct WordToken {
    start: usize,
    end: usize,
}

impl Detector for Bip39Detector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let tokens = word_tokens(text);
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
                let phrase = tokens[start..end]
                    .iter()
                    .map(|token| &text[token.start..token.end])
                    .collect::<Vec<_>>()
                    .join(" ");
                if !has_strong_boundary(text, &tokens, start, end)
                    || !validate::bip39_mnemonic(&phrase)
                {
                    continue;
                }
                let norm = ByteRange::new(tokens[start].start, tokens[end - 1].end);
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
        if ch.is_ascii_alphabetic() {
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
            b'\n' | b'\r' | b':' | b';' | b',' | b'.' | b'<' | b'>' | b'|'
        )
    })
}

fn push_token(text: &str, start: usize, end: usize, tokens: &mut Vec<WordToken>) {
    let len = text[start..end].len();
    if (3..=8).contains(&len) {
        tokens.push(WordToken { start, end });
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
}
