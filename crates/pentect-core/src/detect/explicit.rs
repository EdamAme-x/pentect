use super::Detector;
use crate::model::{labels, ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;

pub(crate) const EXPLICIT_SECRET_PREFIXES: [&str; 2] = ["pentect(", "mask("];

/// Masks values deliberately wrapped as `pentect(value)` or `mask(value)`, regardless of their
/// entropy or shape. The renderer removes the opt-in wrapper while preserving
/// only `value` in recovery, so a restored tool argument receives the intended
/// value rather than the annotation syntax.
pub struct ExplicitSecretDetector;

impl Detector for ExplicitSecretDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        let bytes = text.as_bytes();
        let mut spans = Vec::new();
        let mut cursor = 0usize;

        while cursor < bytes.len() {
            let Some((marker_start, prefix)) = next_explicit_marker(text, cursor) else {
                break;
            };
            let value_start = marker_start + prefix.len();
            let mut depth = 1usize;
            let mut close = value_start;
            while close < bytes.len() {
                match bytes[close] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                close += 1;
            }
            if depth != 0 {
                break;
            }

            let raw_marker = view.to_raw(ByteRange::new(marker_start, value_start));
            let raw_close = view.to_raw(ByteRange::new(close, close + 1));
            if close > value_start && raw_marker.len() == prefix.len() && raw_close.len() == 1 {
                let raw_value = view.to_raw(ByteRange::new(value_start, close));
                if !raw_value.is_empty() {
                    spans.push(Span {
                        range: raw_value,
                        category: Category::Secret,
                        label: labels::KEYED_SECRET.to_string(),
                        confidence: Confidence::High,
                        source: DetectorId::Explicit,
                    });
                }
            }
            cursor = close + 1;
        }

        spans
    }
}

fn next_explicit_marker(text: &str, cursor: usize) -> Option<(usize, &'static str)> {
    EXPLICIT_SECRET_PREFIXES
        .iter()
        .filter_map(|prefix| {
            text[cursor..]
                .match_indices(prefix)
                .map(|(relative, _)| cursor + relative)
                .find(|&start| {
                    start == 0
                        || !text.as_bytes()[start - 1].is_ascii_alphanumeric()
                            && text.as_bytes()[start - 1] != b'_'
                })
                .map(|start| (start, *prefix))
        })
        .min_by_key(|(start, _)| *start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Context, Kind, Region, RegionKind};

    fn detect(text: &str) -> Vec<Span> {
        let region = Region {
            span: ByteRange::new(0, text.len()),
            ctx: Context {
                path: None,
                key: None,
                hints: Vec::new(),
                kind: RegionKind::PlainText,
                format: Kind::Text,
            },
        };
        ExplicitSecretDetector.detect(&NormalizedView::build(&region, text))
    }

    #[test]
    fn finds_low_entropy_and_balanced_values() {
        let text = "a pentect(abc) b mask(pa(ss)word)";
        let spans = detect(text);
        assert_eq!(spans.len(), 2);
        assert_eq!(&text[spans[0].range.start..spans[0].range.end], "abc");
        assert_eq!(
            &text[spans[1].range.start..spans[1].range.end],
            "pa(ss)word"
        );
    }

    #[test]
    fn ignores_empty_unclosed_and_lookalike_markers() {
        assert!(detect("pentect() mask() pentect(unclosed mask(unclosed").is_empty());
        assert!(detect("ｐｅｎｔｅｃｔ(value)").is_empty());
        assert!(detect("unpentect(value) unmask(value)").is_empty());
    }
}
