use super::Detector;
use crate::model::{ByteRange, Category, Confidence, DetectorId, Span};
use crate::normalize::NormalizedView;

include!(concat!(env!("OUT_DIR"), "/shell_prefix_automaton.rs"));

/// Build-time-generated prefix automaton for latency-sensitive shell input.
pub struct ShellPrefixDetector;

pub fn first_shell_secret_range(text: &str) -> Option<ByteRange> {
    shell_prefix_candidates(text).next().map(|(range, _)| range)
}

fn shell_prefix_candidates(text: &str) -> impl Iterator<Item = (ByteRange, usize)> + '_ {
    let bytes = text.as_bytes();
    let mut state = 0usize;
    bytes.iter().enumerate().filter_map(move |(index, &byte)| {
        state = if byte.is_ascii() {
            SHELL_PREFIX_NEXT[state][byte as usize] as usize
        } else {
            0
        };
        let output = SHELL_PREFIX_OUTPUT[state];
        if output < 0 {
            return None;
        }
        let pattern = output as usize;
        let start = index + 1 - SHELL_PREFIX_LENGTHS[pattern];
        let mut end = index + 1;
        while bytes
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            end += 1;
        }
        Some((ByteRange::new(start, end), pattern))
    })
}

impl Detector for ShellPrefixDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let text = view.text();
        shell_prefix_candidates(text)
            .filter(|(range, pattern)| {
                range.end - range.start >= SHELL_PREFIX_MIN_LENGTHS[*pattern]
            })
            .map(|(range, pattern)| Span {
                range: view.to_raw(range),
                category: Category::Secret,
                label: SHELL_PREFIX_LABELS[pattern].to_string(),
                confidence: Confidence::High,
                source: DetectorId::Rule,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, Kind, Region, RegionKind};

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
        ShellPrefixDetector.detect(&NormalizedView::build(&region, text))
    }

    #[test]
    fn generated_automaton_finds_shell_secrets_and_rejects_short_prefixes() {
        let text = "echo rpa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let spans = detect(text);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].label, "SECRET");
        assert_eq!(spans[1].label, "GITHUB_TOKEN");
        assert!(detect("echo rpa_short").is_empty());
        assert_eq!(
            first_shell_secret_range("echo rpa_").unwrap(),
            ByteRange::new(5, 9)
        );
    }
}
