use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use super::validate::Validator;
use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use regex::{Regex, RegexSet};

#[derive(Clone)]
struct PatternRule {
    re: Regex,
    category: Category,
    label: String,
    confidence: Confidence,
    /// Checksum gate applied to each match before it becomes a span.
    validator: Validator,
    /// Optional line/context gate for rules whose regex alphabet overlaps public metadata.
    context: MatchContextPolicy,
    /// 0 masks the full regex match; N masks capture group N.
    capture: usize,
}

/// A regex/capture/validator rule before compilation.
pub struct PatternSpec {
    pub pattern: String,
    pub category: Category,
    pub label: String,
    pub confidence: Confidence,
    pub validator: Validator,
    pub context: MatchContextPolicy,
    pub capture: usize,
    pub prefilter: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MatchContextPolicy {
    #[default]
    Any,
    NotPublicSshKeyLine,
}

/// Generic pattern matcher for deterministic regex-style recognizers.
///
/// Domain detectors should own their rule sets and labels. This type owns only
/// the mechanics: compile, prefilter, run captures, apply validators, and emit
/// spans in raw coordinates.
#[derive(Clone)]
pub struct PatternMatchDetector {
    rules: Vec<PatternRule>,
    /// Unprefiltered rules share one RegexSet, so we do a merged candidate scan
    /// instead of trying every regex blindly. Each matching rule is then scanned
    /// exactly to preserve overlaps, captures, and validators.
    exact: Option<ExactGroup>,
    prefiltered: Option<PrefilterGroup>,
}

#[derive(Clone)]
struct ExactGroup {
    set: RegexSet,
    rules: Vec<usize>,
}

#[derive(Clone)]
struct PrefilterGroup {
    ac: AhoCorasick,
    rules_by_pattern: Vec<Vec<usize>>,
}

impl PatternMatchDetector {
    pub fn from_specs(specs: Vec<PatternSpec>) -> Result<Self, String> {
        let mut rules = Vec::with_capacity(specs.len());
        let mut exact_patterns = Vec::new();
        let mut exact_rules = Vec::new();
        let mut prefilter_literals = Vec::new();
        let mut rules_by_pattern: Vec<Vec<usize>> = Vec::new();

        for s in specs {
            let re = Regex::new(&s.pattern).map_err(|e| format!("rule {}: {e}", s.label))?;
            if s.capture >= re.captures_len() {
                return Err(format!(
                    "rule {}: capture {} does not exist",
                    s.label, s.capture
                ));
            }
            let rule_index = rules.len();
            if s.prefilter.is_empty() {
                exact_patterns.push(s.pattern);
                exact_rules.push(rule_index);
            } else {
                for literal in &s.prefilter {
                    if literal.is_empty() {
                        continue;
                    }
                    prefilter_literals.push(literal.clone());
                    rules_by_pattern.push(vec![rule_index]);
                }
            }
            rules.push(PatternRule {
                re,
                category: s.category,
                label: s.label,
                confidence: s.confidence,
                validator: s.validator,
                context: s.context,
                capture: s.capture,
            });
        }

        let exact = if exact_patterns.is_empty() {
            None
        } else {
            Some(ExactGroup {
                set: RegexSet::new(exact_patterns.iter().map(|s| s.as_str()))
                    .map_err(|e| format!("rule set: {e}"))?,
                rules: exact_rules,
            })
        };
        let prefiltered = if prefilter_literals.is_empty() {
            None
        } else {
            Some(PrefilterGroup {
                ac: AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .build(&prefilter_literals)
                    .map_err(|e| format!("prefilter set: {e}"))?,
                rules_by_pattern,
            })
        };

        Ok(Self {
            rules,
            exact,
            prefiltered,
        })
    }

    #[cfg(test)]
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|rule| rule.label.as_str())
    }
}

impl Detector for PatternMatchDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let mut out = Vec::new();
        if let Some(exact) = &self.exact {
            for i in exact.set.matches(s) {
                let rule = &self.rules[exact.rules[i]];
                for captures in rule.re.captures_iter(s) {
                    if let Some(m) = captures.get(rule.capture) {
                        push_match(view, rule, m.start(), m.end(), m.as_str(), &mut out);
                    }
                }
            }
        }
        if let Some(prefiltered) = &self.prefiltered {
            let mut seen = None;
            let mut candidates = Vec::new();
            for m in prefiltered.ac.find_overlapping_iter(s) {
                for &rule_index in &prefiltered.rules_by_pattern[m.pattern().as_usize()] {
                    let seen = seen.get_or_insert_with(|| vec![false; self.rules.len()]);
                    if !seen[rule_index] {
                        seen[rule_index] = true;
                        candidates.push(rule_index);
                    }
                }
            }
            for rule_index in candidates {
                let rule = &self.rules[rule_index];
                for captures in rule.re.captures_iter(s) {
                    if let Some(m) = captures.get(rule.capture) {
                        push_match(view, rule, m.start(), m.end(), m.as_str(), &mut out);
                    }
                }
            }
        }
        out
    }
}

fn push_match(
    view: &NormalizedView,
    rule: &PatternRule,
    start: usize,
    end: usize,
    value: &str,
    out: &mut Vec<Span>,
) {
    if value.is_empty()
        || !rule.validator.accepts(value)
        || !rule.context.accepts(view.text(), start)
    {
        return;
    }
    out.push(Span {
        range: view.to_raw(ByteRange::new(start, end)),
        category: rule.category,
        label: rule.label.clone(),
        confidence: rule.confidence,
        source: DetectorId::Rule,
    });
}

impl MatchContextPolicy {
    fn accepts(self, text: &str, start: usize) -> bool {
        match self {
            MatchContextPolicy::Any => true,
            MatchContextPolicy::NotPublicSshKeyLine => !is_public_ssh_key_context(text, start),
        }
    }
}

fn is_public_ssh_key_context(text: &str, start: usize) -> bool {
    // OpenSSH authorized_keys/public-key lines are public metadata. Some
    // vendor-token alphabets overlap their base64 payloads; rules that opt into
    // this policy keep their regex recall but reject matches on a line already
    // identified as public key material.
    let line_start = text[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let prefix = &text[line_start..start];
    prefix.contains("ssh-rsa ") || prefix.contains("ssh-ed25519 ") || prefix.contains("ecdsa-sha2-")
}
