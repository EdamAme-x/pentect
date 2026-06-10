use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use regex::Regex;

struct Rule {
    re: Regex,
    category: Category,
    label: String,
    confidence: Confidence,
}

/// A data-form rule (e.g. a TOML pack entry) before its pattern is compiled.
pub struct RuleSpec {
    pub pattern: String,
    pub category: Category,
    pub label: String,
    pub confidence: Confidence,
}

/// Anchored vendor-token rules. High confidence and linear-time (no ReDoS), so
/// these bypass the entropy/profile uncertainty. The built-in set is just the
/// default pack — `from_specs` builds the same detector from loaded data.
pub struct RuleDetector {
    rules: Vec<Rule>,
}

impl RuleDetector {
    /// Compile data-form rules into a detector; errors if any pattern is invalid.
    pub fn from_specs(specs: Vec<RuleSpec>) -> Result<Self, String> {
        let rules = specs
            .into_iter()
            .map(|s| {
                Ok(Rule {
                    re: Regex::new(&s.pattern).map_err(|e| format!("rule {}: {e}", s.label))?,
                    category: s.category,
                    label: s.label,
                    confidence: s.confidence,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { rules })
    }

    pub fn builtin() -> Self {
        use Category::{Identifier, Pii, Secret};
        use Confidence::{High, Medium};
        // Conventions, so new rules stay consistent:
        // - charset order is upper, lower, digits, then extras `_-`, with `-`
        //   written last and unescaped: `[A-Za-z0-9_-]`. Hex is `[0-9a-fA-F]`.
        // - confidence is the pattern's collision-resistance, not vendor fame:
        //   High = a unique prefix/structure makes a match almost certainly the
        //   secret; Medium = a short prefix plus generic hex/charset that a
        //   non-secret could plausibly hit (e.g. Twilio's `AC`+32hex).
        // - labels are UPPER_SNAKE (asserted in tests) so they render cleanly.
        let table: &[(&str, Category, &str, Confidence)] = &[
            (
                r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*",
                Secret,
                "JWT_SECRET",
                High,
            ),
            (r"AKIA[A-Z0-9]{16}", Secret, "AWS_AKID", High),
            (r"sk-[A-Za-z0-9_-]{20,}", Secret, "OPENAI_API_KEY", High),
            (r"xox[baprs]-[A-Za-z0-9-]{10,}", Secret, "SLACK_TOKEN", High),
            (
                r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
                Secret,
                "SLACK_WEBHOOK",
                High,
            ),
            (
                r"(sk|rk)_(live|test)_[A-Za-z0-9]{10,}",
                Secret,
                "STRIPE_SECRET_KEY",
                High,
            ),
            (r"AIza[A-Za-z0-9_-]{35}", Secret, "GOOGLE_API_KEY", High),
            (
                r"GOCSPX-[A-Za-z0-9_-]{28}",
                Secret,
                "GOOGLE_OAUTH_SECRET",
                High,
            ),
            (
                r"ya29\.[A-Za-z0-9_-]{20,}",
                Secret,
                "GOOGLE_OAUTH_TOKEN",
                High,
            ),
            // Fine-grained PAT; distinct format from the classic gh*_ family.
            (r"github_pat_[A-Za-z0-9_]{22,}", Secret, "GITHUB_PAT", High),
            // Classic GitHub token family (p/o/u/s/r) is one format, so one rule.
            (r"gh[oprsu]_[A-Za-z0-9]{36}", Secret, "GITHUB_TOKEN", High),
            (r"SK[0-9a-fA-F]{32}", Secret, "TWILIO_API_KEY", Medium),
            (
                r"AC[0-9a-fA-F]{32}",
                Identifier,
                "TWILIO_ACCOUNT_SID",
                Medium,
            ),
            (
                r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
                Secret,
                "SENDGRID_KEY",
                High,
            ),
            (r"npm_[A-Za-z0-9]{36}", Secret, "NPM_TOKEN", High),
            // Domain is label(.label)*.tld, so consecutive/trailing dots and a
            // leading-dot domain don't match. TLD capped to bound the match.
            (
                r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}",
                Pii,
                "IDENTITY",
                Medium,
            ),
        ];
        let specs = table
            .iter()
            .map(|&(pattern, category, label, confidence)| RuleSpec {
                pattern: pattern.to_string(),
                category,
                label: label.to_string(),
                confidence,
            })
            .collect();
        Self::from_specs(specs).expect("builtin regexes compile")
    }
}

impl Detector for RuleDetector {
    fn detect(&self, view: &NormalizedView) -> Vec<Span> {
        let s = view.text();
        let mut out = Vec::new();
        for rule in &self.rules {
            for m in rule.re.find_iter(s) {
                out.push(Span {
                    range: view.to_raw(ByteRange::new(m.start(), m.end())),
                    category: rule.category,
                    label: rule.label.clone(),
                    confidence: rule.confidence,
                    source: DetectorId::Rule,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::region;

    // Small labelled recall corpus: each vendor secret must be detected under
    // the right label. Samples are split with concat! so the provider prefix and
    // body are separate literals (no contiguous secret in source, which would
    // trip GitHub push protection); the joined value still matches the rule.
    #[test]
    fn vendor_recall_corpus() {
        let cases: &[(&str, &str)] = &[
            ("AKIAIOSFODNN7EXAMPLE", "AWS_AKID"),
            (concat!("sk", "-ABCDEFGHIJKLMNOPQRSTUVWX"), "OPENAI_API_KEY"),
            (
                concat!("ghp", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
                "GITHUB_TOKEN",
            ),
            (
                concat!("github", "_pat_11ABCDEFG0aBcDeFgHiJkLmNoPqRsTuVwXyZ"),
                "GITHUB_PAT",
            ),
            (
                concat!("ghs", "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
                "GITHUB_TOKEN",
            ),
            (
                concat!("sk", "_live_ABCDEFGHIJ1234567890"),
                "STRIPE_SECRET_KEY",
            ),
            (
                concat!("AIza", "SyA1234567890abcdefghijklmnopqrstuv0"),
                "GOOGLE_API_KEY",
            ),
            (
                concat!("GOCSPX", "-abcdefghijklmnopqrstuvwxyz12"),
                "GOOGLE_OAUTH_SECRET",
            ),
            (
                concat!("ya29", ".A0ARrdaMabcdefghijklmnopqrstuvwxyz"),
                "GOOGLE_OAUTH_TOKEN",
            ),
            (
                concat!("SK", "abcdef0123456789abcdef0123456789"),
                "TWILIO_API_KEY",
            ),
            (
                concat!(
                    "SG",
                    ".abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
                ),
                "SENDGRID_KEY",
            ),
            (
                concat!("npm", "_abcdefghijklmnopqrstuvwxyz0123456789"),
                "NPM_TOKEN",
            ),
            (
                concat!(
                    "https://hooks.slack.com/services/",
                    "T00000000/B00000000/abcdEFGH"
                ),
                "SLACK_WEBHOOK",
            ),
        ];
        let det = RuleDetector::builtin();
        for (sample, label) in cases {
            let reg = region(sample);
            let v = NormalizedView::build(&reg, sample);
            let spans = det.detect(&v);
            assert!(
                spans.iter().any(|s| &s.label == label),
                "{sample} should detect {label}, got {:?}",
                spans.iter().map(|s| &s.label).collect::<Vec<_>>()
            );
        }
    }

    // Every label must be UPPER_SNAKE so it renders into a well-formed
    // `<<LABEL_hash>>` placeholder; a new rule can't smuggle in a bad label.
    #[test]
    fn rule_labels_are_upper_snake() {
        let label_re = Regex::new(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$").unwrap();
        for rule in &RuleDetector::builtin().rules {
            assert!(label_re.is_match(&rule.label), "bad label: {}", rule.label);
        }
    }

    // The tightened email rule must reject malformed domains while still
    // matching ordinary addresses.
    #[test]
    fn email_rule_rejects_malformed_domains() {
        let det = RuleDetector::builtin();
        let hits = |s: &str| {
            let reg = region(s);
            let v = NormalizedView::build(&reg, s);
            det.detect(&v).iter().any(|sp| sp.label == "IDENTITY")
        };
        assert!(hits("alice@example.com"));
        assert!(hits("a@b.co.uk"));
        assert!(!hits("alice@.com"));
        assert!(!hits("alice@example."));
    }
}
