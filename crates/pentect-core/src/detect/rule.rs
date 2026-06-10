use super::Detector;
use crate::model::*;
use crate::normalize::NormalizedView;
use regex::Regex;

struct Rule {
    re: Regex,
    category: Category,
    label: &'static str,
    confidence: Confidence,
}

/// Anchored vendor-token rules. High confidence and linear-time (no ReDoS), so
/// these bypass the entropy/profile uncertainty.
pub struct RuleDetector {
    rules: Vec<Rule>,
}

impl RuleDetector {
    pub fn builtin() -> Self {
        let r = |p: &str| Regex::new(p).expect("builtin regex compiles");
        // Conventions, so new rules stay consistent:
        // - charset order is upper, lower, digits, then extras `_-`, with `-`
        //   written last and unescaped: `[A-Za-z0-9_-]`. Hex is `[0-9a-fA-F]`.
        // - confidence is the pattern's collision-resistance, not vendor fame:
        //   High = a unique prefix/structure makes a match almost certainly the
        //   secret; Medium = a short prefix plus generic hex/charset that a
        //   non-secret could plausibly hit (e.g. Twilio's `AC`+32hex).
        // - labels are UPPER_SNAKE (asserted in tests) so they render cleanly
        //   into `<<LABEL_hash>>` placeholders.
        let rules = vec![
            Rule {
                re: r(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
                category: Category::Secret,
                label: "JWT_SECRET",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"AKIA[A-Z0-9]{16}"),
                category: Category::Secret,
                label: "AWS_AKID",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"sk-[A-Za-z0-9_-]{20,}"),
                category: Category::Secret,
                label: "OPENAI_API_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
                category: Category::Secret,
                label: "SLACK_TOKEN",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
                category: Category::Secret,
                label: "SLACK_WEBHOOK",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"(sk|rk)_(live|test)_[A-Za-z0-9]{10,}"),
                category: Category::Secret,
                label: "STRIPE_SECRET_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"AIza[A-Za-z0-9_-]{35}"),
                category: Category::Secret,
                label: "GOOGLE_API_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"GOCSPX-[A-Za-z0-9_-]{28}"),
                category: Category::Secret,
                label: "GOOGLE_OAUTH_SECRET",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"ya29\.[A-Za-z0-9_-]{20,}"),
                category: Category::Secret,
                label: "GOOGLE_OAUTH_TOKEN",
                confidence: Confidence::High,
            },
            // Fine-grained PAT; distinct format from the classic gh*_ family.
            Rule {
                re: r(r"github_pat_[A-Za-z0-9_]{22,}"),
                category: Category::Secret,
                label: "GITHUB_PAT",
                confidence: Confidence::High,
            },
            // Classic GitHub token family (p/o/u/s/r) is one format, so one rule.
            Rule {
                re: r(r"gh[oprsu]_[A-Za-z0-9]{36}"),
                category: Category::Secret,
                label: "GITHUB_TOKEN",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"SK[0-9a-fA-F]{32}"),
                category: Category::Secret,
                label: "TWILIO_API_KEY",
                confidence: Confidence::Medium,
            },
            Rule {
                re: r(r"AC[0-9a-fA-F]{32}"),
                category: Category::Identifier,
                label: "TWILIO_ACCOUNT_SID",
                confidence: Confidence::Medium,
            },
            Rule {
                re: r(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
                category: Category::Secret,
                label: "SENDGRID_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"npm_[A-Za-z0-9]{36}"),
                category: Category::Secret,
                label: "NPM_TOKEN",
                confidence: Confidence::High,
            },
            // Domain is label(.label)*.tld, so consecutive/trailing dots and a
            // leading-dot domain don't match. TLD capped to bound the match.
            Rule {
                re: r(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}"),
                category: Category::Pii,
                label: "IDENTITY",
                confidence: Confidence::Medium,
            },
        ];
        Self { rules }
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
                    label: rule.label.to_string(),
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
            assert!(label_re.is_match(rule.label), "bad label: {}", rule.label);
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
