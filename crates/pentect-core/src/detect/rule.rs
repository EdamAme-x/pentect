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
        let rules = vec![
            Rule {
                re: r(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
                category: Category::Secret,
                label: "JWT_SECRET",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"AKIA[0-9A-Z]{16}"),
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
                re: r(r"ghp_[A-Za-z0-9]{36}"),
                category: Category::Secret,
                label: "GITHUB_PAT",
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
                re: r(r"(sk|rk)_(live|test)_[0-9a-zA-Z]{10,}"),
                category: Category::Secret,
                label: "STRIPE_SECRET_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"AIza[0-9A-Za-z_\-]{35}"),
                category: Category::Secret,
                label: "GOOGLE_API_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"GOCSPX-[0-9A-Za-z_\-]{28}"),
                category: Category::Secret,
                label: "GOOGLE_OAUTH_SECRET",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"ya29\.[0-9A-Za-z_\-]{20,}"),
                category: Category::Secret,
                label: "GOOGLE_OAUTH_TOKEN",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"github_pat_[0-9a-zA-Z_]{22,}"),
                category: Category::Secret,
                label: "GITHUB_PAT",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"gh[ousr]_[0-9a-zA-Z]{36}"),
                category: Category::Secret,
                label: "GITHUB_TOKEN",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"SK[0-9a-fA-F]{32}"),
                category: Category::Secret,
                label: "TWILIO_API_KEY",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"AC[0-9a-fA-F]{32}"),
                category: Category::Identifier,
                label: "TWILIO_ACCOUNT_SID",
                confidence: Confidence::High,
            },
            Rule {
                re: r(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
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
            Rule {
                re: r(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
                category: Category::Pii,
                label: "IDENTITY",
                confidence: Confidence::Medium,
            },
        ];
        Self { rules }
    }
}

impl Detector for RuleDetector {
    fn id(&self) -> &str {
        "rule"
    }
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
                    source: format!("rule:{}", rule.label),
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
                "GITHUB_PAT",
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
}
