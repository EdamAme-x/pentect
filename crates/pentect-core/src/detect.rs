use crate::model::*;
use regex::Regex;

/// Side-effect-free and deterministic. Returns spans in absolute raw coordinates.
pub trait Detector {
    fn id(&self) -> &str;
    fn detect(&self, region: &Region, raw: &str) -> Vec<Span>;
}

pub struct DetectorSet {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorSet {
    pub fn builtin() -> Self {
        Self {
            detectors: vec![
                Box::new(RuleDetector::builtin()),
                Box::new(EntropyDetector::default()),
            ],
        }
    }

    pub fn run(&self, region: &Region, raw: &str) -> Vec<Span> {
        let mut out = Vec::new();
        for d in &self.detectors {
            out.extend(d.detect(region, raw));
        }
        out
    }
}

struct Rule {
    re: Regex,
    category: Category,
    label: &'static str,
    confidence: Confidence,
}

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
    fn detect(&self, region: &Region, raw: &str) -> Vec<Span> {
        let base = region.span.start;
        let s = &raw[region.span.start..region.span.end];
        let mut out = Vec::new();
        for rule in &self.rules {
            for m in rule.re.find_iter(s) {
                out.push(Span {
                    range: ByteRange::new(base + m.start(), base + m.end()),
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

/// Flags long, high-entropy codec-alphabet runs as likely opaque secrets.
pub struct EntropyDetector {
    min_len: usize,
    threshold: f64,
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self { min_len: 24, threshold: 3.2 }
    }
}

impl Detector for EntropyDetector {
    fn id(&self) -> &str {
        "entropy"
    }
    fn detect(&self, region: &Region, raw: &str) -> Vec<Span> {
        let base = region.span.start;
        let s = &raw[region.span.start..region.span.end];
        let bytes = s.as_bytes();
        let is_tok =
            |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-');
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if !is_tok(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_tok(bytes[i]) {
                i += 1;
            }
            let run = &bytes[start..i];
            if run.len() >= self.min_len && shannon(run) >= self.threshold {
                out.push(Span {
                    range: ByteRange::new(base + start, base + i),
                    category: Category::Secret,
                    label: "LIKELY_SECRET".to_string(),
                    confidence: Confidence::Low,
                    source: "entropy".to_string(),
                });
            }
        }
        out
    }
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
