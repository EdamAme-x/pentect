use crate::detect::{RuleDetector, RuleSpec};
use crate::model::{Category, Confidence};
use serde::Deserialize;

/// A Layer-1 rule pack: pure data, no code. v1 supports SAFE-ADDITIVE detector
/// entries (one linear-time regex each). when-conditions, deny/allow, granularity
/// overrides, and sidecars are later layers; entries without a `pattern` are
/// skipped so a pack that mixes layers still contributes its Layer-1 rules.
#[derive(Debug, Deserialize)]
struct PackFile {
    #[serde(default)]
    detector: Vec<DetectorEntry>,
}

#[derive(Debug, Deserialize)]
struct DetectorEntry {
    pattern: Option<String>,
    category: Option<String>,
    label: Option<String>,
    #[serde(default = "default_confidence")]
    confidence: String,
}

fn default_confidence() -> String {
    "high".to_string()
}

/// Parse a TOML rule pack into a detector built from its `[[detector]]` regex
/// entries. Errors on malformed TOML, an unknown category/confidence, an invalid
/// regex, or a regex entry missing its category/label.
pub fn load_rule_detector(toml_src: &str) -> Result<RuleDetector, String> {
    let pack: PackFile = toml::from_str(toml_src).map_err(|e| e.to_string())?;
    let mut specs = Vec::new();
    for d in pack.detector {
        let Some(pattern) = d.pattern else {
            continue; // not a Layer-1 regex rule (e.g. a sidecar/keyword entry)
        };
        let category = d
            .category
            .ok_or("detector with a pattern needs a category")?;
        let label = d.label.ok_or("detector with a pattern needs a label")?;
        specs.push(RuleSpec {
            pattern,
            category: parse_category(&category)?,
            label,
            confidence: parse_confidence(&d.confidence)?,
        });
    }
    RuleDetector::from_specs(specs)
}

fn parse_category(s: &str) -> Result<Category, String> {
    match s.to_ascii_lowercase().as_str() {
        "secret" => Ok(Category::Secret),
        "identifier" => Ok(Category::Identifier),
        "endpoint" => Ok(Category::Endpoint),
        "pii" => Ok(Category::Pii),
        "other" => Ok(Category::Other),
        other => Err(format!("unknown category: {other}")),
    }
}

fn parse_confidence(s: &str) -> Result<Confidence, String> {
    match s.to_ascii_lowercase().as_str() {
        "high" => Ok(Confidence::High),
        "medium" => Ok(Confidence::Medium),
        "low" => Ok(Confidence::Low),
        other => Err(format!("unknown confidence: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{region, Detector};
    use crate::model::*;
    use crate::normalize::NormalizedView;
    use crate::{Config, Engine, Input, MaskAll};

    const ACME: &str = r#"
        schema_version = 1
        name = "acme"
        [[detector]]
        name = "acme-account"
        pattern = '\bACC-[0-9]{10}\b'
        category = "Identifier"
        label = "ACME_ACCOUNT"
        confidence = "high"
    "#;

    #[test]
    fn loaded_rule_matches() {
        let det = load_rule_detector(ACME).unwrap();
        let raw = "id ACC-0123456789 end";
        let spans = det.detect(&NormalizedView::build(&region(raw), raw));
        assert!(
            spans
                .iter()
                .any(|s| s.label == "ACME_ACCOUNT" && s.category == Category::Identifier),
            "{spans:?}"
        );
    }

    #[test]
    fn engine_masks_with_loaded_pack() {
        let det = load_rule_detector(ACME).unwrap();
        let engine = Engine::builder()
            .detector(Box::new(det))
            .policy(Box::new(MaskAll))
            .build();
        let r = engine.mask(
            Input::text("id ACC-0123456789"),
            &Config::insecure_testing(),
        );
        assert!(r.masked.contains("<<ACME_ACCOUNT_"), "{}", r.masked);
    }

    #[test]
    fn higher_layer_entries_are_skipped_not_errors() {
        // A sidecar entry has no pattern; it is ignored, leaving zero Layer-1 rules.
        let pack = r#"
            [[detector]]
            name = "ml"
            kind = "sidecar"
            cmd = "python"
        "#;
        let det = load_rule_detector(pack).unwrap();
        let raw = "AKIAIOSFODNN7EXAMPLE";
        assert!(det
            .detect(&NormalizedView::build(&region(raw), raw))
            .is_empty());
    }

    #[test]
    fn invalid_regex_and_unknown_category_error() {
        assert!(load_rule_detector(
            r#"[[detector]]
               pattern = "("
               category = "secret"
               label = "BAD""#
        )
        .is_err());
        assert!(load_rule_detector(
            r#"[[detector]]
               pattern = "x"
               category = "nope"
               label = "X""#
        )
        .is_err());
    }
}
