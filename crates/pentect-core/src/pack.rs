use crate::detect::{RuleDetector, RuleSpec};
use crate::model::{Category, Confidence};
use serde::Deserialize;

/// A loaded Layer-1 rule pack: pure data, no code. Carries extra regex/keyword
/// rules and a list of built-in labels to turn off. (No key-name vocabulary —
/// open-vocabulary key sensitivity is a model's job, not a hardcoded list's.)
#[derive(Clone)]
pub struct Pack {
    pub rules: RuleDetector,
    /// Built-in (or other) labels this pack suppresses, e.g. `IP_ADDRESS_V4`.
    pub disable: Vec<String>,
}

/// Parse a TOML rule pack. Two knobs cover the real demand: add your own rules
/// (`[[detector]]` with `keywords = [...]` literals, or a regex `pattern` plus an
/// optional checksum `validator`, `capture` group, or `prefilter` literals), and
/// turn built-ins off (`disable = ["LABEL"]`). Errors on malformed TOML,
/// unsupported pack fields, detector entries without a `pattern` or non-empty
/// `keywords`, an unknown category / confidence / validator, an invalid regex,
/// or a missing capture group.
pub fn load_pack(toml_src: &str) -> Result<Pack, String> {
    let pack: PackFile = toml::from_str(toml_src).map_err(|e| e.to_string())?;
    let mut specs = Vec::new();
    for d in pack.detector {
        // `pattern` (regex, for power users) OR `keywords` (plain literal strings,
        // for anyone): a non-expert just lists company terms / internal hosts.
        let pattern = match (d.pattern, d.keywords) {
            (Some(p), _) => p,
            (None, Some(kw)) if !kw.is_empty() => keyword_regex(&kw),
            _ => return Err("detector entry requires pattern or non-empty keywords".to_string()),
        };
        // Sensible defaults so the minimal entry is just a keyword list: mask
        // (Secret) under a CUSTOM label.
        let category = parse_category(d.category.as_deref().unwrap_or("secret"))?;
        let label = d
            .label
            .map_or_else(|| "CUSTOM".to_string(), |l| safe_label(&l));
        let validator = match d.validator.as_deref() {
            None => crate::detect::Validator::None,
            Some(name) => crate::detect::Validator::from_name(name)
                .ok_or_else(|| format!("unknown validator: {name}"))?,
        };
        specs.push(RuleSpec {
            pattern,
            category,
            label,
            confidence: parse_confidence(&d.confidence)?,
            validator,
            context: Default::default(),
            capture: d.capture.unwrap_or(0),
            prefilter: d.prefilter.unwrap_or_default(),
        });
    }
    Ok(Pack {
        rules: RuleDetector::from_specs(specs)?,
        disable: pack.disable,
    })
}

/// Parse only inline detector entries from a `plugin.toml` manifest.
///
/// Plugin metadata, setup commands, and release artifacts are deliberately not
/// part of the rule-pack schema. Keeping only `detector` also means an inline
/// regex plugin cannot disable Pentect's built-in detectors.
pub fn load_plugin_pack(toml_src: &str) -> Result<Pack, String> {
    let manifest: toml::Value = toml::from_str(toml_src).map_err(|e| e.to_string())?;
    if manifest.get("schema").and_then(toml::Value::as_str) != Some("pentect.plugin.v1") {
        return Err("plugin.toml requires schema = \"pentect.plugin.v1\"".to_string());
    }
    let detectors = manifest
        .get("detector")
        .cloned()
        .ok_or_else(|| "plugin manifest has no [[detector]] entries".to_string())?;
    let Some(entries) = detectors.as_array() else {
        return Err("plugin manifest detector must be an array of tables".to_string());
    };
    if entries.is_empty() {
        return Err("plugin manifest has no [[detector]] entries".to_string());
    }
    if entries.iter().any(|entry| {
        entry
            .as_table()
            .and_then(|table| table.get("pattern"))
            .and_then(toml::Value::as_str)
            .is_none_or(str::is_empty)
    }) {
        return Err("plugin.toml inline detectors require a non-empty regex pattern".to_string());
    }
    let mut pack = toml::map::Map::new();
    pack.insert("detector".to_string(), detectors);
    let source = toml::to_string(&toml::Value::Table(pack)).map_err(|e| e.to_string())?;
    load_pack(&source)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    #[serde(default)]
    detector: Vec<DetectorEntry>,
    /// Built-in detector labels to turn off (e.g. `disable = ["IP_ADDRESS_V4"]`).
    #[serde(default)]
    disable: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorEntry {
    /// Regex (power users). Mutually exclusive-ish with `keywords`.
    pattern: Option<String>,
    /// Plain literal strings to mask — no regex knowledge needed. Matched
    /// case-insensitively as exact substrings.
    keywords: Option<Vec<String>>,
    category: Option<String>,
    label: Option<String>,
    #[serde(default = "default_confidence")]
    confidence: String,
    /// Optional checksum gate by name (e.g. "luhn", "iban_mod97", "verhoeff"),
    /// so a pack can add a precision-gated detector, not just a bare regex.
    validator: Option<String>,
    /// 0 or absent masks the full match; N masks capture group N.
    capture: Option<usize>,
    /// Optional literals that must be present before this regex is run.
    prefilter: Option<Vec<String>>,
}

fn default_confidence() -> String {
    "high".to_string()
}

/// Build a case-insensitive alternation of escaped literals (no regex knowledge
/// required from the pack author).
fn keyword_regex(keywords: &[String]) -> String {
    let alts: Vec<String> = keywords.iter().map(|k| regex::escape(k)).collect();
    format!("(?i)(?:{})", alts.join("|"))
}

/// Coerce a user label into a well-formed UPPER_SNAKE placeholder label, so a
/// casual `label = "internal host"` still renders as `<<INTERNAL_HOST_...>>`.
fn safe_label(s: &str) -> String {
    let up: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = up.trim_matches('_');
    match trimmed.chars().next() {
        Some(c) if c.is_ascii_alphabetic() => trimmed.replace("__", "_"),
        _ => "CUSTOM".to_string(),
    }
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

    #[test]
    fn plugin_manifest_loads_inline_detectors_only() {
        let pack = load_plugin_pack(
            r#"
schema = "pentect.plugin.v1"
name = "inline"

[[postscript]]
command = ["ignored"]

[[detector]]
pattern = "secret-[0-9]+"
label = "INLINE_SECRET"
"#,
        )
        .unwrap();
        assert!(pack.disable.is_empty());
    }

    #[test]
    fn plugin_manifest_requires_schema_and_regex_patterns() {
        assert!(load_plugin_pack(
            r#"
[[detector]]
pattern = "secret"
"#
        )
        .is_err());
        assert!(load_plugin_pack(
            r#"
schema = "pentect.plugin.v1"
[[detector]]
keywords = ["secret"]
"#
        )
        .is_err());
    }
    use crate::detect::{region, Detector};
    use crate::model::*;
    use crate::normalize::NormalizedView;
    use crate::{Config, Engine, Input, MaskAll, Profile};

    const ACME: &str = r#"
        [[detector]]
        pattern = '\bACC-[0-9]{10}\b'
        category = "Identifier"
        label = "ACME_ACCOUNT"
        confidence = "high"
    "#;

    #[test]
    fn loaded_rule_matches() {
        let pack = load_pack(ACME).unwrap();
        let raw = "id ACC-0123456789 end";
        let spans = pack.rules.detect(&NormalizedView::build(&region(raw), raw));
        assert!(
            spans
                .iter()
                .any(|s| s.label == "ACME_ACCOUNT" && s.category == Category::Identifier),
            "{spans:?}"
        );
    }

    #[test]
    fn pack_validator_gates_matches() {
        // A pack can add a checksum-gated detector from data: only a Luhn-valid
        // number is flagged.
        let pack = load_pack(
            r#"[[detector]]
               pattern = '\b[0-9]{16}\b'
               category = "Pii"
               label = "MY_CARD"
               validator = "luhn""#,
        )
        .unwrap();
        let hit = |raw: &str| {
            pack.rules
                .detect(&NormalizedView::build(&region(raw), raw))
                .iter()
                .any(|s| s.label == "MY_CARD")
        };
        assert!(hit("4242424242424242")); // valid Luhn
        assert!(!hit("4242424242424243")); // fails Luhn
        assert!(load_pack(
            r#"[[detector]]
               pattern = "x"
               category = "secret"
               label = "X"
               validator = "nope""#
        )
        .is_err());
    }

    #[test]
    fn pack_capture_masks_only_selected_group() {
        let pack = load_pack(
            r#"[[detector]]
               pattern = '(?i)api[_-]?key\s*=\s*([A-Za-z0-9]{12})'
               category = "Secret"
               label = "API_KEY"
               capture = 1"#,
        )
        .unwrap();
        let engine = Engine::builder()
            .detector(Box::new(pack.rules))
            .policy(Box::new(MaskAll))
            .build();
        let out = engine
            .mask(
                Input::text("api_key = ABCDEFGH1234"),
                &Config::insecure_testing(),
            )
            .masked;
        assert!(out.contains("api_key = "), "{out}");
        assert!(!out.contains("ABCDEFGH1234"), "{out}");
        assert!(out.contains("<<API_KEY_"), "{out}");
    }

    #[test]
    fn pack_prefilter_runs_rule_only_when_literal_is_present() {
        let pack = load_pack(
            r#"[[detector]]
               pattern = '(?i)acme.{0,20}([A-Za-z0-9]{12})'
               label = "ACME_TOKEN"
               capture = 1
               prefilter = ["acme"]"#,
        )
        .unwrap();
        let hit = |raw: &str| {
            pack.rules
                .detect(&NormalizedView::build(&region(raw), raw))
                .iter()
                .any(|s| s.label == "ACME_TOKEN")
        };
        assert!(!hit("token ABCDEFGH1234"));
        assert!(hit("acme token ABCDEFGH1234"));
    }

    #[test]
    fn minimal_keyword_pack_needs_no_regex_knowledge() {
        // The simplest thing a non-expert can write: just a list of company terms.
        let pack = load_pack(
            r#"[[detector]]
               keywords = ["Project Titan", "vault.acme.internal"]"#,
        )
        .unwrap();
        let hit = |raw: &str, label: &str| {
            pack.rules
                .detect(&NormalizedView::build(&region(raw), raw))
                .iter()
                .any(|s| s.label == label)
        };
        assert!(hit("notes about Project Titan here", "CUSTOM"));
        assert!(hit("connect to VAULT.ACME.INTERNAL", "CUSTOM")); // case-insensitive
        assert!(!hit("nothing sensitive", "CUSTOM"));

        // A casual label is coerced into a valid placeholder label.
        let p2 = load_pack(
            r#"[[detector]]
               keywords = ["acme"]
               label = "internal host""#,
        )
        .unwrap();
        assert!(p2
            .rules
            .detect(&NormalizedView::build(&region("acme"), "acme"))
            .iter()
            .any(|s| s.label == "INTERNAL_HOST"));
    }

    #[test]
    fn pack_disables_a_builtin_label() {
        let off = load_pack(r#"disable = ["IP_ADDRESS_V4"]"#).unwrap();
        assert_eq!(off.disable, ["IP_ADDRESS_V4"]);
        let input = || Input::text("ping 192.168.1.1 then card 4242424242424242");
        let cfg = Config::insecure_testing();

        // Control: by default the IP is masked.
        let base = Engine::with_profile_and_packs(Profile::Strict, vec![], false);
        assert!(!base.mask(input(), &cfg).masked.contains("192.168.1.1"));

        // With the pack, the IP passes through but the card is still masked.
        let tuned = Engine::with_profile_and_packs(Profile::Strict, vec![off], false);
        let out = tuned.mask(input(), &cfg).masked;
        assert!(out.contains("192.168.1.1"), "{out}");
        assert!(out.contains("<<CARD_"), "{out}");
    }

    #[test]
    fn engine_masks_with_loaded_pack() {
        let pack = load_pack(ACME).unwrap();
        let engine = Engine::builder()
            .detector(Box::new(pack.rules))
            .policy(Box::new(MaskAll))
            .build();
        let r = engine.mask(
            Input::text("id ACC-0123456789"),
            &Config::insecure_testing(),
        );
        assert!(r.masked.contains("<<ACME_ACCOUNT_"), "{}", r.masked);
    }

    #[test]
    fn rejects_unknown_detector_fields() {
        let pack = r#"
            [[detector]]
            name = "ml"
            kind = "model"
            cmd = "python"
        "#;
        assert!(load_pack(pack).is_err());
    }

    #[test]
    fn rejects_unsupported_old_pack_fields() {
        assert!(load_pack(
            r#"schema_version = 1
               [[detector]]
               pattern = "x""#
        )
        .is_err());
        assert!(load_pack(
            r#"name = "acme"
               [[detector]]
               pattern = "x""#
        )
        .is_err());
        assert!(load_pack(
            r#"[[detector]]
               name = "acme-account"
               pattern = "x""#
        )
        .is_err());
    }

    #[test]
    fn rejects_detector_entries_without_rules() {
        assert!(load_pack(r#"[[detector]]"#).is_err());
        assert!(load_pack(
            r#"[[detector]]
               keywords = []"#
        )
        .is_err());
    }

    #[test]
    fn invalid_regex_and_unknown_category_error() {
        assert!(load_pack(
            r#"[[detector]]
               pattern = "("
               category = "secret"
               label = "BAD""#
        )
        .is_err());
        assert!(load_pack(
            r#"[[detector]]
               pattern = "x"
               category = "nope"
               label = "X""#
        )
        .is_err());
    }
}
