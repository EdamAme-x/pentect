use pentect_core::{DetectorId, MaskResult};

pub(crate) fn print(
    result: &MaskResult,
    profile: &str,
    kind: &str,
    decode: &pentect_core::DecodeConfig,
    aggressive: bool,
    json: bool,
) -> Result<(), String> {
    let findings = result.explain();
    let conditions = serde_json::json!({
        "profile": profile,
        "kind": kind,
        "aggressive": aggressive,
        "decode": {
            "enabled": decode.enabled,
            "max_depth": decode.max_depth,
            "min_bytes": decode.min_bytes,
            "max_bytes": decode.max_bytes,
            "max_inflate_bytes": decode.max_inflate_bytes,
            "mask_unknown": decode.mask_unknown,
            "unknown_min_bytes": decode.unknown_min_bytes,
        },
        "parser_fallback": result.summary.parser_fallback,
    });
    let mut reasons: Vec<_> = findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|item| reason(item.source)))
        .collect();
    reasons.sort_unstable();
    reasons.dedup();
    let records: Vec<_> = findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "occurrence": finding.occurrence,
                "handle": finding.handle,
                "evidence": finding.evidence.iter().map(|item| serde_json::json!({
                    "label": item.label,
                    "category": item.category,
                    "confidence": item.confidence,
                    "detector": item.source.as_str(),
                    "reason": reason(item.source),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    if json {
        let report = serde_json::json!({
            "schema": "pentect.mask-explanation.v1",
            "pentect_version": env!("CARGO_PKG_VERSION"),
            "profile": profile,
            "kind": kind,
            "masked": result.masked,
            "conditions": conditions,
            "findings": records,
            "parser_fallback": result.summary.parser_fallback,
            "warnings": result.summary.residual,
            "evidence_scope": "detector class; exact rule and plugin identity are not retained; repeated handles share all retained evidence",
            "public_report": {
                "pentect_version": env!("CARGO_PKG_VERSION"),
                "conditions": conditions,
                "reasons": reasons,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        print!("{}", result.masked);
        eprintln!(
            "[pentect] explanation: profile={profile} kind={kind}; {} masked occurrence(s)",
            findings.len()
        );
        eprintln!("[pentect] conditions: {conditions}");
        eprintln!("[pentect] evidence identifies detector classes, not exact rules or plugin names; repeated handles share retained evidence");
        for finding in findings {
            for item in finding.evidence {
                eprintln!("[pentect] occurrence {}: {} category={:?} confidence={:?} detector={} reason={}",
                    finding.occurrence, item.label, item.category, item.confidence,
                    item.source.as_str(), reason(item.source));
            }
        }
        if result.summary.parser_fallback {
            eprintln!(
                "[pentect] parser fallback: inspected as text; structural context unavailable"
            );
        }
        for warning in &result.summary.residual {
            eprintln!(
                "[pentect] warning: category={:?} detector={}",
                warning.category,
                warning.source.as_str()
            );
        }
    }
    Ok(())
}

fn reason(source: DetectorId) -> &'static str {
    match source {
        DetectorId::Explicit => "explicit-mask-marker",
        DetectorId::Plugin => "plugin-finding",
        DetectorId::CredSweeper => "credsweeper-finding",
        DetectorId::Alcatraz => "personal-data-finding",
        DetectorId::Rule => "configured-pattern",
        DetectorId::KeyValue => "sensitive-key-value",
        DetectorId::Pem => "private-key-block",
        DetectorId::Decode => "secret-in-decoded-value",
        DetectorId::Structural => "sensitive-structural-position",
        DetectorId::DecodeOpaque => "opaque-encoded-value",
        DetectorId::Sweep => "repeated-protected-value",
        DetectorId::PentectTempParser => "structural-parser-finding",
    }
}
