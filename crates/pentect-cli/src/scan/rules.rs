use ignore::overrides::{Override, OverrideBuilder};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Rule {
    Exclude(String),
    Include(String),
}

pub(super) fn build_overrides(
    base: &Path,
    raw_rules: &[String],
) -> Result<Option<Override>, String> {
    let mut rules = Vec::new();
    for raw in raw_rules {
        rules.extend(parse_rule(raw)?);
    }
    if rules.is_empty() {
        return Ok(None);
    }

    let mut builder = OverrideBuilder::new(base);
    if rules.iter().any(|rule| matches!(rule, Rule::Include(_))) {
        builder
            .add("**")
            .map_err(|e| format!("invalid include seed: {e}"))?;
    }
    for rule in rules {
        match rule {
            Rule::Exclude(pattern) => builder
                .add(&format!("!{pattern}"))
                .map_err(|e| format!("invalid exclude pattern '{pattern}': {e}"))?,
            Rule::Include(pattern) => builder
                .add(&pattern)
                .map_err(|e| format!("invalid include pattern '{pattern}': {e}"))?,
        };
    }
    builder
        .build()
        .map(Some)
        .map_err(|e| format!("could not build scan exclude matcher: {e}"))
}

fn parse_rule(raw: &str) -> Result<Vec<Rule>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty exclude pattern".to_string());
    }
    if let Some(name) = raw.strip_prefix("!~") {
        return preset(name)
            .map(|patterns| {
                patterns
                    .iter()
                    .map(|pattern| Rule::Include((*pattern).to_string()))
                    .collect()
            })
            .ok_or_else(|| format!("unknown exclude group: ~{name}"));
    }
    if let Some(name) = raw.strip_prefix('~') {
        return preset(name)
            .map(|patterns| {
                patterns
                    .iter()
                    .map(|pattern| Rule::Exclude((*pattern).to_string()))
                    .collect()
            })
            .ok_or_else(|| format!("unknown exclude group: ~{name}"));
    }
    if let Some(pattern) = raw.strip_prefix('!') {
        if pattern.is_empty() {
            return Err("empty include pattern".to_string());
        }
        return Ok(vec![Rule::Include(pattern.to_string())]);
    }
    Ok(vec![Rule::Exclude(raw.to_string())])
}

fn preset(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "vcs" => Some(&[".git/", ".hg/", ".svn/"]),
        "deps" => Some(&["node_modules/", ".venv/", "venv/"]),
        "build" => Some(&["target/", "dist/", "build/", ".next/"]),
        "cache" => Some(&[
            "__pycache__/",
            ".pytest_cache/",
            ".mypy_cache/",
            ".ruff_cache/",
        ]),
        "pentect" => Some(&[".pentect/agent/"]),
        "heavy" => Some(&[
            "node_modules/",
            ".venv/",
            "venv/",
            "target/",
            "dist/",
            "build/",
            ".next/",
            "__pycache__/",
            ".pytest_cache/",
            ".mypy_cache/",
            ".ruff_cache/",
            ".pentect/agent/",
        ]),
        "all" => Some(&[
            ".git/",
            ".hg/",
            ".svn/",
            "node_modules/",
            ".venv/",
            "venv/",
            "target/",
            "dist/",
            "build/",
            ".next/",
            "__pycache__/",
            ".pytest_cache/",
            ".mypy_cache/",
            ".ruff_cache/",
            ".pentect/agent/",
        ]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_groups_and_restores() {
        let rules = parse_rule("~vcs").unwrap();
        assert!(rules.contains(&Rule::Exclude(".git/".to_string())));

        let rules = parse_rule("!~vcs").unwrap();
        assert!(rules.contains(&Rule::Include(".git/".to_string())));
    }

    #[test]
    fn parses_plain_include_and_exclude() {
        assert_eq!(
            parse_rule("target/").unwrap(),
            vec![Rule::Exclude("target/".to_string())]
        );
        assert_eq!(
            parse_rule("!target/keep.env").unwrap(),
            vec![Rule::Include("target/keep.env".to_string())]
        );
    }

    #[test]
    fn rejects_unknown_group() {
        assert!(parse_rule("~unknown").unwrap_err().contains("unknown"));
    }
}
