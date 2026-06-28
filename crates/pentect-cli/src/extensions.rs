use crate::Result;
use anyhow::{anyhow, bail, Context};
use pentect_core::{load_pack, Pack};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) const PACKS_ENV: &str = "PENTECT_EXTENSION_PACKS";

const PENTECT_DIR: &str = ".pentect";
const EXTENSIONS_DIR: &str = "extensions";
const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Default)]
pub(crate) struct ActiveExtensions {
    pack_paths: Vec<PathBuf>,
}

impl ActiveExtensions {
    pub(crate) fn env_value(&self) -> Result<Option<OsString>> {
        if self.pack_paths.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.pack_paths)
            .map(Some)
            .context("could not encode extension pack paths")
    }
}

pub(crate) fn parse_extension_value(value: &str) -> Result<Vec<String>> {
    let mut specs = Vec::new();
    for raw in value.split(',') {
        let spec = raw.trim();
        if spec.is_empty() {
            continue;
        }
        validate_extension_spec(spec)?;
        if !specs.iter().any(|existing| existing == spec) {
            specs.push(spec.to_string());
        }
    }
    if specs.is_empty() {
        bail!("--extensions requires at least one extension");
    }
    Ok(specs)
}

pub(crate) fn collect_from_args(args: &[String]) -> Result<Vec<String>> {
    let mut specs = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--extensions" {
            let Some(value) = args.get(i + 1) else {
                bail!("--extensions requires a value");
            };
            if value.starts_with("--") {
                bail!("--extensions requires a value");
            }
            extend_unique(&mut specs, parse_extension_value(value)?);
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(specs)
}

pub(crate) fn strip_from_args(args: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    match args.first().map(String::as_str) {
        Some("exec" | "approve") => strip_exec_like_args(args),
        Some("dashboard") | Some("--dir" | "--session" | "--port") | None => {
            strip_option_args(args, &["--dir", "--session", "--port"])
        }
        Some("hook") => strip_option_args(args, &["--session"]),
        _ => Ok((args.to_vec(), Vec::new())),
    }
}

fn strip_exec_like_args(args: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let mut stripped = Vec::new();
    let mut specs = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--" {
            stripped.extend(args[i..].iter().cloned());
            break;
        }
        if args[i] == "--extensions" {
            let Some(value) = args.get(i + 1) else {
                bail!("--extensions requires a value");
            };
            if value.starts_with("--") {
                bail!("--extensions requires a value");
            }
            extend_unique(&mut specs, parse_extension_value(value)?);
            i += 2;
        } else if matches!(args[i].as_str(), "--session") {
            stripped.push(args[i].clone());
            let Some(value) = args.get(i + 1) else {
                bail!("{} requires a value", args[i]);
            };
            stripped.push(value.clone());
            i += 2;
        } else if matches!(args[i].as_str(), "--live" | "--approve") || i == 0 {
            stripped.push(args[i].clone());
            i += 1;
        } else {
            stripped.extend(args[i..].iter().cloned());
            break;
        }
    }
    Ok((stripped, specs))
}

fn strip_option_args(args: &[String], value_flags: &[&str]) -> Result<(Vec<String>, Vec<String>)> {
    let mut stripped = Vec::new();
    let mut specs = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--" {
            stripped.extend(args[i..].iter().cloned());
            break;
        }
        if args[i] == "--extensions" {
            let Some(value) = args.get(i + 1) else {
                bail!("--extensions requires a value");
            };
            if value.starts_with("--") {
                bail!("--extensions requires a value");
            }
            extend_unique(&mut specs, parse_extension_value(value)?);
            i += 2;
            continue;
        }
        stripped.push(args[i].clone());
        if value_flags.contains(&args[i].as_str()) {
            let Some(value) = args.get(i + 1) else {
                bail!("{} requires a value", args[i]);
            };
            stripped.push(value.clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok((stripped, specs))
}

pub(crate) fn active_from_specs(
    explicit_specs: Vec<String>,
    create_named: bool,
) -> Result<ActiveExtensions> {
    let mut specs = config_specs()?;
    extend_unique(&mut specs, explicit_specs);
    let pack_paths = pack_paths_for_specs(&specs, create_named)?;
    Ok(ActiveExtensions { pack_paths })
}

pub(crate) fn load_packs_from_args(args: &[String], create_named: bool) -> Result<Vec<Pack>> {
    load_packs_from_specs(collect_from_args(args)?, create_named)
}

pub(crate) fn load_packs_from_specs(
    explicit_specs: Vec<String>,
    create_named: bool,
) -> Result<Vec<Pack>> {
    let active = active_from_specs(explicit_specs, create_named)?;
    let mut packs = Vec::new();
    for path in active.pack_paths {
        let display = path.display();
        let src = std::fs::read_to_string(&path)
            .with_context(|| format!("could not read extension pack '{display}'"))?;
        let pack =
            load_pack(&src).map_err(|e| anyhow!("extension pack '{display}' is invalid: {e}"))?;
        if !pack.disable.is_empty() {
            bail!("extension pack '{display}' may add detectors but must not disable built-ins");
        }
        packs.push(pack);
    }
    Ok(packs)
}

fn config_specs() -> Result<Vec<String>> {
    let path = PathBuf::from(PENTECT_DIR).join(CONFIG_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let src = std::fs::read_to_string(&path)
        .with_context(|| format!("could not read '{}'", path.display()))?;
    let value = src
        .parse::<toml::Value>()
        .with_context(|| format!("could not parse '{}'", path.display()))?;
    let Some(raw_extensions) = value.get("extensions") else {
        return Ok(Vec::new());
    };
    parse_config_extensions(raw_extensions)
}

fn parse_config_extensions(value: &toml::Value) -> Result<Vec<String>> {
    match value {
        toml::Value::String(s) => parse_extension_value(s),
        toml::Value::Array(items) => {
            let mut specs = Vec::new();
            for item in items {
                let Some(s) = item.as_str() else {
                    bail!(".pentect/config.toml extensions must be strings");
                };
                extend_unique(&mut specs, parse_extension_value(s)?);
            }
            Ok(specs)
        }
        _ => bail!(".pentect/config.toml extensions must be a string or string array"),
    }
}

fn pack_paths_for_specs(specs: &[String], create_named: bool) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for spec in specs {
        if is_path_spec(spec) {
            paths.extend(pack_paths_for_path(Path::new(spec))?);
        } else {
            paths.extend(pack_paths_for_named(spec, create_named)?);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn pack_paths_for_named(name: &str, _create: bool) -> Result<Vec<PathBuf>> {
    validate_extension_name(name)?;
    let root = extensions_root();
    let dir = root.join(name);
    if !dir.exists() {
        bail!("extension '{name}' was not found at '{}'", dir.display());
    }
    let paths = pack_paths_in_extension_dir(&dir)?;
    if paths.is_empty() {
        bail!(
            "extension '{name}' has no rule packs; add '{}' or '{}'",
            dir.join("pack.toml").display(),
            dir.join("packs").display()
        );
    }
    Ok(paths)
}

fn pack_paths_for_path(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            bail!("extension pack must be a .toml file: {}", path.display());
        }
        return canonical_file(path).map(|path| vec![path]);
    }
    if path.is_dir() {
        return pack_paths_in_extension_dir(path);
    }
    bail!("extension path does not exist: {}", path.display())
}

fn pack_paths_in_extension_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let pack = dir.join("pack.toml");
    if pack.exists() {
        paths.push(canonical_file(&pack)?);
    }
    let packs_dir = dir.join("packs");
    if packs_dir.exists() {
        paths.extend(toml_files_in_dir(&packs_dir)?);
    }
    paths.sort();
    Ok(paths)
}

fn canonical_file(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("could not resolve '{}'", path.display()))
}

fn extensions_root() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(EXTENSIONS_DIR)
}

fn validate_extension_spec(spec: &str) -> Result<()> {
    if is_path_spec(spec) {
        if Path::new(spec)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            bail!("extension paths must not contain '..': {spec}");
        }
        return Ok(());
    }
    validate_extension_name(spec)
}

fn validate_extension_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        bail!("extension name must not be empty");
    };
    if !first.is_ascii_alphanumeric() {
        bail!("invalid extension name: {name}");
    }
    if name.len() > 64
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        bail!("invalid extension name: {name}");
    }
    Ok(())
}

fn is_path_spec(spec: &str) -> bool {
    let path = Path::new(spec);
    path.is_absolute()
        || spec.ends_with(".toml")
        || spec.contains('/')
        || spec.contains('\\')
        || spec.starts_with('.')
}

fn toml_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("could not read extension directory '{}'", dir.display()))?
    {
        let path = entry
            .with_context(|| format!("could not read extension directory '{}'", dir.display()))?
            .path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            files.push(canonical_file(&path)?);
        }
    }
    files.sort();
    Ok(files)
}

fn extend_unique(target: &mut Vec<String>, items: Vec<String>) {
    for item in items {
        if !target.iter().any(|existing| existing == &item) {
            target.push(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extension_names_and_paths() {
        assert_eq!(
            parse_extension_value("openai-privacy-filter,local.rules,./rules.toml").unwrap(),
            vec!["openai-privacy-filter", "local.rules", "./rules.toml"]
        );
        assert!(parse_extension_value("../x.toml").is_err());
        assert!(parse_extension_value("../x").is_err());
        assert!(parse_extension_value("").is_err());
    }

    #[test]
    fn strip_extensions_does_not_touch_command_arguments() {
        let args = vec![
            "exec".to_string(),
            "--extensions".to_string(),
            "rules".to_string(),
            "--".to_string(),
            "--extensions".to_string(),
            "literal".to_string(),
        ];
        let (stripped, specs) = strip_from_args(&args).unwrap();
        assert_eq!(specs, ["rules"]);
        assert_eq!(
            stripped,
            vec![
                "exec".to_string(),
                "--".to_string(),
                "--extensions".to_string(),
                "literal".to_string()
            ]
        );

        let args = vec!["exec".to_string(), "rg --extensions literal".to_string()];
        let (stripped, specs) = strip_from_args(&args).unwrap();
        assert!(specs.is_empty());
        assert_eq!(stripped, args);

        let args = vec![
            "exec".to_string(),
            "--live".to_string(),
            "--extensions".to_string(),
            "rules".to_string(),
            "Write-Output ok".to_string(),
        ];
        let (stripped, specs) = strip_from_args(&args).unwrap();
        assert_eq!(specs, ["rules"]);
        assert_eq!(
            stripped,
            vec![
                "exec".to_string(),
                "--live".to_string(),
                "Write-Output ok".to_string()
            ]
        );
    }

    #[test]
    fn strip_extensions_from_dashboard_options_after_values() {
        let args = vec![
            "--dir".to_string(),
            "work".to_string(),
            "--extensions".to_string(),
            "rules".to_string(),
            "--port".to_string(),
            "7331".to_string(),
        ];
        let (stripped, specs) = strip_from_args(&args).unwrap();
        assert_eq!(specs, ["rules"]);
        assert_eq!(
            stripped,
            vec![
                "--dir".to_string(),
                "work".to_string(),
                "--port".to_string(),
                "7331".to_string()
            ]
        );
    }

    #[test]
    fn named_extension_missing_is_an_error() {
        let name = format!(
            "missing-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let err = pack_paths_for_named(&name, true).unwrap_err().to_string();
        assert!(err.contains("was not found"), "{err}");
    }
}
