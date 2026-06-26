use pentect_core::{load_pack, Pack};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) const PACKS_ENV: &str = "PENTECT_EXTENSION_PACKS";

const PENTECT_DIR: &str = ".pentect";
const EXTENSIONS_DIR: &str = "extensions";
const CONFIG_FILE: &str = "config.toml";
const MANIFEST_FILE: &str = "extension.toml";

#[derive(Debug, Default)]
pub(crate) struct ActiveExtensions {
    pack_paths: Vec<PathBuf>,
}

impl ActiveExtensions {
    pub(crate) fn env_value(&self) -> Result<Option<OsString>, String> {
        if self.pack_paths.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.pack_paths)
            .map(Some)
            .map_err(|e| format!("could not encode extension pack paths: {e}"))
    }
}

pub(crate) fn parse_extension_value(value: &str) -> Result<Vec<String>, String> {
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
        return Err("--extensions requires at least one extension".to_string());
    }
    Ok(specs)
}

pub(crate) fn collect_from_args(args: &[String]) -> Result<Vec<String>, String> {
    let mut specs = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--extensions" {
            let Some(value) = args.get(i + 1) else {
                return Err("--extensions requires a value".to_string());
            };
            if value.starts_with("--") {
                return Err("--extensions requires a value".to_string());
            }
            extend_unique(&mut specs, parse_extension_value(value)?);
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(specs)
}

pub(crate) fn strip_from_args(args: &[String]) -> Result<(Vec<String>, Vec<String>), String> {
    match args.first().map(String::as_str) {
        Some("exec" | "approve") => strip_exec_like_args(args),
        Some("dashboard") | Some("--dir" | "--session" | "--port") | None => {
            strip_option_args(args, &["--dir", "--session", "--port"])
        }
        Some("hook") => strip_option_args(args, &["--session"]),
        _ => Ok((args.to_vec(), Vec::new())),
    }
}

fn strip_exec_like_args(args: &[String]) -> Result<(Vec<String>, Vec<String>), String> {
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
                return Err("--extensions requires a value".to_string());
            };
            if value.starts_with("--") {
                return Err("--extensions requires a value".to_string());
            }
            extend_unique(&mut specs, parse_extension_value(value)?);
            i += 2;
        } else if matches!(args[i].as_str(), "--session") {
            stripped.push(args[i].clone());
            let Some(value) = args.get(i + 1) else {
                return Err(format!("{} requires a value", args[i]));
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

fn strip_option_args(
    args: &[String],
    value_flags: &[&str],
) -> Result<(Vec<String>, Vec<String>), String> {
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
                return Err("--extensions requires a value".to_string());
            };
            if value.starts_with("--") {
                return Err("--extensions requires a value".to_string());
            }
            extend_unique(&mut specs, parse_extension_value(value)?);
            i += 2;
            continue;
        }
        stripped.push(args[i].clone());
        if value_flags.contains(&args[i].as_str()) {
            let Some(value) = args.get(i + 1) else {
                return Err(format!("{} requires a value", args[i]));
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
) -> Result<ActiveExtensions, String> {
    let mut specs = config_specs()?;
    extend_unique(&mut specs, explicit_specs);
    let pack_paths = pack_paths_for_specs(&specs, create_named)?;
    Ok(ActiveExtensions { pack_paths })
}

pub(crate) fn load_packs_from_args(
    args: &[String],
    create_named: bool,
) -> Result<Vec<Pack>, String> {
    load_packs_from_specs(collect_from_args(args)?, create_named)
}

pub(crate) fn load_packs_from_specs(
    explicit_specs: Vec<String>,
    create_named: bool,
) -> Result<Vec<Pack>, String> {
    let active = active_from_specs(explicit_specs, create_named)?;
    let mut packs = Vec::new();
    for path in active.pack_paths {
        let display = path.display();
        let src = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read extension pack '{display}': {e}"))?;
        packs.push(
            load_pack(&src).map_err(|e| format!("extension pack '{display}' is invalid: {e}"))?,
        );
    }
    Ok(packs)
}

fn config_specs() -> Result<Vec<String>, String> {
    let path = PathBuf::from(PENTECT_DIR).join(CONFIG_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let src = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    let value = src
        .parse::<toml::Value>()
        .map_err(|e| format!("could not parse '{}': {e}", path.display()))?;
    let Some(raw_extensions) = value.get("extensions") else {
        return Ok(Vec::new());
    };
    parse_config_extensions(raw_extensions)
}

fn parse_config_extensions(value: &toml::Value) -> Result<Vec<String>, String> {
    match value {
        toml::Value::String(s) => parse_extension_value(s),
        toml::Value::Array(items) => {
            let mut specs = Vec::new();
            for item in items {
                let Some(s) = item.as_str() else {
                    return Err(".pentect/config.toml extensions must be strings".to_string());
                };
                extend_unique(&mut specs, parse_extension_value(s)?);
            }
            Ok(specs)
        }
        _ => Err(".pentect/config.toml extensions must be a string or string array".to_string()),
    }
}

fn pack_paths_for_specs(specs: &[String], create_named: bool) -> Result<Vec<PathBuf>, String> {
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

fn pack_paths_for_named(name: &str, create: bool) -> Result<Vec<PathBuf>, String> {
    validate_extension_name(name)?;
    let root = extensions_root();
    let dir = root.join(name);
    if create {
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("could not create '{}': {e}", dir.display()))?;
        let manifest = dir.join(MANIFEST_FILE);
        if !manifest.exists() {
            let src = format!("name = \"{name}\"\n");
            std::fs::write(&manifest, src)
                .map_err(|e| format!("could not write '{}': {e}", manifest.display()))?;
        }
    }
    if !dir.exists() {
        return Ok(Vec::new());
    }
    pack_paths_in_extension_dir(&dir)
}

fn pack_paths_for_path(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            return Err(format!(
                "extension pack must be a .toml file: {}",
                path.display()
            ));
        }
        return canonical_file(path).map(|path| vec![path]);
    }
    if path.is_dir() {
        return pack_paths_in_extension_dir(path);
    }
    Err(format!("extension path does not exist: {}", path.display()))
}

fn pack_paths_in_extension_dir(dir: &Path) -> Result<Vec<PathBuf>, String> {
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

fn canonical_file(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|e| format!("could not resolve '{}': {e}", path.display()))
}

fn extensions_root() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(EXTENSIONS_DIR)
}

fn validate_extension_spec(spec: &str) -> Result<(), String> {
    if is_path_spec(spec) {
        return Ok(());
    }
    validate_extension_name(spec)
}

fn validate_extension_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("extension name must not be empty".to_string());
    };
    if !first.is_ascii_alphanumeric() {
        return Err(format!("invalid extension name: {name}"));
    }
    if name.len() > 64
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("invalid extension name: {name}"));
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

fn toml_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| {
        format!(
            "could not read extension directory '{}': {e}",
            dir.display()
        )
    })? {
        let path = entry
            .map_err(|e| {
                format!(
                    "could not read extension directory '{}': {e}",
                    dir.display()
                )
            })?
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
        assert!(parse_extension_value("../x.toml").is_ok());
        assert!(parse_extension_value("../x").is_ok());
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
}
