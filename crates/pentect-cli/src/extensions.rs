use crate::Result;
use anyhow::{anyhow, bail, Context};
use pentect_core::{load_pack, Pack};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub(crate) const CONFIGS_ENV: &str = "PENTECT_EXTENSION_CONFIGS";
pub(crate) const ADAPTERS_ENV: &str = "PENTECT_EXTENSION_ADAPTERS";

const PENTECT_DIR: &str = ".pentect";
const EXTENSIONS_DIR: &str = "extensions";
const EXTENSIONS_CACHE_DIR: &str = "extension-cache";
const PENTECT_CONFIG_FILE: &str = "config.toml";
const EXTENSION_CONFIG_FILE: &str = "config.toml";
const EXTENSION_CONFIGS_DIR: &str = "configs";
const OFFICIAL_EXTENSIONS_DIR: &str = "extensions";
const DEFAULT_REMOTE_EXTENSIONS_BASE: &str =
    "https://raw.githubusercontent.com/EdamAme-x/pentect/main/extensions";
const REMOTE_EXTENSION_TIMEOUT: Duration = Duration::from_secs(8);
const REMOTE_EXTENSION_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Debug, Default)]
pub(crate) struct ActiveExtensions {
    config_paths: Vec<PathBuf>,
    adapter_paths: Vec<PathBuf>,
}

impl ActiveExtensions {
    pub(crate) fn config_paths(&self) -> &[PathBuf] {
        &self.config_paths
    }

    pub(crate) fn adapter_paths(&self) -> &[PathBuf] {
        &self.adapter_paths
    }

    pub(crate) fn config_env_value(&self) -> Result<Option<OsString>> {
        if self.config_paths.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.config_paths)
            .map(Some)
            .context("could not encode extension config paths")
    }

    pub(crate) fn adapter_env_value(&self) -> Result<Option<OsString>> {
        if self.adapter_paths.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.adapter_paths)
            .map(Some)
            .context("could not encode extension adapter paths")
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
    active_from_explicit_specs(specs, create_named)
}

pub(crate) fn active_from_explicit_specs(
    specs: Vec<String>,
    create_named: bool,
) -> Result<ActiveExtensions> {
    let (config_paths, adapter_paths) = extension_paths_for_specs(&specs, create_named)?;
    Ok(ActiveExtensions {
        config_paths,
        adapter_paths,
    })
}

pub(crate) fn load_config_packs_from_args(
    args: &[String],
    create_named: bool,
) -> Result<Vec<Pack>> {
    load_config_packs_from_specs(collect_from_args(args)?, create_named)
}

pub(crate) fn load_config_packs_from_specs(
    explicit_specs: Vec<String>,
    create_named: bool,
) -> Result<Vec<Pack>> {
    let active = active_from_specs(explicit_specs, create_named)?;
    if !active.adapter_paths.is_empty() {
        bail!("model adapter extensions are only used by agent tool-boundary commands");
    }
    load_config_packs_from_active(&active)
}

pub(crate) fn load_config_packs_from_active(active: &ActiveExtensions) -> Result<Vec<Pack>> {
    let mut packs = Vec::new();
    for path in active.config_paths() {
        let display = path.display();
        let src = std::fs::read_to_string(path)
            .with_context(|| format!("could not read extension config '{display}'"))?;
        let pack =
            load_pack(&src).map_err(|e| anyhow!("extension config '{display}' is invalid: {e}"))?;
        if !pack.disable.is_empty() {
            bail!("extension config '{display}' may add detectors but must not disable built-ins");
        }
        packs.push(pack);
    }
    Ok(packs)
}

fn config_specs() -> Result<Vec<String>> {
    let path = PathBuf::from(PENTECT_DIR).join(PENTECT_CONFIG_FILE);
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

fn extension_paths_for_specs(
    specs: &[String],
    create_named: bool,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut configs = Vec::new();
    let mut adapters = Vec::new();
    for spec in specs {
        if is_url_spec(spec) {
            let found = extension_paths_for_url(spec)?;
            configs.extend(found.config_paths);
            adapters.extend(found.adapter_paths);
        } else if is_path_spec(spec) {
            let found = extension_paths_for_path(Path::new(spec))?;
            configs.extend(found.config_paths);
            adapters.extend(found.adapter_paths);
        } else {
            let found = extension_paths_for_named(spec, create_named)?;
            configs.extend(found.config_paths);
            adapters.extend(found.adapter_paths);
        }
    }
    configs.sort();
    configs.dedup();
    adapters.sort();
    adapters.dedup();
    Ok((configs, adapters))
}

#[derive(Debug, Default)]
struct ExtensionPaths {
    config_paths: Vec<PathBuf>,
    adapter_paths: Vec<PathBuf>,
}

fn extension_paths_for_named(name: &str, _create: bool) -> Result<ExtensionPaths> {
    validate_extension_name(name)?;
    let project_dir = extensions_root().join(name);
    let official_dir = official_extensions_root().join(name);

    if project_dir.is_dir() {
        let paths = extension_paths_in_dir(&project_dir)?;
        if !paths.is_empty() {
            return Ok(paths);
        }
    }

    if official_dir.is_dir() {
        let paths = extension_paths_in_dir(&official_dir)?;
        if !paths.is_empty() {
            return Ok(paths);
        }
    }

    let remote_error = if remote_extensions_enabled() {
        match remote_extension_paths_for_name(name) {
            Ok(paths) if !paths.is_empty() => return Ok(paths),
            Ok(_) => None,
            Err(e) => Some(e),
        }
    } else {
        None
    };
    if project_dir.is_dir() || official_dir.is_dir() {
        let suggestion_dir = if project_dir.is_dir() {
            &project_dir
        } else {
            &official_dir
        };
        let mut message = format!(
            "extension '{name}' has no configs or adapters; add '{}', '{}', '{}', or '{}'",
            suggestion_dir.join(EXTENSION_CONFIG_FILE).display(),
            suggestion_dir.join(EXTENSION_CONFIGS_DIR).display(),
            suggestion_dir.join("adapter.toml").display(),
            suggestion_dir.join("adapters").display()
        );
        if let Some(error) = remote_error {
            message.push_str(&format!("; remote lookup failed: {error}"));
        }
        bail!(message);
    }

    let mut message = format!(
        "extension '{name}' was not found at '{}' or '{}'",
        project_dir.display(),
        official_dir.display()
    );
    if let Some(error) = remote_error {
        message.push_str(&format!("; remote lookup failed: {error}"));
    }
    bail!(message)
}

fn extension_paths_for_url(url: &str) -> Result<ExtensionPaths> {
    let normalized = normalize_github_extension_url(url)?;
    if normalized.ends_with(".toml") {
        let mut paths = ExtensionPaths::default();
        let file = fetch_remote_extension_file(&normalized)?
            .ok_or_else(|| anyhow!("remote extension file was not found: {normalized}"))?;
        if looks_like_adapter_url(&normalized) {
            paths.adapter_paths.push(file);
        } else {
            paths.config_paths.push(file);
        }
        return Ok(paths);
    }
    remote_extension_paths_for_base_url(&normalized)
}

fn extension_paths_for_path(path: &Path) -> Result<ExtensionPaths> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            bail!("extension config must be a .toml file: {}", path.display());
        }
        let mut paths = ExtensionPaths::default();
        let file = canonical_file(path)?;
        if looks_like_adapter_file(path) {
            paths.adapter_paths.push(file);
        } else {
            paths.config_paths.push(file);
        }
        return Ok(paths);
    }
    if path.is_dir() {
        return extension_paths_in_dir(path);
    }
    bail!("extension path does not exist: {}", path.display())
}

fn extension_paths_in_dir(dir: &Path) -> Result<ExtensionPaths> {
    let mut paths = ExtensionPaths::default();
    let config = dir.join(EXTENSION_CONFIG_FILE);
    if config.exists() {
        paths.config_paths.push(canonical_file(&config)?);
    }
    let configs_dir = dir.join(EXTENSION_CONFIGS_DIR);
    if configs_dir.exists() {
        paths.config_paths.extend(toml_files_in_dir(&configs_dir)?);
    }
    let adapter = dir.join("adapter.toml");
    if adapter.exists() {
        paths.adapter_paths.push(canonical_file(&adapter)?);
    }
    let adapters_dir = dir.join("adapters");
    if adapters_dir.exists() {
        paths
            .adapter_paths
            .extend(toml_files_in_dir(&adapters_dir)?);
    }
    paths.config_paths.sort();
    paths.adapter_paths.sort();
    Ok(paths)
}

impl ExtensionPaths {
    fn is_empty(&self) -> bool {
        self.config_paths.is_empty() && self.adapter_paths.is_empty()
    }
}

fn canonical_file(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("could not resolve '{}'", path.display()))
}

fn extensions_root() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(EXTENSIONS_DIR)
}

fn official_extensions_root() -> PathBuf {
    PathBuf::from(OFFICIAL_EXTENSIONS_DIR)
}

fn looks_like_adapter_file(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("adapter.toml")
        || path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            == Some("adapters")
}

fn validate_extension_spec(spec: &str) -> Result<()> {
    if is_url_spec(spec) {
        normalize_github_extension_url(spec).map(|_| ())?;
        return Ok(());
    }
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

fn is_url_spec(spec: &str) -> bool {
    spec.starts_with("https://github.com/")
        || spec.starts_with("https://raw.githubusercontent.com/")
}

fn remote_extension_paths_for_name(name: &str) -> Result<ExtensionPaths> {
    remote_extension_paths_for_base_url(&format!("{DEFAULT_REMOTE_EXTENSIONS_BASE}/{name}"))
}

fn remote_extension_paths_for_base_url(base_url: &str) -> Result<ExtensionPaths> {
    let mut paths = ExtensionPaths::default();
    if let Some(config) = fetch_remote_extension_file(&format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        EXTENSION_CONFIG_FILE
    ))? {
        paths.config_paths.push(config);
    }
    if let Some(adapter) =
        fetch_remote_extension_file(&format!("{}/adapter.toml", base_url.trim_end_matches('/')))?
    {
        paths.adapter_paths.push(adapter);
    }
    if paths.is_empty() {
        bail!("remote extension has no config.toml or adapter.toml: {base_url}");
    }
    Ok(paths)
}

fn fetch_remote_extension_file(url: &str) -> Result<Option<PathBuf>> {
    let path = remote_cache_file(url);
    if cached_remote_extension_is_fresh(&path) {
        return Ok(Some(path));
    }
    let response = reqwest::blocking::Client::builder()
        .timeout(REMOTE_EXTENSION_TIMEOUT)
        .build()
        .context("could not create extension HTTP client")?
        .get(url)
        .send()
        .with_context(|| format!("could not fetch extension '{url}'"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("could not fetch extension '{url}': HTTP {status}");
    }
    let bytes = response
        .bytes()
        .with_context(|| format!("could not read extension '{url}'"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create extension cache '{}'", parent.display()))?;
    }
    std::fs::write(&path, &bytes)
        .with_context(|| format!("could not write extension cache '{}'", path.display()))?;
    Ok(Some(path))
}

fn cached_remote_extension_is_fresh(path: &Path) -> bool {
    let Ok(modified) = path.metadata().and_then(|metadata| metadata.modified()) else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age < REMOTE_EXTENSION_CACHE_TTL)
}

fn remote_cache_file(url: &str) -> PathBuf {
    let mut hash = Sha256::new();
    hash.update(url.as_bytes());
    let digest = hash.finalize();
    let hex = data_encoding::HEXLOWER.encode(&digest[..16]);
    let filename = url
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("extension.toml");
    PathBuf::from(PENTECT_DIR)
        .join(EXTENSIONS_CACHE_DIR)
        .join(hex)
        .join(filename)
}

fn normalize_github_extension_url(url: &str) -> Result<String> {
    if let Some(rest) = url.strip_prefix("https://raw.githubusercontent.com/") {
        if rest.split('/').count() < 4 {
            bail!("GitHub raw extension URL is incomplete: {url}");
        }
        return Ok(url.trim_end_matches('/').to_string());
    }
    let Some(rest) = url.strip_prefix("https://github.com/") else {
        bail!("extensions can only be fetched from GitHub HTTPS URLs");
    };
    let parts = rest.split('/').collect::<Vec<_>>();
    if parts.len() < 5 {
        bail!("GitHub extension URL must point to a blob or tree path: {url}");
    }
    let owner = parts[0];
    let repo = parts[1];
    let mode = parts[2];
    let reference = parts[3];
    let path = parts[4..].join("/");
    match mode {
        "blob" | "tree" => Ok(format!(
            "https://raw.githubusercontent.com/{owner}/{repo}/{reference}/{}",
            path.trim_end_matches('/')
        )),
        _ => bail!("GitHub extension URL must use /blob/ or /tree/: {url}"),
    }
}

fn looks_like_adapter_url(url: &str) -> bool {
    url.rsplit('/').next() == Some("adapter.toml")
        || url
            .trim_end_matches('/')
            .rsplit_once('/')
            .is_some_and(|(parent, _)| parent.ends_with("/adapters"))
}

#[cfg(not(test))]
fn remote_extensions_enabled() -> bool {
    true
}

#[cfg(test)]
fn remote_extensions_enabled() -> bool {
    false
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
        let err = extension_paths_for_named(&name, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("was not found"), "{err}");
    }

    #[test]
    fn github_extension_urls_normalize_to_raw_urls() {
        assert_eq!(
            normalize_github_extension_url(
                "https://github.com/EdamAme-x/pentect/blob/main/extensions/company/config.toml"
            )
            .unwrap(),
            "https://raw.githubusercontent.com/EdamAme-x/pentect/main/extensions/company/config.toml"
        );
        assert_eq!(
            normalize_github_extension_url(
                "https://github.com/EdamAme-x/pentect/tree/main/extensions/company"
            )
            .unwrap(),
            "https://raw.githubusercontent.com/EdamAme-x/pentect/main/extensions/company"
        );
        assert_eq!(
            normalize_github_extension_url(
                "https://raw.githubusercontent.com/EdamAme-x/pentect/main/extensions/company/config.toml"
            )
            .unwrap(),
            "https://raw.githubusercontent.com/EdamAme-x/pentect/main/extensions/company/config.toml"
        );
        assert!(normalize_github_extension_url("https://example.com/company/config.toml").is_err());
        assert!(
            normalize_github_extension_url("https://raw.githubusercontent.com/owner/repo").is_err()
        );
    }

    #[test]
    fn empty_project_extension_does_not_shadow_official_extension() {
        let name = format!("shadow-test-{}", std::process::id());
        let project = PathBuf::from(".pentect").join("extensions").join(&name);
        let official = PathBuf::from("extensions").join(&name);
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&official);
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&official).unwrap();
        std::fs::write(official.join("config.toml"), "").unwrap();

        let paths = extension_paths_for_named(&name, true).unwrap();
        let expected = official.join("config.toml").canonicalize().unwrap();

        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&official);

        assert_eq!(paths.config_paths, vec![expected]);
        assert!(paths.adapter_paths.is_empty());
    }

    #[test]
    fn official_openai_privacy_filter_is_model_adapter() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        let opf = repo.join("extensions").join("openai-privacy-filter");
        let active = active_from_explicit_specs(vec![opf.display().to_string()], true).unwrap();
        assert!(active.config_paths().is_empty());
        assert_eq!(active.adapter_paths().len(), 1);
        assert!(active.adapter_paths()[0].ends_with("adapter.toml"));
    }

    #[test]
    fn directory_extensions_can_contain_configs_and_adapters() {
        let root =
            std::env::temp_dir().join(format!("pentect-extension-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("config.toml"), "").unwrap();
        std::fs::write(root.join("adapter.toml"), "").unwrap();

        let paths = extension_paths_for_path(&root).unwrap();
        assert_eq!(
            paths.config_paths,
            vec![root.join("config.toml").canonicalize().unwrap()]
        );
        assert_eq!(
            paths.adapter_paths,
            vec![root.join("adapter.toml").canonicalize().unwrap()]
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn adapter_only_extensions_are_rejected_for_pack_only_loading() {
        let root =
            std::env::temp_dir().join(format!("pentect-adapter-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("adapter.toml"), "").unwrap();

        let err = match load_config_packs_from_specs(vec![root.display().to_string()], true) {
            Ok(_) => panic!("expected adapter-only extension to be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("model adapter extensions"), "{err}");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_loader_ignores_adapter_paths_for_config_packs() {
        let root =
            std::env::temp_dir().join(format!("pentect-active-adapter-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("adapter.toml"), "").unwrap();

        let active = active_from_explicit_specs(vec![root.display().to_string()], true).unwrap();
        let packs = load_config_packs_from_active(&active).unwrap();
        assert!(packs.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }
}
