use crate::Result;
use anyhow::{anyhow, bail, Context};
use pentect_core::{load_pack, load_plugin_pack, Pack};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub(crate) const CONFIGS_ENV: &str = "PENTECT_PLUGIN_CONFIGS";
pub(crate) const BINARIES_ENV: &str = "PENTECT_PLUGIN_BINARIES";
pub(crate) const PLUGIN_MANIFEST_FILE: &str = "plugin.toml";

const PENTECT_DIR: &str = ".pentect";
const PLUGINS_DIR: &str = "plugins";
const PLUGINS_CACHE_DIR: &str = "plugin-cache";
const PENTECT_CONFIG_FILE: &str = "config.toml";
const PLUGIN_CONFIG_FILE: &str = "config.toml";
const PLUGIN_CONFIGS_DIR: &str = "configs";
const OFFICIAL_PLUGINS_DIR: &str = "plugins";
const DEFAULT_REMOTE_PLUGINS_BASE: &str =
    "https://raw.githubusercontent.com/EdamAme-x/pentect/main/plugins";
const DEFAULT_PLUGIN_REPOSITORY: &str = "EdamAme-x/pentect";
const REMOTE_PLUGIN_TIMEOUT: Duration = Duration::from_secs(8);
const REMOTE_PLUGIN_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_REMOTE_PLUGIN_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Default)]
pub(crate) struct ActivePlugins {
    config_paths: Vec<PathBuf>,
    binary_paths: Vec<PathBuf>,
}

#[derive(Debug)]
pub(crate) struct PluginSource {
    pub(crate) name: String,
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) repository: Option<String>,
}

impl ActivePlugins {
    pub(crate) fn config_paths(&self) -> &[PathBuf] {
        &self.config_paths
    }

    pub(crate) fn binary_paths(&self) -> &[PathBuf] {
        &self.binary_paths
    }

    pub(crate) fn config_env_value(&self) -> Result<Option<OsString>> {
        if self.config_paths.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.config_paths)
            .map(Some)
            .context("could not encode plugin config paths")
    }

    pub(crate) fn binary_env_value(&self) -> Result<Option<OsString>> {
        if self.binary_paths.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.binary_paths)
            .map(Some)
            .context("could not encode plugin binary manifests")
    }
}

pub(crate) fn parse_plugin_value(value: &str) -> Result<Vec<String>> {
    let mut specs = Vec::new();
    for raw in value.split(',') {
        let spec = raw.trim();
        if spec.is_empty() {
            continue;
        }
        validate_plugin_spec(spec)?;
        if !specs.iter().any(|existing| existing == spec) {
            specs.push(spec.to_string());
        }
    }
    if specs.is_empty() {
        bail!("--plugins requires at least one plugin");
    }
    Ok(specs)
}

pub(crate) fn collect_from_args(args: &[String]) -> Result<Vec<String>> {
    let mut specs = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--plugins" {
            let Some(value) = args.get(i + 1) else {
                bail!("--plugins requires a value");
            };
            if value.starts_with("--") {
                bail!("--plugins requires a value");
            }
            extend_unique(&mut specs, parse_plugin_value(value)?);
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(specs)
}

pub(crate) fn strip_from_args(args: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    match args.first().map(String::as_str) {
        Some("exec") => strip_exec_like_args(args),
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
        if args[i] == "--plugins" {
            let Some(value) = args.get(i + 1) else {
                bail!("--plugins requires a value");
            };
            if value.starts_with("--") {
                bail!("--plugins requires a value");
            }
            extend_unique(&mut specs, parse_plugin_value(value)?);
            i += 2;
        } else if matches!(args[i].as_str(), "--session") {
            stripped.push(args[i].clone());
            let Some(value) = args.get(i + 1) else {
                bail!("{} requires a value", args[i]);
            };
            stripped.push(value.clone());
            i += 2;
        } else if args[i] == "--live" || i == 0 {
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
        if args[i] == "--plugins" {
            let Some(value) = args.get(i + 1) else {
                bail!("--plugins requires a value");
            };
            if value.starts_with("--") {
                bail!("--plugins requires a value");
            }
            extend_unique(&mut specs, parse_plugin_value(value)?);
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
) -> Result<ActivePlugins> {
    let mut specs = config_specs()?;
    extend_unique(&mut specs, explicit_specs);
    active_from_explicit_specs(specs, create_named)
}

pub(crate) fn active_from_explicit_specs(
    specs: Vec<String>,
    create_named: bool,
) -> Result<ActivePlugins> {
    let (config_paths, binary_paths) = plugin_paths_for_specs(&specs, create_named)?;
    Ok(ActivePlugins {
        config_paths,
        binary_paths,
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
    load_config_packs_from_active(&active)
}

pub(crate) fn load_config_packs_from_active(active: &ActivePlugins) -> Result<Vec<Pack>> {
    let mut packs = Vec::new();
    for path in active.config_paths() {
        let display = path.display();
        let src = std::fs::read_to_string(path)
            .with_context(|| format!("could not read plugin config '{display}'"))?;
        let pack = load_plugin_config(path, &src)
            .map_err(|e| anyhow!("plugin config '{display}' is invalid: {e}"))?;
        if !pack.disable.is_empty() {
            bail!("plugin config '{display}' may add detectors but must not disable built-ins");
        }
        packs.push(pack);
    }
    Ok(packs)
}

pub(crate) fn load_plugin_config(path: &Path, source: &str) -> Result<Pack, String> {
    if is_plugin_manifest(path) {
        load_plugin_pack(source)
    } else {
        load_pack(source)
    }
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
    let Some(raw_plugins) = value.get("plugins") else {
        return Ok(Vec::new());
    };
    parse_config_plugins(raw_plugins)
}

fn parse_config_plugins(value: &toml::Value) -> Result<Vec<String>> {
    match value {
        toml::Value::String(s) => parse_plugin_value(s),
        toml::Value::Array(items) => {
            let mut specs = Vec::new();
            for item in items {
                let Some(s) = item.as_str() else {
                    bail!(".pentect/config.toml plugins must be strings");
                };
                extend_unique(&mut specs, parse_plugin_value(s)?);
            }
            Ok(specs)
        }
        _ => bail!(".pentect/config.toml plugins must be a string or string array"),
    }
}

fn plugin_paths_for_specs(
    specs: &[String],
    create_named: bool,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut configs = Vec::new();
    let mut binaries = Vec::new();
    for spec in specs {
        if is_remote_spec(spec) {
            let found = plugin_paths_for_url(spec)?;
            configs.extend(found.config_paths);
            binaries.extend(found.binary_paths);
        } else if is_path_spec(spec) {
            let found = plugin_paths_for_path(Path::new(spec))?;
            configs.extend(found.config_paths);
            binaries.extend(found.binary_paths);
        } else {
            let found = plugin_paths_for_named(spec, create_named)?;
            configs.extend(found.config_paths);
            binaries.extend(found.binary_paths);
        }
    }
    dedup_paths(&mut configs);
    dedup_paths(&mut binaries);
    Ok((configs, binaries))
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = std::collections::HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));
}

#[derive(Debug, Default)]
struct PluginPaths {
    config_paths: Vec<PathBuf>,
    binary_paths: Vec<PathBuf>,
}

fn plugin_paths_for_named(name: &str, _create: bool) -> Result<PluginPaths> {
    validate_plugin_name(name)?;
    let project_dir = plugins_root().join(name);
    let official_dir = official_plugins_root().join(name);

    if project_dir.is_dir() {
        let paths = plugin_paths_in_dir(&project_dir)?;
        if !paths.is_empty() {
            return Ok(paths);
        }
    }

    if official_dir.is_dir() {
        let paths = plugin_paths_in_dir(&official_dir)?;
        if !paths.is_empty() {
            return Ok(paths);
        }
    }

    let remote_error = if remote_plugins_enabled() {
        match remote_plugin_paths_for_name(name) {
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
            "plugin '{name}' has no detectors or binary; add '{}' or '{}'",
            suggestion_dir.join(PLUGIN_CONFIG_FILE).display(),
            suggestion_dir.join(PLUGIN_MANIFEST_FILE).display()
        );
        if let Some(error) = remote_error {
            message.push_str(&format!("; remote lookup failed: {error}"));
        }
        bail!(message);
    }

    let mut message = format!(
        "plugin '{name}' was not found at '{}' or '{}'",
        project_dir.display(),
        official_dir.display()
    );
    if let Some(error) = remote_error {
        message.push_str(&format!("; remote lookup failed: {error}"));
    }
    bail!(message)
}

fn plugin_paths_for_url(url: &str) -> Result<PluginPaths> {
    let normalized = normalize_github_plugin_url(url)?;
    if normalized.ends_with(".toml") {
        let mut paths = PluginPaths::default();
        let file = fetch_remote_plugin_file(&normalized)?
            .ok_or_else(|| anyhow!("remote plugin file was not found: {normalized}"))?;
        if normalized.ends_with("/plugin.toml") {
            add_manifest_paths(&file, &mut paths)?;
        } else {
            paths.config_paths.push(file);
        }
        return Ok(paths);
    }
    remote_plugin_paths_for_base_url(&normalized)
}

fn plugin_paths_for_path(path: &Path) -> Result<PluginPaths> {
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            bail!("plugin config must be a .toml file: {}", path.display());
        }
        let mut paths = PluginPaths::default();
        let file = canonical_file(path)?;
        if is_plugin_manifest(path) {
            add_manifest_paths(&file, &mut paths)?;
        } else {
            paths.config_paths.push(file);
        }
        return Ok(paths);
    }
    if path.is_dir() {
        return plugin_paths_in_dir(path);
    }
    bail!("plugin path does not exist: {}", path.display())
}

fn plugin_paths_in_dir(dir: &Path) -> Result<PluginPaths> {
    let mut paths = PluginPaths::default();
    let manifest = dir.join(PLUGIN_MANIFEST_FILE);
    if manifest.is_file() {
        let manifest = canonical_file(&manifest)?;
        add_manifest_paths(&manifest, &mut paths)?;
    }
    let config = dir.join(PLUGIN_CONFIG_FILE);
    if config.exists() {
        paths.config_paths.push(canonical_file(&config)?);
    }
    let configs_dir = dir.join(PLUGIN_CONFIGS_DIR);
    if configs_dir.exists() {
        paths.config_paths.extend(toml_files_in_dir(&configs_dir)?);
    }
    paths.config_paths.sort();
    paths.binary_paths.sort();
    Ok(paths)
}

fn is_plugin_manifest(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some(PLUGIN_MANIFEST_FILE)
}

fn add_manifest_paths(path: &Path, paths: &mut PluginPaths) -> Result<()> {
    let source = read_bounded_plugin_file(path)?;
    let value = source
        .parse::<toml::Value>()
        .with_context(|| format!("could not parse plugin manifest '{}'", path.display()))?;
    if value
        .get("detector")
        .and_then(toml::Value::as_array)
        .is_some_and(|detectors| !detectors.is_empty())
    {
        paths.config_paths.push(path.to_path_buf());
    }
    if value
        .get("binary")
        .and_then(toml::Value::as_str)
        .is_some_and(|binary| !binary.is_empty())
    {
        paths.binary_paths.push(path.to_path_buf());
    }
    Ok(())
}

impl PluginPaths {
    fn is_empty(&self) -> bool {
        self.config_paths.is_empty() && self.binary_paths.is_empty()
    }
}

fn canonical_file(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("could not resolve '{}'", path.display()))
}

fn plugins_root() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(PLUGINS_DIR)
}

fn official_plugins_root() -> PathBuf {
    PathBuf::from(OFFICIAL_PLUGINS_DIR)
}

pub(crate) fn plugin_source(spec: &str) -> Result<PluginSource> {
    validate_plugin_spec(spec)?;
    if is_remote_spec(spec) {
        let normalized = normalize_github_plugin_url(spec)?;
        let repository = github_repository(&normalized);
        let (base, manifest_url) = if normalized.ends_with("/plugin.toml") {
            let base = normalized
                .strip_suffix("/plugin.toml")
                .unwrap_or(&normalized)
                .to_string();
            (base, normalized)
        } else if normalized.ends_with(".toml") {
            bail!("plugin metadata must be a plugin.toml file: {spec}");
        } else {
            let base = normalized.trim_end_matches('/').to_string();
            let manifest = format!("{base}/{PLUGIN_MANIFEST_FILE}");
            (base, manifest)
        };
        let manifest_path = fetch_remote_plugin_file(&manifest_url)?;
        let name = remote_plugin_name(&base)?;
        return Ok(PluginSource {
            name,
            manifest_path,
            repository,
        });
    }
    if is_path_spec(spec) {
        let path = Path::new(spec);
        let root = if path.is_dir() {
            path.to_path_buf()
        } else if path.file_name().and_then(|name| name.to_str()) == Some(PLUGIN_MANIFEST_FILE) {
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        } else if path.is_file() {
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        } else {
            bail!("plugin path does not exist: {}", path.display());
        };
        let root = root
            .canonicalize()
            .with_context(|| format!("could not resolve '{}'", root.display()))?;
        let manifest = root.join(PLUGIN_MANIFEST_FILE);
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("plugin")
            .to_string();
        return Ok(PluginSource {
            name,
            manifest_path: manifest.is_file().then_some(manifest),
            repository: None,
        });
    }

    validate_plugin_name(spec)?;
    for (root, repository) in [
        (plugins_root().join(spec), None),
        (
            official_plugins_root().join(spec),
            Some(DEFAULT_PLUGIN_REPOSITORY.to_string()),
        ),
    ] {
        if root.is_dir() {
            let root = root
                .canonicalize()
                .with_context(|| format!("could not resolve '{}'", root.display()))?;
            let manifest = root.join(PLUGIN_MANIFEST_FILE);
            return Ok(PluginSource {
                name: spec.to_string(),
                manifest_path: manifest.is_file().then_some(manifest),
                repository,
            });
        }
    }
    let base = format!("{DEFAULT_REMOTE_PLUGINS_BASE}/{spec}");
    let manifest_path = fetch_remote_plugin_file(&format!("{base}/{PLUGIN_MANIFEST_FILE}"))?;
    Ok(PluginSource {
        name: spec.to_string(),
        manifest_path,
        repository: Some(DEFAULT_PLUGIN_REPOSITORY.to_string()),
    })
}

fn github_repository(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://raw.githubusercontent.com/")?;
    let mut parts = rest.split('/');
    Some(format!("{}/{}", parts.next()?, parts.next()?))
}

fn remote_plugin_name(base: &str) -> Result<String> {
    let name = base
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("remote plugin path has no name: {base}"))?;
    validate_plugin_name(name)?;
    Ok(name.to_string())
}

fn validate_plugin_spec(spec: &str) -> Result<()> {
    if is_remote_spec(spec) {
        normalize_github_plugin_url(spec).map(|_| ())?;
        return Ok(());
    }
    if is_path_spec(spec) {
        if Path::new(spec)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            bail!("plugin paths must not contain '..': {spec}");
        }
        return Ok(());
    }
    validate_plugin_name(spec)
}

fn validate_plugin_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        bail!("plugin name must not be empty");
    };
    if !first.is_ascii_alphanumeric() {
        bail!("invalid plugin name: {name}");
    }
    if name.len() > 64
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        bail!("invalid plugin name: {name}");
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

fn is_remote_spec(spec: &str) -> bool {
    spec.starts_with("github:")
        || spec.starts_with("https://github.com/")
        || spec.starts_with("https://raw.githubusercontent.com/")
}

fn remote_plugin_paths_for_name(name: &str) -> Result<PluginPaths> {
    remote_plugin_paths_for_base_url(&format!("{DEFAULT_REMOTE_PLUGINS_BASE}/{name}"))
}

fn remote_plugin_paths_for_base_url(base_url: &str) -> Result<PluginPaths> {
    let mut paths = PluginPaths::default();
    let base = base_url.trim_end_matches('/');
    let manifest_url = format!("{base}/{PLUGIN_MANIFEST_FILE}");
    let config_url = format!("{base}/{PLUGIN_CONFIG_FILE}");
    let (manifest, config) = std::thread::scope(|scope| {
        let manifest = scope.spawn(|| fetch_remote_plugin_file(&manifest_url));
        let config = scope.spawn(|| fetch_remote_plugin_file(&config_url));
        (manifest.join(), config.join())
    });
    let join = |result: std::thread::Result<Result<Option<PathBuf>>>| {
        result.map_err(|_| anyhow!("remote plugin fetch worker panicked"))?
    };
    if let Some(manifest) = join(manifest)? {
        add_manifest_paths(&manifest, &mut paths)?;
    }
    if let Some(config) = join(config)? {
        paths.config_paths.push(config);
    }
    if paths.is_empty() {
        bail!("remote plugin has no inline detectors, config.toml, or binary: {base_url}");
    }
    Ok(paths)
}

fn fetch_remote_plugin_file(url: &str) -> Result<Option<PathBuf>> {
    let path = remote_cache_file(url)?;
    if cached_remote_plugin_is_fresh(&path) {
        return Ok(Some(path));
    }
    let response = reqwest::blocking::Client::builder()
        .timeout(REMOTE_PLUGIN_TIMEOUT)
        .build()
        .context("could not create plugin HTTP client")?
        .get(url)
        .send()
        .with_context(|| format!("could not fetch plugin '{url}'"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        bail!("could not fetch plugin '{url}': HTTP {status}");
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_REMOTE_PLUGIN_FILE_BYTES)
    {
        bail!("remote plugin file is too large: {url}");
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_REMOTE_PLUGIN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read plugin '{url}'"))?;
    if bytes.len() as u64 > MAX_REMOTE_PLUGIN_FILE_BYTES {
        bail!("remote plugin file is too large: {url}");
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create plugin cache '{}'", parent.display()))?;
    }
    std::fs::write(&path, &bytes)
        .with_context(|| format!("could not write plugin cache '{}'", path.display()))?;
    Ok(Some(path))
}

fn read_bounded_plugin_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("could not read plugin manifest '{}'", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect plugin manifest '{}'", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_REMOTE_PLUGIN_FILE_BYTES {
        bail!("plugin manifest is too large: {}", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REMOTE_PLUGIN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read plugin manifest '{}'", path.display()))?;
    if bytes.len() as u64 > MAX_REMOTE_PLUGIN_FILE_BYTES {
        bail!("plugin manifest is too large: {}", path.display());
    }
    String::from_utf8(bytes)
        .with_context(|| format!("plugin manifest is not UTF-8: {}", path.display()))
}

fn cached_remote_plugin_is_fresh(path: &Path) -> bool {
    let Ok(modified) = path.metadata().and_then(|metadata| metadata.modified()) else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age < REMOTE_PLUGIN_CACHE_TTL)
}

fn remote_cache_file(url: &str) -> Result<PathBuf> {
    let mut hash = Sha256::new();
    hash.update(url.as_bytes());
    let digest = hash.finalize();
    let hex = data_encoding::HEXLOWER.encode(&digest[..16]);
    let filename = url
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("plugin.toml");
    let cache_root = pentect_agent::plugin_runtime_dirs(PLUGINS_CACHE_DIR)
        .map_err(anyhow::Error::msg)?
        .cache_dir;
    Ok(cache_root.join(hex).join(filename))
}

fn normalize_github_plugin_url(url: &str) -> Result<String> {
    if let Some(rest) = url.strip_prefix("github:") {
        let rest = rest.strip_prefix('@').unwrap_or(rest).trim_matches('/');
        let parts = rest.split('/').collect::<Vec<_>>();
        if parts.len() < 3 || parts.iter().any(|part| part.is_empty()) {
            bail!("GitHub plugin shorthand must be github:@OWNER/REPO/PATH: {url}");
        }
        let owner = parts[0];
        let repo = parts[1];
        let path = parts[2..].join("/");
        if !valid_github_segment(owner) || !valid_github_segment(repo) {
            bail!("invalid GitHub owner or repository in plugin shorthand: {url}");
        }
        return Ok(format!(
            "https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
        ));
    }
    if let Some(rest) = url.strip_prefix("https://raw.githubusercontent.com/") {
        if rest.split('/').count() < 4 {
            bail!("GitHub raw plugin URL is incomplete: {url}");
        }
        return Ok(url.trim_end_matches('/').to_string());
    }
    let Some(rest) = url.strip_prefix("https://github.com/") else {
        bail!("plugins can only be fetched from GitHub HTTPS URLs");
    };
    let parts = rest.split('/').collect::<Vec<_>>();
    if parts.len() < 5 {
        bail!("GitHub plugin URL must point to a blob or tree path: {url}");
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
        _ => bail!("GitHub plugin URL must use /blob/ or /tree/: {url}"),
    }
}

fn valid_github_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

#[cfg(not(test))]
fn remote_plugins_enabled() -> bool {
    true
}

#[cfg(test)]
fn remote_plugins_enabled() -> bool {
    false
}

fn toml_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("could not read plugin directory '{}'", dir.display()))?
    {
        let path = entry
            .with_context(|| format!("could not read plugin directory '{}'", dir.display()))?
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
    fn plugin_toml_alone_can_define_regex_detectors() {
        let root =
            std::env::temp_dir().join(format!("pentect-inline-plugin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("plugin.toml"),
            r#"
schema = "pentect.plugin.v1"
name = "inline"

[[detector]]
pattern = "inline-[0-9]+"
label = "INLINE_SECRET"
"#,
        )
        .unwrap();

        let active = active_from_explicit_specs(vec![root.display().to_string()], true).unwrap();
        assert_eq!(active.config_paths().len(), 1);
        assert!(active.config_paths()[0].ends_with("plugin.toml"));
        assert_eq!(load_config_packs_from_active(&active).unwrap().len(), 1);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_plugin_names_and_paths() {
        assert_eq!(
            parse_plugin_value("openai-privacy-filter,local.rules,./rules.toml").unwrap(),
            vec!["openai-privacy-filter", "local.rules", "./rules.toml"]
        );
        assert!(parse_plugin_value("../x.toml").is_err());
        assert!(parse_plugin_value("../x").is_err());
        assert!(parse_plugin_value("").is_err());
        assert_eq!(
            parse_plugin_value("github:@EdamAme-x/pentect/plugins/pii-ner").unwrap(),
            ["github:@EdamAme-x/pentect/plugins/pii-ner"]
        );
    }

    #[test]
    fn remote_plugin_cache_is_not_project_controlled() {
        let cache = remote_cache_file(
            "https://raw.githubusercontent.com/example/project/main/plugins/sample/plugin.toml",
        )
        .unwrap();
        let project = std::env::current_dir().unwrap();

        assert!(
            !cache.starts_with(&project),
            "remote cache must be outside the project: {}",
            cache.display()
        );
    }

    #[test]
    fn strip_plugins_does_not_touch_command_arguments() {
        let args = vec![
            "exec".to_string(),
            "--plugins".to_string(),
            "rules".to_string(),
            "--".to_string(),
            "--plugins".to_string(),
            "literal".to_string(),
        ];
        let (stripped, specs) = strip_from_args(&args).unwrap();
        assert_eq!(specs, ["rules"]);
        assert_eq!(
            stripped,
            vec![
                "exec".to_string(),
                "--".to_string(),
                "--plugins".to_string(),
                "literal".to_string()
            ]
        );

        let args = vec!["exec".to_string(), "rg --plugins literal".to_string()];
        let (stripped, specs) = strip_from_args(&args).unwrap();
        assert!(specs.is_empty());
        assert_eq!(stripped, args);

        let args = vec![
            "exec".to_string(),
            "--live".to_string(),
            "--plugins".to_string(),
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
    fn named_plugin_missing_is_an_error() {
        let name = format!(
            "missing-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let err = plugin_paths_for_named(&name, true).unwrap_err().to_string();
        assert!(err.contains("was not found"), "{err}");
    }

    #[test]
    fn github_plugin_urls_normalize_to_raw_urls() {
        assert_eq!(
            normalize_github_plugin_url(
                "https://github.com/EdamAme-x/pentect/blob/main/plugins/company/config.toml"
            )
            .unwrap(),
            "https://raw.githubusercontent.com/EdamAme-x/pentect/main/plugins/company/config.toml"
        );
        assert_eq!(
            normalize_github_plugin_url(
                "https://github.com/EdamAme-x/pentect/tree/main/plugins/company"
            )
            .unwrap(),
            "https://raw.githubusercontent.com/EdamAme-x/pentect/main/plugins/company"
        );
        assert_eq!(
            normalize_github_plugin_url(
                "https://raw.githubusercontent.com/EdamAme-x/pentect/main/plugins/company/config.toml"
            )
            .unwrap(),
            "https://raw.githubusercontent.com/EdamAme-x/pentect/main/plugins/company/config.toml"
        );
        assert!(normalize_github_plugin_url("https://example.com/company/config.toml").is_err());
        assert!(
            normalize_github_plugin_url("https://raw.githubusercontent.com/owner/repo").is_err()
        );
        assert_eq!(
            normalize_github_plugin_url("github:@EdamAme-x/pentect/plugins/pii-ner").unwrap(),
            "https://raw.githubusercontent.com/EdamAme-x/pentect/main/plugins/pii-ner"
        );
        assert!(normalize_github_plugin_url("github:@owner/repo").is_err());
        assert_eq!(
            github_repository(
                "https://raw.githubusercontent.com/owner/repo/main/plugins/example/plugin.toml"
            )
            .as_deref(),
            Some("owner/repo")
        );
    }

    #[test]
    fn empty_project_plugin_does_not_shadow_official_plugin() {
        let name = format!("shadow-test-{}", std::process::id());
        let project = PathBuf::from(".pentect").join("plugins").join(&name);
        let official = PathBuf::from("plugins").join(&name);
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&official);
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&official).unwrap();
        std::fs::write(official.join("config.toml"), "").unwrap();

        let paths = plugin_paths_for_named(&name, true).unwrap();
        let expected = official.join("config.toml").canonicalize().unwrap();

        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&official);

        assert_eq!(paths.config_paths, vec![expected]);
        assert!(paths.binary_paths.is_empty());
    }

    #[test]
    fn directory_plugins_can_contain_configs_and_binaries() {
        let root =
            std::env::temp_dir().join(format!("pentect-plugin-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("config.toml"), "").unwrap();
        std::fs::write(
            root.join("plugin.toml"),
            "schema = \"pentect.plugin.v1\"\nbinary = \"tool.wasm\"\n[middleware]\nstages = [\"detect\"]\npermissions = [\"input:read\"]\n",
        )
        .unwrap();

        let paths = plugin_paths_for_path(&root).unwrap();
        assert_eq!(
            paths.config_paths,
            vec![root.join("config.toml").canonicalize().unwrap()]
        );
        assert_eq!(
            paths.binary_paths,
            vec![root.join("plugin.toml").canonicalize().unwrap()]
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binary_only_plugins_add_no_declarative_packs() {
        let root = std::env::temp_dir().join(format!("pentect-binary-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("plugin.toml"),
            "schema = \"pentect.plugin.v1\"\nbinary = \"tool\"\n[middleware]\nstages = [\"detect\"]\npermissions = [\"input:read\"]\n",
        )
        .unwrap();

        let packs = load_config_packs_from_specs(vec![root.display().to_string()], true).unwrap();
        assert!(packs.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_loader_ignores_binary_paths_for_config_packs() {
        let root =
            std::env::temp_dir().join(format!("pentect-active-binary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("plugin.toml"),
            "schema = \"pentect.plugin.v1\"\nbinary = \"tool\"\n[middleware]\nstages = [\"detect\"]\npermissions = [\"input:read\"]\n",
        )
        .unwrap();

        let active = active_from_explicit_specs(vec![root.display().to_string()], true).unwrap();
        let packs = load_config_packs_from_active(&active).unwrap();
        assert!(packs.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }
}
