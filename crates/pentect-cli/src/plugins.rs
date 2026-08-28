use crate::Result;
use anyhow::{anyhow, bail, Context};
use pentect_core::{load_pack, load_plugin_pack, Pack};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub(crate) const CONFIGS_ENV: &str = "PENTECT_PLUGIN_CONFIGS";
pub(crate) const BINARIES_ENV: &str = "PENTECT_PLUGIN_BINARIES";
pub(crate) const GLOBAL_BINARIES_ENV: &str = "PENTECT_GLOBAL_PLUGIN_BINARIES";
pub(crate) const GLOBAL_BINARY_IDS_ENV: &str = "PENTECT_GLOBAL_PLUGIN_IDS";
pub(crate) const PLUGIN_MANIFEST_FILE: &str = "plugin.toml";

const PENTECT_DIR: &str = ".pentect";
const PLUGINS_DIR: &str = "plugins";
const PLUGINS_CACHE_DIR: &str = "plugin-cache";
const PENTECT_CONFIG_FILE: &str = "config.toml";
const PROJECT_PLUGIN_LOCK_FILE: &str = "pentect.plugins.lock";
const PLUGIN_CONFIG_FILE: &str = "config.toml";
const PLUGIN_CONFIGS_DIR: &str = "configs";
const OFFICIAL_PLUGINS_DIR: &str = "plugins";
const DEFAULT_REMOTE_PLUGINS_BASE: &str =
    "https://raw.githubusercontent.com/EdamAme-x/pentect/main/plugins";
const DEFAULT_PLUGIN_REPOSITORY: &str = "EdamAme-x/pentect";
const REMOTE_PLUGIN_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_REMOTE_PLUGIN_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REMOTE_PLUGIN_CACHE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REMOTE_PLUGIN_CACHE_ENTRIES: usize = 256;
const MAX_PROJECT_PLUGIN_LOCK_BYTES: u64 = 1024 * 1024;
static PROJECT_LOCK_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn enforce_tool_plugin_coverage(
    coverage: pentect_agent::MiddlewareCoverage,
    provider: &str,
) -> std::result::Result<(), String> {
    enforce_tool_plugin_coverage_with_policy(
        coverage,
        pentect_agent::unknown_formats_should_block()?,
        provider,
    )
}

fn enforce_tool_plugin_coverage_with_policy(
    coverage: pentect_agent::MiddlewareCoverage,
    block_unknown_formats: bool,
    provider: &str,
) -> std::result::Result<(), String> {
    if block_unknown_formats && coverage == pentect_agent::MiddlewareCoverage::Partial {
        return Err(format!(
            "unknown format blocked: a {provider} ToolCall plugin reported partial coverage; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to allow it"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PluginScope {
    User,
    Project,
}

#[derive(Debug, Default)]
pub(crate) struct ActivePlugins {
    config_paths: Vec<PathBuf>,
    binary_paths: Vec<PathBuf>,
    global_binary_paths: Vec<PathBuf>,
    global_binary_ids: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct PluginSource {
    pub(crate) name: String,
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) repository: Option<String>,
    pub(crate) remote_base: Option<String>,
    pub(crate) scope: PluginScope,
    pub(crate) runtime_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RemotePluginLockEntry {
    pub(crate) source: String,
    pub(crate) resolved: String,
    #[serde(default)]
    pub(crate) files: BTreeMap<String, String>,
}

#[derive(Debug)]
pub(crate) struct RemotePluginCacheSnapshot {
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
    previous_sources: BTreeMap<String, Vec<u8>>,
}

impl RemotePluginCacheSnapshot {
    pub(crate) fn previous_sources(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.previous_sources
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectPluginLock {
    schema: String,
    #[serde(default)]
    plugin: Vec<RemotePluginLockEntry>,
}

impl ActivePlugins {
    pub(crate) fn config_paths(&self) -> &[PathBuf] {
        &self.config_paths
    }

    pub(crate) fn binary_paths(&self) -> &[PathBuf] {
        &self.binary_paths
    }

    pub(crate) fn has_binary(&self) -> bool {
        !self.binary_paths.is_empty() || !self.global_binary_paths.is_empty()
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

    pub(crate) fn global_binary_env_value(&self) -> Result<Option<OsString>> {
        if self.global_binary_paths.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.global_binary_paths)
            .map(Some)
            .context("could not encode global plugin paths")
    }

    pub(crate) fn global_binary_ids_env_value(&self) -> Result<Option<OsString>> {
        if self.global_binary_ids.is_empty() {
            return Ok(None);
        }
        std::env::join_paths(&self.global_binary_ids)
            .map(Some)
            .context("could not encode global plugin identities")
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

pub(crate) fn plugin_spec_for_scope(spec: &str, scope: PluginScope) -> Result<String> {
    validate_plugin_spec(spec)?;
    if scope == PluginScope::User && !is_remote_spec(spec) && is_path_spec(spec) {
        if config_specs_scoped()?
            .into_iter()
            .any(|(configured_scope, configured)| configured_scope == scope && configured == spec)
        {
            return Ok(spec.to_string());
        }
        return Path::new(spec)
            .canonicalize()
            .with_context(|| format!("could not resolve plugin path '{spec}'"))
            .map(|path| path.to_string_lossy().into_owned());
    }
    Ok(spec.to_string())
}

pub(crate) fn collect_from_args(args: &[String]) -> Result<Vec<String>> {
    let mut specs = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if let Some(value) = args[i].strip_prefix("--plugins=") {
            extend_unique(&mut specs, parse_plugin_value(value)?);
            i += 1;
        } else if args[i] == "--plugins" {
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
        if let Some(value) = args[i].strip_prefix("--plugins=") {
            extend_unique(&mut specs, parse_plugin_value(value)?);
            i += 1;
        } else if args[i] == "--plugins" {
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
        if let Some(value) = args[i].strip_prefix("--plugins=") {
            extend_unique(&mut specs, parse_plugin_value(value)?);
            i += 1;
            continue;
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
    let mut specs = config_specs_scoped()?;
    for spec in explicit_specs {
        if !specs.iter().any(|(_, existing)| existing == &spec) {
            specs.push((PluginScope::Project, spec));
        }
    }
    active_from_scoped_specs(specs, create_named)
}

pub(crate) fn active_from_selected_specs(
    specs: Vec<String>,
    create_named: bool,
) -> Result<ActivePlugins> {
    let specs = specs
        .into_iter()
        .map(|spec| {
            let resolved = resolve_configured_plugin_spec(&spec)?;
            let scope = configured_scope(&resolved).unwrap_or(PluginScope::Project);
            Ok((scope, resolved))
        })
        .collect::<Result<Vec<_>>>()?;
    active_from_scoped_specs(specs, create_named)
}

pub(crate) fn active_from_scoped_specs(
    specs: Vec<(PluginScope, String)>,
    create_named: bool,
) -> Result<ActivePlugins> {
    let paths = plugin_paths_for_scoped_specs(&specs, create_named)?;
    Ok(ActivePlugins {
        config_paths: paths.config_paths,
        binary_paths: paths.binary_paths,
        global_binary_paths: paths.global_binary_paths,
        global_binary_ids: paths.global_binary_ids,
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

pub(crate) fn config_specs() -> Result<Vec<String>> {
    Ok(config_specs_scoped()?
        .into_iter()
        .map(|(_, spec)| spec)
        .collect())
}

pub(crate) fn config_specs_scoped() -> Result<Vec<(PluginScope, String)>> {
    let mut specs = Vec::new();
    for (scope, path) in [
        (PluginScope::User, user_plugin_config_path()?),
        (PluginScope::Project, project_plugin_config_path()),
    ] {
        for spec in config_specs_at(&path)? {
            if let Some(existing) = specs.iter_mut().find(|(_, value)| value == &spec) {
                *existing = (scope, spec);
            } else {
                specs.push((scope, spec));
            }
        }
    }
    Ok(specs)
}

fn config_specs_at(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("could not read '{}'", path.display()))?;
    let value = src
        .parse::<toml::Value>()
        .with_context(|| format!("could not parse '{}'", path.display()))?;
    let Some(raw_plugins) = value.get("plugins") else {
        return Ok(Vec::new());
    };
    parse_config_plugins(raw_plugins)
        .with_context(|| format!("invalid plugin config '{}'", path.display()))
}

pub(crate) fn project_plugin_config_path() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(PENTECT_CONFIG_FILE)
}

pub(crate) fn user_plugin_config_path() -> Result<PathBuf> {
    home_dir()
        .map(|home| home.join(PENTECT_DIR).join(PENTECT_CONFIG_FILE))
        .ok_or_else(|| anyhow!("could not find a home directory for global Pentect config"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
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

struct ScopedPluginPaths {
    config_paths: Vec<PathBuf>,
    binary_paths: Vec<PathBuf>,
    global_binary_paths: Vec<PathBuf>,
    global_binary_ids: Vec<PathBuf>,
}

fn plugin_paths_for_scoped_specs(
    specs: &[(PluginScope, String)],
    create_named: bool,
) -> Result<ScopedPluginPaths> {
    let mut configs = Vec::new();
    let mut binaries = Vec::new();
    let mut global_binaries = Vec::new();
    let mut global_ids = Vec::new();
    for (scope, spec) in specs {
        let resolved = resolve_configured_plugin_spec_in_scope(spec, *scope)?;
        let spec = resolved.as_str();
        let found = if is_remote_spec(spec) {
            let found = plugin_paths_for_url(spec)?;
            verify_remote_plugin(*scope, spec, &normalize_github_plugin_url(spec)?)?;
            found
        } else if is_path_spec(spec) {
            plugin_paths_for_path(Path::new(spec))?
        } else {
            plugin_paths_for_named_scoped(spec, create_named, *scope)?
        };
        configs.extend(found.config_paths);
        match scope {
            PluginScope::Project => binaries.extend(found.binary_paths),
            PluginScope::User => {
                let runtime_id = plugin_runtime_id(spec);
                for path in found.binary_paths {
                    global_binaries.push(path);
                    global_ids.push(PathBuf::from(&runtime_id));
                }
            }
        }
    }
    dedup_paths(&mut configs);
    dedup_paths(&mut binaries);
    let mut seen = std::collections::HashSet::new();
    let mut index = 0usize;
    global_binaries.retain(|path| {
        let keep = seen.insert(path.clone());
        if !keep {
            global_ids.remove(index);
        } else {
            index += 1;
        }
        keep
    });
    Ok(ScopedPluginPaths {
        config_paths: configs,
        binary_paths: binaries,
        global_binary_paths: global_binaries,
        global_binary_ids: global_ids,
    })
}

fn plugin_runtime_id(spec: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"pentect-global-plugin-v1");
    digest.update(spec.as_bytes());
    data_encoding::HEXLOWER.encode(&digest.finalize()[..16])
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

#[cfg(test)]
fn plugin_paths_for_named(name: &str, _create: bool) -> Result<PluginPaths> {
    plugin_paths_for_named_scoped(name, _create, PluginScope::Project)
}

fn plugin_paths_for_named_scoped(
    name: &str,
    _create: bool,
    scope: PluginScope,
) -> Result<PluginPaths> {
    validate_plugin_name(name)?;
    let project_dir = plugins_root().join(name);
    let official_dir = official_plugins_root().join(name);

    if scope == PluginScope::Project {
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
    }

    let remote_error = if remote_plugins_enabled() {
        match remote_plugin_paths_for_name(name) {
            Ok(paths) if !paths.is_empty() => {
                verify_remote_plugin(
                    scope,
                    name,
                    &format!("{DEFAULT_REMOTE_PLUGINS_BASE}/{name}"),
                )?;
                return Ok(paths);
            }
            Ok(_) => None,
            Err(e) => Some(e),
        }
    } else {
        None
    };
    if scope == PluginScope::Project && (project_dir.is_dir() || official_dir.is_dir()) {
        let suggestion_dir = if project_dir.is_dir() {
            &project_dir
        } else {
            &official_dir
        };
        let mut message = format!(
            "plugin '{name}' has no detectors, Wasm, or command; add '{}' or '{}'",
            suggestion_dir.join(PLUGIN_CONFIG_FILE).display(),
            suggestion_dir.join(PLUGIN_MANIFEST_FILE).display()
        );
        if let Some(error) = remote_error {
            message.push_str(&format!("; remote lookup failed: {error}"));
        }
        bail!(message);
    }

    let mut message = match scope {
        PluginScope::User => format!("global plugin '{name}' was not found in the remote catalog"),
        PluginScope::Project => format!(
            "plugin '{name}' was not found at '{}' or '{}'",
            project_dir.display(),
            official_dir.display()
        ),
    };
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
    let source =
        pentect_agent::read_bounded_utf8(path, MAX_REMOTE_PLUGIN_FILE_BYTES, "plugin manifest")
            .map_err(anyhow::Error::msg)?;
    let value = source
        .parse::<toml::Value>()
        .with_context(|| format!("could not parse plugin manifest '{}'", path.display()))?;
    let has_detectors = value
        .get("detector")
        .and_then(toml::Value::as_array)
        .is_some_and(|detectors| !detectors.is_empty());
    let canonical_wasm = value
        .get("wasm")
        .and_then(toml::Value::as_str)
        .is_some_and(|wasm| !wasm.is_empty());
    let legacy_wasm = value
        .get("binary")
        .and_then(toml::Value::as_str)
        .is_some_and(|wasm| !wasm.is_empty());
    if canonical_wasm && legacy_wasm {
        bail!("plugin manifest cannot set both wasm and legacy binary");
    }
    let has_wasm = canonical_wasm || legacy_wasm;
    let has_command = value
        .get("command")
        .and_then(toml::Value::as_array)
        .is_some_and(|command| !command.is_empty())
        || value
            .get("commands")
            .and_then(toml::Value::as_table)
            .is_some_and(|commands| !commands.is_empty());
    if usize::from(has_detectors) + usize::from(has_wasm) + usize::from(has_command) != 1 {
        bail!("plugin manifest must contain exactly one of detector, wasm, or command");
    }
    if has_detectors {
        paths.config_paths.push(path.to_path_buf());
    }
    if has_wasm || has_command {
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
    let spec = resolve_configured_plugin_spec(spec)?;
    let scope = configured_scope(&spec).unwrap_or(PluginScope::Project);
    plugin_source_with_refresh(&spec, false, scope)
}

pub(crate) fn refresh_plugin_source_in_scope(
    spec: &str,
    scope: PluginScope,
) -> Result<PluginSource> {
    let spec = resolve_configured_plugin_spec_in_scope(spec, scope)?;
    plugin_source_with_refresh(&spec, true, scope)
}

pub(crate) fn plugin_source_in_scope(spec: &str, scope: PluginScope) -> Result<PluginSource> {
    let spec = resolve_configured_plugin_spec_in_scope(spec, scope)?;
    plugin_source_with_refresh(&spec, false, scope)
}

pub(crate) fn configured_scope(spec: &str) -> Option<PluginScope> {
    config_specs_scoped()
        .ok()?
        .into_iter()
        .find_map(|(scope, configured)| (configured == spec).then_some(scope))
}

fn resolve_configured_plugin_spec(spec: &str) -> Result<String> {
    if is_remote_spec(spec) || is_path_spec(spec) {
        return Ok(spec.to_string());
    }
    let configured_specs = config_specs()?;
    if configured_specs.iter().any(|configured| configured == spec) {
        return Ok(spec.to_string());
    }
    let mut matches = Vec::new();
    for configured in configured_specs {
        let scope = configured_scope(&configured).unwrap_or(PluginScope::Project);
        let Ok(source) = plugin_source_with_refresh(&configured, false, scope) else {
            continue;
        };
        let manifest_name = source
            .manifest_path
            .as_deref()
            .and_then(|path| {
                pentect_agent::read_bounded_utf8(
                    path,
                    MAX_REMOTE_PLUGIN_FILE_BYTES,
                    "plugin manifest",
                )
                .ok()
            })
            .and_then(|text| text.parse::<toml::Value>().ok())
            .and_then(|value| {
                value
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
            });
        if source.name == spec || manifest_name.as_deref() == Some(spec) {
            matches.push(configured);
        }
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [] => Ok(spec.to_string()),
        [resolved] => Ok(resolved.clone()),
        _ => bail!(
            "plugin name '{spec}' is ambiguous; use one exact source: {}",
            matches.join(", ")
        ),
    }
}

fn resolve_configured_plugin_spec_in_scope(spec: &str, scope: PluginScope) -> Result<String> {
    if is_remote_spec(spec) || is_path_spec(spec) {
        return Ok(spec.to_string());
    }
    let configured_specs = config_specs_scoped()?
        .into_iter()
        .filter_map(|(configured_scope, configured)| {
            (configured_scope == scope).then_some(configured)
        })
        .collect::<Vec<_>>();
    if configured_specs.iter().any(|configured| configured == spec) {
        return Ok(spec.to_string());
    }
    let mut matches = Vec::new();
    for configured in configured_specs {
        let Ok(source) = plugin_source_with_refresh(&configured, false, scope) else {
            continue;
        };
        let manifest_name = source
            .manifest_path
            .as_deref()
            .and_then(|path| {
                pentect_agent::read_bounded_utf8(
                    path,
                    MAX_REMOTE_PLUGIN_FILE_BYTES,
                    "plugin manifest",
                )
                .ok()
            })
            .and_then(|text| text.parse::<toml::Value>().ok())
            .and_then(|value| {
                value
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
            });
        if source.name == spec || manifest_name.as_deref() == Some(spec) {
            matches.push(configured);
        }
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [] => Ok(spec.to_string()),
        [resolved] => Ok(resolved.clone()),
        _ => bail!(
            "plugin name '{spec}' is ambiguous in the selected scope; use one exact source: {}",
            matches.join(", ")
        ),
    }
}

fn plugin_source_with_refresh(
    spec: &str,
    refresh: bool,
    scope: PluginScope,
) -> Result<PluginSource> {
    validate_plugin_spec(spec)?;
    if is_remote_spec(spec) {
        let fetch = RemotePluginFetchSession::default();
        let normalized = normalize_github_plugin_url(spec)?;
        let repository = github_repository(&normalized);
        let points_to_manifest = normalized.ends_with("/plugin.toml");
        let (base, manifest_url) = if points_to_manifest {
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
        if refresh {
            fetch.protect_urls([
                manifest_url.as_str(),
                format!("{base}/{PLUGIN_CONFIG_FILE}").as_str(),
            ])?;
        }
        if refresh {
            let _ = fetch_remote_plugin_file_in_session(
                &format!("{base}/{PLUGIN_CONFIG_FILE}"),
                true,
                &fetch,
            )?;
        }
        let manifest_path = fetch_remote_plugin_file_in_session(&manifest_url, refresh, &fetch)?;
        if refresh {
            refresh_remote_command_files_in_session(&base, manifest_path.as_deref(), &fetch)?;
        }
        let name = remote_plugin_name(&base)?;
        let remote_base = if points_to_manifest {
            manifest_url.clone()
        } else {
            base.clone()
        };
        return Ok(PluginSource {
            name,
            manifest_path,
            repository,
            remote_base: Some(remote_base),
            scope,
            runtime_id: plugin_runtime_id(spec),
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
            remote_base: None,
            scope,
            runtime_id: plugin_runtime_id(spec),
        });
    }

    validate_plugin_name(spec)?;
    if scope == PluginScope::Project {
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
                    remote_base: None,
                    scope,
                    runtime_id: plugin_runtime_id(spec),
                });
            }
        }
    }
    let base = format!("{DEFAULT_REMOTE_PLUGINS_BASE}/{spec}");
    let fetch = RemotePluginFetchSession::default();
    if refresh {
        let manifest_url = format!("{base}/{PLUGIN_MANIFEST_FILE}");
        let config_url = format!("{base}/{PLUGIN_CONFIG_FILE}");
        fetch.protect_urls([manifest_url.as_str(), config_url.as_str()])?;
        let _ = fetch_remote_plugin_file_in_session(
            &format!("{base}/{PLUGIN_CONFIG_FILE}"),
            true,
            &fetch,
        )?;
    }
    let manifest_path = fetch_remote_plugin_file_in_session(
        &format!("{base}/{PLUGIN_MANIFEST_FILE}"),
        refresh,
        &fetch,
    )?;
    if refresh {
        refresh_remote_command_files_in_session(&base, manifest_path.as_deref(), &fetch)?;
    }
    Ok(PluginSource {
        name: spec.to_string(),
        manifest_path,
        repository: Some(DEFAULT_PLUGIN_REPOSITORY.to_string()),
        remote_base: Some(base),
        scope,
        runtime_id: plugin_runtime_id(spec),
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
    let fetch = RemotePluginFetchSession::default();
    fetch.protect_urls([manifest_url.as_str(), config_url.as_str()])?;
    let (manifest, config) = std::thread::scope(|scope| {
        let manifest_fetch = fetch.clone();
        let config_fetch = fetch.clone();
        let manifest = scope.spawn(move || {
            fetch_remote_plugin_file_in_session(&manifest_url, false, &manifest_fetch)
        });
        let config = scope
            .spawn(move || fetch_remote_plugin_file_in_session(&config_url, false, &config_fetch));
        (manifest.join(), config.join())
    });
    let join = |result: std::thread::Result<Result<Option<PathBuf>>>| {
        result.map_err(|_| anyhow!("remote plugin fetch worker panicked"))?
    };
    if let Some(manifest) = join(manifest)? {
        let command_files = command_files_from_manifest(base, &manifest)?;
        fetch.protect_urls(command_files.iter().map(|(_, url)| url.as_str()))?;
        for (_, url) in command_files {
            fetch_remote_plugin_file_in_session(&url, false, &fetch)?
                .ok_or_else(|| anyhow!("remote command plugin file was not found: {url}"))?;
        }
        add_manifest_paths(&manifest, &mut paths)?;
    }
    if let Some(config) = join(config)? {
        paths.config_paths.push(config);
    }
    if paths.is_empty() {
        bail!("remote plugin has no inline detectors, config.toml, Wasm, or command: {base_url}");
    }
    Ok(paths)
}

fn fetch_remote_plugin_file(url: &str) -> Result<Option<PathBuf>> {
    fetch_remote_plugin_file_with_refresh(url, false)
}

pub(crate) fn project_plugin_lock_path() -> PathBuf {
    PathBuf::from(PROJECT_PLUGIN_LOCK_FILE)
}

pub(crate) fn user_plugin_lock_path() -> Result<PathBuf> {
    home_dir()
        .map(|home| home.join(PENTECT_DIR).join(PROJECT_PLUGIN_LOCK_FILE))
        .ok_or_else(|| anyhow!("could not find a home directory for global plugin lock"))
}

pub(crate) fn plugin_lock_path(scope: PluginScope) -> Result<PathBuf> {
    match scope {
        PluginScope::User => user_plugin_lock_path(),
        PluginScope::Project => Ok(project_plugin_lock_path()),
    }
}

pub(crate) fn remote_plugin_lock_entry(
    spec: &str,
    source: &PluginSource,
) -> Result<Option<RemotePluginLockEntry>> {
    let Some(resolved) = source.remote_base.clone() else {
        return Ok(None);
    };
    let manifest_url = if resolved.ends_with(".toml") {
        resolved.clone()
    } else {
        format!(
            "{}/{}",
            resolved.trim_end_matches('/'),
            PLUGIN_MANIFEST_FILE
        )
    };
    fetch_remote_plugin_file(&manifest_url)?
        .ok_or_else(|| anyhow!("remote plugin manifest could not be fetched for lock: {spec}"))?;
    let optional_config_url = (!resolved.ends_with(".toml"))
        .then(|| format!("{}/{}", resolved.trim_end_matches('/'), PLUGIN_CONFIG_FILE));
    let mut files = BTreeMap::new();
    for url in remote_plugin_urls(&resolved) {
        let Some(path) = fetch_remote_plugin_file(&url)? else {
            if optional_config_url.as_deref() == Some(url.as_str()) {
                continue;
            }
            bail!("remote plugin file could not be fetched for lock: {url}");
        };
        let bytes = pentect_agent::read_bounded_bytes(
            &path,
            MAX_REMOTE_PLUGIN_FILE_BYTES,
            "remote plugin file",
        )
        .map_err(anyhow::Error::msg)?;
        files.insert(url, data_encoding::HEXLOWER.encode(&Sha256::digest(bytes)));
    }
    if files.is_empty() {
        bail!("remote plugin has no cached files to lock: {spec}");
    }
    Ok(Some(RemotePluginLockEntry {
        source: spec.to_string(),
        resolved,
        files,
    }))
}

pub(crate) fn remote_plugin_sources(source: &PluginSource) -> Result<BTreeMap<String, Vec<u8>>> {
    let Some(resolved) = source.remote_base.as_deref() else {
        return Ok(BTreeMap::new());
    };
    let mut sources = BTreeMap::new();
    for url in remote_plugin_urls(resolved) {
        let path = remote_cache_file(&url)?;
        if path.is_file() {
            let bytes = pentect_agent::read_bounded_bytes(
                &path,
                MAX_REMOTE_PLUGIN_FILE_BYTES,
                "remote plugin file",
            )
            .map_err(anyhow::Error::msg)?;
            sources.insert(url, bytes);
        }
    }
    Ok(sources)
}

pub(crate) fn snapshot_remote_plugin_cache(
    spec: &str,
) -> Result<Option<RemotePluginCacheSnapshot>> {
    let source = plugin_source_with_refresh(
        spec,
        false,
        configured_scope(spec).unwrap_or(PluginScope::Project),
    )?;
    let Some(resolved) = source.remote_base else {
        return Ok(None);
    };
    let mut files = Vec::new();
    let mut previous_sources = BTreeMap::new();
    for url in remote_plugin_urls(&resolved) {
        let path = remote_cache_file(&url)?;
        let contents = if path.is_file() {
            let bytes = pentect_agent::read_bounded_bytes(
                &path,
                MAX_REMOTE_PLUGIN_FILE_BYTES,
                "remote plugin cache",
            )
            .map_err(anyhow::Error::msg)?;
            previous_sources.insert(url, bytes.clone());
            Some(bytes)
        } else {
            None
        };
        files.push((path.clone(), contents));
        let missing = remote_missing_file(&path);
        let missing_contents = if missing.is_file() {
            Some(std::fs::read(&missing).with_context(|| {
                format!("could not snapshot plugin cache '{}'", missing.display())
            })?)
        } else {
            None
        };
        files.push((missing, missing_contents));
    }
    Ok(Some(RemotePluginCacheSnapshot {
        files,
        previous_sources,
    }))
}

pub(crate) fn restore_remote_plugin_cache(snapshot: &RemotePluginCacheSnapshot) -> Result<()> {
    for (path, contents) in &snapshot.files {
        match contents {
            Some(contents) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("could not restore plugin cache '{}'", parent.display())
                    })?;
                }
                let staged = path.with_extension(format!("restore-{}", std::process::id()));
                std::fs::write(&staged, contents).with_context(|| {
                    format!("could not stage plugin cache restore '{}'", path.display())
                })?;
                atomic_replace(&staged, path)?;
            }
            None if path.exists() => {
                std::fs::remove_file(path).with_context(|| {
                    format!(
                        "could not remove refreshed plugin cache '{}'",
                        path.display()
                    )
                })?;
            }
            None => {}
        }
    }
    Ok(())
}

pub(crate) fn lock_plugin_mutation(scope: PluginScope) -> Result<ProjectPluginMutationGuard> {
    ProjectPluginMutationGuard::acquire(&plugin_lock_path(scope)?)
}

pub(crate) fn set_remote_plugin_lock_with_guard(
    scope: PluginScope,
    guard: &ProjectPluginMutationGuard,
    spec: &str,
    entry: Option<RemotePluginLockEntry>,
) -> Result<()> {
    let path = plugin_lock_path(scope)?;
    if guard.project_lock != path {
        bail!("plugin mutation guard does not match the selected lock");
    }
    set_project_remote_plugin_lock_at_locked(&path, spec, entry)
}

#[cfg(test)]
fn set_project_remote_plugin_lock_at(
    path: &Path,
    spec: &str,
    entry: Option<RemotePluginLockEntry>,
) -> Result<()> {
    let _guard = ProjectPluginMutationGuard::acquire(path)?;
    set_project_remote_plugin_lock_at_locked(path, spec, entry)
}

fn set_project_remote_plugin_lock_at_locked(
    path: &Path,
    spec: &str,
    entry: Option<RemotePluginLockEntry>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("could not create '{}'", parent.display()))?;
    // The caller acquired the project guard before any transaction snapshot.
    // Always reread here so this update is based on the latest committed state.
    let mut lock = if path.is_file() {
        let source = pentect_agent::read_bounded_utf8(
            path,
            MAX_PROJECT_PLUGIN_LOCK_BYTES,
            "project plugin lock",
        )
        .map_err(anyhow::Error::msg)?;
        toml::from_str::<ProjectPluginLock>(&source)
            .with_context(|| format!("project plugin lock '{}' is invalid", path.display()))?
    } else {
        ProjectPluginLock {
            schema: "pentect.plugin-project-lock.v1".to_string(),
            plugin: Vec::new(),
        }
    };
    if lock.schema != "pentect.plugin-project-lock.v1" {
        bail!("project plugin lock has an unsupported schema");
    }
    lock.plugin.retain(|item| item.source != spec);
    if let Some(entry) = entry {
        lock.plugin.push(entry);
    }
    lock.plugin
        .sort_by(|left, right| left.source.cmp(&right.source));
    let staged = unique_project_lock_sibling(path, "tmp");
    let encoded = toml::to_string(&lock).context("could not encode project plugin lock")?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .and_then(|mut file| std::io::Write::write_all(&mut file, encoded.as_bytes()))
        .with_context(|| format!("could not stage project plugin lock '{}'", path.display()))?;
    if let Err(error) = atomic_replace(&staged, path) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    Ok(())
}

fn verify_remote_plugin(scope: PluginScope, spec: &str, resolved: &str) -> Result<()> {
    let configured = config_specs_scoped()?
        .iter()
        .any(|(configured_scope, configured)| *configured_scope == scope && configured == spec);
    let path = plugin_lock_path(scope)?;
    let scope_name = match scope {
        PluginScope::User => "user",
        PluginScope::Project => "project",
    };
    let scope_flag = match scope {
        PluginScope::User => "",
        PluginScope::Project => " --project",
    };
    if !path.is_file() {
        if remote_reference_may_run_without_lock(configured, resolved) {
            return Ok(());
        }
        bail!("remote plugin is not locked for this {scope_name} scope; run `pentect plugins add {spec}{scope_flag}`");
    }
    let source = pentect_agent::read_bounded_utf8(
        &path,
        MAX_PROJECT_PLUGIN_LOCK_BYTES,
        "project plugin lock",
    )
    .map_err(anyhow::Error::msg)?;
    let lock: ProjectPluginLock = toml::from_str(&source)
        .with_context(|| format!("project plugin lock '{}' is invalid", path.display()))?;
    if lock.schema != "pentect.plugin-project-lock.v1" {
        bail!("project plugin lock has an unsupported schema");
    }
    let entries = lock
        .plugin
        .iter()
        .filter(|entry| entry.source == spec)
        .collect::<Vec<_>>();
    let [entry] = entries.as_slice() else {
        if entries.is_empty() {
            if remote_reference_may_run_without_lock(configured, resolved) {
                return Ok(());
            }
            bail!("remote plugin is not locked; run `pentect plugins add {spec}{scope_flag}`");
        }
        bail!("remote plugin lock contains duplicate entries for {spec}");
    };
    verify_remote_plugin_lock_entry(spec, resolved, entry)
}

fn verify_remote_plugin_lock_entry(
    spec: &str,
    resolved: &str,
    entry: &RemotePluginLockEntry,
) -> Result<()> {
    if entry.resolved != resolved || entry.files.is_empty() {
        bail!("remote plugin lock does not match {spec}; run `pentect plugins update {spec}`");
    }
    let expected_urls = remote_plugin_urls(resolved);
    let present_urls = expected_urls
        .iter()
        .filter_map(|url| {
            remote_cache_file(url)
                .ok()
                .filter(|path| path.is_file())
                .map(|_| url.as_str())
        })
        .collect::<std::collections::BTreeSet<_>>();
    let locked_urls = entry
        .files
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if present_urls != locked_urls {
        bail!("remote plugin file set changed after it was locked; run `pentect plugins update {spec}`");
    }
    for (url, expected) in &entry.files {
        if !expected_urls.contains(url) || !valid_sha256(expected) {
            bail!("remote plugin lock for {spec} is invalid");
        }
        let path = remote_cache_file(url)?;
        let bytes = pentect_agent::read_bounded_bytes(
            &path,
            MAX_REMOTE_PLUGIN_FILE_BYTES,
            "locked remote plugin file",
        )
        .map_err(anyhow::Error::msg)?;
        let actual = data_encoding::HEXLOWER.encode(&Sha256::digest(bytes));
        if actual != *expected {
            bail!(
                "remote plugin content changed after it was locked; run `pentect plugins update {spec}`"
            );
        }
    }
    Ok(())
}

fn remote_plugin_urls(resolved: &str) -> Vec<String> {
    let mut urls = if resolved.ends_with(".toml") {
        vec![resolved.to_string()]
    } else {
        let base = resolved.trim_end_matches('/');
        vec![
            format!("{base}/{PLUGIN_MANIFEST_FILE}"),
            format!("{base}/{PLUGIN_CONFIG_FILE}"),
        ]
    };
    let manifest_url = if resolved.ends_with("/plugin.toml") {
        resolved.to_string()
    } else if resolved.ends_with(".toml") {
        return urls;
    } else {
        format!(
            "{}/{}",
            resolved.trim_end_matches('/'),
            PLUGIN_MANIFEST_FILE
        )
    };
    if let Ok(path) = remote_cache_file(&manifest_url) {
        let base = manifest_url.trim_end_matches("/plugin.toml");
        if let Ok(files) = command_files_from_manifest(base, &path) {
            urls.extend(files.into_iter().map(|(_, url)| url));
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

fn command_files_from_manifest(base: &str, manifest: &Path) -> Result<Vec<(PathBuf, String)>> {
    let source =
        pentect_agent::read_bounded_utf8(manifest, MAX_REMOTE_PLUGIN_FILE_BYTES, "plugin manifest")
            .map_err(anyhow::Error::msg)?;
    let value = source
        .parse::<toml::Value>()
        .with_context(|| format!("could not parse plugin manifest '{}'", manifest.display()))?;
    let mut files = Vec::new();
    let direct = value.get("command").and_then(toml::Value::as_array);
    let platforms = value.get("commands").and_then(toml::Value::as_table);
    if direct.is_some() && platforms.is_some() {
        bail!("plugin.toml cannot set both command and [commands]");
    }
    let setup = value.get("setup").and_then(toml::Value::as_table);
    let setup_direct = setup
        .and_then(|table| table.get("command"))
        .and_then(toml::Value::as_array);
    let setup_platforms = setup
        .and_then(|table| table.get("commands"))
        .and_then(toml::Value::as_table);
    if setup_direct.is_some() && setup_platforms.is_some() {
        bail!("plugin.toml cannot set both setup.command and [setup.commands]");
    }
    let commands = direct
        .into_iter()
        .chain(
            platforms
                .into_iter()
                .flat_map(|table| table.values().filter_map(toml::Value::as_array)),
        )
        .chain(setup_direct)
        .chain(
            setup_platforms
                .into_iter()
                .flat_map(|table| table.values().filter_map(toml::Value::as_array)),
        )
        .collect::<Vec<_>>();
    for argument in commands
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
    {
        let Some(relative) = argument.strip_prefix("{plugin}/") else {
            continue;
        };
        let relative = PathBuf::from(relative);
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("command plugin file paths must stay inside the plugin directory");
        }
        let url_path = relative
            .iter()
            .map(|part| part.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        files.push((
            relative,
            format!("{}/{url_path}", base.trim_end_matches('/')),
        ));
        if files.len() > 64 {
            bail!("command plugins may distribute at most 64 files");
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files.dedup_by(|left, right| left.0 == right.0);
    Ok(files)
}

#[cfg(test)]
fn refresh_remote_command_files(base: &str, manifest: Option<&Path>) -> Result<()> {
    refresh_remote_command_files_in_session(base, manifest, &RemotePluginFetchSession::default())
}

fn refresh_remote_command_files_in_session(
    base: &str,
    manifest: Option<&Path>,
    fetch: &RemotePluginFetchSession,
) -> Result<()> {
    let Some(manifest) = manifest else {
        return Ok(());
    };
    let command_files =
        command_files_from_manifest(base.trim_end_matches("/plugin.toml"), manifest)?;
    fetch.protect_urls(command_files.iter().map(|(_, url)| url.as_str()))?;
    for (_, url) in command_files {
        fetch_remote_plugin_file_in_session(&url, true, fetch)?
            .ok_or_else(|| anyhow!("remote command plugin file was not found: {url}"))?;
    }
    Ok(())
}

pub(crate) fn remote_command_files(source: &PluginSource) -> Result<Vec<(PathBuf, PathBuf)>> {
    let (Some(base), Some(manifest)) = (
        source.remote_base.as_deref(),
        source.manifest_path.as_deref(),
    ) else {
        return Ok(Vec::new());
    };
    let base = base.trim_end_matches("/plugin.toml");
    let files = command_files_from_manifest(base, manifest)?;
    let fetch = RemotePluginFetchSession::default();
    fetch.protect_urls(remote_plugin_urls(base).iter().map(String::as_str))?;
    files
        .into_iter()
        .map(|(relative, url)| {
            let cached = fetch_remote_plugin_file_in_session(&url, false, &fetch)?
                .ok_or_else(|| anyhow!("remote command plugin file was not found: {url}"))?;
            Ok((relative, cached))
        })
        .collect()
}

fn remote_reference_is_full_commit(resolved: &str) -> bool {
    resolved
        .strip_prefix("https://raw.githubusercontent.com/")
        .and_then(|rest| rest.split('/').nth(2))
        .is_some_and(|reference| {
            reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn remote_reference_may_run_without_lock(configured: bool, resolved: &str) -> bool {
    !configured && remote_reference_is_full_commit(resolved)
}

fn unique_project_lock_sibling(path: &Path, purpose: &str) -> PathBuf {
    let sequence = PROJECT_LOCK_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!(
        "lock.{purpose}-{}-{nanos}-{sequence}",
        std::process::id()
    ))
}

pub(crate) struct ProjectPluginMutationGuard {
    file: File,
    project_lock: PathBuf,
}

impl ProjectPluginMutationGuard {
    fn acquire(project_lock: &Path) -> Result<Self> {
        let project_root = project_lock
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let guard_path = project_root.join(PENTECT_DIR).join("plugin-lock.guard");
        if let Some(parent) = guard_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "could not create project plugin lock guard directory '{}'",
                    parent.display()
                )
            })?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&guard_path)
            .with_context(|| {
                format!(
                    "could not open project plugin lock guard '{}'",
                    guard_path.display()
                )
            })?;
        if !try_lock_project_file(&file).with_context(|| {
            format!(
                "could not inspect project plugin lock guard '{}'",
                guard_path.display()
            )
        })? {
            eprintln!("[pentect] waiting for another plugin operation to finish");
            lock_project_file(&file).with_context(|| {
                format!(
                    "could not acquire project plugin lock guard '{}'",
                    guard_path.display()
                )
            })?;
        }
        Ok(Self {
            file,
            project_lock: project_lock.to_path_buf(),
        })
    }
}

impl Drop for ProjectPluginMutationGuard {
    fn drop(&mut self) {
        let _ = unlock_project_file(&self.file);
    }
}

#[cfg(unix)]
fn try_lock_project_file(file: &File) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    let raw = error.raw_os_error();
    if raw == Some(libc::EWOULDBLOCK) || raw == Some(libc::EAGAIN) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn lock_project_file(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_project_file(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn try_lock_project_file(file: &File) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result != 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(windows)]
fn lock_project_file(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn unlock_project_file(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
    let result = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as _,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(unix)]
fn atomic_replace(staged: &Path, destination: &Path) -> Result<()> {
    // POSIX rename replaces an existing same-filesystem destination atomically.
    std::fs::rename(staged, destination)
        .with_context(|| format!("could not atomically install '{}'", destination.display()))
}

#[cfg(windows)]
fn atomic_replace(staged: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let staged = staged
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            staged.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
            .with_context(|| format!("could not atomically install '{}'", destination.display()))
    }
}

fn fetch_remote_plugin_file_with_refresh(url: &str, refresh: bool) -> Result<Option<PathBuf>> {
    fetch_remote_plugin_file_in_session(url, refresh, &RemotePluginFetchSession::default())
}

#[derive(Clone, Default)]
struct RemotePluginFetchSession {
    protected: Arc<Mutex<BTreeSet<PathBuf>>>,
}

impl RemotePluginFetchSession {
    fn protect_urls<'a>(&self, urls: impl IntoIterator<Item = &'a str>) -> Result<()> {
        for url in urls {
            self.protect(remote_cache_file(url)?)?;
        }
        Ok(())
    }

    fn protect(&self, path: PathBuf) -> Result<Vec<PathBuf>> {
        let mut protected = self
            .protected
            .lock()
            .map_err(|_| anyhow!("remote plugin cache protection lock poisoned"))?;
        protected.insert(path);
        Ok(protected.iter().cloned().collect())
    }
}

fn fetch_remote_plugin_file_in_session(
    url: &str,
    refresh: bool,
    session: &RemotePluginFetchSession,
) -> Result<Option<PathBuf>> {
    let path = remote_cache_file(url)?;
    let protected = session.protect(path.clone())?;
    if let Some(cache_root) = path.parent().and_then(Path::parent) {
        prune_remote_plugin_cache(cache_root, &protected)?;
    }
    let missing = remote_missing_file(&path);
    if !refresh && path.is_file() {
        return Ok(Some(path));
    }
    if !refresh && missing.is_file() {
        return Ok(None);
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
        let _ = std::fs::remove_file(&path);
        if let Some(parent) = missing.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create plugin cache '{}'", parent.display()))?;
        }
        std::fs::write(&missing, [])
            .with_context(|| format!("could not write plugin cache '{}'", missing.display()))?;
        if let Some(cache_root) = path.parent().and_then(Path::parent) {
            let protected = session.protect(missing.clone())?;
            prune_remote_plugin_cache(cache_root, &protected)?;
        }
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
    let _ = std::fs::remove_file(missing);
    if let Some(cache_root) = path.parent().and_then(Path::parent) {
        let protected = session.protect(path.clone())?;
        prune_remote_plugin_cache(cache_root, &protected)?;
    }
    Ok(Some(path))
}

#[derive(Debug)]
struct RemoteCacheEntry {
    path: PathBuf,
    bytes: u64,
    modified: SystemTime,
}

fn prune_remote_plugin_cache(cache_root: &Path, protected: &[PathBuf]) -> Result<()> {
    prune_remote_plugin_cache_with_limits(
        cache_root,
        protected,
        MAX_REMOTE_PLUGIN_CACHE_BYTES,
        MAX_REMOTE_PLUGIN_CACHE_ENTRIES,
    )
}

fn prune_remote_plugin_cache_with_limits(
    cache_root: &Path,
    protected: &[PathBuf],
    max_bytes: u64,
    max_entries: usize,
) -> Result<()> {
    if !cache_root.is_dir() {
        return Ok(());
    }

    let protected_entries = protected
        .iter()
        .filter_map(|path| path.strip_prefix(cache_root).ok())
        .filter_map(|relative| {
            relative
                .components()
                .next()
                .map(|component| cache_root.join(component.as_os_str()))
        })
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::new();
    let cache_entries = match std::fs::read_dir(cache_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("could not inspect plugin cache '{}'", cache_root.display())
            });
        }
    };
    for entry in cache_entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not inspect plugin cache '{}'", cache_root.display())
                });
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not inspect '{}'", entry.path().display()));
            }
        };
        if !file_type.is_dir() {
            continue;
        }
        let (bytes, modified) = remote_cache_entry_usage(&entry.path())?;
        entries.push(RemoteCacheEntry {
            path: entry.path(),
            bytes,
            modified,
        });
    }

    let mut total_bytes = entries.iter().map(|entry| entry.bytes).sum::<u64>();
    let mut total_entries = entries.len();
    if total_bytes <= max_bytes && total_entries <= max_entries {
        return Ok(());
    }

    entries.sort_by_key(|entry| entry.modified);
    for entry in entries {
        if total_bytes <= max_bytes && total_entries <= max_entries {
            break;
        }
        if protected_entries.contains(&entry.path) {
            continue;
        }
        if let Err(error) = std::fs::remove_dir_all(&entry.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error).with_context(|| {
                    format!(
                        "could not remove old plugin cache entry '{}'",
                        entry.path.display()
                    )
                });
            }
        }
        total_bytes = total_bytes.saturating_sub(entry.bytes);
        total_entries = total_entries.saturating_sub(1);
    }
    Ok(())
}

fn remote_cache_entry_usage(path: &Path) -> Result<(u64, SystemTime)> {
    let mut bytes = 0_u64;
    let mut modified = SystemTime::UNIX_EPOCH;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not inspect plugin cache '{}'", directory.display())
                });
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("could not inspect plugin cache '{}'", directory.display())
                    });
                }
            };
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("could not inspect '{}'", entry.path().display())
                    });
                }
            };
            modified = modified.max(metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH));
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            }
        }
    }
    Ok((bytes, modified))
}

fn remote_missing_file(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}missing",
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ))
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
        let (path, reference) = match path.rsplit_once('@') {
            Some((path, reference)) if !path.is_empty() && valid_github_reference(reference) => {
                (path, reference)
            }
            Some(_) => bail!("invalid GitHub plugin version in shorthand: {url}"),
            None => (path.as_str(), "main"),
        };
        if !valid_github_segment(owner) || !valid_github_segment(repo) {
            bail!("invalid GitHub owner or repository in plugin shorthand: {url}");
        }
        return Ok(format!(
            "https://raw.githubusercontent.com/{owner}/{repo}/{reference}/{path}"
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

fn valid_github_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !value.ends_with('.')
        && !value.contains("..")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
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

        let active = active_from_selected_specs(vec![root.display().to_string()], true).unwrap();
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
    fn user_scoped_github_plugin_is_not_resolved_as_a_local_path() {
        let spec = "github:@EdamAme-x/pentect/plugins/example-regex";
        assert_eq!(
            plugin_spec_for_scope(spec, PluginScope::User).unwrap(),
            spec
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
    fn remote_plugin_cache_prunes_entries_without_removing_the_active_download() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pentect-plugin-cache-prune-{nonce}"));
        let first = root.join("first").join("plugin.toml");
        let second = root.join("second").join("plugin.toml");
        let protected = root.join("protected").join("plugin.toml");
        for path in [&first, &second, &protected] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"1234").unwrap();
        }

        prune_remote_plugin_cache_with_limits(&root, std::slice::from_ref(&protected), 8, 2)
            .unwrap();

        assert!(protected.is_file());
        let remaining = std::fs::read_dir(&root).unwrap().count();
        assert_eq!(remaining, 2);
        let remaining_bytes = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| remote_cache_entry_usage(&entry.unwrap().path()).unwrap().0)
            .sum::<u64>();
        assert_eq!(remaining_bytes, 8);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_plugin_cache_pruning_preserves_all_files_in_one_fetch_session() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pentect-plugin-cache-session-{nonce}"));
        let old = root.join("old").join("plugin.toml");
        let manifest = root.join("manifest").join("plugin.toml");
        let config = root.join("config").join("config.toml");
        for path in [&old, &manifest, &config] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"1234").unwrap();
        }

        prune_remote_plugin_cache_with_limits(&root, &[manifest.clone(), config.clone()], 4, 1)
            .unwrap();

        assert!(!old.exists());
        assert!(manifest.is_file());
        assert!(config.is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn github_shorthand_supports_an_explicit_version() {
        assert_eq!(
            normalize_github_plugin_url("github:@owner/repo/plugins/pii@v1.2.3").unwrap(),
            "https://raw.githubusercontent.com/owner/repo/v1.2.3/plugins/pii"
        );
        assert!(normalize_github_plugin_url("github:@owner/repo/plugins/pii@../main").is_err());
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert!(remote_reference_is_full_commit(&format!(
            "https://raw.githubusercontent.com/owner/repo/{commit}/plugins/pii"
        )));
        assert!(!remote_reference_is_full_commit(
            "https://raw.githubusercontent.com/owner/repo/main/plugins/pii"
        ));
        assert!(!remote_reference_is_full_commit(
            "https://raw.githubusercontent.com/owner/repo/v1.2.3/plugins/pii"
        ));
        assert!(!remote_reference_may_run_without_lock(
            false,
            "https://raw.githubusercontent.com/owner/repo/v1.2.3/plugins/pii"
        ));
        assert!(remote_reference_may_run_without_lock(
            false,
            &format!("https://raw.githubusercontent.com/owner/repo/{commit}/plugins/pii")
        ));
        assert!(!remote_reference_may_run_without_lock(
            true,
            &format!("https://raw.githubusercontent.com/owner/repo/{commit}/plugins/pii")
        ));
    }

    #[test]
    fn platform_commands_lock_files_for_every_supported_os() {
        let root = std::env::temp_dir().join(format!(
            "pentect-platform-command-files-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let manifest = root.join("plugin.toml");
        std::fs::write(
            &manifest,
            "schema = \"pentect.plugin.v1\"\n[commands]\nwindows = [\"{plugin}/windows.exe\"]\nmacos = [\"{plugin}/macos\"]\nlinux = [\"{plugin}/linux\"]\n[setup.commands]\nwindows = [\"py\", \"{plugin}/setup.py\"]\nmacos = [\"python3\", \"{plugin}/setup.py\"]\nlinux = [\"python3\", \"{plugin}/setup.py\"]\n",
        )
        .unwrap();
        let files = command_files_from_manifest("https://example.test/plugin", &manifest).unwrap();
        assert_eq!(
            files
                .iter()
                .map(|(path, _)| path.to_string_lossy().replace('\\', "/"))
                .collect::<Vec<_>>(),
            ["linux", "macos", "setup.py", "windows.exe"]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn refreshing_a_manifest_refetches_cached_command_files() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let command_url = format!("{base}/server.py");
        let cached = remote_cache_file(&command_url).unwrap();
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, b"old command").unwrap();
        let root = std::env::temp_dir().join(format!(
            "pentect-refresh-command-files-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let manifest = root.join("plugin.toml");
        std::fs::write(
            &manifest,
            "schema = \"pentect.plugin.v1\"\ncommand = [\"python3\", \"{plugin}/server.py\"]\n",
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nnew command")
                .unwrap();
        });

        refresh_remote_command_files(&base, Some(&manifest)).unwrap();
        server.join().unwrap();

        assert_eq!(std::fs::read(&cached).unwrap(), b"new command");
        let _ = std::fs::remove_dir_all(cached.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remote_lock_detects_cached_content_changes() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let resolved =
            format!("https://raw.githubusercontent.com/owner/repo/main/plugins/lock-test-{nonce}");
        let manifest_url = format!("{resolved}/plugin.toml");
        let path = remote_cache_file(&manifest_url).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = b"schema = \"pentect.plugin.v1\"\n";
        std::fs::write(&path, original).unwrap();
        let entry = RemotePluginLockEntry {
            source: resolved.clone(),
            resolved: resolved.clone(),
            files: BTreeMap::from([(
                manifest_url,
                data_encoding::HEXLOWER.encode(&Sha256::digest(original)),
            )]),
        };
        verify_remote_plugin_lock_entry(&resolved, &resolved, &entry).unwrap();
        std::fs::write(&path, b"changed").unwrap();
        assert!(verify_remote_plugin_lock_entry(&resolved, &resolved, &entry).is_err());
        std::fs::write(&path, original).unwrap();
        let config = remote_cache_file(&format!("{resolved}/config.toml")).unwrap();
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, b"[[detector]]\npattern = \"new\"\n").unwrap();
        assert!(verify_remote_plugin_lock_entry(&resolved, &resolved, &entry).is_err());
        let parent = path.parent().unwrap().to_path_buf();
        let config_parent = config.parent().unwrap().to_path_buf();
        let _ = std::fs::remove_dir_all(parent);
        let _ = std::fs::remove_dir_all(config_parent);
    }

    #[test]
    fn project_remote_lock_update_is_atomic_and_sorted() {
        let root = std::env::temp_dir().join(format!(
            "pentect-project-plugin-lock-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("plugins.lock");
        let entry = |source: &str| RemotePluginLockEntry {
            source: source.to_string(),
            resolved: format!("https://raw.githubusercontent.com/{source}"),
            files: BTreeMap::from([("file".to_string(), "0".repeat(64))]),
        };
        set_project_remote_plugin_lock_at(&path, "z/repo", Some(entry("z/repo"))).unwrap();
        set_project_remote_plugin_lock_at(&path, "a/repo", Some(entry("a/repo"))).unwrap();
        let source = std::fs::read_to_string(&path).unwrap();
        let lock: ProjectPluginLock = toml::from_str(&source).unwrap();
        assert_eq!(
            lock.plugin
                .iter()
                .map(|entry| entry.source.as_str())
                .collect::<Vec<_>>(),
            ["a/repo", "z/repo"]
        );
        set_project_remote_plugin_lock_at(&path, "a/repo", None).unwrap();
        let lock: ProjectPluginLock =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(lock.plugin.len(), 1);
        assert_eq!(lock.plugin[0].source, "z/repo");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_project_lock_updates_do_not_lose_entries() {
        use std::sync::{Arc, Barrier};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-project-plugin-lock-concurrent-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("plugins.lock");
        let count = 12;
        let barrier = Arc::new(Barrier::new(count));
        let mut threads = Vec::new();
        for index in 0..count {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let source = format!("owner/repo-{index}");
                let entry = RemotePluginLockEntry {
                    source: source.clone(),
                    resolved: format!("https://raw.githubusercontent.com/{source}"),
                    files: BTreeMap::from([("file".to_string(), "0".repeat(64))]),
                };
                barrier.wait();
                set_project_remote_plugin_lock_at(&path, &source, Some(entry)).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let lock: ProjectPluginLock =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(lock.plugin.len(), count);
        for index in 0..count {
            assert!(
                lock.plugin
                    .iter()
                    .any(|entry| entry.source == format!("owner/repo-{index}")),
                "concurrent update {index} was lost"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_transaction_rollback_cannot_erase_a_concurrent_success() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-plugin-transaction-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let lock_path = root.join("pentect.plugins.lock");
        let config_path = root.join("config.toml");
        let (a_ready_tx, a_ready_rx) = std::sync::mpsc::channel();
        let (b_attempt_tx, b_attempt_rx) = std::sync::mpsc::channel();

        let a_lock = lock_path.clone();
        let a_config = config_path.clone();
        let failed = std::thread::spawn(move || {
            let guard = ProjectPluginMutationGuard::acquire(&a_lock).unwrap();
            std::fs::write(&a_config, b"plugins = ['failed']\n").unwrap();
            let entry = RemotePluginLockEntry {
                source: "failed".to_string(),
                resolved: "https://raw.githubusercontent.com/owner/failed/main".to_string(),
                files: BTreeMap::from([("failed".to_string(), "0".repeat(64))]),
            };
            set_project_remote_plugin_lock_at_locked(&a_lock, "failed", Some(entry)).unwrap();
            a_ready_tx.send(()).unwrap();
            b_attempt_rx.recv().unwrap();
            // This models restoring the transaction's original empty snapshot.
            std::fs::remove_file(&a_config).unwrap();
            std::fs::remove_file(&a_lock).unwrap();
            drop(guard);
        });

        let b_lock = lock_path.clone();
        let b_config = config_path.clone();
        let succeeded = std::thread::spawn(move || {
            a_ready_rx.recv().unwrap();
            b_attempt_tx.send(()).unwrap();
            let _guard = ProjectPluginMutationGuard::acquire(&b_lock).unwrap();
            std::fs::write(&b_config, b"plugins = ['success']\n").unwrap();
            let entry = RemotePluginLockEntry {
                source: "success".to_string(),
                resolved: "https://raw.githubusercontent.com/owner/success/main".to_string(),
                files: BTreeMap::from([("success".to_string(), "0".repeat(64))]),
            };
            set_project_remote_plugin_lock_at_locked(&b_lock, "success", Some(entry)).unwrap();
        });

        failed.join().unwrap();
        succeeded.join().unwrap();
        assert_eq!(
            std::fs::read_to_string(&config_path).unwrap(),
            "plugins = ['success']\n"
        );
        let lock: ProjectPluginLock =
            toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
        assert_eq!(lock.plugin.len(), 1);
        assert_eq!(lock.plugin[0].source, "success");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn refreshed_remote_cache_can_be_rolled_back_as_one_set() {
        let root = std::env::temp_dir().join(format!(
            "pentect-remote-cache-rollback-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let existing = root.join("plugin.toml");
        let newly_created = root.join("config.toml");
        std::fs::write(&existing, b"old").unwrap();
        let snapshot = RemotePluginCacheSnapshot {
            files: vec![
                (existing.clone(), Some(b"old".to_vec())),
                (newly_created.clone(), None),
            ],
            previous_sources: BTreeMap::new(),
        };
        std::fs::write(&existing, b"new").unwrap();
        std::fs::write(&newly_created, b"new config").unwrap();
        restore_remote_plugin_cache(&snapshot).unwrap();
        assert_eq!(std::fs::read(&existing).unwrap(), b"old");
        assert!(!newly_created.exists());
        let _ = std::fs::remove_dir_all(root);
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
    fn plugins_equals_form_is_consumed_before_child_arguments() {
        let args = vec![
            "exec".to_string(),
            "--plugins=rules,company".to_string(),
            "--".to_string(),
            "--plugins=child-owned".to_string(),
        ];
        let (stripped, specs) = strip_from_args(&args).unwrap();
        assert_eq!(specs, ["rules", "company"]);
        assert_eq!(
            stripped,
            ["exec", "--", "--plugins=child-owned"].map(str::to_string)
        );

        let hook = [
            "hook".to_string(),
            "--session".to_string(),
            "test".to_string(),
            "--plugins=rules".to_string(),
        ];
        let (stripped, specs) = strip_from_args(&hook).unwrap();
        assert_eq!(specs, ["rules"]);
        assert_eq!(stripped, ["hook", "--session", "test"].map(str::to_string));

        assert_eq!(
            collect_from_args(&["mask".to_string(), "--plugins=rules".to_string()]).unwrap(),
            ["rules"]
        );
        assert!(collect_from_args(&["--plugins=".to_string()]).is_err());
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
            "schema = \"pentect.plugin.v1\"\nbinary = \"tool.wasm\"\n",
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
            "schema = \"pentect.plugin.v1\"\nbinary = \"tool\"\n",
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
            "schema = \"pentect.plugin.v1\"\nbinary = \"tool\"\n",
        )
        .unwrap();

        let active = active_from_selected_specs(vec![root.display().to_string()], true).unwrap();
        let packs = load_config_packs_from_active(&active).unwrap();
        assert!(packs.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_tool_plugin_coverage_only_blocks_in_strict_mode() {
        assert!(enforce_tool_plugin_coverage_with_policy(
            pentect_agent::MiddlewareCoverage::Partial,
            true,
            "fixture"
        )
        .is_err());
        assert!(enforce_tool_plugin_coverage_with_policy(
            pentect_agent::MiddlewareCoverage::Partial,
            false,
            "fixture"
        )
        .is_ok());
        assert!(enforce_tool_plugin_coverage_with_policy(
            pentect_agent::MiddlewareCoverage::Full,
            true,
            "fixture"
        )
        .is_ok());
    }
}
