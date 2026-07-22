use crate::{plugins, update};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PENTECT_DIR: &str = ".pentect";
const PLUGINS_DATA_DIR: &str = "plugins-data";
const PLUGIN_CONFIG_FILE: &str = "config.toml";
const PLUGIN_CACHE_DIR: &str = "cache";
const PLUGIN_NAME_ENV: &str = "PENTECT_PLUGIN_NAME";
const PLUGIN_DATA_DIR_ENV: &str = "PENTECT_PLUGIN_DATA_DIR";
const PLUGIN_CACHE_DIR_ENV: &str = "PENTECT_PLUGIN_CACHE_DIR";
const PLUGIN_CONFIG_ENV: &str = "PENTECT_PLUGIN_CONFIG";
const MAX_STDOUT_BYTES: usize = 1024 * 1024;

pub(crate) fn cmd_plugins(args: &[String]) {
    let opts = match PluginCmd::parse(args) {
        Ok(opts) => opts,
        Err(e) => crate::die(e),
    };
    let result = match opts.action {
        Action::List => list_plugins(opts.json),
        Action::Inspect { spec } => inspect_plugin(&spec, opts.json),
        Action::Test { spec } => test_plugin(&spec, opts.json),
        Action::Config { spec, change } => config_plugin(&spec, change, opts.json),
        Action::Setup { spec, approved } => setup_plugin(&spec, approved, opts.json),
        Action::Update { spec } => update_plugin(&spec, opts.json),
    };
    if let Err(e) = result {
        crate::die(e);
    }
}

#[derive(Debug)]
struct PluginCmd {
    action: Action,
    json: bool,
}

#[derive(Debug)]
enum Action {
    List,
    Inspect { spec: String },
    Test { spec: String },
    Config { spec: String, change: ConfigChange },
    Setup { spec: String, approved: bool },
    Update { spec: String },
}

#[derive(Debug)]
enum ConfigChange {
    Show,
    Set(String),
    Unset(String),
}

impl PluginCmd {
    fn parse(args: &[String]) -> Result<Self, String> {
        let Some(action) = args.get(2).map(String::as_str) else {
            return Err("plugins list|inspect|test|config|setup|update".to_string());
        };
        let mut json = false;
        let mut approved = false;
        let mut unset = None;
        let mut values = Vec::new();
        let mut i = 3usize;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => json = true,
                "--yes" => approved = true,
                "--unset" => {
                    let Some(key) = args.get(i + 1) else {
                        return Err("--unset requires a key".to_string());
                    };
                    unset = Some(key.clone());
                    i += 1;
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value => values.push(value.to_string()),
            }
            i += 1;
        }
        let action = match action {
            "list" => {
                reject_action_flags(approved, unset.as_deref())?;
                if !values.is_empty() {
                    return Err("plugins list".to_string());
                }
                Action::List
            }
            "inspect" => {
                reject_action_flags(approved, unset.as_deref())?;
                Action::Inspect {
                    spec: one_value("plugins inspect", values)?,
                }
            }
            "test" => {
                reject_action_flags(approved, unset.as_deref())?;
                Action::Test {
                    spec: one_value("plugins test", values)?,
                }
            }
            "config" => {
                if approved {
                    return Err("--yes is only valid for plugins setup".to_string());
                }
                let spec = values
                    .first()
                    .cloned()
                    .ok_or_else(|| "plugins config NAME|PATH [KEY=VALUE]".to_string())?;
                let change = match (values.get(1), values.get(2), unset) {
                    (None, None, None) => ConfigChange::Show,
                    (Some(value), None, None) => ConfigChange::Set(value.clone()),
                    (None, None, Some(key)) => ConfigChange::Unset(key),
                    _ => {
                        return Err("plugins config NAME|PATH [KEY=VALUE | --unset KEY]".to_string())
                    }
                };
                Action::Config { spec, change }
            }
            "setup" => {
                if unset.is_some() {
                    return Err("--unset is only valid for plugins config".to_string());
                }
                Action::Setup {
                    spec: one_value("plugins setup", values)?,
                    approved,
                }
            }
            "update" => {
                reject_action_flags(approved, unset.as_deref())?;
                Action::Update {
                    spec: one_value("plugins update", values)?,
                }
            }
            other => return Err(format!("unknown plugins command: {other}")),
        };
        Ok(Self { action, json })
    }
}

fn reject_action_flags(approved: bool, unset: Option<&str>) -> Result<(), String> {
    if approved {
        return Err("--yes is only valid for plugins setup".to_string());
    }
    if unset.is_some() {
        return Err("--unset is only valid for plugins config".to_string());
    }
    Ok(())
}

fn one_value(command: &str, values: Vec<String>) -> Result<String, String> {
    match values.as_slice() {
        [value] => Ok(value.clone()),
        _ => Err(format!("{command} NAME|PATH")),
    }
}

fn list_plugins(json_output: bool) -> Result<(), String> {
    let mut rows = plugin_rows()?;
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.source.cmp(b.source)));
    if json_output {
        println!(
            "{}",
            json!({
                "plugins": rows.iter().map(|row| json!({
                    "name": row.name,
                    "source": row.source,
                    "status": row.status(),
                    "configs": row.configs,
                    "runtimes": row.runtimes,
                })).collect::<Vec<_>>()
            })
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!("none");
        return Ok(());
    }
    for row in rows {
        println!(
            "{}: {} {} configs={} runtimes={}",
            row.name,
            row.source,
            row.status(),
            row.configs,
            row.runtimes
        );
    }
    Ok(())
}

fn inspect_plugin(spec: &str, json_output: bool) -> Result<(), String> {
    let active = active_for_one(spec)?;
    let source = plugins::plugin_source(spec).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?;
    if json_output {
        println!(
            "{}",
            json!({
                "name": plugin_name(&source, manifest.as_ref()),
                "description": manifest.as_ref().and_then(|manifest| manifest.description.as_deref()),
                "manifest": source.manifest_path.as_deref().map(display_path),
                "configs": active.config_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
                "runtimes": active.adapter_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
                "postscripts": manifest.as_ref().map(|manifest| manifest.postscript.len()).unwrap_or(0),
                "artifacts": manifest.as_ref().map(|manifest| manifest.artifact.len()).unwrap_or(0),
            })
        );
        return Ok(());
    }
    println!("name: {}", plugin_name(&source, manifest.as_ref()));
    if let Some(description) = manifest
        .as_ref()
        .and_then(|manifest| manifest.description.as_deref())
    {
        println!("description: {description}");
    }
    if let Some(path) = source.manifest_path.as_deref() {
        println!("manifest: {}", display_path(path));
    }
    println!("configs: {}", active.config_paths().len());
    for path in active.config_paths() {
        println!("config: {}", display_path(path));
    }
    println!("runtimes: {}", active.adapter_paths().len());
    for path in active.adapter_paths() {
        println!("runtime: {}", display_path(path));
    }
    println!(
        "postscripts: {}",
        manifest
            .as_ref()
            .map(|manifest| manifest.postscript.len())
            .unwrap_or(0)
    );
    println!(
        "artifacts: {}",
        manifest
            .as_ref()
            .map(|manifest| manifest.artifact.len())
            .unwrap_or(0)
    );
    Ok(())
}

fn test_plugin(spec: &str, json_output: bool) -> Result<(), String> {
    let active = active_for_one(spec)?;
    let mut checks = Vec::new();
    for path in active.config_paths() {
        checks.push(test_pack(path));
    }
    for path in active.adapter_paths() {
        checks.push(test_adapter(path));
    }
    if checks.is_empty() {
        checks.push(Check::fail("plugin", "empty"));
    }
    if json_output {
        println!(
            "{}",
            json!({
                "checks": checks.iter().map(|check| json!({
                    "name": check.name,
                    "status": check.status.as_str(),
                    "detail": check.detail,
                })).collect::<Vec<_>>()
            })
        );
    } else {
        for check in &checks {
            println!("{}: {}", check.name, check.status.as_str());
        }
    }
    if checks.iter().any(|check| check.status == Status::Fail) {
        return Err("plugin test failed".to_string());
    }
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
struct PluginManifest {
    schema: Option<String>,
    name: Option<String>,
    description: Option<String>,
    runtime: Option<RuntimeToml>,
    #[serde(default)]
    postscript: Vec<Postscript>,
    #[serde(default)]
    artifact: Vec<ReleaseArtifact>,
}

#[derive(Debug, Deserialize)]
struct ReleaseArtifact {
    name: String,
    repository: String,
    destination: Option<String>,
    assets: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Postscript {
    name: Option<String>,
    command: Vec<String>,
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    permissions: Vec<String>,
    timeout_ms: Option<u64>,
}

fn load_plugin_manifest(source: &plugins::PluginSource) -> Result<Option<PluginManifest>, String> {
    let Some(path) = &source.manifest_path else {
        return Ok(None);
    };
    let src = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "could not read plugin manifest '{}': {e}",
            display_path(path)
        )
    })?;
    let manifest: PluginManifest = toml::from_str(&src)
        .map_err(|e| format!("invalid plugin manifest '{}': {e}", display_path(path)))?;
    if manifest.schema.as_deref() != Some("pentect.plugin.v1") {
        return Err(format!(
            "plugin manifest '{}' requires schema = \"pentect.plugin.v1\"; found '{}'",
            display_path(path),
            manifest.schema.as_deref().unwrap_or_default()
        ));
    }
    Ok(Some(manifest))
}

fn plugin_name(source: &plugins::PluginSource, manifest: Option<&PluginManifest>) -> String {
    manifest
        .and_then(|manifest| manifest.name.as_deref())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&source.name)
        .to_string()
}

fn config_plugin(spec: &str, change: ConfigChange, json_output: bool) -> Result<(), String> {
    let source = plugins::plugin_source(spec).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?;
    let name = plugin_name(&source, manifest.as_ref());
    let dirs = plugin_runtime_dirs(&plugin_id(&name))?;
    let path = dirs.config_file;
    let mut table = read_plugin_config(&path)?;
    let action = match change {
        ConfigChange::Show => "show",
        ConfigChange::Set(assignment) => {
            let (key, raw_value) = assignment.split_once('=').ok_or_else(|| {
                "config assignment must be KEY=VALUE; quote strings as needed".to_string()
            })?;
            let key = key.trim();
            if key.is_empty() || raw_value.trim().is_empty() {
                return Err("config assignment must be KEY=VALUE".to_string());
            }
            let update = parse_config_assignment(key, raw_value.trim())?;
            merge_toml_tables(&mut table, update);
            write_plugin_config(&path, &table)?;
            "set"
        }
        ConfigChange::Unset(key) => {
            if !remove_toml_key(&mut table, &key)? {
                return Err(format!("config key was not set: {key}"));
            }
            write_plugin_config(&path, &table)?;
            "unset"
        }
    };
    let keys = toml_leaf_keys(&table);
    if json_output {
        println!(
            "{}",
            json!({
                "name": name,
                "action": action,
                "path": display_path(&path),
                "keys": keys,
            })
        );
    } else {
        println!("config: {}", display_path(&path));
        println!(
            "keys: {}",
            if keys.is_empty() {
                "none".to_string()
            } else {
                keys.join(", ")
            }
        );
    }
    Ok(())
}

fn read_plugin_config(path: &Path) -> Result<toml::Table, String> {
    if !path.exists() {
        return Ok(toml::Table::new());
    }
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read plugin config '{}': {e}", display_path(path)))?;
    toml::from_str(&src).map_err(|e| format!("invalid plugin config '{}': {e}", display_path(path)))
}

fn parse_config_assignment(key: &str, value: &str) -> Result<toml::Table, String> {
    validate_config_key(key)?;
    let src = format!("{key} = {value}");
    toml::from_str(&src)
        .or_else(|_| {
            let quoted = toml::Value::String(value.to_string()).to_string();
            toml::from_str(&format!("{key} = {quoted}"))
        })
        .map_err(|e| format!("invalid config assignment '{key}': {e}"))
}

fn validate_config_key(key: &str) -> Result<(), String> {
    if key.split('.').any(|part| {
        part.is_empty()
            || !part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    }) {
        return Err(format!("invalid config key: {key}"));
    }
    Ok(())
}

fn merge_toml_tables(target: &mut toml::Table, update: toml::Table) {
    for (key, value) in update {
        match (target.get_mut(&key), value) {
            (Some(toml::Value::Table(target)), toml::Value::Table(update)) => {
                merge_toml_tables(target, update)
            }
            (_, value) => {
                target.insert(key, value);
            }
        }
    }
}

fn remove_toml_key(table: &mut toml::Table, key: &str) -> Result<bool, String> {
    validate_config_key(key)?;
    let parts = key.split('.').collect::<Vec<_>>();
    remove_toml_key_parts(table, &parts)
}

fn remove_toml_key_parts(table: &mut toml::Table, parts: &[&str]) -> Result<bool, String> {
    if parts.len() == 1 {
        return Ok(table.remove(parts[0]).is_some());
    }
    let Some(value) = table.get_mut(parts[0]) else {
        return Ok(false);
    };
    let Some(child) = value.as_table_mut() else {
        return Err(format!("config key is not a table: {}", parts[0]));
    };
    let removed = remove_toml_key_parts(child, &parts[1..])?;
    if child.is_empty() {
        table.remove(parts[0]);
    }
    Ok(removed)
}

fn write_plugin_config(path: &Path, table: &toml::Table) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "invalid plugin config path".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "could not create plugin config dir '{}': {e}",
            display_path(parent)
        )
    })?;
    let src = toml::to_string_pretty(table).map_err(|e| format!("could not encode config: {e}"))?;
    std::fs::write(path, src).map_err(|e| {
        format!(
            "could not write plugin config '{}': {e}",
            display_path(path)
        )
    })
}

fn toml_leaf_keys(table: &toml::Table) -> Vec<String> {
    fn visit(table: &toml::Table, prefix: &str, out: &mut Vec<String>) {
        for (key, value) in table {
            let full = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if let Some(child) = value.as_table() {
                visit(child, &full, out);
            } else {
                out.push(full);
            }
        }
    }
    let mut keys = Vec::new();
    visit(table, "", &mut keys);
    keys.sort();
    keys
}

fn setup_plugin(spec: &str, approved: bool, json_output: bool) -> Result<(), String> {
    if json_output {
        return Err("plugins setup does not support --json".to_string());
    }
    let source = plugins::plugin_source(spec).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?
        .ok_or_else(|| format!("plugin '{}' has no plugin.toml", source.name))?;
    let name = plugin_name(&source, Some(&manifest));
    let steps = manifest
        .postscript
        .iter()
        .filter(|step| postscript_matches_platform(step))
        .collect::<Vec<_>>();
    if steps.is_empty() && manifest.artifact.is_empty() {
        println!("setup: nothing to do for {}", current_platform());
        return Ok(());
    }
    println!("plugin: {name}");
    if let Some(description) = manifest.description.as_deref() {
        println!("description: {description}");
    }
    println!(
        "source: {}",
        source
            .manifest_path
            .as_deref()
            .map(display_path)
            .unwrap_or_else(|| "plugin.toml".to_string())
    );
    for artifact in &manifest.artifact {
        let asset = artifact_asset(artifact)?;
        println!("artifact: {}", artifact.name);
        println!("  release: github:{}", artifact.repository);
        println!("  asset: {asset}");
        println!(
            "  destination: {}",
            artifact_destination(&name, artifact)?.display()
        );
    }
    for (index, step) in steps.iter().enumerate() {
        validate_postscript(step)?;
        println!(
            "postscript {}: {}",
            index + 1,
            step.name.as_deref().unwrap_or("setup")
        );
        println!("  command: {}", display_command(&step.command));
        println!("  permissions: {}", step.permissions.join(", "));
    }
    if !approved && !confirm_setup()? {
        return Err("plugin setup was not approved".to_string());
    }
    for artifact in &manifest.artifact {
        install_release_artifact(&name, artifact)?;
    }
    for step in steps {
        run_postscript(&name, &source.root, step)?;
    }
    println!("setup: complete");
    Ok(())
}

fn update_plugin(spec: &str, json_output: bool) -> Result<(), String> {
    if json_output {
        return Err("plugins update does not support --json".to_string());
    }
    let source = plugins::plugin_source(spec).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?
        .ok_or_else(|| format!("plugin '{}' has no plugin.toml", source.name))?;
    let name = plugin_name(&source, Some(&manifest));
    if manifest.artifact.is_empty() {
        println!("update: no release artifacts for {name}");
        return Ok(());
    }
    for artifact in &manifest.artifact {
        install_release_artifact(&name, artifact)?;
    }
    println!("update: complete");
    Ok(())
}

fn artifact_platform_key() -> Result<String, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok("windows-x86_64".to_string()),
        ("linux", "x86_64") => Ok("linux-x86_64".to_string()),
        ("macos", "x86_64") => Ok("macos-x86_64".to_string()),
        ("macos", "aarch64") => Ok("macos-aarch64".to_string()),
        (os, arch) => Err(format!(
            "plugin artifacts are not published for {os}/{arch}"
        )),
    }
}

fn artifact_asset(artifact: &ReleaseArtifact) -> Result<&str, String> {
    let platform = artifact_platform_key()?;
    artifact
        .assets
        .get(&platform)
        .map(String::as_str)
        .ok_or_else(|| {
            format!(
                "plugin artifact '{}' has no asset for {platform}",
                artifact.name
            )
        })
}

fn artifact_destination(name: &str, artifact: &ReleaseArtifact) -> Result<PathBuf, String> {
    let default = format!("bin/{}", artifact.name);
    let raw = artifact.destination.as_deref().unwrap_or(&default);
    let mut relative = PathBuf::from(raw);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err(format!(
            "plugin artifact '{}' has unsafe destination: {raw}",
            artifact.name
        ));
    }
    if cfg!(windows) && relative.extension().is_none() {
        relative.set_extension("exe");
    }
    let dirs = plugin_runtime_dirs(&plugin_id(name))?;
    Ok(dirs.data_dir.join(relative))
}

fn install_release_artifact(name: &str, artifact: &ReleaseArtifact) -> Result<(), String> {
    let asset = artifact_asset(artifact)?;
    let destination = artifact_destination(name, artifact)?;
    let download = update::download_latest_release_asset(&artifact.repository, asset)?;
    if destination.is_file() && sha256_path(&destination)? == download.sha256 {
        println!(
            "artifact {}: up to date ({})",
            artifact.name, download.version
        );
        return Ok(());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "plugin artifact destination has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "could not create plugin artifact directory '{}': {e}",
            parent.display()
        )
    })?;
    let staged = destination.with_extension(format!(
        "{}download-{}",
        destination
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default(),
        std::process::id()
    ));
    std::fs::write(&staged, &download.bytes)
        .map_err(|e| format!("could not stage plugin artifact: {e}"))?;
    mark_artifact_executable(&staged)?;
    if sha256_path(&staged)? != download.sha256 {
        let _ = std::fs::remove_file(&staged);
        return Err("staged plugin artifact checksum mismatch".to_string());
    }
    replace_artifact(&staged, &destination)?;
    println!("artifact {}: installed {}", artifact.name, download.version);
    Ok(())
}

fn sha256_path(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)
        .map_err(|e| format!("could not verify plugin artifact '{}': {e}", path.display()))?;
    Ok(data_encoding::HEXLOWER.encode(&Sha256::digest(bytes)))
}

fn replace_artifact(staged: &Path, destination: &Path) -> Result<(), String> {
    if !destination.exists() {
        return std::fs::rename(staged, destination)
            .map_err(|e| format!("could not install plugin artifact: {e}"));
    }
    let backup = destination.with_extension(format!(
        "{}previous",
        destination
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ));
    if backup.exists() {
        std::fs::remove_file(&backup)
            .map_err(|e| format!("could not remove old plugin artifact backup: {e}"))?;
    }
    std::fs::rename(destination, &backup).map_err(|e| {
        format!(
            "could not replace running plugin artifact '{}': {e}",
            destination.display()
        )
    })?;
    if let Err(error) = std::fs::rename(staged, destination) {
        let _ = std::fs::rename(&backup, destination);
        return Err(format!("could not install plugin artifact: {error}"));
    }
    Ok(())
}

#[cfg(unix)]
fn mark_artifact_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("could not mark plugin artifact executable: {e}"))
}

#[cfg(windows)]
fn mark_artifact_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn postscript_matches_platform(step: &Postscript) -> bool {
    step.platforms.is_empty()
        || step
            .platforms
            .iter()
            .any(|platform| platform.eq_ignore_ascii_case(current_platform()))
}

fn validate_postscript(step: &Postscript) -> Result<(), String> {
    if step.command.is_empty() || step.command.iter().any(|part| part.is_empty()) {
        return Err("postscript command must be a non-empty string array".to_string());
    }
    if step.permissions.is_empty() {
        return Err("postscript must declare at least one permission".to_string());
    }
    const PERMISSIONS: &[&str] = &["filesystem", "network", "process", "environment"];
    for permission in &step.permissions {
        if !PERMISSIONS.contains(&permission.as_str()) {
            return Err(format!("unknown postscript permission: {permission}"));
        }
    }
    Ok(())
}

fn confirm_setup() -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Err("plugin setup requires interactive approval or --yes".to_string());
    }
    eprint!("Apply this plugin setup? [y/N] ");
    std::io::stderr().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn display_command(command: &[String]) -> String {
    command
        .iter()
        .map(|part| {
            if part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "-._/:\\".contains(ch))
            {
                part.clone()
            } else {
                format!("{:?}", part)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_postscript(name: &str, cwd: &Path, step: &Postscript) -> Result<(), String> {
    let program = adapter_program(&step.command[0], cwd, &plugin_id(name));
    if find_command(&program).is_none() {
        return Err(format!("postscript command not found: {}", step.command[0]));
    }
    let mut command = adapter_command(&program, &plugin_id(name))?;
    command
        .args(&step.command[1..])
        .current_dir(cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start postscript: {e}"))?;
    let status = wait_for_adapter_child(
        &mut child,
        step.name.as_deref().unwrap_or("postscript"),
        Duration::from_millis(step.timeout_ms.unwrap_or(120_000)),
    )?;
    if !status.success() {
        return Err(format!("postscript failed: {status}"));
    }
    Ok(())
}

fn active_for_one(spec: &str) -> Result<plugins::ActivePlugins, String> {
    let specs = plugins::parse_plugin_value(spec).map_err(|e| e.to_string())?;
    plugins::active_from_explicit_specs(specs, true).map_err(|e| e.to_string())
}

fn test_pack(path: &Path) -> Check {
    let src = match std::fs::read_to_string(path) {
        Ok(src) => src,
        Err(e) => return Check::fail("config", e.to_string()),
    };
    match plugins::load_plugin_config(path, &src) {
        Ok(_) => Check::ok("config", display_path(path)),
        Err(e) => Check::fail("config", e),
    }
}

fn test_adapter(path: &Path) -> Check {
    let adapter = match AdapterFile::load(path) {
        Ok(adapter) => adapter,
        Err(e) => return Check::fail("runtime", e),
    };
    match adapter.run_probe() {
        Ok(count) => Check::ok("runtime", format!("spans={count}")),
        Err(e) => Check::fail("runtime", e),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeToml {
    command: Option<Vec<String>>,
    timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_spans: Option<usize>,
}

#[derive(Debug)]
struct AdapterFile {
    name: String,
    id: String,
    cwd: PathBuf,
    command: Vec<String>,
    timeout: Duration,
    max_input_bytes: usize,
    max_spans: usize,
}

impl AdapterFile {
    fn load(path: &Path) -> Result<Self, String> {
        let src = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read runtime '{}': {e}", display_path(path)))?;
        let manifest: PluginManifest = toml::from_str(&src)
            .map_err(|e| format!("invalid runtime '{}': {e}", display_path(path)))?;
        if manifest.schema.as_deref() != Some("pentect.plugin.v1") {
            return Err("schema".to_string());
        }
        let runtime = manifest.runtime.ok_or_else(|| "runtime".to_string())?;
        let cwd = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let command = adapter_command_from_manifest(runtime.command)?;
        let name = manifest
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| adapter_default_name(path));
        let id = plugin_id(&name);
        let program = adapter_program(&command[0], &cwd, &id);
        if find_command(&program).is_none() {
            return Err("command not found; run `pentect plugins setup`".to_string());
        }
        Ok(Self {
            name,
            id,
            cwd,
            command,
            timeout: Duration::from_millis(runtime.timeout_ms.unwrap_or(3_000)),
            max_input_bytes: runtime.max_input_bytes.unwrap_or(256 * 1024),
            max_spans: runtime.max_spans.unwrap_or(512),
        })
    }

    fn run_probe(&self) -> Result<usize, String> {
        let request = json!({
            "schema": "pentect.model_adapter.v1",
            "kind": "text",
            "text": "Alice Smith",
            "context": null,
        })
        .to_string();
        if request.len() > self.max_input_bytes {
            return Err(format!("{}: input limit", self.name));
        }
        let program = adapter_program(&self.command[0], &self.cwd, &self.id);
        let mut command = adapter_command(&program, &self.id)?;
        command
            .args(&self.command[1..])
            .current_dir(&self.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|e| format!("{}: {e}", self.name))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("{}: stdout", self.name))?;
        let stdout_reader = spawn_adapter_stdout_reader(stdout);
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("{}: stdin", self.name))?;
        let stdin_writer = spawn_adapter_stdin_writer(stdin, request.as_bytes().to_vec());
        let status = match wait_for_adapter_child(&mut child, &self.name, self.timeout) {
            Ok(status) => status,
            Err(err) => {
                let _ = join_adapter_stdin(stdin_writer, &self.name);
                let _ = join_adapter_stdout(stdout_reader, &self.name);
                return Err(err);
            }
        };
        join_adapter_stdin(stdin_writer, &self.name)?;
        let stdout = join_adapter_stdout(stdout_reader, &self.name)?;
        if stdout.len() > MAX_STDOUT_BYTES {
            return Err(format!("{}: output limit", self.name));
        }
        if !status.success() {
            return Err(format!("{}: {status}", self.name));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&stdout).map_err(|e| format!("{}: {e}", self.name))?;
        let count = value
            .get("spans")
            .and_then(|spans| spans.as_array())
            .map(Vec::len)
            .unwrap_or(0);
        if count > self.max_spans {
            return Err(format!("{}: span limit", self.name));
        }
        Ok(count)
    }
}

fn spawn_adapter_stdin_writer(
    mut stdin: ChildStdin,
    request: Vec<u8>,
) -> JoinHandle<Result<(), String>> {
    std::thread::spawn(move || stdin.write_all(&request).map_err(|e| format!("stdin: {e}")))
}

fn spawn_adapter_stdout_reader(stdout: ChildStdout) -> JoinHandle<Result<Vec<u8>, String>> {
    std::thread::spawn(move || {
        let mut stdout = stdout.take(MAX_STDOUT_BYTES as u64 + 1);
        let mut out = Vec::new();
        stdout
            .read_to_end(&mut out)
            .map_err(|e| format!("stdout: {e}"))?;
        Ok(out)
    })
}

fn wait_for_adapter_child(
    child: &mut Child,
    name: &str,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{name}: timeout"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{name}: {e}"));
            }
        }
    }
}

fn join_adapter_stdin(writer: JoinHandle<Result<(), String>>, name: &str) -> Result<(), String> {
    writer
        .join()
        .map_err(|_| format!("{name}: stdin writer panicked"))?
        .map_err(|e| format!("{name}: {e}"))
}

fn join_adapter_stdout(
    reader: JoinHandle<Result<Vec<u8>, String>>,
    name: &str,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("{name}: stdout reader panicked"))?
        .map_err(|e| format!("{name}: {e}"))
}

fn adapter_command_from_manifest(command: Option<Vec<String>>) -> Result<Vec<String>, String> {
    let Some(command) = command else {
        return Err("command".to_string());
    };
    if command.is_empty() || command.iter().any(|part| part.is_empty()) {
        return Err("command".to_string());
    }
    Ok(command)
}

fn adapter_command(program: &Path, id_or_name: &str) -> Result<Command, String> {
    let mut command = Command::new(program);
    command.env_clear();
    for env_name in safe_adapter_env_names() {
        if let Some(value) = std::env::var_os(env_name) {
            command.env(env_name, value);
        }
    }
    let id = plugin_id(id_or_name);
    let dirs = plugin_runtime_dirs(&id)?;
    command.env(PLUGIN_NAME_ENV, id);
    command.env(PLUGIN_DATA_DIR_ENV, dirs.data_dir);
    command.env(PLUGIN_CACHE_DIR_ENV, dirs.cache_dir);
    command.env(PLUGIN_CONFIG_ENV, dirs.config_file);
    Ok(command)
}

#[derive(Debug)]
struct PluginRuntimeDirs {
    data_dir: PathBuf,
    cache_dir: PathBuf,
    config_file: PathBuf,
}

fn plugin_runtime_dirs(id_or_name: &str) -> Result<PluginRuntimeDirs, String> {
    let id = plugin_id(id_or_name);
    let data_dir = PathBuf::from(PENTECT_DIR).join(PLUGINS_DATA_DIR).join(&id);
    let cache_dir = data_dir.join(PLUGIN_CACHE_DIR);
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        format!(
            "could not create plugin data '{}': {e}",
            cache_dir.display()
        )
    })?;
    let config_file = data_dir.join(PLUGIN_CONFIG_FILE);
    Ok(PluginRuntimeDirs {
        data_dir,
        cache_dir,
        config_file,
    })
}

fn adapter_default_name(path: &Path) -> String {
    if path.file_name().and_then(|name| name.to_str()) == Some("plugin.toml") {
        if let Some(name) = path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| !name.trim().is_empty())
        {
            return name.to_string();
        }
    }
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("plugin")
        .to_string()
}

fn plugin_id(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.trim().chars() {
        let next = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if matches!(ch, '-' | '_' | '.' | ' ') {
            Some('-')
        } else {
            None
        };
        let Some(next) = next else {
            continue;
        };
        if next == '-' {
            if out.is_empty() || last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        out.push(next);
        if out.len() >= 64 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "plugin".to_string()
    } else {
        out
    }
}

fn safe_adapter_env_names() -> &'static [&'static str] {
    if cfg!(windows) {
        &[
            "Path",
            "PATH",
            "PATHEXT",
            "SystemRoot",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "USERPROFILE",
        ]
    } else {
        &["PATH", "HOME", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR"]
    }
}

#[derive(Debug)]
struct PluginRow {
    name: String,
    source: &'static str,
    configs: usize,
    runtimes: usize,
}

impl PluginRow {
    fn status(&self) -> &'static str {
        if self.configs == 0 && self.runtimes == 0 {
            "empty"
        } else {
            "ok"
        }
    }
}

fn plugin_rows() -> Result<Vec<PluginRow>, String> {
    let mut rows = Vec::new();
    rows.extend(plugin_rows_in(
        Path::new(".pentect").join("plugins"),
        "project",
    )?);
    rows.extend(plugin_rows_in(
        Path::new("plugins").to_path_buf(),
        "official",
    )?);
    Ok(rows)
}

fn plugin_rows_in(root: PathBuf, source: &'static str) -> Result<Vec<PluginRow>, String> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(&root)
        .map_err(|e| format!("could not read plugin dir '{}': {e}", display_path(&root)))?
    {
        let path = entry
            .map_err(|e| format!("could not read plugin dir '{}': {e}", display_path(&root)))?
            .path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string();
        let active = active_for_one(&path.to_string_lossy())?;
        if active.config_paths().is_empty() && active.adapter_paths().is_empty() {
            continue;
        }
        rows.push(PluginRow {
            name,
            source,
            configs: active.config_paths().len(),
            runtimes: active.adapter_paths().len(),
        });
    }
    Ok(rows)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Fail => "fail",
        }
    }
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            detail: detail.into(),
        }
    }
}

fn adapter_program(program: &str, cwd: &Path, id: &str) -> PathBuf {
    let path = Path::new(program);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    if looks_like_path_command(program) {
        return cwd.join(path);
    }
    installed_plugin_program(program, id)
        .or_else(|| adapter_sidecar_program(program))
        .unwrap_or_else(|| path.to_path_buf())
}

fn installed_plugin_program(program: &str, id: &str) -> Option<PathBuf> {
    let bin = PathBuf::from(PENTECT_DIR)
        .join(PLUGINS_DATA_DIR)
        .join(plugin_id(id))
        .join("bin");
    for name in command_names(program) {
        let candidate = bin.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn looks_like_path_command(program: &str) -> bool {
    program.contains('/') || program.contains('\\')
}

fn adapter_sidecar_program(program: &str) -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    for name in command_names(program) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn find_command(path: &Path) -> Option<PathBuf> {
    if path.is_file() {
        return Some(path.to_path_buf());
    }
    if path.is_absolute()
        || path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return None;
    }
    let name = path.to_str()?;
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for candidate in command_names(name) {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

#[cfg(windows)]
fn command_names(name: &str) -> Vec<String> {
    if Path::new(name).extension().is_some() {
        return vec![name.to_string()];
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    pathext
        .split(';')
        .filter(|ext| !ext.is_empty())
        .map(|ext| format!("{name}{ext}"))
        .collect()
}

#[cfg(not(windows))]
fn command_names(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

fn display_path(path: &Path) -> String {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|cwd| cwd.canonicalize().ok());
    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let rel = cwd
        .as_deref()
        .and_then(|cwd| target.strip_prefix(cwd).ok())
        .unwrap_or(&target);
    rel.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list() {
        let args = vec!["pentect".into(), "plugins".into(), "list".into()];
        assert!(matches!(
            PluginCmd::parse(&args).unwrap().action,
            Action::List
        ));
    }

    #[test]
    fn inspect_requires_one_spec() {
        let args = vec!["pentect".into(), "plugins".into(), "inspect".into()];
        assert!(PluginCmd::parse(&args).is_err());
    }

    #[test]
    fn parses_config_and_approved_setup() {
        let args = vec![
            "pentect".into(),
            "plugins".into(),
            "config".into(),
            "pii-ner".into(),
            "model.threshold=0.8".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&args).unwrap().action,
            Action::Config {
                change: ConfigChange::Set(_),
                ..
            }
        ));

        let args = vec![
            "pentect".into(),
            "plugins".into(),
            "setup".into(),
            "pii-ner".into(),
            "--yes".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&args).unwrap().action,
            Action::Setup { approved: true, .. }
        ));

        let args = vec![
            "pentect".into(),
            "plugins".into(),
            "update".into(),
            "pii-ner".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&args).unwrap().action,
            Action::Update { .. }
        ));
    }

    #[test]
    fn config_values_are_nested_and_key_listing_omits_values() {
        let mut table = toml::Table::new();
        merge_toml_tables(
            &mut table,
            parse_config_assignment("model.threshold", "0.8").unwrap(),
        );
        merge_toml_tables(
            &mut table,
            parse_config_assignment("model.name", "small").unwrap(),
        );
        assert_eq!(toml_leaf_keys(&table), ["model.name", "model.threshold"]);
        assert_eq!(
            table["model"]["name"].as_str(),
            Some("small"),
            "bare values fall back to TOML strings"
        );
        assert!(remove_toml_key(&mut table, "model.name").unwrap());
        assert_eq!(toml_leaf_keys(&table), ["model.threshold"]);
    }

    #[test]
    fn postscript_requires_declared_known_permissions() {
        let missing = Postscript {
            name: None,
            command: vec!["tool".into()],
            platforms: Vec::new(),
            permissions: Vec::new(),
            timeout_ms: None,
        };
        assert!(validate_postscript(&missing).is_err());

        let valid = Postscript {
            permissions: vec!["network".into(), "filesystem".into()],
            ..missing
        };
        assert!(validate_postscript(&valid).is_ok());
    }

    #[test]
    fn postscript_does_not_run_before_approval() {
        let root =
            std::env::temp_dir().join(format!("pentect-plugin-approval-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let marker = root.join("approved.txt");
        #[cfg(windows)]
        let command = r#"["cmd", "/C", "echo approved>approved.txt"]"#;
        #[cfg(not(windows))]
        let command = r#"["sh", "-c", "printf approved > approved.txt"]"#;
        std::fs::write(
            root.join("plugin.toml"),
            format!(
                r#"
schema = "pentect.plugin.v1"
name = "approval-test"

[[postscript]]
command = {command}
permissions = ["filesystem", "process"]
"#
            ),
        )
        .unwrap();

        let spec = root.to_string_lossy();
        assert!(setup_plugin(&spec, false, false).is_err());
        assert!(!marker.exists());
        setup_plugin(&spec, true, false).unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "approved");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn release_artifacts_select_platform_and_reject_unsafe_destinations() {
        let platform = artifact_platform_key().unwrap();
        let mut assets = BTreeMap::new();
        assets.insert(platform, "helper.bin".to_string());
        let artifact = ReleaseArtifact {
            name: "helper".to_string(),
            repository: "owner/repo".to_string(),
            destination: Some("../outside".to_string()),
            assets,
        };
        assert_eq!(artifact_asset(&artifact).unwrap(), "helper.bin");
        assert!(artifact_destination("test", &artifact).is_err());
    }

    #[test]
    fn adapter_probe_env_does_not_inherit_memory_store_credentials() {
        let command = adapter_command(Path::new("echo"), "test-env").unwrap();
        let names = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(!names.iter().any(|name| name == "PENTECT_MEMORY_STORE_ADDR"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_MEMORY_STORE_TOKEN"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_PROCESS_HOST_READ_TOKEN"));
        assert!(!names
            .iter()
            .any(|name| name == "PENTECT_PROCESS_HOST_WRITE_TOKEN"));
    }

    #[test]
    fn adapter_probe_env_exposes_project_local_plugin_data() {
        let command = adapter_command(Path::new("echo"), "My Ext!").unwrap();
        let envs = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().to_string(),
                    value
                        .map(|value| value.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            envs.get(PLUGIN_NAME_ENV).map(String::as_str),
            Some("my-ext")
        );
        assert!(
            envs.get(PLUGIN_DATA_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/plugins-data/my-ext")),
            "{envs:?}"
        );
        assert!(
            envs.get(PLUGIN_CACHE_DIR_ENV)
                .is_some_and(|path| path.ends_with(".pentect/plugins-data/my-ext/cache")),
            "{envs:?}"
        );
        assert!(
            envs.get(PLUGIN_CONFIG_ENV)
                .is_some_and(|path| path.ends_with(".pentect/plugins-data/my-ext/config.toml")),
            "{envs:?}"
        );
    }

    #[test]
    fn list_plugins_skips_empty_dirs() {
        let root = std::env::temp_dir().join(format!("pentect-plugin-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::create_dir_all(root.join("rules")).unwrap();
        std::fs::write(root.join("rules").join("config.toml"), "").unwrap();

        let rows = plugin_rows_in(root.clone(), "official").unwrap();
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "rules");
        assert_eq!(rows[0].configs, 1);
        assert_eq!(rows[0].runtimes, 0);
    }

    #[test]
    fn list_plugins_includes_official_model_and_rule_plugins() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap();
        let rows = plugin_rows_in(repo.join("plugins"), "official").unwrap();
        let names = rows
            .iter()
            .filter(|row| row.source == "official")
            .map(|row| row.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        assert!(names.contains("openai-privacy-filter"), "{names:?}");
        assert!(names.contains("pii-ner"), "{names:?}");
    }

    #[test]
    fn adapter_command_path_is_checked_from_adapter_dir() {
        let root = std::env::temp_dir().join(format!(
            "pentect-cli-adapter-relative-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("tool"), "").unwrap();
        std::fs::write(
            root.join("plugin.toml"),
            r#"
schema = "pentect.plugin.v1"
name = "relative"

[runtime]
command = ["./tool"]
"#,
        )
        .unwrap();

        let loaded = AdapterFile::load(&root.join("plugin.toml"));
        std::fs::remove_dir_all(root).unwrap();
        assert!(loaded.is_ok(), "{loaded:?}");
    }
}
