use crate::{plugins, update};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const PENTECT_DIR: &str = ".pentect";
const PLUGINS_DATA_DIR: &str = "plugins-data";
const PLUGIN_CONFIG_FILE: &str = "config.toml";
const PLUGIN_BINARY_LOCK_FILE: &str = "binary.lock";
const PLUGIN_APPROVAL_FILE: &str = "approval.toml";
const PLUGIN_CACHE_DIR: &str = "cache";
const PLUGIN_NAME_ENV: &str = "PENTECT_PLUGIN_NAME";
const PLUGIN_DATA_DIR_ENV: &str = "PENTECT_PLUGIN_DATA_DIR";
const PLUGIN_CACHE_DIR_ENV: &str = "PENTECT_PLUGIN_CACHE_DIR";
const PLUGIN_CONFIG_ENV: &str = "PENTECT_PLUGIN_CONFIG";

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
                    "binary": row.binary,
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
            "{}: {} {} configs={} binary={}",
            row.name,
            row.source,
            row.status(),
            row.configs,
            if row.binary { "yes" } else { "no" }
        );
    }
    Ok(())
}

fn inspect_plugin(spec: &str, json_output: bool) -> Result<(), String> {
    let active = active_for_one(spec)?;
    let source = plugins::plugin_source(spec).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?;
    let platform = binary_platform();
    let binary = manifest
        .as_ref()
        .and_then(|manifest| manifest.binary.as_deref());
    let repository = manifest.as_ref().and_then(|manifest| {
        manifest
            .repository
            .as_deref()
            .or(source.repository.as_deref())
    });
    let asset = binary.map(|binary| binary_asset(binary, &manifest.as_ref().unwrap().assets));
    if json_output {
        println!(
            "{}",
            json!({
                "name": plugin_name(&source, manifest.as_ref()),
                "description": manifest.as_ref().and_then(|manifest| manifest.description.as_deref()),
                "manifest": source.manifest_path.as_deref().map(display_path),
                "configs": active.config_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
                "platform": platform,
                "binary": binary,
                "repository": repository,
                "asset": asset,
                "middleware": manifest.as_ref().and_then(|manifest| manifest.middleware.as_ref()).map(|middleware| json!({
                    "stages": middleware.stages,
                    "permissions": middleware.permissions,
                    "required": middleware.required,
                    "mode": manifest.as_ref().and_then(|manifest| manifest.execution.as_ref()).and_then(|execution| execution.mode.as_deref()).unwrap_or("persistent"),
                })),
                "postscripts": manifest.as_ref().map(|manifest| manifest.postscript.len()).unwrap_or(0),
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
    if let Some(binary) = binary {
        println!("platform: {platform}");
        println!("binary: {binary}");
        if let Some(repository) = repository {
            println!("repository: {repository}");
        }
        if let Some(asset) = asset {
            println!("asset: {asset}");
        }
    }
    if let Some(middleware) = manifest
        .as_ref()
        .and_then(|manifest| manifest.middleware.as_ref())
    {
        println!("stages: {}", middleware.stages.join(", "));
        println!("permissions: {}", middleware.permissions.join(", "));
        println!("required: {}", middleware.required);
    }
    println!(
        "postscripts: {}",
        manifest
            .as_ref()
            .map(|manifest| manifest.postscript.len())
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
    for path in active.binary_paths() {
        checks.push(test_binary(path));
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
    #[serde(default)]
    postscript: Vec<Postscript>,
    binary: Option<String>,
    repository: Option<String>,
    #[serde(default)]
    assets: BTreeMap<String, String>,
    execution: Option<ExecutionConfig>,
    middleware: Option<MiddlewareConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct ExecutionConfig {
    #[serde(default, rename = "args")]
    _args: Vec<String>,
    mode: Option<String>,
    #[serde(rename = "timeout_ms")]
    _timeout_ms: Option<u64>,
    #[serde(rename = "max_input_bytes")]
    _max_input_bytes: Option<usize>,
    #[serde(rename = "max_output_bytes")]
    _max_output_bytes: Option<usize>,
    #[serde(rename = "max_spans")]
    _max_spans: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct MiddlewareConfig {
    #[serde(default)]
    stages: Vec<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    required: bool,
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
    if let Some(binary) = manifest.binary.as_deref() {
        let name = manifest
            .name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(&source.name);
        validate_binary_name(binary, name)?;
        if let Some(repository) = manifest
            .repository
            .as_deref()
            .or(source.repository.as_deref())
        {
            update::validate_repository(repository)?;
        }
    }
    validate_middleware(&manifest)?;
    Ok(Some(manifest))
}

fn validate_middleware(manifest: &PluginManifest) -> Result<(), String> {
    let Some(middleware) = &manifest.middleware else {
        if manifest.binary.is_some() {
            return Err("binary plugins require [middleware]".to_string());
        }
        return Ok(());
    };
    const STAGES: &[&str] = &[
        "ingest",
        "decode",
        "detect",
        "policy",
        "mask",
        "provider_request",
        "provider_response",
        "tool_call",
        "output",
        "file_discover",
        "file_decode",
        "file_detect",
        "file_transform",
        "finding",
        "report",
    ];
    const PERMISSIONS: &[&str] = &[
        "input:read",
        "payload:write",
        "pipeline:block",
        "pipeline:respond",
        "config:read",
        "cache:write",
    ];
    if middleware.stages.is_empty() {
        return Err("middleware must declare at least one stage".to_string());
    }
    if !middleware
        .permissions
        .iter()
        .any(|value| value == "input:read")
    {
        return Err("middleware requires input:read permission".to_string());
    }
    for stage in &middleware.stages {
        if !STAGES.contains(&stage.as_str()) {
            return Err(format!("unknown middleware stage: {stage}"));
        }
    }
    for permission in &middleware.permissions {
        if !PERMISSIONS.contains(&permission.as_str()) {
            return Err(format!("unknown middleware permission: {permission}"));
        }
    }
    if let Some(mode) = manifest
        .execution
        .as_ref()
        .and_then(|execution| execution.mode.as_deref())
    {
        if !matches!(mode, "persistent" | "oneshot") {
            return Err(format!("unknown plugin execution mode: {mode}"));
        }
    }
    Ok(())
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
    let manifest_hash = source
        .manifest_path
        .as_deref()
        .map(sha256_path)
        .transpose()?;
    let name = plugin_name(&source, Some(&manifest));
    let steps = manifest
        .postscript
        .iter()
        .filter(|step| postscript_matches_platform(step))
        .collect::<Vec<_>>();
    if steps.is_empty() && manifest.binary.is_none() {
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
    if let Some(binary) = manifest.binary.as_deref() {
        let repository = binary_repository(&source, &manifest)?;
        let asset = binary_asset(binary, &manifest.assets);
        println!("binary: {binary}");
        println!("  release: github:{repository}");
        println!("  asset: {asset}");
        println!(
            "  destination: {}",
            binary_destination(&name, binary)?.display()
        );
    }
    if let Some(middleware) = &manifest.middleware {
        println!("middleware:");
        println!("  stages: {}", middleware.stages.join(", "));
        println!("  permissions: {}", middleware.permissions.join(", "));
        println!("  required: {}", middleware.required);
        println!(
            "  execution: {}",
            manifest
                .execution
                .as_ref()
                .and_then(|execution| execution.mode.as_deref())
                .unwrap_or("persistent")
        );
        println!("  trust: executable code (no OS sandbox)");
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
    if let Some(binary) = manifest.binary.as_deref() {
        let repository = binary_repository(&source, &manifest)?;
        install_release_binary(&name, &repository, binary, &manifest.assets)?;
    }
    for step in steps {
        run_postscript(&name, &source.root, step)?;
    }
    if manifest.middleware.is_some() {
        let current_hash = source
            .manifest_path
            .as_deref()
            .map(sha256_path)
            .transpose()?;
        if current_hash != manifest_hash {
            return Err("plugin.toml changed during setup; approval was not recorded".to_string());
        }
        write_plugin_approval(&name, &source, &manifest)?;
    }
    println!("setup: complete");
    Ok(())
}

#[derive(Serialize)]
struct PluginApproval<'a> {
    schema: &'static str,
    manifest_sha256: String,
    stages: &'a [String],
    permissions: &'a [String],
}

fn write_plugin_approval(
    name: &str,
    source: &plugins::PluginSource,
    manifest: &PluginManifest,
) -> Result<(), String> {
    let path = source
        .manifest_path
        .as_deref()
        .ok_or_else(|| "middleware approval requires plugin.toml".to_string())?;
    let middleware = manifest
        .middleware
        .as_ref()
        .ok_or_else(|| "middleware approval requires [middleware]".to_string())?;
    let approval = PluginApproval {
        schema: "pentect.plugin-approval.v1",
        manifest_sha256: sha256_path(path)?,
        stages: &middleware.stages,
        permissions: &middleware.permissions,
    };
    let encoded = toml::to_string(&approval)
        .map_err(|error| format!("could not encode plugin approval: {error}"))?;
    let dirs = plugin_runtime_dirs(&plugin_id(name))?;
    let path = dirs.data_dir.join(PLUGIN_APPROVAL_FILE);
    let temporary = path.with_extension("toml.tmp");
    std::fs::write(&temporary, encoded)
        .map_err(|error| format!("could not write plugin approval: {error}"))?;
    replace_binary(&temporary, &path)
        .map_err(|error| format!("could not activate plugin approval: {error}"))
}

fn update_plugin(spec: &str, json_output: bool) -> Result<(), String> {
    if json_output {
        return Err("plugins update does not support --json".to_string());
    }
    let source = plugins::plugin_source(spec).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?
        .ok_or_else(|| format!("plugin '{}' has no plugin.toml", source.name))?;
    let name = plugin_name(&source, Some(&manifest));
    let Some(binary) = manifest.binary.as_deref() else {
        println!("update: no release binary for {name}");
        return Ok(());
    };
    let repository = binary_repository(&source, &manifest)?;
    verify_plugin_update_approval(&name, &manifest)?;
    install_release_binary(&name, &repository, binary, &manifest.assets)?;
    if manifest.middleware.is_some() {
        write_plugin_approval(&name, &source, &manifest)?;
    }
    println!("update: complete");
    Ok(())
}

#[derive(Deserialize)]
struct StoredPluginApproval {
    schema: String,
    stages: Vec<String>,
    permissions: Vec<String>,
}

fn verify_plugin_update_approval(name: &str, manifest: &PluginManifest) -> Result<(), String> {
    let Some(middleware) = &manifest.middleware else {
        return Ok(());
    };
    let path = plugin_runtime_dirs(&plugin_id(name))?
        .data_dir
        .join(PLUGIN_APPROVAL_FILE);
    let source_text = std::fs::read_to_string(&path)
        .map_err(|_| "plugin update requires prior setup approval".to_string())?;
    let approval: StoredPluginApproval = toml::from_str(&source_text)
        .map_err(|_| "plugin approval is invalid; run `pentect plugins setup`".to_string())?;
    let approved_stages = approval
        .stages
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let approved_permissions = approval
        .permissions
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let stages = middleware
        .stages
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let permissions = middleware
        .permissions
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if approval.schema != "pentect.plugin-approval.v1"
        || approved_stages != stages
        || approved_permissions != permissions
    {
        return Err(
            "plugin capabilities changed; review them with `pentect plugins setup`".to_string(),
        );
    }
    Ok(())
}

fn binary_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn binary_repository(
    source: &plugins::PluginSource,
    manifest: &PluginManifest,
) -> Result<String, String> {
    let repository = manifest
        .repository
        .as_deref()
        .or(source.repository.as_deref())
        .ok_or_else(|| {
            "local binary plugins require repository = \"OWNER/REPO\" in plugin.toml".to_string()
        })?;
    update::validate_repository(repository)?;
    Ok(repository.to_string())
}

fn validate_binary_name(binary: &str, plugin: &str) -> Result<(), String> {
    if binary.is_empty()
        || binary.len() > 128
        || binary.contains('/')
        || binary.contains('\\')
        || !binary
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("plugin '{plugin}' has an invalid binary name"));
    }
    Ok(())
}

fn binary_asset(binary: &str, overrides: &BTreeMap<String, String>) -> String {
    let platform = binary_platform();
    overrides.get(&platform).cloned().unwrap_or_else(|| {
        let suffix = if platform.starts_with("windows-") && !binary.ends_with(".exe") {
            ".exe"
        } else {
            ""
        };
        format!("{binary}-{platform}{suffix}")
    })
}

fn binary_destination(name: &str, binary: &str) -> Result<PathBuf, String> {
    validate_binary_name(binary, name)?;
    let filename = if cfg!(windows) && !binary.to_ascii_lowercase().ends_with(".exe") {
        format!("{binary}.exe")
    } else {
        binary.to_string()
    };
    let dirs = plugin_runtime_dirs(&plugin_id(name))?;
    Ok(dirs.data_dir.join("bin").join(filename))
}

fn install_release_binary(
    name: &str,
    repository: &str,
    binary: &str,
    overrides: &BTreeMap<String, String>,
) -> Result<(), String> {
    let platform = binary_platform();
    let asset = binary_asset(binary, overrides);
    let destination = binary_destination(name, binary)?;
    let download = update::download_latest_release_asset(repository, &asset)
        .map_err(|error| map_binary_download_error(name, &platform, &asset, error))?;
    if destination.is_file() && sha256_path(&destination)? == download.sha256 {
        write_binary_lock(name, repository, &asset, &download)?;
        println!("binary {binary}: up to date ({})", download.version);
        return Ok(());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "plugin binary destination has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "could not create plugin binary directory '{}': {e}",
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
        .map_err(|e| format!("could not stage plugin binary: {e}"))?;
    mark_binary_executable(&staged)?;
    if sha256_path(&staged)? != download.sha256 {
        let _ = std::fs::remove_file(&staged);
        return Err("staged plugin binary checksum mismatch".to_string());
    }
    replace_binary(&staged, &destination)?;
    write_binary_lock(name, repository, &asset, &download)?;
    println!("binary {binary}: installed {}", download.version);
    Ok(())
}

fn map_binary_download_error(name: &str, platform: &str, asset: &str, error: String) -> String {
    if error.contains(&format!("missing asset '{asset}'")) {
        format!("plugin '{name}' is unsupported on {platform}")
    } else {
        error
    }
}

#[derive(Serialize)]
struct BinaryLock<'a> {
    schema: &'static str,
    repository: &'a str,
    version: String,
    asset: &'a str,
    sha256: &'a str,
}

fn write_binary_lock(
    name: &str,
    repository: &str,
    asset: &str,
    download: &update::DownloadedReleaseAsset,
) -> Result<(), String> {
    let dirs = plugin_runtime_dirs(&plugin_id(name))?;
    let lock = BinaryLock {
        schema: "pentect.plugin-lock.v1",
        repository,
        version: download.version.to_string(),
        asset,
        sha256: &download.sha256,
    };
    let source =
        toml::to_string(&lock).map_err(|e| format!("could not encode binary lock: {e}"))?;
    std::fs::write(dirs.data_dir.join(PLUGIN_BINARY_LOCK_FILE), source)
        .map_err(|e| format!("could not write plugin binary lock: {e}"))
}

fn sha256_path(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)
        .map_err(|e| format!("could not verify plugin binary '{}': {e}", path.display()))?;
    Ok(data_encoding::HEXLOWER.encode(&Sha256::digest(bytes)))
}

fn replace_binary(staged: &Path, destination: &Path) -> Result<(), String> {
    if !destination.exists() {
        return std::fs::rename(staged, destination)
            .map_err(|e| format!("could not install plugin binary: {e}"));
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
            .map_err(|e| format!("could not remove old plugin binary backup: {e}"))?;
    }
    std::fs::rename(destination, &backup).map_err(|e| {
        format!(
            "could not replace running plugin binary '{}': {e}",
            destination.display()
        )
    })?;
    if let Err(error) = std::fs::rename(staged, destination) {
        let _ = std::fs::rename(&backup, destination);
        return Err(format!("could not install plugin binary: {error}"));
    }
    Ok(())
}

#[cfg(unix)]
fn mark_binary_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("could not mark plugin binary executable: {e}"))
}

#[cfg(windows)]
fn mark_binary_executable(_path: &Path) -> Result<(), String> {
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
    let program = plugin_program(&step.command[0], cwd, &plugin_id(name));
    if find_command(&program).is_none() {
        return Err(format!("postscript command not found: {}", step.command[0]));
    }
    let mut command = plugin_command(&program, &plugin_id(name))?;
    command
        .args(&step.command[1..])
        .current_dir(cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not start postscript: {e}"))?;
    let status = wait_for_plugin_child(
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

fn test_binary(path: &Path) -> Check {
    let middleware = match pentect_agent::PluginMiddleware::from_paths([path.to_path_buf()]) {
        Ok(middleware) => middleware,
        Err(e) => return Check::fail("binary", e),
    };
    match middleware.detect_and_mask(
        &pentect_core::Engine::with_profile(pentect_core::Profile::Strict),
        pentect_core::Input::text("Alice Smith"),
        None,
        &pentect_core::Config::insecure_testing(),
    ) {
        Ok(run) => Check::ok(
            "binary",
            format!(
                "masked={}",
                run.result
                    .as_ref()
                    .map(|result| result.summary.masked_count)
                    .unwrap_or_default()
            ),
        ),
        Err(e) => Check::fail("binary", e),
    }
}

fn wait_for_plugin_child(
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

fn plugin_command(program: &Path, id_or_name: &str) -> Result<Command, String> {
    let mut command = Command::new(program);
    command.env_clear();
    for env_name in safe_plugin_env_names() {
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
    let data_dir = std::env::current_dir()
        .map_err(|e| format!("could not resolve plugin data directory: {e}"))?
        .join(PENTECT_DIR)
        .join(PLUGINS_DATA_DIR)
        .join(&id);
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

fn safe_plugin_env_names() -> &'static [&'static str] {
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
    binary: bool,
}

impl PluginRow {
    fn status(&self) -> &'static str {
        if self.configs == 0 && !self.binary {
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
        if active.config_paths().is_empty() && active.binary_paths().is_empty() {
            continue;
        }
        rows.push(PluginRow {
            name,
            source,
            configs: active.config_paths().len(),
            binary: !active.binary_paths().is_empty(),
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

fn plugin_program(program: &str, cwd: &Path, id: &str) -> PathBuf {
    let path = Path::new(program);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    if looks_like_path_command(program) {
        return cwd.join(path);
    }
    installed_plugin_program(program, id)
        .or_else(|| plugin_sidecar_program(program))
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

fn plugin_sidecar_program(program: &str) -> Option<PathBuf> {
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
    fn release_binary_uses_convention_and_optional_override() {
        let platform = binary_platform();
        let expected = if cfg!(windows) {
            format!("helper-{platform}.exe")
        } else {
            format!("helper-{platform}")
        };
        assert_eq!(binary_asset("helper", &BTreeMap::new()), expected);
        let overrides = BTreeMap::from([(platform, "custom.bin".to_string())]);
        assert_eq!(binary_asset("helper", &overrides), "custom.bin");
        assert!(binary_destination("test", "../outside").is_err());
        assert!(binary_destination("test", "helper").unwrap().is_absolute());
    }

    #[test]
    fn missing_platform_binary_is_reported_as_unsupported() {
        let error = map_binary_download_error(
            "pii-ner",
            "linux-riscv64",
            "pentect-pii-ner-linux-riscv64",
            "release is missing asset 'pentect-pii-ner-linux-riscv64'".to_string(),
        );
        assert_eq!(error, "plugin 'pii-ner' is unsupported on linux-riscv64");

        let checksum_error = "release is missing checksum asset".to_string();
        assert_eq!(
            map_binary_download_error("pii-ner", "linux-x86_64", "binary", checksum_error.clone()),
            checksum_error
        );
    }

    #[test]
    fn binary_lock_records_the_resolved_release() {
        let lock = BinaryLock {
            schema: "pentect.plugin-lock.v1",
            repository: "owner/repo",
            version: "v1.2.3".to_string(),
            asset: "helper-linux-x86_64",
            sha256: "0123456789abcdef",
        };
        let encoded = toml::to_string(&lock).unwrap();
        let decoded: toml::Value = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded["repository"].as_str(), Some("owner/repo"));
        assert_eq!(decoded["version"].as_str(), Some("v1.2.3"));
        assert_eq!(decoded["asset"].as_str(), Some("helper-linux-x86_64"));
        assert_eq!(decoded["sha256"].as_str(), Some("0123456789abcdef"));
    }

    #[test]
    fn plugin_env_does_not_inherit_memory_store_credentials() {
        let command = plugin_command(Path::new("echo"), "test-env").unwrap();
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
    fn plugin_env_exposes_project_local_plugin_data() {
        let command = plugin_command(Path::new("echo"), "My Ext!").unwrap();
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
        assert!(!rows[0].binary);
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
    fn local_binary_requires_repository() {
        let root =
            std::env::temp_dir().join(format!("pentect-local-binary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(plugins::PLUGIN_MANIFEST_FILE),
            "schema = \"pentect.plugin.v1\"\nname = \"local\"\nbinary = \"tool\"\n[middleware]\nstages = [\"detect\"]\npermissions = [\"input:read\"]\n",
        )
        .unwrap();

        let source = plugins::PluginSource {
            name: "local".to_string(),
            root: root.clone(),
            manifest_path: Some(root.join(plugins::PLUGIN_MANIFEST_FILE)),
            repository: None,
        };
        let manifest = load_plugin_manifest(&source).unwrap().unwrap();
        let err = binary_repository(&source, &manifest).unwrap_err();
        assert!(err.contains("require repository"), "{err}");

        std::fs::remove_dir_all(root).unwrap();
    }
}
