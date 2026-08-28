use crate::{plugins, update};
use pentect_agent::{read_bounded_bytes, read_bounded_utf8, DEFAULT_PUBLISHER_WORKFLOW};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PLUGIN_BINARY_LOCK_FILE: &str = "binary.lock";
const PLUGIN_COMMAND_LOCK_FILE: &str = "command.lock";
const PLUGIN_APPROVAL_FILE: &str = "approval.toml";
const MAX_PLUGIN_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_PLUGIN_METADATA_BYTES: u64 = 64 * 1024;
const MAX_PLUGIN_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PLUGIN_WASM_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) fn cmd_plugins(args: &[String]) {
    let opts = match PluginCmd::parse(args) {
        Ok(opts) => opts,
        Err(e) => crate::die(e),
    };
    let result = match opts.action {
        Action::List => list_plugins(opts.json),
        Action::Add {
            spec,
            approved,
            scope,
            profile,
        } => add_plugin(&spec, approved, scope, profile.as_deref(), opts.json),
        Action::Remove { spec, scope } => remove_plugin(&spec, scope, opts.json),
        Action::Search { query } => search_plugins(query.as_deref(), opts.json),
        Action::Inspect { spec } => inspect_plugin(&spec, opts.json),
        Action::Test { spec } => test_plugin(&spec, opts.json),
        Action::New { name, form } => new_plugin(&name, form, opts.json),
        Action::Dev { spec, approved } => dev_plugin(&spec, approved, opts.json),
        Action::Publish { spec } => publish_plugin(&spec, opts.json),
        Action::Config {
            spec,
            change,
            scope,
        } => config_plugin(&spec, change, scope, opts.json),
        Action::Setup {
            spec,
            approved,
            scope,
            profile,
        } => setup_plugin(&spec, approved, scope, profile.as_deref(), opts.json),
        Action::Update {
            spec,
            approved,
            scope,
        } => match spec {
            Some(spec) => update_plugin(&spec, approved, scope, opts.json),
            None => update_all_plugins(approved, scope, opts.json),
        },
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
    Add {
        spec: String,
        approved: bool,
        scope: plugins::PluginScope,
        profile: Option<String>,
    },
    Remove {
        spec: String,
        scope: plugins::PluginScope,
    },
    Search {
        query: Option<String>,
    },
    Inspect {
        spec: String,
    },
    Test {
        spec: String,
    },
    New {
        name: String,
        form: Option<NewPluginForm>,
    },
    Dev {
        spec: String,
        approved: bool,
    },
    Publish {
        spec: String,
    },
    Config {
        spec: String,
        change: ConfigChange,
        scope: plugins::PluginScope,
    },
    Setup {
        spec: String,
        approved: bool,
        scope: plugins::PluginScope,
        profile: Option<String>,
    },
    Update {
        spec: Option<String>,
        approved: bool,
        scope: plugins::PluginScope,
    },
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
            return Err(
                "plugins new|dev|publish|add|remove|list|search|inspect|test|config|setup|update"
                    .to_string(),
            );
        };
        let mut json = false;
        let mut approved = false;
        let mut scope = plugins::PluginScope::User;
        let mut scope_explicit = false;
        let mut unset = None;
        let mut profile = None;
        let mut values = Vec::new();
        let mut i = 3usize;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => json = true,
                "--yes" => approved = true,
                "--project" => {
                    scope = plugins::PluginScope::Project;
                    scope_explicit = true;
                }
                "--unset" => {
                    let Some(key) = args.get(i + 1) else {
                        return Err("--unset requires a key".to_string());
                    };
                    unset = Some(key.clone());
                    i += 1;
                }
                "--profile" => {
                    let Some(value) = args.get(i + 1) else {
                        return Err("--profile requires a profile name".to_string());
                    };
                    if value.starts_with("--") {
                        return Err("--profile requires a profile name".to_string());
                    }
                    if profile.replace(value.clone()).is_some() {
                        return Err("--profile may only be set once".to_string());
                    }
                    i += 1;
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value => values.push(value.to_string()),
            }
            i += 1;
        }
        if scope_explicit && !matches!(action, "add" | "remove" | "config" | "setup" | "update") {
            return Err(
                "--project is only valid for plugins add, remove, config, setup, or update"
                    .to_string(),
            );
        }
        let action = match action {
            "list" => {
                reject_action_flags(approved, unset.as_deref())?;
                if !values.is_empty() {
                    return Err("plugins list".to_string());
                }
                Action::List
            }
            "add" => {
                if unset.is_some() {
                    return Err("--unset is only valid for plugins config".to_string());
                }
                Action::Add {
                    spec: one_value("plugins add", values)?,
                    approved,
                    scope,
                    profile: profile.clone(),
                }
            }
            "remove" => {
                reject_action_flags(approved, unset.as_deref())?;
                Action::Remove {
                    spec: one_value("plugins remove", values)?,
                    scope,
                }
            }
            "search" => {
                reject_action_flags(approved, unset.as_deref())?;
                let query = match values.as_slice() {
                    [] => None,
                    [query] => Some(query.clone()),
                    _ => return Err("plugins search [QUERY]".to_string()),
                };
                Action::Search { query }
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
            "new" => {
                reject_action_flags(approved, unset.as_deref())?;
                let (name, form) = match values.as_slice() {
                    [name] => (name.clone(), None),
                    [name, form] => (name.clone(), Some(NewPluginForm::parse(form)?)),
                    _ => return Err("plugins new NAME [manifest|wasm|command]".to_string()),
                };
                Action::New { name, form }
            }
            "dev" => {
                if unset.is_some() {
                    return Err("--unset is only valid for plugins config".to_string());
                }
                Action::Dev {
                    spec: one_value("plugins dev", values)?,
                    approved,
                }
            }
            "publish" => {
                reject_action_flags(approved, unset.as_deref())?;
                Action::Publish {
                    spec: one_value("plugins publish", values)?,
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
                Action::Config {
                    spec,
                    change,
                    scope,
                }
            }
            "setup" => {
                if unset.is_some() {
                    return Err("--unset is only valid for plugins config".to_string());
                }
                Action::Setup {
                    spec: one_value("plugins setup", values)?,
                    approved,
                    scope,
                    profile: profile.clone(),
                }
            }
            "update" => {
                if unset.is_some() {
                    return Err("--unset is only valid for plugins config".to_string());
                }
                Action::Update {
                    spec: match values.as_slice() {
                        [] => None,
                        [spec] => Some(spec.clone()),
                        _ => return Err("plugins update [NAME|PATH]".to_string()),
                    },
                    approved,
                    scope,
                }
            }
            other => return Err(format!("unknown plugins command: {other}")),
        };
        if profile.is_some() && !matches!(action, Action::Add { .. } | Action::Setup { .. }) {
            return Err("--profile is only valid for plugins add or setup".to_string());
        }
        Ok(Self { action, json })
    }
}

const BUILTIN_PLUGIN_REGISTRY: &str = include_str!("../../../plugins/registry.toml");

#[derive(Debug, Deserialize)]
struct PluginRegistry {
    schema: String,
    #[serde(default)]
    plugin: Vec<RegistryPlugin>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RegistryPlugin {
    name: String,
    description: String,
    source: String,
    publisher: String,
    form: PluginRuntime,
}

fn search_plugins(query: Option<&str>, json_output: bool) -> Result<(), String> {
    let registry: PluginRegistry = toml::from_str(BUILTIN_PLUGIN_REGISTRY)
        .map_err(|error| format!("built-in plugin registry is invalid: {error}"))?;
    if registry.schema != "pentect.plugin-registry.v1" {
        return Err("built-in plugin registry schema is unsupported".to_string());
    }
    for plugin in &registry.plugin {
        let expected = format!("github:@{}/", plugin.publisher);
        if !plugin.source.starts_with(&expected) {
            return Err(format!(
                "built-in plugin '{}' source does not match publisher '{}'",
                plugin.name, plugin.publisher
            ));
        }
    }
    let query = query.unwrap_or_default().trim().to_ascii_lowercase();
    let plugins = registry
        .plugin
        .into_iter()
        .filter(|plugin| {
            query.is_empty()
                || plugin.name.to_ascii_lowercase().contains(&query)
                || plugin.description.to_ascii_lowercase().contains(&query)
                || plugin.publisher.to_ascii_lowercase().contains(&query)
        })
        .collect::<Vec<_>>();
    if json_output {
        println!(
            "{}",
            json!({
                "schema": registry.schema,
                "plugins": plugins,
            })
        );
        return Ok(());
    }
    if plugins.is_empty() {
        println!("none");
        return Ok(());
    }
    for plugin in plugins {
        println!(
            "{}: {} [{}; {}]\n  {}",
            plugin.name,
            plugin.description,
            runtime_name(plugin.form),
            plugin.publisher,
            plugin.source
        );
    }
    Ok(())
}

fn reject_action_flags(approved: bool, unset: Option<&str>) -> Result<(), String> {
    if approved {
        return Err("--yes is only valid for plugins add, dev, setup, or update".to_string());
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
    for (scope, spec) in plugins::config_specs_scoped().map_err(|error| error.to_string())? {
        let active = plugins::active_from_scoped_specs(vec![(scope, spec.clone())], true)
            .map_err(|error| error.to_string())?;
        let source =
            plugins::plugin_source_in_scope(&spec, scope).map_err(|error| error.to_string())?;
        let manifest = load_plugin_manifest(&source)?;
        rows.push(PluginRow {
            name: plugin_name(&source, manifest.as_ref()),
            source: match scope {
                plugins::PluginScope::User => "user",
                plugins::PluginScope::Project => "project",
            }
            .to_string(),
            configs: active.config_paths().len(),
            binary: active.has_binary(),
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.source.cmp(&b.source)));
    rows.dedup_by(|a, b| {
        a.name == b.name && a.source == b.source && a.configs == b.configs && a.binary == b.binary
    });
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

fn add_plugin(
    spec: &str,
    approved: bool,
    scope: plugins::PluginScope,
    profile: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
    if json_output {
        return Err("plugins add does not support --json".to_string());
    }
    let spec = plugins::plugin_spec_for_scope(spec, scope).map_err(|error| error.to_string())?;
    let spec = spec.as_str();
    let project_guard = plugins::lock_plugin_mutation(scope).map_err(|error| error.to_string())?;
    let cache = plugins::snapshot_remote_plugin_cache(spec).map_err(|error| error.to_string())?;
    let project = snapshot_plugin_files(scope)?;
    let result = (|| {
        let source = plugins::refresh_plugin_source_in_scope(spec, scope)
            .map_err(|error| error.to_string())?;
        let lock_entry =
            plugins::remote_plugin_lock_entry(spec, &source).map_err(|error| error.to_string())?;
        if let Some(entry) = lock_entry {
            plugins::set_remote_plugin_lock_with_guard(scope, &project_guard, spec, Some(entry))
                .map_err(|error| error.to_string())?;
        }
        if source.manifest_path.is_some() {
            setup_plugin_source(source.clone(), approved, profile, false)?;
        }
        if source.manifest_path.is_none() {
            if profile.is_some() {
                return Err("this plugin does not declare setup profiles".to_string());
            }
            let active = plugins::active_from_scoped_specs(vec![(scope, spec.to_string())], true)
                .map_err(|error| error.to_string())?;
            if active.config_paths().is_empty() {
                return Err(format!(
                    "plugin '{}' has no plugin.toml or detector config",
                    source.name
                ));
            }
        }
        update_scoped_plugins(scope, spec, true)?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err(rollback_plugin_transaction(
            error,
            cache.as_ref(),
            &project,
            scope,
        ));
    }
    println!("enabled: {spec}");
    Ok(())
}

fn remove_plugin(spec: &str, scope: plugins::PluginScope, json_output: bool) -> Result<(), String> {
    if json_output {
        return Err("plugins remove does not support --json".to_string());
    }
    let spec = plugins::plugin_spec_for_scope(spec, scope).map_err(|error| error.to_string())?;
    let spec = spec.as_str();
    let project_guard = plugins::lock_plugin_mutation(scope).map_err(|error| error.to_string())?;
    let project = snapshot_plugin_files(scope)?;
    let result = (|| {
        let removed = update_scoped_plugins(scope, spec, false)?;
        for source in removed {
            plugins::set_remote_plugin_lock_with_guard(scope, &project_guard, &source, None)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        restore_plugin_files(scope, &project)?;
        return Err(error);
    }
    println!("removed: {spec}");
    Ok(())
}

struct ProjectPluginFiles {
    config: Option<Vec<u8>>,
    lock: Option<Vec<u8>>,
}

fn snapshot_plugin_files(scope: plugins::PluginScope) -> Result<ProjectPluginFiles, String> {
    snapshot_project_plugin_files_at(
        &plugin_config_path(scope)?,
        &plugins::plugin_lock_path(scope).map_err(|error| error.to_string())?,
    )
}

fn snapshot_project_plugin_files_at(
    config_path: &Path,
    lock_path: &Path,
) -> Result<ProjectPluginFiles, String> {
    Ok(ProjectPluginFiles {
        config: read_optional_bounded(
            config_path,
            MAX_PLUGIN_CONFIG_BYTES,
            "Pentect project config",
        )?,
        lock: read_optional_bounded(lock_path, MAX_PLUGIN_CONFIG_BYTES, "project plugin lock")?,
    })
}

fn restore_plugin_files(
    scope: plugins::PluginScope,
    snapshot: &ProjectPluginFiles,
) -> Result<(), String> {
    restore_project_plugin_files_at(
        snapshot,
        &plugin_config_path(scope)?,
        &plugins::plugin_lock_path(scope).map_err(|error| error.to_string())?,
    )
}

fn restore_project_plugin_files_at(
    snapshot: &ProjectPluginFiles,
    config_path: &Path,
    lock_path: &Path,
) -> Result<(), String> {
    let config = restore_optional_file(config_path, snapshot.config.as_deref());
    let lock = restore_optional_file(lock_path, snapshot.lock.as_deref());
    combine_rollback_results([("project config", config), ("project plugin lock", lock)])
}

fn rollback_plugin_transaction(
    error: String,
    cache: Option<&plugins::RemotePluginCacheSnapshot>,
    project: &ProjectPluginFiles,
    scope: plugins::PluginScope,
) -> String {
    // Evaluate both before aggregating so a cache rollback error never skips
    // restoration of the project config and lock (or vice versa).
    let cache = cache
        .map(plugins::restore_remote_plugin_cache)
        .unwrap_or(Ok(()))
        .map_err(|error| error.to_string());
    let project = restore_plugin_files(scope, project);
    let rollback =
        combine_rollback_results([("plugin source", cache), ("project plugin files", project)]);
    attach_rollback_error(error, rollback)
}

fn attach_rollback_error(error: String, rollback: Result<(), String>) -> String {
    match rollback {
        Ok(()) => error,
        Err(rollback) => format!("{error}; rollback failed: {rollback}"),
    }
}

fn combine_rollback_results<const N: usize>(
    results: [(&str, Result<(), String>); N],
) -> Result<(), String> {
    let failures = results
        .into_iter()
        .filter_map(|(name, result)| result.err().map(|error| format!("{name}: {error}")))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn update_scoped_plugins(
    scope: plugins::PluginScope,
    spec: &str,
    enable: bool,
) -> Result<Vec<String>, String> {
    let path = plugin_config_path(scope)?;
    update_project_plugins_at(&path, spec, enable, scope)
}

fn plugin_config_path(scope: plugins::PluginScope) -> Result<PathBuf, String> {
    match scope {
        plugins::PluginScope::User => {
            plugins::user_plugin_config_path().map_err(|error| error.to_string())
        }
        plugins::PluginScope::Project => Ok(plugins::project_plugin_config_path()),
    }
}

fn update_project_plugins_at(
    path: &Path,
    spec: &str,
    enable: bool,
    scope: plugins::PluginScope,
) -> Result<Vec<String>, String> {
    let mut document = if path.is_file() {
        read_bounded_utf8(path, MAX_PLUGIN_CONFIG_BYTES, "Pentect project config")?
            .parse::<toml_edit::DocumentMut>()
            .map_err(|error| format!("invalid project config '{}': {error}", display_path(path)))?
    } else {
        toml_edit::DocumentMut::new()
    };
    let mut active = match document.get("plugins") {
        None => Vec::new(),
        Some(item) if item.as_str().is_some() => vec![item
            .as_str()
            .ok_or_else(|| "project plugins must be a string or string array".to_string())?
            .to_string()],
        Some(item) if item.as_array().is_some() => item
            .as_array()
            .ok_or_else(|| "project plugins must be a string or string array".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "project plugins must be strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err("project plugins must be a string or string array".to_string()),
    };
    let mut removed = Vec::new();
    if enable {
        if !active.iter().any(|value| value == spec) {
            active.push(spec.to_string());
        }
    } else {
        let mut matches = active
            .iter()
            .filter(|value| value.as_str() == spec)
            .cloned()
            .collect::<Vec<_>>();
        if matches.is_empty() {
            for value in &active {
                let Ok(source) = plugins::plugin_source_in_scope(value, scope) else {
                    continue;
                };
                let Ok(manifest) = load_plugin_manifest(&source) else {
                    continue;
                };
                if plugin_name(&source, manifest.as_ref()) == spec {
                    matches.push(value.clone());
                }
            }
        }
        if matches.is_empty() {
            return Err(format!(
                "plugin is not enabled in the selected scope: {spec}"
            ));
        }
        if matches.len() > 1 {
            return Err(format!(
                "plugin name is ambiguous; remove one exact source: {}",
                matches.join(", ")
            ));
        }
        active.retain(|value| value != &matches[0]);
        removed = matches;
    }
    if !active.is_empty() {
        let mut values = toml_edit::Array::new();
        for value in active {
            values.push(value);
        }
        document["plugins"] = toml_edit::value(values);
    } else {
        document.as_table_mut().remove("plugins");
    }
    let parent = path
        .parent()
        .ok_or_else(|| "project config has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create '{}': {error}", display_path(parent)))?;
    let encoded = document.to_string();
    let temporary = path.with_extension(format!("toml.tmp-{}", std::process::id()));
    std::fs::write(&temporary, encoded)
        .map_err(|error| format!("could not stage project config: {error}"))?;
    replace_binary(&temporary, path)?;
    Ok(removed)
}

fn inspect_plugin(spec: &str, json_output: bool) -> Result<(), String> {
    let active = active_for_one(spec)?;
    let source = plugins::plugin_source(spec).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?;
    let name = plugin_name(&source, manifest.as_ref());
    let hooks = installed_wasm_hooks(&name, manifest.as_ref(), &source)?;
    let binary = manifest.as_ref().and_then(PluginManifest::wasm_name);
    let form = manifest.as_ref().map(plugin_runtime);
    let command = match manifest
        .as_ref()
        .filter(|manifest| manifest.form().ok() == Some(PluginRuntime::Command))
    {
        Some(manifest) => manifest.selected_command()?,
        None => None,
    };
    let platform = binary.is_some().then_some("portable-wasm");
    let repository = manifest.as_ref().and_then(|manifest| {
        manifest
            .repository
            .as_deref()
            .or(source.repository.as_deref())
    });
    let asset = binary.map(|binary| {
        binary_asset(
            binary,
            plugin_runtime(manifest.as_ref().unwrap()),
            &manifest.as_ref().unwrap().assets,
        )
    });
    if json_output {
        println!(
            "{}",
            json!({
                "name": name,
                "description": manifest.as_ref().and_then(|manifest| manifest.description.as_deref()),
                "manifest": source.manifest_path.as_deref().map(display_path),
                "configs": active.config_paths().iter().map(|path| display_path(path)).collect::<Vec<_>>(),
                "platform": platform,
                "binary": binary,
                "repository": repository,
                "asset": asset,
                "form": form,
                "command": command,
                "publisher_workflow": manifest.as_ref().filter(|manifest| manifest.wasm_name().is_some()).and_then(|manifest| publisher_workflow(manifest).ok()),
                "hooks": hooks,
                "required": manifest.as_ref().filter(|manifest| manifest.form().ok() != Some(PluginRuntime::Manifest)).map(|manifest| manifest.required),
                "network": manifest.as_ref().and_then(|manifest| manifest.network_config()),
                "permissions": manifest.as_ref().and_then(|manifest| manifest.permissions.as_ref()),
            })
        );
        return Ok(());
    }
    println!("name: {name}");
    if let Some(description) = manifest
        .as_ref()
        .and_then(|manifest| manifest.description.as_deref())
    {
        println!("description: {description}");
    }
    if let Some(path) = source.manifest_path.as_deref() {
        println!("manifest: {}", display_path(path));
    }
    if let Some(form) = form {
        println!("form: {}", runtime_name(form));
    }
    println!("configs: {}", active.config_paths().len());
    for path in active.config_paths() {
        println!("config: {}", display_path(path));
    }
    if let Some(binary) = binary {
        println!("platform: {}", platform.expect("Wasm has a platform"));
        println!("binary: {binary}");
        if let Some(repository) = repository {
            println!("repository: {repository}");
        }
        if let Some(workflow) = manifest.as_ref().and_then(|manifest| {
            manifest
                .wasm_name()
                .and_then(|_| publisher_workflow(manifest).ok())
        }) {
            println!("publisher-workflow: {workflow}");
        }
        if let Some(asset) = asset {
            println!("asset: {asset}");
        }
    } else if let Some(command) = command {
        println!("command: {}", display_command(command));
    }
    if let Some(hooks) = hooks {
        println!("hooks: {}", hooks.join(", "));
    }
    if let Some(manifest) = manifest
        .as_ref()
        .filter(|manifest| manifest.form().ok() != Some(PluginRuntime::Manifest))
    {
        println!("required: {}", manifest.required);
    }
    if let Some(network) = manifest
        .as_ref()
        .and_then(|manifest| manifest.network_config())
    {
        println!("network-allow: {}", network.allow.join(", "));
        println!(
            "network-methods: {}",
            network
                .methods
                .iter()
                .map(|method| method.to_ascii_uppercase())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("network-private: {}", network.private_network);
        println!("network-insecure: {}", network.allow_insecure);
    }
    if let Some(permissions) = manifest
        .as_ref()
        .and_then(|manifest| manifest.permissions.as_ref())
    {
        print_permissions(permissions);
    }
    Ok(())
}

fn installed_wasm_hooks(
    name: &str,
    manifest: Option<&PluginManifest>,
    source: &plugins::PluginSource,
) -> Result<Option<Vec<String>>, String> {
    let Some(manifest) = manifest else {
        return Ok(None);
    };
    if manifest.form()? == PluginRuntime::Command {
        return Ok(Some(manifest.hooks.clone()));
    }
    let Some(binary) = manifest.wasm_name() else {
        return Ok(None);
    };
    let destination = binary_destination(name, binary, plugin_runtime(manifest), source)?;
    if !destination.is_file() {
        return Ok(None);
    }
    let bytes = read_bounded_bytes(&destination, MAX_PLUGIN_WASM_BYTES, "WebAssembly plugin")?;
    pentect_agent::inspect_wasm_plugin_hooks(&bytes).map(Some)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NewPluginForm {
    Manifest,
    Wasm,
    Command,
}

impl NewPluginForm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "manifest" => Ok(Self::Manifest),
            "wasm" => Ok(Self::Wasm),
            "command" => Ok(Self::Command),
            _ => Err("plugin form must be manifest, wasm, or command".to_string()),
        }
    }
}

fn new_plugin_next_steps(form: NewPluginForm) -> &'static str {
    match form {
        NewPluginForm::Manifest => "pentect plugins test .\npentect plugins add .",
        NewPluginForm::Wasm => "pentect plugins dev .\npentect plugins test .",
        NewPluginForm::Command => "pentect plugins setup .\npentect plugins test .",
    }
}

fn choose_new_plugin_form() -> Result<NewPluginForm, String> {
    if !std::io::stdin().is_terminal() {
        return Err("choose a form: pentect plugins new NAME manifest|wasm|command".to_string());
    }
    println!("Choose one plugin form:");
    println!("  1  Manifest  regex declarations, no code");
    println!("  2  Wasm      sandboxed code with approved access");
    println!("  3  Command   Python, Node.js, native, or Docker over JSONL");
    print!("Form [1-3]: ");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("could not show plugin form prompt: {error}"))?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("could not read plugin form: {error}"))?;
    match answer.trim() {
        "1" | "manifest" => Ok(NewPluginForm::Manifest),
        "2" | "wasm" => Ok(NewPluginForm::Wasm),
        "3" | "command" => Ok(NewPluginForm::Command),
        _ => Err("plugin form must be 1, 2, or 3".to_string()),
    }
}

fn new_plugin(name: &str, form: Option<NewPluginForm>, json_output: bool) -> Result<(), String> {
    if json_output {
        return Err("plugins new does not support --json".to_string());
    }
    validate_new_plugin_name(name)?;
    let root = Path::new("plugins").join(name);
    if root.exists() {
        return Err(format!(
            "plugin path already exists: {}",
            display_path(&root)
        ));
    }
    let form = form.map(Ok).unwrap_or_else(choose_new_plugin_form)?;
    let crate_name = name.replace('-', "_");
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("could not create plugin directory: {error}"))?;
    match form {
        NewPluginForm::Manifest => write_manifest_plugin_template(&root, name)?,
        NewPluginForm::Wasm => write_wasm_plugin_template(&root, name, &crate_name)?,
        NewPluginForm::Command => write_command_plugin_template(&root, name)?,
    }
    let next_steps = new_plugin_next_steps(form);
    std::fs::write(
        root.join("README.md"),
        format!("# {name}\n\nCreated with `pentect plugins new {name}`.\n\n```sh\n{next_steps}\n```\n\nRead the plugin guide at https://pentect.dev/plugins/build/.\n"),
    )
    .map_err(|error| format!("could not write plugin README: {error}"))?;
    println!("created: {}", display_path(&root));
    println!("next: cd {}", display_path(&root));
    for command in next_steps.lines() {
        println!("      {command}");
    }
    Ok(())
}

fn write_manifest_plugin_template(root: &Path, name: &str) -> Result<(), String> {
    std::fs::write(
        root.join("plugin.toml"),
        format!(
            "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\ndescription = \"A Pentect plugin.\"\n\n[[detector]]\nlabel = \"CUSTOM_SECRET\"\npattern = '''CHANGE_ME_[A-Za-z0-9]+'''\n"
        ),
    )
    .map_err(|error| format!("could not write plugin.toml: {error}"))
}

fn write_wasm_plugin_template(root: &Path, name: &str, crate_name: &str) -> Result<(), String> {
    std::fs::create_dir_all(root.join("src"))
        .map_err(|error| format!("could not create plugin source directory: {error}"))?;
    std::fs::create_dir_all(root.join(".github/workflows"))
        .map_err(|error| format!("could not create plugin workflow directory: {error}"))?;
    std::fs::write(
        root.join("plugin.toml"),
        format!(
            "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\ndescription = \"A Pentect plugin.\"\nwasm = \"{name}.wasm\"\n# Set this before publishing:\n# repository = \"OWNER/REPOSITORY\"\n"
        ),
    )
    .map_err(|error| format!("could not write plugin.toml: {error}"))?;
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\npublish = false\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\npentect-plugin = \"0.1.0\"\n\n[workspace]\n"
        ),
    )
    .map_err(|error| format!("could not write Cargo.toml: {error}"))?;
    std::fs::write(
        root.join("src/lib.rs"),
        "use pentect_plugin::{Finding, Inspect, PluginResult};\n\nfn inspect(context: &mut Inspect) -> PluginResult {\n    if let Some(start) = context.input().text.find(\"CHANGE_ME\") {\n        context.add_finding(Finding::new(start, start + 9, \"CUSTOM_SECRET\"))?;\n    }\n    Ok(())\n}\n\npentect_plugin::export!(inspect);\n",
    )
    .map_err(|error| format!("could not write plugin source: {error}"))?;
    std::fs::write(root.join(".gitignore"), "/target\n/dist\n")
        .map_err(|error| format!("could not write plugin .gitignore: {error}"))?;
    std::fs::write(
        root.join(".github/workflows/release.yml"),
        plugin_release_workflow(name, crate_name),
    )
    .map_err(|error| format!("could not write plugin release workflow: {error}"))
}

fn write_command_plugin_template(root: &Path, name: &str) -> Result<(), String> {
    std::fs::write(
        root.join("plugin.toml"),
        format!(
            "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\ndescription = \"A Pentect plugin.\"\nhooks = [\"inspect\"]\n\n[commands]\nwindows = [\"py\", \"{{plugin}}/server.py\"]\nmacos = [\"python3\", \"{{plugin}}/server.py\"]\nlinux = [\"python3\", \"{{plugin}}/server.py\"]\n"
        ),
    )
    .map_err(|error| format!("could not write plugin.toml: {error}"))?;
    std::fs::write(
        root.join("server.py"),
        r#"import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    text = request.get("payload", {}).get("text", "")
    spans = []
    marker = "CHANGE_ME"
    start = text.find(marker)
    if start >= 0:
        spans.append({"start": start, "end": start + len(marker), "label": "CUSTOM_SECRET", "category": "secret", "confidence": "high"})
    response = {"schema": "pentect.plugin.v1", "id": request["id"], "type": "result", "action": "next", "spans": spans}
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#,
    )
    .map_err(|error| format!("could not write command plugin source: {error}"))
}

fn validate_new_plugin_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || name.starts_with('-')
        || name.ends_with('-')
        || !name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(
            "plugin name must use lowercase letters, numbers, and single hyphens".to_string(),
        );
    }
    if name.as_bytes().windows(2).any(|pair| pair == b"--") {
        return Err("plugin name cannot contain consecutive hyphens".to_string());
    }
    Ok(())
}

fn dev_plugin(spec: &str, approved: bool, json_output: bool) -> Result<(), String> {
    if json_output {
        return Err("plugins dev does not support --json".to_string());
    }
    let source = plugins::plugin_source(spec).map_err(|error| error.to_string())?;
    let manifest = load_plugin_manifest(&source)?
        .ok_or_else(|| "plugin development requires plugin.toml".to_string())?;
    if manifest.form()? != PluginRuntime::Wasm {
        return Err("plugins dev currently builds Wasm plugins only".to_string());
    }
    let manifest_path = source
        .manifest_path
        .as_deref()
        .ok_or_else(|| "plugin development requires a local plugin.toml".to_string())?;
    let manifest_hash = sha256_path(manifest_path)?;
    let built = build_local_plugin(&source, &manifest)?;
    let built_bytes = read_bounded_bytes(&built, MAX_PLUGIN_WASM_BYTES, "WebAssembly plugin")?;
    let hooks = pentect_agent::inspect_wasm_plugin_hooks(&built_bytes)?;
    let check = if manifest.network_config().is_some() {
        Check::ok(
            "binary",
            "valid Wasm; network access is checked during activation",
        )
    } else {
        test_binary(&built)
    };
    println!("binary: {}", check.status.as_str());
    if check.status == Status::Fail {
        return Err(format!("plugin test failed: {}", check.detail));
    }
    let name = plugin_name(&source, Some(&manifest));
    println!("built: {}", display_path(&built));
    println!("hooks: {}", hooks.join(", "));
    println!("required: {}", manifest.required);
    if let Some(network) = manifest.network_config() {
        println!("requested network access:");
        println!("  allow: {}", network.allow.join(", "));
        println!("  methods: {}", network.methods.join(", "));
        println!("WARNING: this development build can send hook input to these origins");
    }
    if !approved && !confirm_setup()? {
        return Err("plugin development activation was not approved".to_string());
    }

    let binary = manifest
        .wasm_name()
        .ok_or_else(|| "plugin development requires a Wasm binary".to_string())?;
    let destination = binary_destination(&name, binary, plugin_runtime(&manifest), &source)?;
    let dirs = plugin_runtime_dirs_for_source(&name, &source)?;
    let lock_path = dirs.data_dir.join(PLUGIN_BINARY_LOCK_FILE);
    let approval_path = dirs.data_dir.join(PLUGIN_APPROVAL_FILE);
    let previous_binary = read_optional_bounded(
        &destination,
        MAX_PLUGIN_WASM_BYTES,
        "installed development plugin",
    )?;
    let previous_lock =
        read_optional_bounded(&lock_path, MAX_PLUGIN_METADATA_BYTES, "plugin binary lock")?;
    let previous_approval =
        read_optional_bounded(&approval_path, MAX_PLUGIN_METADATA_BYTES, "plugin approval")?;

    let activation = (|| {
        let parent = destination
            .parent()
            .ok_or_else(|| "plugin binary destination has no parent".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create plugin binary directory: {error}"))?;
        let staged = destination.with_extension(format!("wasm.tmp-{}", std::process::id()));
        std::fs::copy(&built, &staged)
            .map_err(|error| format!("could not stage development plugin: {error}"))?;
        replace_binary(&staged, &destination)?;
        let sha256 = sha256_path(&destination)?;
        write_development_binary_lock(&name, &source, binary, &sha256)?;
        if sha256_path(manifest_path)? != manifest_hash {
            return Err("plugin.toml changed during the development build".to_string());
        }
        write_plugin_approval(&name, &source, &manifest, &hooks)?;
        let active_check = test_binary(manifest_path);
        if active_check.status == Status::Fail {
            return Err(format!(
                "activated development plugin test failed: {}",
                active_check.detail
            ));
        }
        Ok(())
    })();
    if let Err(error) = activation {
        let binary = restore_optional_file(&destination, previous_binary.as_deref());
        let lock = restore_optional_file(&lock_path, previous_lock.as_deref());
        let approval = restore_optional_file(&approval_path, previous_approval.as_deref());
        return Err(attach_rollback_error(
            error,
            combine_rollback_results([
                ("plugin binary", binary),
                ("plugin binary lock", lock),
                ("plugin approval", approval),
            ]),
        ));
    }
    println!("active: local development build");
    Ok(())
}

fn publish_plugin(spec: &str, json_output: bool) -> Result<(), String> {
    if json_output {
        return Err("plugins publish does not support --json".to_string());
    }
    let source = plugins::plugin_source(spec).map_err(|error| error.to_string())?;
    let manifest = load_plugin_manifest(&source)?
        .ok_or_else(|| "plugins publish requires plugin.toml".to_string())?;
    if manifest.form()? != PluginRuntime::Wasm {
        return Err("plugins publish currently packages Wasm plugins only".to_string());
    }
    let repository = binary_repository(&source, &manifest)?;
    let binary = manifest
        .wasm_name()
        .ok_or_else(|| "declarative plugins do not need a release binary".to_string())?;
    let built = build_local_plugin(&source, &manifest)?;
    let check = test_binary(&built);
    if check.status == Status::Fail {
        return Err(format!("plugin test failed: {}", check.detail));
    }
    let root = source
        .manifest_path
        .as_deref()
        .and_then(Path::parent)
        .ok_or_else(|| "plugin manifest has no parent directory".to_string())?;
    let dist = root.join("dist");
    std::fs::create_dir_all(&dist)
        .map_err(|error| format!("could not create dist directory: {error}"))?;
    let asset = dist.join(binary);
    std::fs::copy(&built, &asset)
        .map_err(|error| format!("could not stage plugin binary: {error}"))?;
    let digest = sha256_path(&asset)?;
    std::fs::write(
        dist.join(format!("{binary}.sha256")),
        format!("{digest}  {binary}\n"),
    )
    .map_err(|error| format!("could not write plugin checksum: {error}"))?;
    println!("publish bundle: {}", display_path(&dist));
    println!("repository: {repository}");
    println!(
        "release: push a v* tag; the generated workflow builds, attests, and uploads the asset"
    );
    Ok(())
}

fn build_local_plugin(
    source: &plugins::PluginSource,
    manifest: &PluginManifest,
) -> Result<PathBuf, String> {
    let binary = manifest
        .wasm_name()
        .ok_or_else(|| "declarative plugins do not need a WebAssembly build".to_string())?;
    let root = source
        .manifest_path
        .as_deref()
        .and_then(Path::parent)
        .ok_or_else(|| "plugin manifest has no parent directory".to_string())?;
    if !root.join("Cargo.toml").is_file() {
        return Err("plugins dev currently supports Rust plugins with Cargo.toml".to_string());
    }
    let metadata = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not inspect Cargo build directory: {error}"))?;
    if !metadata.status.success() {
        return Err("could not inspect Cargo build directory".to_string());
    }
    let target_directory = serde_json::from_slice::<serde_json::Value>(&metadata.stdout)
        .ok()
        .and_then(|value| value.get("target_directory")?.as_str().map(PathBuf::from))
        .ok_or_else(|| "Cargo metadata did not report target_directory".to_string())?;
    let status = Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not start cargo: {error}"))?;
    if !status.success() {
        return Err("plugin build failed".to_string());
    }
    let crate_asset = binary.replace('-', "_");
    let built = target_directory
        .join("wasm32-unknown-unknown/release")
        .join(crate_asset);
    if !built.is_file() {
        return Err(format!(
            "build completed but {} was not produced",
            display_path(&built)
        ));
    }
    Ok(built)
}

fn plugin_release_workflow(name: &str, crate_name: &str) -> String {
    format!(
        r#"name: Release plugin

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c # stable
        with:
          targets: wasm32-unknown-unknown
      - run: cargo build --release --locked --target wasm32-unknown-unknown
      - name: Package
        run: |
          cp target/wasm32-unknown-unknown/release/{crate_name}.wasm {name}.wasm
          sha256sum {name}.wasm > {name}.wasm.sha256
      - uses: actions/attest-build-provenance@e3fe62ef559997059fe8380e7d2b4c909e2d65f4 # v3
        with:
          subject-path: {name}.wasm
      - name: Publish
        env:
          GH_TOKEN: ${{{{ github.token }}}}
        run: gh release create "$GITHUB_REF_NAME" {name}.wasm {name}.wasm.sha256 --verify-tag --generate-notes
"#
    )
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
#[serde(deny_unknown_fields)]
struct PluginManifest {
    schema: Option<String>,
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    postscript: Vec<toml::Value>,
    #[serde(default)]
    #[serde(rename = "detector")]
    detector: Vec<toml::Value>,
    wasm: Option<String>,
    /// Legacy alias for `wasm`, retained while installed v0.0.x plugins migrate.
    binary: Option<String>,
    #[serde(default)]
    command: Vec<String>,
    commands: Option<PlatformCommands>,
    setup: Option<CommandSetupConfig>,
    #[serde(default)]
    hooks: Vec<String>,
    repository: Option<String>,
    publisher: Option<PublisherConfig>,
    #[serde(default)]
    assets: BTreeMap<String, String>,
    execution: Option<ExecutionConfig>,
    #[serde(default)]
    required: bool,
    network: Option<NetworkConfig>,
    permissions: Option<PermissionsConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublisherConfig {
    workflow: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionConfig {
    #[serde(default, rename = "args")]
    args: Vec<String>,
    runtime: Option<String>,
    mode: Option<String>,
    timeout_ms: Option<u64>,
    startup_timeout_ms: Option<u64>,
    max_input_bytes: Option<usize>,
    max_output_bytes: Option<usize>,
    max_spans: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkConfig {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    private_network: bool,
    #[serde(default)]
    allow_insecure: bool,
    max_request_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    max_requests: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PermissionsConfig {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    run: Vec<Vec<String>>,
    #[serde(default)]
    storage: bool,
    network: Option<NetworkConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformCommands {
    windows: Option<Vec<String>>,
    macos: Option<Vec<String>>,
    linux: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandSetupConfig {
    #[serde(default)]
    command: Vec<String>,
    commands: Option<PlatformCommands>,
    #[serde(default)]
    profiles: Vec<String>,
    profile_arg: Option<String>,
    download: Option<String>,
    disk: Option<String>,
}

impl CommandSetupConfig {
    fn selected_command(&self) -> Result<&[String], String> {
        if !self.command.is_empty() && self.commands.is_some() {
            return Err("[setup] cannot set both command and [setup.commands]".to_string());
        }
        if !self.command.is_empty() {
            return Ok(&self.command);
        }
        let Some(commands) = self.commands.as_ref() else {
            return Err("[setup] requires command or [setup.commands]".to_string());
        };
        #[cfg(windows)]
        let selected = commands.windows.as_deref();
        #[cfg(target_os = "macos")]
        let selected = commands.macos.as_deref();
        #[cfg(target_os = "linux")]
        let selected = commands.linux.as_deref();
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        let selected: Option<&[String]> = None;
        selected.ok_or_else(|| {
            format!(
                "plugin environment setup is unsupported on {}",
                std::env::consts::OS
            )
        })
    }

    fn command_variants(&self) -> Vec<&[String]> {
        if !self.command.is_empty() {
            return vec![&self.command];
        }
        self.commands
            .iter()
            .flat_map(|commands| {
                [
                    commands.windows.as_deref(),
                    commands.macos.as_deref(),
                    commands.linux.as_deref(),
                ]
            })
            .flatten()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PluginRuntime {
    Manifest,
    #[default]
    Wasm,
    Command,
}

impl PluginManifest {
    fn wasm_name(&self) -> Option<&str> {
        self.wasm.as_deref().or(self.binary.as_deref())
    }

    fn network_config(&self) -> Option<&NetworkConfig> {
        self.permissions
            .as_ref()
            .and_then(|permissions| permissions.network.as_ref())
            .or(self.network.as_ref())
    }

    fn form(&self) -> Result<PluginRuntime, String> {
        let manifest = !self.detector.is_empty();
        let wasm = self.wasm_name().is_some();
        if !self.command.is_empty() && self.commands.is_some() {
            return Err("plugin.toml cannot set both command and [commands]".to_string());
        }
        let command = !self.command.is_empty() || self.commands.is_some();
        let count = usize::from(manifest) + usize::from(wasm) + usize::from(command);
        if count != 1 {
            return Err(
                "plugin.toml must contain exactly one of [[detector]], wasm, or command"
                    .to_string(),
            );
        }
        Ok(if manifest {
            PluginRuntime::Manifest
        } else if wasm {
            PluginRuntime::Wasm
        } else {
            PluginRuntime::Command
        })
    }

    fn selected_command(&self) -> Result<Option<&[String]>, String> {
        if !self.command.is_empty() {
            return Ok(Some(&self.command));
        }
        let Some(commands) = self.commands.as_ref() else {
            return Ok(None);
        };
        #[cfg(windows)]
        let selected = commands.windows.as_deref();
        #[cfg(target_os = "macos")]
        let selected = commands.macos.as_deref();
        #[cfg(target_os = "linux")]
        let selected = commands.linux.as_deref();
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        let selected: Option<&[String]> = None;
        selected
            .map(Some)
            .ok_or_else(|| format!("command plugin is unsupported on {}", std::env::consts::OS))
    }

    fn command_variants(&self) -> Vec<&[String]> {
        if !self.command.is_empty() {
            return vec![&self.command];
        }
        self.commands
            .iter()
            .flat_map(|commands| {
                [
                    commands.windows.as_deref(),
                    commands.macos.as_deref(),
                    commands.linux.as_deref(),
                ]
            })
            .flatten()
            .collect()
    }
}

fn plugin_runtime(manifest: &PluginManifest) -> PluginRuntime {
    manifest
        .form()
        .expect("validated plugin manifest has one runtime")
}

fn runtime_name(runtime: PluginRuntime) -> &'static str {
    match runtime {
        PluginRuntime::Manifest => "manifest",
        PluginRuntime::Wasm => "wasm",
        PluginRuntime::Command => "command",
    }
}

fn display_command(argv: &[String]) -> String {
    argv.iter()
        .map(|argument| {
            if argument.is_empty()
                || argument
                    .chars()
                    .any(|character| character.is_whitespace() || matches!(character, '"' | '\''))
            {
                serde_json::to_string(argument).unwrap_or_else(|_| "\"<invalid>\"".to_string())
            } else {
                argument.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn load_plugin_manifest(source: &plugins::PluginSource) -> Result<Option<PluginManifest>, String> {
    let Some(path) = &source.manifest_path else {
        return Ok(None);
    };
    let src = read_bounded_utf8(path, MAX_PLUGIN_MANIFEST_BYTES, "plugin manifest")?;
    let manifest: PluginManifest = toml::from_str(&src)
        .map_err(|e| format!("invalid plugin manifest '{}': {e}", display_path(path)))?;
    if manifest.schema.as_deref() != Some("pentect.plugin.v1") {
        return Err(format!(
            "plugin manifest '{}' requires schema = \"pentect.plugin.v1\"; found '{}'",
            display_path(path),
            manifest.schema.as_deref().unwrap_or_default()
        ));
    }
    if !manifest.postscript.is_empty() {
        return Err(
            "plugin postscripts are not supported; publish setup output as a signed release asset"
                .to_string(),
        );
    }
    let form = manifest.form()?;
    if manifest.wasm.is_some() && manifest.binary.is_some() {
        return Err("plugin.toml cannot set both wasm and legacy binary".to_string());
    }
    if manifest.network.is_some()
        && manifest
            .permissions
            .as_ref()
            .and_then(|permissions| permissions.network.as_ref())
            .is_some()
    {
        return Err("use [permissions.network], not both it and legacy [network]".to_string());
    }
    if let Some(binary) = manifest.wasm_name() {
        let name = manifest
            .name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(&source.name);
        validate_binary_name(binary, name)?;
        if !binary.to_ascii_lowercase().ends_with(".wasm") {
            return Err("wasm plugins must publish a portable .wasm module".to_string());
        }
        let execution = manifest.execution.as_ref();
        if execution
            .and_then(|execution| execution.runtime.as_deref())
            .is_some_and(|runtime| runtime != "wasm")
        {
            return Err("plugins only support execution.runtime = \"wasm\"".to_string());
        }
        if execution
            .and_then(|execution| execution.mode.as_deref())
            .is_some_and(|mode| mode != "oneshot")
        {
            return Err("plugins only support execution.mode = \"oneshot\"".to_string());
        }
        if execution.is_some_and(|execution| !execution.args.is_empty()) {
            return Err("WebAssembly plugins cannot declare execution.args".to_string());
        }
        if let Some(repository) = manifest
            .repository
            .as_deref()
            .or(source.repository.as_deref())
        {
            update::validate_repository(repository)?;
        }
        validate_publisher(&manifest)?;
    }
    if form == PluginRuntime::Command {
        validate_command(&manifest)?;
        validate_command_setup(manifest.setup.as_ref())?;
        if manifest.network.is_some() || manifest.permissions.is_some() {
            return Err(
                "command plugins run natively; [network] and [permissions] apply only to Wasm"
                    .to_string(),
            );
        }
    } else if !manifest.hooks.is_empty() || manifest.setup.is_some() {
        return Err("hooks and [setup] are declared only by command plugins".to_string());
    }
    if form == PluginRuntime::Wasm {
        validate_permissions(manifest.permissions.as_ref())?;
    } else if manifest.permissions.is_some() {
        return Err("[permissions] is only valid for Wasm plugins".to_string());
    }
    if form != PluginRuntime::Wasm && manifest.network.is_some() {
        return Err("[network] is only valid for Wasm plugins".to_string());
    }
    validate_network(&manifest)?;
    validate_execution(&manifest)?;
    Ok(Some(manifest))
}

fn validate_permissions(permissions: Option<&PermissionsConfig>) -> Result<(), String> {
    let Some(permissions) = permissions else {
        return Ok(());
    };
    if permissions.read.len() > 64
        || permissions.write.len() > 64
        || permissions.env.len() > 64
        || permissions.run.len() > 64
    {
        return Err("Wasm permissions allow at most 64 entries per access type".to_string());
    }
    for (kind, paths) in [
        ("read", permissions.read.as_slice()),
        ("write", permissions.write.as_slice()),
    ] {
        let mut seen = BTreeSet::new();
        for path in paths {
            let valid_root = path.starts_with("project:") || path.starts_with("plugin:");
            let relative = path.split_once(':').map(|(_, value)| value).unwrap_or("");
            if !valid_root
                || relative.is_empty()
                || relative.starts_with(['/', '\\'])
                || relative
                    .split(['/', '\\'])
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || (!relative.ends_with("/**") && relative.contains('*'))
                || relative.contains('?')
            {
                return Err(format!(
                    "Wasm permission {kind} path must be project:PATH or plugin:PATH and may only end in /**"
                ));
            }
            if !seen.insert(path) {
                return Err(format!("duplicate Wasm {kind} permission: {path}"));
            }
        }
    }
    let mut env = BTreeSet::new();
    for name in &permissions.env {
        if name.is_empty()
            || name.len() > 128
            || name.as_bytes()[0].is_ascii_digit()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(format!("invalid environment permission: {name}"));
        }
        if !env.insert(name) {
            return Err(format!("duplicate environment permission: {name}"));
        }
    }
    let mut run = BTreeSet::new();
    for argv in &permissions.run {
        if argv.is_empty()
            || argv.len() > 64
            || argv
                .iter()
                .any(|argument| argument.len() > 8192 || argument.contains('\0'))
        {
            return Err("Wasm run permissions must contain a bounded argv array".to_string());
        }
        if !run.insert(argv) {
            return Err("duplicate Wasm run permission".to_string());
        }
    }
    if let Some(network) = permissions.network.as_ref() {
        validate_network_config(network)?;
    }
    Ok(())
}

fn validate_command(manifest: &PluginManifest) -> Result<(), String> {
    let variants = manifest.command_variants();
    if variants.is_empty() {
        return Err("command plugins require at least one command argv".to_string());
    }
    for command in variants {
        if command.is_empty() || command[0].trim().is_empty() {
            return Err("command plugins require a non-empty command argv".to_string());
        }
        if command.len() > 256 || command.iter().any(|argument| argument.len() > 32 * 1024) {
            return Err("command argv exceeds its limit".to_string());
        }
    }
    if manifest.hooks.is_empty() {
        return Err("command plugins require at least one hook".to_string());
    }
    let allowed = [
        "prepare",
        "inspect",
        "finalize",
        "request",
        "response",
        "tool_call",
        "file",
    ];
    let mut seen = BTreeSet::new();
    for hook in &manifest.hooks {
        if !allowed.contains(&hook.as_str()) {
            return Err(format!("command plugin declares unknown hook '{hook}'"));
        }
        if !seen.insert(hook) {
            return Err(format!(
                "command plugin declares hook '{hook}' more than once"
            ));
        }
    }
    Ok(())
}

fn validate_command_setup(setup: Option<&CommandSetupConfig>) -> Result<(), String> {
    let Some(setup) = setup else {
        return Ok(());
    };
    let variants = setup.command_variants();
    if variants.is_empty() {
        return Err("[setup] requires at least one command argv".to_string());
    }
    for command in variants {
        if command.is_empty() || command[0].trim().is_empty() {
            return Err("[setup] requires a non-empty command argv".to_string());
        }
        if command.len() > 256 || command.iter().any(|argument| argument.len() > 32 * 1024) {
            return Err("setup command argv exceeds its limit".to_string());
        }
    }
    if setup.profiles.len() > 16 {
        return Err("[setup] allows at most 16 profiles".to_string());
    }
    let mut profiles = BTreeSet::new();
    for profile in &setup.profiles {
        if profile.is_empty()
            || profile.len() > 32
            || !profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(format!("invalid setup profile: {profile}"));
        }
        if !profiles.insert(profile) {
            return Err(format!("duplicate setup profile: {profile}"));
        }
    }
    match (setup.profiles.is_empty(), setup.profile_arg.as_deref()) {
        (true, Some(_)) => return Err("setup profile_arg requires profiles".to_string()),
        (false, None) => return Err("setup profiles require profile_arg".to_string()),
        (_, Some(argument))
            if argument.is_empty()
                || argument.len() > 128
                || !argument.starts_with('-')
                || argument.chars().any(char::is_whitespace) =>
        {
            return Err("setup profile_arg must be one bounded option".to_string())
        }
        _ => {}
    }
    for (name, value) in [("download", &setup.download), ("disk", &setup.disk)] {
        if value.as_ref().is_some_and(|value| value.len() > 512) {
            return Err(format!("setup {name} description exceeds its limit"));
        }
    }
    Ok(())
}

fn validate_publisher(manifest: &PluginManifest) -> Result<(), String> {
    let workflow = publisher_workflow(manifest)?;
    if !pentect_agent::valid_plugin_publisher_workflow(workflow) {
        return Err("publisher workflow must be a repository-relative YAML path".to_string());
    }
    Ok(())
}

fn validate_network(manifest: &PluginManifest) -> Result<(), String> {
    let Some(network) = manifest.network_config() else {
        return Ok(());
    };
    validate_network_config(network)
}

fn validate_network_config(network: &NetworkConfig) -> Result<(), String> {
    if network.allow.is_empty() || network.allow.len() > 64 {
        return Err("network access requires 1 to 64 allowed origins".to_string());
    }
    if network.methods.is_empty() {
        return Err("network access requires at least one method".to_string());
    }
    for origin in &network.allow {
        let url = reqwest::Url::parse(origin)
            .map_err(|_| "network allow list contains an invalid origin".to_string())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "HTTP origins must be scheme://host[:port] without credentials or paths"
                    .to_string(),
            );
        }
        if url.scheme() == "http" && !network.allow_insecure {
            return Err("HTTP origins require network.allow_insecure = true".to_string());
        }
    }
    for method in &network.methods {
        let method = method.trim().to_ascii_uppercase();
        reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| format!("invalid network method: {method}"))?;
        if !matches!(
            method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            return Err(format!("unsupported network method: {method}"));
        }
    }
    for (name, limit) in [
        ("max_request_bytes", network.max_request_bytes),
        ("max_response_bytes", network.max_response_bytes),
    ] {
        if limit == Some(0) {
            return Err(format!("network.{name} must be greater than zero"));
        }
    }
    if network
        .max_request_bytes
        .is_some_and(|limit| limit > 1024 * 1024)
        || network
            .max_response_bytes
            .is_some_and(|limit| limit > 4 * 1024 * 1024)
        || network
            .max_requests
            .is_some_and(|limit| limit == 0 || limit > 16)
    {
        return Err("network limits exceed Pentect's sandbox limits".to_string());
    }
    Ok(())
}

fn validate_execution(manifest: &PluginManifest) -> Result<(), String> {
    let Some(execution) = manifest.execution.as_ref() else {
        return Ok(());
    };
    if execution
        .timeout_ms
        .is_some_and(|value| value == 0 || value > 60_000)
        || execution
            .startup_timeout_ms
            .is_some_and(|value| value == 0 || value > 600_000)
        || execution
            .max_input_bytes
            .is_some_and(|value| value == 0 || value > 4 * 1024 * 1024)
        || execution
            .max_output_bytes
            .is_some_and(|value| value == 0 || value > 4 * 1024 * 1024)
        || execution
            .max_spans
            .is_some_and(|value| value == 0 || value > 4096)
    {
        return Err("execution limits exceed Pentect's runtime limits".to_string());
    }
    Ok(())
}

fn publisher_workflow(manifest: &PluginManifest) -> Result<&str, String> {
    Ok(manifest
        .publisher
        .as_ref()
        .and_then(|publisher| publisher.workflow.as_deref())
        .unwrap_or(DEFAULT_PUBLISHER_WORKFLOW))
}

fn plugin_name(source: &plugins::PluginSource, manifest: Option<&PluginManifest>) -> String {
    manifest
        .and_then(|manifest| manifest.name.as_deref())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&source.name)
        .to_string()
}

fn config_plugin(
    spec: &str,
    change: ConfigChange,
    scope: plugins::PluginScope,
    json_output: bool,
) -> Result<(), String> {
    let spec = plugins::plugin_spec_for_scope(spec, scope).map_err(|error| error.to_string())?;
    let source = plugins::plugin_source_in_scope(&spec, scope).map_err(|e| e.to_string())?;
    let manifest = load_plugin_manifest(&source)?;
    let name = plugin_name(&source, manifest.as_ref());
    let dirs = plugin_runtime_dirs_for_source(&name, &source)?;
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
    let src = read_bounded_utf8(path, MAX_PLUGIN_CONFIG_BYTES, "plugin config")?;
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
    let temporary = path.with_extension(format!("toml.tmp-{}", std::process::id()));
    std::fs::write(&temporary, src).map_err(|e| {
        format!(
            "could not stage plugin config '{}': {e}",
            display_path(path)
        )
    })?;
    replace_binary(&temporary, path)
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

fn setup_plugin(
    spec: &str,
    approved: bool,
    scope: plugins::PluginScope,
    profile: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
    let spec = plugins::plugin_spec_for_scope(spec, scope).map_err(|error| error.to_string())?;
    let spec = spec.as_str();
    let project_guard = plugins::lock_plugin_mutation(scope).map_err(|error| error.to_string())?;
    let cache = plugins::snapshot_remote_plugin_cache(spec).map_err(|error| error.to_string())?;
    let project = snapshot_plugin_files(scope)?;
    let result = (|| {
        let source = plugins::refresh_plugin_source_in_scope(spec, scope)
            .map_err(|error| error.to_string())?;
        if let Some(entry) =
            plugins::remote_plugin_lock_entry(spec, &source).map_err(|error| error.to_string())?
        {
            plugins::set_remote_plugin_lock_with_guard(scope, &project_guard, spec, Some(entry))
                .map_err(|error| error.to_string())?;
        }
        setup_plugin_source(source, approved, profile, json_output)
    })();
    if let Err(error) = result {
        return Err(rollback_plugin_transaction(
            error,
            cache.as_ref(),
            &project,
            scope,
        ));
    }
    Ok(())
}

fn setup_plugin_source(
    source: plugins::PluginSource,
    approved: bool,
    profile: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
    let command_snapshot = load_plugin_manifest(&source)?
        .filter(|manifest| manifest.form().ok() == Some(PluginRuntime::Command))
        .map(|manifest| {
            let name = plugin_name(&source, Some(&manifest));
            snapshot_command_runtime(&name, &source)
        })
        .transpose()?;
    let result = setup_plugin_source_inner(source, approved, profile, json_output);
    match (result, command_snapshot) {
        (Ok(()), Some(snapshot)) => {
            snapshot.discard();
            Ok(())
        }
        (Ok(()), None) => Ok(()),
        (Err(error), Some(snapshot)) => Err(attach_rollback_error(error, snapshot.restore())),
        (Err(error), None) => Err(error),
    }
}

fn setup_plugin_source_inner(
    source: plugins::PluginSource,
    approved: bool,
    profile: Option<&str>,
    json_output: bool,
) -> Result<(), String> {
    if json_output {
        return Err("plugins setup does not support --json".to_string());
    }
    let manifest = load_plugin_manifest(&source)?
        .ok_or_else(|| format!("plugin '{}' has no plugin.toml", source.name))?;
    let manifest_hash = source
        .manifest_path
        .as_deref()
        .map(sha256_path)
        .transpose()?;
    let name = plugin_name(&source, Some(&manifest));
    let form = manifest.form()?;
    if profile.is_some() && manifest.setup.is_none() {
        return Err("this plugin does not declare setup profiles".to_string());
    }
    if form == PluginRuntime::Manifest {
        println!("verified: manifest-only plugin");
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
    if let Some(binary) = manifest.wasm_name() {
        let repository = binary_repository(&source, &manifest)?;
        let runtime = plugin_runtime(&manifest);
        let asset = binary_asset(binary, runtime, &manifest.assets);
        println!("binary: {binary}");
        println!("  release: github:{repository}");
        println!("  publisher-workflow: {}", publisher_workflow(&manifest)?);
        println!("  asset: {asset}");
        println!(
            "  destination: {}",
            binary_destination(&name, binary, runtime, &source)?.display()
        );
    }
    if form == PluginRuntime::Wasm {
        println!("plugin hooks:");
        println!("  hooks: detected from WebAssembly exports");
        println!("  required: {}", manifest.required);
        println!("  isolation: WebAssembly sandbox (explicit access only)");
    } else {
        let command = manifest
            .selected_command()?
            .ok_or_else(|| "command plugin has no command for this platform".to_string())?;
        println!("plugin hooks: {}", manifest.hooks.join(", "));
        print_hook_access(&manifest.hooks);
        println!("required: {}", manifest.required);
        println!("command: {}", display_command(command));
        println!(
            "executable: {}",
            command_executable_preview(&name, &source, &command[0])?.display()
        );
        println!("isolation: native process (runs with your user permissions)");
        if let Some(setup) = manifest.setup.as_ref() {
            if let Some(profile) = profile {
                if !setup.profiles.iter().any(|candidate| candidate == profile) {
                    return Err(format!(
                        "unknown setup profile '{profile}'; choose one of: {}",
                        setup.profiles.join(", ")
                    ));
                }
            }
            let setup_command = setup.selected_command()?;
            println!("environment setup: {}", display_command(setup_command));
            println!(
                "setup executable: {}",
                command_executable_preview(&name, &source, &setup_command[0])?.display()
            );
            if !setup.profiles.is_empty() {
                println!("setup profiles: {}", setup.profiles.join(", "));
                println!(
                    "selected profile: {}",
                    profile.unwrap_or("automatic or previously selected")
                );
            }
            if let Some(download) = setup.download.as_deref() {
                println!("expected download: {download}");
            }
            if let Some(disk) = setup.disk.as_deref() {
                println!("expected disk: {disk}");
            }
            println!("WARNING: environment setup runs natively with your user permissions");
        }
    }
    if let Some(network) = manifest.network_config() {
        println!("requested network access:");
        println!("  allow: {}", network.allow.join(", "));
        println!(
            "  methods: {}",
            network
                .methods
                .iter()
                .map(|method| method.to_ascii_uppercase())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  private-network: {}", network.private_network);
        println!("  insecure-http: {}", network.allow_insecure);
        println!(
            "  request-limit: {} bytes",
            network.max_request_bytes.unwrap_or(262_144)
        );
        println!(
            "  response-limit: {} bytes",
            network.max_response_bytes.unwrap_or(1_048_576)
        );
        println!(
            "  request-count-limit: {}",
            network.max_requests.unwrap_or(4)
        );
        if form == PluginRuntime::Wasm {
            println!("WARNING: this plugin can send hook input to approved network origins");
        }
    }
    if let Some(permissions) = manifest.permissions.as_ref() {
        println!("requested host access:");
        print_permissions(permissions);
        for argv in &permissions.run {
            println!(
                "permission-run-executable: {}",
                resolve_command_executable(&argv[0])?.display()
            );
        }
        println!("WARNING: approved access is brokered by the WebAssembly sandbox");
    }
    let approved_hooks = if let Some(binary) = manifest.wasm_name() {
        let repository = binary_repository(&source, &manifest)?;
        let runtime = plugin_runtime(&manifest);
        let destination = binary_destination(&name, binary, runtime, &source)?;
        let lock_path = plugin_runtime_dirs_for_source(&name, &source)?
            .data_dir
            .join(PLUGIN_BINARY_LOCK_FILE);
        let previous_binary = read_optional_bounded(
            &destination,
            MAX_PLUGIN_WASM_BYTES,
            "installed WebAssembly plugin",
        )?;
        let previous_lock =
            read_optional_bounded(&lock_path, MAX_PLUGIN_METADATA_BYTES, "plugin binary lock")?;
        install_release_binary(
            &name,
            &source,
            &repository,
            binary,
            runtime,
            publisher_workflow(&manifest)?,
            &manifest.assets,
        )?;
        let bytes = read_bounded_bytes(&destination, MAX_PLUGIN_WASM_BYTES, "WebAssembly plugin")?;
        let hooks = pentect_agent::inspect_wasm_plugin_hooks(&bytes)?;
        println!("hooks: {}", hooks.join(", "));
        print_hook_access(&hooks);
        if !approved && !confirm_setup()? {
            return Err(attach_rollback_error(
                "plugin setup was not approved".to_string(),
                restore_plugin_binary_files(
                    &destination,
                    previous_binary.as_deref(),
                    &lock_path,
                    previous_lock.as_deref(),
                ),
            ));
        }
        hooks
    } else {
        if !approved && !confirm_setup()? {
            return Err("plugin setup was not approved".to_string());
        }
        write_command_lock(&name, &source, &manifest)?;
        if let Some(setup) = manifest.setup.as_ref() {
            run_command_environment_setup(&name, &source, setup, profile)?;
        }
        manifest.hooks.clone()
    };
    if form != PluginRuntime::Manifest {
        let current_hash = source
            .manifest_path
            .as_deref()
            .map(sha256_path)
            .transpose()?;
        if current_hash != manifest_hash {
            return Err("plugin.toml changed during setup; approval was not recorded".to_string());
        }
        write_plugin_approval(&name, &source, &manifest, &approved_hooks)?;
    }
    println!("setup: complete");
    Ok(())
}

fn run_command_environment_setup(
    name: &str,
    source: &plugins::PluginSource,
    setup: &CommandSetupConfig,
    profile: Option<&str>,
) -> Result<(), String> {
    let remote = plugins::remote_command_files(source).map_err(|error| error.to_string())?;
    let root = if remote.is_empty() {
        source
            .manifest_path
            .as_deref()
            .and_then(Path::parent)
            .ok_or_else(|| "command plugin manifest has no parent directory".to_string())?
            .to_path_buf()
    } else {
        plugin_runtime_dirs_for_source(name, source)?
            .data_dir
            .join("command")
    };
    let mut argv = setup.selected_command()?.to_vec();
    for argument in &mut argv {
        if argument == "{plugin}" {
            *argument = root.to_string_lossy().into_owned();
        } else if let Some(relative) = argument.strip_prefix("{plugin}/") {
            let relative = Path::new(relative);
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err("setup command path must stay inside the plugin directory".to_string());
            }
            *argument = root.join(relative).to_string_lossy().into_owned();
        }
    }
    if let Some(profile) = profile {
        let argument = setup
            .profile_arg
            .as_deref()
            .ok_or_else(|| "this plugin does not accept a setup profile".to_string())?;
        argv.push(argument.to_string());
        argv.push(profile.to_string());
    }
    let executable = resolve_command_executable(&argv[0])?;
    println!("environment setup: starting");
    let status = Command::new(executable)
        .args(&argv[1..])
        .current_dir(&root)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| format!("could not start plugin environment setup: {error}"))?;
    if !status.success() {
        return Err(format!(
            "plugin environment setup failed with {}",
            status
                .code()
                .map(|code| format!("exit {code}"))
                .unwrap_or_else(|| "a signal".to_string())
        ));
    }
    println!("environment setup: complete");
    Ok(())
}

struct CommandRuntimeSnapshot {
    data_dir: PathBuf,
    approval: Option<Vec<u8>>,
    lock: Option<Vec<u8>>,
    backup: Option<PathBuf>,
}

impl CommandRuntimeSnapshot {
    fn restore(self) -> Result<(), String> {
        let command = self.data_dir.join("command");
        let command_restore = (|| {
            if command.exists() {
                std::fs::remove_dir_all(&command)
                    .map_err(|error| format!("could not clear updated command files: {error}"))?;
            }
            if let Some(backup) = self.backup {
                std::fs::rename(&backup, &command)
                    .map_err(|error| format!("could not restore command files: {error}"))?;
            }
            Ok(())
        })();
        combine_rollback_results([
            ("plugin command files", command_restore),
            (
                "plugin approval",
                restore_optional_file(
                    &self.data_dir.join(PLUGIN_APPROVAL_FILE),
                    self.approval.as_deref(),
                ),
            ),
            (
                "plugin command lock",
                restore_optional_file(
                    &self.data_dir.join(PLUGIN_COMMAND_LOCK_FILE),
                    self.lock.as_deref(),
                ),
            ),
        ])
    }

    fn discard(self) {
        if let Some(backup) = self.backup {
            let _ = std::fs::remove_dir_all(backup);
        }
    }
}

fn snapshot_command_runtime(
    name: &str,
    source: &plugins::PluginSource,
) -> Result<CommandRuntimeSnapshot, String> {
    let data_dir = plugin_runtime_dirs_for_source(name, source)?.data_dir;
    let approval = read_optional_bounded(
        &data_dir.join(PLUGIN_APPROVAL_FILE),
        MAX_PLUGIN_METADATA_BYTES,
        "plugin approval",
    )?;
    let lock = read_optional_bounded(
        &data_dir.join(PLUGIN_COMMAND_LOCK_FILE),
        MAX_PLUGIN_METADATA_BYTES,
        "plugin command lock",
    )?;
    let command = data_dir.join("command");
    let backup = if command.is_dir() {
        let backup = data_dir.join(format!("command.rollback-{}", std::process::id()));
        if backup.exists() {
            std::fs::remove_dir_all(&backup)
                .map_err(|error| format!("could not clear command rollback directory: {error}"))?;
        }
        copy_command_tree(&command, &backup)?;
        Some(backup)
    } else {
        None
    };
    Ok(CommandRuntimeSnapshot {
        data_dir,
        approval,
        lock,
        backup,
    })
}

fn copy_command_tree(source: &Path, destination: &Path) -> Result<(), String> {
    std::fs::create_dir_all(destination)
        .map_err(|error| format!("could not create command rollback directory: {error}"))?;
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    let mut files = 0usize;
    while let Some((from, to)) = pending.pop() {
        for entry in std::fs::read_dir(&from)
            .map_err(|error| format!("could not read command files for rollback: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("could not read command file for rollback: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("could not inspect command file for rollback: {error}"))?;
            let target = to.join(entry.file_name());
            if kind.is_dir() {
                std::fs::create_dir_all(&target).map_err(|error| {
                    format!("could not create command rollback directory: {error}")
                })?;
                pending.push((entry.path(), target));
            } else if kind.is_file() {
                files += 1;
                if files > 64 {
                    return Err("command plugin rollback exceeds 64 files".to_string());
                }
                std::fs::copy(entry.path(), target).map_err(|error| {
                    format!("could not copy command file for rollback: {error}")
                })?;
            } else {
                return Err("command plugin rollback refuses links and special files".to_string());
            }
        }
    }
    Ok(())
}

fn command_executable_preview(
    name: &str,
    source: &plugins::PluginSource,
    value: &str,
) -> Result<PathBuf, String> {
    let Some(relative) = value.strip_prefix("{plugin}/") else {
        return resolve_command_executable(value);
    };
    let relative = PathBuf::from(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("command executable path must stay inside the plugin directory".to_string());
    }
    let remote = plugins::remote_command_files(source).map_err(|error| error.to_string())?;
    if remote.is_empty() {
        let root = source
            .manifest_path
            .as_deref()
            .and_then(Path::parent)
            .ok_or_else(|| "command plugin manifest has no parent directory".to_string())?;
        return resolve_plugin_command_executable(value, root);
    }
    if !remote.iter().any(|(path, _)| path == &relative) {
        return Err(format!(
            "command executable is not distributed by plugin '{name}'"
        ));
    }
    Ok(plugin_runtime_dirs_for_source(name, source)?
        .data_dir
        .join("command")
        .join(relative))
}

fn print_hook_access(hooks: &[String]) {
    for hook in hooks {
        let access = match hook.as_str() {
            "prepare" => "reads and may change text before masking",
            "inspect" => "reads text before masking and may add findings",
            "finalize" => "reads and may change masked text",
            "request" => "reads and may change provider request JSON",
            "response" => "reads and may change provider response JSON",
            "tool_call" => "reads and may change a completed local tool call",
            "file" => "reads file metadata and may block the file action",
            _ => "unknown access",
        };
        println!("  {hook}: {access}");
    }
}

#[derive(Serialize)]
struct PluginApproval {
    schema: &'static str,
    manifest_sha256: String,
    hooks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_lock_sha256: Option<String>,
}

#[derive(Serialize)]
struct CommandLock {
    schema: &'static str,
    executable: String,
    managed: bool,
    file: Vec<CommandLockFile>,
}

#[derive(Serialize)]
struct CommandLockFile {
    path: String,
    sha256: String,
}

fn write_command_lock(
    name: &str,
    source: &plugins::PluginSource,
    manifest: &PluginManifest,
) -> Result<(), String> {
    let dirs = plugin_runtime_dirs_for_source(name, source)?;
    std::fs::create_dir_all(&dirs.data_dir)
        .map_err(|error| format!("could not create plugin data directory: {error}"))?;

    let remote = plugins::remote_command_files(source).map_err(|error| error.to_string())?;
    let managed = !remote.is_empty();
    let root = if remote.is_empty() {
        source
            .manifest_path
            .as_deref()
            .and_then(Path::parent)
            .ok_or_else(|| "command plugin manifest has no parent directory".to_string())?
            .to_path_buf()
    } else {
        stage_remote_command_files(&dirs.data_dir, &remote)?
    };

    let mut files = Vec::new();
    let command = manifest
        .selected_command()?
        .ok_or_else(|| "command plugin has no command for this platform".to_string())?;
    let command_files = command
        .iter()
        .filter_map(|argument| argument.strip_prefix("{plugin}/").map(PathBuf::from))
        .collect::<Vec<_>>();
    let mut command_files = command_files;
    if let Some(setup) = manifest.setup.as_ref() {
        command_files.extend(
            setup
                .selected_command()?
                .iter()
                .filter_map(|argument| argument.strip_prefix("{plugin}/"))
                .map(PathBuf::from),
        );
    }
    let locked_files = if managed {
        remote
            .iter()
            .map(|(relative, _)| relative.clone())
            .collect()
    } else {
        command_files
    };
    for relative in locked_files {
        let relative = relative.to_string_lossy().replace('\\', "/");
        if files
            .iter()
            .any(|file: &CommandLockFile| file.path == relative)
        {
            continue;
        }
        let path = root.join(&relative);
        if !path.is_file() {
            return Err(format!(
                "command plugin file is unavailable: {}",
                display_path(&path)
            ));
        }
        files.push(CommandLockFile {
            path: relative.replace('\\', "/"),
            sha256: sha256_path(&path)?,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let executable = resolve_plugin_command_executable(&command[0], &root)?;
    let encoded = toml::to_string(&CommandLock {
        schema: "pentect.plugin-command-lock.v1",
        executable: executable.to_string_lossy().into_owned(),
        managed,
        file: files,
    })
    .map_err(|error| format!("could not encode plugin command lock: {error}"))?;
    let destination = dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE);
    let temporary = dirs.data_dir.join(format!(
        "{PLUGIN_COMMAND_LOCK_FILE}.tmp-{}",
        std::process::id()
    ));
    std::fs::write(&temporary, encoded)
        .map_err(|error| format!("could not write plugin command lock: {error}"))?;
    replace_binary(&temporary, &destination)
}

fn resolve_plugin_command_executable(value: &str, root: &Path) -> Result<PathBuf, String> {
    let Some(relative) = value.strip_prefix("{plugin}/") else {
        return resolve_command_executable(value);
    };
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("command executable path must stay inside the plugin directory".to_string());
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|_| "command plugin directory is unavailable".to_string())?;
    let executable = canonical_root
        .join(relative)
        .canonicalize()
        .map_err(|_| format!("command executable is unavailable: {value}"))?;
    if !executable.starts_with(&canonical_root) || !supported_command_executable(&executable) {
        return Err(format!("command executable is unavailable: {value}"));
    }
    Ok(executable)
}

fn resolve_command_executable(value: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(value);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        let resolved = candidate
            .canonicalize()
            .map_err(|_| format!("command executable is unavailable: {value}"));
        return resolved.and_then(|path| {
            supported_command_executable(&path)
                .then_some(path)
                .ok_or_else(|| format!("command executable is unavailable: {value}"))
        });
    }
    let paths = std::env::var_os("PATH").unwrap_or_default();
    #[cfg(windows)]
    let extensions = std::env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|extension| windows_command_extension_supported(extension))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![
                ".EXE".to_string(),
                ".COM".to_string(),
                ".CMD".to_string(),
                ".BAT".to_string(),
            ]
        });
    #[cfg(not(windows))]
    let extensions = vec![String::new()];
    for directory in std::env::split_paths(&paths) {
        for extension in &extensions {
            let path = if extension.is_empty()
                || value
                    .to_ascii_lowercase()
                    .ends_with(&extension.to_ascii_lowercase())
            {
                directory.join(value)
            } else {
                directory.join(format!("{value}{extension}"))
            };
            if let Ok(path) = path.canonicalize() {
                if supported_command_executable(&path) {
                    return Ok(path);
                }
            }
        }
    }
    Err(format!("command executable is unavailable: {value}"))
}

#[cfg(unix)]
fn supported_command_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn supported_command_executable(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(windows_command_extension_supported)
}

#[cfg(any(windows, test))]
fn windows_command_extension_supported(extension: &str) -> bool {
    matches!(
        extension
            .strip_prefix('.')
            .unwrap_or(extension)
            .to_ascii_lowercase()
            .as_str(),
        "exe" | "com" | "cmd" | "bat"
    )
}

fn stage_remote_command_files(
    data_dir: &Path,
    files: &[(PathBuf, PathBuf)],
) -> Result<PathBuf, String> {
    let destination = data_dir.join("command");
    let staged = data_dir.join(format!("command.tmp-{}", std::process::id()));
    if staged.exists() {
        std::fs::remove_dir_all(&staged)
            .map_err(|error| format!("could not clear staged command plugin: {error}"))?;
    }
    std::fs::create_dir_all(&staged)
        .map_err(|error| format!("could not stage command plugin: {error}"))?;
    for (relative, cached) in files {
        let target = staged.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not stage command plugin: {error}"))?;
        }
        std::fs::copy(cached, &target)
            .map_err(|error| format!("could not stage command plugin file: {error}"))?;
    }
    if destination.exists() {
        let backup = data_dir.join(format!("command.previous-{}", std::process::id()));
        if backup.exists() {
            std::fs::remove_dir_all(&backup)
                .map_err(|error| format!("could not clear command plugin backup: {error}"))?;
        }
        std::fs::rename(&destination, &backup)
            .map_err(|error| format!("could not replace command plugin: {error}"))?;
        if let Err(error) = std::fs::rename(&staged, &destination) {
            let _ = std::fs::rename(&backup, &destination);
            return Err(format!("could not activate command plugin: {error}"));
        }
        std::fs::remove_dir_all(&backup)
            .map_err(|error| format!("could not remove command plugin backup: {error}"))?;
    } else {
        std::fs::rename(&staged, &destination)
            .map_err(|error| format!("could not activate command plugin: {error}"))?;
    }
    Ok(destination)
}

fn write_plugin_approval(
    name: &str,
    source: &plugins::PluginSource,
    manifest: &PluginManifest,
    hooks: &[String],
) -> Result<(), String> {
    let path = source
        .manifest_path
        .as_deref()
        .ok_or_else(|| "plugin approval requires plugin.toml".to_string())?;
    let approval = PluginApproval {
        schema: "pentect.plugin-approval.v1",
        manifest_sha256: sha256_path(path)?,
        hooks: hooks.to_vec(),
        command_lock_sha256: (manifest.form()? == PluginRuntime::Command)
            .then(|| {
                plugin_runtime_dirs_for_source(name, source)
                    .and_then(|dirs| sha256_path(&dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE)))
            })
            .transpose()?,
    };
    let encoded = toml::to_string(&approval)
        .map_err(|error| format!("could not encode plugin approval: {error}"))?;
    let dirs = plugin_runtime_dirs_for_source(name, source)?;
    let path = dirs.data_dir.join(PLUGIN_APPROVAL_FILE);
    let temporary = path.with_extension("toml.tmp");
    std::fs::write(&temporary, encoded)
        .map_err(|error| format!("could not write plugin approval: {error}"))?;
    replace_binary(&temporary, &path)
        .map_err(|error| format!("could not activate plugin approval: {error}"))
}

fn update_plugin(
    spec: &str,
    approved: bool,
    scope: plugins::PluginScope,
    json_output: bool,
) -> Result<(), String> {
    if json_output {
        return Err("plugins update does not support --json".to_string());
    }
    let spec = plugins::plugin_spec_for_scope(spec, scope).map_err(|error| error.to_string())?;
    let spec = spec.as_str();
    let project_guard = plugins::lock_plugin_mutation(scope).map_err(|error| error.to_string())?;
    let cache = plugins::snapshot_remote_plugin_cache(spec).map_err(|error| error.to_string())?;
    let project = snapshot_plugin_files(scope)?;
    let result = update_plugin_inner(spec, approved, scope, cache.as_ref(), &project_guard);
    if let Err(error) = result {
        return Err(rollback_plugin_transaction(
            error,
            cache.as_ref(),
            &project,
            scope,
        ));
    }
    Ok(())
}

fn update_plugin_inner(
    spec: &str,
    approved: bool,
    scope: plugins::PluginScope,
    previous: Option<&plugins::RemotePluginCacheSnapshot>,
    project_guard: &plugins::ProjectPluginMutationGuard,
) -> Result<(), String> {
    let source = plugins::refresh_plugin_source_in_scope(spec, scope).map_err(|e| e.to_string())?;
    let lock_entry =
        plugins::remote_plugin_lock_entry(spec, &source).map_err(|error| error.to_string())?;
    let manifest = load_plugin_manifest(&source)?
        .ok_or_else(|| format!("plugin '{}' has no plugin.toml", source.name))?;
    let name = plugin_name(&source, Some(&manifest));
    let current_sources =
        plugins::remote_plugin_sources(&source).map_err(|error| error.to_string())?;
    let detector_changed = show_detector_diff(previous, &current_sources)?;
    if detector_update_requires_confirmation(detector_changed, approved) && !confirm_setup()? {
        return Err("plugin update was not approved".to_string());
    }
    let Some(binary) = manifest.wasm_name() else {
        if manifest.form()? == PluginRuntime::Command {
            let command_sources_changed =
                previous.is_some_and(|snapshot| snapshot.previous_sources() != &current_sources);
            if command_sources_changed
                || verify_plugin_update_approval(&name, &source, &manifest).is_err()
            {
                println!("plugin command, files, or hook access changed; reviewing updated access");
                if let Some(entry) = lock_entry {
                    plugins::set_remote_plugin_lock_with_guard(
                        scope,
                        project_guard,
                        spec,
                        Some(entry),
                    )
                    .map_err(|error| error.to_string())?;
                }
                setup_plugin_source(source, approved, None, false)?;
                return Ok(());
            }
        }
        if let Some(entry) = lock_entry {
            plugins::set_remote_plugin_lock_with_guard(scope, project_guard, spec, Some(entry))
                .map_err(|error| error.to_string())?;
        }
        println!("update: refreshed manifest for {name}");
        return Ok(());
    };
    let repository = binary_repository(&source, &manifest)?;
    if verify_plugin_update_approval(&name, &source, &manifest).is_err() {
        println!("plugin manifest changed; reviewing updated access");
        if let Some(entry) = lock_entry {
            plugins::set_remote_plugin_lock_with_guard(scope, project_guard, spec, Some(entry))
                .map_err(|error| error.to_string())?;
        }
        setup_plugin_source(source, approved, None, false)?;
        return Ok(());
    }
    let runtime = plugin_runtime(&manifest);
    let destination = binary_destination(&name, binary, runtime, &source)?;
    let lock_path = plugin_runtime_dirs_for_source(&name, &source)?
        .data_dir
        .join(PLUGIN_BINARY_LOCK_FILE);
    let previous_binary = read_optional_bounded(
        &destination,
        MAX_PLUGIN_WASM_BYTES,
        "installed WebAssembly plugin",
    )?;
    let previous_lock =
        read_optional_bounded(&lock_path, MAX_PLUGIN_METADATA_BYTES, "plugin binary lock")?;
    install_release_binary(
        &name,
        &source,
        &repository,
        binary,
        runtime,
        publisher_workflow(&manifest)?,
        &manifest.assets,
    )?;
    if verify_plugin_update_approval(&name, &source, &manifest).is_err() {
        restore_plugin_binary_files(
            &destination,
            previous_binary.as_deref(),
            &lock_path,
            previous_lock.as_deref(),
        )?;
        println!("plugin hook access changed; reviewing updated access");
        if let Some(entry) = lock_entry {
            plugins::set_remote_plugin_lock_with_guard(scope, project_guard, spec, Some(entry))
                .map_err(|error| error.to_string())?;
        }
        setup_plugin_source(source, approved, None, false)?;
        return Ok(());
    }
    // Updating a release binary must not rewrite the user's manifest approval.
    // Keeping the original digest makes any concurrent or later edit require setup again.
    if let Some(entry) = lock_entry {
        if let Err(error) =
            plugins::set_remote_plugin_lock_with_guard(scope, project_guard, spec, Some(entry))
        {
            return Err(attach_rollback_error(
                error.to_string(),
                restore_plugin_binary_files(
                    &destination,
                    previous_binary.as_deref(),
                    &lock_path,
                    previous_lock.as_deref(),
                ),
            ));
        }
    }
    println!("update: complete");
    Ok(())
}

fn print_permissions(permissions: &PermissionsConfig) {
    if !permissions.read.is_empty() {
        println!("permission-read: {}", permissions.read.join(", "));
    }
    if !permissions.write.is_empty() {
        println!("permission-write: {}", permissions.write.join(", "));
    }
    if !permissions.env.is_empty() {
        println!("permission-env: {}", permissions.env.join(", "));
        let sensitive = sensitive_env_permissions(&permissions.env);
        if !sensitive.is_empty() {
            println!(
                "WARNING: credential-like environment access: {}",
                sensitive.join(", ")
            );
        }
    }
    for argv in &permissions.run {
        println!("permission-run: {}", display_command(argv));
    }
    if permissions.storage {
        println!("permission-storage: enabled");
    }
}

fn sensitive_env_permissions(names: &[String]) -> Vec<&str> {
    names
        .iter()
        .filter(|name| {
            let upper = name.to_ascii_uppercase();
            upper == "PASSWORD"
                || upper == "PASSWD"
                || upper == "API_KEY"
                || upper == "SECRET"
                || upper == "TOKEN"
                || upper == "CREDENTIAL"
                || upper == "CREDENTIALS"
                || upper == "PRIVATE_KEY"
                || upper == "ACCESS_KEY"
                || upper.ends_with("_PASSWORD")
                || upper.ends_with("_PASSWD")
                || upper.contains("_API_KEY")
                || upper.ends_with("_SECRET")
                || upper.contains("_SECRET_")
                || upper.ends_with("_TOKEN")
                || upper.contains("_TOKEN_")
                || upper.ends_with("_CREDENTIAL")
                || upper.ends_with("_CREDENTIALS")
                || upper.ends_with("_PRIVATE_KEY")
                || upper.ends_with("_ACCESS_KEY")
        })
        .map(String::as_str)
        .collect()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DetectorDescriptor {
    label: String,
    category: String,
    confidence: String,
    rule_sha256: String,
}

fn detector_update_requires_confirmation(detector_changed: bool, approved: bool) -> bool {
    detector_changed && !approved
}

fn show_detector_diff(
    previous: Option<&plugins::RemotePluginCacheSnapshot>,
    current: &BTreeMap<String, Vec<u8>>,
) -> Result<bool, String> {
    let Some(previous) = previous else {
        return Ok(false);
    };
    let mut before = BTreeSet::new();
    for source in previous.previous_sources().values() {
        before.extend(detector_descriptors(source)?);
    }
    let mut after = BTreeSet::new();
    for source in current.values() {
        after.extend(detector_descriptors(source)?);
    }
    if before == after {
        return Ok(false);
    }
    println!("detector changes:");
    for detector in before.difference(&after) {
        println!("  - {}", detector_summary(detector));
    }
    for detector in after.difference(&before) {
        println!("  + {}", detector_summary(detector));
    }
    Ok(true)
}

fn detector_descriptors(source: &[u8]) -> Result<BTreeSet<DetectorDescriptor>, String> {
    let source = std::str::from_utf8(source)
        .map_err(|_| "remote plugin detector source is not UTF-8".to_string())?;
    let value: toml::Value = toml::from_str(source)
        .map_err(|error| format!("remote plugin detector source is invalid: {error}"))?;
    let Some(detectors) = value.get("detector").and_then(toml::Value::as_array) else {
        return Ok(BTreeSet::new());
    };
    detectors
        .iter()
        .map(|detector| {
            let table = detector
                .as_table()
                .ok_or_else(|| "remote plugin detector entry must be a table".to_string())?;
            let canonical = canonical_detector_value(detector);
            Ok(DetectorDescriptor {
                label: table
                    .get("label")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("SECRET")
                    .to_string(),
                category: table
                    .get("category")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("secret")
                    .to_string(),
                confidence: table
                    .get("confidence")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("medium")
                    .to_string(),
                rule_sha256: data_encoding::HEXLOWER.encode(&Sha256::digest(&canonical)),
            })
        })
        .collect()
}

fn canonical_detector_value(value: &toml::Value) -> Vec<u8> {
    fn append_bytes(output: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        output.push(tag);
        output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        output.extend_from_slice(bytes);
    }
    fn append(output: &mut Vec<u8>, value: &toml::Value) {
        match value {
            toml::Value::String(value) => append_bytes(output, b's', value.as_bytes()),
            toml::Value::Integer(value) => append_bytes(output, b'i', &value.to_be_bytes()),
            toml::Value::Float(value) => append_bytes(output, b'f', &value.to_bits().to_be_bytes()),
            toml::Value::Boolean(value) => output.extend_from_slice(&[b'b', u8::from(*value)]),
            toml::Value::Datetime(value) => {
                append_bytes(output, b'd', value.to_string().as_bytes())
            }
            toml::Value::Array(values) => {
                output.push(b'a');
                output.extend_from_slice(&(values.len() as u64).to_be_bytes());
                for value in values {
                    append(output, value);
                }
            }
            toml::Value::Table(table) => {
                output.push(b't');
                output.extend_from_slice(&(table.len() as u64).to_be_bytes());
                let mut keys = table.keys().collect::<Vec<_>>();
                keys.sort();
                for key in keys {
                    append_bytes(output, b'k', key.as_bytes());
                    append(output, &table[key]);
                }
            }
        }
    }

    let mut output = Vec::new();
    append(&mut output, value);
    output
}

fn detector_summary(detector: &DetectorDescriptor) -> String {
    let short_rule = detector
        .rule_sha256
        .get(..16)
        .unwrap_or(&detector.rule_sha256);
    format!(
        "{} category={} confidence={} rule={}",
        detector.label, detector.category, detector.confidence, short_rule
    )
}

fn update_all_plugins(
    approved: bool,
    scope: plugins::PluginScope,
    json_output: bool,
) -> Result<(), String> {
    let specs = plugins::config_specs_scoped()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter_map(|(configured_scope, spec)| (configured_scope == scope).then_some(spec))
        .collect::<Vec<_>>();
    if specs.is_empty() {
        println!("none");
        return Ok(());
    }
    let mut failures = Vec::new();
    for spec in specs {
        if let Err(error) = update_plugin(&spec, approved, scope, json_output) {
            failures.push(format!("{spec}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "plugin updates failed:\n- {}",
            failures.join("\n- ")
        ))
    }
}

#[derive(Deserialize)]
struct StoredPluginApproval {
    schema: String,
    manifest_sha256: String,
    hooks: Vec<String>,
    command_lock_sha256: Option<String>,
}

fn verify_plugin_update_approval(
    name: &str,
    plugin: &plugins::PluginSource,
    manifest: &PluginManifest,
) -> Result<(), String> {
    if manifest.form()? == PluginRuntime::Manifest {
        return Ok(());
    }
    let manifest_path = plugin
        .manifest_path
        .as_deref()
        .ok_or_else(|| "plugin update requires plugin.toml".to_string())?;
    let path = plugin_runtime_dirs_for_source(name, plugin)?
        .data_dir
        .join(PLUGIN_APPROVAL_FILE);
    let source_text = read_bounded_utf8(&path, MAX_PLUGIN_METADATA_BYTES, "plugin approval")
        .map_err(|_| "plugin update requires prior setup approval".to_string())?;
    let approval: StoredPluginApproval = toml::from_str(&source_text)
        .map_err(|_| "plugin approval is invalid; run `pentect plugins setup`".to_string())?;
    if approval.schema != "pentect.plugin-approval.v1"
        || approval.manifest_sha256 != sha256_path(manifest_path)?
    {
        return Err("plugin manifest changed; review it with `pentect plugins setup`".to_string());
    }
    if manifest.form()? == PluginRuntime::Command {
        let lock = plugin_runtime_dirs_for_source(name, plugin)?
            .data_dir
            .join(PLUGIN_COMMAND_LOCK_FILE);
        let lock_sha256 = sha256_path(&lock)?;
        if approval.command_lock_sha256.as_deref() != Some(lock_sha256.as_str()) {
            return Err("plugin command files changed; run setup again".to_string());
        }
        pentect_agent::PluginMiddleware::from_paths([manifest_path.to_path_buf()])
            .map_err(|_| "plugin command files changed; run setup again".to_string())?;
    }
    let hooks = installed_wasm_hooks(name, Some(manifest), plugin)?
        .ok_or_else(|| "installed plugin binary is missing; run setup again".to_string())?;
    if approval.hooks != hooks {
        return Err(
            "plugin hook access changed; review it with `pentect plugins setup`".to_string(),
        );
    }
    Ok(())
}

fn read_optional_bounded(path: &Path, max: u64, label: &str) -> Result<Option<Vec<u8>>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    read_bounded_bytes(path, max, label).map(Some)
}

fn restore_optional_file(path: &Path, contents: Option<&[u8]>) -> Result<(), String> {
    let Some(contents) = contents else {
        if path.exists() {
            std::fs::remove_file(path).map_err(|error| {
                format!(
                    "could not remove rejected plugin file '{}': {error}",
                    path.display()
                )
            })?;
        }
        return Ok(());
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .or(Some(Path::new(".")))
        .ok_or_else(|| "plugin restore destination has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create plugin restore directory: {error}"))?;
    let staged = path.with_extension(format!("restore-{}", std::process::id()));
    std::fs::write(&staged, contents)
        .map_err(|error| format!("could not stage plugin restore: {error}"))?;
    replace_binary(&staged, path)
}

fn restore_plugin_binary_files(
    binary_path: &Path,
    binary: Option<&[u8]>,
    lock_path: &Path,
    lock: Option<&[u8]>,
) -> Result<(), String> {
    let binary = restore_optional_file(binary_path, binary);
    let lock = restore_optional_file(lock_path, lock);
    combine_rollback_results([("plugin binary", binary), ("plugin binary lock", lock)])
}

fn binary_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn binary_repository(
    source: &plugins::PluginSource,
    manifest: &PluginManifest,
) -> Result<String, String> {
    if let (Some(source_repository), Some(manifest_repository)) =
        (source.repository.as_deref(), manifest.repository.as_deref())
    {
        if !source_repository.eq_ignore_ascii_case(manifest_repository) {
            return Err(format!(
                "remote plugin repository mismatch: source is {source_repository}, manifest requests {manifest_repository}"
            ));
        }
    }
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

fn binary_asset(
    binary: &str,
    _runtime: PluginRuntime,
    overrides: &BTreeMap<String, String>,
) -> String {
    overrides
        .get("wasm32")
        .cloned()
        .unwrap_or_else(|| binary.to_string())
}

fn binary_destination(
    name: &str,
    binary: &str,
    _runtime: PluginRuntime,
    source: &plugins::PluginSource,
) -> Result<PathBuf, String> {
    validate_binary_name(binary, name)?;
    if !binary.to_ascii_lowercase().ends_with(".wasm") {
        return Err(format!("plugin '{name}' binary must end in .wasm"));
    }
    let dirs = plugin_runtime_dirs_for_source(name, source)?;
    Ok(dirs.data_dir.join("bin").join(binary))
}

fn install_release_binary(
    name: &str,
    source: &plugins::PluginSource,
    repository: &str,
    binary: &str,
    runtime: PluginRuntime,
    publisher_workflow: &str,
    overrides: &BTreeMap<String, String>,
) -> Result<(), String> {
    let platform = binary_platform();
    let asset = binary_asset(binary, runtime, overrides);
    let destination = binary_destination(name, binary, runtime, source)?;
    let download = update::download_latest_release_asset(repository, &asset, MAX_PLUGIN_WASM_BYTES)
        .map_err(|error| map_binary_download_error(name, &platform, &asset, error))?;
    reject_plugin_downgrade(name, source, &download.version)?;
    if destination.is_file() && sha256_path(&destination)? == download.sha256 {
        verify_github_attestation(&destination, repository, publisher_workflow, name)?;
        write_binary_lock(
            name,
            source,
            repository,
            publisher_workflow,
            &asset,
            &download,
        )?;
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
    if sha256_path(&staged)? != download.sha256 {
        let _ = std::fs::remove_file(&staged);
        return Err("staged plugin binary checksum mismatch".to_string());
    }
    if let Err(error) = verify_github_attestation(&staged, repository, publisher_workflow, name) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    replace_binary(&staged, &destination)?;
    write_binary_lock(
        name,
        source,
        repository,
        publisher_workflow,
        &asset,
        &download,
    )?;
    println!("binary {binary}: installed {}", download.version);
    Ok(())
}

fn verify_github_attestation(
    path: &Path,
    repository: &str,
    workflow: &str,
    name: &str,
) -> Result<(), String> {
    let gh = find_command(Path::new("gh")).ok_or_else(|| {
        "signed plugin verification requires GitHub CLI v2.51.0 or newer: https://cli.github.com/"
            .to_string()
    })?;
    verify_gh_attestation_version(&gh)?;
    let signer_workflow = format!("{repository}/{workflow}");
    let output = Command::new(gh)
        .arg("attestation")
        .arg("verify")
        .arg(path)
        .arg("--repo")
        .arg(repository)
        .arg("--signer-workflow")
        .arg(&signer_workflow)
        .arg("--deny-self-hosted-runners")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("could not run GitHub attestation verification: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    Err(if detail.is_empty() {
        format!("plugin '{name}' has no valid GitHub build attestation from {signer_workflow}")
    } else {
        format!("plugin '{name}' GitHub build attestation failed for {signer_workflow}: {detail}")
    })
}

fn verify_gh_attestation_version(gh: &Path) -> Result<(), String> {
    const MINIMUM: semver::Version = semver::Version::new(2, 51, 0);
    let output = Command::new(gh)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not inspect GitHub CLI version: {error}"))?;
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(2))
        .and_then(|version| semver::Version::parse(version.trim_start_matches('v')).ok())
        .ok_or_else(|| {
            "could not determine GitHub CLI version; v2.51.0 or newer is required".to_string()
        })?;
    if version < MINIMUM {
        return Err(format!(
            "GitHub CLI v{version} is too old; signed plugin verification requires v{MINIMUM} or newer"
        ));
    }
    Ok(())
}

fn map_binary_download_error(name: &str, platform: &str, asset: &str, error: String) -> String {
    if error.contains(&format!("missing asset '{asset}'")) {
        let _ = platform;
        format!("plugin '{name}' does not publish the portable WebAssembly asset '{asset}'")
    } else {
        error
    }
}

#[derive(Serialize)]
struct BinaryLock<'a> {
    schema: &'static str,
    repository: &'a str,
    publisher_workflow: &'a str,
    version: String,
    asset: &'a str,
    sha256: &'a str,
}

#[derive(Deserialize)]
struct StoredBinaryLock {
    schema: String,
    version: String,
}

fn reject_plugin_downgrade(
    name: &str,
    source: &plugins::PluginSource,
    candidate: &semver::Version,
) -> Result<(), String> {
    let path = plugin_runtime_dirs_for_source(name, source)?
        .data_dir
        .join(PLUGIN_BINARY_LOCK_FILE);
    if !path.is_file() {
        return Ok(());
    }
    let source = read_bounded_utf8(&path, MAX_PLUGIN_METADATA_BYTES, "plugin binary lock")?;
    let lock: StoredBinaryLock = toml::from_str(&source)
        .map_err(|_| "plugin binary lock is invalid; run setup again".to_string())?;
    let current = semver::Version::parse(&lock.version)
        .map_err(|_| "plugin binary lock has an invalid version; run setup again".to_string())?;
    if lock.schema != "pentect.plugin-lock.v1" {
        return Err("plugin binary lock has an unsupported schema; run setup again".to_string());
    }
    if candidate < &current {
        return Err(format!(
            "plugin update would downgrade {name} from {current} to {candidate}"
        ));
    }
    Ok(())
}

fn write_binary_lock(
    name: &str,
    plugin: &plugins::PluginSource,
    repository: &str,
    publisher_workflow: &str,
    asset: &str,
    download: &update::DownloadedReleaseAsset,
) -> Result<(), String> {
    let dirs = plugin_runtime_dirs_for_source(name, plugin)?;
    let lock = BinaryLock {
        schema: "pentect.plugin-lock.v1",
        repository,
        publisher_workflow,
        version: download.version.to_string(),
        asset,
        sha256: &download.sha256,
    };
    let source =
        toml::to_string(&lock).map_err(|e| format!("could not encode binary lock: {e}"))?;
    let destination = dirs.data_dir.join(PLUGIN_BINARY_LOCK_FILE);
    let temporary = dirs.data_dir.join(format!(
        "{PLUGIN_BINARY_LOCK_FILE}.tmp-{}",
        std::process::id()
    ));
    std::fs::write(&temporary, source)
        .map_err(|e| format!("could not write plugin binary lock: {e}"))?;
    if let Err(error) = replace_binary(&temporary, &destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn write_development_binary_lock(
    name: &str,
    plugin: &plugins::PluginSource,
    asset: &str,
    sha256: &str,
) -> Result<(), String> {
    let dirs = plugin_runtime_dirs_for_source(name, plugin)?;
    let lock = BinaryLock {
        schema: "pentect.plugin-lock.v1",
        repository: "local/development",
        publisher_workflow: "local/development.yml",
        version: "0.0.0".to_string(),
        asset,
        sha256,
    };
    let source =
        toml::to_string(&lock).map_err(|error| format!("could not encode binary lock: {error}"))?;
    let destination = dirs.data_dir.join(PLUGIN_BINARY_LOCK_FILE);
    let temporary = dirs.data_dir.join(format!(
        "{PLUGIN_BINARY_LOCK_FILE}.tmp-{}",
        std::process::id()
    ));
    std::fs::write(&temporary, source)
        .map_err(|error| format!("could not write plugin binary lock: {error}"))?;
    replace_binary(&temporary, &destination)
}

fn sha256_path(path: &Path) -> Result<String, String> {
    pentect_agent::sha256_file(path, "plugin file")
}

fn replace_binary(staged: &Path, destination: &Path) -> Result<(), String> {
    if !destination.exists() {
        return std::fs::rename(staged, destination)
            .map_err(|e| format!("could not install plugin data: {e}"));
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
            "could not replace plugin data '{}': {e}",
            destination.display()
        )
    })?;
    if let Err(error) = std::fs::rename(staged, destination) {
        let _ = std::fs::rename(&backup, destination);
        return Err(format!("could not install plugin data: {error}"));
    }
    std::fs::remove_file(&backup)
        .map_err(|error| format!("installed plugin data but could not remove backup: {error}"))?;
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

fn active_for_one(spec: &str) -> Result<plugins::ActivePlugins, String> {
    let specs = plugins::parse_plugin_value(spec).map_err(|e| e.to_string())?;
    plugins::active_from_selected_specs(specs, true).map_err(|e| e.to_string())
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
    if path.extension().and_then(|extension| extension.to_str()) == Some("wasm") {
        let bytes = match read_bounded_bytes(path, MAX_PLUGIN_WASM_BYTES, "WebAssembly plugin") {
            Ok(bytes) => bytes,
            Err(error) => return Check::fail("binary", error),
        };
        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("local-plugin");
        return match pentect_agent::test_local_wasm_plugin(&bytes, name) {
            Ok(run) => Check::ok("binary", format!("hooks-invoked={run}")),
            Err(error) => Check::fail("binary", error),
        };
    }
    let middleware = match pentect_agent::PluginMiddleware::from_paths([path.to_path_buf()]) {
        Ok(middleware) => middleware,
        Err(e) => return Check::fail("binary", e),
    };
    match middleware.test_hooks() {
        Ok(run) => Check::ok("binary", format!("hooks-invoked={run}")),
        Err(e) => Check::fail("binary", e),
    }
}

fn plugin_runtime_dirs(id_or_name: &str) -> Result<pentect_agent::PluginRuntimeDirs, String> {
    pentect_agent::plugin_runtime_dirs(id_or_name)
}

fn plugin_runtime_dirs_for_source(
    name: &str,
    source: &plugins::PluginSource,
) -> Result<pentect_agent::PluginRuntimeDirs, String> {
    if source.scope == plugins::PluginScope::User {
        return pentect_agent::global_plugin_runtime_dirs(&source.runtime_id);
    }
    match source.manifest_path.as_deref() {
        Some(manifest) => pentect_agent::plugin_runtime_dirs_for_manifest(name, manifest),
        None => plugin_runtime_dirs(name),
    }
}

#[derive(Debug)]
struct PluginRow {
    name: String,
    source: String,
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
            source: source.to_string(),
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

fn find_command(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() && path.is_file() {
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
        if !dir.is_absolute() {
            continue;
        }
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
    fn windows_command_plugins_accept_batch_shims_only() {
        for extension in [".EXE", "com", ".CMD", "bat"] {
            assert!(windows_command_extension_supported(extension));
        }
        for extension in ["ps1", ".js", "sh", ""] {
            assert!(!windows_command_extension_supported(extension));
        }
    }

    fn python_test_executable() -> Option<&'static str> {
        ["python3", "python"].into_iter().find(|candidate| {
            std::process::Command::new(candidate)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        })
    }

    #[test]
    fn parses_list() {
        let args = vec!["pentect".into(), "plugins".into(), "list".into()];
        assert!(matches!(
            PluginCmd::parse(&args).unwrap().action,
            Action::List
        ));
    }

    #[test]
    fn parses_plugin_author_commands() {
        for (command, expected) in [("new", "new"), ("dev", "dev"), ("publish", "publish")] {
            let args = vec![
                "pentect".into(),
                "plugins".into(),
                command.into(),
                "example-plugin".into(),
            ];
            let action = PluginCmd::parse(&args).unwrap().action;
            assert!(matches!(
                (expected, action),
                ("new", Action::New { .. })
                    | ("dev", Action::Dev { .. })
                    | ("publish", Action::Publish { .. })
            ));
        }
        assert!(validate_new_plugin_name("safe-plugin-2").is_ok());
        assert!(validate_new_plugin_name("../escape").is_err());
        assert!(validate_new_plugin_name("double--hyphen").is_err());

        let dev = vec![
            "pentect".into(),
            "plugins".into(),
            "dev".into(),
            "example-plugin".into(),
            "--yes".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&dev).unwrap().action,
            Action::Dev { approved: true, .. }
        ));

        for form in ["manifest", "wasm", "command"] {
            let args = vec![
                "pentect".into(),
                "plugins".into(),
                "new".into(),
                "example-plugin".into(),
                form.into(),
            ];
            assert!(matches!(
                PluginCmd::parse(&args).unwrap().action,
                Action::New { form: Some(_), .. }
            ));
        }
        assert!(NewPluginForm::parse("native").is_err());
    }

    #[test]
    fn generated_plugin_steps_match_each_runtime() {
        assert_eq!(
            new_plugin_next_steps(NewPluginForm::Manifest),
            "pentect plugins test .\npentect plugins add ."
        );
        assert_eq!(
            new_plugin_next_steps(NewPluginForm::Wasm),
            "pentect plugins dev .\npentect plugins test ."
        );
        assert_eq!(
            new_plugin_next_steps(NewPluginForm::Command),
            "pentect plugins setup .\npentect plugins test ."
        );
    }

    #[test]
    fn wasm_template_bridges_cargo_and_release_artifact_names() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pentect-wasm-template-{nonce}"));
        std::fs::create_dir_all(&root).unwrap();
        write_wasm_plugin_template(&root, "my-test-plugin", "my_test_plugin").unwrap();

        let manifest = std::fs::read_to_string(root.join("plugin.toml")).unwrap();
        let workflow = std::fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
        assert!(manifest.contains("wasm = \"my-test-plugin.wasm\""));
        assert!(workflow.contains(
            "cp target/wasm32-unknown-unknown/release/my_test_plugin.wasm my-test-plugin.wasm"
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn command_template_uses_the_common_jsonl_envelope() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pentect-command-template-{nonce}"));
        std::fs::create_dir_all(&root).unwrap();
        write_command_plugin_template(&root, "example-plugin").unwrap();
        let manifest = std::fs::read_to_string(root.join("plugin.toml")).unwrap();
        let server = std::fs::read_to_string(root.join("server.py")).unwrap();
        assert!(manifest.contains("[commands]"));
        assert!(manifest.contains("windows = [\"py\", \"{plugin}/server.py\"]"));
        assert!(manifest.contains("linux = [\"python3\", \"{plugin}/server.py\"]"));
        assert!(manifest.contains("hooks = [\"inspect\"]"));
        assert!(server.contains("request.get(\"payload\", {})"));
        assert!(server.contains("\"schema\": \"pentect.plugin.v1\""));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn project_plugin_edit_preserves_unrelated_config_and_comments() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-project-plugin-config-{}-{nonce}",
            std::process::id(),
        ));
        let path = root.join("config.toml");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &path,
            "# keep this comment\nplugins = [\"first\"]\nmode = \"stable\" # and this one\n",
        )
        .unwrap();

        update_project_plugins_at(&path, "second", true, plugins::PluginScope::Project).unwrap();
        let after_add = std::fs::read_to_string(&path).unwrap();
        assert!(after_add.contains("# keep this comment"), "{after_add}");
        assert!(after_add.contains("# and this one"), "{after_add}");
        assert!(after_add.contains("mode = \"stable\""), "{after_add}");
        assert!(after_add.contains("\"first\""), "{after_add}");
        assert!(after_add.contains("\"second\""), "{after_add}");

        update_project_plugins_at(&path, "first", false, plugins::PluginScope::Project).unwrap();
        let after_remove = std::fs::read_to_string(&path).unwrap();
        assert!(!after_remove.contains("\"first\""), "{after_remove}");
        assert!(after_remove.contains("\"second\""), "{after_remove}");
        assert!(
            after_remove.contains("# keep this comment"),
            "{after_remove}"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn project_plugin_config_and_lock_restore_together() {
        let root = std::env::temp_dir().join(format!(
            "pentect-project-plugin-rollback-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let lock = root.join("pentect.plugins.lock");
        std::fs::write(&config, "plugins = [\"old\"]\n").unwrap();
        std::fs::write(&lock, "schema = \"old\"\n").unwrap();
        let snapshot = snapshot_project_plugin_files_at(&config, &lock).unwrap();

        std::fs::write(&config, "plugins = [\"new\"]\n").unwrap();
        std::fs::remove_file(&lock).unwrap();
        restore_project_plugin_files_at(&snapshot, &config, &lock).unwrap();

        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "plugins = [\"old\"]\n"
        );
        assert_eq!(
            std::fs::read_to_string(&lock).unwrap(),
            "schema = \"old\"\n"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parses_add_and_remove() {
        let add = vec![
            "pentect".into(),
            "plugins".into(),
            "add".into(),
            "company-policy".into(),
            "--yes".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&add).unwrap().action,
            Action::Add {
                approved: true,
                scope: plugins::PluginScope::User,
                ..
            }
        ));
        let mut project_add = add.clone();
        project_add.push("--project".into());
        assert!(matches!(
            PluginCmd::parse(&project_add).unwrap().action,
            Action::Add {
                scope: plugins::PluginScope::Project,
                ..
            }
        ));
        let remove = vec![
            "pentect".into(),
            "plugins".into(),
            "remove".into(),
            "company-policy".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&remove).unwrap().action,
            Action::Remove {
                scope: plugins::PluginScope::User,
                ..
            }
        ));
        let invalid = vec![
            "pentect".into(),
            "plugins".into(),
            "list".into(),
            "--project".into(),
        ];
        assert!(PluginCmd::parse(&invalid).is_err());
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
            "example-plugin".into(),
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
            "example-plugin".into(),
            "--yes".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&args).unwrap().action,
            Action::Setup { approved: true, .. }
        ));

        let args = vec![
            "pentect".into(),
            "plugins".into(),
            "setup".into(),
            "example-plugin".into(),
            "--profile".into(),
            "cuda".into(),
            "--yes".into(),
        ];
        assert!(matches!(
            PluginCmd::parse(&args).unwrap().action,
            Action::Setup {
                approved: true,
                profile: Some(profile),
                ..
            } if profile == "cuda"
        ));

        let args = vec![
            "pentect".into(),
            "plugins".into(),
            "update".into(),
            "example-plugin".into(),
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
    fn postscripts_are_rejected() {
        let root =
            std::env::temp_dir().join(format!("pentect-plugin-postscript-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("plugin.toml"),
            "schema = \"pentect.plugin.v1\"\nname = \"unsafe\"\n[[postscript]]\ncommand = [\"tool\"]\n",
        )
        .unwrap();
        let source = plugins::plugin_source(&root.to_string_lossy()).unwrap();
        let error = load_plugin_manifest(&source).unwrap_err();
        let _ = std::fs::remove_dir_all(root);
        assert!(error.contains("postscripts are not supported"), "{error}");
    }

    #[test]
    fn plugin_forms_are_inferred_and_ambiguous_manifests_are_rejected() {
        let manifest: PluginManifest =
            toml::from_str("schema = \"pentect.plugin.v1\"\n[[detector]]\npattern = \"x\"\n")
                .unwrap();
        assert_eq!(manifest.form().unwrap(), PluginRuntime::Manifest);

        let wasm: PluginManifest =
            toml::from_str("schema = \"pentect.plugin.v1\"\nwasm = \"plugin.wasm\"\n").unwrap();
        assert_eq!(wasm.form().unwrap(), PluginRuntime::Wasm);

        let legacy: PluginManifest =
            toml::from_str("schema = \"pentect.plugin.v1\"\nbinary = \"plugin.wasm\"\n").unwrap();
        assert_eq!(legacy.form().unwrap(), PluginRuntime::Wasm);

        let command: PluginManifest = toml::from_str(
            "schema = \"pentect.plugin.v1\"\ncommand = [\"python\", \"plugin.py\"]\nhooks = [\"inspect\"]\n",
        )
        .unwrap();
        assert_eq!(command.form().unwrap(), PluginRuntime::Command);
        validate_command(&command).unwrap();

        let platform_command: PluginManifest = toml::from_str(
            "schema = \"pentect.plugin.v1\"\nhooks = [\"inspect\"]\n[commands]\nwindows = [\"py\", \"plugin.py\"]\nmacos = [\"python3\", \"plugin.py\"]\nlinux = [\"python3\", \"plugin.py\"]\n",
        )
        .unwrap();
        assert_eq!(platform_command.form().unwrap(), PluginRuntime::Command);
        validate_command(&platform_command).unwrap();
        assert!(platform_command.selected_command().unwrap().is_some());

        let duplicate_command: PluginManifest = toml::from_str(
            "schema = \"pentect.plugin.v1\"\ncommand = [\"python\"]\n[commands]\nlinux = [\"python3\"]\n",
        )
        .unwrap();
        assert!(duplicate_command.form().is_err());

        let ambiguous: PluginManifest = toml::from_str(
            "schema = \"pentect.plugin.v1\"\nwasm = \"plugin.wasm\"\ncommand = [\"tool\"]\nhooks = [\"inspect\"]\n",
        )
        .unwrap();
        assert!(ambiguous.form().is_err());
    }

    #[test]
    fn approved_command_setup_runs_selected_profile_and_is_locked() {
        let Some(python) = python_test_executable() else {
            return;
        };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("command-setup-{nonce}");
        let root = std::env::temp_dir().join(&name);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("server.py"), "print('unused')\n").unwrap();
        std::fs::write(
            root.join("setup.py"),
            "import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser();p.add_argument('--profile');a=p.parse_args();Path(__file__).with_name('selected.txt').write_text(a.profile)\n",
        )
        .unwrap();
        std::fs::write(
            root.join(plugins::PLUGIN_MANIFEST_FILE),
            format!(
                "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\ncommand = [\"{python}\", \"{{plugin}}/server.py\"]\nhooks = [\"inspect\"]\n[setup]\ncommand = [\"{python}\", \"{{plugin}}/setup.py\"]\nprofiles = [\"cpu\", \"cuda\"]\nprofile_arg = \"--profile\"\ndownload = \"fixture\"\ndisk = \"fixture\"\n"
            ),
        )
        .unwrap();
        let source = plugins::plugin_source(&root.to_string_lossy()).unwrap();
        let runtime = plugin_runtime_dirs_for_source(&name, &source).unwrap();

        setup_plugin_source(source, true, Some("cpu"), false).unwrap();

        assert_eq!(
            std::fs::read_to_string(root.join("selected.txt")).unwrap(),
            "cpu"
        );
        let lock =
            std::fs::read_to_string(runtime.data_dir.join(PLUGIN_COMMAND_LOCK_FILE)).unwrap();
        assert!(lock.contains("path = \"setup.py\""), "{lock}");
        let _ = std::fs::remove_dir_all(runtime.data_dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn wasm_permissions_use_compact_explicit_scopes() {
        let permissions: PermissionsConfig = toml::from_str(
            r#"
                read = ["project:config/**", "plugin:model.json"]
                write = ["project:generated/result.json"]
                env = ["POLICY_URL"]
                run = [["git", "status", "--porcelain"]]
                storage = true
            "#,
        )
        .unwrap();
        validate_permissions(Some(&permissions)).unwrap();

        let traversal: PermissionsConfig =
            toml::from_str(r#"read = ["project:../secret"]"#).unwrap();
        assert!(validate_permissions(Some(&traversal)).is_err());
        let broad_glob: PermissionsConfig =
            toml::from_str(r#"read = ["project:**/*.env"]"#).unwrap();
        assert!(validate_permissions(Some(&broad_glob)).is_err());
    }

    #[test]
    fn local_command_files_are_hashed_into_the_runtime_lock() {
        let Some(python) = python_test_executable() else {
            return;
        };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("command-lock-{nonce}");
        let root = std::env::temp_dir().join(&name);
        std::fs::create_dir_all(&root).unwrap();
        let manifest_path = root.join(plugins::PLUGIN_MANIFEST_FILE);
        std::fs::write(
            &manifest_path,
            format!(
                "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\ncommand = [\"{python}\", \"{{plugin}}/server.py\"]\nhooks = [\"inspect\"]\n"
            ),
        )
        .unwrap();
        let script = root.join("server.py");
        std::fs::write(&script, "print('first')\n").unwrap();
        let source = plugins::PluginSource {
            name: name.clone(),
            manifest_path: Some(manifest_path),
            repository: None,
            remote_base: None,
            scope: plugins::PluginScope::Project,
            runtime_id: name.clone(),
        };
        let manifest = load_plugin_manifest(&source).unwrap().unwrap();
        write_command_lock(&name, &source, &manifest).unwrap();
        let dirs = plugin_runtime_dirs_for_source(&name, &source).unwrap();
        let first = std::fs::read_to_string(dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE)).unwrap();
        assert!(first.contains("path = \"server.py\""));

        std::fs::write(&script, "print('second')\n").unwrap();
        write_command_lock(&name, &source, &manifest).unwrap();
        let second = std::fs::read_to_string(dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE)).unwrap();
        assert_ne!(first, second);
        let _ = std::fs::remove_dir_all(dirs.data_dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn command_runtime_snapshot_restores_only_managed_state() {
        let Some(python) = python_test_executable() else {
            return;
        };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("command-rollback-{nonce}");
        let root = std::env::temp_dir().join(&name);
        std::fs::create_dir_all(&root).unwrap();
        let manifest_path = root.join(plugins::PLUGIN_MANIFEST_FILE);
        std::fs::write(
            &manifest_path,
            format!(
                "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\ncommand = [\"{python}\", \"{{plugin}}/server.py\"]\nhooks = [\"inspect\"]\n"
            ),
        )
        .unwrap();
        let source = plugins::PluginSource {
            name: name.clone(),
            manifest_path: Some(manifest_path),
            repository: None,
            remote_base: None,
            scope: plugins::PluginScope::Project,
            runtime_id: name.clone(),
        };
        let dirs = plugin_runtime_dirs_for_source(&name, &source).unwrap();
        std::fs::create_dir_all(dirs.data_dir.join("command")).unwrap();
        std::fs::write(dirs.data_dir.join("command/server.py"), "old").unwrap();
        std::fs::write(dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE), "old-lock").unwrap();
        std::fs::write(dirs.data_dir.join(PLUGIN_APPROVAL_FILE), "old-approval").unwrap();

        let snapshot = snapshot_command_runtime(&name, &source).unwrap();
        std::fs::write(dirs.data_dir.join("command/server.py"), "new").unwrap();
        std::fs::write(dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE), "new-lock").unwrap();
        std::fs::write(dirs.data_dir.join(PLUGIN_APPROVAL_FILE), "new-approval").unwrap();
        snapshot.restore().unwrap();

        assert_eq!(
            std::fs::read_to_string(dirs.data_dir.join("command/server.py")).unwrap(),
            "old"
        );
        assert_eq!(
            std::fs::read_to_string(dirs.data_dir.join(PLUGIN_COMMAND_LOCK_FILE)).unwrap(),
            "old-lock"
        );
        assert_eq!(
            std::fs::read_to_string(dirs.data_dir.join(PLUGIN_APPROVAL_FILE)).unwrap(),
            "old-approval"
        );
        let _ = std::fs::remove_dir_all(dirs.data_dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn network_access_requires_explicit_safe_scope() {
        let valid: PluginManifest = toml::from_str(
            r#"
                schema = "pentect.plugin.v1"
                [network]
                allow = ["https://api.example.com"]
                methods = ["get", "POST"]
            "#,
        )
        .unwrap();
        validate_network(&valid).unwrap();

        let path: PluginManifest = toml::from_str(
            r#"
                schema = "pentect.plugin.v1"
                [network]
                allow = ["https://api.example.com/private"]
                methods = ["GET"]
            "#,
        )
        .unwrap();
        assert!(validate_network(&path).is_err());

        let insecure: PluginManifest = toml::from_str(
            r#"
                schema = "pentect.plugin.v1"
                [network]
                allow = ["http://127.0.0.1:8080"]
                methods = ["GET"]
                private_network = true
            "#,
        )
        .unwrap();
        assert!(validate_network(&insecure).is_err());
    }

    #[test]
    fn release_binary_is_portable_wasm_with_optional_override() {
        let root =
            std::env::temp_dir().join(format!("pentect-plugin-destination-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let manifest = root.join(plugins::PLUGIN_MANIFEST_FILE);
        std::fs::write(&manifest, "schema = \"pentect.plugin.v1\"\n").unwrap();
        let source = plugins::PluginSource {
            name: "test".to_string(),
            manifest_path: Some(manifest),
            repository: None,
            remote_base: None,
            scope: plugins::PluginScope::Project,
            runtime_id: "test".to_string(),
        };
        assert_eq!(
            binary_asset("helper.wasm", PluginRuntime::Wasm, &BTreeMap::new()),
            "helper.wasm"
        );
        let overrides = BTreeMap::from([("wasm32".to_string(), "custom.wasm".to_string())]);
        assert_eq!(
            binary_asset("helper.wasm", PluginRuntime::Wasm, &overrides),
            "custom.wasm"
        );
        assert!(
            binary_destination("test", "../outside.wasm", PluginRuntime::Wasm, &source).is_err()
        );
        assert!(binary_destination("test", "helper", PluginRuntime::Wasm, &source).is_err());
        assert!(
            binary_destination("test", "helper.wasm", PluginRuntime::Wasm, &source)
                .unwrap()
                .is_absolute()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_wasm_binary_is_reported_as_unsupported() {
        let error = map_binary_download_error(
            "policy",
            "windows-x86_64",
            "policy.wasm",
            "release is missing asset 'policy.wasm'".to_string(),
        );
        assert_eq!(
            error,
            "plugin 'policy' does not publish the portable WebAssembly asset 'policy.wasm'"
        );

        let checksum_error = "release is missing checksum asset".to_string();
        assert_eq!(
            map_binary_download_error("policy", "linux-x86_64", "binary", checksum_error.clone()),
            checksum_error
        );
    }

    #[test]
    fn binary_lock_records_the_resolved_release() {
        let lock = BinaryLock {
            schema: "pentect.plugin-lock.v1",
            repository: "owner/repo",
            publisher_workflow: ".github/workflows/release.yml",
            version: "v1.2.3".to_string(),
            asset: "helper-linux-x86_64",
            sha256: "0123456789abcdef",
        };
        let encoded = toml::to_string(&lock).unwrap();
        let decoded: toml::Value = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded["repository"].as_str(), Some("owner/repo"));
        assert_eq!(
            decoded["publisher_workflow"].as_str(),
            Some(".github/workflows/release.yml")
        );
        assert_eq!(decoded["version"].as_str(), Some("v1.2.3"));
        assert_eq!(decoded["asset"].as_str(), Some("helper-linux-x86_64"));
        assert_eq!(decoded["sha256"].as_str(), Some("0123456789abcdef"));
    }

    #[test]
    fn detector_diff_tracks_label_category_confidence_and_rule() {
        let before = detector_descriptors(
            br#"[[detector]]
pattern = "old-[0-9]+"
label = "ACCOUNT_ID"
category = "pii"
confidence = "high"
"#,
        )
        .unwrap();
        let after = detector_descriptors(
            br#"[[detector]]
pattern = "new-[0-9]+"
label = "ACCOUNT_ID"
category = "pii"
confidence = "high"
"#,
        )
        .unwrap();
        assert_ne!(before, after);
        let item = after.iter().next().unwrap();
        assert_eq!(item.label, "ACCOUNT_ID");
        assert_eq!(item.category, "pii");
        assert_eq!(item.confidence, "high");
        assert_eq!(item.rule_sha256.len(), 64);
        let summary = detector_summary(item);
        assert!(summary.contains(&format!("rule={}", &item.rule_sha256[..16])));
        assert!(!summary.contains(&item.rule_sha256));
    }

    #[test]
    fn detector_digest_is_stable_when_toml_keys_are_reordered() {
        let first = detector_descriptors(
            br#"[[detector]]
pattern = "token-[0-9]+"
label = "TOKEN"
category = "secret"
confidence = "high"
"#,
        )
        .unwrap();
        let reordered = detector_descriptors(
            br#"[[detector]]
confidence = "high"
category = "secret"
label = "TOKEN"
pattern = "token-[0-9]+"
"#,
        )
        .unwrap();
        assert_eq!(first, reordered);
    }

    #[test]
    fn detector_changes_require_confirmation_before_plugin_kind_is_selected() {
        assert!(detector_update_requires_confirmation(true, false));
        assert!(!detector_update_requires_confirmation(true, true));
        assert!(!detector_update_requires_confirmation(false, false));
    }

    #[test]
    fn project_restore_attempts_lock_even_when_config_restore_fails() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-plugin-rollback-both-{}-{nonce}",
            std::process::id()
        ));
        let config = root.join("config.toml");
        let lock = root.join("pentect.plugins.lock");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(&lock, b"new lock").unwrap();
        let snapshot = ProjectPluginFiles {
            config: Some(b"old config".to_vec()),
            lock: Some(b"old lock".to_vec()),
        };
        let error = restore_project_plugin_files_at(&snapshot, &config, &lock).unwrap_err();
        assert!(error.contains("project config"));
        assert_eq!(std::fs::read(&lock).unwrap(), b"old lock");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn binary_restore_attempts_lock_and_keeps_the_original_error() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "pentect-plugin-binary-rollback-both-{}-{nonce}",
            std::process::id()
        ));
        let binary = root.join("plugin.wasm");
        let lock = root.join("binary.lock");
        std::fs::create_dir_all(&binary).unwrap();
        std::fs::write(&lock, b"new lock").unwrap();
        let rollback =
            restore_plugin_binary_files(&binary, Some(b"old binary"), &lock, Some(b"old lock"));
        let error = attach_rollback_error("original failure".to_string(), rollback);
        assert!(error.starts_with("original failure; rollback failed:"));
        assert!(error.contains("plugin binary"));
        assert_eq!(std::fs::read(&lock).unwrap(), b"old lock");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_update_requires_the_exact_approved_manifest() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("update-approval-{nonce}");
        let root = std::env::temp_dir().join(&name);
        std::fs::create_dir_all(&root).unwrap();
        let manifest_path = root.join(plugins::PLUGIN_MANIFEST_FILE);
        let manifest_source = format!(
            "schema = \"pentect.plugin.v1\"\nname = \"{name}\"\nbinary = \"helper.wasm\"\nrepository = \"owner/repo\"\n[publisher]\nworkflow = \".github/workflows/release.yml\"\n"
        );
        std::fs::write(&manifest_path, &manifest_source).unwrap();
        let source = plugins::PluginSource {
            name: name.clone(),
            manifest_path: Some(manifest_path.clone()),
            repository: None,
            remote_base: None,
            scope: plugins::PluginScope::Project,
            runtime_id: name.clone(),
        };
        let manifest = load_plugin_manifest(&source).unwrap().unwrap();
        let hooks = vec!["inspect".to_string()];
        let data_dir = plugin_runtime_dirs_for_source(&name, &source)
            .unwrap()
            .data_dir;
        std::fs::create_dir_all(data_dir.join("bin")).unwrap();
        let wasm = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "pentect_alloc") (param i32) (result i32) i32.const 0)
                (func (export "pentect_inspect") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        std::fs::write(data_dir.join("bin/helper.wasm"), wasm).unwrap();
        write_plugin_approval(&name, &source, &manifest, &hooks).unwrap();
        verify_plugin_update_approval(&name, &source, &manifest).unwrap();

        std::fs::write(
            &manifest_path,
            manifest_source.replace("owner/repo", "other/repo"),
        )
        .unwrap();
        let changed = load_plugin_manifest(&source).unwrap().unwrap();
        assert!(verify_plugin_update_approval(&name, &source, &changed).is_err());

        let data_dir = plugin_runtime_dirs_for_source(&name, &source)
            .unwrap()
            .data_dir;
        let _ = std::fs::remove_dir_all(data_dir);
        let _ = std::fs::remove_dir_all(root);
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
    fn list_plugins_includes_official_plugins() {
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

        assert!(names.contains("example-regex"), "{names:?}");
        assert!(names.contains("openai-privacy-filter"), "{names:?}");
        assert!(!names.contains("pii-ner"), "{names:?}");
    }

    #[test]
    fn local_binary_requires_repository() {
        let root =
            std::env::temp_dir().join(format!("pentect-local-binary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(plugins::PLUGIN_MANIFEST_FILE),
            "schema = \"pentect.plugin.v1\"\nname = \"local\"\nbinary = \"tool.wasm\"\n[publisher]\nworkflow = \".github/workflows/release.yml\"\n",
        )
        .unwrap();

        let source = plugins::PluginSource {
            name: "local".to_string(),
            manifest_path: Some(root.join(plugins::PLUGIN_MANIFEST_FILE)),
            repository: None,
            remote_base: None,
            scope: plugins::PluginScope::Project,
            runtime_id: "local".to_string(),
        };
        let manifest = load_plugin_manifest(&source).unwrap().unwrap();
        let err = binary_repository(&source, &manifest).unwrap_err();
        assert!(err.contains("require repository"), "{err}");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_binary_cannot_redirect_to_another_repository() {
        let source = plugins::PluginSource {
            name: "remote".to_string(),
            manifest_path: None,
            repository: Some("trusted/owner".to_string()),
            remote_base: None,
            scope: plugins::PluginScope::Project,
            runtime_id: "remote".to_string(),
        };
        let manifest: PluginManifest = toml::from_str(
            "schema = \"pentect.plugin.v1\"\nname = \"remote\"\nrepository = \"attacker/repo\"\n",
        )
        .unwrap();

        let error = binary_repository(&source, &manifest).unwrap_err();
        assert!(error.contains("repository mismatch"), "{error}");
    }

    #[test]
    fn plugin_update_rejects_release_downgrades() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("downgrade-{nonce}");
        let root = std::env::temp_dir().join(&name);
        std::fs::create_dir_all(&root).unwrap();
        let manifest = root.join(plugins::PLUGIN_MANIFEST_FILE);
        std::fs::write(&manifest, "schema = \"pentect.plugin.v1\"\n").unwrap();
        let source = plugins::PluginSource {
            name: name.clone(),
            manifest_path: Some(manifest),
            repository: None,
            remote_base: None,
            scope: plugins::PluginScope::Project,
            runtime_id: name.clone(),
        };
        let data_dir = plugin_runtime_dirs_for_source(&name, &source)
            .unwrap()
            .data_dir;
        std::fs::write(
            data_dir.join(PLUGIN_BINARY_LOCK_FILE),
            "schema = \"pentect.plugin-lock.v1\"\nversion = \"2.0.0\"\n",
        )
        .unwrap();

        assert!(reject_plugin_downgrade(&name, &source, &semver::Version::new(1, 9, 9)).is_err());
        assert!(reject_plugin_downgrade(&name, &source, &semver::Version::new(2, 0, 0)).is_ok());
        assert!(reject_plugin_downgrade(&name, &source, &semver::Version::new(2, 1, 0)).is_ok());

        let _ = std::fs::remove_dir_all(data_dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn credential_like_environment_permissions_are_highlighted() {
        let names = vec![
            "PATH".to_string(),
            "OPENAI_API_KEY".to_string(),
            "GITHUB_TOKEN".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "DATABASE_PASSWORD".to_string(),
            "PUBLIC_ENDPOINT".to_string(),
        ];
        assert_eq!(
            sensitive_env_permissions(&names),
            [
                "OPENAI_API_KEY",
                "GITHUB_TOKEN",
                "AWS_SECRET_ACCESS_KEY",
                "DATABASE_PASSWORD"
            ]
        );
    }
}
