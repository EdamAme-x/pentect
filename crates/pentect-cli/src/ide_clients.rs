//! Launchers for editor and editor-adjacent clients with documented,
//! short-lived configuration surfaces.
//!
//! None of these launchers edits the user's normal configuration. Continue
//! receives a one-shot config file, Cline receives an isolated provider
//! registry, Roo imports into an isolated VS Code profile, and Zed receives an
//! isolated user-data directory.

use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_MODEL: &str = "gpt-5";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdeClient {
    Continue,
    Cline,
    Roo,
    Zed,
}

pub(crate) fn run(
    client: IdeClient,
    opts: &crate::AgentToolOpts,
    pentect: &Path,
) -> Result<std::process::ExitStatus, String> {
    let upstream = opts
        .upstream
        .clone()
        .or_else(|| nonempty_env("OPENAI_BASE_URL"))
        .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
    let (args, model) = sanitized_args(client, &opts.tool_args, opts.model.as_deref())?;

    if opts.dry_run {
        let mut shown = args;
        shown.extend(dry_run_suffix(client, &model));
        crate::print_dry_run(&opts.command, &shown);
        return Ok(crate::success_status());
    }
    if client == IdeClient::Roo {
        ensure_vscode_extension(&opts.command, "RooVeterinaryInc.roo-cline", "Roo Code")?;
    }

    let active_plugins = crate::agent_tool_plugins(opts)?;
    let memory_store = crate::start_memory_store(pentect)?;
    let _parent_env = crate::agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    let standard_key_names = if has_authorization_override(&opts.upstream_header_env) {
        &[][..]
    } else {
        &["OPENAI_API_KEY"][..]
    };
    let _authorization = crate::upstream_bearer_guard(standard_key_names);
    let proxy = crate::openai_http_proxy::OpenAiHttpProxyGuard::start_with_header_env(
        upstream,
        &opts.upstream_header_env,
    )?;
    let gateway_key = "pentect-local";

    let mut command = Command::new(&opts.command);
    crate::clear_pentect_control_env(&mut command);
    crate::upstream::hide_header_source_env(&mut command, &opts.upstream_header_env);
    // The gateway owns the upstream credential. Clients authenticate to the
    // loopback gateway with a non-secret placeholder and must not inherit the
    // real OpenAI key into agent tools or extensions.
    command.env_remove("OPENAI_API_KEY");
    crate::apply_plugin_env(&mut command, &active_plugins)?;
    crate::apply_pentect_env(&mut command, pentect, Some(memory_store.token.as_str()))?;
    crate::apply_memory_store_env(&mut command, Some(&memory_store));

    match client {
        IdeClient::Continue => {
            let contents = continue_config(proxy.base_url(), &model)?;
            let config = crate::secure_temp::SecureTempFile::create(
                &std::env::temp_dir(),
                ".pentect-continue-",
                ".yaml",
                contents.as_bytes(),
                "Continue config",
            )?;
            command.env("PENTECT_GATEWAY_API_KEY", gateway_key);
            command.args(args);
            command.arg("--config").arg(config.path());
            crate::run_native_command_with_guards(
                command,
                &opts.command,
                (proxy, memory_store, config),
            )
        }
        IdeClient::Cline => {
            let contents = cline_provider_config(proxy.base_url(), &model, gateway_key)?;
            let providers = crate::secure_temp::SecureTempFile::create(
                &std::env::temp_dir(),
                ".pentect-cline-providers-",
                ".json",
                contents.as_bytes(),
                "Cline provider registry",
            )?;
            let data = EphemeralDirectory::create("cline")?;
            command.env("CLINE_PROVIDER_SETTINGS_PATH", providers.path());
            command.env("CLINE_DATA_DIR", data.path());
            command.args(args);
            command.arg("--data-dir").arg(data.path()).args([
                "--provider",
                "pentect",
                "--model",
                &model,
            ]);
            crate::run_native_command_with_guards(
                command,
                &opts.command,
                (proxy, memory_store, providers, data),
            )
        }
        IdeClient::Roo => {
            let import = roo_import_config(proxy.base_url(), &model, gateway_key)?;
            let import = crate::secure_temp::SecureTempFile::create(
                &std::env::temp_dir(),
                ".pentect-roo-import-",
                ".json",
                import.as_bytes(),
                "Roo settings import",
            )?;
            let data = EphemeralDirectory::create("roo-vscode")?;
            let user = data.path().join("User");
            std::fs::create_dir_all(&user)
                .map_err(|error| format!("could not create isolated VS Code profile: {error}"))?;
            write_owner_only(
                &user.join("settings.json"),
                serde_json::to_string_pretty(&json!({
                    "roo-cline.autoImportSettingsPath": import.path()
                }))
                .map_err(|error| format!("could not encode Roo VS Code settings: {error}"))?
                .as_bytes(),
                "Roo VS Code settings",
            )?;
            command.args(args);
            command
                .arg("--new-window")
                .arg("--wait")
                .arg("--user-data-dir")
                .arg(data.path())
                .arg(".");
            crate::run_native_command_with_guards(
                command,
                &opts.command,
                (proxy, memory_store, import, data),
            )
        }
        IdeClient::Zed => {
            let data = EphemeralDirectory::create("zed")?;
            let config = data.path().join("config");
            std::fs::create_dir_all(&config)
                .map_err(|error| format!("could not create isolated Zed config: {error}"))?;
            write_owner_only(
                &config.join("settings.json"),
                zed_settings(proxy.base_url(), &model)?.as_bytes(),
                "Zed settings",
            )?;
            command.env("PENTECT_API_KEY", gateway_key);
            command.args(args);
            command
                .arg("--foreground")
                .arg("--user-data-dir")
                .arg(data.path());
            crate::run_native_command_with_guards(
                command,
                &opts.command,
                (proxy, memory_store, data),
            )
        }
    }
}

fn ensure_vscode_extension(command: &Path, id: &str, display_name: &str) -> Result<(), String> {
    let output = Command::new(command)
        .arg("--list-extensions")
        .output()
        .map_err(|error| format!("could not inspect {display_name} installation: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not inspect {display_name} installation with {} --list-extensions",
            command.display()
        ));
    }
    let installed = String::from_utf8_lossy(&output.stdout);
    if installed
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case(id))
    {
        Ok(())
    } else {
        Err(format!(
            "{display_name} is not installed for {}; install extension {id} first",
            command.display()
        ))
    }
}

fn dry_run_suffix(client: IdeClient, model: &str) -> Vec<String> {
    match client {
        IdeClient::Continue => vec!["--config".into(), "<pentect-config>".into()],
        IdeClient::Cline => vec![
            "--data-dir".into(),
            "<pentect-data>".into(),
            "--provider".into(),
            "pentect".into(),
            "--model".into(),
            model.into(),
        ],
        IdeClient::Roo => vec![
            "--new-window".into(),
            "--wait".into(),
            "--user-data-dir".into(),
            "<pentect-profile>".into(),
            ".".into(),
        ],
        IdeClient::Zed => vec![
            "--foreground".into(),
            "--user-data-dir".into(),
            "<pentect-data>".into(),
        ],
    }
}

fn sanitized_args(
    client: IdeClient,
    args: &[String],
    explicit_model: Option<&str>,
) -> Result<(Vec<String>, String), String> {
    if client == IdeClient::Cline
        && args.first().is_some_and(|arg| {
            matches!(
                arg.as_str(),
                "auth" | "config" | "connect" | "hub" | "update" | "kanban"
            )
        })
    {
        return Err(
            "Cline management commands are not model requests; run them outside `pentect cline`"
                .to_string(),
        );
    }
    if client == IdeClient::Continue && args.iter().any(|arg| arg == "--agent") {
        return Err(
            "Continue --agent can replace the protected local config and is not supported"
                .to_string(),
        );
    }
    if client == IdeClient::Continue && args.iter().any(|arg| arg.starts_with("--agent=")) {
        return Err(
            "Continue --agent can replace the protected local config and is not supported"
                .to_string(),
        );
    }
    if client == IdeClient::Cline
        && args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--zen" | "-z"))
    {
        return Err(
            "Cline --zen detaches from the local gateway and is not supported by `pentect cline`"
                .to_string(),
        );
    }
    if client == IdeClient::Roo
        && args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--disable-extensions"
                    | "--disable-extension"
                    | "--extensions-dir"
                    | "--reuse-window"
            ) || arg.starts_with("--disable-extension=")
                || arg.starts_with("--extensions-dir=")
        })
    {
        return Err(
            "Roo requires its installed VS Code extension; extension-disabling flags are not supported"
                .to_string(),
        );
    }

    let mut output = Vec::with_capacity(args.len());
    let mut model = explicit_model.map(str::to_owned);
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let forced_inline = match client {
            IdeClient::Continue => arg.starts_with("--config="),
            IdeClient::Cline => [
                "--data-dir=",
                "--config=",
                "--provider=",
                "--key=",
                "--model=",
            ]
            .iter()
            .any(|prefix| arg.starts_with(prefix)),
            IdeClient::Roo | IdeClient::Zed => arg.starts_with("--user-data-dir="),
        };
        if forced_inline {
            if client == IdeClient::Cline {
                if let Some(value) = arg.strip_prefix("--model=") {
                    if value.is_empty() {
                        return Err("--model requires a value".to_string());
                    }
                    model = Some(value.to_string());
                }
            }
            index += 1;
            continue;
        }
        let takes_value = match client {
            IdeClient::Continue => matches!(arg.as_str(), "--config"),
            IdeClient::Cline => matches!(
                arg.as_str(),
                "--data-dir" | "--config" | "--provider" | "-P" | "--key" | "-k"
            ),
            IdeClient::Roo | IdeClient::Zed => arg == "--user-data-dir",
        };
        if takes_value {
            if args.get(index + 1).is_none() {
                return Err(format!("{arg} requires a value"));
            }
            index += 2;
            continue;
        }
        if matches!(client, IdeClient::Cline) && matches!(arg.as_str(), "--model" | "-m") {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{arg} requires a value"))?;
            model = Some(value.clone());
            index += 2;
            continue;
        }
        output.push(arg.clone());
        index += 1;
    }
    let model = model.unwrap_or_else(|| DEFAULT_MODEL.to_string());
    validate_model(&model)?;
    Ok((output, model))
}

fn validate_model(model: &str) -> Result<(), String> {
    if model.is_empty()
        || model.trim() != model
        || model.len() > 200
        || model.chars().any(char::is_control)
    {
        return Err("model ID is invalid".to_string());
    }
    Ok(())
}

fn continue_config(proxy: &str, model: &str) -> Result<String, String> {
    let proxy = serde_json::to_string(proxy).map_err(|error| error.to_string())?;
    let model = serde_json::to_string(model).map_err(|error| error.to_string())?;
    Ok(format!(
        "name: Pentect\nversion: 0.0.1\nschema: v1\nmodels:\n  - name: Pentect\n    provider: openai\n    model: {model}\n    apiBase: {proxy}\n    apiKey: ${{{{ secrets.PENTECT_GATEWAY_API_KEY }}}}\n    roles: [chat, edit, apply]\n    capabilities: [tool_use, image_input]\n"
    ))
}

fn cline_provider_config(proxy: &str, model: &str, key: &str) -> Result<String, String> {
    serde_json::to_string_pretty(&json!({
        "version": 1,
        "lastUsedProvider": "pentect",
        "providers": {
            "pentect": {
                "settings": {
                    "provider": "pentect",
                    "baseUrl": proxy,
                    "model": model,
                    "apiKey": key,
                    "capabilities": ["streaming", "tools", "images"]
                },
                "updatedAt": "1970-01-01T00:00:00.000Z",
                "tokenSource": "manual"
            }
        }
    }))
    .map_err(|error| format!("could not encode Cline provider registry: {error}"))
}

fn roo_import_config(proxy: &str, model: &str, key: &str) -> Result<String, String> {
    let id = "pentect-ephemeral";
    serde_json::to_string_pretty(&json!({
        "providerProfiles": {
            "currentApiConfigName": "Pentect",
            "apiConfigs": {
                "Pentect": {
                    "apiProvider": "openai",
                    "openAiBaseUrl": proxy,
                    "openAiApiKey": key,
                    "openAiModelId": model,
                    "openAiCustomModelInfo": {
                        "contextWindow": 128000,
                        "maxTokens": 32768,
                        "supportsImages": true
                    },
                    "openAiStreamingEnabled": true,
                    "openAiHeaders": {},
                    "id": id
                }
            },
            "modeApiConfigs": {
                "code": id,
                "architect": id,
                "ask": id,
                "debug": id,
                "orchestrator": id
            }
        },
        "globalSettings": {}
    }))
    .map_err(|error| format!("could not encode Roo import: {error}"))
}

fn zed_settings(proxy: &str, model: &str) -> Result<String, String> {
    serde_json::to_string_pretty(&json!({
        // Edit Prediction uses a separate completion provider and does not
        // traverse the OpenAI-compatible agent provider below.
        "edit_predictions": {"provider": "none"},
        "language_models": {
            "openai_compatible": {
                "pentect": {
                    "api_url": proxy,
                    "available_models": [{
                        "name": model,
                        "display_name": model,
                        "max_tokens": 128000,
                        "max_output_tokens": 32768,
                        "capabilities": {
                            "tools": true,
                            "images": true,
                            "parallel_tool_calls": true,
                            "prompt_cache_key": false,
                            "chat_completions": true,
                            "interleaved_reasoning": false,
                            "max_tokens_parameter": false
                        }
                    }]
                }
            }
        },
        "agent": {
            "default_model": {"provider": "pentect", "model": model},
            "compaction_model": {"provider": "pentect", "model": model}
        }
    }))
    .map_err(|error| format!("could not encode Zed settings: {error}"))
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn has_authorization_override(specs: &[String]) -> bool {
    specs.iter().any(|spec| {
        spec.split_once('=')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
    })
}

#[derive(Debug)]
struct EphemeralDirectory {
    path: PathBuf,
}

impl EphemeralDirectory {
    fn create(label: &str) -> Result<Self, String> {
        cleanup_stale_directories(label);
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("OS CSPRNG unavailable for {label} state: {error}"))?;
        let path = std::env::temp_dir().join(format!(
            ".pentect-{label}-{}-{}",
            std::process::id(),
            data_encoding::HEXLOWER.encode(&nonce)
        ));
        #[allow(unused_mut)]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|error| format!("could not create isolated {label} state: {error}"))?;
        if let Err(error) = crate::secure_temp::restrict_to_current_user(&path) {
            let _ = std::fs::remove_dir(&path);
            return Err(error);
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn cleanup_stale_directories(label: &str) {
    let prefix = format!(".pentect-{label}-");
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    let mut candidates = Vec::new();
    for path in entries.filter_map(|entry| entry.ok().map(|entry| entry.path())) {
        // Never follow a same-name symlink or Windows reparse point during
        // crash-residue cleanup. Only directories created by Pentect itself
        // are eligible for recursive removal.
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some((owner, nonce)) = stem.split_once('-') else {
            continue;
        };
        if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(owner) = owner.parse::<u32>() else {
            continue;
        };
        if owner != std::process::id() {
            candidates.push((path, sysinfo::Pid::from_u32(owner)));
        }
    }
    if candidates.is_empty() {
        return;
    }
    let pids = candidates.iter().map(|(_, pid)| *pid).collect::<Vec<_>>();
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&pids),
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    for (path, owner) in candidates {
        if system.process(owner).is_none() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

impl Drop for EphemeralDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_owner_only(path: &Path, contents: &[u8], purpose: &str) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("could not create {purpose}: {error}"))?;
    if let Err(error) = crate::secure_temp::restrict_to_current_user(path) {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(format!("could not write {purpose}: {error}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SECRET: &str = "sk-synthetic-never-use-123456789";

    #[test]
    fn continue_only_enables_proxy_supported_roles_and_keeps_key_out_of_config() {
        let config = continue_config("http://127.0.0.1:1234/v1", "gpt-5").unwrap();
        assert!(config.contains("roles: [chat, edit, apply]"));
        assert!(!config.contains("autocomplete"));
        assert!(!config.contains("embed"));
        assert!(!config.contains(SECRET));
        assert!(config.contains("secrets.PENTECT_GATEWAY_API_KEY"));
    }

    #[test]
    fn cline_registry_uses_documented_v1_envelope() {
        let value: Value = serde_json::from_str(
            &cline_provider_config("http://127.0.0.1:1234/v1", "gpt-5", "pentect-local").unwrap(),
        )
        .unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["lastUsedProvider"], "pentect");
        assert_eq!(
            value["providers"]["pentect"]["settings"]["baseUrl"],
            "http://127.0.0.1:1234/v1"
        );
        assert_eq!(
            value["providers"]["pentect"]["settings"]["apiKey"],
            "pentect-local"
        );
        assert!(!value.to_string().contains(SECRET));
    }

    #[test]
    fn roo_import_routes_every_builtin_mode_to_ephemeral_profile() {
        let value: Value = serde_json::from_str(
            &roo_import_config("http://127.0.0.1:1234/v1", "gpt-5", "pentect-local").unwrap(),
        )
        .unwrap();
        for mode in ["code", "architect", "ask", "debug", "orchestrator"] {
            assert_eq!(
                value["providerProfiles"]["modeApiConfigs"][mode],
                "pentect-ephemeral"
            );
        }
        assert_eq!(
            value["providerProfiles"]["apiConfigs"]["Pentect"]["openAiApiKey"],
            "pentect-local"
        );
        assert!(!value.to_string().contains(SECRET));
    }

    #[test]
    fn zed_config_covers_zed_owned_agent_features_without_edit_prediction() {
        let value: Value =
            serde_json::from_str(&zed_settings("http://127.0.0.1:1234/v1", "gpt-5").unwrap())
                .unwrap();
        assert_eq!(
            value["language_models"]["openai_compatible"]["pentect"]["api_url"],
            "http://127.0.0.1:1234/v1"
        );
        assert_eq!(value["agent"]["default_model"]["provider"], "pentect");
        assert_eq!(value["edit_predictions"]["provider"], "none");
        assert!(!value.to_string().contains(SECRET));
    }

    #[test]
    fn protected_routing_flags_are_consumed_and_reapplied() {
        let args = vec![
            "prompt".to_string(),
            "--provider".to_string(),
            "other".to_string(),
            "--model".to_string(),
            "gpt-4.1".to_string(),
            "--data-dir".to_string(),
            "unsafe".to_string(),
        ];
        let (forwarded, model) = sanitized_args(IdeClient::Cline, &args, None).unwrap();
        assert_eq!(forwarded, ["prompt"]);
        assert_eq!(model, "gpt-4.1");
    }

    #[test]
    fn cline_management_commands_are_not_misrepresented_as_protected_requests() {
        assert!(sanitized_args(IdeClient::Cline, &["auth".into()], None).is_err());
    }

    #[test]
    fn roo_rejects_flags_that_can_remove_the_verified_extension() {
        assert!(
            sanitized_args(IdeClient::Roo, &["--extensions-dir=elsewhere".into()], None).is_err()
        );
        assert!(sanitized_args(
            IdeClient::Roo,
            &["--disable-extension=RooVeterinaryInc.roo-cline".into()],
            None
        )
        .is_err());
    }

    #[test]
    fn stale_isolated_state_is_removed_without_touching_current_state() {
        let stale = std::env::temp_dir().join(format!(
            ".pentect-test-cleanup-{}-{}",
            u32::MAX,
            "1".repeat(32)
        ));
        let _ = std::fs::remove_dir_all(&stale);
        std::fs::create_dir(&stale).unwrap();
        let current = EphemeralDirectory::create("test-cleanup").unwrap();
        assert!(!stale.exists());
        assert!(current.path().exists());
    }
}
