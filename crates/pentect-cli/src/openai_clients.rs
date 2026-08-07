//! Launchers for OpenAI-compatible coding agents.
//!
//! Both clients receive an ephemeral provider definition. User configuration
//! files are never edited and no prompt/tool hook is installed.

use serde_json::{json, Map, Value};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

const DEFAULT_UPSTREAM: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-5";

pub(crate) fn run(
    tool: crate::AgentTool,
    opts: &crate::AgentToolOpts,
    pentect: &Path,
) -> Result<std::process::ExitStatus, String> {
    let upstream = opts
        .openai_upstream
        .clone()
        .or_else(|| {
            std::env::var("OPENAI_BASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| DEFAULT_UPSTREAM.to_string());
    let (args, model) = client_args_and_model(&opts.tool_args, opts.model.as_deref())?;
    let api = ClientApi::parse(opts.api.as_deref())?;
    if opts.dry_run {
        let mut shown = args;
        match tool {
            crate::AgentTool::OpenCode => {}
            crate::AgentTool::Pi => {
                shown.extend([
                    "--extension".to_string(),
                    "<pentect-provider>".to_string(),
                    "--model".to_string(),
                    format!("pentect/{model}"),
                ]);
            }
            _ => return Err("internal client launcher mismatch".to_string()),
        }
        crate::print_dry_run(&opts.command, &shown);
        return Ok(crate::success_status());
    }

    let active_plugins = crate::agent_tool_plugins(opts)?;
    let memory_store = crate::start_memory_store(pentect)?;
    let _parent_env = crate::agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    let proxy = crate::openai_http_proxy::OpenAiHttpProxyGuard::start_with_header_env(
        upstream,
        &opts.upstream_header_env,
    )?;
    let mut command = Command::new(&opts.command);
    crate::clear_pentect_control_env(&mut command);
    crate::upstream::hide_header_source_env(&mut command, &opts.upstream_header_env);
    crate::apply_plugin_env(&mut command, &active_plugins)?;
    crate::apply_pentect_env(&mut command, pentect, Some(memory_store.token.as_str()))?;
    crate::apply_memory_store_env(&mut command, Some(&memory_store));

    match tool {
        crate::AgentTool::OpenCode => {
            let config = opencode_config(proxy.base_url(), &model, api)?;
            command.env("OPENCODE_CONFIG_CONTENT", config);
            command.args(args);
            crate::run_native_command_with_guards(command, &opts.command, (proxy, memory_store))
        }
        crate::AgentTool::Pi => {
            let extension = PiProviderFile::create()?;
            command.env("PENTECT_PROXY_URL", proxy.base_url());
            command.env("PENTECT_PROVIDER_MODEL", &model);
            command.env("PENTECT_PROVIDER_API", api.pi_name());
            command.args(args);
            // Appended last so a caller argument cannot select an unprotected
            // provider after Pentect has started its gateway.
            command.args([
                OsString::from("--extension"),
                extension.path.as_os_str().to_owned(),
                OsString::from("--model"),
                OsString::from(format!("pentect/{model}")),
            ]);
            crate::run_native_command_with_guards(
                command,
                &opts.command,
                (proxy, memory_store, extension),
            )
        }
        _ => Err("internal client launcher mismatch".to_string()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientApi {
    ChatCompletions,
    Responses,
}

impl ClientApi {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("chat") {
            "chat" | "chat-completions" => Ok(Self::ChatCompletions),
            "responses" => Ok(Self::Responses),
            value => Err(format!(
                "unsupported API format '{value}'; use --api chat or --api responses"
            )),
        }
    }

    fn opencode_package(self) -> &'static str {
        match self {
            Self::ChatCompletions => "@ai-sdk/openai-compatible",
            Self::Responses => "@ai-sdk/openai",
        }
    }

    fn pi_name(self) -> &'static str {
        match self {
            Self::ChatCompletions => "openai-completions",
            Self::Responses => "openai-responses",
        }
    }
}

fn client_args_and_model(
    args: &[String],
    explicit: Option<&str>,
) -> Result<(Vec<String>, String), String> {
    let mut output = Vec::with_capacity(args.len());
    let mut model = explicit.map(str::to_string);
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "--model" | "-m") {
            let Some(value) = args.get(index + 1) else {
                return Err(format!("{arg} requires a value"));
            };
            model = Some(value.clone());
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--model=") {
            if value.is_empty() {
                return Err("--model requires a value".to_string());
            }
            model = Some(value.to_string());
            index += 1;
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
    if model.trim() != model
        || model.is_empty()
        || model.len() > 200
        || model.chars().any(char::is_control)
    {
        return Err("model ID is invalid".to_string());
    }
    Ok(())
}

fn opencode_config(proxy: &str, model: &str, api: ClientApi) -> Result<String, String> {
    let mut root = match std::env::var("OPENCODE_CONFIG_CONTENT") {
        Ok(existing) if !existing.trim().is_empty() => serde_json::from_str::<Value>(&existing)
            .map_err(|error| format!("OPENCODE_CONFIG_CONTENT is invalid JSON: {error}"))?,
        _ => Value::Object(Map::new()),
    };
    let root_object = root
        .as_object_mut()
        .ok_or_else(|| "OPENCODE_CONFIG_CONTENT must contain a JSON object".to_string())?;
    let providers = root_object
        .entry("provider")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "OPENCODE_CONFIG_CONTENT.provider must be an object".to_string())?;
    let api_key = if std::env::var_os("OPENAI_API_KEY").is_some() {
        "{env:OPENAI_API_KEY}"
    } else {
        "pentect-local"
    };
    providers.insert(
        "pentect".to_string(),
        json!({
            "npm": api.opencode_package(),
            "name": "Pentect",
            "options": {"baseURL": proxy, "apiKey": api_key},
            "models": {(model): {"name": model}}
        }),
    );
    root_object.insert(
        "model".to_string(),
        Value::String(format!("pentect/{model}")),
    );
    root_object.insert(
        "small_model".to_string(),
        Value::String(format!("pentect/{model}")),
    );
    // OpenCode agents and lightweight background tasks may select a provider
    // independently of the main model. Restrict this launch to the ephemeral
    // provider so those requests cannot bypass the local gateway.
    root_object.insert("enabled_providers".to_string(), json!(["pentect"]));
    root_object.insert("disabled_providers".to_string(), json!([]));
    serde_json::to_string(&root)
        .map_err(|error| format!("could not encode temporary OpenCode config: {error}"))
}

struct PiProviderFile {
    path: PathBuf,
}

impl PiProviderFile {
    fn create() -> Result<Self, String> {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|error| format!("could not create Pi provider file name: {error}"))?;
        let name = format!("pentect-pi-{}.mjs", data_encoding::HEXLOWER.encode(&random));
        random.zeroize();
        let path = std::env::temp_dir().join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("could not create temporary Pi provider: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("could not protect temporary Pi provider: {error}"))?;
        }
        file.write_all(PI_PROVIDER.as_bytes())
            .and_then(|_| file.flush())
            .map_err(|error| format!("could not write temporary Pi provider: {error}"))?;
        Ok(Self { path })
    }
}

impl Drop for PiProviderFile {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("[pentect] could not remove temporary Pi provider: {error}");
            }
        }
    }
}

const PI_PROVIDER: &str = r#"export default function (pi) {
  const baseUrl = process.env.PENTECT_PROXY_URL;
  const model = process.env.PENTECT_PROVIDER_MODEL;
  const api = process.env.PENTECT_PROVIDER_API;
  if (!baseUrl || !model || !api) throw new Error("Pentect provider environment is missing");
  pi.registerProvider("pentect", {
    name: "Pentect",
    baseUrl,
    apiKey: process.env.OPENAI_API_KEY || "pentect-local",
    authHeader: true,
    api,
    models: [{
      id: model,
      name: model,
      reasoning: api === "openai-responses",
      input: ["text", "image"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000,
      maxTokens: 32768
    }]
  });
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_flags_are_consumed_wherever_the_client_puts_them() {
        let args = vec![
            "prompt".to_string(),
            "--model".to_string(),
            "anthropic/claude-sonnet".to_string(),
            "--verbose".to_string(),
        ];
        let (forwarded, model) = client_args_and_model(&args, None).unwrap();
        assert_eq!(model, "anthropic/claude-sonnet");
        assert_eq!(forwarded, ["prompt", "--verbose"]);
    }

    #[test]
    fn opencode_config_preserves_unrelated_inline_settings() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::set_var("OPENCODE_CONFIG_CONTENT", r#"{"theme":"dark"}"#);
        let value: Value = serde_json::from_str(
            &opencode_config(
                "http://127.0.0.1/token",
                "openai/gpt-5",
                ClientApi::ChatCompletions,
            )
            .unwrap(),
        )
        .unwrap();
        match old {
            Some(value) => std::env::set_var("OPENCODE_CONFIG_CONTENT", value),
            None => std::env::remove_var("OPENCODE_CONFIG_CONTENT"),
        }
        assert_eq!(value["theme"], "dark");
        assert_eq!(value["model"], "pentect/openai/gpt-5");
        assert_eq!(value["small_model"], "pentect/openai/gpt-5");
        assert_eq!(value["enabled_providers"], serde_json::json!(["pentect"]));
        assert_eq!(
            value["provider"]["pentect"]["options"]["baseURL"],
            "http://127.0.0.1/token"
        );
    }

    #[test]
    fn responses_mode_selects_native_responses_adapters() {
        assert_eq!(
            ClientApi::parse(Some("responses"))
                .unwrap()
                .opencode_package(),
            "@ai-sdk/openai"
        );
        assert_eq!(
            ClientApi::parse(Some("responses")).unwrap().pi_name(),
            "openai-responses"
        );
        assert!(ClientApi::parse(Some("anthropic")).is_err());
    }
}
