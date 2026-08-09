//! Launchers for OpenAI-compatible coding agents.
//!
//! Both clients receive an ephemeral provider definition. User configuration
//! files are never edited and no prompt/tool hook is installed.

use serde_json::{json, Map, Value};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

const DEFAULT_MODEL: &str = "gpt-5";

pub(crate) fn run(
    tool: &'static crate::client_descriptor::ClientDescriptor,
    opts: &crate::AgentToolOpts,
    pentect: &Path,
) -> Result<std::process::ExitStatus, String> {
    let upstream = opts
        .upstream
        .clone()
        .or_else(|| configured_upstream(tool))
        .or_else(|| tool.default_upstream.map(str::to_string))
        .ok_or_else(|| format!("{} has no configured upstream", tool.name))?;
    let crate::client_descriptor::Launcher::OpenAi(injection) = tool.launcher else {
        return Err("internal OpenAI client launcher mismatch".to_string());
    };
    let args = opts.tool_args.clone();
    let model = selected_model(opts.model.as_deref())?;
    let api = ClientApi::parse(opts.api.as_deref())?;
    if opts.dry_run {
        let mut shown = args;
        match injection {
            crate::client_descriptor::OpenAiInjection::InlineConfig => {}
            crate::client_descriptor::OpenAiInjection::TempExtension => {
                shown.extend([
                    "--extension".to_string(),
                    "<pentect-provider>".to_string(),
                    "--model".to_string(),
                    format!("pentect/{model}"),
                ]);
            }
            crate::client_descriptor::OpenAiInjection::ForcedArgs => {
                shown.extend(aider_gateway_args("<pentect-gateway>", &model)?)
            }
            crate::client_descriptor::OpenAiInjection::GooseEnv => {}
            crate::client_descriptor::OpenAiInjection::JunieProfile => {
                shown.extend([
                    "--model-location".to_string(),
                    "<pentect-models>".to_string(),
                    "--model".to_string(),
                    "custom:<pentect-model>".to_string(),
                ]);
            }
        }
        crate::print_dry_run(&opts.command, &shown);
        return Ok(crate::success_status());
    }

    let active_plugins = crate::agent_tool_plugins(opts)?;
    let memory_store = crate::start_memory_store(pentect)?;
    let _parent_env = crate::agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    let standard_key_names: &[&str] = match injection {
        crate::client_descriptor::OpenAiInjection::GooseEnv => {
            &["GOOSE_PROVIDER__API_KEY", "OPENAI_API_KEY"]
        }
        crate::client_descriptor::OpenAiInjection::JunieProfile => {
            &["JUNIE_OPENAI_API_KEY", "OPENAI_API_KEY"]
        }
        _ => &["OPENAI_API_KEY"],
    };
    let standard_key_names = if has_authorization_override(&opts.upstream_header_env) {
        &[][..]
    } else {
        standard_key_names
    };
    let _authorization = crate::upstream_bearer_guard(standard_key_names);
    let proxy = crate::openai_http_proxy::OpenAiHttpProxyGuard::start_with_header_env(
        upstream,
        &opts.upstream_header_env,
    )?;
    let mut command = Command::new(&opts.command);
    crate::clear_pentect_control_env(&mut command);
    crate::upstream::hide_header_source_env(&mut command, &opts.upstream_header_env);
    // Provider credentials belong to the gateway, not to the agent process or
    // its local tools. The client only needs a syntactically valid loopback
    // credential; the gateway replaces it for the upstream request.
    command.env("OPENAI_API_KEY", "pentect-local");
    command.env_remove("GOOSE_PROVIDER__API_KEY");
    command.env_remove("JUNIE_OPENAI_API_KEY");
    crate::apply_plugin_env(&mut command, &active_plugins)?;
    crate::apply_pentect_env(&mut command, pentect, Some(memory_store.token.as_str()))?;
    crate::apply_memory_store_env(&mut command, Some(&memory_store));

    match injection {
        crate::client_descriptor::OpenAiInjection::InlineConfig => {
            let config = opencode_config(proxy.base_url(), &model, api)?;
            command.env("OPENCODE_CONFIG_CONTENT", config);
            command.args(args);
            crate::run_native_command_with_guards(command, &opts.command, (proxy, memory_store))
        }
        crate::client_descriptor::OpenAiInjection::TempExtension => {
            let extension = PiProviderFile::create()?;
            command.env("PENTECT_PROXY_URL", proxy.base_url());
            command.env("PENTECT_PROVIDER_MODEL", &model);
            command.env("PENTECT_PROVIDER_API", api.pi_name());
            command.args(args);
            // Appended last so a caller argument cannot select an unprotected
            // provider after Pentect has started its gateway.
            command.args([
                OsString::from("--extension"),
                extension.file.path().as_os_str().to_owned(),
                OsString::from("--model"),
                OsString::from(format!("pentect/{model}")),
            ]);
            crate::run_native_command_with_guards(
                command,
                &opts.command,
                (proxy, memory_store, extension),
            )
        }
        crate::client_descriptor::OpenAiInjection::ForcedArgs => {
            command.args(args);
            // Appended last so config files, environment variables and caller
            // options cannot select an unprotected provider or helper model.
            command.args(aider_gateway_args(proxy.base_url(), &model)?);
            crate::run_native_command_with_guards(command, &opts.command, (proxy, memory_store))
        }
        crate::client_descriptor::OpenAiInjection::GooseEnv => {
            crate::openai_client_injection::configure_goose(
                &mut command,
                proxy.base_url(),
                &model,
                std::ffi::OsStr::new("pentect-local"),
            );
            command.args(args);
            crate::run_native_command_with_guards(command, &opts.command, (proxy, memory_store))
        }
        crate::client_descriptor::OpenAiInjection::JunieProfile => {
            let profile = crate::openai_client_injection::JunieModelProfile::create(
                proxy.base_url(),
                &model,
                api.injection_api(),
            )?;
            command.args(args);
            profile.apply(&mut command, std::ffi::OsStr::new("pentect-local"));
            crate::run_native_command_with_guards(
                command,
                &opts.command,
                (proxy, memory_store, profile),
            )
        }
    }
}

fn has_authorization_override(specs: &[String]) -> bool {
    specs.iter().any(|spec| {
        spec.split_once('=')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
    })
}

fn configured_upstream(tool: &crate::client_descriptor::ClientDescriptor) -> Option<String> {
    tool.upstream_env.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    })
}

fn aider_model(model: &str) -> Result<String, String> {
    if model.starts_with("openai/") {
        Ok(model.to_string())
    } else if model.contains('/') {
        Err(format!(
            "Aider model '{model}' uses a provider that cannot be routed through the Pentect OpenAI gateway; use an openai/ model and pass --upstream for a compatible custom endpoint"
        ))
    } else {
        Ok(format!("openai/{model}"))
    }
}

fn aider_gateway_args(proxy: &str, model: &str) -> Result<Vec<String>, String> {
    let model = aider_model(model)?;
    Ok(vec![
        "--openai-api-base".to_string(),
        proxy.to_string(),
        "--model".to_string(),
        model.clone(),
        "--weak-model".to_string(),
        model.clone(),
        "--editor-model".to_string(),
        model,
    ])
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

    fn injection_api(self) -> crate::openai_client_injection::OpenAiWireApi {
        match self {
            Self::ChatCompletions => crate::openai_client_injection::OpenAiWireApi::ChatCompletions,
            Self::Responses => crate::openai_client_injection::OpenAiWireApi::Responses,
        }
    }
}

fn selected_model(explicit: Option<&str>) -> Result<String, String> {
    let model = explicit.unwrap_or(DEFAULT_MODEL).to_string();
    validate_model(&model)?;
    Ok(model)
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
    // Do not copy credentials for unrelated providers into the child process.
    // This launch intentionally exposes only the ephemeral Pentect provider.
    providers.clear();
    let api_key = "{env:OPENAI_API_KEY}";
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
    file: crate::secure_temp::SecureTempFile,
}

impl PiProviderFile {
    fn create() -> Result<Self, String> {
        let file = crate::secure_temp::SecureTempFile::create(
            &std::env::temp_dir(),
            ".pentect-pi-provider-",
            ".mjs",
            PI_PROVIDER.as_bytes(),
            "Pi provider",
        )?;
        Ok(Self { file })
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
    fn selected_model_only_uses_the_parsed_pentect_option() {
        assert_eq!(selected_model(None).unwrap(), DEFAULT_MODEL);
        assert_eq!(
            selected_model(Some("anthropic/claude-sonnet")).unwrap(),
            "anthropic/claude-sonnet"
        );
    }

    #[test]
    fn opencode_config_preserves_settings_but_drops_other_providers() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::set_var(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"theme":"dark","provider":{"other":{"options":{"apiKey":"must-not-survive"}}}}"#,
        );
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
        assert_eq!(value["provider"].as_object().unwrap().len(), 1);
        assert!(!value.to_string().contains("must-not-survive"));
    }

    #[test]
    fn explicit_authorization_header_disables_implicit_key_selection() {
        assert!(has_authorization_override(&[
            "authorization=MY_HEADER".to_string()
        ]));
        assert!(has_authorization_override(&[
            " Authorization =MY_HEADER".to_string()
        ]));
        assert!(!has_authorization_override(&[
            "X-Api-Key=MY_HEADER".to_string()
        ]));
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

    #[test]
    fn aider_gateway_options_override_all_openai_model_routes() {
        assert_eq!(
            aider_gateway_args("http://127.0.0.1:4321/v1", "gpt-5").unwrap(),
            [
                "--openai-api-base",
                "http://127.0.0.1:4321/v1",
                "--model",
                "openai/gpt-5",
                "--weak-model",
                "openai/gpt-5",
                "--editor-model",
                "openai/gpt-5",
            ]
        );
        assert_eq!(aider_model("openai/custom").unwrap(), "openai/custom");
        assert!(aider_model("anthropic/claude-sonnet").is_err());
    }
}
