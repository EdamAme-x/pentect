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
    let crate::client_descriptor::Launcher::OpenAi(injection) = tool.launcher else {
        return Err("internal OpenAI client launcher mismatch".to_string());
    };
    if injection == crate::client_descriptor::OpenAiInjection::InlineConfig {
        return run_opencode(tool, opts, pentect);
    }
    let upstream = opts
        .upstream
        .clone()
        .or_else(|| configured_upstream(tool))
        .or_else(|| tool.default_upstream.map(str::to_string))
        .ok_or_else(|| format!("{} has no configured upstream", tool.name))?;
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
            unreachable!("OpenCode is handled by run_opencode")
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenCodeProtocol {
    OpenAi,
    Anthropic,
    Gemini,
}

#[derive(Debug, Eq, PartialEq)]
struct OpenCodeRoute {
    provider: String,
    model: Option<String>,
    upstream: String,
    protocol: OpenCodeProtocol,
    bearer_env: Option<&'static str>,
}

impl OpenCodeRoute {
    fn resolve(opts: &crate::AgentToolOpts) -> Result<Self, String> {
        if let Some(upstream) = opts.upstream.clone() {
            let model = selected_model(opts.model.as_deref())?;
            return Ok(Self {
                provider: "pentect-gateway".to_string(),
                model: Some(format!("pentect-gateway/{model}")),
                upstream,
                protocol: OpenCodeProtocol::OpenAi,
                bearer_env: Some("OPENAI_API_KEY"),
            });
        }

        let Some(model) = opts.model.as_deref() else {
            return Ok(Self {
                provider: "opencode".to_string(),
                model: None,
                upstream: "https://opencode.ai/zen/v1".to_string(),
                protocol: OpenCodeProtocol::OpenAi,
                bearer_env: Some("OPENCODE_API_KEY"),
            });
        };
        validate_model(model)?;
        let (provider, model_id) = model.split_once('/').unwrap_or(("openai", model));
        let (upstream, protocol, bearer_env) = match provider {
            "opencode" => (
                "https://opencode.ai/zen/v1",
                OpenCodeProtocol::OpenAi,
                Some("OPENCODE_API_KEY"),
            ),
            "openai" => (
                "https://api.openai.com/v1",
                OpenCodeProtocol::OpenAi,
                Some("OPENAI_API_KEY"),
            ),
            "openrouter" => (
                "https://openrouter.ai/api/v1",
                OpenCodeProtocol::OpenAi,
                Some("OPENROUTER_API_KEY"),
            ),
            "anthropic" => (
                "https://api.anthropic.com",
                OpenCodeProtocol::Anthropic,
                None,
            ),
            "google" => (
                "https://generativelanguage.googleapis.com",
                OpenCodeProtocol::Gemini,
                None,
            ),
            _ => {
                return Err(format!(
                    "OpenCode provider '{provider}' is not routed yet; use --upstream with an OpenAI-compatible gateway"
                ))
            }
        };
        if model_id.is_empty() {
            return Err("OpenCode model ID is empty".to_string());
        }
        Ok(Self {
            provider: provider.to_string(),
            model: Some(format!("{provider}/{model_id}")),
            upstream: upstream.to_string(),
            protocol,
            bearer_env,
        })
    }
}

enum OpenCodeProxyGuard {
    OpenAi(crate::openai_http_proxy::OpenAiHttpProxyGuard),
    Anthropic(crate::claude_http_proxy::ClaudeHttpProxyGuard),
    Gemini(crate::gemini_http_proxy::GeminiHttpProxyGuard),
}

impl OpenCodeProxyGuard {
    fn base_url(&self) -> &str {
        match self {
            Self::OpenAi(proxy) => proxy.base_url(),
            Self::Anthropic(proxy) => proxy.base_url(),
            Self::Gemini(proxy) => proxy.base_url(),
        }
    }
}

fn run_opencode(
    _tool: &'static crate::client_descriptor::ClientDescriptor,
    opts: &crate::AgentToolOpts,
    pentect: &Path,
) -> Result<std::process::ExitStatus, String> {
    let route = OpenCodeRoute::resolve(opts)?;
    let api = ClientApi::parse(opts.api.as_deref())?;
    if opts.dry_run {
        crate::print_dry_run(&opts.command, &opts.tool_args);
        return Ok(crate::success_status());
    }

    let active_plugins = crate::agent_tool_plugins(opts)?;
    let memory_store = crate::start_memory_store(pentect)?;
    let _parent_env = crate::agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    let mut header_env = opts.upstream_header_env.clone();
    let bearer_env = route.bearer_env.filter(|name| {
        std::env::var_os(name).is_some_and(|value| !value.is_empty())
            && !has_authorization_override(&header_env)
    });
    let mut child_key_env = bearer_env.or_else(|| {
        route
            .bearer_env
            .filter(|_| has_authorization_override(&header_env))
    });
    if route.protocol == OpenCodeProtocol::Anthropic {
        if let Some(name) = configured_key_env(&["ANTHROPIC_API_KEY"]) {
            child_key_env = Some(name);
            if !has_header_override(&header_env, "x-api-key")
                && !has_authorization_override(&header_env)
            {
                header_env.push(format!("x-api-key={name}"));
            }
        } else if has_header_override(&header_env, "x-api-key")
            || has_authorization_override(&header_env)
        {
            child_key_env = Some("ANTHROPIC_API_KEY");
        }
    } else if route.protocol == OpenCodeProtocol::Gemini {
        if let Some(name) = configured_key_env(&[
            "GOOGLE_API_KEY",
            "GOOGLE_GENERATIVE_AI_API_KEY",
            "GEMINI_API_KEY",
        ]) {
            child_key_env = Some(name);
            if !has_header_override(&header_env, "x-goog-api-key")
                && !has_authorization_override(&header_env)
            {
                header_env.push(format!("x-goog-api-key={name}"));
            }
        } else if has_header_override(&header_env, "x-goog-api-key")
            || has_authorization_override(&header_env)
        {
            child_key_env = Some("GOOGLE_API_KEY");
        }
    }
    let proxy = match route.protocol {
        OpenCodeProtocol::OpenAi => OpenCodeProxyGuard::OpenAi(
            crate::openai_http_proxy::OpenAiHttpProxyGuard::start_with_header_env_and_bearer_env(
                route.upstream.clone(),
                &header_env,
                bearer_env,
            )?,
        ),
        OpenCodeProtocol::Anthropic => OpenCodeProxyGuard::Anthropic(
            crate::claude_http_proxy::ClaudeHttpProxyGuard::start_with_header_env(
                route.upstream.clone(),
                &header_env,
            )?,
        ),
        OpenCodeProtocol::Gemini => OpenCodeProxyGuard::Gemini(
            crate::gemini_http_proxy::GeminiHttpProxyGuard::start_with_header_env(
                route.upstream.clone(),
                &header_env,
            )?,
        ),
    };
    let package = opts.upstream.as_ref().map(|_| api.opencode_package());
    let config = opencode_config(
        proxy.base_url(),
        &route.provider,
        route.model.as_deref(),
        package,
    )?;
    let mut command = Command::new(&opts.command);
    crate::clear_pentect_control_env(&mut command);
    crate::upstream::hide_header_source_env(&mut command, &header_env);
    for name in [
        "OPENAI_API_KEY",
        "OPENCODE_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENERATIVE_AI_API_KEY",
        "GEMINI_API_KEY",
    ] {
        command.env_remove(name);
    }
    if let Some(name) = child_key_env {
        command.env(name, "pentect-local");
    }
    crate::apply_plugin_env(&mut command, &active_plugins)?;
    crate::apply_pentect_env(&mut command, pentect, Some(memory_store.token.as_str()))?;
    crate::apply_memory_store_env(&mut command, Some(&memory_store));
    command.env("OPENCODE_CONFIG_CONTENT", config);
    command.args(&opts.tool_args);
    crate::run_native_command_with_guards(command, &opts.command, (proxy, memory_store))
}

fn configured_key_env(names: &[&'static str]) -> Option<&'static str> {
    names
        .iter()
        .copied()
        .find(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

fn has_authorization_override(specs: &[String]) -> bool {
    has_header_override(specs, "authorization")
}

fn has_header_override(specs: &[String], header: &str) -> bool {
    specs.iter().any(|spec| {
        spec.split_once('=')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case(header))
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
            "chat" | "chat-completions" | "openai-completions" => Ok(Self::ChatCompletions),
            "responses" | "openai-responses" => Ok(Self::Responses),
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

fn opencode_config(
    proxy: &str,
    provider: &str,
    model: Option<&str>,
    package: Option<&str>,
) -> Result<String, String> {
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
    let mut provider_config = providers
        .remove(provider)
        .unwrap_or_else(|| Value::Object(Map::new()));
    providers.clear();
    remove_provider_credentials(&mut provider_config);
    let provider_object = provider_config
        .as_object_mut()
        .ok_or_else(|| format!("OPENCODE_CONFIG_CONTENT.provider.{provider} must be an object"))?;
    let options = provider_object
        .entry("options")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            format!("OPENCODE_CONFIG_CONTENT.provider.{provider}.options must be an object")
        })?;
    options.insert("baseURL".to_string(), Value::String(proxy.to_string()));
    if let Some(package) = package {
        provider_object.insert("npm".to_string(), Value::String(package.to_string()));
        if let Some(model_id) = model.and_then(|value| value.strip_prefix(&format!("{provider}/")))
        {
            let models = provider_object
                .entry("models")
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| {
                    format!("OPENCODE_CONFIG_CONTENT.provider.{provider}.models must be an object")
                })?;
            models.insert(model_id.to_string(), json!({"name": model_id}));
        }
    }
    providers.insert(provider.to_string(), provider_config);
    if let Some(model) = model {
        root_object.insert("model".to_string(), Value::String(model.to_string()));
        root_object.insert("small_model".to_string(), Value::String(model.to_string()));
    } else {
        root_object.remove("model");
        root_object.remove("small_model");
    }
    // OpenCode agents and lightweight background tasks may select a provider
    // independently of the main model. Restrict this launch to the ephemeral
    // provider so those requests cannot bypass the local gateway.
    root_object.insert("enabled_providers".to_string(), json!([provider]));
    root_object.insert("disabled_providers".to_string(), json!([]));
    serde_json::to_string(&root)
        .map_err(|error| format!("could not encode temporary OpenCode config: {error}"))
}

fn remove_provider_credentials(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|key, _| !is_provider_credential_key(key));
            for value in object.values_mut() {
                remove_provider_credentials(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_provider_credentials(value);
            }
        }
        _ => {}
    }
}

fn is_provider_credential_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "apikey"
            | "token"
            | "secret"
            | "password"
            | "authorization"
            | "headers"
            | "credentials"
            | "accesskeyid"
            | "secretaccesskey"
            | "sessiontoken"
    )
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
      reasoning: piBoolean("PENTECT_PI_REASONING", api === "openai-responses"),
      input: piInputs(),
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: piPositiveInteger("PENTECT_PI_CONTEXT_WINDOW", 128000),
      maxTokens: piPositiveInteger("PENTECT_PI_MAX_TOKENS", 32768)
    }]
  });
}

function piPositiveInteger(name, fallback) {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function piBoolean(name, fallback) {
  const value = process.env[name]?.trim().toLowerCase();
  if (!value || value === "auto") return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be auto, true, or false`);
}

function piInputs() {
  const value = process.env.PENTECT_PI_INPUTS?.trim().toLowerCase();
  if (!value || value === "text,image" || value === "image,text") return ["text", "image"];
  if (value === "text") return ["text"];
  throw new Error("PENTECT_PI_INPUTS must be text or text,image");
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
    fn opencode_config_preserves_settings_and_native_provider_without_credentials() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::set_var(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"theme":"dark","provider":{"other":{"options":{"apiKey":"other-secret"}},"openrouter":{"models":{"team-alias":{"name":"Team alias"}},"options":{"timeout":30000,"apiKey":"must-not-survive"}}}}"#,
        );
        let value: Value = serde_json::from_str(
            &opencode_config(
                "http://127.0.0.1/token",
                "openrouter",
                Some("openrouter/anthropic/claude-sonnet"),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        match old {
            Some(value) => std::env::set_var("OPENCODE_CONFIG_CONTENT", value),
            None => std::env::remove_var("OPENCODE_CONFIG_CONTENT"),
        }
        assert_eq!(value["theme"], "dark");
        assert_eq!(value["model"], "openrouter/anthropic/claude-sonnet");
        assert_eq!(value["small_model"], "openrouter/anthropic/claude-sonnet");
        assert_eq!(
            value["enabled_providers"],
            serde_json::json!(["openrouter"])
        );
        assert_eq!(
            value["provider"]["openrouter"]["options"]["baseURL"],
            "http://127.0.0.1/token"
        );
        assert_eq!(value["provider"].as_object().unwrap().len(), 1);
        assert_eq!(
            value["provider"]["openrouter"]["models"]["team-alias"]["name"],
            "Team alias"
        );
        assert_eq!(value["provider"]["openrouter"]["options"]["timeout"], 30000);
        assert!(!value.to_string().contains("must-not-survive"));
        assert!(!value.to_string().contains("other-secret"));
        assert!(!value.to_string().contains("apiKey"));
        assert!(!value.to_string().contains("pentect/"));
    }

    #[test]
    fn opencode_default_keeps_the_native_picker_unforced() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::set_var(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"model":"other/unsafe","small_model":"other/unsafe"}"#,
        );
        let value: Value = serde_json::from_str(
            &opencode_config("http://127.0.0.1/token", "opencode", None, None).unwrap(),
        )
        .unwrap();
        match old {
            Some(value) => std::env::set_var("OPENCODE_CONFIG_CONTENT", value),
            None => std::env::remove_var("OPENCODE_CONFIG_CONTENT"),
        }
        assert!(value.get("model").is_none());
        assert!(value.get("small_model").is_none());
        assert_eq!(value["enabled_providers"], serde_json::json!(["opencode"]));
    }

    #[test]
    fn opencode_custom_gateway_registers_its_arbitrary_model() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::remove_var("OPENCODE_CONFIG_CONTENT");
        let value: Value = serde_json::from_str(
            &opencode_config(
                "http://127.0.0.1/token",
                "pentect-gateway",
                Some("pentect-gateway/team/custom-model"),
                Some("@ai-sdk/openai-compatible"),
            )
            .unwrap(),
        )
        .unwrap();
        match old {
            Some(value) => std::env::set_var("OPENCODE_CONFIG_CONTENT", value),
            None => std::env::remove_var("OPENCODE_CONFIG_CONTENT"),
        }
        assert_eq!(
            value["provider"]["pentect-gateway"]["models"]["team/custom-model"]["name"],
            "team/custom-model"
        );
    }

    #[test]
    fn opencode_routes_supported_native_providers() {
        let opts = |model: Option<&str>, upstream: Option<&str>| crate::AgentToolOpts {
            pentect: None,
            command: "opencode".into(),
            plugins: Vec::new(),
            dry_run: false,
            upstream: upstream.map(str::to_string),
            model: model.map(str::to_string),
            api: None,
            upstream_header_env: Vec::new(),
            tool_args: Vec::new(),
        };
        let default = OpenCodeRoute::resolve(&opts(None, None)).unwrap();
        assert_eq!(default.provider, "opencode");
        assert_eq!(default.model, None);
        assert_eq!(default.upstream, "https://opencode.ai/zen/v1");

        let openrouter =
            OpenCodeRoute::resolve(&opts(Some("openrouter/anthropic/claude-sonnet"), None))
                .unwrap();
        assert_eq!(openrouter.provider, "openrouter");
        assert_eq!(openrouter.protocol, OpenCodeProtocol::OpenAi);
        assert_eq!(
            openrouter.model.as_deref(),
            Some("openrouter/anthropic/claude-sonnet")
        );

        let anthropic =
            OpenCodeRoute::resolve(&opts(Some("anthropic/claude-sonnet-4"), None)).unwrap();
        assert_eq!(anthropic.protocol, OpenCodeProtocol::Anthropic);

        let gateway = OpenCodeRoute::resolve(&opts(
            Some("anthropic/claude-sonnet"),
            Some("http://127.0.0.1:8080/openai/v1"),
        ))
        .unwrap();
        assert_eq!(gateway.provider, "pentect-gateway");
        assert_eq!(
            gateway.model.as_deref(),
            Some("pentect-gateway/anthropic/claude-sonnet")
        );
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
        assert_eq!(
            ClientApi::parse(Some("openai-completions")).unwrap(),
            ClientApi::ChatCompletions
        );
        assert_eq!(
            ClientApi::parse(Some("openai-responses")).unwrap(),
            ClientApi::Responses
        );
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
