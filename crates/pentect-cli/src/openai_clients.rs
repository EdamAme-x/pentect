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
    let args = protected_client_args(injection, &opts.tool_args)?;
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
    let standard_key_names = provider_key_env_names(injection);
    let standard_key_names = if crate::upstream::has_origin_auth_override(&opts.upstream_header_env)
    {
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
    command.env_remove("AIDER_OPENAI_API_KEY");
    command.env_remove("GOOSE_PROVIDER__API_KEY");
    command.env_remove("JUNIE_OPENAI_API_KEY");
    crate::apply_plugin_env(&mut command, &active_plugins)?;
    crate::apply_untrusted_client_env(&mut command, pentect)?;

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
            command.env("AIDER_OPENAI_API_KEY", "pentect-local");
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

fn provider_key_env_names(
    injection: crate::client_descriptor::OpenAiInjection,
) -> &'static [&'static str] {
    match injection {
        crate::client_descriptor::OpenAiInjection::ForcedArgs => {
            &["AIDER_OPENAI_API_KEY", "OPENAI_API_KEY"]
        }
        crate::client_descriptor::OpenAiInjection::GooseEnv => {
            &["GOOSE_PROVIDER__API_KEY", "OPENAI_API_KEY"]
        }
        crate::client_descriptor::OpenAiInjection::JunieProfile => {
            &["JUNIE_OPENAI_API_KEY", "OPENAI_API_KEY"]
        }
        _ => &["OPENAI_API_KEY"],
    }
}

fn protected_client_args(
    injection: crate::client_descriptor::OpenAiInjection,
    args: &[String],
) -> Result<Vec<String>, String> {
    if injection == crate::client_descriptor::OpenAiInjection::TempExtension
        && args.iter().any(|arg| arg == "--export")
    {
        return Err(
            "Pi session export is unavailable in a protected launch because stored sessions may contain restored values"
                .to_string(),
        );
    }
    Ok(args.to_vec())
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
    let tool_args = protected_opencode_args(&opts.tool_args);
    // Authentication does not carry conversation content. Let OpenCode own this
    // flow so its complete native provider catalog remains available and the
    // credential is stored under the real provider ID. Injecting the protected
    // conversation config here would restrict first-time setup to the currently
    // routed provider.
    if is_opencode_auth_command(&opts.tool_args) {
        if opts.dry_run {
            crate::print_dry_run(&opts.command, &tool_args);
            return Ok(crate::success_status());
        }
        let mut command = Command::new(&opts.command);
        crate::clear_pentect_control_env(&mut command);
        command.args(&tool_args);
        return crate::run_native_command_with_guards(command, &opts.command, ());
    }

    let api = ClientApi::parse(opts.api.as_deref())?;
    let route = OpenCodeRoute::resolve(opts)?;
    validate_opencode_route(&route, &opts.upstream_header_env)?;
    if opts.dry_run {
        crate::print_dry_run(&opts.command, &tool_args);
        println!(
            "[pentect] route provider={} model={} upstream=<pentect-upstream>",
            route.provider,
            route.model.as_deref().unwrap_or("<picker>")
        );
        return Ok(crate::success_status());
    }

    let active_plugins = crate::agent_tool_plugins(opts)?;
    let memory_store = crate::start_memory_store(pentect)?;
    let _parent_env = crate::agent_parent_env_guard(pentect, &memory_store, &active_plugins)?;
    if opts.model.is_none() && opts.upstream.is_none() {
        return run_opencode_picker(opts, pentect, &active_plugins, memory_store);
    }

    let (proxy, header_env, child_key_env) =
        start_opencode_proxy(&route, &opts.upstream_header_env)?;
    let package = opts.upstream.as_ref().map(|_| api.opencode_package());
    let mut config = opencode_config(
        proxy.base_url(),
        &route.provider,
        route.model.as_deref(),
        package,
    )?;
    if crate::execution_boundary::opencode_server_command(&opts.tool_args) {
        config = opencode_loopback_server_config(&config)?;
    }
    let mut command = opencode_command(opts, pentect, &active_plugins, &header_env)?;
    if let Some(name) = child_key_env {
        command.env(name, "pentect-local");
    }
    apply_opencode_protection(&mut command, config, &opts.tool_args);
    crate::run_native_command_with_guards(command, &opts.command, (proxy, memory_store))
}

fn apply_opencode_protection(command: &mut Command, config: String, args: &[String]) {
    command.env("OPENCODE_CONFIG_CONTENT", config);
    command.args(protected_opencode_args(args));
}

fn protected_opencode_args(args: &[String]) -> Vec<String> {
    let Some(command_index) = opencode_command_index(args) else {
        return args.to_vec();
    };
    if args[command_index] != "export" {
        return args.to_vec();
    }
    let option_end = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut protected = Vec::with_capacity(args.len() + 1);
    let mut index = 0;
    while index < option_end {
        let arg = &args[index];
        if arg == "--sanitize" {
            index += 1;
            if index < option_end && matches!(args[index].as_str(), "true" | "false") {
                index += 1;
            }
            continue;
        }
        if arg == "--no-sanitize"
            || arg.starts_with("--sanitize=")
            || arg.starts_with("--no-sanitize=")
        {
            index += 1;
            continue;
        }
        protected.push(arg.clone());
        index += 1;
    }
    protected.push("--sanitize=true".to_string());
    protected.extend_from_slice(&args[option_end..]);
    protected
}

fn opencode_command_index(args: &[String]) -> Option<usize> {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--" => return None,
            "-h" | "--help" | "-v" | "--version" | "--print-logs" | "--pure" => index += 1,
            "--log-level" => {
                if index + 1 >= args.len() {
                    return None;
                }
                index += 2;
            }
            arg if arg.starts_with("--log-level=") => index += 1,
            arg if arg.starts_with('-') => return None,
            _ => return Some(index),
        }
    }
    None
}

fn validate_opencode_route(
    route: &OpenCodeRoute,
    base_header_env: &[String],
) -> Result<(), String> {
    match route.protocol {
        OpenCodeProtocol::OpenAi => {
            crate::openai_http_proxy::parse_upstream_base(&route.upstream)?;
        }
        OpenCodeProtocol::Anthropic => {
            crate::claude_http_proxy::parse_upstream_base(&route.upstream)?;
        }
        OpenCodeProtocol::Gemini => {
            crate::upstream::parse_base(&route.upstream, "Gemini")?;
        }
    }
    let (header_env, bearer_env, _) = opencode_proxy_auth(route, base_header_env);
    crate::upstream::header_overrides_with_bearer_env(&header_env, bearer_env)?;
    Ok(())
}

fn start_opencode_proxy(
    route: &OpenCodeRoute,
    base_header_env: &[String],
) -> Result<(OpenCodeProxyGuard, Vec<String>, Option<&'static str>), String> {
    let (header_env, bearer_env, child_key_env) = opencode_proxy_auth(route, base_header_env);
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
    Ok((proxy, header_env, child_key_env))
}

fn opencode_proxy_auth(
    route: &OpenCodeRoute,
    base_header_env: &[String],
) -> (Vec<String>, Option<&'static str>, Option<&'static str>) {
    let mut header_env = base_header_env.to_vec();
    let bearer_env = route.bearer_env.filter(|name| {
        std::env::var_os(name).is_some_and(|value| !value.is_empty())
            && !crate::upstream::has_origin_auth_override(&header_env)
    });
    let mut child_key_env = bearer_env.or_else(|| {
        route
            .bearer_env
            .filter(|_| crate::upstream::has_origin_auth_override(&header_env))
    });
    if route.protocol == OpenCodeProtocol::Anthropic {
        if let Some(name) = configured_key_env(&["ANTHROPIC_API_KEY"]) {
            child_key_env = Some(name);
            if !has_header_override(&header_env, "x-api-key")
                && !crate::upstream::has_origin_auth_override(&header_env)
            {
                header_env.push(format!("x-api-key={name}"));
            }
        } else if has_header_override(&header_env, "x-api-key")
            || crate::upstream::has_origin_auth_override(&header_env)
        {
            child_key_env = Some("ANTHROPIC_API_KEY");
        }
    } else if route.protocol == OpenCodeProtocol::Gemini {
        if let Some(name) = configured_key_env(crate::GOOGLE_API_KEY_ENV_NAMES) {
            child_key_env = Some(name);
            if !has_header_override(&header_env, "x-goog-api-key")
                && !crate::upstream::has_origin_auth_override(&header_env)
            {
                header_env.push(format!("x-goog-api-key={name}"));
            }
        } else if has_header_override(&header_env, "x-goog-api-key")
            || crate::upstream::has_origin_auth_override(&header_env)
        {
            child_key_env = Some("GOOGLE_API_KEY");
        }
    }
    (header_env, bearer_env, child_key_env)
}

fn opencode_command(
    opts: &crate::AgentToolOpts,
    pentect: &Path,
    active_plugins: &crate::plugins::ActivePlugins,
    header_env: &[String],
) -> Result<Command, String> {
    let mut command = Command::new(&opts.command);
    crate::clear_pentect_control_env(&mut command);
    crate::upstream::hide_header_source_env(&mut command, header_env);
    for name in [
        "OPENAI_API_KEY",
        "OPENCODE_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
    ] {
        command.env_remove(name);
    }
    for name in crate::GOOGLE_API_KEY_ENV_NAMES {
        command.env_remove(name);
    }
    crate::apply_plugin_env(&mut command, active_plugins)?;
    crate::apply_untrusted_client_env(&mut command, pentect)?;
    Ok(command)
}

fn run_opencode_picker(
    opts: &crate::AgentToolOpts,
    pentect: &Path,
    active_plugins: &crate::plugins::ActivePlugins,
    memory_store: crate::MemoryStoreGuard,
) -> Result<std::process::ExitStatus, String> {
    let routes = [
        OpenCodeRoute {
            provider: "opencode".to_string(),
            model: None,
            upstream: "https://opencode.ai/zen/v1".to_string(),
            protocol: OpenCodeProtocol::OpenAi,
            bearer_env: Some("OPENCODE_API_KEY"),
        },
        OpenCodeRoute {
            provider: "openai".to_string(),
            model: None,
            upstream: "https://api.openai.com/v1".to_string(),
            protocol: OpenCodeProtocol::OpenAi,
            bearer_env: Some("OPENAI_API_KEY"),
        },
        OpenCodeRoute {
            provider: "openrouter".to_string(),
            model: None,
            upstream: "https://openrouter.ai/api/v1".to_string(),
            protocol: OpenCodeProtocol::OpenAi,
            bearer_env: Some("OPENROUTER_API_KEY"),
        },
        OpenCodeRoute {
            provider: "anthropic".to_string(),
            model: None,
            upstream: "https://api.anthropic.com".to_string(),
            protocol: OpenCodeProtocol::Anthropic,
            bearer_env: None,
        },
        OpenCodeRoute {
            provider: "google".to_string(),
            model: None,
            upstream: "https://generativelanguage.googleapis.com".to_string(),
            protocol: OpenCodeProtocol::Gemini,
            bearer_env: None,
        },
    ];
    let mut proxies = Vec::with_capacity(routes.len());
    let mut provider_urls = Vec::with_capacity(routes.len());
    let mut hidden_header_env = Vec::new();
    let mut child_key_env = Vec::new();
    for route in &routes {
        let (proxy, headers, child_key) = start_opencode_proxy(route, &opts.upstream_header_env)?;
        provider_urls.push((route.provider.as_str(), proxy.base_url().to_string()));
        hidden_header_env.extend(headers);
        if let Some(name) = child_key {
            child_key_env.push(name);
        }
        proxies.push(proxy);
    }
    let mut config = opencode_picker_config(&provider_urls)?;
    if crate::execution_boundary::opencode_server_command(&opts.tool_args) {
        config = opencode_loopback_server_config(&config)?;
    }
    let mut command = opencode_command(opts, pentect, active_plugins, &hidden_header_env)?;
    child_key_env.sort_unstable();
    child_key_env.dedup();
    for name in child_key_env {
        command.env(name, "pentect-local");
    }
    apply_opencode_protection(&mut command, config, &opts.tool_args);
    crate::run_native_command_with_guards(command, &opts.command, (proxies, memory_store))
}

fn is_opencode_auth_command(args: &[String]) -> bool {
    args.first().is_some_and(|arg| arg == "auth")
}

fn configured_key_env(names: &[&'static str]) -> Option<&'static str> {
    names
        .iter()
        .copied()
        .find(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
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
        "--openai-api-key".to_string(),
        "pentect-local".to_string(),
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

fn opencode_loopback_server_config(config: &str) -> Result<String, String> {
    let mut root = serde_json::from_str::<Value>(config)
        .map_err(|_| "generated OpenCode config is invalid".to_string())?;
    let object = root
        .as_object_mut()
        .ok_or_else(|| "generated OpenCode config must be an object".to_string())?;
    let server = object
        .entry("server")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| "OpenCode server config must be an object".to_string())?;
    server.insert(
        "hostname".to_string(),
        Value::String("127.0.0.1".to_string()),
    );
    server.insert("mdns".to_string(), Value::Bool(false));
    serde_json::to_string(&root).map_err(|_| "could not encode OpenCode config".to_string())
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

fn opencode_picker_config(provider_urls: &[(&str, String)]) -> Result<String, String> {
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
    let mut protected = Vec::with_capacity(provider_urls.len());
    for (provider, proxy) in provider_urls {
        let mut provider_config = providers
            .remove(*provider)
            .unwrap_or_else(|| Value::Object(Map::new()));
        remove_provider_credentials(&mut provider_config);
        let provider_object = provider_config.as_object_mut().ok_or_else(|| {
            format!("OPENCODE_CONFIG_CONTENT.provider.{provider} must be an object")
        })?;
        let options = provider_object
            .entry("options")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| {
                format!("OPENCODE_CONFIG_CONTENT.provider.{provider}.options must be an object")
            })?;
        options.insert("baseURL".to_string(), Value::String(proxy.clone()));
        protected.push(((*provider).to_string(), provider_config));
    }
    providers.clear();
    for (provider, config) in protected {
        providers.insert(provider, config);
    }
    root_object.remove("model");
    root_object.remove("small_model");
    root_object.insert(
        "enabled_providers".to_string(),
        Value::Array(
            provider_urls
                .iter()
                .map(|(provider, _)| Value::String((*provider).to_string()))
                .collect(),
        ),
    );
    root_object.insert("disabled_providers".to_string(), json!([]));
    root_object.insert("share".to_string(), Value::String("disabled".to_string()));
    root_object.insert("autoshare".to_string(), Value::Bool(false));
    serde_json::to_string(&root)
        .map_err(|error| format!("could not encode temporary OpenCode config: {error}"))
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
    root_object.insert("share".to_string(), Value::String("disabled".to_string()));
    root_object.insert("autoshare".to_string(), Value::Bool(false));
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

    struct ScopedEnv {
        name: &'static str,
        previous: Option<OsString>,
    }

    impl ScopedEnv {
        fn set(name: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self { name, previous }
        }

        fn remove(name: &'static str) -> Self {
            let previous = std::env::var_os(name);
            std::env::remove_var(name);
            Self { name, previous }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    #[test]
    fn selected_model_only_uses_the_parsed_pentect_option() {
        assert_eq!(selected_model(None).unwrap(), DEFAULT_MODEL);
        assert_eq!(
            selected_model(Some("anthropic/claude-sonnet")).unwrap(),
            "anthropic/claude-sonnet"
        );
    }

    #[test]
    fn opencode_exports_are_canonicalized_to_the_upstream_sanitizer() {
        assert_eq!(
            protected_opencode_args(&[
                "--print-logs".to_string(),
                "--log-level".to_string(),
                "DEBUG".to_string(),
                "export".to_string(),
                "session-canary".to_string(),
                "--no-sanitize".to_string(),
                "--sanitize=false".to_string(),
                "--sanitize".to_string(),
                "false".to_string(),
                "--no-sanitize=false".to_string(),
            ]),
            [
                "--print-logs",
                "--log-level",
                "DEBUG",
                "export",
                "session-canary",
                "--sanitize=true"
            ]
        );
        assert_eq!(
            protected_opencode_args(&["run".to_string(), "--share".to_string()]),
            ["run", "--share"]
        );
        assert_eq!(
            protected_opencode_args(&[
                "--log-level".to_string(),
                "export".to_string(),
                "session-canary".to_string(),
            ]),
            ["--log-level", "export", "session-canary"]
        );
        assert_eq!(
            protected_opencode_args(&[
                "export".to_string(),
                "--sanitize=false".to_string(),
                "--".to_string(),
                "--sanitize=false".to_string(),
            ]),
            ["export", "--sanitize=true", "--", "--sanitize=false"]
        );
    }

    #[test]
    fn opencode_fixed_and_picker_commands_capture_protected_export_and_share_config() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::set_var(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"share":"auto","autoshare":true}"#,
        );
        let args = [
            "--log-level".to_string(),
            "DEBUG".to_string(),
            "export".to_string(),
            "session-capture-canary".to_string(),
            "--no-sanitize".to_string(),
        ];
        let mut fixed = Command::new("fake-opencode-capture-canary");
        apply_opencode_protection(
            &mut fixed,
            opencode_config(
                "http://127.0.0.1/fixed",
                "openrouter",
                Some("openrouter/canary"),
                None,
            )
            .unwrap(),
            &args,
        );
        let mut picker = Command::new("fake-opencode-capture-canary");
        apply_opencode_protection(
            &mut picker,
            opencode_picker_config(&[("opencode", "http://127.0.0.1/picker".to_string())]).unwrap(),
            &args,
        );
        match old {
            Some(value) => std::env::set_var("OPENCODE_CONFIG_CONTENT", value),
            None => std::env::remove_var("OPENCODE_CONFIG_CONTENT"),
        }

        for command in [&fixed, &picker] {
            let captured_args = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                captured_args,
                [
                    "--log-level",
                    "DEBUG",
                    "export",
                    "session-capture-canary",
                    "--sanitize=true"
                ]
            );
            let config = command
                .get_envs()
                .find_map(|(name, value)| {
                    (name == "OPENCODE_CONFIG_CONTENT")
                        .then(|| value.unwrap().to_string_lossy().into_owned())
                })
                .unwrap();
            let config: Value = serde_json::from_str(&config).unwrap();
            assert_eq!(config["share"], "disabled");
            assert_eq!(config["autoshare"], false);
        }
    }

    #[test]
    fn pi_cli_export_is_rejected_before_launch() {
        let error = protected_client_args(
            crate::client_descriptor::OpenAiInjection::TempExtension,
            &[
                "--export".to_string(),
                "raw-session-canary.jsonl".to_string(),
            ],
        )
        .unwrap_err();
        assert!(error.contains("session export is unavailable"), "{error}");
        assert!(protected_client_args(
            crate::client_descriptor::OpenAiInjection::TempExtension,
            &["--print".to_string(), "hello".to_string()],
        )
        .is_ok());
        assert!(protected_client_args(
            crate::client_descriptor::OpenAiInjection::TempExtension,
            &["--export=not-a-pi-option".to_string()],
        )
        .is_ok());
    }

    #[test]
    fn opencode_server_config_cannot_widen_the_generated_listener() {
        let value: Value = serde_json::from_str(
            &opencode_loopback_server_config(
                r#"{"theme":"dark","server":{"hostname":"0.0.0.0","mdns":true,"port":4096}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(value["theme"], "dark");
        assert_eq!(value["server"]["hostname"], "127.0.0.1");
        assert_eq!(value["server"]["mdns"], false);
        assert_eq!(value["server"]["port"], 4096);
    }

    #[test]
    fn opencode_config_preserves_settings_and_native_provider_without_credentials() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::set_var(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"theme":"dark","share":"auto","autoshare":true,"provider":{"other":{"options":{"apiKey":"other-secret"}},"openrouter":{"models":{"team-alias":{"name":"Team alias"}},"options":{"timeout":30000,"apiKey":"must-not-survive"}}}}"#,
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
        assert_eq!(value["share"], "disabled");
        assert_eq!(value["autoshare"], false);
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
        assert_eq!(value["share"], "disabled");
        assert_eq!(value["autoshare"], false);
    }

    #[test]
    fn opencode_picker_routes_every_supported_native_provider() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("OPENCODE_CONFIG_CONTENT");
        std::env::set_var(
            "OPENCODE_CONFIG_CONTENT",
            r#"{"model":"old/model","share":"manual","autoshare":true,"provider":{"openrouter":{"models":{"team":{"name":"Team"}},"options":{"apiKey":"secret","timeout":30000}},"unprotected":{"options":{"baseURL":"https://bypass.invalid"}}}}"#,
        );
        let urls = [
            ("opencode", "http://127.0.0.1:1/opencode".to_string()),
            ("openai", "http://127.0.0.1:2/openai".to_string()),
            ("openrouter", "http://127.0.0.1:3/openrouter".to_string()),
            ("anthropic", "http://127.0.0.1:4/anthropic".to_string()),
            ("google", "http://127.0.0.1:5/google".to_string()),
        ];
        let value: Value = serde_json::from_str(&opencode_picker_config(&urls).unwrap()).unwrap();
        match old {
            Some(value) => std::env::set_var("OPENCODE_CONFIG_CONTENT", value),
            None => std::env::remove_var("OPENCODE_CONFIG_CONTENT"),
        }
        assert!(value.get("model").is_none());
        assert!(value.get("small_model").is_none());
        assert_eq!(value["share"], "disabled");
        assert_eq!(value["autoshare"], false);
        assert_eq!(
            value["enabled_providers"],
            serde_json::json!(["opencode", "openai", "openrouter", "anthropic", "google"])
        );
        assert!(value["provider"].get("unprotected").is_none());
        assert_eq!(
            value["provider"]["openrouter"]["options"]["baseURL"],
            "http://127.0.0.1:3/openrouter"
        );
        assert_eq!(value["provider"]["openrouter"]["options"]["timeout"], 30000);
        assert!(value["provider"]["openrouter"]["options"]
            .get("apiKey")
            .is_none());
        assert_eq!(
            value["provider"]["openrouter"]["models"]["team"]["name"],
            "Team"
        );
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
    fn opencode_auth_commands_bypass_conversation_provider_injection() {
        assert!(is_opencode_auth_command(&[
            "auth".to_string(),
            "login".to_string()
        ]));
        assert!(is_opencode_auth_command(&[
            "auth".to_string(),
            "list".to_string()
        ]));
        assert!(!is_opencode_auth_command(&[]));
        assert!(!is_opencode_auth_command(&[
            "run".to_string(),
            "auth".to_string()
        ]));
    }

    #[test]
    fn explicit_origin_auth_header_disables_implicit_key_selection() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let _authorization = ScopedEnv::remove("PENTECT_UPSTREAM_AUTHORIZATION");
        assert!(crate::upstream::has_origin_auth_override(&[
            "authorization=MY_HEADER".to_string()
        ]));
        assert!(crate::upstream::has_origin_auth_override(&[
            " Authorization =MY_HEADER".to_string()
        ]));
        assert!(crate::upstream::has_origin_auth_override(&[
            "X-Api-Key=MY_HEADER".to_string()
        ]));
    }

    #[test]
    fn authorization_control_env_prevents_native_provider_key_injection() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let _authorization = ScopedEnv::set(
            "PENTECT_UPSTREAM_AUTHORIZATION",
            "Bearer custom-upstream-token",
        );
        let _anthropic_key = ScopedEnv::set("ANTHROPIC_API_KEY", "anthropic-origin-key");
        let _google_key = ScopedEnv::remove("GOOGLE_API_KEY");
        let _generative_key = ScopedEnv::set(
            "GOOGLE_GENERATIVE_AI_API_KEY",
            "google-generative-origin-key",
        );
        let _gemini_key = ScopedEnv::remove("GEMINI_API_KEY");

        for (protocol, forbidden_header, expected_child_key) in [
            (
                OpenCodeProtocol::Anthropic,
                "x-api-key",
                "ANTHROPIC_API_KEY",
            ),
            (
                OpenCodeProtocol::Gemini,
                "x-goog-api-key",
                "GOOGLE_GENERATIVE_AI_API_KEY",
            ),
        ] {
            let route = OpenCodeRoute {
                provider: "test".to_string(),
                model: None,
                upstream: "http://127.0.0.1:1".to_string(),
                protocol,
                bearer_env: None,
            };
            let (headers, bearer_env, child_key_env) = opencode_proxy_auth(&route, &[]);
            assert!(
                !has_header_override(&headers, forbidden_header),
                "{forbidden_header} must not be added beside an explicit authorization override"
            );
            assert_eq!(bearer_env, None);
            assert_eq!(child_key_env, Some(expected_child_key));
        }
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
                "--openai-api-key",
                "pentect-local",
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
        assert_eq!(
            provider_key_env_names(crate::client_descriptor::OpenAiInjection::ForcedArgs),
            ["AIDER_OPENAI_API_KEY", "OPENAI_API_KEY"]
        );
        assert_eq!(aider_model("openai/custom").unwrap(), "openai/custom");
        assert!(aider_model("anthropic/claude-sonnet").is_err());
    }
}
