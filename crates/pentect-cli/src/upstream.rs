//! Shared transport and URL handling for provider-compatible upstreams.

use std::path::Path;
use zeroize::Zeroize;

const UPSTREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

const CA_CERT_ENV: &str = "PENTECT_UPSTREAM_CA_CERT";
const IDENTITY_ENV: &str = "PENTECT_UPSTREAM_IDENTITY";
const AUTHORIZATION_ENV: &str = "PENTECT_UPSTREAM_AUTHORIZATION";

#[derive(Clone)]
struct HeaderOverride {
    name: reqwest::header::HeaderName,
    value: Option<reqwest::header::HeaderValue>,
}

#[derive(Clone, Default)]
pub(crate) struct HeaderOverrides {
    values: Vec<HeaderOverride>,
    suppress_origin_auth: bool,
}

impl HeaderOverrides {
    pub(crate) fn forward_incoming_header(&self, name: &str) -> bool {
        !(self.suppress_origin_auth && is_replaceable_origin_auth_header(name))
            && !self
                .values
                .iter()
                .any(|header| header.name.as_str().eq_ignore_ascii_case(name))
    }

    pub(crate) fn apply(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        for header in &self.values {
            if let Some(value) = &header.value {
                request = request.header(&header.name, value);
            }
        }
        request
    }

    /// Canonical, short-lived input used to bind local file attestations to
    /// the effective upstream identity. The caller must hash this with a
    /// local keyed digest and discard it; it must never be persisted or logged.
    pub(crate) fn credential_scope_material(
        &self,
        incoming: &hyper::HeaderMap,
    ) -> zeroize::Zeroizing<Vec<u8>> {
        let mut fields = Vec::<(Vec<u8>, Vec<u8>)>::new();
        for (name, value) in incoming {
            if is_origin_auth_header(name.as_str()) && self.forward_incoming_header(name.as_str()) {
                fields.push((
                    name.as_str().to_ascii_lowercase().into_bytes(),
                    value.as_bytes().to_vec(),
                ));
            }
        }
        for override_header in &self.values {
            if let Some(value) = &override_header.value {
                fields.push((
                    override_header
                        .name
                        .as_str()
                        .to_ascii_lowercase()
                        .into_bytes(),
                    value.as_bytes().to_vec(),
                ));
            }
        }
        fields.sort();
        let mut material = zeroize::Zeroizing::new(Vec::new());
        for (name, mut value) in fields {
            append_scope_field(&mut material, &name);
            append_scope_field(&mut material, &value);
            value.zeroize();
        }
        material
    }
}

fn append_scope_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

pub(crate) fn header_overrides(specs: &[String]) -> Result<HeaderOverrides, String> {
    if specs.len() > 32 {
        return Err("too many --upstream-header-env options (maximum 32)".to_string());
    }
    let mut overrides = HeaderOverrides::default();
    if let Some(value) = std::env::var_os(AUTHORIZATION_ENV) {
        let value = if value.is_empty() {
            None
        } else {
            let mut value = value
                .into_string()
                .map_err(|_| format!("{AUTHORIZATION_ENV} is not valid Unicode"))?;
            let header = sensitive_header_value(&value, AUTHORIZATION_ENV);
            value.zeroize();
            Some(header?)
        };
        overrides.suppress_origin_auth = true;
        overrides.values.push(HeaderOverride {
            name: reqwest::header::AUTHORIZATION,
            value,
        });
    }

    for spec in specs {
        let (name, env_name) = spec.split_once('=').ok_or_else(|| {
            "--upstream-header-env must use HEADER=ENV_NAME (for example x-bf-vk=BIFROST_API_KEY)"
                .to_string()
        })?;
        let name = reqwest::header::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| format!("invalid upstream header name '{name}'"))?;
        reject_unsafe_override_header(&name)?;
        if overrides
            .values
            .iter()
            .any(|existing| existing.name == name)
        {
            return Err(format!(
                "upstream header '{}' is configured more than once",
                name
            ));
        }
        let env_name = env_name.trim();
        if env_name.is_empty() || env_name.contains('=') || env_name.contains('\0') {
            return Err("upstream header environment variable name is invalid".to_string());
        }
        let mut value = std::env::var(env_name).map_err(|_| {
            format!("environment variable {env_name} is not set or is not valid Unicode")
        })?;
        if value.is_empty() {
            return Err(format!("environment variable {env_name} is empty"));
        }
        if value.len() > 16 * 1024 {
            value.zeroize();
            return Err(format!("environment variable {env_name} is too large"));
        }
        let header = sensitive_header_value(&value, env_name);
        value.zeroize();
        overrides.suppress_origin_auth = true;
        overrides.values.push(HeaderOverride {
            name,
            value: Some(header?),
        });
    }
    Ok(overrides)
}

pub(crate) fn has_authorization_override(specs: &[String]) -> bool {
    std::env::var_os(AUTHORIZATION_ENV).is_some()
        || specs.iter().any(|spec| {
            spec.split_once('=').is_some_and(|(name, _)| {
                name.trim()
                    .eq_ignore_ascii_case(reqwest::header::AUTHORIZATION.as_str())
            })
        })
}

pub(crate) fn header_overrides_with_bearer_env(
    specs: &[String],
    bearer_env: Option<&str>,
) -> Result<HeaderOverrides, String> {
    let mut overrides = header_overrides(specs)?;
    let Some(env_name) = bearer_env.filter(|_| !overrides.suppress_origin_auth) else {
        return Ok(overrides);
    };
    if env_name.is_empty() || env_name.contains('=') || env_name.contains('\0') {
        return Err("provider API key environment variable name is invalid".to_string());
    }
    let mut value = std::env::var(env_name).map_err(|_| {
        format!(
            "provider API key environment variable {env_name} is not set or is not valid Unicode"
        )
    })?;
    if value.is_empty() {
        return Err(format!(
            "provider API key environment variable {env_name} is empty"
        ));
    }
    if value.len() > 16 * 1024 {
        value.zeroize();
        return Err(format!(
            "provider API key environment variable {env_name} is too large"
        ));
    }
    let mut authorization = format!("Bearer {value}");
    value.zeroize();
    let header = sensitive_header_value(&authorization, env_name);
    authorization.zeroize();
    overrides.suppress_origin_auth = true;
    overrides.values.push(HeaderOverride {
        name: reqwest::header::AUTHORIZATION,
        value: Some(header?),
    });
    Ok(overrides)
}

pub(crate) fn hide_header_source_env(command: &mut std::process::Command, specs: &[String]) {
    for spec in specs {
        if let Some(env_name) = header_source_env_name(spec) {
            command.env_remove(env_name);
        }
    }
}

pub(crate) fn header_source_env_name(spec: &str) -> Option<&str> {
    let (_, env_name) = spec.split_once('=')?;
    let env_name = env_name.trim();
    (!env_name.is_empty()).then_some(env_name)
}

fn is_origin_auth_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("x-api-key")
        || name.eq_ignore_ascii_case("api-key")
        || name.eq_ignore_ascii_case("x-goog-api-key")
        || name.eq_ignore_ascii_case("cookie")
}

fn is_replaceable_origin_auth_header(name: &str) -> bool {
    is_origin_auth_header(name) && !name.eq_ignore_ascii_case("cookie")
}

fn sensitive_header_value(
    value: &str,
    source: &str,
) -> Result<reqwest::header::HeaderValue, String> {
    let mut header = reqwest::header::HeaderValue::from_str(value)
        .map_err(|_| format!("{source} is not a valid HTTP header value"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn reject_unsafe_override_header(name: &reqwest::header::HeaderName) -> Result<(), String> {
    if matches!(
        name.as_str(),
        "accept-encoding"
            | "connection"
            | "content-length"
            | "host"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) {
        return Err(format!("upstream header '{name}' cannot be overridden"));
    }
    Ok(())
}

pub(crate) fn parse_base(value: &str, protocol: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(value.trim())
        .map_err(|_| format!("{protocol} upstream is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(format!(
            "{protocol} upstream must use http or https and include a host"
        ));
    }
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{protocol} upstream must not contain credentials or a fragment"
        ));
    }
    if url.scheme() == "http"
        && !url.host_str().is_some_and(is_loopback_host)
        && std::env::var("PENTECT_ALLOW_INSECURE_UPSTREAM").as_deref() != Ok("1")
    {
        return Err(format!(
            "remote {protocol} upstream must use https (set PENTECT_ALLOW_INSECURE_UPSTREAM=1 to override)"
        ));
    }
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub(crate) fn join_url(
    base: &reqwest::Url,
    path_and_query: &str,
    protocol: &str,
) -> Result<reqwest::Url, String> {
    let (request_path, request_query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
    let base_query = base.query().map(str::to_string);
    let mut without_query = base.clone();
    without_query.set_query(None);
    let mut joined = without_query.as_str().trim_end_matches('/').to_string();
    let request_path = strip_duplicate_api_version(&without_query, request_path);
    if !request_path.starts_with('/') && !request_path.is_empty() {
        joined.push('/');
    }
    joined.push_str(request_path);
    let mut joined = reqwest::Url::parse(&joined)
        .map_err(|_| format!("could not construct {protocol} upstream URL"))?;
    let query = match (base_query.as_deref(), request_query) {
        (Some(base), Some(request)) if !base.is_empty() && !request.is_empty() => {
            Some(format!("{base}&{request}"))
        }
        (Some(base), _) if !base.is_empty() => Some(base.to_string()),
        (_, Some(request)) if !request.is_empty() => Some(request.to_string()),
        _ => None,
    };
    joined.set_query(query.as_deref());
    Ok(joined)
}

fn strip_duplicate_api_version<'a>(base: &reqwest::Url, request_path: &'a str) -> &'a str {
    let request = request_path.trim_start_matches('/');
    let (first, remainder) = request.split_once('/').unwrap_or((request, ""));
    let is_version = first
        .strip_prefix('v')
        .and_then(|suffix| suffix.as_bytes().first())
        .is_some_and(u8::is_ascii_digit)
        && first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    let base_last = base.path().trim_end_matches('/').rsplit('/').next();
    if is_version && base_last == Some(first) {
        remainder
    } else {
        request_path
    }
}

pub(crate) fn client(protocol: &str) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(UPSTREAM_READ_TIMEOUT)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .tcp_nodelay(true);

    if let Some(path) = nonempty_path_env(CA_CERT_ENV) {
        let pem = read_transport_file(&path, CA_CERT_ENV)?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|_| format!("{CA_CERT_ENV} is not a valid PEM certificate bundle"))?;
        if certificates.is_empty() {
            return Err(format!("{CA_CERT_ENV} contains no certificates"));
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }

    if let Some(path) = nonempty_path_env(IDENTITY_ENV) {
        let mut pem = read_transport_file(&path, IDENTITY_ENV)?;
        let identity = reqwest::Identity::from_pem(&pem).map_err(|_| {
            format!("{IDENTITY_ENV} must contain a PEM client certificate and private key")
        });
        pem.zeroize();
        let identity = identity?;
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map_err(|_| format!("could not build {protocol} upstream client"))
}

fn nonempty_path_env(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

fn read_transport_file(path: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|_| format!("could not read {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvRestore {
        name: &'static str,
        value: Option<std::ffi::OsString>,
    }

    impl EnvRestore {
        fn set(name: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self {
                name,
                value: previous,
            }
        }

        fn remove(name: &'static str) -> Self {
            let previous = std::env::var_os(name);
            std::env::remove_var(name);
            Self {
                name,
                value: previous,
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.value {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    #[test]
    fn bifrost_base_paths_are_preserved_for_both_protocols() {
        let openai = parse_base("http://127.0.0.1:8080/openai/v1", "OpenAI Responses").unwrap();
        assert_eq!(
            join_url(&openai, "/responses?stream=true", "OpenAI Responses")
                .unwrap()
                .as_str(),
            "http://127.0.0.1:8080/openai/v1/responses?stream=true"
        );

        let anthropic =
            parse_base("http://localhost:8080/anthropic", "Anthropic Messages").unwrap();
        assert_eq!(
            join_url(&anthropic, "/v1/messages", "Anthropic Messages")
                .unwrap()
                .as_str(),
            "http://localhost:8080/anthropic/v1/messages"
        );
    }

    #[test]
    fn authorization_override_detection_is_case_and_whitespace_insensitive() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let _unset = EnvRestore::remove(AUTHORIZATION_ENV);
        assert!(has_authorization_override(&[
            "authorization=GATEWAY_AUTH".to_string()
        ]));
        assert!(has_authorization_override(&[
            " Authorization = GATEWAY_AUTH ".to_string()
        ]));
        assert!(!has_authorization_override(&[
            "x-api-key=GATEWAY_KEY".to_string()
        ]));
        assert!(!has_authorization_override(&["authorization".to_string()]));
        {
            let _authorization = EnvRestore::set(AUTHORIZATION_ENV, "Bearer gateway-token");
            assert!(has_authorization_override(&[]));
        }
        {
            let _authorization = EnvRestore::set(AUTHORIZATION_ENV, "");
            assert!(
                has_authorization_override(&[]),
                "an empty control value explicitly removes origin authorization"
            );
        }
    }

    #[test]
    fn duplicate_api_version_prefix_is_joined_once() {
        let base = parse_base("https://gateway.example/openai/v1", "OpenAI Responses").unwrap();
        assert_eq!(
            join_url(
                &base,
                "/v1/chat/completions?stream=true",
                "OpenAI Responses"
            )
            .unwrap()
            .as_str(),
            "https://gateway.example/openai/v1/chat/completions?stream=true"
        );
        assert_eq!(
            join_url(&base, "/api/v1/chat/completions", "OpenAI Responses")
                .unwrap()
                .as_str(),
            "https://gateway.example/openai/v1/api/v1/chat/completions"
        );
    }

    #[test]
    fn header_source_env_name_extracts_only_the_environment_name() {
        assert_eq!(
            header_source_env_name("x-api-key= ANTHROPIC_API_KEY "),
            Some("ANTHROPIC_API_KEY")
        );
        assert_eq!(header_source_env_name("x-api-key="), None);
        assert_eq!(header_source_env_name("ANTHROPIC_API_KEY"), None);
    }

    #[test]
    fn upstream_read_timeout_allows_long_reasoning_gaps() {
        assert_eq!(UPSTREAM_READ_TIMEOUT, std::time::Duration::from_secs(600));
    }

    #[test]
    fn credentials_fragments_and_remote_plaintext_are_rejected() {
        assert!(parse_base("https://user:secret@example.test/v1", "OpenAI Responses").is_err());
        assert!(parse_base("https://example.test/v1#secret", "OpenAI Responses").is_err());
        assert!(parse_base("http://example.test/v1", "OpenAI Responses").is_err());
        assert!(parse_base("http://[::1]:8080/v1", "OpenAI Responses").is_ok());
    }

    #[test]
    fn authorization_can_be_removed_or_replaced_without_exposing_the_value() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        {
            let _env = EnvRestore::set(AUTHORIZATION_ENV, "");
            let overrides = header_overrides(&[]).unwrap();
            assert!(!overrides.forward_incoming_header("authorization"));
        }
        {
            let _env = EnvRestore::set(AUTHORIZATION_ENV, "Bearer gateway-token");
            let overrides = header_overrides(&[]).unwrap();
            assert!(!overrides.forward_incoming_header("authorization"));
            assert!(!overrides.forward_incoming_header("x-api-key"));
            assert!(overrides.forward_incoming_header("anthropic-version"));
            assert!(overrides.values[0].value.as_ref().unwrap().is_sensitive());
        }
    }

    #[test]
    fn named_header_reads_secret_from_environment() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let _secret = EnvRestore::set("PENTECT_TEST_BIFROST_KEY", "bf-test-key");
        let overrides =
            header_overrides(&["x-bf-vk=PENTECT_TEST_BIFROST_KEY".to_string()]).unwrap();
        assert!(!overrides.forward_incoming_header("X-BF-VK"));
        assert!(!overrides.forward_incoming_header("authorization"));
        assert!(overrides.values[0].value.as_ref().unwrap().is_sensitive());
        let request = overrides
            .apply(reqwest::Client::new().get("https://example.test"))
            .build()
            .unwrap();
        assert_eq!(request.headers().get("x-bf-vk").unwrap(), "bf-test-key");

        let mut command = std::process::Command::new("example");
        command.env("PENTECT_TEST_BIFROST_KEY", "bf-test-key");
        hide_header_source_env(
            &mut command,
            &["x-bf-vk=PENTECT_TEST_BIFROST_KEY".to_string()],
        );
        assert!(command
            .get_envs()
            .any(|(name, value)| name == "PENTECT_TEST_BIFROST_KEY" && value.is_none()));
    }

    #[test]
    fn named_header_rejects_missing_values_and_transport_headers() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("PENTECT_TEST_MISSING_KEY");
        assert!(header_overrides(&["x-bf-vk=PENTECT_TEST_MISSING_KEY".to_string()]).is_err());
        assert!(header_overrides(&["host=PENTECT_TEST_MISSING_KEY".to_string()]).is_err());
        assert!(
            header_overrides(&["accept-encoding=PENTECT_TEST_MISSING_KEY".to_string()]).is_err()
        );
    }

    #[test]
    fn provider_env_key_becomes_a_bearer_header() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let _secret = EnvRestore::set("PENTECT_TEST_PROVIDER_KEY", "provider-test-key");
        let overrides =
            header_overrides_with_bearer_env(&[], Some("PENTECT_TEST_PROVIDER_KEY")).unwrap();
        let request = overrides
            .apply(reqwest::Client::new().get("https://example.test"))
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap(),
            "Bearer provider-test-key"
        );
        assert!(!overrides.forward_incoming_header("authorization"));
    }

    #[test]
    fn explicit_header_override_takes_precedence_over_provider_env_key() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let _explicit = EnvRestore::set("PENTECT_TEST_EXPLICIT_KEY", "explicit-test-key");
        std::env::remove_var("PENTECT_TEST_PROVIDER_MISSING");
        let overrides = header_overrides_with_bearer_env(
            &["x-api-key=PENTECT_TEST_EXPLICIT_KEY".to_string()],
            Some("PENTECT_TEST_PROVIDER_MISSING"),
        )
        .unwrap();
        let request = overrides
            .apply(reqwest::Client::new().get("https://example.test"))
            .build()
            .unwrap();
        assert_eq!(
            request.headers().get("x-api-key").unwrap(),
            "explicit-test-key"
        );
        assert!(request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
    }
}
