//! Shared transport and URL handling for provider-compatible upstreams.

use std::path::Path;

const CA_CERT_ENV: &str = "PENTECT_UPSTREAM_CA_CERT";
const IDENTITY_ENV: &str = "PENTECT_UPSTREAM_IDENTITY";
const AUTHORIZATION_ENV: &str = "PENTECT_UPSTREAM_AUTHORIZATION";

#[derive(Clone)]
pub(crate) enum AuthorizationOverride {
    Forward,
    Remove,
    Replace(reqwest::header::HeaderValue),
}

impl AuthorizationOverride {
    pub(crate) fn forward_incoming_header(&self, name: &str) -> bool {
        matches!(self, Self::Forward) || !is_origin_auth_header(name)
    }

    pub(crate) fn replacement(&self) -> Option<&reqwest::header::HeaderValue> {
        match self {
            Self::Replace(value) => Some(value),
            Self::Forward | Self::Remove => None,
        }
    }
}

fn is_origin_auth_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("x-api-key")
        || name.eq_ignore_ascii_case("api-key")
}

pub(crate) fn authorization_override() -> Result<AuthorizationOverride, String> {
    let Some(value) = std::env::var_os(AUTHORIZATION_ENV) else {
        return Ok(AuthorizationOverride::Forward);
    };
    if value.is_empty() {
        return Ok(AuthorizationOverride::Remove);
    }
    let value = value
        .into_string()
        .map_err(|_| format!("{AUTHORIZATION_ENV} is not valid Unicode"))?;
    let mut header = reqwest::header::HeaderValue::from_str(&value)
        .map_err(|_| format!("{AUTHORIZATION_ENV} is not a valid HTTP header value"))?;
    header.set_sensitive(true);
    Ok(AuthorizationOverride::Replace(header))
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
    if !request_path.starts_with('/') {
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

pub(crate) fn client(protocol: &str) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(60))
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
        let pem = read_transport_file(&path, IDENTITY_ENV)?;
        let identity = reqwest::Identity::from_pem(&pem).map_err(|_| {
            format!("{IDENTITY_ENV} must contain a PEM client certificate and private key")
        })?;
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
            assert!(matches!(
                authorization_override().unwrap(),
                AuthorizationOverride::Remove
            ));
        }
        {
            let _env = EnvRestore::set(AUTHORIZATION_ENV, "Bearer gateway-token");
            let override_value = authorization_override().unwrap();
            assert!(!override_value.forward_incoming_header("authorization"));
            assert!(!override_value.forward_incoming_header("x-api-key"));
            assert!(!override_value.forward_incoming_header("api-key"));
            assert!(override_value.forward_incoming_header("anthropic-version"));
            assert!(override_value.replacement().is_some());
            assert!(override_value.replacement().unwrap().is_sensitive());
        }
    }
}
