//! Value-free HTTP gateway diagnostics shared by provider adapters.
//!
//! Never pass request/response bodies, headers, URLs, credentials, or raw
//! error messages to the persistent activity log. This module converts them
//! into a fixed vocabulary before recording anything.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestContext {
    pub(crate) endpoint: &'static str,
    pub(crate) method: &'static str,
}

pub(crate) fn method_name(method: &hyper::Method) -> &'static str {
    match *method {
        hyper::Method::GET => "GET",
        hyper::Method::POST => "POST",
        hyper::Method::PUT => "PUT",
        hyper::Method::PATCH => "PATCH",
        hyper::Method::DELETE => "DELETE",
        hyper::Method::HEAD => "HEAD",
        hyper::Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

pub(crate) fn record_request_failure(
    surface: &'static str,
    context: RequestContext,
    error: &str,
    response_status: u16,
) {
    let local_rejection = is_local_rejection(error);
    let (kind, retryable) = failure_kind(error);
    record(
        surface,
        if local_rejection {
            "request-rejected"
        } else {
            "request-failed"
        },
        kind,
        context,
        Some(response_status),
        retryable,
    );
}

pub(crate) fn record_upstream_status(
    surface: &'static str,
    context: RequestContext,
    status: reqwest::StatusCode,
) {
    if status.is_success() {
        return;
    }
    let (kind, retryable) = status_kind(status.as_u16());
    record(
        surface,
        "upstream-response",
        kind,
        context,
        Some(status.as_u16()),
        retryable,
    );
}

pub(crate) fn record(
    surface: &'static str,
    event: &'static str,
    kind: &'static str,
    context: RequestContext,
    status: Option<u16>,
    retryable: bool,
) {
    pentect_agent::record_http_diagnostic_activity(
        surface,
        event,
        kind,
        context.endpoint,
        context.method,
        status,
        retryable,
        env!("CARGO_PKG_VERSION"),
    );
}

pub(crate) fn is_local_rejection(error: &str) -> bool {
    error.starts_with("image blocked:")
        || error.starts_with("document blocked:")
        || error.starts_with("remote ")
        || error.starts_with("OpenAI file ")
        || error.starts_with("file upload blocked:")
        || error.starts_with("Files API upload ")
        || error.starts_with("plugin blocked:")
        || error.starts_with("request body blocked:")
        || error.starts_with("unknown format blocked:")
}

pub(crate) fn failure_status(error: &str) -> hyper::StatusCode {
    if is_local_rejection(error) || matches!(failure_kind(error).0, "protocol" | "limit" | "plugin")
    {
        hyper::StatusCode::UNPROCESSABLE_ENTITY
    } else {
        hyper::StatusCode::BAD_GATEWAY
    }
}

fn failure_kind(error: &str) -> (&'static str, bool) {
    let lower = error.to_ascii_lowercase();
    if error.starts_with("unknown format blocked: OpenAI endpoint is not supported")
        || error.starts_with("unknown format blocked: Anthropic endpoint is not supported")
        || error.starts_with("unknown format blocked: Gemini endpoint is not supported")
        || error.starts_with("unknown format blocked: Google Cloud Code endpoint is not supported")
    {
        ("unsupported-endpoint", false)
    } else if is_local_rejection(error) {
        ("policy", false)
    } else if lower.contains("timed out") || lower.contains("timeout") {
        ("timeout", true)
    } else if lower.contains("connection failed") || lower.contains("could not reach") {
        ("connect", true)
    } else if lower.contains("stream failed") {
        ("stream", true)
    } else if lower.contains("invalid response body")
        || lower.contains("could not read") && lower.contains("response")
    {
        ("response-body", true)
    } else if lower.contains("too large") || lower.contains("exceeded limit") {
        ("limit", false)
    } else if lower.contains("plugin") {
        ("plugin", false)
    } else if lower.contains("invalid json")
        || lower.contains("not valid json")
        || lower.contains("unsupported content encoding")
        || lower.contains("unsupported shape")
    {
        ("protocol", false)
    } else if lower.contains("lock was poisoned") || lower.contains("task failed") {
        ("internal", false)
    } else {
        ("unclassified", false)
    }
}

fn status_kind(status: u16) -> (&'static str, bool) {
    match status {
        401 | 403 => ("authentication", false),
        408 => ("timeout", true),
        409 => ("conflict", false),
        429 => ("rate-limit", true),
        500..=599 => ("upstream-server", true),
        400..=499 => ("upstream-client", false),
        300..=399 => ("redirect", false),
        _ => ("unexpected-status", false),
    }
}

/// Classify the explicit verdict, never words in a provider's error message.
pub(crate) fn upstream_error_kind(value: &serde_json::Value) -> (&'static str, bool) {
    let error = value
        .get("error")
        .filter(|error| error.is_object())
        .or_else(|| {
            value
                .get("response")
                .and_then(|r| r.get("error"))
                .filter(|error| error.is_object())
        })
        .unwrap_or(value);
    match error
        .get("code")
        .and_then(serde_json::Value::as_str)
        .or_else(|| error.get("type").and_then(serde_json::Value::as_str))
    {
        Some(
            "invalid_prompt"
            | "cyber_policy"
            | "misalignment_policy_violation"
            | "bio_policy"
            | "content_policy_violation",
        ) => ("policy", false),
        Some("insufficient_quota" | "usage_not_included") => ("quota", false),
        Some("context_length_exceeded") => ("context-limit", false),
        Some("authentication_error" | "permission_error" | "invalid_api_key") => {
            ("authentication", false)
        }
        Some("invalid_request_error") => ("protocol", false),
        Some("rate_limit_error" | "rate_limit_exceeded") => ("rate-limit", true),
        Some(
            "overloaded_error"
            | "api_error"
            | "server_error"
            | "upstream_reset"
            | "upstream_server_error",
        ) => ("upstream-server", true),
        _ => ("unclassified", false),
    }
}

pub(crate) fn record_stream_failure(
    surface: &'static str,
    endpoint: &'static str,
    kind: &'static str,
    retryable: bool,
) {
    record(
        surface,
        "stream-failed",
        kind,
        RequestContext {
            endpoint,
            method: "POST",
        },
        None,
        retryable,
    );
}

/// A disconnected startup channel means the worker exited, not that it timed out.
pub(crate) fn wait_for_startup(
    receiver: &std::sync::mpsc::Receiver<Result<String, String>>,
    name: &str,
) -> Result<String, String> {
    match receiver.recv_timeout(crate::GATEWAY_STARTUP_TIMEOUT) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(format!("{name} initialization timed out"))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(format!(
            "{name} initialization worker exited before readiness"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_failure_is_not_reported_as_a_timeout() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Err("invalid compatibility config".to_string()))
            .unwrap();
        assert_eq!(
            wait_for_startup(&rx, "Test").unwrap_err(),
            "invalid compatibility config"
        );
        drop(tx);
        let error = wait_for_startup(&rx, "Test").unwrap_err();
        assert!(error.contains("worker exited"));
        assert!(!error.contains("timed out"));
    }

    #[test]
    fn failures_are_reduced_to_fixed_safe_categories() {
        assert_eq!(
            failure_kind("could not reach provider: timed out"),
            ("timeout", true)
        );
        assert_eq!(
            failure_kind("could not reach provider: connection failed"),
            ("connect", true)
        );
        assert_eq!(failure_kind("plugin blocked: fixture"), ("policy", false));
        assert_eq!(
            failure_kind("request body blocked: fixture"),
            ("policy", false)
        );
        assert_eq!(
            failure_kind("unknown format blocked: OpenAI endpoint is not supported"),
            ("unsupported-endpoint", false)
        );
        assert_eq!(
            failure_kind("arbitrary secret-bearing detail"),
            ("unclassified", false)
        );
    }

    #[test]
    fn statuses_have_actionable_retry_classification() {
        assert_eq!(status_kind(401), ("authentication", false));
        assert_eq!(status_kind(429), ("rate-limit", true));
        assert_eq!(status_kind(503), ("upstream-server", true));
    }

    #[test]
    fn upstream_verdict_is_not_inferred_from_secret_bearing_message() {
        use serde_json::json;
        for (code, kind, retryable) in [
            ("invalid_prompt", "policy", false),
            ("insufficient_quota", "quota", false),
            ("context_length_exceeded", "context-limit", false),
            ("upstream_reset", "upstream-server", true),
            ("rate_limit_error", "rate-limit", true),
            ("private-key", "unclassified", false),
        ] {
            let error = json!({"code":code,"message":"timeout invalid_prompt private-key"});
            for value in [
                error.clone(),
                json!({"error":error}),
                json!({"response":{"error":error}}),
            ] {
                assert_eq!(upstream_error_kind(&value), (kind, retryable));
            }
        }
        assert_eq!(
            upstream_error_kind(
                &json!({"error":{"code":"upstream_reset"},"response":{"error":{"code":"invalid_prompt"}}})
            ),
            ("upstream-server", true)
        );
    }

    #[test]
    fn local_policy_verdict_wins_over_embedded_transport_words() {
        for detail in ["timeout", "connection failed", "stream failed"] {
            assert_eq!(
                failure_kind(&format!("plugin blocked: {detail}")),
                ("policy", false)
            );
        }
        assert_eq!(
            failure_status("OpenAI tool call has an unsupported shape"),
            hyper::StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            failure_status("could not reach provider: connection failed"),
            hyper::StatusCode::BAD_GATEWAY
        );
    }
}
