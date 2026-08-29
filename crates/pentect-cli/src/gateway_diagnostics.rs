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

fn failure_kind(error: &str) -> (&'static str, bool) {
    let lower = error.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        ("timeout", true)
    } else if lower.contains("connection failed") || lower.contains("could not reach") {
        ("connect", true)
    } else if lower.contains("stream failed") {
        ("stream", true)
    } else if lower.contains("invalid response body")
        || lower.contains("could not read") && lower.contains("response")
    {
        ("response-body", true)
    } else if is_local_rejection(error) {
        ("policy", false)
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
