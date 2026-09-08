//! Validation boundary for explicit handle views in completed tool inputs.
//!
//! This module deliberately does not infer a tool's language, shell, or
//! command semantics.  A caller supplies the operation kind and a resolver
//! supplied by the core recovery implementation.  Validation happens for the
//! complete input before the resolver is called, so a late failure cannot
//! publish a partially resolved tool input.

use std::collections::HashMap;
use std::fmt;

/// The data contract of the operation receiving a tool input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolInputKind {
    Data,
    RawFile,
    JsonTemplate,
    Code,
    Unknown,
}

/// The explicit representation requested by a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleView {
    Raw,
    Base64,
    Json,
}

/// Stable identity supplied by the caller for one logical operation.
///
/// Retry accounting intentionally does not attempt to compare arbitrary
/// commands or payloads.  Callers must provide the same identity for a retry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OperationContext {
    pub session_id: String,
    pub operation_id: String,
}

impl OperationContext {
    pub fn new(session_id: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            operation_id: operation_id.into(),
        }
    }
}

/// Errors are intentionally value-free: neither a handle nor resolved data is
/// included in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolInputError {
    UnknownSurface,
    MalformedView,
    UnsupportedView,
    UnknownHandle,
    RetryLimit,
}

impl fmt::Display for ToolInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownSurface => "protected handle use is unsupported for this tool surface",
            Self::MalformedView => "protected handle view is malformed",
            Self::UnsupportedView => "protected handle view is unsupported for this operation",
            Self::UnknownHandle => "protected handle is unavailable in this session",
            Self::RetryLimit => "the same protected operation exceeded its retry limit",
        })
    }
}

impl ToolInputError {
    /// The processor never executes a tool.  Callers can use this invariant
    /// when turning a rejection into their normal retryable tool error.
    pub const fn executed(self) -> bool {
        false
    }

    pub const fn retryable(self) -> bool {
        true
    }
}

/// A validated input ready for the caller's local execution path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedToolInput {
    pub text: String,
    pub executed: bool,
}

/// Maximum retries for one explicitly identified operation.
pub const MAX_OPERATION_RETRIES: u8 = 3;
const MAX_TRACKED_OPERATIONS: usize = 1024;

#[derive(Default)]
pub struct RetryTracker {
    attempts: HashMap<OperationContext, u8>,
}

impl RetryTracker {
    /// Records one execution attempt.  Different operation IDs never consume
    /// each other's budget, even when their payloads happen to match.
    pub fn record(&mut self, context: &OperationContext) -> Result<(), ToolInputError> {
        if !self.attempts.contains_key(context) && self.attempts.len() >= MAX_TRACKED_OPERATIONS {
            return Err(ToolInputError::RetryLimit);
        }
        let attempts = self.attempts.entry(context.clone()).or_default();
        if *attempts >= MAX_OPERATION_RETRIES {
            return Err(ToolInputError::RetryLimit);
        }
        *attempts += 1;
        Ok(())
    }

    pub fn attempts(&self, context: &OperationContext) -> u8 {
        self.attempts.get(context).copied().unwrap_or(0)
    }
}

/// Core's recovery implementation supplies this callback.  `view` is explicit
/// and never inferred from a tool name or a substring of the input.
pub trait ViewResolver {
    fn resolve_view(&self, handle: &str, view: HandleView) -> Result<String, ToolInputError>;
}

impl<F> ViewResolver for F
where
    F: Fn(&str, HandleView) -> Result<String, ToolInputError>,
{
    fn resolve_view(&self, handle: &str, view: HandleView) -> Result<String, ToolInputError> {
        self(handle, view)
    }
}

/// Validates and resolves one complete tool input.
pub fn process_tool_input<R: ViewResolver>(
    input: &str,
    kind: ToolInputKind,
    resolver: &R,
) -> Result<ValidatedToolInput, ToolInputError> {
    let spans = scan_views(input)?;
    validate_surface(kind, &spans)?;

    // No output is allocated or published until every view has passed the
    // surface policy and every resolver lookup succeeds.
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for span in spans {
        output.push_str(&input[cursor..span.start]);
        output.push_str(&resolver.resolve_view(&span.handle, span.view)?);
        cursor = span.end;
    }
    output.push_str(&input[cursor..]);
    Ok(ValidatedToolInput {
        text: output,
        executed: false,
    })
}

#[derive(Clone, Debug)]
struct ViewSpan {
    start: usize,
    end: usize,
    handle: String,
    view: HandleView,
}

fn scan_views(input: &str) -> Result<Vec<ViewSpan>, ToolInputError> {
    let mut spans = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = input[cursor..].find("<<") {
        let start = cursor + relative_start;
        let relative_end = input[start + 2..]
            .find(">>")
            .ok_or(ToolInputError::MalformedView)?;
        let end = start + 2 + relative_end + 2;
        let body = &input[start + 2..end - 2];
        let (handle, view) = match body.split_once('|') {
            None => (body, HandleView::Raw),
            Some((handle, name)) => (
                handle,
                match name {
                    "base64" => HandleView::Base64,
                    "json" => HandleView::Json,
                    _ => return Err(ToolInputError::MalformedView),
                },
            ),
        };
        if handle.is_empty() || handle.contains('<') || handle.contains('>') {
            return Err(ToolInputError::MalformedView);
        }
        spans.push(ViewSpan {
            start,
            end,
            handle: format!("<<{handle}>>"),
            view,
        });
        cursor = end;
    }
    Ok(spans)
}

fn validate_surface(kind: ToolInputKind, spans: &[ViewSpan]) -> Result<(), ToolInputError> {
    for span in spans {
        let supported = match kind {
            ToolInputKind::Data | ToolInputKind::RawFile => {
                matches!(span.view, HandleView::Raw | HandleView::Base64)
            }
            ToolInputKind::JsonTemplate => {
                matches!(
                    span.view,
                    HandleView::Raw | HandleView::Base64 | HandleView::Json
                )
            }
            ToolInputKind::Code => matches!(span.view, HandleView::Base64),
            ToolInputKind::Unknown => return Err(ToolInputError::UnknownSurface),
        };
        if !supported {
            return Err(ToolInputError::UnsupportedView);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn resolver(handle: &str, view: HandleView) -> Result<String, ToolInputError> {
        match (handle, view) {
            ("<<KEY_abcdef0123456789>>", HandleView::Base64) => Ok("c2VjcmV0".into()),
            ("<<KEY_abcdef0123456789>>", HandleView::Json) => Ok("\"secret\"".into()),
            ("<<KEY_abcdef0123456789>>", HandleView::Raw) => Ok("secret".into()),
            _ => Err(ToolInputError::UnknownHandle),
        }
    }

    #[test]
    fn code_allows_only_explicit_base64_view() {
        let input = "python -c 'decode(\"<<KEY_abcdef0123456789|base64>>\")'";
        let result = process_tool_input(input, ToolInputKind::Code, &resolver).unwrap();
        assert_eq!(result.text, "python -c 'decode(\"c2VjcmV0\")'");
        assert!(!result.executed);
        assert_eq!(
            process_tool_input(
                "echo <<KEY_abcdef0123456789>>",
                ToolInputKind::Code,
                &resolver
            ),
            Err(ToolInputError::UnsupportedView)
        );
        assert_eq!(
            process_tool_input(
                "echo <<KEY_abcdef0123456789|json>>",
                ToolInputKind::Code,
                &resolver
            ),
            Err(ToolInputError::UnsupportedView)
        );
    }

    #[test]
    fn unknown_surface_rejects_without_calling_resolver() {
        let calls = Cell::new(0);
        let result = process_tool_input(
            "payload <<KEY_abcdef0123456789|base64>>",
            ToolInputKind::Unknown,
            &|_, _| {
                calls.set(calls.get() + 1);
                Ok("unexpected".into())
            },
        );
        assert_eq!(result, Err(ToolInputError::UnknownSurface));
        assert_eq!(calls.get(), 0);
        assert!(!ToolInputError::UnknownSurface.executed());
        assert!(ToolInputError::UnknownSurface.retryable());
    }

    #[test]
    fn malformed_or_unknown_views_are_rejected_before_resolution() {
        let calls = Cell::new(0);
        let resolve = |_: &str, _: HandleView| {
            calls.set(calls.get() + 1);
            Ok("unexpected".to_string())
        };
        assert_eq!(
            process_tool_input(
                "x <<KEY_abcdef0123456789|wat>>",
                ToolInputKind::Data,
                &resolve
            ),
            Err(ToolInputError::MalformedView)
        );
        assert_eq!(
            process_tool_input("x <<KEY_abcdef0123456789", ToolInputKind::Data, &resolve),
            Err(ToolInputError::MalformedView)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn late_resolution_failure_publishes_no_partial_output() {
        let calls = Cell::new(0);
        let result = process_tool_input(
            "a <<KEY_abcdef0123456789|base64>> b <<OTHER_abcdef0123456789|base64>>",
            ToolInputKind::Code,
            &|handle, _| {
                calls.set(calls.get() + 1);
                if handle.starts_with("<<KEY_") {
                    Ok("first".into())
                } else {
                    Err(ToolInputError::UnknownHandle)
                }
            },
        );
        assert_eq!(result, Err(ToolInputError::UnknownHandle));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn retry_budget_is_scoped_to_explicit_session_and_operation() {
        let mut tracker = RetryTracker::default();
        let first = OperationContext::new("s", "one");
        let second = OperationContext::new("s", "two");
        for _ in 0..MAX_OPERATION_RETRIES {
            tracker.record(&first).unwrap();
        }
        assert_eq!(tracker.record(&first), Err(ToolInputError::RetryLimit));
        tracker.record(&second).unwrap();
        assert_eq!(tracker.attempts(&second), 1);
    }
}
