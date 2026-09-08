//! Validation boundary for explicit handle views in completed tool inputs.
//!
//! This module deliberately does not infer a tool's language, shell, or
//! command semantics.  A caller supplies the operation kind and a resolver
//! supplied by the core recovery implementation.  Validation happens for the
//! complete input before the resolver is called, so a late failure cannot
//! publish a partially resolved tool input.

use pentect_core::{
    scan_recovery_views, Recovery, RecoveryViewKind, RecoveryViewScanError, RecoveryViewToken,
};
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

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
    InvalidOperationContext,
}

impl fmt::Display for ToolInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownSurface => "protected handle use is unsupported for this tool surface",
            Self::MalformedView => "protected handle view is malformed",
            Self::UnsupportedView => "protected handle view is unsupported for this operation",
            Self::UnknownHandle => "protected handle is unavailable in this session",
            Self::RetryLimit => "the same protected operation exceeded its retry limit",
            Self::InvalidOperationContext => "protected operation identity is invalid",
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
        matches!(self, Self::MalformedView | Self::UnsupportedView)
    }
}

/// A validated input ready for the caller's local execution path.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedToolInput {
    pub text: String,
    pub executed: bool,
}

impl fmt::Debug for ValidatedToolInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedToolInput")
            .field("text", &"<redacted>")
            .field("executed", &self.executed)
            .finish()
    }
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
        if context.session_id.is_empty()
            || context.operation_id.is_empty()
            || context.session_id.len() > 256
            || context.operation_id.len() > 256
        {
            return Err(ToolInputError::InvalidOperationContext);
        }
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

    pub fn finish(&mut self, context: &OperationContext) {
        self.attempts.remove(context);
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

    // No output is published until every view has passed the surface policy
    // and every resolver lookup succeeds. The temporary is zeroized if a
    // later resolver fails.
    let mut output = Zeroizing::new(String::with_capacity(input.len()));
    let mut cursor = 0;
    for span in spans {
        output.push_str(&input[cursor..span.start]);
        let rendered =
            Zeroizing::new(resolver.resolve_view(&span.handle, handle_view_from_core(span.kind))?);
        output.push_str(&rendered);
        cursor = span.end;
    }
    output.push_str(&input[cursor..]);
    let text = output.as_str().to_owned();
    output.zeroize();
    Ok(ValidatedToolInput {
        text,
        executed: false,
    })
}

/// Runtime adapter for the core recovery implementation.  This is the
/// production entry point: callers still declare the operation surface here,
/// while core owns the authenticated handle/view mapping and encoding.
pub fn process_recovery_tool_input(
    input: &str,
    kind: ToolInputKind,
    recovery: &Recovery,
) -> Result<ValidatedToolInput, ToolInputError> {
    let spans = scan_views(input)?;
    validate_surface(kind, &spans)?;
    let known: std::collections::HashSet<_> = recovery.placeholders().into_iter().collect();
    if spans.iter().any(|span| !known.contains(&span.handle)) {
        return Err(ToolInputError::UnknownHandle);
    }
    let text = recovery
        .resolve_with_views(input)
        .map_err(|error| match error {
            pentect_core::RecoveryViewError::Malformed => ToolInputError::MalformedView,
            pentect_core::RecoveryViewError::UnknownHandle => ToolInputError::UnknownHandle,
            pentect_core::RecoveryViewError::UnknownView => ToolInputError::MalformedView,
        })?;
    Ok(ValidatedToolInput {
        text,
        executed: false,
    })
}

fn scan_views(input: &str) -> Result<Vec<RecoveryViewToken>, ToolInputError> {
    let spans = scan_recovery_views(input).map_err(|error| match error {
        RecoveryViewScanError::Malformed
        | RecoveryViewScanError::UnknownView
        | RecoveryViewScanError::Limit => ToolInputError::MalformedView,
    })?;
    Ok(spans)
}

fn handle_view_from_core(kind: RecoveryViewKind) -> HandleView {
    match kind {
        RecoveryViewKind::Raw => HandleView::Raw,
        RecoveryViewKind::Base64 => HandleView::Base64,
        RecoveryViewKind::Json => HandleView::Json,
    }
}

fn validate_surface(
    kind: ToolInputKind,
    spans: &[RecoveryViewToken],
) -> Result<(), ToolInputError> {
    for span in spans {
        let supported = match kind {
            ToolInputKind::Data | ToolInputKind::RawFile => {
                matches!(span.kind, RecoveryViewKind::Raw | RecoveryViewKind::Base64)
            }
            ToolInputKind::JsonTemplate => matches!(span.kind, RecoveryViewKind::Json),
            ToolInputKind::Code => matches!(span.kind, RecoveryViewKind::Base64),
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
    use std::collections::HashMap;

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
        assert!(ToolInputError::UnsupportedView.retryable());
        assert_eq!(
            process_tool_input(
                "echo <<KEY_abcdef0123456789|json>>",
                ToolInputKind::Code,
                &resolver
            ),
            Err(ToolInputError::UnsupportedView)
        );
        assert_eq!(
            process_tool_input(
                "{\"api_key\":<<KEY_abcdef0123456789|json>>}",
                ToolInputKind::JsonTemplate,
                &resolver,
            )
            .unwrap()
            .text,
            "{\"api_key\":\"secret\"}"
        );
    }

    #[test]
    fn unknown_surface_rejects_without_calling_resolver() {
        let calls = Cell::new(0);
        let result = process_tool_input(
            "payload <<KEY_abcdef0123456789|base64>>",
            ToolInputKind::Unknown,
            &|_: &str, _: HandleView| {
                calls.set(calls.get() + 1);
                Ok("unexpected".into())
            },
        );
        assert_eq!(result, Err(ToolInputError::UnknownSurface));
        assert_eq!(calls.get(), 0);
        assert!(!ToolInputError::UnknownSurface.executed());
        assert!(!ToolInputError::UnknownSurface.retryable());
    }

    #[test]
    fn malformed_views_and_nonhandles_are_distinguished() {
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
            process_tool_input(
                "x <<KEY_abcdef0123456789|base64",
                ToolInputKind::Data,
                &resolve,
            ),
            Err(ToolInputError::MalformedView)
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            process_tool_input("x << not a handle", ToolInputKind::Data, &resolve)
                .unwrap()
                .text,
            "x << not a handle"
        );
    }

    #[test]
    fn late_resolution_failure_publishes_no_partial_output() {
        let calls = Cell::new(0);
        let result = process_tool_input(
            "a <<KEY_abcdef0123456789|base64>> b <<OTHER_abcdef0123456789|base64>>",
            ToolInputKind::Code,
            &|handle: &str, _view: HandleView| {
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
        assert!(!ToolInputError::RetryLimit.retryable());
        tracker.record(&second).unwrap();
        assert_eq!(tracker.attempts(&second), 1);
        tracker.finish(&second);
        assert_eq!(tracker.attempts(&second), 0);
        assert_eq!(
            tracker.record(&OperationContext::new("", "operation")),
            Err(ToolInputError::InvalidOperationContext)
        );
        assert_eq!(
            tracker.record(&OperationContext::new("session", "x".repeat(257))),
            Err(ToolInputError::InvalidOperationContext)
        );
    }

    #[test]
    fn recovery_adapter_rejects_unknown_raw_and_handles_full_placeholder_grammar() {
        let mut values = HashMap::new();
        let long_handle =
            "<<KEY_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef>>";
        values.insert(long_handle.to_string(), "synthetic-64".to_string());
        let hinted = "<<KEY_abcdef0123456789_length_12_chars>>";
        values.insert(hinted.to_string(), "synthetic-hint".to_string());
        let recovery = Recovery::seal(values, &[9u8; 32]);

        assert_eq!(
            process_recovery_tool_input(
                "x <<KEY_deadbeefdeadbeef>>",
                ToolInputKind::Data,
                &recovery,
            ),
            Err(ToolInputError::UnknownHandle)
        );
        assert_eq!(
            process_recovery_tool_input(
                "<<KEY_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|base64>>",
                ToolInputKind::Code,
                &recovery,
            )
            .unwrap()
            .text,
            data_encoding::BASE64.encode(b"synthetic-64")
        );
        assert_eq!(
            process_recovery_tool_input(
                "<<KEY_abcdef0123456789_length_12_chars|json>>",
                ToolInputKind::JsonTemplate,
                &recovery,
            )
            .unwrap()
            .text,
            "\"synthetic-hint\""
        );
    }

    #[test]
    fn ordinary_syntax_and_incomplete_view_are_distinguished() {
        let recovery = Recovery::empty_for_key(&[8u8; 32]);
        let heredoc = "cat <<EOF | sed 's/x/y/'\nEOF";
        assert_eq!(
            process_recovery_tool_input(heredoc, ToolInputKind::Data, &recovery)
                .unwrap()
                .text,
            heredoc
        );
        assert_eq!(
            process_recovery_tool_input(
                "<<KEY_abcdef0123456789|base64",
                ToolInputKind::Code,
                &recovery,
            ),
            Err(ToolInputError::MalformedView)
        );
        assert_eq!(
            process_recovery_tool_input(
                "unicode 東京 <<not-a-handle>>",
                ToolInputKind::Data,
                &recovery
            )
            .unwrap()
            .text,
            "unicode 東京 <<not-a-handle>>"
        );
    }
}
