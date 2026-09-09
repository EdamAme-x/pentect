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
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const MAX_RESTORED_TOOL_INPUT_BYTES: usize = 32 * 1024 * 1024;

/// The data contract of the operation receiving a tool input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolInputKind {
    Data,
    /// Provider prose/output: current snapshot only, with no trusted-file reads.
    PassiveData,
    RawFile,
    Code,
    Patch,
    Unknown,
}

/// The explicit representation requested by a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleView {
    Raw,
    Base64,
}

/// Errors are intentionally value-free: neither a handle nor resolved data is
/// included in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolInputError {
    UnknownSurface,
    MalformedView,
    UnsupportedView,
    UnknownHandle,
    RecoveryDisabled,
    RecoverySourceChanged,
    RecoverySourceUnavailable,
    RecoveryScopeChanged,
    RecoveryStoreUnavailable,
    RecoveryLimitExceeded,
    OutputTooLarge,
}

impl fmt::Display for ToolInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownSurface => "protected handle use is unsupported for this tool surface",
            Self::MalformedView => "protected handle view is malformed",
            Self::UnsupportedView => "protected handle view is unsupported for this operation",
            Self::UnknownHandle => "protected handle is unavailable in this session; reread the original input",
            Self::RecoveryDisabled => "file recovery is disabled; reread the original input in this session",
            Self::RecoverySourceChanged => "protected handle source has changed; reread it to obtain a new handle",
            Self::RecoverySourceUnavailable => "protected handle source cannot be read; restore access or reread the original input",
            Self::RecoveryScopeChanged => "protected handle belongs to a different identity scope; reread the original input in this session",
            Self::RecoveryStoreUnavailable => "protected handle recovery store is unavailable; restart the protected session and reread the original input",
            Self::RecoveryLimitExceeded => "protected handle recovery exceeds this response's read limit; reread only the required sources",
            Self::OutputTooLarge => "protected tool input is too large after restoration",
        })
    }
}

impl ToolInputError {
    /// The processor never executes a tool.  Callers can use this invariant
    /// when turning a rejection into their normal retryable tool error.
    pub const fn executed(self) -> bool {
        false
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
        checked_append(&mut output, &input[cursor..span.start])?;
        let rendered =
            Zeroizing::new(resolver.resolve_view(&span.handle, handle_view_from_core(span.kind))?);
        validate_rendered(kind, span.kind, &rendered)?;
        checked_append(&mut output, &rendered)?;
        cursor = span.end;
    }
    checked_append(&mut output, &input[cursor..])?;
    let text = output.as_str().to_owned();
    output.zeroize();
    Ok(ValidatedToolInput {
        text,
        executed: false,
    })
}

fn checked_append(output: &mut String, value: &str) -> Result<(), ToolInputError> {
    if output.len().saturating_add(value.len()) > MAX_RESTORED_TOOL_INPUT_BYTES {
        output.zeroize();
        return Err(ToolInputError::OutputTooLarge);
    }
    output.push_str(value);
    Ok(())
}

/// Runtime adapter that lets a gateway declare the operation surface while core owns
/// the authenticated handle/view mapping and encoding.
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
    for span in &spans {
        if span.kind == RecoveryViewKind::Raw {
            let rendered = Zeroizing::new(recovery.resolve(&span.handle));
            validate_rendered(kind, span.kind, &rendered)?;
        }
    }
    let text = Zeroizing::new(
        recovery
            .resolve_with_views(input)
            .map_err(|error| match error {
                pentect_core::RecoveryViewError::Malformed => ToolInputError::MalformedView,
                pentect_core::RecoveryViewError::UnknownHandle => ToolInputError::UnknownHandle,
                pentect_core::RecoveryViewError::UnknownView => ToolInputError::MalformedView,
                pentect_core::RecoveryViewError::OutputTooLarge => ToolInputError::OutputTooLarge,
            })?,
    );
    Ok(ValidatedToolInput {
        text: text.to_string(),
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
    }
}

fn validate_surface(
    kind: ToolInputKind,
    spans: &[RecoveryViewToken],
) -> Result<(), ToolInputError> {
    for span in spans {
        let supported = match kind {
            ToolInputKind::Data | ToolInputKind::PassiveData | ToolInputKind::RawFile => {
                matches!(span.kind, RecoveryViewKind::Raw | RecoveryViewKind::Base64)
            }
            ToolInputKind::Code | ToolInputKind::Patch => {
                matches!(span.kind, RecoveryViewKind::Raw | RecoveryViewKind::Base64)
            }
            ToolInputKind::Unknown => return Err(ToolInputError::UnknownSurface),
        };
        if !supported {
            return Err(ToolInputError::UnsupportedView);
        }
    }
    Ok(())
}

fn validate_rendered(
    kind: ToolInputKind,
    view: RecoveryViewKind,
    rendered: &str,
) -> Result<(), ToolInputError> {
    if matches!(kind, ToolInputKind::Code | ToolInputKind::Patch)
        && view == RecoveryViewKind::Raw
        && !raw_code_representation_supported(rendered)
    {
        return Err(ToolInputError::UnsupportedView);
    }
    Ok(())
}

/// Conservative representation guard for a raw handle embedded as one quoted
/// data value in code or a patch. This is not a shell or language parser and
/// does not make arbitrary interpolation safe.
pub fn raw_code_representation_supported(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'.' | b'/' | b':' | b'@' | b'+' | b'=' | b',' | b'-'
                )
        })
}

/// Classify only argument fields whose data contract Pentect knows. Unknown
/// tools and fields remain inert rather than receiving speculative recovery.
pub fn classify_tool_input_field(tool_name: &str, field: &str) -> ToolInputKind {
    let tool = tool_name.to_ascii_lowercase().replace('-', "_");
    let field = field.to_ascii_lowercase();
    if matches!(
        tool.as_str(),
        "bash" | "shell" | "powershell" | "exec" | "exec_command" | "run_command" | "terminal"
    ) {
        return match field.as_str() {
            "command" | "cmd" | "script" => ToolInputKind::Code,
            "cwd" | "workdir" | "working_directory" => ToolInputKind::Data,
            _ => ToolInputKind::Unknown,
        };
    }
    if matches!(tool.as_str(), "apply_patch" | "patch") {
        return matches!(field.as_str(), "patch" | "patchtext" | "input" | "command")
            .then_some(ToolInputKind::Patch)
            .unwrap_or(ToolInputKind::Unknown);
    }
    if matches!(
        tool.as_str(),
        "edit" | "edit_file" | "multiedit" | "multi_edit"
    ) {
        return match field.as_str() {
            "old_string" | "oldstring" | "old_text" | "oldtext" | "new_string" | "newstring"
            | "new_text" | "newtext" => ToolInputKind::RawFile,
            "path" | "file_path" | "filepath" => ToolInputKind::Data,
            _ => ToolInputKind::Unknown,
        };
    }
    if matches!(tool.as_str(), "write" | "write_file" | "create_file") {
        return match field.as_str() {
            "content" | "data" | "text" => ToolInputKind::RawFile,
            "path" | "file_path" | "filepath" => ToolInputKind::Data,
            _ => ToolInputKind::Unknown,
        };
    }
    if matches!(tool.as_str(), "read" | "read_file")
        && matches!(field.as_str(), "path" | "file_path" | "filepath")
    {
        return ToolInputKind::Data;
    }
    ToolInputKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashMap;

    fn resolver(handle: &str, view: HandleView) -> Result<String, ToolInputError> {
        match (handle, view) {
            ("<<KEY_abcdef0123456789>>", HandleView::Base64) => Ok("c2VjcmV0".into()),
            ("<<KEY_abcdef0123456789>>", HandleView::Raw) => Ok("secret".into()),
            _ => Err(ToolInputError::UnknownHandle),
        }
    }

    #[test]
    fn code_allows_base64_and_conservative_raw_values() {
        let input = "python -c 'decode(\"<<KEY_abcdef0123456789|base64>>\")'";
        let result = process_tool_input(input, ToolInputKind::Code, &resolver).unwrap();
        assert_eq!(result.text, "python -c 'decode(\"c2VjcmV0\")'");
        assert!(!result.executed);
        assert_eq!(
            process_tool_input(
                "echo <<KEY_abcdef0123456789>>",
                ToolInputKind::Code,
                &resolver
            )
            .unwrap()
            .text,
            "echo secret"
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
    }

    #[test]
    fn powershell_command_is_a_declared_code_surface() {
        assert_eq!(
            classify_tool_input_field("PowerShell", "command"),
            ToolInputKind::Code
        );
        assert_eq!(
            classify_tool_input_field("PowerShell", "metadata"),
            ToolInputKind::Unknown
        );
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
