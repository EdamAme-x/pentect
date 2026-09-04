pub(crate) const HANDLE_CONTRACT: &str = r#"Pentect replaced local sensitive values with opaque handles such as <<LABEL_HASH>>. A handle in a file or tool result is intentional protected content: it does not mean the file is corrupted, truncated, or invalid. Treat the surrounding content normally and preserve every handle byte-for-byte when reading, reasoning about, or editing it. Do not delete, repair, expand, guess, or reformat a handle. When a local tool needs the represented value, copy the handle unchanged into that tool's input; the local Pentect process can replace a known handle immediately before execution. The original value is not visible to the model and must not be printed or guessed."#;

#[cfg(test)]
mod tests {
    use super::HANDLE_CONTRACT;

    #[test]
    fn contract_explains_file_handles_without_exposing_values() {
        assert!(HANDLE_CONTRACT.contains("does not mean the file is corrupted"));
        assert!(HANDLE_CONTRACT.contains("preserve every handle byte-for-byte"));
        assert!(HANDLE_CONTRACT.contains("must not be printed or guessed"));
    }
}
