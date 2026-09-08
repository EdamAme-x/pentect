pub(crate) const HANDLE_CONTRACT: &str = r#"Pentect replaced local sensitive values with opaque handles such as <<LABEL_HASH>>. A handle in a file or tool result is intentional protected content: it does not mean the file is corrupted, truncated, or invalid. Treat the surrounding content normally and preserve every handle byte-for-byte when reading, reasoning about, or editing it. Do not delete, repair, expand, guess, or reformat a handle. For native writes or edits, supply the complete desired file content with ordinary handles intact; a value represented by a handle is not missing or empty. In code or patch text, keep an ordinary handle as one complete quoted data argument or string, never as syntax or eval input. If Pentect cannot conservatively represent the value there, append |base64 before the closing >>, keep that explicit view as one complete quoted data value, and decode it locally through argv, stdin, or another data API. This explicit suffix is the only supported edit to a handle. The original value is not visible to the model and must not be printed or guessed."#;

#[cfg(test)]
mod tests {
    use super::HANDLE_CONTRACT;

    #[test]
    fn contract_explains_file_handles_without_exposing_values() {
        assert!(HANDLE_CONTRACT.contains("does not mean the file is corrupted"));
        assert!(HANDLE_CONTRACT.contains("preserve every handle byte-for-byte"));
        assert!(HANDLE_CONTRACT.contains("must not be printed or guessed"));
        assert!(HANDLE_CONTRACT.contains("complete desired file content with ordinary handles"));
        assert!(HANDLE_CONTRACT.contains("append |base64 before the closing >>"));
    }
}
