use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Reads a regular file without allowing metadata races or chunked sources to
/// exceed the caller's hard byte limit.
pub fn read_bounded_bytes(path: &Path, max_bytes: u64, kind: &str) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("could not read {kind} '{}': {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("could not inspect {kind} '{}': {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{kind} '{}' is not a regular file", path.display()));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "{kind} '{}' exceeds {max_bytes} bytes",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read {kind} '{}': {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{kind} '{}' exceeds {max_bytes} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Reads a bounded regular file and rejects non-UTF-8 data.
pub fn read_bounded_utf8(path: &Path, max_bytes: u64, kind: &str) -> Result<String, String> {
    let bytes = read_bounded_bytes(path, max_bytes, kind)?;
    String::from_utf8(bytes).map_err(|_| format!("{kind} '{}' is not UTF-8", path.display()))
}

/// Hashes a file with fixed memory use.
pub fn sha256_file(path: &Path, kind: &str) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("could not verify {kind} '{}': {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("could not verify {kind} '{}': {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(data_encoding::HEXLOWER.encode(&digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_rejects_oversized_files() {
        let path =
            std::env::temp_dir().join(format!("pentect-bounded-read-{}", std::process::id()));
        std::fs::write(&path, b"12345").unwrap();
        let error = read_bounded_bytes(&path, 4, "test file").unwrap_err();
        assert!(error.contains("exceeds 4 bytes"), "{error}");
        std::fs::remove_file(path).unwrap();
    }
}
