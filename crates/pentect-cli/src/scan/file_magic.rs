use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Prefix16 {
    bytes: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileMagic {
    TextCandidate,
    Binary(&'static str),
}

pub(super) fn classify(bytes: &[u8]) -> FileMagic {
    if bytes.is_empty() {
        return FileMagic::TextCandidate;
    }
    if bytes.starts_with(b"\xEF\xBB\xBF") {
        return FileMagic::TextCandidate;
    }
    if let Some(reason) = classify_short_magic(bytes) {
        return FileMagic::Binary(reason);
    }
    let Ok((prefix, _)) = Prefix16::ref_from_prefix(bytes) else {
        return FileMagic::TextCandidate;
    };
    classify_prefix(prefix)
}

fn classify_prefix(prefix: &Prefix16) -> FileMagic {
    let b = &prefix.bytes;
    if b.starts_with(b"\x89PNG\r\n\x1A\n") {
        return FileMagic::Binary("png header");
    }
    if b.starts_with(b"\x7FELF") {
        return FileMagic::Binary("elf header");
    }
    if b.starts_with(b"\xCA\xFE\xBA\xBE") {
        return FileMagic::Binary("java class header");
    }
    if b.starts_with(b"SQLite format 3\0") {
        return FileMagic::Binary("sqlite header");
    }
    if b.starts_with(b"wOFF") || b.starts_with(b"wOF2") {
        return FileMagic::Binary("font header");
    }
    if b.starts_with(b"\0asm") {
        return FileMagic::Binary("wasm header");
    }
    if b.starts_with(b"ONNX") {
        return FileMagic::Binary("onnx header");
    }
    FileMagic::TextCandidate
}

fn classify_short_magic(bytes: &[u8]) -> Option<&'static str> {
    [
        (b"\x89PNG\r\n\x1A\n".as_slice(), "png header"),
        (b"\x7FELF".as_slice(), "elf header"),
        (b"\xFF\xD8\xFF".as_slice(), "jpeg header"),
        (b"GIF87a".as_slice(), "gif header"),
        (b"GIF89a".as_slice(), "gif header"),
        (b"%PDF-".as_slice(), "pdf header"),
        (b"PK\x03\x04".as_slice(), "zip header"),
        (b"PK\x05\x06".as_slice(), "zip header"),
        (b"PK\x07\x08".as_slice(), "zip header"),
        (b"\x1F\x8B".as_slice(), "gzip header"),
        (b"BZh".as_slice(), "bzip2 header"),
        (b"\xFD\x37\x7A\x58\x5A\x00".as_slice(), "xz header"),
        (b"\x28\xB5\x2F\xFD".as_slice(), "zstd header"),
        (b"Rar!\x1A\x07\x00".as_slice(), "rar header"),
        (b"Rar!\x1A\x07\x01\x00".as_slice(), "rar header"),
        (b"7z\xBC\xAF\x27\x1C".as_slice(), "7z header"),
        (b"\xFE\xED\xFA\xCE".as_slice(), "mach-o header"),
        (b"\xFE\xED\xFA\xCF".as_slice(), "mach-o header"),
        (b"\xCE\xFA\xED\xFE".as_slice(), "mach-o header"),
        (b"\xCF\xFA\xED\xFE".as_slice(), "mach-o header"),
        (b"\xCA\xFE\xBA\xBE".as_slice(), "fat mach-o/class header"),
        (b"\x00\x00\x01\x00".as_slice(), "ico header"),
        (b"\x00\x00\x02\x00".as_slice(), "cur header"),
        (b"\x00\x01\x00\x00".as_slice(), "ttf header"),
        (b"OTTO".as_slice(), "otf header"),
    ]
    .into_iter()
    .find_map(|(magic, reason)| bytes.starts_with(magic).then_some(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_text_as_candidate() {
        assert_eq!(
            FileMagic::TextCandidate,
            classify(b"const PASSWORD = \"helloworld1234\";\n")
        );
        assert_eq!(
            FileMagic::TextCandidate,
            classify(b"MZ\nconst PASSWORD = \"helloworld1234\";\n")
        );
        assert_eq!(
            FileMagic::TextCandidate,
            classify(b"\xEF\xBB\xBFKEY=value\n")
        );
    }

    #[test]
    fn classifies_binary_headers() {
        assert_eq!(
            FileMagic::Binary("png header"),
            classify(b"\x89PNG\r\n\x1A\nxx")
        );
        assert_eq!(FileMagic::Binary("zip header"), classify(b"PK\x03\x04xx"));
        assert_eq!(
            FileMagic::Binary("sqlite header"),
            classify(b"SQLite format 3\0more")
        );
    }
}
