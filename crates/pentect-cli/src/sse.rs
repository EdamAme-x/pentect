//! Small, byte-preserving helpers for Server-Sent Events.

/// Return the end of the first SSE event, whose blank line may use CR, LF,
/// CRLF, or a mixture. A terminal CR is held because the next transport
/// chunk may complete it as CRLF.
pub(crate) fn first_block_end(bytes: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index < bytes.len() {
        let first_end = match bytes[index] {
            b'\n' => index + 1,
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => index + 2,
            b'\r' => index + 1,
            _ => {
                index += 1;
                continue;
            }
        };
        if first_end >= bytes.len() {
            return None;
        }
        let second_end = match bytes[first_end] {
            b'\n' => first_end + 1,
            b'\r' if bytes.get(first_end + 1) == Some(&b'\n') => first_end + 2,
            // A second bare CR is itself a complete blank-line delimiter.
            // A lone terminal CR (handled below before this match) remains
            // buffered by the caller until the next transport chunk.
            b'\r' => first_end + 1,
            _ => {
                index = first_end;
                continue;
            }
        };
        return Some(second_end);
    }
    None
}

/// Iterate logical SSE lines without allocating or changing their contents.
pub(crate) fn lines(input: &str) -> impl Iterator<Item = &str> {
    lines_with_endings(input).map(|(line, _)| line)
}

pub(crate) fn lines_with_endings(input: &str) -> impl Iterator<Item = (&str, &str)> {
    let mut offset = 0;
    std::iter::from_fn(move || {
        if offset >= input.len() {
            return None;
        }
        let start = offset;
        let bytes = input.as_bytes();
        while offset < bytes.len() && !matches!(bytes[offset], b'\r' | b'\n') {
            offset += 1;
        }
        let end = offset;
        if offset < bytes.len() {
            if bytes[offset] == b'\r' && bytes.get(offset + 1) == Some(&b'\n') {
                offset += 2;
            } else {
                offset += 1;
            }
        }
        Some((&input[start..end], &input[end..offset]))
    })
}

#[cfg(test)]
mod tests {
    use super::{first_block_end, lines};

    #[test]
    fn boundaries_accept_all_line_endings_without_waiting_for_next_event() {
        for event in [
            b"data: x\n\n".as_slice(),
            b"data: x\r\n\r\n",
            b"data: x\r\r",
        ] {
            let with_next = [event, b"event: next"].concat();
            assert_eq!(first_block_end(&with_next), Some(event.len()));
        }
        assert_eq!(first_block_end(b"data: x\n\n"), Some(9));
        assert_eq!(first_block_end(b"data: x\r\n\r\n"), Some(11));
        assert_eq!(first_block_end(b"data: x\r\r"), Some(9));
        assert_eq!(first_block_end(b"data: x\r\n\r"), Some(10));
        assert_eq!(first_block_end(b"data: x\r"), None);
    }

    #[test]
    fn lines_handle_cr_lf_and_mixed_endings() {
        assert_eq!(
            lines("event: x\rdata: y\r\n\n").collect::<Vec<_>>(),
            ["event: x", "data: y", ""]
        );
    }
}
