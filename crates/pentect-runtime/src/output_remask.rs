use crate::memory_store::MemoryStoreClient;
use pentect_core::{recovery::RecoveryStreamRemasker, Recovery};
use zeroize::Zeroize;

const MAX_PENDING_CONTROL_BYTES: usize = 1024 * 1024;

pub struct ActiveTerminalOutputRemasker {
    client: Option<MemoryStoreClient>,
    observed_masked_count: u64,
    terminal: TerminalOutputRemasker,
}

impl ActiveTerminalOutputRemasker {
    pub fn new() -> Result<Self, String> {
        let Some(client) = MemoryStoreClient::from_env() else {
            return Ok(Self {
                client: None,
                observed_masked_count: 0,
                terminal: TerminalOutputRemasker::default(),
            });
        };
        let observed_masked_count = client.masked_count().map_err(|error| error.to_string())?;
        let snapshot = client.snapshot().map_err(|error| error.to_string())?;
        Ok(Self {
            client: Some(client),
            observed_masked_count,
            terminal: TerminalOutputRemasker::new(&snapshot.recovery),
        })
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        self.refresh()?;
        self.terminal.push(bytes)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>, String> {
        self.refresh()?;
        Ok(self.terminal.finish())
    }

    fn refresh(&mut self) -> Result<(), String> {
        let Some(client) = &self.client else {
            return Ok(());
        };
        let count = client.masked_count().map_err(|error| error.to_string())?;
        if count == self.observed_masked_count {
            return Ok(());
        }
        let snapshot = client.snapshot().map_err(|error| error.to_string())?;
        self.terminal.merge_recovery(&snapshot.recovery);
        self.observed_masked_count = count;
        Ok(())
    }
}

#[derive(Default)]
struct TerminalOutputRemasker {
    matcher: RecoveryStreamRemasker,
    pending: Vec<u8>,
    alternate_screen: bool,
    alternate_keyboard_depth: usize,
}

impl TerminalOutputRemasker {
    fn new(recovery: &Recovery) -> Self {
        Self {
            matcher: recovery.stream_remasker(),
            pending: Vec::new(),
            alternate_screen: false,
            alternate_keyboard_depth: 0,
        }
    }

    fn merge_recovery(&mut self, recovery: &Recovery) {
        self.matcher.merge_recovery(recovery);
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::with_capacity(bytes.len());
        let mut cursor = 0usize;
        while cursor < self.pending.len() {
            let byte = self.pending[cursor];
            if byte == 0x1b {
                let Some(next) = self.pending.get(cursor + 1).copied() else {
                    break;
                };
                match next {
                    b'[' => {
                        let Some(end) = csi_end(&self.pending, cursor + 2) else {
                            break;
                        };
                        let sequence = &self.pending[cursor..=end];
                        Self::push_csi(
                            &mut self.matcher,
                            &mut self.alternate_screen,
                            &mut self.alternate_keyboard_depth,
                            sequence,
                            &mut out,
                        );
                        cursor = end + 1;
                    }
                    b']' => {
                        let Some((payload_end, sequence_end)) = osc_end(&self.pending, cursor + 2)
                        else {
                            break;
                        };
                        out.extend(
                            self.matcher
                                .push_boundary_control(&self.pending[cursor..cursor + 2]),
                        );
                        out.extend(
                            self.matcher
                                .push_text(&self.pending[cursor + 2..payload_end]),
                        );
                        out.extend(
                            self.matcher
                                .push_boundary_control(&self.pending[payload_end..sequence_end]),
                        );
                        cursor = sequence_end;
                    }
                    b'P' | b'X' | b'^' | b'_' => {
                        let Some((payload_end, sequence_end)) =
                            string_control_end(&self.pending, cursor + 2)
                        else {
                            break;
                        };
                        out.extend(
                            self.matcher
                                .push_boundary_control(&self.pending[cursor..cursor + 2]),
                        );
                        out.extend(
                            self.matcher
                                .push_text(&self.pending[cursor + 2..payload_end]),
                        );
                        out.extend(
                            self.matcher
                                .push_boundary_control(&self.pending[payload_end..sequence_end]),
                        );
                        cursor = sequence_end;
                    }
                    _ => {
                        out.extend(
                            self.matcher
                                .push_boundary_control(&self.pending[cursor..cursor + 2]),
                        );
                        cursor += 2;
                    }
                }
                continue;
            }
            if byte == 0x9b {
                let Some(end) = csi_end(&self.pending, cursor + 1) else {
                    break;
                };
                let sequence = &self.pending[cursor..=end];
                Self::push_csi(
                    &mut self.matcher,
                    &mut self.alternate_screen,
                    &mut self.alternate_keyboard_depth,
                    sequence,
                    &mut out,
                );
                cursor = end + 1;
                continue;
            }
            if byte == 0x9d {
                let Some((payload_end, sequence_end)) = osc_end(&self.pending, cursor + 1) else {
                    break;
                };
                out.extend(
                    self.matcher
                        .push_boundary_control(&self.pending[cursor..cursor + 1]),
                );
                out.extend(
                    self.matcher
                        .push_text(&self.pending[cursor + 1..payload_end]),
                );
                out.extend(
                    self.matcher
                        .push_boundary_control(&self.pending[payload_end..sequence_end]),
                );
                cursor = sequence_end;
                continue;
            }
            if matches!(byte, 0x90 | 0x98 | 0x9e | 0x9f) {
                let Some((payload_end, sequence_end)) =
                    string_control_end(&self.pending, cursor + 1)
                else {
                    break;
                };
                out.extend(
                    self.matcher
                        .push_boundary_control(&self.pending[cursor..cursor + 1]),
                );
                out.extend(
                    self.matcher
                        .push_text(&self.pending[cursor + 1..payload_end]),
                );
                out.extend(
                    self.matcher
                        .push_boundary_control(&self.pending[payload_end..sequence_end]),
                );
                cursor = sequence_end;
                continue;
            }
            if is_terminal_control(byte) {
                out.extend(
                    self.matcher
                        .push_boundary_control(&self.pending[cursor..cursor + 1]),
                );
                cursor += 1;
                continue;
            }
            let end = text_run_end(&self.pending, cursor);
            if end == cursor {
                break;
            }
            out.extend(self.matcher.push_text(&self.pending[cursor..end]));
            cursor = end;
        }
        if cursor > 0 {
            let remaining = self.pending.len() - cursor;
            self.pending.copy_within(cursor.., 0);
            self.pending[remaining..].zeroize();
            self.pending.truncate(remaining);
        }
        if self.pending.len() > MAX_PENDING_CONTROL_BYTES {
            self.pending.zeroize();
            self.pending.clear();
            return Err("terminal output control sequence exceeds 1 MiB".to_string());
        }
        Ok(out)
    }

    fn push_csi(
        matcher: &mut RecoveryStreamRemasker,
        alternate_screen: &mut bool,
        alternate_keyboard_depth: &mut usize,
        sequence: &[u8],
        out: &mut Vec<u8>,
    ) {
        if let Some(entering) = alternate_screen_change(sequence) {
            if entering {
                out.extend(matcher.push_boundary_control(sequence));
                if !*alternate_screen {
                    out.extend(matcher.push_boundary_control(b"\x1b[>0u"));
                    *alternate_screen = true;
                    *alternate_keyboard_depth = 1;
                }
            } else {
                if *alternate_screen && *alternate_keyboard_depth > 0 {
                    let pop = kitty_pop(*alternate_keyboard_depth);
                    out.extend(matcher.push_boundary_control(&pop));
                }
                out.extend(matcher.push_boundary_control(sequence));
                *alternate_screen = false;
                *alternate_keyboard_depth = 0;
            }
        } else if is_win32_input_mode(sequence) {
            out.extend(matcher.push_boundary_control(&[]));
        } else if is_sgr(sequence) {
            out.extend(matcher.push_control(sequence));
        } else {
            out.extend(matcher.push_boundary_control(sequence));
        }
        if *alternate_screen {
            match kitty_stack_change(sequence) {
                Some(KittyStackChange::Push) => {
                    *alternate_keyboard_depth = alternate_keyboard_depth.saturating_add(1);
                }
                Some(KittyStackChange::Pop(count)) => {
                    *alternate_keyboard_depth = alternate_keyboard_depth.saturating_sub(count);
                }
                None => {}
            }
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.pending.is_empty() {
            out.extend(self.matcher.push_text(&self.pending));
            self.pending.zeroize();
            self.pending.clear();
        }
        out.extend(self.matcher.finish());
        out
    }
}

fn csi_end(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, byte)| (b'@'..=b'~').contains(byte).then_some(index))
}

fn is_sgr(sequence: &[u8]) -> bool {
    let Some(body) = csi_body(sequence).and_then(|sequence| sequence.strip_suffix(b"m")) else {
        return false;
    };
    body.iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b';' | b':'))
}

fn is_win32_input_mode(sequence: &[u8]) -> bool {
    csi_body(sequence).is_some_and(|body| matches!(body, b"?9001h" | b"?9001l"))
}

fn alternate_screen_change(sequence: &[u8]) -> Option<bool> {
    let body = csi_body(sequence)?;
    let (parameters, enabled) = match body.last()? {
        b'h' => (&body[..body.len() - 1], true),
        b'l' => (&body[..body.len() - 1], false),
        _ => return None,
    };
    let parameters = parameters.strip_prefix(b"?")?;
    parameters
        .split(|byte| *byte == b';')
        .any(|parameter| matches!(parameter, b"47" | b"1047" | b"1049"))
        .then_some(enabled)
}

enum KittyStackChange {
    Push,
    Pop(usize),
}

fn kitty_stack_change(sequence: &[u8]) -> Option<KittyStackChange> {
    let body = csi_body(sequence)?.strip_suffix(b"u")?;
    match body.first()? {
        b'>' => Some(KittyStackChange::Push),
        b'<' => Some(KittyStackChange::Pop(
            parse_decimal(&body[1..]).unwrap_or(1).max(1),
        )),
        _ => None,
    }
}

fn csi_body(sequence: &[u8]) -> Option<&[u8]> {
    sequence
        .strip_prefix(b"\x1b[")
        .or_else(|| sequence.strip_prefix(b"\x9b"))
}

fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0usize, |value, byte| {
        byte.is_ascii_digit().then(|| {
            value
                .saturating_mul(10)
                .saturating_add(usize::from(byte - b'0'))
        })
    })
}

fn kitty_pop(depth: usize) -> Vec<u8> {
    if depth == 1 {
        b"\x1b[<u".to_vec()
    } else {
        format!("\x1b[<{depth}u").into_bytes()
    }
}

fn osc_end(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut index = start;
    while index < bytes.len() {
        if let Some(width) = utf8_sequence_width(bytes[index]) {
            let end = index.checked_add(width)?;
            if end > bytes.len() {
                return None;
            }
            if bytes[index + 1..end]
                .iter()
                .all(|byte| (0x80..=0xbf).contains(byte))
            {
                index = end;
                continue;
            }
        }
        if bytes[index] == 0x07 {
            return Some((index, index + 1));
        }
        if bytes[index] == 0x9c {
            return Some((index, index + 1));
        }
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'\\') {
            return Some((index, index + 2));
        }
        index += 1;
    }
    None
}

fn string_control_end(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut index = start;
    while index < bytes.len() {
        if let Some(width) = utf8_sequence_width(bytes[index]) {
            let end = index.checked_add(width)?;
            if end > bytes.len() {
                return None;
            }
            if bytes[index + 1..end]
                .iter()
                .all(|byte| (0x80..=0xbf).contains(byte))
            {
                index = end;
                continue;
            }
        }
        if bytes[index] == 0x9c {
            return Some((index, index + 1));
        }
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'\\') {
            return Some((index, index + 2));
        }
        index += 1;
    }
    None
}

fn is_terminal_control(byte: u8) -> bool {
    (byte < 0x20 && !matches!(byte, b'\r' | b'\n' | b'\t'))
        || byte == 0x7f
        || (0x80..=0x9f).contains(&byte)
}

fn text_run_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte == 0x1b || is_terminal_control(byte) {
            return cursor;
        }
        if let Some(width) = utf8_sequence_width(byte) {
            let Some(end) = cursor.checked_add(width).filter(|end| *end <= bytes.len()) else {
                return cursor;
            };
            if bytes[cursor + 1..end]
                .iter()
                .all(|byte| (0x80..=0xbf).contains(byte))
            {
                cursor = end;
                continue;
            }
        }
        cursor += 1;
    }
    cursor
}

fn utf8_sequence_width(byte: u8) -> Option<usize> {
    match byte {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn recovery() -> Recovery {
        Recovery::seal(
            HashMap::from([(
                "<<OPENAI_API_KEY_0011223344556677>>".to_string(),
                "sk-ABCDEFGHIJKLMNOPQRSTUVWX".to_string(),
            )]),
            &[9u8; 32],
        )
    }

    #[test]
    fn terminal_output_remasks_across_chunks_and_ansi() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker.push(b"answer sk-ABC").unwrap();
        out.extend(remasker.push(b"\x1b[31mDEFGHIJKLMNOP").unwrap());
        out.extend(remasker.push(b"QRSTUVWX\x1b[0m done").unwrap());
        out.extend(remasker.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "answer <<OPENAI_API_KEY_0011223344556677>>\x1b[0m done"
        );
    }

    #[test]
    fn terminal_output_remasks_across_c1_sgr() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker.push(b"answer sk-ABC").unwrap();
        out.extend(remasker.push(b"\x9b31mDEFGHIJKLMNOP").unwrap());
        out.extend(remasker.push(b"QRSTUVWX\x9b0m done").unwrap());
        out.extend(remasker.finish());
        let mut expected = b"answer <<OPENAI_API_KEY_0011223344556677>>".to_vec();
        expected.extend_from_slice(b"\x9b0m done");
        assert_eq!(out, expected);
    }

    #[test]
    fn c1_string_terminators_do_not_hold_following_output() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker.push(b"\x9d0;title").unwrap();
        assert!(out.is_empty());
        out.extend(remasker.push(b"\x9cafter\x90payload").unwrap());
        out.extend(remasker.push(b"\x9cmore").unwrap());
        out.extend(remasker.finish());
        assert_eq!(out, b"\x9d0;title\x9cafter\x90payload\x9cmore");
    }

    #[test]
    fn terminal_output_remasks_secrets_inside_7_bit_control_strings() {
        for introducer in [b"\x1bP", b"\x1bX", b"\x1b^", b"\x1b_"] {
            assert_control_string_remasked(introducer, b"\x1b\\");
        }
    }

    #[test]
    fn terminal_output_remasks_secrets_inside_c1_control_strings() {
        for introducer in [b"\x90".as_slice(), b"\x98", b"\x9e", b"\x9f"] {
            assert_control_string_remasked(introducer, b"\x9c");
        }
    }

    #[test]
    fn utf8_inside_terminal_strings_is_not_a_c1_terminator() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut input = b"\x9d0;title ".to_vec();
        input.extend_from_slice("Ü".as_bytes());
        input.extend_from_slice(b" [not-st]\x9cafter\x90payload ");
        input.extend_from_slice("Ü".as_bytes());
        input.extend_from_slice(b"\x9cmore");

        let mut out = remasker.push(&input[..12]).unwrap();
        out.extend(remasker.push(&input[12..]).unwrap());
        out.extend(remasker.finish());
        assert_eq!(out, input);
    }

    #[test]
    fn c1_alternate_screen_uses_an_owned_keyboard_frame() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker.push(b"\x9b?1049h\x9b=15;1u\x9b?1049l").unwrap();
        out.extend(remasker.finish());
        assert_eq!(out, b"\x9b?1049h\x1b[>0u\x9b=15;1u\x1b[<u\x9b?1049l");
    }

    #[test]
    fn terminal_output_remasks_osc_payload_and_preserves_wrapper() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker
            .push(b"\x1b]0;key=sk-ABCDEFGHIJKLMNOPQRSTUVWX\x07")
            .unwrap();
        out.extend(remasker.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\x1b]0;key=<<OPENAI_API_KEY_0011223344556677>>\x07"
        );
    }

    #[test]
    fn utf8_continuation_bytes_are_not_c1_controls() {
        let text = "日本語の漛端末 answer sk-ABCDEFGHIJKLMNOPQRSTUVWX";
        assert!(text.as_bytes().contains(&0x9b));
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let split = text.find('漛').unwrap() + 2;
        let mut out = remasker.push(&text.as_bytes()[..split]).unwrap();
        out.extend(remasker.push(&text.as_bytes()[split..]).unwrap());
        out.extend(remasker.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "日本語の漛端末 answer <<OPENAI_API_KEY_0011223344556677>>"
        );
    }

    #[test]
    fn terminal_output_does_not_remask_a_placeholder_again() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let handle = b"<<OPENAI_API_KEY_0011223344556677>>";
        let mut out = remasker.push(handle).unwrap();
        out.extend(remasker.finish());
        assert_eq!(out, handle);
    }

    #[test]
    fn terminal_output_does_not_delay_layout_controls_behind_partial_values() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let out = remasker.push(b"answer sk-ABC\x1b[10C").unwrap();
        assert_eq!(out, b"answer sk-ABC\x1b[10C");
    }

    #[test]
    fn xterm_keyboard_configuration_is_not_mistaken_for_sgr() {
        assert!(is_sgr(b"\x1b[38:2:1:2:3m"));
        assert!(!is_sgr(b"\x1b[>4;2m"));
    }

    #[test]
    fn nested_win32_input_mode_does_not_escape_the_proxy() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker
            .push(b"before\x1b[?9001hready\x1b[?9001lafter")
            .unwrap();
        out.extend(remasker.finish());
        assert_eq!(out, b"beforereadyafter");
    }

    #[test]
    fn alternate_screen_direct_keyboard_changes_use_an_owned_frame() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker.push(b"\x1b[?1049h\x1b[=15;1u\x1b[?1049l").unwrap();
        out.extend(remasker.finish());
        assert_eq!(out, b"\x1b[?1049h\x1b[>0u\x1b[=15;1u\x1b[<u\x1b[?1049l");
    }

    fn assert_control_string_remasked(introducer: &[u8], terminator: &[u8]) {
        let secret = b"sk-ABCDEFGHIJKLMNOPQRSTUVWX";
        let mut input = Vec::new();
        input.extend_from_slice(introducer);
        input.extend_from_slice(b"key=");
        input.extend_from_slice(secret);
        input.extend_from_slice(terminator);
        input.extend_from_slice(b"after");

        let secret_split = introducer.len() + b"key=sk-ABC".len();
        let terminator_split = introducer.len() + b"key=".len() + secret.len() + 1;
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let mut out = remasker.push(&input[..secret_split]).unwrap();
        out.extend(
            remasker
                .push(&input[secret_split..terminator_split])
                .unwrap(),
        );
        out.extend(remasker.push(&input[terminator_split..]).unwrap());
        out.extend(remasker.finish());

        let mut expected = Vec::new();
        expected.extend_from_slice(introducer);
        expected.extend_from_slice(b"key=<<OPENAI_API_KEY_0011223344556677>>");
        expected.extend_from_slice(terminator);
        expected.extend_from_slice(b"after");
        assert_eq!(out, expected);
    }
}
