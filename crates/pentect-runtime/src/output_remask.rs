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
}

impl TerminalOutputRemasker {
    fn new(recovery: &Recovery) -> Self {
        Self {
            matcher: recovery.stream_remasker(),
            pending: Vec::new(),
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
                        out.extend(self.matcher.push_control(&self.pending[cursor..=end]));
                        cursor = end + 1;
                    }
                    b']' => {
                        let Some((payload_end, sequence_end)) = osc_end(&self.pending, cursor + 2)
                        else {
                            break;
                        };
                        out.extend(self.matcher.push_control(&self.pending[cursor..cursor + 2]));
                        out.extend(
                            self.matcher
                                .push_text(&self.pending[cursor + 2..payload_end]),
                        );
                        out.extend(
                            self.matcher
                                .push_control(&self.pending[payload_end..sequence_end]),
                        );
                        cursor = sequence_end;
                    }
                    b'P' | b'X' | b'^' | b'_' => {
                        let Some(end) = string_control_end(&self.pending, cursor + 2) else {
                            break;
                        };
                        out.extend(self.matcher.push_control(&self.pending[cursor..end]));
                        cursor = end;
                    }
                    _ => {
                        out.extend(self.matcher.push_control(&self.pending[cursor..cursor + 2]));
                        cursor += 2;
                    }
                }
                continue;
            }
            if is_terminal_control(byte) {
                out.extend(self.matcher.push_control(&self.pending[cursor..cursor + 1]));
                cursor += 1;
                continue;
            }
            let end = self.pending[cursor..]
                .iter()
                .position(|byte| *byte == 0x1b || is_terminal_control(*byte))
                .map_or(self.pending.len(), |offset| cursor + offset);
            out.extend(self.matcher.push_text(&self.pending[cursor..end]));
            cursor = end;
        }
        if cursor > 0 {
            let mut consumed = self.pending.drain(..cursor).collect::<Vec<_>>();
            consumed.zeroize();
        }
        if self.pending.len() > MAX_PENDING_CONTROL_BYTES {
            self.pending.zeroize();
            self.pending.clear();
            return Err("terminal output control sequence exceeds 1 MiB".to_string());
        }
        Ok(out)
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

fn osc_end(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] == 0x07 {
            return Some((index, index + 1));
        }
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'\\') {
            return Some((index, index + 2));
        }
        index += 1;
    }
    None
}

fn string_control_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    while index + 1 < bytes.len() {
        if bytes[index] == 0x1b && bytes[index + 1] == b'\\' {
            return Some(index + 2);
        }
        index += 1;
    }
    None
}

fn is_terminal_control(byte: u8) -> bool {
    (byte < 0x20 && !matches!(byte, b'\r' | b'\n' | b'\t')) || byte == 0x7f
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
    fn terminal_output_does_not_remask_a_placeholder_again() {
        let mut remasker = TerminalOutputRemasker::new(&recovery());
        let handle = b"<<OPENAI_API_KEY_0011223344556677>>";
        let mut out = remasker.push(handle).unwrap();
        out.extend(remasker.finish());
        assert_eq!(out, handle);
    }
}
