use crate::Result;
use anyhow::{anyhow, bail, Context};
use pentect_core::{Config, Recovery};
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroize;

pub(crate) const ENV_ADDR: &str = "PENTECT_IN_MEMORY_MANAGER_ADDR";
pub(crate) const ENV_TOKEN: &str = "PENTECT_IN_MEMORY_MANAGER_TOKEN";

const TOKEN_BYTES: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(crate) struct InMemoryManagerClient {
    addr: String,
    token: String,
}

pub(crate) struct InMemoryManagerSnapshot {
    pub(crate) key: [u8; 32],
    pub(crate) recovery: Recovery,
}

struct InMemoryManagerState {
    key: [u8; 32],
    recovery: Recovery,
    masked_count: u64,
}

impl Drop for InMemoryManagerState {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl InMemoryManagerClient {
    pub(crate) fn from_env() -> Option<Self> {
        let addr = std::env::var(ENV_ADDR).ok()?;
        let token = std::env::var(ENV_TOKEN).ok()?;
        if addr.is_empty() || token.is_empty() {
            return None;
        }
        Some(Self { addr, token })
    }

    pub(crate) fn snapshot(&self) -> Result<InMemoryManagerSnapshot> {
        let line = self.request("SNAPSHOT", "")?;
        let fields = response_fields(&line)?;
        if fields.len() != 3 || fields[0] != "OK" {
            bail!("in-memory manager snapshot response is malformed");
        }
        let key = decode_key_hex(fields[1])?;
        let recovery_blob = data_encoding::BASE64
            .decode(fields[2].as_bytes())
            .context("in-memory manager snapshot is not valid base64")?;
        let recovery = Recovery::load(&recovery_blob, &key)
            .map_err(|e| anyhow!("in-memory manager snapshot is invalid: {e}"))?;
        Ok(InMemoryManagerSnapshot { key, recovery })
    }

    pub(crate) fn key(&self) -> Result<[u8; 32]> {
        let line = self.request("KEY", "")?;
        let fields = response_fields(&line)?;
        if fields.len() != 2 || fields[0] != "OK" {
            bail!("in-memory manager key response is malformed");
        }
        decode_key_hex(fields[1])
    }

    pub(crate) fn add_recovery(&self, key: &[u8; 32], recovery: &Recovery) -> Result<()> {
        let payload = data_encoding::BASE64.encode(&recovery.serialize(key));
        let line = self.request("ADD", &payload)?;
        let fields = response_fields(&line)?;
        if fields.as_slice() == ["OK"] {
            Ok(())
        } else {
            bail!("in-memory manager add response is malformed")
        }
    }

    pub(crate) fn masked_count(&self) -> Result<u64> {
        let line = self.request("COUNT", "")?;
        let fields = response_fields(&line)?;
        if fields.len() != 2 || fields[0] != "OK" {
            bail!("in-memory manager count response is malformed");
        }
        fields[1]
            .parse::<u64>()
            .context("in-memory manager masked count is not a number")
    }

    pub(crate) fn add_masked_count(&self, count: u64) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let line = self.request("ADD_COUNT", &count.to_string())?;
        let fields = response_fields(&line)?;
        if fields.as_slice() == ["OK"] {
            Ok(())
        } else {
            bail!("in-memory manager add count response is malformed")
        }
    }

    fn request(&self, command: &str, payload: &str) -> Result<String> {
        let mut stream = TcpStream::connect(&self.addr)
            .with_context(|| format!("could not connect to in-memory manager at {}", self.addr))?;
        let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
        writeln!(stream, "{}\t{}\t{}", self.token, command, payload)
            .context("could not send in-memory manager request")?;
        let _ = stream.shutdown(Shutdown::Write);
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .context("could not read in-memory manager response")?;
        if line.is_empty() {
            bail!("in-memory manager closed the connection");
        }
        if let Some(reason) = line.strip_prefix("ERR\t") {
            bail!("in-memory manager rejected request: {}", reason.trim());
        }
        Ok(line)
    }
}

pub(crate) fn serve_in_memory_manager() -> i32 {
    match serve_in_memory_manager_inner() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[pentect] {e}");
            2
        }
    }
}

fn serve_in_memory_manager_inner() -> Result<()> {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).context("could not bind in-memory manager listener")?;
    let addr = listener
        .local_addr()
        .context("could not read in-memory manager address")?;
    let token = random_token_hex()?;
    let key = Config::generate().key;
    let state = Arc::new(Mutex::new(InMemoryManagerState {
        key,
        recovery: Recovery::empty_for_key(&key),
        masked_count: 0,
    }));
    println!(
        "{}",
        serde_json::json!({
            "addr": addr.to_string(),
            "token": token,
        })
    );
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let state = state.clone();
        let token = token.clone();
        std::thread::spawn(move || {
            let _ = handle_client(stream, &token, &state);
        });
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn spawn_test_in_memory_manager(token: String) -> String {
    let key = Config::generate().key;
    let state = Arc::new(Mutex::new(InMemoryManagerState {
        key,
        recovery: Recovery::empty_for_key(&key),
        masked_count: 0,
    }));
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        // Unit tests open only a handful of requests; bound the helper server so
        // finished tests do not keep an idle listener thread around forever.
        for stream in listener.incoming().take(8) {
            handle_client(stream.unwrap(), &token, &state).unwrap();
        }
    });
    addr
}

fn handle_client(
    stream: TcpStream,
    token: &str,
    state: &Arc<Mutex<InMemoryManagerState>>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("could not read in-memory manager request")?;
    let mut stream = reader.into_inner();
    let fields = request_fields(&line);
    let response = match fields.as_slice() {
        [provided_token, "KEY", ""] if *provided_token == token => key_response(state),
        [provided_token, "COUNT", ""] if *provided_token == token => count_response(state),
        [provided_token, "SNAPSHOT", ""] if *provided_token == token => snapshot_response(state),
        [provided_token, "ADD", payload] if *provided_token == token => {
            add_recovery_request(state, payload)
        }
        [provided_token, "ADD_COUNT", payload] if *provided_token == token => {
            add_masked_count_request(state, payload)
        }
        [provided_token, ..] if *provided_token != token => Err(anyhow!("bad token")),
        _ => Err(anyhow!("malformed request")),
    };
    match response {
        Ok(line) => {
            writeln!(stream, "{line}").context("could not write in-memory manager response")?
        }
        Err(e) => writeln!(stream, "ERR\t{}", sanitize_field(&e.to_string()))
            .context("could not write in-memory manager error")?,
    }
    Ok(())
}

fn key_response(state: &Arc<Mutex<InMemoryManagerState>>) -> Result<String> {
    let guard = state
        .lock()
        .map_err(|_| anyhow!("in-memory manager lock poisoned"))?;
    Ok(format!(
        "OK\t{}",
        data_encoding::HEXLOWER.encode(&guard.key)
    ))
}

fn snapshot_response(state: &Arc<Mutex<InMemoryManagerState>>) -> Result<String> {
    let guard = state
        .lock()
        .map_err(|_| anyhow!("in-memory manager lock poisoned"))?;
    Ok(format!(
        "OK\t{}\t{}",
        data_encoding::HEXLOWER.encode(&guard.key),
        data_encoding::BASE64.encode(&guard.recovery.serialize(&guard.key))
    ))
}

fn count_response(state: &Arc<Mutex<InMemoryManagerState>>) -> Result<String> {
    let guard = state
        .lock()
        .map_err(|_| anyhow!("in-memory manager lock poisoned"))?;
    Ok(format!("OK\t{}", guard.masked_count))
}

fn add_recovery_request(state: &Arc<Mutex<InMemoryManagerState>>, payload: &str) -> Result<String> {
    let bytes = data_encoding::BASE64
        .decode(payload.as_bytes())
        .context("recovery payload is not valid base64")?;
    let mut guard = state
        .lock()
        .map_err(|_| anyhow!("in-memory manager lock poisoned"))?;
    let recovery = Recovery::load(&bytes, &guard.key)
        .map_err(|e| anyhow!("recovery payload is invalid: {e}"))?;
    if !recovery.is_empty() {
        guard.recovery.extend_same_key(recovery);
    }
    Ok("OK".to_string())
}

fn add_masked_count_request(
    state: &Arc<Mutex<InMemoryManagerState>>,
    payload: &str,
) -> Result<String> {
    let count = payload
        .parse::<u64>()
        .context("masked count payload is not a number")?;
    let mut guard = state
        .lock()
        .map_err(|_| anyhow!("in-memory manager lock poisoned"))?;
    guard.masked_count = guard.masked_count.saturating_add(count);
    Ok("OK".to_string())
}

fn request_fields(line: &str) -> Vec<&str> {
    line.trim_end_matches(['\r', '\n']).split('\t').collect()
}

fn response_fields(line: &str) -> Result<Vec<&str>> {
    let fields = request_fields(line);
    if fields.first() == Some(&"ERR") {
        let reason = fields.get(1).copied().unwrap_or("unknown error");
        bail!("{reason}");
    }
    Ok(fields)
}

fn random_token_hex() -> Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow!("could not generate in-memory manager token: {e}"))?;
    Ok(data_encoding::HEXLOWER.encode(&bytes))
}

fn decode_key_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = data_encoding::HEXLOWER
        .decode(value.as_bytes())
        .context("in-memory manager key is not valid hex")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("in-memory manager key has wrong length"))?;
    Ok(key)
}

fn sanitize_field(value: &str) -> String {
    value.replace(['\r', '\n', '\t'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentect_core::{Engine, Input, Kind, Profile};

    #[test]
    fn client_round_trips_recovery_through_in_memory_manager_state() {
        let token = "test-token".to_string();
        let client = InMemoryManagerClient {
            addr: spawn_test_in_memory_manager(token.clone()),
            token,
        };
        assert_eq!(client.key().unwrap(), client.snapshot().unwrap().key);
        let snapshot = client.snapshot().unwrap();
        let result = Engine::with_profile(Profile::Strict).mask(
            Input {
                kind: Kind::Env,
                data: "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n".to_string(),
            },
            &Config::new(snapshot.key),
        );
        let masked = result.masked.clone();
        client
            .add_recovery(&snapshot.key, &result.recovery)
            .unwrap();

        let snapshot = client.snapshot().unwrap();
        assert_eq!(
            snapshot.recovery.resolve(&masked),
            "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
        );
    }

    #[test]
    fn read_style_masking_registers_recovery_and_env_aliases_in_in_memory_manager() {
        let token = "test-token-read".to_string();
        let client = InMemoryManagerClient {
            addr: spawn_test_in_memory_manager(token.clone()),
            token,
        };
        let raw = "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n";
        let result = crate::mask_input_into_in_memory_manager_client(
            &client,
            Input {
                kind: Kind::Env,
                data: raw.to_string(),
            },
            Profile::Strict,
            Vec::new(),
        )
        .unwrap();
        assert!(result.masked.contains("OPENAI_API_KEY=<<OPENAI_API_KEY_"));
        assert!(!result.masked.contains("_length_"), "{}", result.masked);
        assert_eq!(client.masked_count().unwrap(), 1);

        let snapshot = client.snapshot().unwrap();
        assert_eq!(snapshot.recovery.resolve(&result.masked), raw);
        let alias_records: Vec<_> = snapshot
            .recovery
            .placeholders()
            .into_iter()
            .filter(|placeholder| crate::masking::is_env_alias_placeholder(placeholder))
            .filter_map(|placeholder| {
                let record = snapshot.recovery.resolve(&placeholder);
                crate::masking::decode_env_alias_record(&record)
                    .map(|(name, handle)| (name.to_string(), handle.to_string()))
            })
            .collect();
        assert!(alias_records.iter().any(|(name, handle)| {
            name == "OPENAI_API_KEY"
                && snapshot.recovery.resolve(handle) == "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
        }));
    }

    #[test]
    fn client_tracks_masked_count_in_memory() {
        let token = "test-token-count".to_string();
        let client = InMemoryManagerClient {
            addr: spawn_test_in_memory_manager(token.clone()),
            token,
        };
        assert_eq!(client.masked_count().unwrap(), 0);
        client.add_masked_count(2).unwrap();
        client.add_masked_count(3).unwrap();
        assert_eq!(client.masked_count().unwrap(), 5);
    }
}
