use crate::masking::{decode_env_alias_record, is_env_alias_placeholder};
use pentect_core::{Config, Recovery};
use std::collections::BTreeMap;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

const VAULT_FILE: &str = "capability-vault.pnt";
const VAULT_MAGIC: &[u8; 4] = b"PNV1";
const VAULT_VERSION: u8 = 1;
#[derive(Clone)]
pub(crate) struct Session {
    pub(crate) key: [u8; 32],
    pub(crate) recoveries: Arc<Mutex<Vec<Recovery>>>,
    vault_path: Option<PathBuf>,
}

impl Session {
    pub(crate) fn open(name: &str) -> Result<Self, String> {
        let root = session_root(name)?;
        let vault_path = root.join(VAULT_FILE);
        if vault_path.exists() {
            return Self::load_vault(vault_path);
        }
        Ok(Self::in_memory())
    }

    pub(crate) fn open_capability(name: &str) -> Result<Self, String> {
        let root = session_root(name)?;
        Self::open_capability_root(root)
    }

    fn in_memory() -> Self {
        Self {
            key: Config::generate().key,
            recoveries: Arc::new(Mutex::new(Vec::new())),
            vault_path: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn open_at(base: &Path, name: &str) -> Result<Self, String> {
        let _ = base;
        checked_session_name(name)?;
        Ok(Self::in_memory())
    }

    #[cfg(test)]
    pub(crate) fn open_capability_at(base: &Path, name: &str) -> Result<Self, String> {
        Self::open_capability_root(base.join(checked_session_name(name)?))
    }

    #[cfg(test)]
    pub(crate) fn save_recovery(&self, recovery: &Recovery) -> Result<(), String> {
        if recovery.is_empty() {
            return Ok(());
        }
        self.recoveries
            .lock()
            .map_err(|_| "recovery cache lock poisoned".to_string())?
            .push(recovery.clone());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn resolve_all(&self, text: &str) -> Result<String, String> {
        let mut out = text.to_string();
        for rec in self.recoveries()? {
            out = rec.resolve(&out);
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn remask_all(&self, text: &str) -> Result<String, String> {
        let mut out = text.to_string();
        for rec in self.recoveries()? {
            out = rec.remask(&out);
        }
        Ok(out)
    }

    fn recoveries(&self) -> Result<Vec<Recovery>, String> {
        Ok(self
            .recoveries
            .lock()
            .map_err(|_| "recovery cache lock poisoned".to_string())?
            .clone())
    }

    fn open_capability_root(root: PathBuf) -> Result<Self, String> {
        let vault_path = root.join(VAULT_FILE);
        if vault_path.exists() {
            return Self::load_vault(vault_path);
        }
        std::fs::create_dir_all(&root)
            .map_err(|e| format!("could not create '{}': {e}", root.display()))?;
        let session = Self {
            key: Config::generate().key,
            recoveries: Arc::new(Mutex::new(Vec::new())),
            vault_path: Some(vault_path),
        };
        session.persist_recoveries()?;
        Ok(session)
    }

    fn load_vault(path: PathBuf) -> Result<Self, String> {
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        let (key, recovery) = decode_vault(&bytes)?;
        Ok(Self {
            key,
            recoveries: Arc::new(Mutex::new(if recovery.is_empty() {
                Vec::new()
            } else {
                vec![recovery]
            })),
            vault_path: Some(path),
        })
    }

    fn persist_recoveries(&self) -> Result<(), String> {
        let Some(path) = &self.vault_path else {
            return Ok(());
        };
        let mut batch = Recovery::empty_for_key(&self.key);
        for recovery in self.recoveries()? {
            batch.extend_same_key(recovery);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create '{}': {e}", parent.display()))?;
        }
        std::fs::write(path, encode_vault(&self.key, &batch))
            .map_err(|e| format!("could not write '{}': {e}", path.display()))
    }

    pub(crate) fn vault_status(name: &str) -> Result<Option<PathBuf>, String> {
        let path = session_root(name)?.join(VAULT_FILE);
        Ok(path.exists().then_some(path))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn resolve_with_recoveries(recoveries: &[Recovery], text: &str) -> String {
    let mut out = text.to_string();
    for rec in recoveries {
        out = rec.resolve(&out);
    }
    out
}

#[derive(Clone)]
pub(crate) struct RecoveryStore {
    pub(crate) session: Session,
    recoveries: Arc<Mutex<Vec<Recovery>>>,
}

impl RecoveryStore {
    pub(crate) fn load(session: &Session) -> Result<Self, String> {
        Ok(Self {
            session: session.clone(),
            recoveries: session.recoveries.clone(),
        })
    }

    pub(crate) fn resolve_all(&self, text: &str) -> Result<String, String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for rec in recoveries.iter() {
            out = rec.resolve(&out);
        }
        Ok(out)
    }

    pub(crate) fn remask_all(&self, text: &str) -> Result<String, String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for rec in recoveries.iter() {
            out = rec.remask(&out);
        }
        Ok(out)
    }

    pub(crate) fn snapshot(&self) -> Result<Vec<Recovery>, String> {
        Ok(self.lock()?.clone())
    }

    pub(crate) fn auto_env_bindings(&self) -> Result<Vec<(String, String)>, String> {
        let recoveries = self.snapshot()?;
        let mut bindings: BTreeMap<String, (String, String)> = BTreeMap::new();
        for recovery in &recoveries {
            for placeholder in recovery.placeholders() {
                if !is_env_alias_placeholder(&placeholder) {
                    continue;
                }
                let record = recovery.resolve(&placeholder);
                let Some((name, handle)) = decode_env_alias_record(&record) else {
                    continue;
                };
                if is_reserved_child_env_name(name) {
                    continue;
                }
                let value = resolve_with_recoveries(&recoveries, handle);
                if value == handle {
                    continue;
                }
                bindings.insert(name.to_ascii_lowercase(), (name.to_string(), value));
            }
        }
        Ok(bindings.into_values().collect())
    }

    pub(crate) fn add_recovery(&self, recovery: Recovery) -> Result<(), String> {
        if recovery.is_empty() {
            return Ok(());
        }
        {
            self.lock()?.push(recovery);
        }
        self.session.persist_recoveries()?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<Recovery>>, String> {
        self.recoveries
            .lock()
            .map_err(|_| "recovery cache lock poisoned".to_string())
    }
}

fn is_reserved_child_env_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "path"
            | "pathext"
            | "systemroot"
            | "windir"
            | "comspec"
            | "temp"
            | "tmp"
            | "userprofile"
            | "home"
            | "shell"
            | "term"
            | "lang"
            | "lc_all"
            | "tmpdir"
            | "pentect_agent"
            | "pentect_agent_home"
            | "pentect_agent_session"
    )
}

fn encode_vault(key: &[u8; 32], recovery: &Recovery) -> Vec<u8> {
    let recovery_blob = recovery.serialize(key);
    let mut out = Vec::with_capacity(4 + 1 + 32 + 4 + recovery_blob.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.push(VAULT_VERSION);
    out.extend_from_slice(key);
    out.extend_from_slice(&(recovery_blob.len() as u32).to_le_bytes());
    out.extend_from_slice(&recovery_blob);
    out
}

fn decode_vault(bytes: &[u8]) -> Result<([u8; 32], Recovery), String> {
    if bytes.len() < 4 + 1 + 32 + 4 {
        return Err("capability vault is malformed".to_string());
    }
    if &bytes[..4] != VAULT_MAGIC {
        return Err("capability vault has unknown magic".to_string());
    }
    if bytes[4] != VAULT_VERSION {
        return Err(format!(
            "unsupported capability vault version: {}",
            bytes[4]
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[5..37]);
    let len = u32::from_le_bytes(
        bytes[37..41]
            .try_into()
            .map_err(|_| "capability vault is malformed".to_string())?,
    ) as usize;
    let end = 41usize
        .checked_add(len)
        .ok_or_else(|| "capability vault is too large".to_string())?;
    if end != bytes.len() {
        return Err("capability vault has trailing or truncated data".to_string());
    }
    let recovery = Recovery::load(&bytes[41..end], &key)
        .map_err(|e| format!("could not load capability vault recovery: {e}"))?;
    Ok((key, recovery))
}

pub(crate) fn session_root(name: &str) -> Result<PathBuf, String> {
    let name = checked_session_name(name)?;
    let base = std::env::var_os("PENTECT_AGENT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".pentect-agent"));
    Ok(base.join(name))
}

pub(crate) fn checked_session_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("session name must not be empty".to_string());
    }
    if matches!(name, "." | "..") {
        return Err("session name must not be a dot path segment".to_string());
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return Err("session name must be a simple file-name segment".to_string());
    }
    Ok(name.to_string())
}
