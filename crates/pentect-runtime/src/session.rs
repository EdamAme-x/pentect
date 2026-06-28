use crate::masking::{decode_env_alias_record, is_env_alias_placeholder};
use crate::memory_vault::MemoryVaultClient;
use crate::Result;
use anyhow::{anyhow, bail};
use pentect_core::{Config, Recovery};
use std::collections::BTreeMap;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

const PENTECT_DIR: &str = ".pentect";
const AGENT_DIR: &str = "agent";

#[derive(Clone)]
pub(crate) struct Session {
    pub(crate) key: [u8; 32],
    pub(crate) recoveries: Arc<Mutex<Vec<Recovery>>>,
    backend: SessionBackend,
}

#[derive(Clone)]
enum SessionBackend {
    Local,
    MemoryVault(MemoryVaultClient),
}

impl Session {
    pub(crate) fn open(name: &str) -> Result<Self> {
        checked_session_name(name)?;
        Self::open_active()
    }

    pub(crate) fn open_capability(name: &str) -> Result<Self> {
        checked_session_name(name)?;
        Self::open_active()
    }

    fn in_memory() -> Self {
        Self {
            key: Config::generate().key,
            recoveries: Arc::new(Mutex::new(Vec::new())),
            backend: SessionBackend::Local,
        }
    }

    fn open_active() -> Result<Self> {
        let Some(client) = MemoryVaultClient::from_env() else {
            return Ok(Self::in_memory());
        };
        let snapshot = client.snapshot()?;
        Ok(Self {
            key: snapshot.key,
            recoveries: Arc::new(Mutex::new(if snapshot.recovery.is_empty() {
                Vec::new()
            } else {
                vec![snapshot.recovery]
            })),
            backend: SessionBackend::MemoryVault(client),
        })
    }

    #[cfg(test)]
    pub(crate) fn open_at(base: &Path, name: &str) -> Result<Self> {
        let _ = base;
        checked_session_name(name)?;
        Ok(Self::in_memory())
    }

    #[cfg(test)]
    pub(crate) fn open_capability_at(base: &Path, name: &str) -> Result<Self> {
        let _ = base;
        checked_session_name(name)?;
        Ok(Self::in_memory())
    }

    #[cfg(test)]
    pub(crate) fn save_recovery(&self, recovery: &Recovery) -> Result<()> {
        if recovery.is_empty() {
            return Ok(());
        }
        self.recoveries
            .lock()
            .map_err(|_| anyhow!("recovery cache lock poisoned"))?
            .push(recovery.clone());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn resolve_all(&self, text: &str) -> Result<String> {
        let mut out = text.to_string();
        for rec in self.recoveries()? {
            out = rec.resolve(&out);
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn remask_all(&self, text: &str) -> Result<String> {
        let mut out = text.to_string();
        for rec in self.recoveries()? {
            out = rec.remask(&out);
        }
        Ok(out)
    }

    #[cfg(test)]
    fn recoveries(&self) -> Result<Vec<Recovery>> {
        Ok(self
            .recoveries
            .lock()
            .map_err(|_| anyhow!("recovery cache lock poisoned"))?
            .clone())
    }

    pub(crate) fn vault_status(name: &str) -> Result<Option<String>> {
        checked_session_name(name)?;
        Ok(MemoryVaultClient::from_env()
            .is_some()
            .then_some("memory-only, active while parent Pentect process is running".to_string()))
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
    pub(crate) fn load(session: &Session) -> Result<Self> {
        Ok(Self {
            session: session.clone(),
            recoveries: session.recoveries.clone(),
        })
    }

    pub(crate) fn resolve_all(&self, text: &str) -> Result<String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for rec in recoveries.iter() {
            out = rec.resolve(&out);
        }
        Ok(out)
    }

    pub(crate) fn remask_all(&self, text: &str) -> Result<String> {
        let recoveries = self.lock()?;
        let mut out = text.to_string();
        for rec in recoveries.iter() {
            out = rec.remask(&out);
        }
        Ok(out)
    }

    pub(crate) fn snapshot(&self) -> Result<Vec<Recovery>> {
        Ok(self.lock()?.clone())
    }

    pub(crate) fn auto_env_bindings(&self) -> Result<Vec<(String, String)>> {
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

    pub(crate) fn add_recovery(&self, recovery: Recovery) -> Result<()> {
        if recovery.is_empty() {
            return Ok(());
        }
        if let SessionBackend::MemoryVault(client) = &self.session.backend {
            client.add_recovery(&self.session.key, &recovery)?;
        }
        {
            self.lock()?.push(recovery);
        }
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<Recovery>>> {
        self.recoveries
            .lock()
            .map_err(|_| anyhow!("recovery cache lock poisoned"))
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
            | "pentect_bin"
            | "pentect_home"
            | "pentect_session"
    )
}

pub(crate) fn session_root(name: &str) -> Result<PathBuf> {
    let name = checked_session_name(name)?;
    let base = std::env::var_os("PENTECT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(PENTECT_DIR).join(AGENT_DIR));
    Ok(base.join(name))
}

pub(crate) fn checked_session_name(name: &str) -> Result<String> {
    if name.is_empty() {
        bail!("session name must not be empty");
    }
    if matches!(name, "." | "..") {
        bail!("session name must not be a dot path segment");
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        bail!("session name must be a simple file-name segment");
    }
    Ok(name.to_string())
}
