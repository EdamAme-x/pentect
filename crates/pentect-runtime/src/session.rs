use crate::memory_store::MemoryStoreClient;
use crate::Result;
#[cfg(test)]
use anyhow::anyhow;
use anyhow::bail;
use pentect_core::{Config, Recovery};
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
    pub(crate) identity_key: [u8; 32],
    pub(crate) recoveries: Arc<Mutex<Vec<Recovery>>>,
    backend: SessionBackend,
}

#[derive(Clone)]
enum SessionBackend {
    Local,
    MemoryStore(MemoryStoreClient),
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

    fn in_memory() -> Result<Self> {
        let generated = Config::generate();
        #[cfg(not(test))]
        let identity_key = crate::config::handle_identity_key().map_err(anyhow::Error::msg)?;
        #[cfg(test)]
        let identity_key = generated.identity_key;
        Ok(Self {
            key: generated.key,
            identity_key,
            recoveries: Arc::new(Mutex::new(Vec::new())),
            backend: SessionBackend::Local,
        })
    }

    fn open_active() -> Result<Self> {
        let Some(client) = MemoryStoreClient::from_env() else {
            return Self::in_memory();
        };
        let snapshot = client.snapshot()?;
        Ok(Self {
            key: snapshot.key,
            identity_key: snapshot.identity_key,
            recoveries: Arc::new(Mutex::new(if snapshot.recovery.is_empty() {
                Vec::new()
            } else {
                vec![snapshot.recovery]
            })),
            backend: SessionBackend::MemoryStore(client),
        })
    }

    pub(crate) fn sync_recovery(&self, recovery: &Recovery) -> Result<()> {
        if let SessionBackend::MemoryStore(client) = &self.backend {
            client.add_recovery(&self.key, recovery)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn open_at(base: &Path, name: &str) -> Result<Self> {
        let _ = base;
        checked_session_name(name)?;
        Self::in_memory()
    }

    #[cfg(test)]
    pub(crate) fn open_capability_at(base: &Path, name: &str) -> Result<Self> {
        let _ = base;
        checked_session_name(name)?;
        Self::in_memory()
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
}

impl Drop for Session {
    fn drop(&mut self) {
        self.key.zeroize();
        self.identity_key.zeroize();
    }
}

pub(crate) fn session_root(name: &str) -> Result<PathBuf> {
    let name = checked_session_name(name)?;
    let base = PathBuf::from(PENTECT_DIR).join(AGENT_DIR);
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
