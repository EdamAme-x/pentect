//! Replay accounting only. This must never skip inspection or restoration.
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

const MAX_TRACKED_CONTENT: usize = 65_536;
static LIMIT_REPORTED: AtomicBool = AtomicBool::new(false);

struct Request {
    key: [u8; 32],
    occurrences: HashMap<[u8; 32], u64>,
}

thread_local! {
    static REQUEST: RefCell<Option<Request>> = const { RefCell::new(None) };
}
static SEEN: OnceLock<Mutex<HashMap<[u8; 32], u64>>> = OnceLock::new();

/// Synchronous provider-body protection scope. Nested adapters share the outer
/// scope. Fingerprints stay in process memory; no values or hashes enter logs.
pub struct MetricsRequestScope {
    owner: bool,
    // Thread-local state must be cleared on the same thread that created it.
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Default for MetricsRequestScope {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRequestScope {
    pub fn new() -> Self {
        let key = crate::memory_store::MemoryStoreClient::from_env()
            .and_then(|client| client.keys().ok())
            .map(|keys| keys.0);
        Self::with_key(key)
    }

    pub(crate) fn with_key(key: Option<[u8; 32]>) -> Self {
        let owner = REQUEST.with(|request| {
            let mut request = request.borrow_mut();
            if request.is_some() {
                return false;
            }
            *request = key.map(|key| Request {
                key,
                occurrences: HashMap::new(),
            });
            request.is_some()
        });
        Self {
            owner,
            _thread_bound: std::marker::PhantomData,
        }
    }
}

impl Drop for MetricsRequestScope {
    fn drop(&mut self) {
        if self.owner {
            REQUEST.with(|request| *request.borrow_mut() = None);
        }
    }
}

pub(crate) fn count_content(surface: &str, content: &[u8]) -> bool {
    REQUEST.with(|request| {
        let mut request = request.borrow_mut();
        let Some(request) = request.as_mut() else {
            return true;
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&request.key).expect("fixed HMAC key");
        mac.update(surface.as_bytes());
        mac.update(&[0]);
        mac.update(content);
        let fingerprint: [u8; 32] = mac.finalize().into_bytes().into();
        let mut seen = SEEN
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() >= MAX_TRACKED_CONTENT && !seen.contains_key(&fingerprint) {
            drop(seen);
            if !LIMIT_REPORTED.swap(true, Ordering::Relaxed) {
                crate::activity_log::record_diagnostic(
                    "logger",
                    "metrics-replay-limit",
                    Some("capacity"),
                    None,
                    None,
                    None,
                    Some(false),
                    None,
                );
            }
            // Do not evict old identities and accidentally count their replay.
            // Protection still runs; only uncertain metrics are omitted.
            return false;
        }
        let ordinal = request.occurrences.entry(fingerprint).or_default();
        *ordinal = ordinal.saturating_add(1);
        let previous = seen.entry(fingerprint).or_default();
        if *ordinal <= *previous {
            return false;
        }
        *previous = *ordinal;
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_is_excluded_but_additional_occurrences_and_sessions_count() {
        {
            let _scope = MetricsRequestScope::with_key(Some([173; 32]));
            assert!(count_content("prompt", b"synthetic masked item"));
            assert!(count_content("prompt", b"synthetic masked item"));
        }
        {
            let _scope = MetricsRequestScope::with_key(Some([173; 32]));
            assert!(!count_content("prompt", b"synthetic masked item"));
            assert!(!count_content("prompt", b"synthetic masked item"));
            assert!(count_content("prompt", b"synthetic masked item"));
            assert!(count_content("image", b"synthetic image"));
        }
        {
            let _scope = MetricsRequestScope::with_key(Some([174; 32]));
            assert!(count_content("prompt", b"synthetic masked item"));
        }
        assert!(count_content("prompt", b"synthetic masked item"));
    }
}
