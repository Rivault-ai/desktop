//! In-memory keypair store keyed by upstream `request_id`.
//!
//! The flow:
//! 1. Caller invokes `UpstreamClient::create_auth_request` (or hybrid/login).
//!    The client mints a fresh [`Keypair`], sends its public SPKI to the
//!    backend, learns the request id, then `store(request_id, keypair)`.
//! 2. Later, on `poll_auth_status` (etc.), if `status=approved/submitted`
//!    and an envelope is present, the client calls `take(request_id)` and
//!    decrypts. Take consumes the keypair — one envelope per request id.
//!
//! Process-memory only. Never serialised. Lost on daemon restart, in
//! which case the affected requests have to be recreated; this matches
//! the prior `/tmp/rv_priv_*` lifecycle but without the disk surface.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::upstream::envelope::Keypair;

#[derive(Clone, Default)]
pub struct KeypairStore {
    inner: Arc<Mutex<HashMap<String, Keypair>>>,
}

impl KeypairStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stash a keypair under the upstream-issued request id. Replaces any
    /// previous keypair for the same id (which would only happen if the
    /// caller reused an id; in practice the backend issues fresh ids).
    pub fn store(&self, request_id: &str, keypair: Keypair) {
        let mut g = self.inner.lock().unwrap();
        g.insert(request_id.to_string(), keypair);
    }

    /// Pop the keypair so it can be used for one decrypt. Returns `None`
    /// if no keypair was stored (caller already consumed it, or the daemon
    /// restarted between request creation and poll).
    pub fn take(&self, request_id: &str) -> Option<Keypair> {
        let mut g = self.inner.lock().unwrap();
        g.remove(request_id)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_take() {
        let store = KeypairStore::new();
        let kp = Keypair::generate().unwrap();
        store.store("rq_1", kp);
        assert_eq!(store.len(), 1);
        assert!(store.take("rq_1").is_some());
        assert_eq!(store.len(), 0);
        assert!(store.take("rq_1").is_none());
    }

    #[test]
    fn unknown_id_returns_none() {
        let store = KeypairStore::new();
        assert!(store.take("never-stored").is_none());
    }
}
