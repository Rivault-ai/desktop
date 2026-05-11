//! Persistent keypair store keyed by upstream `request_id`.
//!
//! The flow:
//! 1. Caller invokes `UpstreamClient::create_auth_request` (or hybrid /
//!    login). The client (or the Tier-B proxy on its behalf) mints a
//!    fresh [`Keypair`], sends its public SPKI to the backend, learns
//!    the request id, then `store(request_id, keypair)`.
//! 2. Later, on `poll_*_status` (or the matching proxy hop), if
//!    `status=approved/submitted` and an envelope is present, the caller
//!    invokes `take(request_id)` and decrypts. Take consumes the keypair
//!    — one envelope per request id.
//!
//! Disk-backed via SQLite at `~/Library/Application Support/Rivault/
//! keypairs.db` (or the analogous path on Linux/Windows). Each row's
//! PKCS#8 DER private key is wrapped with AES-256-GCM using the daemon's
//! per-install secret from the macOS keychain. This survives daemon
//! restarts: a hybrid request created in one process can still be
//! decrypted by the next process, eliminating the failure mode where
//! any restart strands every pending L2 approval.
//!
//! Best-effort fallback: if the keychain secret or DB is unavailable
//! at boot, the store transparently degrades to in-memory mode — no
//! restart resilience, but no hard error either.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p256::SecretKey;
use rand::RngCore;
use rusqlite::{params, Connection};

use crate::upstream::envelope::Keypair;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS proxy_keypairs (
    request_id    TEXT PRIMARY KEY,
    wrapped_b64   TEXT NOT NULL,
    iv_b64        TEXT NOT NULL,
    created_at    TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_proxy_keypairs_created
    ON proxy_keypairs(created_at);
";

/// Auth requests at the backend expire after 30 min; we sweep stored
/// keypairs at twice that to cover skew + the user occasionally taking
/// the full window. Keypairs older than this are dropped on every
/// `store()` call (cheap one-shot maintenance).
const KEYPAIR_TTL_SECS: i64 = 60 * 60;

#[derive(Clone)]
pub struct KeypairStore {
    inner: Arc<Inner>,
}

struct Inner {
    /// Per-install wrapping key (32 bytes from `keychain::load_or_create_secret`).
    /// `None` = persistence disabled, fall back to in-memory only.
    wrap_key: Option<[u8; 32]>,
    /// SQLite connection guarded by a mutex. `None` = persistence disabled.
    conn: Option<Mutex<Connection>>,
    /// In-memory fallback (always populated as a write-through cache so
    /// we never lose a keypair to a transient DB error mid-task).
    memory: Mutex<HashMap<String, Keypair>>,
}

impl Default for KeypairStore {
    fn default() -> Self {
        Self::open_default().unwrap_or_else(|e| {
            tracing::warn!(
                "keypair_store: persistence init failed ({e:#}); using in-memory fallback"
            );
            Self::in_memory()
        })
    }
}

impl KeypairStore {
    /// In-memory-only store. Used as a fallback when persistence init
    /// fails and as the simplest constructor in tests.
    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(Inner {
                wrap_key: None,
                conn: None,
                memory: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Backwards-compatible constructor used by existing call sites.
    /// Tries to open the persistent store, falls back to in-memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the persistent store. Resolves the DB path under the app's
    /// support directory and loads the wrapping key from the keychain.
    pub fn open_default() -> Result<Self> {
        let secret = crate::keychain::load_or_create_secret()
            .context("load wrapping key for keypair persistence")?;
        if secret.len() < 32 {
            anyhow::bail!("keychain secret too short ({} bytes)", secret.len());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&secret[..32]);
        let path = default_db_path()?;
        Self::open_at(path, key)
    }

    fn open_at(path: PathBuf, wrap_key: [u8; 32]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(&path).context("open keypair store")?;
        conn.execute_batch(SCHEMA).context("init keypair schema")?;
        Ok(Self {
            inner: Arc::new(Inner {
                wrap_key: Some(wrap_key),
                conn: Some(Mutex::new(conn)),
                memory: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Stash a keypair under the upstream-issued request id. The
    /// in-memory cache is always updated; SQLite persistence is
    /// best-effort and logged but not fatal.
    pub fn store(&self, request_id: &str, keypair: Keypair) {
        if let (Some(key), Some(conn)) = (&self.inner.wrap_key, &self.inner.conn) {
            match self.persist(conn, key, request_id, &keypair) {
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    request_id = %request_id,
                    "keypair_store: persist failed (keeping in-memory): {e:#}"
                ),
            }
            if let Err(e) = self.sweep_expired(conn) {
                tracing::debug!("keypair_store: sweep failed: {e:#}");
            }
        }
        let mut mem = self.inner.memory.lock().unwrap();
        mem.insert(request_id.to_string(), keypair);
    }

    /// Pop the keypair so it can be used for one decrypt. Checks
    /// in-memory first (hot path), then SQLite (cold path after a
    /// daemon restart).
    pub fn take(&self, request_id: &str) -> Option<Keypair> {
        {
            let mut mem = self.inner.memory.lock().unwrap();
            if let Some(kp) = mem.remove(request_id) {
                if let Some(conn) = &self.inner.conn {
                    if let Ok(c) = conn.lock() {
                        let _ = c.execute(
                            "DELETE FROM proxy_keypairs WHERE request_id = ?",
                            params![request_id],
                        );
                    }
                }
                return Some(kp);
            }
        }
        let (key, conn) = match (&self.inner.wrap_key, &self.inner.conn) {
            (Some(k), Some(c)) => (k, c),
            _ => return None,
        };
        self.load_and_delete(conn, key, request_id)
            .unwrap_or_else(|e| {
                tracing::warn!(
                    request_id = %request_id,
                    "keypair_store: load failed: {e:#}"
                );
                None
            })
    }

    fn persist(
        &self,
        conn: &Mutex<Connection>,
        wrap_key: &[u8; 32],
        request_id: &str,
        keypair: &Keypair,
    ) -> Result<()> {
        let der = keypair
            .secret()
            .to_pkcs8_der()
            .context("encode secret to PKCS#8 DER")?;
        let mut iv = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut iv);
        let cipher = Aes256Gcm::new(wrap_key.into());
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher
            .encrypt(nonce, der.as_bytes())
            .map_err(|e| anyhow::anyhow!("wrap keypair: {e}"))?;
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let c = conn.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO proxy_keypairs (request_id, wrapped_b64, iv_b64, created_at)
             VALUES (?, ?, ?, ?)",
            params![request_id, B64.encode(&ct), B64.encode(iv), now],
        )?;
        Ok(())
    }

    fn load_and_delete(
        &self,
        conn: &Mutex<Connection>,
        wrap_key: &[u8; 32],
        request_id: &str,
    ) -> Result<Option<Keypair>> {
        let c = conn.lock().unwrap();
        let row: Option<(String, String)> = c
            .query_row(
                "SELECT wrapped_b64, iv_b64 FROM proxy_keypairs WHERE request_id = ?",
                params![request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let Some((wrapped_b64, iv_b64)) = row else {
            return Ok(None);
        };
        let _ = c.execute(
            "DELETE FROM proxy_keypairs WHERE request_id = ?",
            params![request_id],
        );
        drop(c);

        let wrapped = B64.decode(wrapped_b64.as_bytes())?;
        let iv = B64.decode(iv_b64.as_bytes())?;
        if iv.len() != 12 {
            anyhow::bail!("bad iv length: {}", iv.len());
        }
        let cipher = Aes256Gcm::new(wrap_key.into());
        let nonce = Nonce::from_slice(&iv);
        let der = cipher
            .decrypt(nonce, wrapped.as_ref())
            .map_err(|e| anyhow::anyhow!("unwrap keypair: {e}"))?;
        let secret = SecretKey::from_pkcs8_der(&der)
            .map_err(|e| anyhow::anyhow!("parse PKCS#8 DER: {e}"))?;
        let kp = Keypair::from_secret(secret).context("rebuild Keypair from secret")?;
        Ok(Some(kp))
    }

    fn sweep_expired(&self, conn: &Mutex<Connection>) -> Result<()> {
        let cutoff = time::OffsetDateTime::now_utc()
            - time::Duration::seconds(KEYPAIR_TTL_SECS);
        let cutoff_str = cutoff
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let c = conn.lock().unwrap();
        c.execute(
            "DELETE FROM proxy_keypairs WHERE created_at < ?",
            params![cutoff_str],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.memory.lock().unwrap().len()
    }
}

fn default_db_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("no home dir")?;
    #[cfg(target_os = "macos")]
    let dir = home
        .join("Library")
        .join("Application Support")
        .join("Rivault");
    #[cfg(not(target_os = "macos"))]
    let dir = home.join(".local").join("share").join("Rivault");
    Ok(dir.join("keypairs.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, KeypairStore) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kp.db");
        let key = [42u8; 32];
        let store = KeypairStore::open_at(path, key).unwrap();
        (tmp, store)
    }

    #[test]
    fn store_and_take_in_memory_path() {
        let (_tmp, store) = temp_store();
        let kp = Keypair::generate().unwrap();
        store.store("rq_1", kp);
        assert_eq!(store.len(), 1);
        assert!(store.take("rq_1").is_some());
        assert_eq!(store.len(), 0);
        assert!(store.take("rq_1").is_none());
    }

    #[test]
    fn unknown_id_returns_none() {
        let store = KeypairStore::in_memory();
        assert!(store.take("never-stored").is_none());
    }

    #[test]
    fn survives_simulated_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kp.db");
        let key = [7u8; 32];

        let kp_pubkey;
        {
            let store = KeypairStore::open_at(path.clone(), key).unwrap();
            let kp = Keypair::generate().unwrap();
            kp_pubkey = kp.public_spki_b64();
            store.store("rq_persist", kp);
        }
        {
            let store2 = KeypairStore::open_at(path, key).unwrap();
            let recovered = store2.take("rq_persist").expect("recovered keypair");
            assert_eq!(recovered.public_spki_b64(), kp_pubkey);
        }
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("kp.db");

        {
            let store = KeypairStore::open_at(path.clone(), [1u8; 32]).unwrap();
            store.store("rq_x", Keypair::generate().unwrap());
        }
        let store2 = KeypairStore::open_at(path, [2u8; 32]).unwrap();
        assert!(store2.take("rq_x").is_none());
    }
}
