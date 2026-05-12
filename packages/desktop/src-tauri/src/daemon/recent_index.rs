//! TTL-bounded index of recently-released plaintexts.
//!
//! When a release lands (via local MCP, Tier-B proxy, or any other channel
//! that ends up in `Daemon::accept`), the plaintext is pushed into this
//! index. The cross-runtime scanner pulls the union of currently-valid
//! needles from here to redact across every watched transcript root.
//!
//! Two storage modes:
//!
//! - **In-memory only** (default, used in tests). The index is empty
//!   after a daemon restart by design — historical retentions are gone.
//! - **Encrypted-at-rest** (`open_default`). The index is backed by a
//!   SQLite table whose rows are wrapped with AES-256-GCM under the
//!   per-install keychain secret. On restart, every non-expired row is
//!   decrypted and re-populated into memory, so cross-runtime scrub
//!   coverage survives the daemon-restart boundary for the TTL window.
//!
//! Persistent mode uses a 1h TTL — much shorter than the 24h in-memory
//! default — to bound the leak window if the keychain secret is ever
//! compromised. Plaintext never sits on disk for longer than that.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use rusqlite::{params, Connection};
use time::OffsetDateTime;

const DEFAULT_TTL_SECS: i64 = 24 * 60 * 60;
const PERSISTENT_TTL_SECS: i64 = 60 * 60;
const DEFAULT_MAX_ENTRIES: usize = 1000;

/// SQLite `user_version` for the recent-releases table. Bump when the
/// schema changes incompatibly; the loader will migrate or drop based
/// on the value at startup.
const SCHEMA_VERSION: i32 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS recent_releases (
    value_hash         TEXT PRIMARY KEY,
    wrapped_b64        TEXT NOT NULL,
    iv_b64             TEXT NOT NULL,
    source_release_id  TEXT NOT NULL,
    expires_at         TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS idx_recent_releases_expires_at
    ON recent_releases(expires_at);
";

#[derive(Debug, Clone)]
pub struct RecentRelease {
    pub plaintext: String,
    pub value_hash: String,
    pub source_release_id: String,
    pub expires_at: OffsetDateTime,
}

pub struct RecentReleasesIndex {
    inner: RwLock<Inner>,
    ttl_secs: i64,
    max_entries: usize,
    persistence: Option<Persistence>,
}

struct Inner {
    /// FIFO order of insertion — pruned from the front when over `max_entries`.
    order: VecDeque<u64>,
    /// `seq` → release row.
    items: HashMap<u64, RecentRelease>,
    /// Dedup: value_hash → seq currently representing it. Prevents the
    /// same plaintext from occupying multiple slots when the agent
    /// re-retrieves the same item.
    by_hash: HashMap<String, u64>,
    next_seq: u64,
}

struct Persistence {
    wrap_key: [u8; 32],
    conn: Mutex<Connection>,
}

impl Default for RecentReleasesIndex {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_SECS, DEFAULT_MAX_ENTRIES)
    }
}

impl RecentReleasesIndex {
    /// In-memory-only index with the given TTL and cap. Used as the
    /// fallback when persistence init fails and as the simplest
    /// constructor in tests.
    pub fn new(ttl_secs: i64, max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(Inner::empty()),
            ttl_secs,
            max_entries,
            persistence: None,
        }
    }

    /// Encrypted-at-rest index backed by SQLite under the daemon's
    /// data directory. The wrapping key is the per-install keychain
    /// secret. On open, every non-expired row is decrypted and seeded
    /// into the in-memory cache so cross-runtime scanning has its
    /// needle list ready before the first new release arrives.
    pub fn open_default() -> Result<Self> {
        let secret = crate::keychain::load_or_create_secret()
            .context("load wrapping key for recent-releases persistence")?;
        if secret.len() < 32 {
            anyhow::bail!("keychain secret too short ({} bytes)", secret.len());
        }
        let mut wrap_key = [0u8; 32];
        wrap_key.copy_from_slice(&secret[..32]);
        let path = default_db_path()?;
        Self::open_at(&path, wrap_key, PERSISTENT_TTL_SECS, DEFAULT_MAX_ENTRIES)
    }

    fn open_at(
        path: &Path,
        wrap_key: [u8; 32],
        ttl_secs: i64,
        max_entries: usize,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).context("open recent_releases store")?;
        let current: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if current != 0 && current != SCHEMA_VERSION {
            // Future-proofing: any unrecognised version → drop the table
            // rather than corrupt it. Plaintext at rest is bounded by
            // TTL anyway; the cost of losing pre-upgrade rows is small.
            conn.execute_batch("DROP TABLE IF EXISTS recent_releases;")
                .context("drop incompatible recent_releases schema")?;
        }
        conn.execute_batch(SCHEMA).context("init recent_releases schema")?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .context("set user_version")?;
        let now = OffsetDateTime::now_utc();
        let inner = Inner::seed_from(&conn, &wrap_key, now)
            .context("seed in-memory index from persisted rows")?;
        let mut idx = Self {
            inner: RwLock::new(inner),
            ttl_secs,
            max_entries,
            persistence: Some(Persistence {
                wrap_key,
                conn: Mutex::new(conn),
            }),
        };
        idx.purge_expired_rows(now);
        Ok(idx)
    }

    /// Insert (or refresh, if the same `value_hash` is already present)
    /// a recent release. Same-hash deduplication keeps the index
    /// bounded for hot vault items the user retrieves repeatedly.
    pub fn insert(&self, plaintext: String, value_hash: String, source_release_id: String) {
        if plaintext.is_empty() {
            return;
        }
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(self.ttl_secs);

        // Persist first so a partial failure leaves the in-memory state
        // in sync with disk (no in-memory row without a row on disk).
        if let Some(p) = &self.persistence {
            if let Err(e) = p.upsert(&plaintext, &value_hash, &source_release_id, expires_at) {
                tracing::warn!(
                    value_hash = %value_hash,
                    "recent_releases: persist failed ({e:#}); keeping in memory only"
                );
            }
        }

        let mut g = self.inner.write().unwrap();
        if let Some(&seq) = g.by_hash.get(&value_hash) {
            if let Some(entry) = g.items.get_mut(&seq) {
                entry.expires_at = expires_at;
                entry.source_release_id = source_release_id;
            }
            return;
        }
        let seq = g.next_seq;
        g.next_seq += 1;
        g.items.insert(
            seq,
            RecentRelease {
                plaintext,
                value_hash: value_hash.clone(),
                source_release_id,
                expires_at,
            },
        );
        g.by_hash.insert(value_hash, seq);
        g.order.push_back(seq);

        while g.order.len() > self.max_entries {
            if let Some(old_seq) = g.order.pop_front() {
                if let Some(entry) = g.items.remove(&old_seq) {
                    g.by_hash.remove(&entry.value_hash);
                    if let Some(p) = &self.persistence {
                        if let Err(e) = p.delete(&entry.value_hash) {
                            tracing::debug!(
                                "recent_releases: cap-evict delete failed: {e:#}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Snapshot every plaintext whose TTL has not yet elapsed. Caller
    /// feeds these into `build_needles` for the scrub. Cleans up
    /// expired entries (in memory and on disk) on the way out.
    pub fn live_plaintexts(&self) -> Vec<String> {
        let now = OffsetDateTime::now_utc();
        let mut g = self.inner.write().unwrap();
        let expired: Vec<u64> = g
            .items
            .iter()
            .filter_map(|(seq, e)| (e.expires_at <= now).then_some(*seq))
            .collect();
        for seq in expired {
            if let Some(entry) = g.items.remove(&seq) {
                g.by_hash.remove(&entry.value_hash);
                if let Some(p) = &self.persistence {
                    if let Err(e) = p.delete(&entry.value_hash) {
                        tracing::debug!(
                            "recent_releases: ttl-evict delete failed: {e:#}"
                        );
                    }
                }
            }
        }
        g.items.values().map(|e| e.plaintext.clone()).collect()
    }

    /// Drop any disk rows whose `expires_at` is in the past. Called
    /// once after `open_at` seeds the in-memory cache, to keep the
    /// persistence file from growing unbounded across restarts where
    /// the daemon never gets around to a regular sweep.
    fn purge_expired_rows(&mut self, now: OffsetDateTime) {
        let Some(p) = &self.persistence else {
            return;
        };
        let now_iso = match now.format(&time::format_description::well_known::Rfc3339) {
            Ok(s) => s,
            Err(_) => return,
        };
        let conn = p.conn.lock().unwrap();
        if let Err(e) = conn.execute(
            "DELETE FROM recent_releases WHERE expires_at <= ?",
            params![now_iso],
        ) {
            tracing::debug!("recent_releases: startup purge failed: {e:#}");
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().items.len()
    }
}

impl Inner {
    fn empty() -> Self {
        Self {
            order: VecDeque::new(),
            items: HashMap::new(),
            by_hash: HashMap::new(),
            next_seq: 0,
        }
    }

    fn seed_from(
        conn: &Connection,
        wrap_key: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<Self> {
        let mut stmt = conn.prepare(
            "SELECT value_hash, wrapped_b64, iv_b64, source_release_id, expires_at
             FROM recent_releases ORDER BY expires_at ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut me = Self::empty();
        for row in rows {
            let (value_hash, wrapped_b64, iv_b64, source_release_id, expires_at_iso) =
                row?;
            let expires_at = match OffsetDateTime::parse(
                &expires_at_iso,
                &time::format_description::well_known::Rfc3339,
            ) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if expires_at <= now {
                continue; // expired row, skip — purge_expired_rows will sweep
            }
            let plaintext = match decrypt(wrap_key, &iv_b64, &wrapped_b64) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        value_hash = %value_hash,
                        "recent_releases: row decrypt failed ({e:#}); dropping"
                    );
                    continue;
                }
            };
            let seq = me.next_seq;
            me.next_seq += 1;
            me.items.insert(
                seq,
                RecentRelease {
                    plaintext,
                    value_hash: value_hash.clone(),
                    source_release_id,
                    expires_at,
                },
            );
            me.by_hash.insert(value_hash, seq);
            me.order.push_back(seq);
        }
        Ok(me)
    }
}

impl Persistence {
    fn upsert(
        &self,
        plaintext: &str,
        value_hash: &str,
        source_release_id: &str,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);
        let cipher = Aes256Gcm::new((&self.wrap_key).into());
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("encrypt recent release: {e}"))?;
        let expires_iso = expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .context("format expires_at")?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recent_releases (value_hash, wrapped_b64, iv_b64, source_release_id, expires_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(value_hash) DO UPDATE SET
                 wrapped_b64       = excluded.wrapped_b64,
                 iv_b64            = excluded.iv_b64,
                 source_release_id = excluded.source_release_id,
                 expires_at        = excluded.expires_at",
            params![value_hash, B64.encode(&ct), B64.encode(iv), source_release_id, expires_iso],
        )?;
        Ok(())
    }

    fn delete(&self, value_hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM recent_releases WHERE value_hash = ?",
            params![value_hash],
        )?;
        Ok(())
    }
}

fn decrypt(wrap_key: &[u8; 32], iv_b64: &str, wrapped_b64: &str) -> Result<String> {
    let iv = B64.decode(iv_b64).context("decode iv")?;
    let ct = B64.decode(wrapped_b64).context("decode wrapped")?;
    let cipher = Aes256Gcm::new(wrap_key.into());
    let nonce = Nonce::from_slice(&iv);
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| anyhow::anyhow!("decrypt recent release: {e}"))?;
    String::from_utf8(pt).context("recent release plaintext must be UTF-8")
}

fn default_db_path() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .context("no data dir")?
        .join("Rivault");
    Ok(dir.join("recent_releases.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x55; 32]
    }

    #[test]
    fn insert_and_snapshot() {
        let idx = RecentReleasesIndex::default();
        idx.insert("hello".into(), "hash1".into(), "rel1".into());
        idx.insert("world".into(), "hash2".into(), "rel2".into());
        let mut got = idx.live_plaintexts();
        got.sort();
        assert_eq!(got, vec!["hello", "world"]);
    }

    #[test]
    fn empty_plaintext_ignored() {
        let idx = RecentReleasesIndex::default();
        idx.insert(String::new(), "hash".into(), "rel".into());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn duplicate_hash_refreshes_in_place() {
        let idx = RecentReleasesIndex::default();
        idx.insert("hello".into(), "hash1".into(), "rel1".into());
        idx.insert("hello".into(), "hash1".into(), "rel2".into());
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn ttl_expiry_drops_entries() {
        let idx = RecentReleasesIndex::new(-1, 1000);
        idx.insert("hello".into(), "hash1".into(), "rel1".into());
        assert!(idx.live_plaintexts().is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn cap_evicts_oldest() {
        let idx = RecentReleasesIndex::new(DEFAULT_TTL_SECS, 2);
        idx.insert("a".into(), "h1".into(), "r1".into());
        idx.insert("b".into(), "h2".into(), "r2".into());
        idx.insert("c".into(), "h3".into(), "r3".into());
        let got = idx.live_plaintexts();
        assert_eq!(got.len(), 2);
        assert!(got.contains(&"b".to_string()));
        assert!(got.contains(&"c".to_string()));
        assert!(!got.contains(&"a".to_string()));
    }

    #[test]
    fn persistent_round_trip_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recent.db");

        let idx = RecentReleasesIndex::open_at(&path, key(), DEFAULT_TTL_SECS, 1000).unwrap();
        idx.insert("foo".into(), "h-foo".into(), "rel-foo".into());
        idx.insert("bar".into(), "h-bar".into(), "rel-bar".into());
        drop(idx);

        let rehydrated =
            RecentReleasesIndex::open_at(&path, key(), DEFAULT_TTL_SECS, 1000).unwrap();
        let mut got = rehydrated.live_plaintexts();
        got.sort();
        assert_eq!(got, vec!["bar", "foo"]);
    }

    #[test]
    fn persistent_drops_expired_rows_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recent.db");

        let idx = RecentReleasesIndex::open_at(&path, key(), -1, 1000).unwrap();
        idx.insert("stale".into(), "h-stale".into(), "rel".into());
        drop(idx);

        let rehydrated =
            RecentReleasesIndex::open_at(&path, key(), DEFAULT_TTL_SECS, 1000).unwrap();
        // The TTL was negative when we wrote, so the row was already
        // expired when persisted. On reopen the seed skips it and
        // purge_expired_rows deletes it.
        assert_eq!(rehydrated.len(), 0);

        // Sanity: the row really is gone from disk.
        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM recent_releases", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn persistent_drops_rows_when_wrap_key_doesnt_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recent.db");

        let idx_a = RecentReleasesIndex::open_at(&path, key(), DEFAULT_TTL_SECS, 1000).unwrap();
        idx_a.insert("under-key-a".into(), "h1".into(), "rel".into());
        drop(idx_a);

        // Rotate the wrap key (e.g. keychain was reinitialised). Rows
        // encrypted under the old key are unreadable; the loader logs
        // and drops them rather than crashing.
        let other = [0xAAu8; 32];
        let idx_b = RecentReleasesIndex::open_at(&path, other, DEFAULT_TTL_SECS, 1000).unwrap();
        assert_eq!(idx_b.len(), 0);
    }

    #[test]
    fn persistent_dedup_keeps_latest_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recent.db");
        let idx = RecentReleasesIndex::open_at(&path, key(), DEFAULT_TTL_SECS, 1000).unwrap();
        idx.insert("v".into(), "h".into(), "first".into());
        idx.insert("v".into(), "h".into(), "second".into());
        drop(idx);

        // After restart only one row survives.
        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM recent_releases", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
