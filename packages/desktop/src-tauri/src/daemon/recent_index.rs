//! In-memory TTL-bounded index of recently-released plaintexts.
//!
//! When a release lands (via local MCP, Tier-B proxy, or any other channel
//! that ends up in `Daemon::accept`), we push the plaintext into this index
//! with a configurable TTL (default 24h). The cross-runtime scanner pulls
//! the union of currently-valid needles from this index to redact across
//! every watched transcript root on disk.
//!
//! Plaintext is deliberately **not** persisted to disk. The ledger stores
//! only `value_hash`; this in-memory store survives only for the daemon's
//! process lifetime. On daemon restart the cross-session feature is empty
//! by design — the per-release scrub anchors (which the ledger does
//! persist) still handle the session that retrieved each value.

use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;
use time::OffsetDateTime;

const DEFAULT_TTL_SECS: i64 = 24 * 60 * 60;
const DEFAULT_MAX_ENTRIES: usize = 1000;

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
}

struct Inner {
    /// FIFO order of insertion — pruned from the front when over `max_entries`.
    order: VecDeque<u64>,
    /// `seq` → release row.
    items: HashMap<u64, RecentRelease>,
    /// Dedup: value_hash → seq currently representing it. Prevents the same
    /// plaintext from occupying multiple slots when the agent re-retrieves
    /// the same item.
    by_hash: HashMap<String, u64>,
    next_seq: u64,
}

impl Default for RecentReleasesIndex {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_SECS, DEFAULT_MAX_ENTRIES)
    }
}

impl RecentReleasesIndex {
    pub fn new(ttl_secs: i64, max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(Inner {
                order: VecDeque::new(),
                items: HashMap::new(),
                by_hash: HashMap::new(),
                next_seq: 0,
            }),
            ttl_secs,
            max_entries,
        }
    }

    /// Insert (or refresh, if the same `value_hash` is already present) a
    /// recent release. Same-hash deduplication keeps the index bounded for
    /// hot vault items the user retrieves repeatedly.
    pub fn insert(&self, plaintext: String, value_hash: String, source_release_id: String) {
        if plaintext.is_empty() {
            return;
        }
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(self.ttl_secs);
        let mut g = self.inner.write().unwrap();

        if let Some(&seq) = g.by_hash.get(&value_hash) {
            // Already present — refresh expiry in place; don't enqueue twice.
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

        // Evict oldest entries past `max_entries` cap regardless of TTL.
        while g.order.len() > self.max_entries {
            if let Some(old_seq) = g.order.pop_front() {
                if let Some(entry) = g.items.remove(&old_seq) {
                    g.by_hash.remove(&entry.value_hash);
                }
            }
        }
    }

    /// Snapshot every plaintext whose TTL has not yet elapsed. Caller feeds
    /// these into `build_needles` for the scrub. Cleans up expired entries
    /// on the way out so the index doesn't grow without bound when TTL
    /// elapses without new inserts.
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
            }
            // VecDeque does not support efficient mid-removal; skip
            // compaction here. Stale seqs in `order` will be observed
            // by `items.get(&seq) == None` in the eviction loop and
            // silently dropped on the next `insert` cycle.
        }
        g.items.values().map(|e| e.plaintext.clone()).collect()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().items.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let idx = RecentReleasesIndex::new(-1, 1000); // negative TTL → always expired
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
}
