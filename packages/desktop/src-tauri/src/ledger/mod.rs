//! Local SQLite ledger at `~/Library/Application Support/Rivault/ledger.db`.
//!
//! On daemon restart any row with `scrubbed_at = NULL` past the hard cap is
//! re-enqueued for scrub.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::daemon::release::{AgentRuntime, McpMode, Tier};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS releases (
    release_id              TEXT PRIMARY KEY,
    session_id              TEXT NOT NULL,
    value_hash              TEXT NOT NULL,
    tier                    TEXT NOT NULL,
    agent_runtime           TEXT NOT NULL,
    mcp_mode                TEXT,
    channel                 TEXT NOT NULL,
    plaintext_seen_locally  INTEGER NOT NULL,
    transcript_paths        TEXT NOT NULL,
    transcript_offsets      TEXT,
    scrub_anchors           TEXT,
    released_at             TEXT NOT NULL,
    scrubbed_at             TEXT,
    rotated_at              TEXT,
    trigger_that_fired      TEXT,
    scrub_verified          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_releases_open
  ON releases (released_at) WHERE scrubbed_at IS NULL;
";

// Adds columns introduced after the v0 schema. ALTER TABLE ADD COLUMN is
// idempotent here only because we wrap each in its own transaction and
// silently ignore the duplicate-column error rusqlite raises on retry.
//
// `transcript_offsets` is kept (not dropped) so older rows remain readable;
// `scrub_anchors` supersedes it for new inserts and carries both file-byte
// offsets and SQLite rowid anchors.
const MIGRATIONS: &[&str] = &[
    "ALTER TABLE releases ADD COLUMN transcript_offsets TEXT",
    "ALTER TABLE releases ADD COLUMN scrub_anchors TEXT",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub release_id: String,
    pub session_id: String,
    pub value_hash: String,
    pub tier: Tier,
    pub agent_runtime: AgentRuntime,
    pub mcp_mode: Option<McpMode>,
    pub channel: Channel,
    pub plaintext_seen_locally: bool,
    pub transcript_paths: Vec<String>,
    /// Snapshots taken at release time so the scrubber can confine its
    /// edits to the task window and leave pre-release content
    /// byte-identical. Carries file-byte offsets for append-only JSONL
    /// transcripts and per-table `MAX(rowid)` for SQLite memory stores
    /// (e.g. `~/.openclaw/memory/main.sqlite`). Empty / missing for older
    /// rows or runtimes we can't safely scope.
    #[serde(default)]
    pub scrub_anchors: ScrubAnchors,
    pub released_at: String,
    pub scrubbed_at: Option<String>,
    pub rotated_at: Option<String>,
    pub trigger_that_fired: Option<String>,
    pub scrub_verified: bool,
}

/// Task-window anchors persisted alongside each release.
///
/// Three flavors today:
/// - `files`: per-path byte offset captured from `metadata.len()` at release
///   time. Scrubbed bytes are confined to `[offset, EOF)` — used by the
///   targeted Scope-1 scrubber.
/// - `files_precount`: pre-existing occurrence count of the plaintext (and
///   each encoded variant) in every sibling transcript file at release
///   time. Used by the Scope-2 escalation scrubber to redact only the
///   *new* occurrences in files we didn't snapshot byte-offsets for.
///   Outer key: file path. Inner key: needle. Value: occurrence count
///   pre-release.
/// - `sqlite`: per-database `MAX(rowid)` snapshot per table (used by the
///   OpenClaw memory scrubber). Rows where `rowid > snapshot` are
///   in-window and may be scrubbed; older rows are left byte-identical.
///
/// Maps are keyed by absolute path so a single release can carry a mix
/// (e.g. an OpenClaw release scopes the JSONL transcript, every sibling
/// session file, and the memory DB).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScrubAnchors {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub files: HashMap<String, u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub files_precount: HashMap<String, HashMap<String, usize>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sqlite: HashMap<String, SqliteAnchor>,
}

impl ScrubAnchors {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.files_precount.is_empty() && self.sqlite.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SqliteAnchor {
    /// Per-table `MAX(rowid)` at release time. `INTEGER PRIMARY KEY` columns
    /// alias `rowid`, so this also covers tables with explicit primary keys.
    pub max_rowids: HashMap<String, i64>,
    /// WAL frame number at snapshot time; informational, not load-bearing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wal_frame: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Ipc,
    Localhost,
    Websocket,
}

impl Channel {
    fn as_str(&self) -> &'static str {
        match self {
            Channel::Ipc => "ipc",
            Channel::Localhost => "localhost",
            Channel::Websocket => "websocket",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "ipc" => Channel::Ipc,
            "localhost" => Channel::Localhost,
            _ => Channel::Websocket,
        }
    }
}

#[derive(Clone)]
pub struct Ledger {
    conn: Arc<Mutex<Connection>>,
}

impl Ledger {
    pub fn open() -> Result<Self> {
        let path = ledger_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(&path).with_context(|| format!("open {path:?}"))?;
        conn.execute_batch(SCHEMA)?;
        run_migrations(&conn);
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        run_migrations(&conn);
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn insert(&self, entry: &LedgerEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        // New rows write `scrub_anchors` only. The old `transcript_offsets`
        // column stays NULL on new inserts (it's preserved for read-back of
        // historical rows; see `row_to_entry`).
        let anchors_json = if entry.scrub_anchors.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&entry.scrub_anchors)?)
        };
        conn.execute(
            "INSERT OR REPLACE INTO releases (
                release_id, session_id, value_hash, tier, agent_runtime, mcp_mode,
                channel, plaintext_seen_locally, transcript_paths, transcript_offsets,
                scrub_anchors, released_at, scrubbed_at, rotated_at, trigger_that_fired,
                scrub_verified
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                entry.release_id,
                entry.session_id,
                entry.value_hash,
                serde_json::to_string(&entry.tier)?,
                serde_json::to_string(&entry.agent_runtime)?,
                entry
                    .mcp_mode
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                entry.channel.as_str(),
                entry.plaintext_seen_locally as i64,
                serde_json::to_string(&entry.transcript_paths)?,
                Option::<String>::None,
                anchors_json,
                entry.released_at,
                entry.scrubbed_at,
                entry.rotated_at,
                entry.trigger_that_fired,
                entry.scrub_verified as i64,
            ],
        )?;
        Ok(())
    }

    pub fn mark_scrubbed(
        &self,
        release_id: &str,
        scrubbed_at: &str,
        trigger: &str,
        verified: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE releases SET scrubbed_at = ?, trigger_that_fired = ?, scrub_verified = ?
             WHERE release_id = ?",
            params![scrubbed_at, trigger, verified as i64, release_id],
        )?;
        Ok(())
    }

    pub fn mark_rotated(&self, release_id: &str, rotated_at: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE releases SET rotated_at = ? WHERE release_id = ?",
            params![rotated_at, release_id],
        )?;
        Ok(())
    }

    pub fn get(&self, release_id: &str) -> Result<Option<LedgerEntry>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT release_id, session_id, value_hash, tier, agent_runtime, mcp_mode,
                    channel, plaintext_seen_locally, transcript_paths, transcript_offsets,
                    scrub_anchors, released_at, scrubbed_at, rotated_at, trigger_that_fired,
                    scrub_verified
             FROM releases WHERE release_id = ?",
            params![release_id],
            row_to_entry,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list_recent(&self, limit: i64) -> Result<Vec<LedgerEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT release_id, session_id, value_hash, tier, agent_runtime, mcp_mode,
                    channel, plaintext_seen_locally, transcript_paths, transcript_offsets,
                    scrub_anchors, released_at, scrubbed_at, rotated_at, trigger_that_fired,
                    scrub_verified
             FROM releases ORDER BY released_at DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit], row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn list_unscrubbed(&self) -> Result<Vec<LedgerEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT release_id, session_id, value_hash, tier, agent_runtime, mcp_mode,
                    channel, plaintext_seen_locally, transcript_paths, transcript_offsets,
                    scrub_anchors, released_at, scrubbed_at, rotated_at, trigger_that_fired,
                    scrub_verified
             FROM releases WHERE scrubbed_at IS NULL ORDER BY released_at ASC",
        )?;
        let rows = stmt.query_map([], row_to_entry)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<LedgerEntry> {
    let tier_s: String = row.get(3)?;
    let runtime_s: String = row.get(4)?;
    let mcp_mode_s: Option<String> = row.get(5)?;
    let channel_s: String = row.get(6)?;
    let paths_s: String = row.get(8)?;
    let legacy_offsets_s: Option<String> = row.get(9)?;
    let anchors_s: Option<String> = row.get(10)?;

    // Prefer the new `scrub_anchors` column. For older rows that only have
    // `transcript_offsets`, lift those into anchors.files so the scrubber
    // sees a uniform shape regardless of when the row was written.
    let scrub_anchors: ScrubAnchors = match anchors_s
        .as_deref()
        .and_then(|s| serde_json::from_str::<ScrubAnchors>(s).ok())
    {
        Some(a) => a,
        None => {
            let files: HashMap<String, u64> = legacy_offsets_s
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            ScrubAnchors {
                files,
                files_precount: HashMap::new(),
                sqlite: HashMap::new(),
            }
        }
    };

    Ok(LedgerEntry {
        release_id: row.get(0)?,
        session_id: row.get(1)?,
        value_hash: row.get(2)?,
        tier: serde_json::from_str(&tier_s).unwrap_or(Tier::L1),
        agent_runtime: serde_json::from_str(&runtime_s).unwrap_or(AgentRuntime::Custom),
        mcp_mode: mcp_mode_s.and_then(|s| serde_json::from_str(&s).ok()),
        channel: Channel::parse(&channel_s),
        plaintext_seen_locally: row.get::<_, i64>(7)? != 0,
        transcript_paths: serde_json::from_str(&paths_s).unwrap_or_default(),
        scrub_anchors,
        released_at: row.get(11)?,
        scrubbed_at: row.get(12)?,
        rotated_at: row.get(13)?,
        trigger_that_fired: row.get(14)?,
        scrub_verified: row.get::<_, i64>(15)? != 0,
    })
}

fn run_migrations(conn: &Connection) {
    for stmt in MIGRATIONS {
        if let Err(e) = conn.execute(stmt, []) {
            // Duplicate column on second open is expected; only log other errors.
            let s = e.to_string();
            if !s.contains("duplicate column") {
                tracing::warn!("ledger migration `{stmt}` failed: {s}");
            }
        }
    }
}

fn ledger_path() -> Result<PathBuf> {
    Ok(dirs::data_dir()
        .context("no data dir")?
        .join("Rivault")
        .join("ledger.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(release_id: &str) -> LedgerEntry {
        LedgerEntry {
            release_id: release_id.into(),
            session_id: "s1".into(),
            value_hash: "abcd".into(),
            tier: Tier::L1,
            agent_runtime: AgentRuntime::ClaudeCode,
            mcp_mode: Some(McpMode::ServerDecrypt),
            channel: Channel::Ipc,
            plaintext_seen_locally: true,
            transcript_paths: vec!["/tmp/x.jsonl".into()],
            scrub_anchors: ScrubAnchors {
                files: HashMap::from([("/tmp/x.jsonl".to_string(), 100u64)]),
                files_precount: HashMap::new(),
                sqlite: HashMap::new(),
            },
            released_at: "2026-05-01T00:00:00Z".into(),
            scrubbed_at: None,
            rotated_at: None,
            trigger_that_fired: None,
            scrub_verified: false,
        }
    }

    #[test]
    fn round_trip() {
        let l = Ledger::open_in_memory().unwrap();
        l.insert(&fixture("rls_1")).unwrap();
        let got = l.get("rls_1").unwrap().unwrap();
        assert_eq!(got.session_id, "s1");
        assert!(got.scrubbed_at.is_none());
    }

    #[test]
    fn duplicate_release_id_returns_ok_no_panic() {
        // Regression for an old audit finding that warned the orchestrator
        // could `.unwrap()` a ledger.insert failure and crash the spawn
        // task. The orchestrator now propagates errors via `?`; this test
        // anchors the *ledger's* side of that contract — inserts always
        // return a `Result`, never panic, even when the row already
        // exists. The schema's `INSERT OR REPLACE` semantics make a
        // duplicate `release_id` overwrite cleanly, so the second insert
        // observes the second entry's contents.
        let l = Ledger::open_in_memory().unwrap();
        let mut first = fixture("rls_dup");
        first.session_id = "first".into();
        l.insert(&first).expect("first insert returns Ok");

        let mut second = fixture("rls_dup");
        second.session_id = "second".into();
        // Must not panic — that's the audit's load-bearing concern.
        l.insert(&second).expect("duplicate insert returns Ok");

        let got = l.get("rls_dup").unwrap().unwrap();
        assert_eq!(got.session_id, "second");
    }

    #[test]
    fn mark_scrubbed_persists() {
        let l = Ledger::open_in_memory().unwrap();
        l.insert(&fixture("rls_2")).unwrap();
        l.mark_scrubbed("rls_2", "2026-05-01T00:01:00Z", "stop_signal", true)
            .unwrap();
        let got = l.get("rls_2").unwrap().unwrap();
        assert_eq!(got.scrubbed_at.as_deref(), Some("2026-05-01T00:01:00Z"));
        assert_eq!(got.trigger_that_fired.as_deref(), Some("stop_signal"));
        assert!(got.scrub_verified);
    }

    #[test]
    fn lists_unscrubbed_only() {
        let l = Ledger::open_in_memory().unwrap();
        l.insert(&fixture("rls_a")).unwrap();
        l.insert(&fixture("rls_b")).unwrap();
        l.mark_scrubbed("rls_a", "now", "hard_cap", true).unwrap();
        let open = l.list_unscrubbed().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].release_id, "rls_b");
    }

    #[test]
    fn anchors_round_trip_files_only() {
        let l = Ledger::open_in_memory().unwrap();
        let entry = fixture("rls_files");
        l.insert(&entry).unwrap();
        let got = l.get("rls_files").unwrap().unwrap();
        assert_eq!(got.scrub_anchors, entry.scrub_anchors);
        assert_eq!(got.scrub_anchors.files["/tmp/x.jsonl"], 100u64);
        assert!(got.scrub_anchors.sqlite.is_empty());
    }

    #[test]
    fn anchors_round_trip_with_sqlite() {
        let l = Ledger::open_in_memory().unwrap();
        let mut entry = fixture("rls_sql");
        let mut max_rowids = HashMap::new();
        max_rowids.insert("memories".to_string(), 4242i64);
        max_rowids.insert("threads".to_string(), 17i64);
        entry.scrub_anchors.sqlite.insert(
            "/Users/u/.openclaw/memory/main.sqlite".to_string(),
            SqliteAnchor {
                max_rowids,
                wal_frame: Some(99),
            },
        );
        l.insert(&entry).unwrap();

        let got = l.get("rls_sql").unwrap().unwrap();
        assert_eq!(got.scrub_anchors, entry.scrub_anchors);
        let sql = &got.scrub_anchors.sqlite["/Users/u/.openclaw/memory/main.sqlite"];
        assert_eq!(sql.max_rowids["memories"], 4242);
        assert_eq!(sql.wal_frame, Some(99));
    }

    /// Older rows wrote `transcript_offsets` and never `scrub_anchors`. The
    /// reader has to lift those into `anchors.files` so callers see one shape.
    #[test]
    fn legacy_transcript_offsets_lift_into_anchors() {
        let l = Ledger::open_in_memory().unwrap();
        // Bypass the normal `insert` path to write a row that mimics what
        // an older daemon would have produced: transcript_offsets populated,
        // scrub_anchors NULL.
        {
            let conn = l.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO releases (
                    release_id, session_id, value_hash, tier, agent_runtime, mcp_mode,
                    channel, plaintext_seen_locally, transcript_paths, transcript_offsets,
                    scrub_anchors, released_at, scrubbed_at, rotated_at, trigger_that_fired,
                    scrub_verified
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    "rls_legacy",
                    "s1",
                    "h",
                    "\"l1\"",
                    "\"claude-code\"",
                    Option::<String>::None,
                    "ipc",
                    1i64,
                    "[\"/tmp/old.jsonl\"]",
                    "{\"/tmp/old.jsonl\":7}",
                    Option::<String>::None,
                    "2026-05-01T00:00:00Z",
                    Option::<String>::None,
                    Option::<String>::None,
                    Option::<String>::None,
                    0i64,
                ],
            )
            .unwrap();
        }

        let got = l.get("rls_legacy").unwrap().unwrap();
        assert_eq!(got.scrub_anchors.files["/tmp/old.jsonl"], 7u64);
        assert!(got.scrub_anchors.sqlite.is_empty());
    }
}
