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
const MIGRATIONS: &[&str] = &[
    "ALTER TABLE releases ADD COLUMN transcript_offsets TEXT",
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
    /// File-size snapshot per `transcript_paths` at the moment the release
    /// was accepted. Populated for runtimes that store transcripts in
    /// append-only JSONL — used by the scrubber to confine redaction to
    /// the task window so existing pre-release content stays untouched.
    /// Empty / missing for older rows or runtimes we can't safely scope.
    #[serde(default)]
    pub transcript_offsets: HashMap<String, u64>,
    pub released_at: String,
    pub scrubbed_at: Option<String>,
    pub rotated_at: Option<String>,
    pub trigger_that_fired: Option<String>,
    pub scrub_verified: bool,
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
        let offsets_json = if entry.transcript_offsets.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&entry.transcript_offsets)?)
        };
        conn.execute(
            "INSERT OR REPLACE INTO releases (
                release_id, session_id, value_hash, tier, agent_runtime, mcp_mode,
                channel, plaintext_seen_locally, transcript_paths, transcript_offsets,
                released_at, scrubbed_at, rotated_at, trigger_that_fired, scrub_verified
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                offsets_json,
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
                    released_at, scrubbed_at, rotated_at, trigger_that_fired, scrub_verified
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
                    released_at, scrubbed_at, rotated_at, trigger_that_fired, scrub_verified
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
                    released_at, scrubbed_at, rotated_at, trigger_that_fired, scrub_verified
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
    let offsets_s: Option<String> = row.get(9)?;
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
        transcript_offsets: offsets_s
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        released_at: row.get(10)?,
        scrubbed_at: row.get(11)?,
        rotated_at: row.get(12)?,
        trigger_that_fired: row.get(13)?,
        scrub_verified: row.get::<_, i64>(14)? != 0,
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
            transcript_offsets: HashMap::from([("/tmp/x.jsonl".to_string(), 100u64)]),
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
}
