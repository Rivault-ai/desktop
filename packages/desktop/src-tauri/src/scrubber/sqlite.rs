//! Scrub OpenClaw long-term memory at `~/.openclaw/memory/main.sqlite`.
//!
//! OpenClaw persists agent memory in a SQLite database alongside its
//! JSONL session logs — a secret retrieved during a task can land here
//! too (the model summarising what it just saw). This module is the
//! analogue of the file-byte-offset scrubber: at release time we capture
//! `MAX(rowid)` per user table; at scrub time we redact only rows
//! created during the task window so the user's pre-existing memories
//! stay byte-identical.
//!
//! Concurrency: opens the DB with WAL-friendly settings (busy timeout +
//! IMMEDIATE transaction) so an in-flight OpenClaw process can keep
//! reading; we briefly hold the write lock to do the redactions, then
//! `wal_checkpoint(TRUNCATE)` so redacted bytes don't linger in the WAL.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;

use crate::ledger::SqliteAnchor;
use crate::scrubber::REDACTION_MARKER;

/// Capture a rowid+WAL snapshot of every user table in the DB at release
/// time. Returns `None` if the DB doesn't exist yet (release happened
/// before OpenClaw wrote anything to memory) — callers should treat that
/// as "no SQLite scrubbing needed for this release".
///
/// Schema discovery is dynamic: we read `sqlite_schema` and treat every
/// table that's not a SQLite-internal `sqlite_*` table as a target. This
/// stays correct if OpenClaw adds new memory tables without code changes.
pub fn snapshot_anchor(db_path: &Path) -> Result<Option<SqliteAnchor>> {
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {} read-only", db_path.display()))?;
    let tables = list_user_tables(&conn)?;
    let mut max_rowids: HashMap<String, i64> = HashMap::new();
    for table in &tables {
        // COALESCE handles empty tables (MAX over zero rows is NULL).
        let stmt = format!(
            "SELECT COALESCE(MAX(rowid), 0) FROM {}",
            quote_ident(table)
        );
        let max: i64 = conn.query_row(&stmt, [], |r| r.get(0)).unwrap_or(0);
        max_rowids.insert(table.clone(), max);
    }
    let wal_frame = read_wal_frame(&conn).ok();
    Ok(Some(SqliteAnchor {
        max_rowids,
        wal_frame,
    }))
}

#[derive(Debug, Default, Clone)]
pub struct ScrubSqliteReport {
    pub rows_modified: usize,
    pub replacements: usize,
    pub wal_truncated: bool,
}

/// Scrub a single SQLite anchor. Returns the number of rows rewritten so
/// callers can roll the count into a [`crate::scrubber::ScrubReport`].
///
/// Failure modes worth knowing about:
/// - DB locked beyond `lock_retry_ms`: returns Err — caller decides whether
///   to defer (the orchestrator will), and the release stays
///   `scrub_verified=false` until the retry succeeds.
/// - DB rotated away (path no longer exists / different inode): we silently
///   skip; the original DB is gone and there's nothing to redact.
pub fn scrub_anchor(
    db_path: &Path,
    anchor: &SqliteAnchor,
    needles: &[String],
    lock_retry_ms: u64,
) -> Result<ScrubSqliteReport> {
    let mut report = ScrubSqliteReport::default();
    if !db_path.exists() || needles.is_empty() {
        return Ok(report);
    }

    let mut conn = Connection::open(db_path)
        .with_context(|| format!("open {} rw", db_path.display()))?;
    conn.busy_timeout(std::time::Duration::from_millis(lock_retry_ms))
        .ok();

    {
        // BEGIN IMMEDIATE acquires the write lock right away so we don't
        // race a concurrent OpenClaw write that might add more rows
        // mid-scrub.
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("begin immediate")?;

        // Re-discover tables inside the transaction in case OpenClaw added one.
        let tables = list_user_tables(&tx)?;
        for table in &tables {
            let snapshot_max = anchor.max_rowids.get(table).copied().unwrap_or(0);
            let columns = text_or_blob_columns(&tx, table)?;
            if columns.is_empty() {
                continue;
            }

            // Pull rowid + each candidate column for in-window rows.
            let select_cols = std::iter::once("rowid".to_string())
                .chain(columns.iter().map(|c| quote_ident(c)))
                .collect::<Vec<_>>()
                .join(", ");
            let select_stmt = format!(
                "SELECT {} FROM {} WHERE rowid > ?1",
                select_cols,
                quote_ident(table),
            );
            let rows: Vec<(i64, Vec<Option<Vec<u8>>>)> = {
                let mut stmt = tx.prepare(&select_stmt)?;
                let collected: rusqlite::Result<Vec<(i64, Vec<Option<Vec<u8>>>)>> = stmt
                    .query_map(params![snapshot_max], |r| {
                        let rowid: i64 = r.get(0)?;
                        let mut vals: Vec<Option<Vec<u8>>> = Vec::with_capacity(columns.len());
                        for i in 0..columns.len() {
                            let raw = r.get_ref(i + 1)?;
                            vals.push(match raw {
                                rusqlite::types::ValueRef::Null => None,
                                rusqlite::types::ValueRef::Text(b) => Some(b.to_vec()),
                                rusqlite::types::ValueRef::Blob(b) => Some(b.to_vec()),
                                // Numeric/Integer values can't contain plaintext
                                // we care about; skip them.
                                _ => None,
                            });
                        }
                        Ok((rowid, vals))
                    })?
                    .collect();
                collected?
            };

            for (rowid, values) in rows {
                for (i, val) in values.iter().enumerate() {
                    let Some(bytes) = val else { continue };
                    let Ok(text) = std::str::from_utf8(bytes) else {
                        continue;
                    };
                    let mut s = text.to_string();
                    let mut hits = 0usize;
                    for n in needles {
                        let count = s.matches(n.as_str()).count();
                        if count > 0 {
                            s = s.replace(n.as_str(), REDACTION_MARKER);
                            hits += count;
                        }
                    }
                    if hits == 0 {
                        continue;
                    }
                    let update_stmt = format!(
                        "UPDATE {} SET {} = ?1 WHERE rowid = ?2",
                        quote_ident(table),
                        quote_ident(&columns[i]),
                    );
                    tx.execute(&update_stmt, params![s, rowid])?;
                    report.rows_modified += 1;
                    report.replacements += hits;
                }
            }
        }

        tx.commit().context("commit scrub txn")?;
    }

    // Drain the WAL so redacted bytes don't sit in the -wal file. If
    // TRUNCATE can't fully drain (other readers active), fall back to
    // FULL — better than nothing.
    let drained = checkpoint_truncate(&conn)
        .or_else(|_| checkpoint_full(&conn))
        .is_ok();
    report.wal_truncated = drained;
    Ok(report)
}

// ---- helpers --------------------------------------------------------------

fn list_user_tables(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .context("prepare list_user_tables")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names)
}

fn text_or_blob_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let pragma = format!("PRAGMA table_info({})", quote_ident(table));
    let mut stmt = conn.prepare(&pragma)?;
    let cols = stmt
        .query_map([], |r| {
            let name: String = r.get(1)?;
            let decl_type: String = r.get(2).unwrap_or_default();
            Ok((name, decl_type))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(cols
        .into_iter()
        .filter_map(|(name, ty)| {
            // Match SQLite's type-affinity rules loosely: if declared type
            // contains TEXT, CLOB, CHAR, or BLOB, we'll inspect it. Empty
            // declared type defaults to BLOB affinity (SQLite spec) so we
            // include it.
            let t = ty.to_ascii_uppercase();
            let included = ty.is_empty()
                || t.contains("TEXT")
                || t.contains("CLOB")
                || t.contains("CHAR")
                || t.contains("BLOB");
            included.then_some(name)
        })
        .collect())
}

/// Best-effort WAL frame number read. Returns whatever
/// `PRAGMA wal_checkpoint(PASSIVE)` reports for the log-size counter,
/// or `Err` if the DB isn't in WAL mode (rolling back to journal mode
/// would also surface here as a non-WAL error).
fn read_wal_frame(conn: &Connection) -> Result<u64> {
    let row: (i64, i64, i64) = conn.query_row(
        "PRAGMA wal_checkpoint(PASSIVE)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok(row.1.max(0) as u64)
}

fn checkpoint_truncate(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

fn checkpoint_full(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA wal_checkpoint(FULL)")?;
    Ok(())
}

/// Quote a SQLite identifier with double-quotes, doubling embedded
/// double-quotes per the SQL spec. Defends against crafted table/column
/// names if OpenClaw ever stores user-controlled identifiers.
fn quote_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for c in name.chars() {
        if c == '"' {
            out.push_str("\"\"");
        } else {
            out.push(c);
        }
    }
    out.push('"');
    out
}

// ---- tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn tmp_db(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rivault-sqlite-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn open_seed(p: &std::path::Path) -> Connection {
        let conn = Connection::open(p).unwrap();
        conn.execute_batch(
            "CREATE TABLE memories (
                id INTEGER PRIMARY KEY,
                kind TEXT,
                body TEXT
            );",
        )
        .unwrap();
        conn
    }

    fn count_in_col(conn: &Connection, table: &str, col: &str, needle: &str) -> usize {
        let q = format!("SELECT COUNT(*) FROM {table} WHERE instr({col}, ?1) > 0");
        conn.query_row(&q, params![needle], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    #[test]
    fn snapshot_returns_none_for_missing_db() {
        let p = std::env::temp_dir().join(format!("does-not-exist-{}.db", rand::random::<u64>()));
        let got = snapshot_anchor(&p).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn snapshot_captures_max_rowid_per_table() {
        let p = tmp_db("snap.sqlite");
        let conn = open_seed(&p);
        conn.execute(
            "INSERT INTO memories (kind, body) VALUES ('note', 'first')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO memories (kind, body) VALUES ('note', 'second')",
            [],
        )
        .unwrap();
        drop(conn);
        let anchor = snapshot_anchor(&p).unwrap().unwrap();
        assert_eq!(anchor.max_rowids.get("memories").copied(), Some(2));
    }

    #[test]
    fn scrub_redacts_only_rows_added_after_snapshot() {
        let p = tmp_db("scrub.sqlite");
        // Pre-existing user memory containing the value.
        let conn = open_seed(&p);
        conn.execute(
            "INSERT INTO memories (kind, body) VALUES ('user', 'my email is alice@example.com')",
            [],
        )
        .unwrap();
        drop(conn);

        let anchor = snapshot_anchor(&p).unwrap().unwrap();
        // Pretend the anchor's been written, then OpenClaw appends two
        // task-window memories — one with the value, one without.
        let conn = Connection::open(&p).unwrap();
        conn.execute(
            "INSERT INTO memories (kind, body) VALUES ('agent', 'used alice@example.com on form')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO memories (kind, body) VALUES ('agent', 'task complete')",
            [],
        )
        .unwrap();
        drop(conn);

        let report = scrub_anchor(
            &p,
            &anchor,
            &["alice@example.com".to_string()],
            5_000,
        )
        .unwrap();

        let conn = Connection::open(&p).unwrap();
        // Pre-existing row (rowid=1) must be byte-identical.
        let pre_body: String = conn
            .query_row(
                "SELECT body FROM memories WHERE rowid = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pre_body, "my email is alice@example.com");
        // The task-window row that contained the value is redacted.
        assert_eq!(
            count_in_col(&conn, "memories", "body", "alice@example.com"),
            1,
            "only the original pre-task occurrence should remain"
        );
        assert_eq!(report.rows_modified, 1);
        assert_eq!(report.replacements, 1);
    }

    #[test]
    fn scrub_handles_multiple_tables() {
        let p = tmp_db("multi.sqlite");
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE memories (id INTEGER PRIMARY KEY, body TEXT);
             CREATE TABLE threads (id INTEGER PRIMARY KEY, summary TEXT);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO memories (body) VALUES ('pre-existing memory with bobs-token')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (summary) VALUES ('pre-existing thread with bobs-token')",
            [],
        )
        .unwrap();
        drop(conn);

        let anchor = snapshot_anchor(&p).unwrap().unwrap();

        let conn = Connection::open(&p).unwrap();
        conn.execute(
            "INSERT INTO memories (body) VALUES ('task memory bobs-token in there')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (summary) VALUES ('task thread bobs-token here')",
            [],
        )
        .unwrap();
        drop(conn);

        scrub_anchor(&p, &anchor, &["bobs-token".to_string()], 5_000).unwrap();

        let conn = Connection::open(&p).unwrap();
        assert_eq!(count_in_col(&conn, "memories", "body", "bobs-token"), 1);
        assert_eq!(
            count_in_col(&conn, "threads", "summary", "bobs-token"),
            1
        );
    }

    #[test]
    fn scrub_ignores_internal_sqlite_tables() {
        // sqlite_schema and friends should never be touched even though they
        // are tables. The list_user_tables helper filters them out.
        let p = tmp_db("internal.sqlite");
        let conn = open_seed(&p);
        // Trigger SQLite to create an internal sqlite_sequence table by
        // inserting into a table with autoincrement.
        conn.execute_batch(
            "CREATE TABLE auto (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT);
             INSERT INTO auto (body) VALUES ('seed value-x');",
        )
        .unwrap();
        drop(conn);
        let tables = {
            let conn = Connection::open(&p).unwrap();
            list_user_tables(&conn).unwrap()
        };
        assert!(tables.contains(&"memories".to_string()));
        assert!(tables.contains(&"auto".to_string()));
        assert!(
            !tables.iter().any(|t| t.starts_with("sqlite_")),
            "internal tables must be filtered: {tables:?}"
        );
    }

    #[test]
    fn schema_change_after_snapshot_does_not_panic() {
        // OpenClaw could add a table after we snapshotted. Scrub must
        // still succeed — the new table just has snapshot_max=0 so
        // every row in it is treated as in-window.
        let p = tmp_db("growth.sqlite");
        let conn = open_seed(&p);
        conn.execute("INSERT INTO memories (body) VALUES ('value-w')", [])
            .unwrap();
        drop(conn);
        let anchor = snapshot_anchor(&p).unwrap().unwrap();

        // Now add a new table with an entry containing the same value.
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, content TEXT);
             INSERT INTO notes (content) VALUES ('task wrote value-w');",
        )
        .unwrap();
        drop(conn);

        scrub_anchor(&p, &anchor, &["value-w".to_string()], 5_000).unwrap();

        // notes.content was added entirely after the snapshot — every
        // occurrence is post-task and should be redacted.
        let conn = Connection::open(&p).unwrap();
        assert_eq!(count_in_col(&conn, "notes", "content", "value-w"), 0);
        // memories.body was pre-existing — unchanged.
        assert_eq!(count_in_col(&conn, "memories", "body", "value-w"), 1);
    }
}
