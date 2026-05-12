//! Wires release events through allowlist validation, ledger insert, watcher
//! arming, trigger race, and scrub.
//!
//! On every release event:
//! 1. Validate every transcript path against the runtime's allowlist
//! 2. Insert ledger row (open: scrubbed_at NULL)
//! 3. Build needles (plaintext + variants, when permitted by the path)
//! 4. Race a stop-signal watcher against the 15-min hard cap
//! 5. First fire wins → run scrubber → mark ledger scrubbed
//! 6. On verify failure (or out-of-band rotation flag) → enqueue rotation

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::oneshot;

use crate::daemon::allowlist;
use crate::daemon::cross_runtime_scanner;
use crate::daemon::recent_index::RecentReleasesIndex;
use crate::daemon::release::{AgentRuntime, ReleaseEvent};
use crate::daemon::watcher::{watch_for_stop, watch_sqlite_for_quiet};
use crate::ledger::{Channel, Ledger, LedgerEntry, ScrubAnchors, SqliteAnchor};
use crate::scrubber::{build_needles, scrub_paths, scrub_sqlite_anchors, sqlite as sqlite_scrubber};
use crate::triggers::HARD_CAP_SECONDS;

/// Scope for an external scrub-now signal (`POST /stop`).
///
/// Either field selects the open releases that should fire their scrub
/// immediately. If both are set, the intersection is used. If neither is
/// set, the request is rejected by the endpoint — callers must declare
/// what they're stopping (defence against a bug accidentally scrubbing
/// the world).
#[derive(Debug, Clone, Default)]
pub struct StopScope {
    pub release_id: Option<String>,
    pub session_id: Option<String>,
}

impl StopScope {
    pub fn is_empty(&self) -> bool {
        self.release_id.is_none() && self.session_id.is_none()
    }
}

/// Open release tracking: each entry holds the `session_id` and a
/// oneshot sender that fires the scrub immediately when invoked. Used
/// by [`Daemon::trigger_stop`] (the `POST /stop` endpoint and the local
/// MCP server's disconnect cleanup).
struct OpenRelease {
    session_id: String,
    stopper: oneshot::Sender<()>,
}

#[derive(Clone)]
pub struct Daemon {
    ledger: Ledger,
    open_releases: Arc<Mutex<HashMap<String, OpenRelease>>>,
    /// Serializes the read-modify-write phase of `scrub_paths` across all
    /// releases so two concurrent scrubs targeting the same transcript
    /// file don't clobber each other's redactions. Async-aware so we can
    /// hold it across `await` points if the scrub ever becomes async; for
    /// today's blocking `scrub_paths` it's just a critical section.
    scrub_mutex: Arc<tokio::sync::Mutex<()>>,
    /// Recently-released plaintexts (TTL-bounded, in-memory only). Drives
    /// the cross-runtime scanner; see `daemon::recent_index` for the
    /// retention policy and `daemon::cross_runtime_scanner` for the
    /// continuous redaction pass.
    recent_index: Arc<RecentReleasesIndex>,
}

impl Daemon {
    pub fn new(ledger: Ledger) -> Self {
        let scrub_mutex = Arc::new(tokio::sync::Mutex::new(()));
        // Try to open the persistent recent-releases store so cross-runtime
        // scanning has its needle list ready after a daemon restart. Falls
        // back to in-memory only on any init failure (keychain unavailable,
        // disk write-locked, etc.) — operational fail-open: scrub coverage
        // narrows but the daemon still runs.
        let recent_index = Arc::new(
            RecentReleasesIndex::open_default().unwrap_or_else(|e| {
                tracing::warn!(
                    "recent_releases: persistence init failed ({e:#}); using in-memory fallback"
                );
                RecentReleasesIndex::default()
            }),
        );
        Self {
            ledger,
            open_releases: Arc::new(Mutex::new(HashMap::new())),
            scrub_mutex,
            recent_index,
        }
    }

    /// Spin up the single long-running watcher that redacts cross-session
    /// leaks across every runtime's transcript root. Split out from
    /// `Daemon::new` so the `AppHandle` (only available inside Tauri's
    /// setup closure) can flow in for `cross_runtime_scanner` to emit
    /// persistent-failure events to the UI. `None` is supported for
    /// headless / test contexts; the scanner still runs, it just doesn't
    /// surface failures in a banner.
    pub fn start_cross_runtime_scanner(&self, app: Option<tauri::AppHandle>) {
        cross_runtime_scanner::spawn(
            Arc::clone(&self.recent_index),
            Arc::clone(&self.scrub_mutex),
            app,
        );
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Force any matching open release to scrub immediately.
    ///
    /// Returns the number of releases that were signalled — `0` is a
    /// legitimate outcome (no matching open release; perhaps already
    /// scrubbed by the watcher or hard cap, perhaps the scope didn't
    /// match anything). Callers should treat that as success, not error.
    pub fn trigger_stop(&self, scope: &StopScope) -> usize {
        let mut g = self.open_releases.lock().unwrap();
        // Collect matching keys first so we can `remove` without borrowing
        // the map immutably during iteration.
        let matches: Vec<String> = g
            .iter()
            .filter(|(rid, entry)| {
                let rid_match = scope
                    .release_id
                    .as_deref()
                    .map(|r| r == rid.as_str())
                    .unwrap_or(true);
                let sid_match = scope
                    .session_id
                    .as_deref()
                    .map(|s| s == entry.session_id.as_str())
                    .unwrap_or(true);
                rid_match && sid_match
            })
            .map(|(rid, _)| rid.clone())
            .collect();
        let mut fired = 0usize;
        for rid in matches {
            if let Some(entry) = g.remove(&rid) {
                if entry.stopper.send(()).is_ok() {
                    fired += 1;
                }
            }
        }
        fired
    }

    /// Accept a release event from any IPC channel. Returns Ok(release_id)
    /// once the release has been validated and persisted; the actual scrub
    /// runs as a background task.
    pub fn accept(self: &Arc<Self>, event: ReleaseEvent, channel: Channel) -> Result<String> {
        let validated = self.validate(&event)?;

        // Snapshot file size at release time. The scrubber later confines its
        // edits to bytes written after this point so existing pre-release
        // content (and the user's older saves) stay byte-identical.
        let mut file_offsets: HashMap<String, u64> = HashMap::new();
        for path in &validated {
            let key = path.display().to_string();
            match std::fs::metadata(path) {
                Ok(meta) => {
                    file_offsets.insert(key, meta.len());
                }
                Err(_) => {
                    // File doesn't exist yet — treat as offset 0 so the
                    // entire file is in the task window when it's created.
                    file_offsets.insert(key, 0);
                }
            }
        }
        // Pre-count occurrences of every needle in every sibling file in
        // the runtime's session dir — feeds the Scope-2 scrubber so it
        // knows which occurrences pre-existed and must not be touched.
        // Cheap: a single read + count per file.
        let needles_for_precount = build_needles(
            event.value_plaintext.as_deref(),
            &event.encoded_variants,
        );
        let files_precount = precount_runtime_siblings(&validated, &needles_for_precount);

        // OpenClaw persists agent memory in a SQLite DB next to its
        // session JSONLs; snapshot per-table MAX(rowid) at release time
        // so the SQLite scrubber can confine its edits to rows created
        // during the task window. Other runtimes don't have a
        // file-system memory store today.
        let mut sqlite_anchors: HashMap<String, SqliteAnchor> = HashMap::new();
        if matches!(event.agent_runtime, AgentRuntime::Openclaw) {
            if let Some(home) = dirs::home_dir() {
                let memory_db = home.join(".openclaw").join("memory").join("main.sqlite");
                match sqlite_scrubber::snapshot_anchor(&memory_db) {
                    Ok(Some(anchor)) => {
                        sqlite_anchors.insert(memory_db.display().to_string(), anchor);
                    }
                    Ok(None) => { /* DB doesn't exist yet — nothing to scope */ }
                    Err(e) => {
                        tracing::warn!(
                            "openclaw memory snapshot failed (will skip sqlite scrub): {e:#}"
                        );
                    }
                }
            }
        }

        let anchors = ScrubAnchors {
            files: file_offsets,
            files_precount,
            sqlite: sqlite_anchors,
        };

        let entry = LedgerEntry {
            release_id: event.release_id.clone(),
            session_id: event.session_id.clone(),
            value_hash: event.value_hash.clone(),
            tier: event.tier.clone(),
            agent_runtime: event.agent_runtime.clone(),
            mcp_mode: event.mcp_mode.clone(),
            channel,
            plaintext_seen_locally: event.value_plaintext.is_some(),
            transcript_paths: validated.iter().map(|p| p.display().to_string()).collect(),
            scrub_anchors: anchors.clone(),
            released_at: event.released_at.clone(),
            scrubbed_at: None,
            rotated_at: None,
            trigger_that_fired: None,
            scrub_verified: false,
        };
        self.ledger.insert(&entry).context("ledger insert")?;

        // Register the plaintext with the cross-runtime scanner so it can
        // redact this value from any *other* transcript on disk for the
        // configured TTL — closes the leak where a value released in
        // session A surfaces in session B via a different MCP (chrome
        // page read, screenshot OCR, etc.). Plaintext stays in memory
        // only; the ledger row holds the hash, not the plaintext.
        if let Some(plaintext) = event.value_plaintext.as_ref() {
            self.recent_index.insert(
                plaintext.clone(),
                event.value_hash.clone(),
                event.release_id.clone(),
            );
        }

        let needles = build_needles(
            event.value_plaintext.as_deref(),
            &event.encoded_variants,
        );

        if needles.is_empty() {
            tracing::warn!(
                release_id = %event.release_id,
                "no needles built (true-E2E with no variants); hash-content scan not yet implemented"
            );
        }

        let (external_tx, external_rx) = oneshot::channel::<()>();
        {
            let mut g = self.open_releases.lock().unwrap();
            g.insert(
                event.release_id.clone(),
                OpenRelease {
                    session_id: event.session_id.clone(),
                    stopper: external_tx,
                },
            );
        }

        let me = Arc::clone(self);
        let release_id = event.release_id.clone();
        let paths = validated.clone();
        let rotation_supported = event.rotation_supported;

        tokio::spawn(async move {
            if let Err(e) = me
                .run_lifecycle(
                    release_id,
                    paths,
                    needles,
                    anchors,
                    rotation_supported,
                    external_rx,
                )
                .await
            {
                tracing::error!("release lifecycle: {e:#}");
            }
        });

        Ok(event.release_id)
    }

    fn validate(&self, event: &ReleaseEvent) -> Result<Vec<PathBuf>> {
        let mut out = Vec::with_capacity(event.transcript_paths.len());
        for p in &event.transcript_paths {
            let resolved = allowlist::validate_path(&event.agent_runtime, p)
                .with_context(|| format!("allowlist reject: {p}"))?;
            out.push(resolved);
        }
        Ok(out)
    }

    async fn run_lifecycle(
        self: Arc<Self>,
        release_id: String,
        paths: Vec<PathBuf>,
        needles: Vec<String>,
        anchors: ScrubAnchors,
        rotation_supported: bool,
        external_rx: oneshot::Receiver<()>,
    ) -> Result<()> {
        let watcher_rx = if !paths.is_empty() {
            match watch_for_stop(paths.clone()) {
                Ok(rx) => Some(rx),
                Err(e) => {
                    tracing::warn!("watcher arm failed: {e:#}");
                    None
                }
            }
        } else {
            None
        };

        let trigger = race_triggers(watcher_rx, external_rx).await;

        // Drop the open-release entry once a trigger fires. If the entry
        // was already removed by `trigger_stop`, this is a no-op.
        {
            let mut g = self.open_releases.lock().unwrap();
            g.remove(&release_id);
        }

        let path_strs: Vec<String> =
            paths.iter().map(|p| p.display().to_string()).collect();

        let scrub_outcome = if needles.is_empty() {
            ScrubOutcome::Skipped
        } else {
            // Serialize concurrent scrubs. Two parallel releases on the
            // same transcript file would otherwise race: each one snapshots
            // the file, modifies it, and writes it back; the later writer
            // can clobber the earlier writer's redactions because its
            // in-memory copy was taken before the earlier write. With this
            // lock the second scrubber reads the post-first-scrub content
            // and finds its own plaintext at the shifted position.
            let _scrub_guard = self.scrub_mutex.lock().await;
            // File scrub first; result drives the verified flag.
            let mut outcome = match scrub_paths(&path_strs, &needles, &anchors) {
                Ok(report) => {
                    if report.verified {
                        ScrubOutcome::Verified
                    } else {
                        ScrubOutcome::Unverified
                    }
                }
                Err(e) => {
                    tracing::error!("file scrub failed for {release_id}: {e:#}");
                    ScrubOutcome::Failed
                }
            };

            // SQLite scrub runs only when anchors are present (today,
            // OpenClaw memory). Failure here downgrades the outcome to
            // Unverified — there's a real leak in the memory DB, even
            // if the JSONL scrub looked clean.
            const SQLITE_LOCK_RETRY_MS: u64 = 5_000;
            if !anchors.sqlite.is_empty() {
                match scrub_sqlite_anchors(&anchors, &needles, SQLITE_LOCK_RETRY_MS) {
                    Ok(report) => {
                        tracing::info!(
                            release_id = %release_id,
                            rows = report.rows_modified,
                            replacements = report.replacements,
                            wal_truncated = report.wal_truncated,
                            "sqlite scrub complete",
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            release_id = %release_id,
                            "sqlite scrub failed: {e:#} — marking release unverified \
                             (deferred retry not yet implemented)",
                        );
                        outcome = ScrubOutcome::Unverified;
                    }
                }
            }
            outcome
        };

        // Deferred SQLite scrub: OpenClaw often writes a post-task memory
        // summary AFTER the stop signal fires, which means those rows land
        // after the scrub above has already finished. We watch the DB for
        // write activity to settle, then re-run the SQLite scrubber to catch
        // any post-stop rows. This runs in the background — the primary
        // scrub outcome and the ledger mark are not blocked by it.
        if !anchors.sqlite.is_empty() && !needles.is_empty() {
            let deferred_anchors = anchors.clone();
            let deferred_needles = needles.clone();
            let deferred_release_id = release_id.clone();
            tokio::spawn(async move {
                run_deferred_sqlite_scrub(
                    deferred_anchors,
                    deferred_needles,
                    deferred_release_id,
                )
                .await;
            });
        }

        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::new());

        let verified = matches!(scrub_outcome, ScrubOutcome::Verified);
        self.ledger
            .mark_scrubbed(&release_id, &now, trigger.as_str(), verified)?;

        if !verified && rotation_supported {
            tracing::warn!(release_id = %release_id, "scrub unverified; enqueueing rotation");
            self.ledger.mark_rotated(&release_id, &now)?;
        }

        Ok(())
    }

    /// On daemon start, re-enqueue any release whose row remains unscrubbed.
    /// Each gets a fresh hard-cap window — the scrub will fire either when
    /// the agent emits a late stop signal or when the timer expires.
    pub fn recover_unscrubbed(self: &Arc<Self>) -> Result<()> {
        let open = self.ledger.list_unscrubbed()?;
        for entry in open {
            tracing::info!("re-enqueuing orphaned release {}", entry.release_id);
            let needles: Vec<String> = Vec::new();
            let paths: Vec<PathBuf> =
                entry.transcript_paths.iter().map(PathBuf::from).collect();
            let anchors = entry.scrub_anchors.clone();
            // Recovered releases also get an external-stop channel so a
            // post-restart `POST /stop` can preempt the hard-cap timer.
            let (tx, rx) = oneshot::channel::<()>();
            {
                let mut g = self.open_releases.lock().unwrap();
                g.insert(
                    entry.release_id.clone(),
                    OpenRelease {
                        session_id: entry.session_id.clone(),
                        stopper: tx,
                    },
                );
            }
            let me = Arc::clone(self);
            // `recover_unscrubbed` is called from Tauri's main-thread
            // setup closure where there's no thread-local tokio runtime
            // context, so bare `tokio::spawn` would panic. Use Tauri's
            // explicit-handle wrapper instead.
            tauri::async_runtime::spawn(async move {
                let _ = me
                    .run_lifecycle(entry.release_id, paths, needles, anchors, false, rx)
                    .await;
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum Trigger {
    StopSignal,
    HardCap,
    /// `POST /stop` from the local MCP server, OpenClaw exit hook, etc.
    ExternalStop,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Trigger::StopSignal => "stop_signal",
            Trigger::HardCap => "hard_cap",
            Trigger::ExternalStop => "external_stop",
        }
    }
}

enum ScrubOutcome {
    Verified,
    Unverified,
    Failed,
    Skipped,
}

/// Pre-count occurrences of each needle in every `.jsonl` file in the
/// parent directories of the validated transcript paths. This snapshot
/// feeds the Scope-2 scrubber so it can redact only the *new* occurrences
/// and leave pre-release content byte-identical.
///
/// Wait for every SQLite DB in `anchors` to go quiet (no mtime change for
/// `DEFERRED_QUIET_SECS`), then re-run the SQLite scrubber. This catches
/// rows that OpenClaw writes after the stop signal fires (e.g. post-task
/// memory summaries). The anchor's max_rowids snapshot was taken at
/// release time, so any row written since then — whether during or after
/// the task — still has rowid > snapshot and will be caught.
async fn run_deferred_sqlite_scrub(
    anchors: ScrubAnchors,
    needles: Vec<String>,
    release_id: String,
) {
    /// Seconds of write inactivity before we consider the DB settled.
    const DEFERRED_QUIET_SECS: u64 = 10;
    /// Hard cap: give up and scrub anyway after this many seconds.
    const DEFERRED_CAP_SECS: u64 = 5 * 60;

    for db_path_str in anchors.sqlite.keys() {
        let db_path = std::path::PathBuf::from(db_path_str);
        if !db_path.exists() {
            continue;
        }
        let quiet_rx = watch_sqlite_for_quiet(db_path, DEFERRED_QUIET_SECS, DEFERRED_CAP_SECS);
        // Await quiet signal (or cap). If the channel dropped (thread
        // panicked), fall through and scrub anyway.
        let _ = quiet_rx.await;
    }

    const LOCK_RETRY_MS: u64 = 5_000;
    match scrub_sqlite_anchors(&anchors, &needles, LOCK_RETRY_MS) {
        Ok(r) if r.rows_modified > 0 => {
            tracing::info!(
                release_id = %release_id,
                rows = r.rows_modified,
                replacements = r.replacements,
                "deferred post-task sqlite scrub caught post-stop writes",
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                release_id = %release_id,
                "deferred post-task sqlite scrub failed: {e:#}",
            );
        }
    }
}

/// Walks one level only: the runtime's session dir. Going recursive
/// across `~/.claude/projects/**` would be expensive on large checkouts;
/// the Scope-3 ladder (cross-project sweep) is opt-in and lives in the
/// scrubber once the user enables it.
fn precount_runtime_siblings(
    validated: &[PathBuf],
    needles: &[String],
) -> HashMap<String, HashMap<String, usize>> {
    let mut out: HashMap<String, HashMap<String, usize>> = HashMap::new();
    if needles.is_empty() {
        return out;
    }
    // Dedup parent directories — a single release can list multiple
    // transcript paths in the same dir.
    let mut parents: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    for p in validated {
        if let Some(parent) = p.parent() {
            parents.insert(parent.to_path_buf());
        }
    }
    for parent in parents {
        let Ok(read) = std::fs::read_dir(&parent) else {
            continue;
        };
        for entry in read.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            // Include primary transcript paths as well. Scope-1 covers
            // them via byte-offset slicing, but two concurrent releases
            // on the same primary file can shift bytes underneath each
            // other and leave residue Scope-1 misses. Carrying a
            // precount lets Scope-2 rescue those cases.
            let Ok(bytes) = std::fs::read(&p) else {
                continue;
            };
            let Ok(text) = std::str::from_utf8(&bytes) else {
                continue;
            };
            let mut per_needle: HashMap<String, usize> = HashMap::new();
            for n in needles {
                let count = text.matches(n.as_str()).count();
                if count > 0 {
                    per_needle.insert(n.clone(), count);
                }
            }
            // Insert even if zero across all needles — at scrub time we
            // need to know "we looked at this file, count was zero" so
            // any new occurrences are unambiguously task-window content.
            out.insert(p.display().to_string(), per_needle);
        }
    }
    out
}

/// Race three sources of "task is done — scrub now":
/// - The transcript watcher detecting `stop_reason`/`finish_reason`.
/// - An out-of-band `POST /stop` (or local MCP disconnect).
/// - The 15-minute hard cap (last-ditch).
///
/// First fire wins; the trigger label is recorded on the ledger row.
async fn race_triggers(
    watcher_rx: Option<oneshot::Receiver<()>>,
    external_rx: oneshot::Receiver<()>,
) -> Trigger {
    let hard_cap = tokio::time::sleep(std::time::Duration::from_secs(HARD_CAP_SECONDS));
    tokio::pin!(hard_cap);

    match watcher_rx {
        Some(rx) => tokio::select! {
            _ = rx => Trigger::StopSignal,
            _ = external_rx => Trigger::ExternalStop,
            _ = &mut hard_cap => Trigger::HardCap,
        },
        None => tokio::select! {
            _ = external_rx => Trigger::ExternalStop,
            _ = &mut hard_cap => Trigger::HardCap,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Insert a fake OpenRelease entry directly so we can test `trigger_stop`
    /// without spinning up a real `accept()` flow (which requires a real
    /// transcript file inside the runtime allowlist).
    fn install_fake(daemon: &Daemon, release_id: &str, session_id: &str) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel::<()>();
        let mut g = daemon.open_releases.lock().unwrap();
        g.insert(
            release_id.to_string(),
            OpenRelease {
                session_id: session_id.to_string(),
                stopper: tx,
            },
        );
        rx
    }

    #[test]
    fn trigger_stop_by_release_id_fires_one() {
        let daemon = Daemon::new(Ledger::open_in_memory().unwrap());
        let mut rx_a = install_fake(&daemon, "rls_a", "s1");
        let mut rx_b = install_fake(&daemon, "rls_b", "s2");

        let fired = daemon.trigger_stop(&StopScope {
            release_id: Some("rls_a".into()),
            session_id: None,
        });
        assert_eq!(fired, 1);
        assert!(rx_a.try_recv().is_ok(), "rls_a stopper should have fired");
        assert!(
            matches!(
                rx_b.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "rls_b must not have fired",
        );

        // Map no longer contains rls_a; rls_b is still tracked.
        let g = daemon.open_releases.lock().unwrap();
        assert!(!g.contains_key("rls_a"));
        assert!(g.contains_key("rls_b"));
    }

    #[test]
    fn trigger_stop_by_session_id_fires_all_in_session() {
        let daemon = Daemon::new(Ledger::open_in_memory().unwrap());
        let mut rx_a = install_fake(&daemon, "rls_a", "s1");
        let mut rx_b = install_fake(&daemon, "rls_b", "s1");
        let mut rx_c = install_fake(&daemon, "rls_c", "s2");

        let fired = daemon.trigger_stop(&StopScope {
            release_id: None,
            session_id: Some("s1".into()),
        });
        assert_eq!(fired, 2);
        assert!(rx_a.try_recv().is_ok());
        assert!(rx_b.try_recv().is_ok());
        assert!(matches!(
            rx_c.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        let g = daemon.open_releases.lock().unwrap();
        assert_eq!(g.len(), 1);
        assert!(g.contains_key("rls_c"));
    }

    #[test]
    fn trigger_stop_intersection_when_both_provided() {
        let daemon = Daemon::new(Ledger::open_in_memory().unwrap());
        // Same release_id under different sessions wouldn't actually happen
        // in practice (release_id is globally unique), but use distinct
        // ids+sessions to verify the AND semantics anyway.
        let _rx_a = install_fake(&daemon, "rls_a", "s1");
        let _rx_b = install_fake(&daemon, "rls_b", "s1");
        let fired = daemon.trigger_stop(&StopScope {
            release_id: Some("rls_a".into()),
            session_id: Some("s2".into()),
        });
        assert_eq!(fired, 0, "release_id and session_id must both match");
    }

    #[test]
    fn trigger_stop_with_unknown_scope_is_zero_not_error() {
        let daemon = Daemon::new(Ledger::open_in_memory().unwrap());
        let _rx = install_fake(&daemon, "rls_a", "s1");
        let fired = daemon.trigger_stop(&StopScope {
            release_id: Some("does-not-exist".into()),
            session_id: None,
        });
        assert_eq!(fired, 0);
    }

    #[test]
    fn stop_scope_is_empty() {
        assert!(StopScope::default().is_empty());
        assert!(!StopScope {
            release_id: Some("x".into()),
            session_id: None,
        }
        .is_empty());
        assert!(!StopScope {
            release_id: None,
            session_id: Some("y".into()),
        }
        .is_empty());
    }
}
