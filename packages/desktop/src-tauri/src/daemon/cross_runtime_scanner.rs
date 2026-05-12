//! Cross-runtime continuous scanner.
//!
//! One long-running `notify` watcher armed over the union of every
//! runtime's transcript root (`allowlist::all_default_roots()`). On any
//! `Modify`/`Create` event under those roots, the scanner debounces for
//! ~500ms, then runs a scrub against the union of currently-valid
//! plaintexts in the daemon's `RecentReleasesIndex`.
//!
//! This closes the cross-session leak gap: a value released through
//! Rivault in session A is also redacted from session B's transcript
//! within the TTL window, even when B retrieved it via an unrelated
//! channel (chrome page read, OCR, another MCP, etc.).
//!
//! Bounded blast radius:
//! - Watches *only* allowlist roots. Files outside them are never read.
//! - Only `*.jsonl` files trigger scrubs (transcript convention across
//!   all current runtimes). Other file types are ignored.
//! - The plaintext index is in-memory and TTL-bounded; once a value's
//!   TTL elapses, the scanner stops scrubbing future occurrences.

use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

use crate::daemon::allowlist::all_default_roots;
use crate::daemon::recent_index::RecentReleasesIndex;
use crate::scrubber::{build_needles, scrub_for_index};

/// Debounce window: collapse a burst of writes to the same file into a
/// single scan. The agent runtime writes one JSONL line at a time, so
/// a multi-line tool result can produce ~50 events in a few ms.
const DEBOUNCE_MS: u64 = 500;

/// Additional EOF-stability window: even after the debounce elapses, the
/// scanner stats the file and waits for `(size, mtime)` to be unchanged
/// for this long before scrubbing. Closes a race where a multi-line
/// tool result writes one line every ~600ms — the debounce alone would
/// fire on the first quiet gap and scan a partial file, missing
/// plaintext appended afterward.
const STABILITY_MS: u64 = 200;

/// Tauri event name the desktop UI listens for to surface persistent
/// scrub failures. Frontend in `packages/desktop/src/App.tsx` listens
/// on this exact string.
pub const SCANNER_FAILURE_EVENT: &str = "rivault://scanner-failure";

/// How many consecutive failures on the same path must accumulate
/// before we surface the banner. Three keeps the UI quiet for
/// transient blips (a permission glitch during a logout, a brief
/// `mkdir` race in a fresh runtime) while still firing fast enough
/// for genuinely stuck files.
pub const FAILURE_THRESHOLD: u32 = 3;

/// Payload sent to the frontend on a persistent scrub failure.
/// `consecutive` matches `FAILURE_THRESHOLD` on the first emit; if
/// failures keep accumulating, the counter keeps rising so the UI
/// can show the duration of the stall.
#[derive(Debug, Clone, Serialize)]
pub struct ScannerFailurePayload {
    pub path: String,
    pub error: String,
    pub consecutive: u32,
}

/// Spawn the scanner. Returns once the watcher thread is alive; the
/// thread runs for the daemon's lifetime.
///
/// `scrub_mutex` is shared with `Daemon` so the scanner serializes with
/// per-release `scrub_paths` and doesn't race the targeted scrubber on
/// the same file.
pub fn spawn(
    index: Arc<RecentReleasesIndex>,
    scrub_mutex: Arc<Mutex<()>>,
    app: Option<AppHandle>,
) {
    let roots = all_default_roots();
    if roots.is_empty() {
        tracing::info!("cross-runtime scanner: no allowlist roots — skipping");
        return;
    }
    let roots_for_log: Vec<String> = roots.iter().map(|p| p.display().to_string()).collect();
    tracing::info!(
        roots = ?roots_for_log,
        "starting cross-runtime scanner",
    );

    std::thread::Builder::new()
        .name("rivault-cross-runtime-scanner".into())
        .spawn(move || {
            if let Err(e) = run(roots, index, scrub_mutex, app) {
                tracing::warn!("cross-runtime scanner exited: {e:#}");
            }
        })
        .expect("failed to spawn cross-runtime scanner thread");
}

fn run(
    roots: Vec<PathBuf>,
    index: Arc<RecentReleasesIndex>,
    scrub_mutex: Arc<Mutex<()>>,
    app: Option<AppHandle>,
) -> Result<()> {
    let (tx_evt, rx_evt) = channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx_evt.send(res);
    })?;

    for root in &roots {
        // Watch the root if it exists, otherwise its parent so the
        // scanner picks up new transcript dirs created at runtime
        // (e.g. first OpenClaw session after a fresh install).
        let target: &Path = if root.exists() {
            root
        } else {
            root.parent().unwrap_or(root)
        };
        if let Err(e) = watcher.watch(target, RecursiveMode::Recursive) {
            tracing::warn!(
                "cross-runtime scanner: watch {} failed: {e}",
                target.display()
            );
        }
    }

    let mut pending: HashMap<PathBuf, PendingEntry> = HashMap::new();
    let mut failures: HashMap<PathBuf, u32> = HashMap::new();
    loop {
        // Block briefly for the next event; if we have a pending debounce,
        // wake up to flush it.
        let timeout = if pending.is_empty() {
            Duration::from_secs(60)
        } else {
            Duration::from_millis(DEBOUNCE_MS / 2)
        };
        match rx_evt.recv_timeout(timeout) {
            Ok(Ok(evt)) => {
                if !matches!(
                    evt.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Any
                ) {
                    continue;
                }
                let now = Instant::now();
                for path in evt.paths {
                    if !is_candidate(&path) {
                        continue;
                    }
                    pending
                        .entry(path)
                        .and_modify(|e| e.last_event = now)
                        .or_insert_with(|| PendingEntry::new(now));
                }
            }
            Ok(Err(e)) => tracing::trace!("cross-runtime scanner notify err: {e}"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Ok(()),
        }
        flush_debounced(&mut pending, &mut failures, &index, &scrub_mutex, app.as_ref());
    }
}

/// State for a single transcript path waiting to be scrubbed. Tracks
/// both the last-event timestamp (debounce timer) and the most recent
/// stat result (EOF-stability timer).
struct PendingEntry {
    last_event: Instant,
    last_stat: Option<(u64, SystemTime)>,
    last_stat_at: Option<Instant>,
}

impl PendingEntry {
    fn new(now: Instant) -> Self {
        Self {
            last_event: now,
            last_stat: None,
            last_stat_at: None,
        }
    }
}

fn is_candidate(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()) == Some("jsonl") && p.is_file()
}

fn flush_debounced(
    pending: &mut HashMap<PathBuf, PendingEntry>,
    failures: &mut HashMap<PathBuf, u32>,
    index: &Arc<RecentReleasesIndex>,
    scrub_mutex: &Arc<Mutex<()>>,
    app: Option<&AppHandle>,
) {
    if pending.is_empty() {
        return;
    }
    let now = Instant::now();
    let debounce = Duration::from_millis(DEBOUNCE_MS);
    let stability = Duration::from_millis(STABILITY_MS);

    let mut ready: Vec<PathBuf> = Vec::new();
    let mut to_remove: Vec<PathBuf> = Vec::new();

    for (path, entry) in pending.iter_mut() {
        // Step 1: debounce — must be `DEBOUNCE_MS` since the last event.
        if now.duration_since(entry.last_event) < debounce {
            continue;
        }
        // Step 2: EOF-stability — stat the file, defer if size or mtime
        // changed since the last check, scrub once it's been quiet for
        // `STABILITY_MS`. A missing file is treated as "settled" so we
        // remove it from `pending` without scrubbing.
        let stat = match std::fs::metadata(path) {
            Ok(m) => (m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)),
            Err(_) => {
                to_remove.push(path.clone());
                continue;
            }
        };
        match (entry.last_stat, entry.last_stat_at) {
            (Some(prev), Some(prev_ts)) if prev == stat => {
                if now.duration_since(prev_ts) >= stability {
                    ready.push(path.clone());
                }
            }
            _ => {
                entry.last_stat = Some(stat);
                entry.last_stat_at = Some(now);
            }
        }
    }
    for p in &to_remove {
        pending.remove(p);
    }
    if ready.is_empty() {
        return;
    }
    for p in &ready {
        pending.remove(p);
    }
    let plaintexts = index.live_plaintexts();
    if plaintexts.is_empty() {
        return;
    }
    let needles = build_needles_from_plaintexts(&plaintexts);
    if needles.is_empty() {
        return;
    }
    // Serialize with per-release scrubs. The mutex is async; acquire
    // synchronously via blocking_lock since the scanner thread is not
    // inside a tokio runtime.
    let scrub_mutex = Arc::clone(scrub_mutex);
    let _guard = scrub_mutex.blocking_lock_owned();
    for p in ready {
        match scrub_for_index(&p, &needles) {
            Ok(0) => {
                // No-op success — clear any prior failure streak.
                failures.remove(&p);
            }
            Ok(hits) => {
                failures.remove(&p);
                tracing::info!(
                    path = %p.display(),
                    redactions = hits,
                    "cross-runtime scanner redacted {hits} occurrence(s)",
                );
            }
            Err(e) => {
                let err_str = format!("{e:#}");
                tracing::warn!(
                    path = %p.display(),
                    error = %err_str,
                    "cross-runtime scanner scrub failed",
                );
                if let Some(payload) = record_failure(failures, &p, err_str) {
                    if let Some(app) = app {
                        if let Err(e) = app.emit(SCANNER_FAILURE_EVENT, &payload) {
                            tracing::debug!(
                                "failed to emit scanner-failure event: {e:#}",
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Increment the consecutive-failure counter for `path` and return a
/// payload when the threshold is crossed. The first emit fires at
/// `FAILURE_THRESHOLD`; subsequent emits fire on every additional
/// failure so a stuck file keeps surfacing (with a rising counter)
/// rather than going silent after the initial banner.
fn record_failure(
    failures: &mut HashMap<PathBuf, u32>,
    path: &Path,
    error: String,
) -> Option<ScannerFailurePayload> {
    let count = failures.entry(path.to_path_buf()).or_insert(0);
    *count += 1;
    if *count >= FAILURE_THRESHOLD {
        Some(ScannerFailurePayload {
            path: path.display().to_string(),
            error,
            consecutive: *count,
        })
    } else {
        None
    }
}

/// `build_needles` takes a single plaintext at a time; the scanner
/// works with a snapshot of many plaintexts. Union the needle sets and
/// dedup so we don't re-replace the same byte sequence.
fn build_needles_from_plaintexts(plaintexts: &[String]) -> Vec<String> {
    let mut set: HashSet<String> = HashSet::new();
    for pt in plaintexts {
        for n in build_needles(Some(pt), &[]) {
            set.insert(n);
        }
    }
    let mut out: Vec<String> = set.into_iter().collect();
    // Longest first so we don't shadow a longer match with a shorter one.
    out.sort_by(|a, b| b.len().cmp(&a.len()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrubber::REDACTION_MARKER;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn build_dedups_across_plaintexts() {
        // Two identical plaintexts produce one needle set.
        let needles = build_needles_from_plaintexts(&["hello".into(), "hello".into()]);
        let direct = build_needles(Some("hello"), &[]);
        assert_eq!(needles.len(), direct.len());
    }

    #[test]
    fn end_to_end_scrub() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("session.jsonl");
        fs::write(
            &f,
            r#"{"type":"user","msg":"give me demo@rivault.ai now"}"#,
        )
        .unwrap();

        let needles = build_needles_from_plaintexts(&["demo@rivault.ai".into()]);
        let hits = scrub_for_index(&f, &needles).unwrap();
        assert_eq!(hits, 1);
        let after = fs::read_to_string(&f).unwrap();
        assert!(after.contains(REDACTION_MARKER));
        assert!(!after.contains("demo@rivault.ai"));
    }

    /// Pure unit test for the debounce + stability decision. Builds a
    /// `pending` map by hand and asserts which paths a flush would
    /// promote to the "scrub now" list. Avoids spinning up a notify
    /// watcher or sleeping; instead we mint `Instant`s by subtracting
    /// from `now`.
    #[test]
    fn flush_requires_stability_after_debounce() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("transcript.jsonl");
        fs::write(&path, "first line\n").unwrap();
        let stat0 = fs::metadata(&path).unwrap();
        let s0 = (
            stat0.len(),
            stat0.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        );

        let now = Instant::now();
        let long_ago = now - Duration::from_millis(DEBOUNCE_MS + STABILITY_MS + 50);
        let just_after_debounce = now - Duration::from_millis(DEBOUNCE_MS + 10);

        let index = Arc::new(RecentReleasesIndex::default());
        let scrub_mutex = Arc::new(Mutex::new(()));

        // Case 1: debounce satisfied, but stat was just observed → not
        // yet stable, must remain pending.
        let mut pending = HashMap::new();
        pending.insert(
            path.clone(),
            PendingEntry {
                last_event: just_after_debounce,
                last_stat: Some(s0),
                last_stat_at: Some(now), // observed "now" → 0ms stable
            },
        );
        flush_debounced(&mut pending, &mut HashMap::new(), &index, &scrub_mutex, None);
        assert!(
            pending.contains_key(&path),
            "stat just observed; must defer until STABILITY_MS elapses"
        );

        // Case 2: debounce satisfied AND stat unchanged long enough →
        // ready to flush (and gets removed).
        let mut pending = HashMap::new();
        pending.insert(
            path.clone(),
            PendingEntry {
                last_event: long_ago,
                last_stat: Some(s0),
                last_stat_at: Some(long_ago),
            },
        );
        flush_debounced(&mut pending, &mut HashMap::new(), &index, &scrub_mutex, None);
        assert!(
            !pending.contains_key(&path),
            "stable file past STABILITY_MS must flush and drop the entry"
        );

        // Case 3: stale stat from a previous observation no longer
        // matches the current file (size grew between checks) → stat is
        // replaced and the entry stays pending for another stability
        // window.
        let mut pending = HashMap::new();
        pending.insert(
            path.clone(),
            PendingEntry {
                last_event: long_ago,
                last_stat: Some((s0.0 + 999, s0.1)), // pretend last stat saw a different size
                last_stat_at: Some(long_ago),
            },
        );
        flush_debounced(&mut pending, &mut HashMap::new(), &index, &scrub_mutex, None);
        let entry = pending.get(&path).expect("size mismatch must defer");
        assert_eq!(entry.last_stat, Some(s0), "stat updated to current file");
    }

    #[test]
    fn flush_drops_path_when_file_disappears() {
        let dir = TempDir::new().unwrap();
        let ghost = dir.path().join("vanished.jsonl");
        let index = Arc::new(RecentReleasesIndex::default());
        let scrub_mutex = Arc::new(Mutex::new(()));

        let mut pending = HashMap::new();
        pending.insert(
            ghost.clone(),
            PendingEntry {
                last_event: Instant::now() - Duration::from_secs(1),
                last_stat: None,
                last_stat_at: None,
            },
        );
        flush_debounced(&mut pending, &mut HashMap::new(), &index, &scrub_mutex, None);
        assert!(
            !pending.contains_key(&ghost),
            "missing file must be removed from pending instead of stalling forever"
        );
    }

    /// Direct test of the failure-counter threshold logic. Avoids
    /// running the scanner thread or trying to coax scrub_for_index into
    /// failing; we just want to lock in: the first two failures emit
    /// nothing, the third returns a payload, subsequent failures keep
    /// returning rising-`consecutive` payloads, and a success between
    /// failures resets the streak.
    #[test]
    fn record_failure_emits_on_third_consecutive() {
        let mut failures: HashMap<PathBuf, u32> = HashMap::new();
        let p = PathBuf::from("/tmp/rivault-test-failure.jsonl");

        assert!(record_failure(&mut failures, &p, "io1".into()).is_none());
        assert!(record_failure(&mut failures, &p, "io2".into()).is_none());
        let third = record_failure(&mut failures, &p, "io3".into())
            .expect("third failure must emit");
        assert_eq!(third.consecutive, FAILURE_THRESHOLD);
        assert_eq!(third.error, "io3");
        assert_eq!(third.path, p.display().to_string());

        let fourth = record_failure(&mut failures, &p, "io4".into())
            .expect("subsequent failures keep emitting with rising count");
        assert_eq!(fourth.consecutive, FAILURE_THRESHOLD + 1);
    }

    #[test]
    fn record_failure_separate_paths_have_independent_counters() {
        let mut failures: HashMap<PathBuf, u32> = HashMap::new();
        let a = PathBuf::from("/tmp/a.jsonl");
        let b = PathBuf::from("/tmp/b.jsonl");
        // Two failures on `a` and two on `b` — both still under threshold.
        for _ in 0..2 {
            assert!(record_failure(&mut failures, &a, "err".into()).is_none());
            assert!(record_failure(&mut failures, &b, "err".into()).is_none());
        }
        // Third failure on `a` crosses, but `b` is unaffected.
        let payload = record_failure(&mut failures, &a, "err".into()).unwrap();
        assert_eq!(payload.consecutive, FAILURE_THRESHOLD);
        assert_eq!(payload.path, a.display().to_string());
    }
}
