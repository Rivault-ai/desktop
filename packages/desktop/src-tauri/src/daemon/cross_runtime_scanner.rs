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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::daemon::allowlist::all_default_roots;
use crate::daemon::recent_index::RecentReleasesIndex;
use crate::scrubber::{build_needles, scrub_for_index};

/// Debounce window: collapse a burst of writes to the same file into a
/// single scan. The agent runtime writes one JSONL line at a time, so
/// a multi-line tool result can produce ~50 events in a few ms.
const DEBOUNCE_MS: u64 = 500;

/// Spawn the scanner. Returns once the watcher thread is alive; the
/// thread runs for the daemon's lifetime.
///
/// `scrub_mutex` is shared with `Daemon` so the scanner serializes with
/// per-release `scrub_paths` and doesn't race the targeted scrubber on
/// the same file.
pub fn spawn(index: Arc<RecentReleasesIndex>, scrub_mutex: Arc<Mutex<()>>) {
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
            if let Err(e) = run(roots, index, scrub_mutex) {
                tracing::warn!("cross-runtime scanner exited: {e:#}");
            }
        })
        .expect("failed to spawn cross-runtime scanner thread");
}

fn run(
    roots: Vec<PathBuf>,
    index: Arc<RecentReleasesIndex>,
    scrub_mutex: Arc<Mutex<()>>,
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

    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
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
                    pending.insert(path, now);
                }
            }
            Ok(Err(e)) => tracing::trace!("cross-runtime scanner notify err: {e}"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Ok(()),
        }
        flush_debounced(&mut pending, &index, &scrub_mutex);
    }
}

fn is_candidate(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()) == Some("jsonl") && p.is_file()
}

fn flush_debounced(
    pending: &mut HashMap<PathBuf, Instant>,
    index: &Arc<RecentReleasesIndex>,
    scrub_mutex: &Arc<Mutex<()>>,
) {
    if pending.is_empty() {
        return;
    }
    let now = Instant::now();
    let deadline = Duration::from_millis(DEBOUNCE_MS);
    let ready: Vec<PathBuf> = pending
        .iter()
        .filter_map(|(p, ts)| (now.duration_since(*ts) >= deadline).then(|| p.clone()))
        .collect();
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
            Ok(0) => {}
            Ok(hits) => {
                tracing::info!(
                    path = %p.display(),
                    redactions = hits,
                    "cross-runtime scanner redacted {hits} occurrence(s)",
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %p.display(),
                    error = %e,
                    "cross-runtime scanner scrub failed",
                );
            }
        }
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
}
