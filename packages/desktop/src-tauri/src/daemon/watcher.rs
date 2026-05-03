//! Tails transcript files referenced by a release. On every modify event,
//! reads only the appended bytes and feeds each new line through the
//! stop-signal detector. First detection on any watched file resolves the
//! returned future.
//!
//! Watch registration is per-release: nothing is watched when no values are
//! armed.

use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;
use tokio::sync::oneshot;

use crate::triggers::stop_signal::line_signals_stop;

/// Watch the given files (or directories) and resolve the returned receiver
/// the first time any of them appends a line containing a stop signal.
pub fn watch_for_stop(paths: Vec<PathBuf>) -> Result<oneshot::Receiver<()>> {
    let (tx, rx) = oneshot::channel::<()>();

    std::thread::Builder::new()
        .name("rivault-watcher".into())
        .spawn(move || {
            if let Err(e) = run_watch(paths, tx) {
                tracing::warn!("stop-signal watcher exited: {e:#}");
            }
        })?;

    Ok(rx)
}

fn run_watch(paths: Vec<PathBuf>, tx: oneshot::Sender<()>) -> Result<()> {
    let mut offsets: HashMap<PathBuf, u64> = HashMap::new();
    for p in &paths {
        if p.is_file() {
            offsets.insert(p.clone(), p.metadata().map(|m| m.len()).unwrap_or(0));
        }
    }

    let (tx_evt, rx_evt) = channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx_evt.send(res);
    })?;

    for p in &paths {
        let mode = if p.is_dir() {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        // Watch the parent for files that don't yet exist (e.g. new session JSONL).
        let target: &Path = if p.exists() { p } else { p.parent().unwrap_or(p) };
        if let Err(e) = watcher.watch(target, mode) {
            tracing::warn!("watch {} failed: {e}", target.display());
        }
    }

    // Initial check — the file may already contain a stop signal at registration time.
    if scan_all(&paths, &mut offsets) {
        let _ = tx.send(());
        return Ok(());
    }

    let mut tx_holder = Some(tx);
    loop {
        match rx_evt.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(evt)) => {
                if !matches!(
                    evt.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Any
                ) {
                    continue;
                }
                if scan_all(&paths, &mut offsets) {
                    if let Some(t) = tx_holder.take() {
                        let _ = t.send(());
                    }
                    return Ok(());
                }
            }
            Ok(Err(e)) => tracing::trace!("notify err: {e}"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if tx_holder.is_none() {
                    return Ok(());
                }
            }
            Err(_) => return Ok(()),
        }
    }
}

fn scan_all(paths: &[PathBuf], offsets: &mut HashMap<PathBuf, u64>) -> bool {
    for p in paths {
        if p.is_dir() {
            if scan_dir(p, offsets) {
                return true;
            }
        } else if scan_file(p, offsets) {
            return true;
        }
    }
    false
}

fn scan_dir(dir: &Path, offsets: &mut HashMap<PathBuf, u64>) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if scan_dir(&p, offsets) {
                return true;
            }
        } else if scan_file(&p, offsets) {
            return true;
        }
    }
    false
}

fn scan_file(path: &Path, offsets: &mut HashMap<PathBuf, u64>) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    let len = meta.len();
    let prev = *offsets.get(path).unwrap_or(&0);
    if len <= prev {
        offsets.insert(path.to_path_buf(), len);
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    if f.seek(SeekFrom::Start(prev)).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return false;
    }
    offsets.insert(path.to_path_buf(), len);
    let Ok(s) = std::str::from_utf8(&buf) else {
        return false;
    };
    for line in s.split('\n') {
        if line_signals_stop(line) {
            return true;
        }
    }
    false
}
