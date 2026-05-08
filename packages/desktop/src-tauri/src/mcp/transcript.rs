//! Resolve the active transcript path(s) for a runtime.
//!
//! Rust port of `packages/skill/src/lib/daemonEmit.ts::resolveTranscriptPaths`.
//! Keeping the heuristics identical so the OpenClaw plugin's behavior and
//! the daemon's MCP behavior agree on what gets scrubbed.
//!
//! Order of precedence:
//! 1. Env var override (`OPENCLAW_TRANSCRIPT_PATH`, etc.). Most authoritative.
//! 2. Most-recently-modified `.jsonl` under the runtime's well-known dir.
//!    Reliable in practice — agents append to the active session in
//!    real time, so its mtime is always the newest.
//! 3. `[]` for runtimes whose transcripts live in proprietary blobs
//!    (Claude Desktop LevelDB; ChatGPT desktop). The daemon records the
//!    release as `unsupported_runtime` and won't pretend to scrub.

use crate::daemon::release::AgentRuntime;
use std::fs;
use std::path::PathBuf;

/// Returns the absolute path string of the resolved transcript, or an
/// empty vec if none could be resolved (release will be flagged
/// `unsupported_runtime` in the ledger).
pub fn resolve_transcript_paths(runtime: &AgentRuntime) -> Vec<String> {
    // Env-var hints take precedence — they're the most authoritative
    // signal a runtime can give us.
    let env_keys = &[
        "OPENCLAW_TRANSCRIPT_PATH",
        "CLAUDE_TRANSCRIPT_PATH",
        "CODEX_TRANSCRIPT_PATH",
    ];
    let mut from_env: Vec<String> = Vec::new();
    for k in env_keys {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                from_env.push(v);
            }
        }
    }
    if !from_env.is_empty() {
        return from_env;
    }

    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };

    let (dir, recursive): (Option<PathBuf>, bool) = match runtime {
        AgentRuntime::Openclaw => (
            Some(home.join(".openclaw").join("agents").join("main").join("sessions")),
            false,
        ),
        AgentRuntime::ClaudeCode => (Some(home.join(".claude").join("projects")), true),
        AgentRuntime::Codex => (Some(home.join(".codex").join("sessions")), true),
        AgentRuntime::ClaudeDesktop | AgentRuntime::Custom => (None, false),
    };

    let Some(dir) = dir else {
        return Vec::new();
    };
    match most_recent_jsonl(&dir, recursive) {
        Some(p) => vec![p.display().to_string()],
        None => Vec::new(),
    }
}

/// Walk `root` looking for the most-recently-modified file with extension
/// `.jsonl`. Returns `None` if no such file exists or the directory is
/// unreadable. When `recursive` is false, only the immediate children of
/// `root` are inspected.
fn most_recent_jsonl(root: &PathBuf, recursive: bool) -> Option<PathBuf> {
    let mut best: Option<(PathBuf, std::time::SystemTime)> = None;
    let mut stack: Vec<PathBuf> = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let p = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                if recursive {
                    stack.push(p);
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(mtime) = meta.modified() else { continue };
            match &best {
                None => best = Some((p, mtime)),
                Some((_, prev)) if mtime > *prev => best = Some((p, mtime)),
                _ => {}
            }
        }
    }
    best.map(|(p, _)| p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, SystemTime};

    /// Sandbox for tests: builds an isolated tmp dir, runs the closure with
    /// a fake home that the resolver can probe.
    fn with_tmp_dir<F: FnOnce(&PathBuf)>(f: F) {
        let dir = std::env::temp_dir().join(format!(
            "rivault-mcp-transcript-{}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        f(&dir);
        let _ = fs::remove_dir_all(&dir);
    }

    fn touch(p: &PathBuf, contents: &str, age: Duration) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        // Age the file backward by `age` so the "most recent" comparison
        // is deterministic regardless of filesystem mtime resolution.
        let when = SystemTime::now() - age;
        let _ = filetime::set_file_mtime(p, filetime::FileTime::from_system_time(when));
    }

    #[test]
    fn picks_most_recently_modified_jsonl() {
        with_tmp_dir(|root| {
            let older = root.join("older.jsonl");
            let newer = root.join("newer.jsonl");
            touch(&older, "{}", Duration::from_secs(60));
            touch(&newer, "{}", Duration::from_secs(1));
            let got = most_recent_jsonl(root, false).unwrap();
            assert_eq!(got, newer);
        });
    }

    #[test]
    fn ignores_non_jsonl() {
        with_tmp_dir(|root| {
            let log = root.join("session.log");
            let json = root.join("session.json");
            let jsonl = root.join("session.jsonl");
            touch(&log, "x", Duration::from_secs(60));
            touch(&json, "x", Duration::from_secs(30));
            touch(&jsonl, "x", Duration::from_secs(10));
            let got = most_recent_jsonl(root, false).unwrap();
            assert_eq!(got, jsonl);
        });
    }

    #[test]
    fn recursive_mode_descends_subdirs() {
        with_tmp_dir(|root| {
            let nested = root.join("project-a").join("session.jsonl");
            touch(&nested, "{}", Duration::from_secs(5));
            assert!(most_recent_jsonl(root, false).is_none());
            assert_eq!(most_recent_jsonl(root, true).unwrap(), nested);
        });
    }

    #[test]
    fn empty_dir_returns_none() {
        with_tmp_dir(|root| {
            assert!(most_recent_jsonl(root, true).is_none());
        });
    }
}
