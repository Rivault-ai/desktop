//! Scrub engine.
//!
//! V0 covers exact-string match against plaintext + caller-supplied encoded
//! variants. Hash-content scan for true-E2E L2 (where plaintext is absent
//! from the release event) is a v1 follow-up; the entry point accepts the
//! hash but does not yet scan for it.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

pub const REDACTION_MARKER: &str = "[REDACTED:rivault]";

/// Build the set of needles for a given plaintext value:
/// - the value itself
/// - base64 (standard)
/// - URL-encoded
/// - JSON-escaped (string body, no surrounding quotes)
/// - any caller-supplied precomputed variants (e.g. mobile-precomputed for E2E paths)
pub fn build_needles(plaintext: Option<&str>, supplied_variants: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Some(v) = plaintext {
        if !v.is_empty() {
            set.insert(v.to_string());
            set.insert(B64.encode(v.as_bytes()));
            set.insert(urlencoding::encode(v).into_owned());
            set.insert(json_escape(v));
        }
    }
    for v in supplied_variants {
        if !v.is_empty() {
            set.insert(v.clone());
        }
    }
    // Sort by length desc so we never replace a substring of a still-pending match.
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_by(|a, b| b.len().cmp(&a.len()));
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct ScrubReport {
    pub files_modified: Vec<String>,
    pub total_replacements: usize,
    pub verified: bool,
}

/// Scrub the given paths.
///
/// `offsets` records the file size at the moment the release was accepted.
/// We scrub only bytes written *after* that offset — the task window — so
/// older content the user wrote before the agent retrieved a value is left
/// byte-identical. Files not present in `offsets` (e.g. the path is a
/// directory we recursed into) are scrubbed in full.
///
/// Three integrity checks before we overwrite:
/// 1. File still UTF-8 (skip if binary now)
/// 2. Current size >= stored offset (otherwise the file was truncated/
///    rotated underneath us — fall back to full-file scrub on the new file
///    since we have no idea where the task-window suffix begins)
/// 3. Verify pass after rewrite confirms no needle remains anywhere in the
///    suffix; if any does, the report is marked unverified and the
///    orchestrator can enqueue rotation.
pub fn scrub_paths(
    paths: &[String],
    needles: &[String],
    offsets: &HashMap<String, u64>,
) -> Result<ScrubReport> {
    if needles.is_empty() {
        return Err(anyhow!("no needles to scrub"));
    }
    let mut report = ScrubReport::default();
    for p in paths {
        let path = Path::new(p);
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            scrub_dir(path, needles, offsets, &mut report)?;
        } else {
            let start = offsets.get(p).copied().unwrap_or(0);
            scrub_one(path, needles, start, &mut report)?;
        }
    }
    report.verified = verify(paths, needles, offsets)?;
    Ok(report)
}

fn scrub_dir(
    dir: &Path,
    needles: &[String],
    offsets: &HashMap<String, u64>,
    report: &mut ScrubReport,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            scrub_dir(&p, needles, offsets, report)?;
        } else {
            // Files inside a watched directory don't have per-path offsets
            // (the orchestrator only snapshots explicit transcript paths),
            // so fall back to full-file scrub for these.
            let start = offsets.get(&p.display().to_string()).copied().unwrap_or(0);
            scrub_one(&p, needles, start, report)?;
        }
    }
    Ok(())
}

fn scrub_one(
    path: &Path,
    needles: &[String],
    start: u64,
    report: &mut ScrubReport,
) -> Result<()> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return Ok(()), // best effort; skip unreadable
    };
    // Truncation / rotation guard: if the file shrunk below our snapshot,
    // the original task-window suffix is gone. Whatever's there now is
    // entirely "new" — scrub the whole thing rather than crashing on
    // out-of-range slicing.
    let effective_start = if (start as usize) <= bytes.len() {
        start as usize
    } else {
        0
    };
    let prefix = &bytes[..effective_start];
    let suffix = &bytes[effective_start..];
    let Ok(suffix_str) = std::str::from_utf8(suffix) else {
        return Ok(()); // skip binary suffix
    };
    let mut s = suffix_str.to_string();
    let mut hits = 0;
    for n in needles {
        let count = s.matches(n.as_str()).count();
        if count > 0 {
            s = s.replace(n.as_str(), REDACTION_MARKER);
            hits += count;
        }
    }
    if hits > 0 {
        // Reassemble: untouched prefix + scrubbed suffix.
        let mut out = Vec::with_capacity(prefix.len() + s.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(s.as_bytes());
        fs::write(path, out)?;
        report.files_modified.push(path.display().to_string());
        report.total_replacements += hits;
    }
    Ok(())
}

/// Verify pass — confirms no needle survives in the task-window suffix.
///
/// We deliberately only check the suffix, not the whole file. Pre-release
/// content that happens to contain a needle (e.g. the user pasted the same
/// password into a chat days ago) is none of the daemon's business — we
/// want to verify the redaction we *did*, not all historical occurrences.
fn verify(
    paths: &[String],
    needles: &[String],
    offsets: &HashMap<String, u64>,
) -> Result<bool> {
    for p in paths {
        let path = Path::new(p);
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            if !verify_dir(path, needles, offsets)? {
                return Ok(false);
            }
        } else {
            let start = offsets.get(p).copied().unwrap_or(0);
            if !verify_one(path, needles, start)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn verify_dir(
    dir: &Path,
    needles: &[String],
    offsets: &HashMap<String, u64>,
) -> Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            if !verify_dir(&p, needles, offsets)? {
                return Ok(false);
            }
        } else {
            let start = offsets.get(&p.display().to_string()).copied().unwrap_or(0);
            if !verify_one(&p, needles, start)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn verify_one(path: &Path, needles: &[String], start: u64) -> Result<bool> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(true);
    };
    let effective_start = if (start as usize) <= bytes.len() {
        start as usize
    } else {
        0
    };
    let Ok(s) = std::str::from_utf8(&bytes[effective_start..]) else {
        return Ok(true);
    };
    for n in needles {
        if s.contains(n.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpfile(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rivault-test-{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        p
    }

    fn no_offsets() -> HashMap<String, u64> {
        HashMap::new()
    }

    #[test]
    fn replaces_plaintext_and_base64() {
        let p = tmpfile(
            "x.jsonl",
            "leak hello@rivault.ai and aGVsbG9Acml2YXVsdC5haQ== then done",
        );
        let needles = build_needles(Some("hello@rivault.ai"), &[]);
        let report =
            scrub_paths(&[p.display().to_string()], &needles, &no_offsets()).unwrap();
        assert!(report.verified);
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("hello@rivault.ai"));
        assert!(!after.contains("aGVsbG9Acml2YXVsdC5haQ=="));
        assert!(after.contains(REDACTION_MARKER));
        assert!(report.total_replacements >= 2);
    }

    #[test]
    fn handles_url_encoded() {
        let p = tmpfile("y.jsonl", "redirect=secret%40rivault.ai end");
        let needles = build_needles(Some("secret@rivault.ai"), &[]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_offsets()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("secret%40rivault.ai"));
    }

    #[test]
    fn supplied_variants_only_path() {
        let p = tmpfile("z.jsonl", "ciphertext: AAAA== body BBBB done");
        let needles = build_needles(None, &["AAAA==".into(), "BBBB".into()]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_offsets()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("AAAA=="));
        assert!(!after.contains("BBBB"));
    }

    #[test]
    fn missing_path_is_ok() {
        let needles = build_needles(Some("x"), &[]);
        let r = scrub_paths(&["/tmp/does-not-exist-xyz".into()], &needles, &no_offsets())
            .unwrap();
        assert!(r.verified);
        assert!(r.files_modified.is_empty());
    }

    #[test]
    fn longest_needle_wins() {
        let p = tmpfile("zz.jsonl", "abcdef and abc done");
        let needles = build_needles(None, &["abc".into(), "abcdef".into()]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_offsets()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("abcdef"));
        assert!(!after.contains("abc"));
    }

    #[test]
    fn task_window_preserves_pre_release_content() {
        // Pre-release prefix already contains the same string the agent
        // later retrieved (coincidence). Offset says the task window
        // starts after that prefix — only the post-offset suffix is
        // scrubbed.
        let prefix = "older line: super-secret was already here\n";
        let suffix = "task line: super-secret\n";
        let p = tmpfile("window.jsonl", &format!("{prefix}{suffix}"));

        let mut offsets = HashMap::new();
        offsets.insert(p.display().to_string(), prefix.len() as u64);

        let needles = build_needles(Some("super-secret"), &[]);
        let report = scrub_paths(&[p.display().to_string()], &needles, &offsets).unwrap();

        let after = fs::read_to_string(&p).unwrap();
        // Pre-release line untouched
        assert!(
            after.starts_with(prefix),
            "prefix changed unexpectedly: {after}"
        );
        // Suffix has the redaction marker
        assert!(after.contains(REDACTION_MARKER));
        assert_eq!(report.total_replacements, 1);
        // Verify only checks the suffix, so it should still pass even though
        // the marker-free pre-release occurrence is technically present.
        assert!(report.verified);
    }

    #[test]
    fn truncation_falls_back_to_full_file_scrub() {
        // File shrunk below the recorded offset (rotation/rewrite). The
        // scrubber should not panic and should treat the whole file as the
        // task window.
        let p = tmpfile("rotate.jsonl", "fresh content with secret123 in it");
        let mut offsets = HashMap::new();
        offsets.insert(p.display().to_string(), 9_999u64);
        let needles = build_needles(Some("secret123"), &[]);
        let r = scrub_paths(&[p.display().to_string()], &needles, &offsets).unwrap();
        assert!(r.verified);
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("secret123"));
    }
}
