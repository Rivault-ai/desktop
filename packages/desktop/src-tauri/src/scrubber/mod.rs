//! Scrub engine.
//!
//! V0 covers exact-string match against plaintext + caller-supplied encoded
//! variants. Hash-content scan for true-E2E L2 (where plaintext is absent
//! from the release event) is a v1 follow-up; the entry point accepts the
//! hash but does not yet scan for it.

pub mod sqlite;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::ledger::ScrubAnchors;

/// Which scope ultimately landed the scrub. Recorded for postmortem so we
/// can see in production whether targeted-scope is doing its job or
/// whether we're frequently escalating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeUsed {
    Targeted,
    RuntimeWide,
    None,
}

impl ScopeUsed {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeUsed::Targeted => "scope_targeted",
            ScopeUsed::RuntimeWide => "scope_runtime_wide",
            ScopeUsed::None => "scope_none",
        }
    }
}

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
    /// Set to the highest scope that actually ran. `None` only when
    /// `needles` was empty (degenerate request).
    pub scope_used: Option<ScopeUsed>,
}

/// Scrub the given paths.
///
/// `anchors.files` records the file size at the moment the release was
/// accepted. We scrub only bytes written *after* that offset — the task
/// window — so older content the user wrote before the agent retrieved a
/// value is left byte-identical. Files not present in `anchors.files`
/// (e.g. the path is a directory we recursed into) are scrubbed in full.
///
/// `anchors.sqlite` is consumed by the SQLite memory scrubber wired in a
/// later commit; this entry point ignores it for now.
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
    anchors: &ScrubAnchors,
) -> Result<ScrubReport> {
    if needles.is_empty() {
        return Err(anyhow!("no needles to scrub"));
    }
    let mut report = ScrubReport::default();

    // Scope 1: targeted byte-offset scrub on the primary transcript paths.
    // This is the cheap, deterministic happy path — most releases settle
    // here and never escalate.
    let offsets = &anchors.files;
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
    report.scope_used = Some(ScopeUsed::Targeted);

    // Verify on TWO surfaces, not just the primary paths:
    //   - the primary paths' in-window suffix (Scope-1 territory),
    //   - the pre-counted siblings (Scope-2 territory; current count
    //     must equal pre count or there's residue we missed).
    // If either surface has residue, escalate to Scope 2.
    let scope_1_primary_ok = verify(paths, needles, offsets)?;
    let scope_1_siblings_ok = verify_with_precounts(needles, &anchors.files_precount)?;
    if scope_1_primary_ok && scope_1_siblings_ok {
        report.verified = true;
        return Ok(report);
    }

    if !anchors.files_precount.is_empty() {
        scrub_runtime_wide(needles, &anchors.files_precount, &mut report)?;
        report.scope_used = Some(ScopeUsed::RuntimeWide);
        report.verified = verify_with_precounts(needles, &anchors.files_precount)?
            && verify(paths, needles, offsets)?;
    } else {
        report.verified = false;
    }

    Ok(report)
}

/// Scrub SQLite anchors (e.g. OpenClaw memory DB) for a release.
///
/// Separate from `scrub_paths` because the failure semantics differ:
/// - File-based scrub failures degrade to "unverified".
/// - SQLite scrub failures (e.g. lock contention) are deferrable — the
///   orchestrator may retry later without re-running file scrub.
///
/// Returns a tuple `(rows_modified, replacements, wal_truncated)` summed
/// across every anchored DB. Errors propagate so the caller can choose
/// whether to retry.
pub fn scrub_sqlite_anchors(
    anchors: &ScrubAnchors,
    needles: &[String],
    lock_retry_ms: u64,
) -> Result<sqlite::ScrubSqliteReport> {
    let mut total = sqlite::ScrubSqliteReport::default();
    if anchors.sqlite.is_empty() || needles.is_empty() {
        return Ok(total);
    }
    for (db_path_str, anchor) in &anchors.sqlite {
        let db_path = PathBuf::from(db_path_str);
        let r = sqlite::scrub_anchor(&db_path, anchor, needles, lock_retry_ms)?;
        total.rows_modified += r.rows_modified;
        total.replacements += r.replacements;
        total.wal_truncated = total.wal_truncated || r.wal_truncated;
    }
    Ok(total)
}

/// Scope 2: runtime-wide. Walk every file we pre-counted at release time
/// and redact `current_count - pre_count` occurrences of each needle.
/// Replaces from the *last* match backwards: in append-only JSONL
/// transcripts that's chronologically the newest content, which is the
/// content the agent just wrote.
fn scrub_runtime_wide(
    needles: &[String],
    precounts: &HashMap<String, HashMap<String, usize>>,
    report: &mut ScrubReport,
) -> Result<()> {
    for (path_str, per_needle_pre) in precounts {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let mut s = text.to_string();
        let mut hit_count = 0usize;
        // `needles` is already sorted longest-first by `build_needles`,
        // so substring-of-substring collisions are handled correctly.
        for n in needles {
            let pre = per_needle_pre.get(n).copied().unwrap_or(0);
            let cur = s.matches(n.as_str()).count();
            if cur <= pre {
                continue;
            }
            // Replace the last `cur - pre` occurrences.
            let to_redact = cur - pre;
            s = redact_last_n(&s, n, to_redact);
            hit_count += to_redact;
        }
        if hit_count > 0 {
            fs::write(path, s.as_bytes())?;
            report.files_modified.push(path.display().to_string());
            report.total_replacements += hit_count;
        }
    }
    Ok(())
}

/// Replace the last `n` occurrences of `needle` in `s` with the redaction
/// marker, leaving earlier occurrences untouched.
fn redact_last_n(s: &str, needle: &str, n: usize) -> String {
    if n == 0 || needle.is_empty() {
        return s.to_string();
    }
    // Collect match start indices, walking forward.
    let mut positions: Vec<usize> = Vec::new();
    let mut start = 0;
    while let Some(pos) = s[start..].find(needle) {
        let abs = start + pos;
        positions.push(abs);
        start = abs + needle.len();
    }
    if positions.len() <= n {
        // Replace all of them (this can happen when a sibling file we
        // pre-counted at zero suddenly has occurrences post-task — they
        // are all task-window content by definition).
        return s.replace(needle, REDACTION_MARKER);
    }
    // Keep the first `positions.len() - n` matches; replace the last `n`.
    let cutoff = positions.len() - n;
    let to_replace_at: std::collections::BTreeSet<usize> =
        positions.iter().skip(cutoff).copied().collect();

    let mut out = String::with_capacity(s.len());
    let mut cursor = 0usize;
    while cursor < s.len() {
        if to_replace_at.contains(&cursor) {
            out.push_str(REDACTION_MARKER);
            cursor += needle.len();
        } else {
            // Find the next match position so we can copy the gap as-is.
            let next = to_replace_at
                .range(cursor..)
                .next()
                .copied()
                .unwrap_or(s.len());
            out.push_str(&s[cursor..next]);
            cursor = next;
        }
    }
    out
}

/// Verify that no Scope-2 file gained occurrences relative to its
/// pre-release count. Independent of the file-offset verifier.
fn verify_with_precounts(
    needles: &[String],
    precounts: &HashMap<String, HashMap<String, usize>>,
) -> Result<bool> {
    for (path_str, per_needle_pre) in precounts {
        let path = Path::new(path_str);
        if !path.exists() {
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for n in needles {
            let pre = per_needle_pre.get(n).copied().unwrap_or(0);
            let cur = text.matches(n.as_str()).count();
            if cur > pre {
                return Ok(false);
            }
        }
    }
    Ok(true)
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

    fn no_anchors() -> ScrubAnchors {
        ScrubAnchors::default()
    }

    fn anchors_files(map: HashMap<String, u64>) -> ScrubAnchors {
        ScrubAnchors {
            files: map,
            files_precount: HashMap::new(),
            sqlite: HashMap::new(),
        }
    }

    #[test]
    fn replaces_plaintext_and_base64() {
        let p = tmpfile(
            "x.jsonl",
            "leak hello@rivault.ai and aGVsbG9Acml2YXVsdC5haQ== then done",
        );
        let needles = build_needles(Some("hello@rivault.ai"), &[]);
        let report =
            scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
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
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("secret%40rivault.ai"));
    }

    #[test]
    fn supplied_variants_only_path() {
        let p = tmpfile("z.jsonl", "ciphertext: AAAA== body BBBB done");
        let needles = build_needles(None, &["AAAA==".into(), "BBBB".into()]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("AAAA=="));
        assert!(!after.contains("BBBB"));
    }

    #[test]
    fn missing_path_is_ok() {
        let needles = build_needles(Some("x"), &[]);
        let r = scrub_paths(&["/tmp/does-not-exist-xyz".into()], &needles, &no_anchors())
            .unwrap();
        assert!(r.verified);
        assert!(r.files_modified.is_empty());
    }

    #[test]
    fn longest_needle_wins() {
        let p = tmpfile("zz.jsonl", "abcdef and abc done");
        let needles = build_needles(None, &["abc".into(), "abcdef".into()]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
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
        let report =
            scrub_paths(&[p.display().to_string()], &needles, &anchors_files(offsets))
                .unwrap();

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
        let r = scrub_paths(&[p.display().to_string()], &needles, &anchors_files(offsets))
            .unwrap();
        assert!(r.verified);
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("secret123"));
    }

    /// Sanity check that anchors carrying a SQLite snapshot don't disturb
    /// file scrubbing. The SQLite scrubber is wired in a later commit; until
    /// then, sqlite anchors must be a passive payload.
    #[test]
    fn sqlite_anchors_dont_perturb_file_scrub() {
        use crate::ledger::SqliteAnchor;
        let p = tmpfile("sql.jsonl", "task line: secret-token here");
        let mut a = ScrubAnchors::default();
        a.sqlite.insert(
            "/Users/u/.openclaw/memory/main.sqlite".to_string(),
            SqliteAnchor {
                max_rowids: HashMap::from([("memories".to_string(), 99i64)]),
                wal_frame: Some(7),
            },
        );
        let needles = build_needles(Some("secret-token"), &[]);
        let r = scrub_paths(&[p.display().to_string()], &needles, &a).unwrap();
        assert!(r.verified);
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("secret-token"));
    }

    // ---- Scope-2 escalation -------------------------------------------

    #[test]
    fn redact_last_n_keeps_earlier_matches() {
        let s = "alpha SECRET beta SECRET gamma SECRET delta";
        let out = redact_last_n(s, "SECRET", 2);
        // The first occurrence remains, the last two are redacted.
        let first_marker = out.find(REDACTION_MARKER).unwrap();
        let first_secret = out.find("SECRET");
        assert!(first_secret.is_some(), "earliest SECRET must remain");
        assert!(
            first_secret.unwrap() < first_marker,
            "earliest match should precede the first redaction"
        );
        assert_eq!(out.matches(REDACTION_MARKER).count(), 2);
        assert_eq!(out.matches("SECRET").count(), 1);
    }

    #[test]
    fn redact_last_n_replaces_all_when_n_exceeds() {
        let s = "x SECRET y";
        let out = redact_last_n(s, "SECRET", 5);
        assert_eq!(out, format!("x {REDACTION_MARKER} y"));
    }

    #[test]
    fn scope2_escalates_when_scope1_misses_sibling() {
        // The agent retrieved a value that ended up in a sibling .jsonl
        // file (e.g. a sub-process's transcript) NOT covered by the
        // primary path's offset snapshot. Scope-1 verify finds it and
        // we escalate to Scope-2, which redacts only the new occurrence
        // while leaving the pre-existing copy alone.
        let primary =
            tmpfile("primary.jsonl", "primary line — clean\n");
        // Sibling lives in the same dir.
        let sibling = primary.parent().unwrap().join("sibling.jsonl");
        fs::write(
            &sibling,
            "OLD: target-value was here intentionally\nNEW: target-value\n",
        )
        .unwrap();

        let needles = build_needles(Some("target-value"), &[]);
        let mut anchors = ScrubAnchors::default();
        // Pretend at release time: primary file was 0 bytes, sibling
        // had ONE pre-existing occurrence (the OLD line).
        anchors.files.insert(primary.display().to_string(), 0);
        let mut sibling_pre = HashMap::new();
        sibling_pre.insert("target-value".to_string(), 1usize);
        anchors
            .files_precount
            .insert(sibling.display().to_string(), sibling_pre);

        let report = scrub_paths(&[primary.display().to_string()], &needles, &anchors).unwrap();

        let after = fs::read_to_string(&sibling).unwrap();
        assert!(
            after.contains("OLD: target-value was here intentionally"),
            "pre-release line must stay byte-identical: {after}"
        );
        assert!(
            after.contains(&format!("NEW: {REDACTION_MARKER}")),
            "post-release line must be redacted: {after}"
        );
        assert_eq!(report.scope_used, Some(ScopeUsed::RuntimeWide));
        assert!(report.verified);
    }

    #[test]
    fn scope2_files_with_zero_pre_count_get_full_redaction() {
        // A sibling file that had ZERO occurrences pre-release but now
        // has occurrences — every one of them is task-window content.
        let primary = tmpfile("primary.jsonl", "primary clean\n");
        let sibling = primary.parent().unwrap().join("clean-sibling.jsonl");
        fs::write(
            &sibling,
            "first line\nsecret-x in here\nlast line\nsecret-x again\n",
        )
        .unwrap();

        let needles = build_needles(Some("secret-x"), &[]);
        let mut anchors = ScrubAnchors::default();
        anchors.files.insert(primary.display().to_string(), 0);
        // Sibling at release time had no occurrences; pre-count is empty
        // map, so for any needle the "pre" defaults to 0.
        anchors
            .files_precount
            .insert(sibling.display().to_string(), HashMap::new());

        let report = scrub_paths(&[primary.display().to_string()], &needles, &anchors).unwrap();
        let after = fs::read_to_string(&sibling).unwrap();
        assert!(!after.contains("secret-x"));
        assert_eq!(after.matches(REDACTION_MARKER).count(), 2);
        assert_eq!(report.scope_used, Some(ScopeUsed::RuntimeWide));
        assert!(report.verified);
    }

    #[test]
    fn scope1_alone_when_no_residue() {
        // Standard happy path: Scope-1 scrub completes the work; Scope-2
        // is skipped, scope_used stays Targeted.
        let p = tmpfile("h.jsonl", "task: secret-y here");
        let needles = build_needles(Some("secret-y"), &[]);
        let mut anchors = ScrubAnchors::default();
        anchors.files.insert(p.display().to_string(), 0);
        let report = scrub_paths(&[p.display().to_string()], &needles, &anchors).unwrap();
        assert_eq!(report.scope_used, Some(ScopeUsed::Targeted));
        assert!(report.verified);
    }
}
