//! Scrub engine.
//!
//! V0 covers exact-string match against plaintext + caller-supplied encoded
//! variants. Hash-content scan for true-E2E L2 (where plaintext is absent
//! from the release event) is a v1 follow-up; the entry point accepts the
//! hash but does not yet scan for it.

pub mod sqlite;

use anyhow::{anyhow, Result};
use base64::{
    engine::general_purpose::{
        STANDARD as B64, STANDARD_NO_PAD as B64_NO_PAD, URL_SAFE as B64_URL,
        URL_SAFE_NO_PAD as B64_URL_NO_PAD,
    },
    Engine,
};
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
/// - base64 standard, URL-safe, and both unpadded variants (JWTs, OAuth
///   tokens, and ad-hoc encoding all show up in agent transcripts)
/// - URL-encoded
/// - JSON-escaped (string body, no surrounding quotes)
/// - hex (lower + upper), JSON unicode-escape (`\uXXXX` per char) —
///   skipped for very short plaintexts to avoid false-positive
///   collisions with unrelated bytes
/// - any caller-supplied precomputed variants (e.g. mobile-precomputed
///   for E2E paths)
pub fn build_needles(plaintext: Option<&str>, supplied_variants: &[String]) -> Vec<String> {
    /// Minimum plaintext byte-length before adding short-collision-prone
    /// encodings (hex, unicode-escape). Hex of "a" is "61" which would
    /// match every random byte in every file; for plaintexts shorter
    /// than this we skip those variants. Real-world secrets are 8+ bytes
    /// so this only excludes pathological/degenerate cases.
    const COLLISION_SAFE_MIN_LEN: usize = 4;

    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Some(v) = plaintext {
        if !v.is_empty() {
            let bytes = v.as_bytes();
            set.insert(v.to_string());
            // Four base64 variants — agents producing JWTs, OAuth
            // bearer tokens, signed URLs, or plain attachments hit
            // different ones depending on the library.
            set.insert(B64.encode(bytes));
            set.insert(B64_NO_PAD.encode(bytes));
            set.insert(B64_URL.encode(bytes));
            set.insert(B64_URL_NO_PAD.encode(bytes));
            set.insert(urlencoding::encode(v).into_owned());
            set.insert(json_escape(v));
            if v.len() >= COLLISION_SAFE_MIN_LEN {
                set.insert(hex_encode(bytes, false));
                set.insert(hex_encode(bytes, true));
                set.insert(unicode_escape(v));
            }
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

fn hex_encode(bytes: &[u8], uppercase: bool) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        if uppercase {
            s.push_str(&format!("{:02X}", b));
        } else {
            s.push_str(&format!("{:02x}", b));
        }
    }
    s
}

/// Emit `\uXXXX` for every char. Matches what some JSON serializers do
/// when they unicode-escape every code point (e.g. `JSON.stringify` in
/// some browsers, or Python's `json.dumps(..., ensure_ascii=True)` on
/// non-ASCII values). Non-BMP chars (> U+FFFF) are encoded as Rust
/// surrogate-pair equivalents per JSON spec: `\uHHHH\uLLLL`.
fn unicode_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 6);
    for c in s.chars() {
        let code = c as u32;
        if code <= 0xFFFF {
            out.push_str(&format!("\\u{:04x}", code));
        } else {
            // Surrogate pair encoding for chars outside the BMP.
            let v = code - 0x10000;
            let high = 0xD800 + (v >> 10);
            let low = 0xDC00 + (v & 0x3FF);
            out.push_str(&format!("\\u{:04x}\\u{:04x}", high, low));
        }
    }
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

/// Scrub the given paths, retrying until verified or the hard-cap
/// deadline elapses.
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
/// Retry-until-clean: each pass runs Scope 1 (offset-anchored on the
/// primary transcript) + Scope 2 (precount-aware whole-file rewrite on
/// every file in `files_precount`, which now includes the primary), then
/// verifies. If verify is still dirty we sleep with exponential backoff
/// and try again, up to `HARD_CAP_SECONDS` (15 min) total. The reason
/// for retry: when the agent is still actively writing the plaintext to
/// the transcript at the moment of the first scrub, residue can re-appear
/// between rewrite and verify — looping handles this race. After the
/// deadline the release is marked unverified so the operator can see the
/// scrub didn't fully settle.
///
/// Three integrity checks during each pass:
/// 1. File still UTF-8 (skip if binary now)
/// 2. Current size >= stored offset (otherwise the file was truncated/
///    rotated underneath us — fall back to full-file scrub on the new file
///    since we have no idea where the task-window suffix begins)
/// 3. Verify pass after rewrite confirms no needle remains in the
///    suffix and no sibling file has more occurrences than its precount.
pub fn scrub_paths(
    paths: &[String],
    needles: &[String],
    anchors: &ScrubAnchors,
) -> Result<ScrubReport> {
    scrub_paths_until(
        paths,
        needles,
        anchors,
        std::time::Duration::from_secs(15 * 60), // mirror HARD_CAP_SECONDS
    )
}

/// Same as [`scrub_paths`] but with a caller-supplied deadline. Exposed
/// for tests so the deadline-exhaustion path can be exercised quickly.
pub fn scrub_paths_until(
    paths: &[String],
    needles: &[String],
    anchors: &ScrubAnchors,
    budget: std::time::Duration,
) -> Result<ScrubReport> {
    if needles.is_empty() {
        return Err(anyhow!("no needles to scrub"));
    }
    let deadline = std::time::Instant::now() + budget;
    let offsets = &anchors.files;
    let mut report = ScrubReport::default();
    let mut attempt: u32 = 0;
    let mut backoff = std::time::Duration::from_millis(100);
    let backoff_cap = std::time::Duration::from_secs(5);

    // Working copy of precounts. We extend it on every pass with any
    // `.jsonl` siblings that have appeared since the release snapshot
    // (e.g. the agent rotated its transcript mid-task, or a sub-process
    // spawned a new session file). New files default to pre-count = 0
    // for every needle, so every occurrence in them is task-window
    // content by definition — they get fully scrubbed by Scope 2 and
    // checked by the precount verifier.
    let mut working_precount: HashMap<String, HashMap<String, usize>> =
        anchors.files_precount.clone();

    // Parent dirs to re-walk on every retry. Seed from the primary
    // transcript paths (their parents) and from any pre-existing
    // precount entries (their parents). One level only — same as
    // `precount_runtime_siblings` in the orchestrator.
    let parent_dirs: BTreeSet<PathBuf> = {
        let mut s: BTreeSet<PathBuf> = BTreeSet::new();
        for p in paths {
            let path = Path::new(p);
            if path.is_dir() {
                s.insert(path.to_path_buf());
            } else if let Some(parent) = path.parent() {
                s.insert(parent.to_path_buf());
            }
        }
        for k in anchors.files_precount.keys() {
            if let Some(parent) = Path::new(k).parent() {
                s.insert(parent.to_path_buf());
            }
        }
        s
    };

    // Primary transcript paths are protected by Scope 1's offset
    // anchor and (in production) by the orchestrator's own precount
    // entry. We must NOT auto-add them to the precount with pre=0,
    // because that would let Scope 2 wipe pre-release content the
    // offset is supposed to preserve.
    let primaries: BTreeSet<String> = paths.iter().cloned().collect();

    loop {
        attempt += 1;

        // Pull in any `.jsonl` siblings that have appeared since the
        // last pass. Existing entries are left alone so we never
        // overwrite their pre-counts.
        discover_new_jsonl_siblings(&parent_dirs, &primaries, &mut working_precount);

        // Each pass: Scope 1 on the primary paths (targeted, offset-
        // anchored) then Scope 2 on every precounted file (which now
        // includes the primary via `precount_runtime_siblings` plus
        // any files discovered mid-task).
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
        if !working_precount.is_empty() {
            scrub_runtime_wide(needles, &working_precount, &mut report)?;
            report.scope_used = Some(ScopeUsed::RuntimeWide);
        } else if report.scope_used.is_none() {
            report.scope_used = Some(ScopeUsed::Targeted);
        }

        // Verify both surfaces.
        let primary_ok = verify(paths, needles, offsets)?;
        let siblings_ok = verify_with_precounts(needles, &working_precount)?;
        if primary_ok && siblings_ok {
            report.verified = true;
            tracing::debug!(
                attempt,
                "scrub verified clean",
            );
            return Ok(report);
        }

        if std::time::Instant::now() >= deadline {
            // Deadline hit. Surface the unverified state; the orchestrator
            // will mark the ledger row so the user sees it.
            report.verified = false;
            tracing::warn!(
                attempt,
                "scrub hit hard-cap deadline with residue still present"
            );
            return Ok(report);
        }

        // Brief pause before retry so a still-writing agent has a chance
        // to flush before we redact again. Exponential backoff caps at
        // 5s so the loop converges quickly when the writer is idle.
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(backoff_cap);
    }
}

/// Cross-runtime, anchor-free scrub used by the continuous scanner.
///
/// Different invariant from `scrub_paths`: there is no notion of "task
/// window" or "pre-existing content I must preserve". The caller hands us
/// a TTL-bounded set of plaintext values that the daemon believes are
/// currently sensitive, and we redact **every** occurrence of those
/// values (or their encoded variants) in the file. Pre-task / pre-release
/// occurrences are intentionally redacted too — that is the whole point
/// of the cross-session feature.
///
/// `needles` must already be built via `build_needles` (sorted longest-
/// first to avoid substring shadowing).
///
/// Returns the number of redactions performed; 0 means the file was
/// clean or unreadable.
pub fn scrub_for_index(path: &Path, needles: &[String]) -> Result<usize> {
    if needles.is_empty() {
        return Ok(0);
    }
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return Ok(0), // file disappeared mid-event; best-effort
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(0); // skip binary content
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
    if hits > 0 {
        fs::write(path, s.as_bytes())?;
    }
    Ok(hits)
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

/// Walk `parent_dirs` (one level, no recursion) and add any `.jsonl`
/// file not already in `working_precount` with an empty per-needle map.
///
/// Empty map means "we never counted this file at release time" — the
/// Scope-2 scrubber treats `pre = 0` for every needle, so any
/// occurrence we find is task-window content and gets redacted in full.
/// Existing entries are left alone so their pre-counts (which protect
/// pre-release content from being touched) are preserved across retries.
fn discover_new_jsonl_siblings(
    parent_dirs: &BTreeSet<PathBuf>,
    primaries: &BTreeSet<String>,
    working_precount: &mut HashMap<String, HashMap<String, usize>>,
) {
    for parent in parent_dirs {
        let Ok(read) = fs::read_dir(parent) else {
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
            let key = p.display().to_string();
            // Primaries are handled by Scope 1's offset anchor and by
            // the orchestrator's own precount entry — never auto-add
            // them with pre=0.
            if primaries.contains(&key) {
                continue;
            }
            working_precount.entry(key).or_default();
        }
    }
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
    fn retries_then_succeeds_when_writer_is_idle() {
        // Smoke test: deadline-budgeted scrub_paths_until returns the
        // same verified=true outcome on a normal one-pass-clean case.
        // The retry loop's value shows up on concurrent-writer cases
        // which are hard to deterministically simulate in a unit test —
        // those are covered manually in integration.
        let p = tmpfile("retry_clean.jsonl", "before secret@x.com after");
        let needles = build_needles(Some("secret@x.com"), &[]);
        let r = scrub_paths_until(
            &[p.display().to_string()],
            &needles,
            &no_anchors(),
            std::time::Duration::from_secs(2),
        )
        .unwrap();
        assert!(r.verified, "single-pass-clean must return verified");
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("secret@x.com"));
        assert!(after.contains(REDACTION_MARKER));
    }

    #[test]
    fn deadline_zero_returns_after_one_pass() {
        // Deadline already-elapsed-at-call: one pass runs (Scope-1 +
        // optional Scope-2), then the loop checks the deadline,
        // returns. Verifies the loop doesn't infinite-spin and the
        // first pass is always run regardless of budget.
        let p = tmpfile("zerod.jsonl", "alpha secret@x.com omega");
        let needles = build_needles(Some("secret@x.com"), &[]);
        let started = std::time::Instant::now();
        let r = scrub_paths_until(
            &[p.display().to_string()],
            &needles,
            &no_anchors(),
            std::time::Duration::from_millis(0),
        )
        .unwrap();
        let elapsed = started.elapsed();
        assert!(r.verified, "single pass on idle file should verify clean");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "should not block on a 0ms deadline"
        );
        let after = fs::read_to_string(&p).unwrap();
        assert!(after.contains(REDACTION_MARKER));
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
    fn handles_url_safe_base64() {
        // JWT-style payload: URL-safe base64 of the secret embedded in
        // a `eyJhbGciOi...` style blob would use URL_SAFE.
        let secret = "Hello+World/Foo=";
        // URL-safe b64 of this value substitutes + → -, / → _, = → padding.
        let url_safe = "SGVsbG8rV29ybGQvRm9vPQ=="
            .replace('+', "-")
            .replace('/', "_");
        let body = format!("token={} end", url_safe);
        let p = tmpfile("urlsafe.jsonl", &body);
        let needles = build_needles(Some(secret), &[]);
        let report =
            scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
        assert!(report.verified);
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains(&url_safe), "url-safe b64 must be redacted: {after}");
    }

    #[test]
    fn handles_base64_unpadded() {
        // JWT segments are typically unpadded URL-safe base64.
        let secret = "open-sesame-please";
        let url_safe_no_pad = B64_URL_NO_PAD.encode(secret.as_bytes());
        let p = tmpfile(
            "jwt.jsonl",
            &format!("\"jwt\": \"header.{}.sig\"", url_safe_no_pad),
        );
        let needles = build_needles(Some(secret), &[]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(
            !after.contains(&url_safe_no_pad),
            "unpadded URL-safe b64 must be redacted: {after}"
        );
    }

    #[test]
    fn handles_hex_encoding() {
        // Some debug paths (curl --data-binary, hexdumps, low-level
        // libs) emit hex. Both cases covered.
        let secret = "alpha-bravo-charlie";
        let hex_lo = hex_encode(secret.as_bytes(), false);
        let hex_up = hex_encode(secret.as_bytes(), true);
        let p = tmpfile(
            "hex.jsonl",
            &format!("dump lo {} dump up {} end", hex_lo, hex_up),
        );
        let needles = build_needles(Some(secret), &[]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains(&hex_lo), "lowercase hex must be redacted: {after}");
        assert!(!after.contains(&hex_up), "uppercase hex must be redacted: {after}");
    }

    #[test]
    fn handles_unicode_escape() {
        // `JSON.stringify` in some pipelines (or Python's
        // `ensure_ascii=True`) emits every char as `\uXXXX`.
        let secret = "tokenABC";
        let escaped = unicode_escape(secret);
        // Sanity-check the helper.
        assert_eq!(
            escaped,
            "\\u0074\\u006f\\u006b\\u0065\\u006e\\u0041\\u0042\\u0043"
        );
        let p = tmpfile("unicode.jsonl", &format!("payload: \"{}\" end", escaped));
        let needles = build_needles(Some(secret), &[]);
        let _ = scrub_paths(&[p.display().to_string()], &needles, &no_anchors()).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(
            !after.contains(&escaped),
            "unicode-escaped form must be redacted: {after}"
        );
    }

    #[test]
    fn short_plaintext_skips_collision_prone_encodings() {
        // For pathologically-short plaintexts ("a" → hex "61"), hex and
        // unicode-escape forms are skipped to avoid wiping unrelated
        // file content. The literal value is still in the needle list.
        let needles = build_needles(Some("a"), &[]);
        // hex("a") = "61" — must NOT appear.
        assert!(!needles.iter().any(|n| n == "61"));
        // unicode_escape("a") = "\\u0061" — must NOT appear.
        assert!(!needles.iter().any(|n| n == "\\u0061"));
        // The raw byte is still tracked.
        assert!(needles.iter().any(|n| n == "a"));
    }

    #[test]
    fn discovers_new_sibling_jsonl_created_after_release() {
        // Simulates the failure mode where the agent rotated its
        // transcript (or a sub-process opened a new session file) AFTER
        // the release snapshot. The new file is not in
        // `anchors.files_precount`, so without re-enumeration it would
        // be a silent miss. With re-enumeration, the retry pass
        // discovers it, scrubs it, and verify passes.
        let primary = tmpfile("primary.jsonl", "primary line clean\n");
        let new_sibling = primary.parent().unwrap().join("rotated.jsonl");
        // Sibling exists with the secret BUT was not present at release
        // time, so anchors knows nothing about it.
        fs::write(&new_sibling, "agent wrote: rotated-secret here\n").unwrap();

        let needles = build_needles(Some("rotated-secret"), &[]);
        let mut anchors = ScrubAnchors::default();
        anchors.files.insert(primary.display().to_string(), 0);
        // Note: `rotated.jsonl` deliberately NOT in files_precount.

        let report = scrub_paths(
            &[primary.display().to_string()],
            &needles,
            &anchors,
        )
        .unwrap();

        let after = fs::read_to_string(&new_sibling).unwrap();
        assert!(
            !after.contains("rotated-secret"),
            "newly-appearing sibling must be scrubbed: {after}"
        );
        assert!(after.contains(REDACTION_MARKER));
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
