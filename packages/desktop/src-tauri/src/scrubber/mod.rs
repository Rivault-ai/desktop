//! Scrub engine.
//!
//! V0 covers exact-string match against plaintext + caller-supplied encoded
//! variants. Hash-content scan for true-E2E L2 (where plaintext is absent
//! from the release event) is a v1 follow-up; the entry point accepts the
//! hash but does not yet scan for it.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::collections::BTreeSet;
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

pub fn scrub_paths(paths: &[String], needles: &[String]) -> Result<ScrubReport> {
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
            scrub_dir(path, needles, &mut report)?;
        } else {
            scrub_one(path, needles, &mut report)?;
        }
    }
    report.verified = verify(paths, needles)?;
    Ok(report)
}

fn scrub_dir(dir: &Path, needles: &[String], report: &mut ScrubReport) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            scrub_dir(&p, needles, report)?;
        } else {
            scrub_one(&p, needles, report)?;
        }
    }
    Ok(())
}

fn scrub_one(path: &Path, needles: &[String], report: &mut ScrubReport) -> Result<()> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => return Ok(()), // best effort; skip unreadable
    };
    let Ok(mut s) = String::from_utf8(bytes) else {
        return Ok(()); // skip binary
    };
    let mut hits = 0;
    for n in needles {
        let count = s.matches(n.as_str()).count();
        if count > 0 {
            s = s.replace(n.as_str(), REDACTION_MARKER);
            hits += count;
        }
    }
    if hits > 0 {
        fs::write(path, s)?;
        report.files_modified.push(path.display().to_string());
        report.total_replacements += hits;
    }
    Ok(())
}

fn verify(paths: &[String], needles: &[String]) -> Result<bool> {
    for p in paths {
        let path = Path::new(p);
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            if !verify_dir(path, needles)? {
                return Ok(false);
            }
        } else if !verify_one(path, needles)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_dir(dir: &Path, needles: &[String]) -> Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            if !verify_dir(&p, needles)? {
                return Ok(false);
            }
        } else if !verify_one(&p, needles)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_one(path: &Path, needles: &[String]) -> Result<bool> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(true);
    };
    let Ok(s) = std::str::from_utf8(&bytes) else {
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

    #[test]
    fn replaces_plaintext_and_base64() {
        let p = tmpfile(
            "x.jsonl",
            "leak hello@rivault.ai and aGVsbG9Acml2YXVsdC5haQ== then done",
        );
        let needles = build_needles(Some("hello@rivault.ai"), &[]);
        let report = scrub_paths(&[p.display().to_string()], &needles).unwrap();
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
        let _ = scrub_paths(&[p.display().to_string()], &needles).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("secret%40rivault.ai"));
    }

    #[test]
    fn supplied_variants_only_path() {
        let p = tmpfile("z.jsonl", "ciphertext: AAAA== body BBBB done");
        // Simulating true-E2E: no plaintext, just precomputed variants.
        let needles = build_needles(None, &["AAAA==".into(), "BBBB".into()]);
        let _ = scrub_paths(&[p.display().to_string()], &needles).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("AAAA=="));
        assert!(!after.contains("BBBB"));
    }

    #[test]
    fn missing_path_is_ok() {
        let needles = build_needles(Some("x"), &[]);
        let r = scrub_paths(&["/tmp/does-not-exist-xyz".into()], &needles).unwrap();
        assert!(r.verified);
        assert!(r.files_modified.is_empty());
    }

    #[test]
    fn longest_needle_wins() {
        let p = tmpfile("zz.jsonl", "abcdef and abc done");
        let needles = build_needles(None, &["abc".into(), "abcdef".into()]);
        let _ = scrub_paths(&[p.display().to_string()], &needles).unwrap();
        let after = fs::read_to_string(&p).unwrap();
        assert!(!after.contains("abcdef"));
        assert!(!after.contains("abc"));
    }
}
