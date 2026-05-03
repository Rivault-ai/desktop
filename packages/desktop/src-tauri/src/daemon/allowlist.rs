//! Per-platform allowlist roots. Every transcript path on an inbound release
//! event must canonicalize to a descendant of one of these roots, otherwise
//! the event is rejected at ingest — defense in depth against a compromised
//! emitter trying to weaponize the daemon to scrub arbitrary user files.
//!
//! Allowlist is configurable but additive only via explicit user action.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use super::release::AgentRuntime;

fn home() -> Result<PathBuf> {
    dirs::home_dir().context("no home dir")
}

pub fn default_roots(runtime: &AgentRuntime) -> Result<Vec<PathBuf>> {
    let home = home()?;
    Ok(match runtime {
        AgentRuntime::Openclaw => vec![home.join(".openclaw").join("agents")],
        AgentRuntime::ClaudeCode => vec![home.join(".claude").join("projects")],
        AgentRuntime::ClaudeDesktop => vec![home
            .join("Library")
            .join("Application Support")
            .join("Claude")],
        AgentRuntime::Codex => vec![home.join(".codex")],
        AgentRuntime::Custom => vec![],
    })
}

/// Resolve a path even if it does not yet exist by canonicalizing the longest
/// existing prefix and reattaching the remainder.
fn resolve(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(c) = cur.canonicalize() {
            let mut out = c;
            for seg in tail.iter().rev() {
                out.push(seg);
            }
            return out;
        }
        let name = cur.file_name().map(|n| n.to_os_string());
        let parent = cur.parent().map(|p| p.to_path_buf());
        match (parent, name) {
            (Some(parent), Some(name)) => {
                tail.push(name);
                cur = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

pub fn validate_path(runtime: &AgentRuntime, path: &str) -> Result<PathBuf> {
    let candidate = resolve(Path::new(path));
    let roots = default_roots(runtime)?;
    if roots.is_empty() {
        return Err(anyhow!(
            "custom runtime has no default allowlist; explicit user opt-in required"
        ));
    }
    for root in &roots {
        let resolved_root = resolve(root);
        if candidate.starts_with(&resolved_root) {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "path {} outside allowlist for runtime {:?}",
        candidate.display(),
        runtime
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_outside_allowlist() {
        let r = validate_path(&AgentRuntime::ClaudeCode, "/etc/passwd");
        assert!(r.is_err());
    }

    #[test]
    fn rejects_documents_path() {
        let home = home().unwrap();
        let p = home.join("Documents").join("contacts.txt");
        let r = validate_path(&AgentRuntime::ClaudeCode, p.to_str().unwrap());
        assert!(r.is_err(), "Documents must not be in any allowlist");
    }

    #[test]
    fn accepts_inside_allowlist() {
        let home = home().unwrap();
        let p = home
            .join(".claude")
            .join("projects")
            .join("session.jsonl");
        let r = validate_path(&AgentRuntime::ClaudeCode, p.to_str().unwrap());
        assert!(r.is_ok());
    }
}
