//! Per-runtime nonce authentication for the local MCP endpoint.
//!
//! Each agent runtime (Claude Code, Codex, Claude Desktop, OpenClaw) is
//! registered with a distinct nonce in its MCP URL. At tool-call time the
//! daemon looks the nonce up to (a) authenticate the caller as a runtime
//! we installed ourselves and (b) tag the ledger row + pick the right
//! allowlist root.
//!
//! Without nonces, any same-UID local process could hit
//! `http://127.0.0.1:<port>/mcp?runtime=claude_code` and either masquerade
//! as a real runtime (writing scrubs to the wrong transcript directory)
//! or pick `runtime=custom` (which has an empty allowlist, silently
//! skipping the scrub).
//!
//! Nonces are derived deterministically from the per-install IPC secret
//! (see `keychain::load_or_create_secret`) via HMAC-SHA256. Properties:
//!
//! - **Stable across restarts.** The secret is persisted, so the daemon
//!   computes the same nonce table on every boot — `auto_install` stays
//!   idempotent and the agent's config doesn't need rewriting unless the
//!   user reinstalls.
//! - **Unguessable.** Only code with read access to the IPC secret file
//!   (mode 0600 under `~/Library/Application Support/Rivault/`) can derive
//!   a valid nonce; that's the same boundary as the existing HMAC the
//!   daemon uses for `/release` and `/stop`.
//! - **Per-install distinct.** Two machines with different IPC secrets
//!   produce different nonces, so leaking one install's URL doesn't help
//!   on another.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::daemon::release::AgentRuntime;

type HmacSha256 = Hmac<Sha256>;

/// Versioned domain-separation tag. Bump the suffix if we ever need to
/// rotate the derivation without changing the on-disk secret.
const NONCE_INFO: &[u8] = b"rivault-mcp-runtime-v1";

/// Canonical runtime labels. The MCP URL embedded in each runtime's
/// config carries the nonce derived from one of these labels; the label
/// itself never appears in the URL — looking up the nonce in the map
/// yields the matching `AgentRuntime`.
const RUNTIMES: &[(&str, AgentRuntime)] = &[
    ("claude_code", AgentRuntime::ClaudeCode),
    ("claude_desktop", AgentRuntime::ClaudeDesktop),
    ("codex", AgentRuntime::Codex),
    ("openclaw", AgentRuntime::Openclaw),
];

/// Lookup table from runtime label → nonce and from nonce → runtime,
/// derived once at daemon startup.
#[derive(Debug, Clone)]
pub struct RuntimeNonceMap {
    by_runtime: HashMap<&'static str, String>,
}

impl RuntimeNonceMap {
    /// Build the table from the per-install IPC secret.
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut by_runtime = HashMap::with_capacity(RUNTIMES.len());
        for (name, _) in RUNTIMES {
            by_runtime.insert(*name, derive_nonce(secret, name));
        }
        Self { by_runtime }
    }

    /// Nonce to embed in the MCP URL for `runtime`. Returns None for
    /// runtimes outside the canonical set (e.g. `AgentRuntime::Custom`),
    /// which by design we do not install a managed MCP entry for.
    pub fn nonce_for(&self, runtime: &str) -> Option<&str> {
        self.by_runtime.get(runtime).map(String::as_str)
    }

    /// Constant-time reverse lookup. Returns the runtime whose stored
    /// nonce matches `candidate`, or None if no stored nonce matches.
    ///
    /// The loop walks every entry on every call so iteration timing
    /// does not leak which runtime a guess collided with; per-byte
    /// comparison via `subtle::ct_eq` avoids the early-exit timing leak.
    pub fn runtime_for(&self, candidate: &str) -> Option<AgentRuntime> {
        let candidate_bytes = candidate.as_bytes();
        let mut hit: Option<AgentRuntime> = None;
        for (name, runtime) in RUNTIMES {
            let stored = self
                .by_runtime
                .get(name)
                .expect("nonce map populated for every canonical runtime");
            if bool::from(stored.as_bytes().ct_eq(candidate_bytes)) {
                hit = Some(runtime.clone());
            }
        }
        hit
    }
}

/// HMAC-SHA256(secret, NONCE_INFO || 0x00 || runtime_label), truncated
/// to 16 bytes (128 bits) and hex-encoded — 32 ASCII chars.
fn derive_nonce(secret: &[u8], runtime: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(NONCE_INFO);
    mac.update(&[0u8]);
    mac.update(runtime.as_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    #[test]
    fn derive_is_deterministic_per_secret() {
        let m1 = RuntimeNonceMap::from_secret(&secret(7));
        let m2 = RuntimeNonceMap::from_secret(&secret(7));
        assert_eq!(m1.nonce_for("claude_code"), m2.nonce_for("claude_code"));
        assert_eq!(m1.nonce_for("codex"), m2.nonce_for("codex"));
    }

    #[test]
    fn different_secrets_yield_different_nonces() {
        let a = RuntimeNonceMap::from_secret(&secret(1));
        let b = RuntimeNonceMap::from_secret(&secret(2));
        assert_ne!(a.nonce_for("claude_code"), b.nonce_for("claude_code"));
    }

    #[test]
    fn nonces_differ_across_runtimes() {
        let m = RuntimeNonceMap::from_secret(&secret(9));
        let cc = m.nonce_for("claude_code").unwrap();
        let cd = m.nonce_for("claude_desktop").unwrap();
        let cx = m.nonce_for("codex").unwrap();
        let oc = m.nonce_for("openclaw").unwrap();
        assert_ne!(cc, cd);
        assert_ne!(cc, cx);
        assert_ne!(cc, oc);
        assert_ne!(cd, cx);
        assert_ne!(cd, oc);
        assert_ne!(cx, oc);
    }

    #[test]
    fn reverse_lookup_returns_correct_runtime() {
        let m = RuntimeNonceMap::from_secret(&secret(3));
        let n = m.nonce_for("codex").unwrap().to_string();
        match m.runtime_for(&n) {
            Some(AgentRuntime::Codex) => {}
            other => panic!("expected Codex, got {other:?}"),
        }
    }

    #[test]
    fn reverse_lookup_rejects_unknown_nonce() {
        let m = RuntimeNonceMap::from_secret(&secret(4));
        assert!(m.runtime_for("not-a-real-nonce").is_none());
        // Empty string: a likely "missing param defaulted to ''" mistake.
        assert!(m.runtime_for("").is_none());
        // Correct length but wrong bytes (32 hex chars):
        assert!(m
            .runtime_for("00000000000000000000000000000000")
            .is_none());
    }

    #[test]
    fn nonce_is_thirty_two_hex_chars() {
        let m = RuntimeNonceMap::from_secret(&secret(5));
        for (name, _) in RUNTIMES {
            let n = m.nonce_for(name).unwrap();
            assert_eq!(n.len(), 32, "{name}");
            assert!(n.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
        }
    }

    #[test]
    fn runtime_for_unknown_label_returns_none_via_nonce_for() {
        let m = RuntimeNonceMap::from_secret(&secret(6));
        assert!(m.nonce_for("custom").is_none());
        assert!(m.nonce_for("emacs").is_none());
    }
}
