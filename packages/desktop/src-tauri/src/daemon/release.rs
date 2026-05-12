//! Canonical release-event payload + allowlist validation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    L1,
    L2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentRuntime {
    ClaudeCode,
    Openclaw,
    ClaudeDesktop,
    Codex,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpMode {
    EnvelopeVerbatim,
    ServerDecrypt,
}

/// Local-IPC wire format. `deny_unknown_fields` is load-bearing: the
/// daemon writes ReleaseEvent and the daemon reads it back across the
/// HMAC-authenticated `/release` boundary, so any extra field is either
/// a bug or an attacker probing the surface. We want it loud, not silent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvent {
    pub release_id: String,
    pub session_id: String,
    pub tier: Tier,
    pub agent_runtime: AgentRuntime,
    pub mcp_mode: Option<McpMode>,
    pub value_plaintext: Option<String>,
    pub value_hash: String,
    pub encoded_variants: Vec<String>,
    pub transcript_paths: Vec<String>,
    pub released_at: String,
    pub rotation_supported: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_json() -> &'static str {
        r#"{
            "release_id": "r-1",
            "session_id": "s-1",
            "tier": "l1",
            "agent_runtime": "openclaw",
            "mcp_mode": null,
            "value_plaintext": "hello",
            "value_hash": "h",
            "encoded_variants": [],
            "transcript_paths": [],
            "released_at": "2025-01-01T00:00:00Z",
            "rotation_supported": false
        }"#
    }

    #[test]
    fn release_event_round_trips_valid_json() {
        let parsed: ReleaseEvent = serde_json::from_str(valid_json()).unwrap();
        assert_eq!(parsed.release_id, "r-1");
    }

    #[test]
    fn release_event_rejects_unknown_field() {
        let with_extra = valid_json().replace(
            "\"rotation_supported\": false",
            "\"rotation_supported\": false, \"injected\": \"x\"",
        );
        let err = serde_json::from_str::<ReleaseEvent>(&with_extra).unwrap_err();
        assert!(
            err.to_string().contains("injected"),
            "expected unknown-field error, got: {err}"
        );
    }
}
