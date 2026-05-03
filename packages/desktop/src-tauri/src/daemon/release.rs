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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
