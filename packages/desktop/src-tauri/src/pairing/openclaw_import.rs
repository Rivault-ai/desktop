//! Read an existing Rivault API key out of the user's OpenClaw config so
//! a returning OpenClaw user doesn't have to paste their key into the
//! desktop Setup screen.
//!
//! Source path: `~/.openclaw/openclaw.json`
//! Field path:  `plugins.entries.rivault.config.apiKey`
//!
//! Best-effort: any missing field, malformed JSON, or unreadable file
//! returns `None` rather than an error — the caller falls through to
//! the regular Setup flow.

use std::fs;
use std::path::PathBuf;

fn openclaw_config_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".openclaw").join("openclaw.json"))
}

/// Returns the Rivault API key configured in OpenClaw, if one exists.
pub fn detect_api_key() -> Option<String> {
    let path = openclaw_config_path()?;
    let raw = fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let key = json
        .get("plugins")?
        .get("entries")?
        .get("rivault")?
        .get("config")?
        .get("apiKey")?
        .as_str()?;
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}
