//! Per-runtime MCP installation: write the right config entry for each
//! agent so it points at the daemon's local `/mcp` instead of the cloud
//! Rivault MCP.
//!
//! Today, MCP entry conventions are different per agent:
//!   - **Claude Code**: `claude mcp add` CLI, or write `~/.claude.json`.
//!   - **Claude Desktop**: JSON config at
//!     `~/Library/Application Support/Claude/claude_desktop_config.json`.
//!   - **Codex**: TOML config at `~/.codex/config.toml` under
//!     `[mcp_servers.<name>]` with `command` + `args` (stdio) or `url`
//!     (streamable HTTP, supported in recent Codex versions).
//!   - **OpenClaw**: plugin config; the plugin already honors
//!     `RIVAULT_API_URL` so we just override that.
//!
//! Each function is idempotent: running it twice is a no-op once the
//! entry exists. Uninstalls are likewise idempotent.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Logical identifier per runtime; the on-disk entry name in each
/// agent's config. We standardise on `"rivault"` so users can find
/// it consistently.
pub const ENTRY_NAME: &str = "rivault";

/// Aggregate "did the user install this for runtime X?" snapshot.
/// Driven by reading each agent's config file directly — no shell-out.
#[derive(Debug, Clone, Default, Serialize)]
pub struct McpInstallStatus {
    pub claude_code: bool,
    pub claude_desktop: bool,
    pub codex: bool,
    pub openclaw: bool,
}

/// Probe each runtime's config and report whether `rivault` is wired up.
pub fn probe_status() -> McpInstallStatus {
    McpInstallStatus {
        claude_code: claude_code::probe().unwrap_or(false),
        claude_desktop: claude_desktop::probe().unwrap_or(false),
        codex: codex::probe().unwrap_or(false),
        openclaw: openclaw::probe().unwrap_or(false),
    }
}

/// Build the URL the desktop app advertises to MCP clients.
pub fn mcp_url(http_port: u16) -> String {
    format!("http://127.0.0.1:{http_port}/mcp")
}

// ---- Claude Code ----------------------------------------------------------
pub mod claude_code {
    use super::*;
    use serde_json::{json, Value};

    fn config_path() -> Result<PathBuf> {
        Ok(home()?.join(".claude.json"))
    }

    pub fn probe() -> Result<bool> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(false);
        }
        let text = fs::read_to_string(&p)?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok(v.pointer(&format!("/mcpServers/{ENTRY_NAME}")).is_some())
    }

    pub fn install(http_port: u16) -> Result<()> {
        let p = config_path()?;
        let mut root: Value = if p.exists() {
            let text = fs::read_to_string(&p)?;
            serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
        } else {
            json!({})
        };
        let servers = root
            .as_object_mut()
            .ok_or_else(|| anyhow!("~/.claude.json is not a JSON object"))?
            .entry("mcpServers")
            .or_insert_with(|| json!({}));
        let map = servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("mcpServers is not an object"))?;
        map.insert(
            ENTRY_NAME.to_string(),
            json!({
                "type": "http",
                "url": super::mcp_url(http_port),
            }),
        );
        atomic_write_json(&p, &root)
    }

    pub fn uninstall() -> Result<()> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&p)?;
        let mut root: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if let Some(map) = root
            .as_object_mut()
            .and_then(|o| o.get_mut("mcpServers"))
            .and_then(|s| s.as_object_mut())
        {
            map.remove(ENTRY_NAME);
        }
        atomic_write_json(&p, &root)
    }
}

// ---- Claude Desktop -------------------------------------------------------
pub mod claude_desktop {
    use super::*;
    use serde_json::{json, Value};

    fn config_path() -> Result<PathBuf> {
        // macOS-only for now; Windows/Linux use different paths but the
        // daemon ships macOS-only too.
        Ok(home()?
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json"))
    }

    pub fn probe() -> Result<bool> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(false);
        }
        let text = fs::read_to_string(&p)?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok(v.pointer(&format!("/mcpServers/{ENTRY_NAME}")).is_some())
    }

    pub fn install(http_port: u16) -> Result<()> {
        let p = config_path()?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).ok();
        }
        let mut root: Value = if p.exists() {
            let text = fs::read_to_string(&p)?;
            serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
        } else {
            json!({})
        };
        let servers = root
            .as_object_mut()
            .ok_or_else(|| anyhow!("claude_desktop_config.json is not a JSON object"))?
            .entry("mcpServers")
            .or_insert_with(|| json!({}));
        let map = servers
            .as_object_mut()
            .ok_or_else(|| anyhow!("mcpServers is not an object"))?;
        // Claude Desktop currently expects stdio with `command` + `args`,
        // but recent versions accept `url`. Using `url` keeps everything
        // in one process; falling back to a shim subprocess would
        // fragment the daemon. If the user is on an older Claude Desktop
        // build, we'd need to ship a shim binary; flagged as a follow-up.
        map.insert(
            ENTRY_NAME.to_string(),
            json!({
                "url": super::mcp_url(http_port),
            }),
        );
        atomic_write_json(&p, &root)
    }

    pub fn uninstall() -> Result<()> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&p)?;
        let mut root: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if let Some(map) = root
            .as_object_mut()
            .and_then(|o| o.get_mut("mcpServers"))
            .and_then(|s| s.as_object_mut())
        {
            map.remove(ENTRY_NAME);
        }
        atomic_write_json(&p, &root)
    }
}

// ---- Codex ----------------------------------------------------------------
pub mod codex {
    use super::*;

    fn config_path() -> Result<PathBuf> {
        Ok(home()?.join(".codex").join("config.toml"))
    }

    /// Marker line bracketing our config block so we can find + remove it
    /// without bringing in a TOML parser. The config file may contain
    /// hand-edited content; surgical block-edits keep the user's
    /// modifications intact.
    const BEGIN: &str = "# >>> rivault (managed) >>>";
    const END: &str = "# <<< rivault (managed) <<<";

    pub fn probe() -> Result<bool> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(false);
        }
        Ok(fs::read_to_string(&p)?.contains(BEGIN))
    }

    pub fn install(http_port: u16) -> Result<()> {
        let p = config_path()?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).ok();
        }
        let url = super::mcp_url(http_port);
        let block = format!(
            "{BEGIN}\n[mcp_servers.{ENTRY_NAME}]\nurl = \"{url}\"\n{END}\n",
        );
        let existing = if p.exists() {
            fs::read_to_string(&p)?
        } else {
            String::new()
        };
        let new = match existing
            .find(BEGIN)
            .and_then(|s| existing[s..].find(END).map(|e| (s, s + e + END.len())))
        {
            Some((s, e)) => {
                // Replace existing block in place (idempotent; preserves
                // surrounding hand-edits).
                let mut out = String::with_capacity(existing.len());
                out.push_str(&existing[..s]);
                out.push_str(block.trim_end());
                out.push_str(&existing[e..]);
                out
            }
            None => {
                // Append, ensuring a leading newline if needed.
                let mut out = existing;
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&block);
                out
            }
        };
        atomic_write_text(&p, &new)
    }

    pub fn uninstall() -> Result<()> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&p)?;
        let Some(start) = text.find(BEGIN) else {
            return Ok(());
        };
        let Some(end_rel) = text[start..].find(END) else {
            return Ok(());
        };
        let end = start + end_rel + END.len();
        // Also consume the trailing newline if present.
        let end = if text.as_bytes().get(end) == Some(&b'\n') {
            end + 1
        } else {
            end
        };
        let mut out = String::with_capacity(text.len());
        out.push_str(&text[..start]);
        out.push_str(&text[end..]);
        atomic_write_text(&p, &out)
    }
}

// ---- OpenClaw -------------------------------------------------------------
pub mod openclaw {
    use super::*;
    use serde_json::{json, Value};

    fn config_path() -> Result<PathBuf> {
        Ok(home()?.join(".openclaw").join("openclaw.json"))
    }

    /// We don't add a separate "MCP" entry for OpenClaw — its existing
    /// Rivault skill plugin already calls into the upstream client via
    /// `RIVAULT_API_URL`. Pointing that env at the daemon's HTTP listener
    /// (where the proxy lives in Tier B; once the local MCP is the
    /// preferred path, OpenClaw will use the same `/mcp` endpoint) is
    /// the install gesture.
    ///
    /// Probe returns `true` when the env override is configured in
    /// `openclaw.json` and points at 127.0.0.1.
    pub fn probe() -> Result<bool> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(false);
        }
        let text = fs::read_to_string(&p)?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let env = v.pointer("/env/RIVAULT_API_URL").and_then(|v| v.as_str());
        Ok(env.map_or(false, |s| s.contains("127.0.0.1")))
    }

    pub fn install(http_port: u16) -> Result<()> {
        let p = config_path()?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).ok();
        }
        let mut root: Value = if p.exists() {
            let text = fs::read_to_string(&p)?;
            serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
        } else {
            json!({})
        };
        let env = root
            .as_object_mut()
            .ok_or_else(|| anyhow!("openclaw.json is not a JSON object"))?
            .entry("env")
            .or_insert_with(|| json!({}));
        let env_map = env
            .as_object_mut()
            .ok_or_else(|| anyhow!("openclaw.json `env` is not an object"))?;
        env_map.insert(
            "RIVAULT_API_URL".to_string(),
            json!(format!("http://127.0.0.1:{http_port}")),
        );
        atomic_write_json(&p, &root)
    }

    pub fn uninstall() -> Result<()> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&p)?;
        let mut root: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if let Some(env_map) = root
            .as_object_mut()
            .and_then(|o| o.get_mut("env"))
            .and_then(|e| e.as_object_mut())
        {
            env_map.remove("RIVAULT_API_URL");
        }
        atomic_write_json(&p, &root)
    }
}

// ---- shared utilities -----------------------------------------------------

fn home() -> Result<PathBuf> {
    dirs::home_dir().context("no home dir")
}

fn atomic_write_text(p: &Path, body: &str) -> Result<()> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).ok();
    }
    let tmp = p.with_extension("tmp.rivault");
    fs::write(&tmp, body.as_bytes())?;
    fs::rename(&tmp, p)?;
    Ok(())
}

fn atomic_write_json(p: &Path, value: &serde_json::Value) -> Result<()> {
    let pretty = serde_json::to_string_pretty(value)?;
    atomic_write_text(p, &pretty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// $HOME is process-global, and these tests mutate it. Serialize
    /// every test in this module so they don't race each other through
    /// `dirs::home_dir()`.
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn fresh_home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn with_home<F: FnOnce()>(home: &Path, f: F) {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", home);
        f();
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_code_install_then_uninstall_round_trips() {
        let home = fresh_home();
        with_home(home.path(), || {
            assert!(!claude_code::probe().unwrap());
            claude_code::install(47318).unwrap();
            assert!(claude_code::probe().unwrap());
            // Idempotent re-install
            claude_code::install(47318).unwrap();
            assert!(claude_code::probe().unwrap());
            claude_code::uninstall().unwrap();
            assert!(!claude_code::probe().unwrap());
            // Idempotent re-uninstall
            claude_code::uninstall().unwrap();
        });
    }

    #[test]
    fn claude_code_install_preserves_other_entries() {
        let home = fresh_home();
        with_home(home.path(), || {
            // Pretend the user has another MCP server already configured.
            let p = home.path().join(".claude.json");
            fs::write(
                &p,
                r#"{"mcpServers":{"other":{"url":"http://example.com"}},"settings":{"theme":"dark"}}"#,
            )
            .unwrap();
            claude_code::install(47318).unwrap();
            let after = fs::read_to_string(&p).unwrap();
            // Both entries present, settings unchanged.
            assert!(after.contains("\"other\""));
            assert!(after.contains("\"rivault\""));
            assert!(after.contains("\"theme\""));
            // Uninstall keeps the other entry.
            claude_code::uninstall().unwrap();
            let after = fs::read_to_string(&p).unwrap();
            assert!(after.contains("\"other\""));
            assert!(!after.contains("\"rivault\""));
        });
    }

    #[test]
    fn codex_install_uses_managed_block() {
        let home = fresh_home();
        with_home(home.path(), || {
            // User-authored TOML before our block.
            let p = home.path().join(".codex").join("config.toml");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, "model = \"o4-mini\"\n").unwrap();
            codex::install(47318).unwrap();
            let after = fs::read_to_string(&p).unwrap();
            assert!(after.contains("model = \"o4-mini\""));
            assert!(after.contains("[mcp_servers.rivault]"));
            assert!(after.contains("http://127.0.0.1:47318/mcp"));
            // Re-install replaces the managed block in place.
            codex::install(47319).unwrap();
            let after = fs::read_to_string(&p).unwrap();
            assert!(after.contains("http://127.0.0.1:47319/mcp"));
            assert!(!after.contains("47318"));
            // Uninstall strips just our block.
            codex::uninstall().unwrap();
            let after = fs::read_to_string(&p).unwrap();
            assert!(after.contains("model = \"o4-mini\""));
            assert!(!after.contains("[mcp_servers.rivault]"));
        });
    }

    #[test]
    fn openclaw_install_sets_env_var() {
        let home = fresh_home();
        with_home(home.path(), || {
            openclaw::install(47318).unwrap();
            let p = home.path().join(".openclaw").join("openclaw.json");
            let v: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            assert_eq!(
                v["env"]["RIVAULT_API_URL"],
                serde_json::Value::String("http://127.0.0.1:47318".into())
            );
            assert!(openclaw::probe().unwrap());
            openclaw::uninstall().unwrap();
            assert!(!openclaw::probe().unwrap());
        });
    }
}
