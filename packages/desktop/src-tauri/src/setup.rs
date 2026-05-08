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

/// Decide whether a per-runtime install should write, skip, or no-op.
///
/// Defends against three failure modes:
/// - **Clobbering a deliberate user override.** If the existing value
///   points at something other than localhost (staging proxy, corp
///   gateway, alternate port outside our range), don't touch it.
/// - **Wasted writes.** If the value already matches what we'd write,
///   don't re-open the file. Removes write-race surface and keeps the
///   audit trail clean.
/// - **Stale localhost values.** If the value is a 127.0.0.1 URL on a
///   different port (we picked a different port last run), overwrite.
fn decide(current: Option<&str>, target: &str) -> InstallDecision {
    match current {
        None => InstallDecision::Write,
        Some(s) if s == target => InstallDecision::NoOp,
        Some(s) if is_local_url(s) => InstallDecision::Write,
        Some(s) => InstallDecision::Skip(s.to_string()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InstallDecision {
    /// Field absent or pointing at a stale localhost URL (different port).
    Write,
    /// Field already matches the target — don't open the file for write.
    NoOp,
    /// Field is a non-local URL the user set deliberately. Carries the
    /// existing value for logging.
    Skip(String),
}

fn is_local_url(s: &str) -> bool {
    s.starts_with("http://127.0.0.1")
        || s.starts_with("http://localhost")
        || s.starts_with("https://127.0.0.1")
        || s.starts_with("https://localhost")
}

fn log_skip(runtime: &str, existing: &str) {
    tracing::info!(
        runtime,
        existing,
        "skipping mcp install: user has a non-localhost value configured; \
         delete it manually if you want the daemon to manage this runtime",
    );
}

/// Auto-install on every supported runtime whose config file exists.
///
/// Called by the daemon at startup once the HTTP port is bound.
/// Idempotent: each per-runtime `install()` short-circuits to NoOp if
/// the entry already points at the right URL, and Skip if the user has
/// a non-localhost value.
pub fn auto_install(http_port: u16) {
    if claude_code::config_exists() {
        if let Err(e) = claude_code::install(http_port) {
            tracing::warn!("claude_code auto-install: {e:#}");
        }
    }
    if claude_desktop::config_exists() {
        if let Err(e) = claude_desktop::install(http_port) {
            tracing::warn!("claude_desktop auto-install: {e:#}");
        }
    }
    if codex::config_exists() {
        if let Err(e) = codex::install(http_port) {
            tracing::warn!("codex auto-install: {e:#}");
        }
    }
    if openclaw::config_exists() {
        if let Err(e) = openclaw::install(http_port) {
            tracing::warn!("openclaw auto-install: {e:#}");
        }
    }
}

// ---- Claude Code ----------------------------------------------------------
pub mod claude_code {
    use super::*;
    use serde_json::{json, Value};

    fn config_path() -> Result<PathBuf> {
        Ok(home()?.join(".claude.json"))
    }

    pub fn config_exists() -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
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
        let target = super::mcp_url(http_port);
        let root_text = if p.exists() {
            fs::read_to_string(&p)?
        } else {
            String::new()
        };
        let mut root: Value = if root_text.is_empty() {
            json!({})
        } else {
            serde_json::from_str(&root_text).unwrap_or_else(|_| json!({}))
        };

        let current = root
            .pointer(&format!("/mcpServers/{ENTRY_NAME}/url"))
            .and_then(|v| v.as_str());
        match decide(current, &target) {
            InstallDecision::NoOp => return Ok(()),
            InstallDecision::Skip(existing) => {
                log_skip("claude_code", &existing);
                return Ok(());
            }
            InstallDecision::Write => {}
        }

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
                "url": target,
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

    pub fn config_exists() -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
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
        let target = super::mcp_url(http_port);
        let mut root: Value = if p.exists() {
            let text = fs::read_to_string(&p)?;
            serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
        } else {
            json!({})
        };

        let current = root
            .pointer(&format!("/mcpServers/{ENTRY_NAME}/url"))
            .and_then(|v| v.as_str());
        match decide(current, &target) {
            InstallDecision::NoOp => return Ok(()),
            InstallDecision::Skip(existing) => {
                log_skip("claude_desktop", &existing);
                return Ok(());
            }
            InstallDecision::Write => {}
        }

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
                "url": target,
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

    pub fn config_exists() -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
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

    /// Detect a hand-authored `[mcp_servers.rivault]` table outside our
    /// managed block. If present, the user owns this entry — leave it
    /// alone so we don't create duplicate TOML keys.
    fn has_unmanaged_entry(existing: &str) -> bool {
        // Strip the managed block first, then scan the rest.
        let stripped = match existing
            .find(BEGIN)
            .and_then(|s| existing[s..].find(END).map(|e| (s, s + e + END.len())))
        {
            Some((s, e)) => {
                let mut out = String::with_capacity(existing.len());
                out.push_str(&existing[..s]);
                out.push_str(&existing[e..]);
                out
            }
            None => existing.to_string(),
        };
        // Match `[mcp_servers.rivault]` anchored to the start of a line.
        stripped
            .lines()
            .any(|line| line.trim_start() == "[mcp_servers.rivault]")
    }

    pub fn install(http_port: u16) -> Result<()> {
        let p = config_path()?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).ok();
        }
        let url = super::mcp_url(http_port);
        let target_block = format!(
            "{BEGIN}\n[mcp_servers.{ENTRY_NAME}]\nurl = \"{url}\"\n{END}\n",
        );
        let existing = if p.exists() {
            fs::read_to_string(&p)?
        } else {
            String::new()
        };

        if has_unmanaged_entry(&existing) {
            log_skip("codex", "[mcp_servers.rivault] (hand-authored)");
            return Ok(());
        }

        // If the managed block is already exactly what we'd write, no-op.
        let trimmed_target = target_block.trim_end();
        if let Some(start) = existing.find(BEGIN) {
            if let Some(end_rel) = existing[start..].find(END) {
                let end = start + end_rel + END.len();
                let current_block = &existing[start..end];
                if current_block == trimmed_target {
                    return Ok(());
                }
            }
        }

        let new = match existing
            .find(BEGIN)
            .and_then(|s| existing[s..].find(END).map(|e| (s, s + e + END.len())))
        {
            Some((s, e)) => {
                // Replace existing block in place (idempotent; preserves
                // surrounding hand-edits).
                let mut out = String::with_capacity(existing.len());
                out.push_str(&existing[..s]);
                out.push_str(trimmed_target);
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
                out.push_str(&target_block);
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
//
// OpenClaw is unusual among the supported runtimes in that its config
// schema rejects unknown keys. Earlier iterations of this module wrote
// `skills.entries.rivault.apiUrl` to point the plugin at the daemon —
// the user's `openclaw doctor` correctly flagged it as an invalid key
// and refused to start the gateway.
//
// The skill auto-discovers the daemon now: the desktop daemon's
// discovery file at `~/Library/Application Support/Rivault/daemon.json`
// is read by `packages/skill/src/lib/discovery.ts` and used as the
// preferred API base URL when present. So OpenClaw needs *no* config
// edit to route through the daemon — the install() function below is
// reduced to a cleanup-only operation that strips the now-invalid
// `apiUrl` key from rows that an older daemon binary may have written.

pub mod openclaw {
    use super::*;
    use serde_json::Value;

    fn config_path() -> Result<PathBuf> {
        Ok(home()?.join(".openclaw").join("openclaw.json"))
    }

    pub fn config_exists() -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Probe returns `true` once the cleanup is settled — there is no
    /// `apiUrl` left in `skills.entries.rivault`. The daemon no longer
    /// writes this key; auto-discovery handles routing.
    pub fn probe() -> Result<bool> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(false);
        }
        let text = fs::read_to_string(&p)?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let has_legacy_apiurl = v
            .pointer("/skills/entries/rivault/apiUrl")
            .is_some();
        Ok(!has_legacy_apiurl)
    }

    /// Cleanup-only: strip a legacy `apiUrl` key under
    /// `skills.entries.rivault` if present. No-ops if the key isn't
    /// there or the file doesn't exist.
    ///
    /// Signature still takes `http_port` for API symmetry with the
    /// other runtimes' `install(port)` calls — the value is unused.
    pub fn install(_http_port: u16) -> Result<()> {
        uninstall()
    }

    pub fn uninstall() -> Result<()> {
        let p = config_path()?;
        if !p.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&p)?;
        let mut root: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let removed = root
            .as_object_mut()
            .and_then(|o| o.get_mut("skills"))
            .and_then(|s| s.as_object_mut())
            .and_then(|s| s.get_mut("entries"))
            .and_then(|e| e.as_object_mut())
            .and_then(|e| e.get_mut("rivault"))
            .and_then(|r| r.as_object_mut())
            .and_then(|entry| entry.remove("apiUrl"))
            .is_some();
        if removed {
            atomic_write_json(&p, &root)?;
            tracing::info!(
                "openclaw: stripped legacy `skills.entries.rivault.apiUrl` \
                 (skill now auto-discovers the daemon via discovery file)"
            );
        }
        Ok(())
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
    fn openclaw_install_strips_legacy_apiurl_in_place() {
        let home = fresh_home();
        with_home(home.path(), || {
            // Pre-condition: a previous daemon binary wrote `apiUrl` here,
            // and OpenClaw rejects it as an unknown key.
            let p = home.path().join(".openclaw").join("openclaw.json");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(
                &p,
                r#"{"skills":{"entries":{"rivault":{"enabled":true,"apiKey":"rv_live_xxx","apiUrl":"http://127.0.0.1:47318"}}}}"#,
            )
            .unwrap();
            assert!(!openclaw::probe().unwrap(), "legacy apiUrl present pre-cleanup");

            openclaw::install(47318).unwrap();

            let v: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            let entry = &v["skills"]["entries"]["rivault"];
            assert_eq!(entry["apiKey"], "rv_live_xxx");
            assert_eq!(entry["enabled"], true);
            assert!(entry.get("apiUrl").is_none(), "apiUrl must be stripped");
            assert!(openclaw::probe().unwrap(), "post-cleanup probe true");
        });
    }

    #[test]
    fn openclaw_install_no_op_when_clean() {
        let home = fresh_home();
        with_home(home.path(), || {
            let p = home.path().join(".openclaw").join("openclaw.json");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(
                &p,
                r#"{"skills":{"entries":{"rivault":{"enabled":true,"apiKey":"rv_live_xxx"}}}}"#,
            )
            .unwrap();
            let mtime_before = fs::metadata(&p).unwrap().modified().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            openclaw::install(47318).unwrap();
            let mtime_after = fs::metadata(&p).unwrap().modified().unwrap();
            assert_eq!(
                mtime_before, mtime_after,
                "no-op cleanup must not rewrite the config"
            );
        });
    }

    #[test]
    fn openclaw_install_no_op_when_file_absent() {
        let home = fresh_home();
        with_home(home.path(), || {
            openclaw::install(47318).unwrap();
            let p = home.path().join(".openclaw").join("openclaw.json");
            assert!(!p.exists(), "install must not create openclaw.json");
        });
    }

    #[test]
    fn install_skips_when_user_has_non_local_url() {
        let home = fresh_home();
        with_home(home.path(), || {
            // User points Claude Code at a corporate proxy.
            let p = home.path().join(".claude.json");
            fs::write(
                &p,
                r#"{"mcpServers":{"rivault":{"type":"http","url":"https://rivault.corp.example.com/mcp"}}}"#,
            )
            .unwrap();
            // Auto-install must NOT clobber it.
            claude_code::install(47318).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            assert_eq!(
                v["mcpServers"]["rivault"]["url"],
                "https://rivault.corp.example.com/mcp"
            );
        });
    }

    #[test]
    fn install_overwrites_stale_localhost_port() {
        let home = fresh_home();
        with_home(home.path(), || {
            // Previous run picked a different port; new run uses 47320.
            let p = home.path().join(".claude.json");
            fs::write(
                &p,
                r#"{"mcpServers":{"rivault":{"type":"http","url":"http://127.0.0.1:47318/mcp"}}}"#,
            )
            .unwrap();
            claude_code::install(47320).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            assert_eq!(
                v["mcpServers"]["rivault"]["url"],
                "http://127.0.0.1:47320/mcp"
            );
        });
    }

    #[test]
    fn install_is_no_op_when_already_correct() {
        let home = fresh_home();
        with_home(home.path(), || {
            let p = home.path().join(".claude.json");
            // Pre-existing file, exactly the URL we'd write.
            fs::write(
                &p,
                r#"{"mcpServers":{"rivault":{"type":"http","url":"http://127.0.0.1:47318/mcp"}}}"#,
            )
            .unwrap();
            let mtime_before = fs::metadata(&p).unwrap().modified().unwrap();
            // Sleep enough that any rewrite would land at a later mtime.
            std::thread::sleep(std::time::Duration::from_millis(20));
            claude_code::install(47318).unwrap();
            let mtime_after = fs::metadata(&p).unwrap().modified().unwrap();
            // No-op path must not touch the file at all.
            assert_eq!(
                mtime_before, mtime_after,
                "no-op install must not rewrite the config file"
            );
        });
    }

    #[test]
    fn codex_install_skips_when_user_authored_unmanaged_block() {
        let home = fresh_home();
        with_home(home.path(), || {
            let p = home.path().join(".codex").join("config.toml");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            // User wrote their own [mcp_servers.rivault] table by hand.
            fs::write(
                &p,
                "model = \"o4-mini\"\n\n[mcp_servers.rivault]\nurl = \"https://rivault.corp.example.com/mcp\"\n",
            )
            .unwrap();
            codex::install(47318).unwrap();
            let after = fs::read_to_string(&p).unwrap();
            // Original entry intact; no managed block appended.
            assert!(after.contains("rivault.corp.example.com"));
            assert!(!after.contains("# >>> rivault (managed) >>>"));
            assert!(!after.contains("127.0.0.1"));
        });
    }

    #[test]
    fn openclaw_install_preserves_other_skill_fields() {
        let home = fresh_home();
        with_home(home.path(), || {
            // Mimic real openclaw.json: skills.entries.rivault.apiKey set
            // by user wizard, plus a stale apiUrl from an older daemon.
            // Cleanup must remove ONLY apiUrl, leaving every other field
            // byte-identical.
            let p = home.path().join(".openclaw").join("openclaw.json");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(
                &p,
                r#"{"skills":{"entries":{"rivault":{"enabled":true,"apiKey":"rv_live_xxx","apiUrl":"http://127.0.0.1:99999"}}}}"#,
            )
            .unwrap();
            openclaw::install(47318).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            let entry = &v["skills"]["entries"]["rivault"];
            assert_eq!(entry["apiKey"], "rv_live_xxx");
            assert_eq!(entry["enabled"], true);
            assert!(entry.get("apiUrl").is_none());
        });
    }
}
