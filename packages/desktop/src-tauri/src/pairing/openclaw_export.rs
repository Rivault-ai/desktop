//! Configure the OpenClaw plugin for users who have OpenClaw installed.
//!
//! ## Detection condition
//!
//! Used by both `install.sh` and the desktop daemon to decide whether to
//! touch OpenClaw at all:
//!
//! ```text
//! HAS_OPENCLAW = `openclaw` is on PATH  AND  ~/.openclaw/openclaw.json exists
//! ```
//!
//! Having the CLI installed but never having run the gateway isn't enough
//! — the first `openclaw gateway` run creates `openclaw.json`. We use the
//! file as the signal of intent.
//!
//! ## What `install_and_configure` does, in order
//!
//! Only if the detection condition holds:
//!
//!   1. `openclaw plugins uninstall rivault --force` (idempotent prep).
//!   2. `openclaw plugins install <skill_dir>` — locates the skill bundle
//!      at the first of:
//!         - `~/.openclaw/skills/rivault/` (where install.sh drops it)
//!         - the Tauri app's `Contents/Resources/skill/` (the fallback
//!           for users who installed via Homebrew Cask without running
//!           install.sh)
//!   3. Write `plugins.entries.rivault.config.apiKey` into `openclaw.json`,
//!      set `enabled: true`, ensure `rivault` is in `plugins.allow`. The
//!      CLI's `install` command does NOT populate apiKey, so this step
//!      is still needed after a successful install. We deliberately do
//!      NOT write `apiUrl`: when present, the plugin uses it literally
//!      and bypasses the local daemon, which breaks L2 envelope
//!      decryption (the daemon owns the ephemeral keypair store).
//!      Leaving `apiUrl` unset lets the plugin auto-discover the daemon
//!      via `~/Library/Application Support/Rivault/daemon.json`.
//!
//! Returns `Ok(true)` when the plugin was fully configured. `Ok(false)`
//! when OpenClaw isn't installed (no warning, no work — this is the
//! happy path for MCP-only users). `Err(_)` only for genuinely
//! unexpected failures.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn openclaw_config_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".openclaw").join("openclaw.json"))
}

fn openclaw_skill_dir() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let p = home.join(".openclaw").join("skills").join("rivault");
    if p.is_dir() { Some(p) } else { None }
}

/// Find the `openclaw` binary. PATH lookup is unreliable when the app
/// was launched via `open` from Finder (GUI processes don't inherit the
/// shell's PATH), so we also check the standard install locations.
fn find_openclaw_bin() -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("openclaw");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for fallback in [
        "/opt/homebrew/bin/openclaw",
        "/usr/local/bin/openclaw",
        "/usr/bin/openclaw",
    ] {
        let p = PathBuf::from(fallback);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// True iff the user has OpenClaw set up enough that we should manage
/// the rivault plugin for them.
pub fn has_openclaw() -> bool {
    let Some(cfg) = openclaw_config_path() else { return false };
    if !cfg.is_file() {
        return false;
    }
    find_openclaw_bin().is_some()
}

/// Install + configure the rivault plugin in OpenClaw.
///
/// `bundled_skill_dir`: optional fallback path (typically
/// `app.path().resource_dir()?.join("skill")`) used when the user
/// installed Rivault via Homebrew Cask and didn't run install.sh, so
/// `~/.openclaw/skills/rivault/` is empty.
///
/// Returns `Ok(false)` when OpenClaw isn't installed — no warnings, no
/// work, this is the happy path for MCP-only users.
pub fn install_and_configure(
    api_key: &str,
    bundled_skill_dir: Option<&Path>,
) -> Result<bool> {
    if !has_openclaw() {
        return Ok(false);
    }
    let cli = find_openclaw_bin().expect("has_openclaw just confirmed it");

    // Locate a skill bundle. Prefer the install.sh-managed location so
    // the user (or `openclaw plugins list`) can find the source dir at
    // the canonical path; fall back to the .app-bundled copy.
    let skill_dir = openclaw_skill_dir().or_else(|| {
        bundled_skill_dir.and_then(|p| if p.is_dir() { Some(p.to_path_buf()) } else { None })
    });
    let Some(skill_dir) = skill_dir else {
        // We could neither find a skill on disk nor a bundled fallback.
        // Still write the apiKey to openclaw.json so the plugin
        // configuration is correct for whenever the skill bundle later
        // appears.
        write_credentials_only(api_key)?;
        tracing::warn!(
            "openclaw is installed but no skill bundle was found at \
             ~/.openclaw/skills/rivault or the app's Resources — wrote \
             apiKey only; run install.sh to register the plugin"
        );
        return Ok(true);
    };

    // Idempotent prep: tolerate "not installed" exit codes.
    let _ = Command::new(&cli)
        .args(["plugins", "uninstall", "rivault", "--force"])
        .output();

    // Belt-and-suspenders. `openclaw plugins uninstall --force` clears
    // the openclaw.json records (plugins.{allow,entries,installs}) but
    // in several edge cases leaves `~/.openclaw/extensions/rivault/`
    // behind — most reliably when the install record was already
    // cleared by an earlier call, which causes uninstall to refuse
    // with "Plugin 'rivault' is not managed by plugins config/install
    // records". The next `plugins install` then fails with "plugin
    // already exists: ... (delete it first)". Same workaround
    // install.sh uses in its uninstall branch.
    if let Some(home) = dirs::home_dir() {
        let ext = home.join(".openclaw").join("extensions").join("rivault");
        if ext.exists() {
            let _ = fs::remove_dir_all(&ext);
        }
    }

    let install_out = Command::new(&cli)
        .args(["plugins", "install"])
        .arg(&skill_dir)
        .output()
        .context("invoke openclaw plugins install")?;
    if !install_out.status.success() {
        let stderr = String::from_utf8_lossy(&install_out.stderr);
        anyhow::bail!(
            "`openclaw plugins install {}` failed: {}",
            skill_dir.display(),
            stderr.trim()
        );
    }

    // The CLI registers the plugin but never sets apiKey on the plugin
    // config — that's the daemon's job. Do it now.
    write_credentials_only(api_key)?;
    Ok(true)
}

/// Write `apiKey` to `plugins.entries.rivault.config`. We deliberately
/// do NOT write `apiUrl`: when present, the plugin uses it literally,
/// short-circuiting `config.apiBaseUrl`'s discovery logic and routing
/// every call straight to the public API. That bypasses the local
/// daemon, which is where ephemeral P-256 keypairs are generated and
/// stored for L2 envelope decryption — without those, the daemon emits
/// `no keypair stored for request_id=...; daemon restart between create
/// and poll?` when the plugin tries to poll. Leaving `apiUrl` unset
/// lets the plugin auto-discover the daemon via
/// `~/Library/Application Support/Rivault/daemon.json`. Users who need
/// to override the URL can still do so via `RIVAULT_API_URL`.
fn write_credentials_only(api_key: &str) -> Result<()> {
    let path = openclaw_config_path().context("no home dir")?;
    let raw = fs::read_to_string(&path)?;
    let mut root: Value = serde_json::from_str(&raw)?;
    if !root.is_object() {
        root = json!({});
    }
    let root_obj = root.as_object_mut().expect("root is object");
    let plugins = root_obj.entry("plugins").or_insert_with(|| json!({}));
    let plugins_obj = plugins
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("openclaw.json::plugins is not an object"))?;
    let entries = plugins_obj.entry("entries").or_insert_with(|| json!({}));
    let entries_obj = entries
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("openclaw.json::plugins.entries is not an object"))?;
    let rivault = entries_obj.entry("rivault").or_insert_with(|| json!({}));
    let rivault_obj = rivault
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("openclaw.json::plugins.entries.rivault is not an object"))?;
    rivault_obj.insert("enabled".into(), Value::Bool(true));
    let config = rivault_obj.entry("config").or_insert_with(|| json!({}));
    let config_obj = config.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("openclaw.json::plugins.entries.rivault.config is not an object")
    })?;
    config_obj.insert("apiKey".into(), Value::String(api_key.to_string()));
    // Belt-and-suspenders: scrub any pre-existing apiUrl. Older builds
    // wrote it and users upgrading should not stay routed direct-to-cloud.
    config_obj.remove("apiUrl");

    let pretty = serde_json::to_string_pretty(&root)?;
    let tmp = path.with_extension("tmp.rivault");
    fs::write(&tmp, pretty.as_bytes())?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Clear apiKey + apiUrl from the plugin config without disturbing
/// other plugin entries. Called from `clear_config` (sign out).
///
/// Returns `Ok(true)` when fields were actually removed. Does not run
/// `openclaw plugins uninstall` — we keep the plugin installed so the
/// user can re-pair without re-running install.sh.
pub fn clear_credentials() -> Result<bool> {
    let Some(path) = openclaw_config_path() else { return Ok(false) };
    if !path.is_file() {
        return Ok(false);
    }
    let raw = fs::read_to_string(&path)?;
    let mut root: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let Some(cfg) = root
        .get_mut("plugins")
        .and_then(|p| p.get_mut("entries"))
        .and_then(|e| e.get_mut("rivault"))
        .and_then(|r| r.get_mut("config"))
        .and_then(|c| c.as_object_mut())
    else {
        return Ok(false);
    };
    let had_key = cfg.remove("apiKey").is_some();
    let had_url = cfg.remove("apiUrl").is_some();
    if !had_key && !had_url {
        return Ok(false);
    }
    let pretty = serde_json::to_string_pretty(&root)?;
    let tmp = path.with_extension("tmp.rivault");
    fs::write(&tmp, pretty.as_bytes())?;
    fs::rename(&tmp, &path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn with_home<F: FnOnce()>(home: &Path, f: F) {
        let _g = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", home);
        f();
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn has_openclaw_false_when_config_absent() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            assert!(!has_openclaw());
        });
    }

    #[test]
    fn install_returns_false_without_openclaw() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            let r = install_and_configure("rv_live_x", None).unwrap();
            assert!(!r, "no openclaw → false, no work");
        });
    }

    #[test]
    fn write_credentials_only_populates_apikey_and_scrubs_apiurl() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            let oc = dir.path().join(".openclaw");
            fs::create_dir_all(&oc).unwrap();
            // Seed with a pre-existing apiUrl from an older daemon
            // version so we can verify the scrub.
            fs::write(
                oc.join("openclaw.json"),
                r#"{ "plugins": { "entries": { "rivault": { "config": { "apiUrl": "https://api.rivault.ai" } } } } }"#,
            ).unwrap();
            write_credentials_only("rv_live_test").unwrap();
            let v: Value =
                serde_json::from_str(&fs::read_to_string(oc.join("openclaw.json")).unwrap())
                    .unwrap();
            assert_eq!(v["plugins"]["entries"]["rivault"]["enabled"], true);
            assert_eq!(
                v["plugins"]["entries"]["rivault"]["config"]["apiKey"],
                "rv_live_test"
            );
            assert!(
                v["plugins"]["entries"]["rivault"]["config"]
                    .get("apiUrl")
                    .is_none(),
                "stale apiUrl must be scrubbed so plugin auto-discovers daemon"
            );
        });
    }

    #[test]
    fn clear_removes_credentials_in_place() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            let oc = dir.path().join(".openclaw");
            fs::create_dir_all(&oc).unwrap();
            fs::write(
                oc.join("openclaw.json"),
                r#"{ "plugins": { "entries": { "rivault": { "enabled": true, "config": { "apiKey": "x", "apiUrl": "u" } } } } }"#,
            ).unwrap();
            assert!(clear_credentials().unwrap());
            let v: Value =
                serde_json::from_str(&fs::read_to_string(oc.join("openclaw.json")).unwrap())
                    .unwrap();
            let cfg = &v["plugins"]["entries"]["rivault"]["config"];
            assert!(cfg.get("apiKey").is_none());
            assert!(cfg.get("apiUrl").is_none());
            assert_eq!(v["plugins"]["entries"]["rivault"]["enabled"], true);
        });
    }

    #[test]
    fn clear_is_noop_when_config_absent() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            assert!(!clear_credentials().unwrap());
        });
    }
}
