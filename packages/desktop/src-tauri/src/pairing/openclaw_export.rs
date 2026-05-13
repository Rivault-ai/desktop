//! Write the user's Rivault API key into the OpenClaw plugin config so
//! the OpenClaw runtime authenticates without a separate install.sh
//! prompt. Mirror of `openclaw_import`'s read path.
//!
//! Target path:  `~/.openclaw/openclaw.json`
//! Field paths:
//!   - `plugins.entries.rivault.config.apiKey`
//!   - `plugins.entries.rivault.config.apiUrl`
//!   - `plugins.entries.rivault.enabled  = true`
//!   - `plugins.allow` ← contains `"rivault"`
//!
//! Best-effort: any missing parent dir, malformed JSON, or unwritable
//! file logs a warning and returns `Ok(false)` rather than an error.
//! `save_config` should never fail because OpenClaw isn't installed.

use anyhow::Result;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

fn openclaw_config_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".openclaw").join("openclaw.json"))
}

/// Write the credentials into the OpenClaw plugin config. Returns
/// `Ok(true)` if the file existed and was updated, `Ok(false)` if
/// OpenClaw isn't installed (no openclaw.json present) — both are
/// success outcomes from save_config's perspective.
pub fn write_credentials(api_key: &str, base_url: &str) -> Result<bool> {
    let Some(path) = openclaw_config_path() else {
        return Ok(false);
    };
    if !path.exists() {
        // OpenClaw not installed — nothing to write. Not an error.
        return Ok(false);
    }
    let raw = fs::read_to_string(&path)?;
    let mut root: Value = serde_json::from_str(&raw)?;

    // Ensure root is an object.
    if !root.is_object() {
        root = json!({});
    }
    let root_obj = root.as_object_mut().expect("just-ensured");

    // plugins.entries.rivault.config { apiKey, apiUrl } + enabled = true
    let plugins = root_obj
        .entry("plugins")
        .or_insert_with(|| json!({}));
    let plugins_obj = plugins.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("openclaw.json::plugins is not an object")
    })?;

    let entries = plugins_obj
        .entry("entries")
        .or_insert_with(|| json!({}));
    let entries_obj = entries.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("openclaw.json::plugins.entries is not an object")
    })?;

    let rivault = entries_obj
        .entry("rivault")
        .or_insert_with(|| json!({}));
    let rivault_obj = rivault.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("openclaw.json::plugins.entries.rivault is not an object")
    })?;
    rivault_obj.insert("enabled".into(), Value::Bool(true));
    let config = rivault_obj
        .entry("config")
        .or_insert_with(|| json!({}));
    let config_obj = config.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("openclaw.json::plugins.entries.rivault.config is not an object")
    })?;
    config_obj.insert("apiKey".into(), Value::String(api_key.to_string()));
    config_obj.insert("apiUrl".into(), Value::String(base_url.to_string()));

    // plugins.allow includes "rivault"
    let allow = plugins_obj
        .entry("allow")
        .or_insert_with(|| json!([]));
    if let Some(arr) = allow.as_array_mut() {
        let has = arr.iter().any(|v| v.as_str() == Some("rivault"));
        if !has {
            arr.push(Value::String("rivault".into()));
        }
    }

    let pretty = serde_json::to_string_pretty(&root)?;
    let tmp = path.with_extension("tmp.rivault");
    fs::write(&tmp, pretty.as_bytes())?;
    fs::rename(&tmp, &path)?;
    Ok(true)
}

/// Clear our credentials from OpenClaw's plugin config without
/// disturbing other plugin entries. Called from `clear_config` (sign
/// out) and as part of full uninstall flows.
pub fn clear_credentials() -> Result<bool> {
    let Some(path) = openclaw_config_path() else {
        return Ok(false);
    };
    if !path.exists() {
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

    fn with_home<F: FnOnce()>(home: &std::path::Path, f: F) {
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
    fn write_returns_false_when_openclaw_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            // No .openclaw dir → Ok(false), not an error.
            let r = write_credentials("rv_live_x", "https://api.rivault.ai").unwrap();
            assert!(!r, "no openclaw.json present → false");
        });
    }

    #[test]
    fn write_populates_all_required_fields_on_fresh_file() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            let oc = dir.path().join(".openclaw");
            fs::create_dir_all(&oc).unwrap();
            fs::write(oc.join("openclaw.json"), "{}").unwrap();

            let r = write_credentials("rv_live_test", "https://api.rivault.ai").unwrap();
            assert!(r);

            let raw = fs::read_to_string(oc.join("openclaw.json")).unwrap();
            let v: Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(v["plugins"]["entries"]["rivault"]["enabled"], true);
            assert_eq!(
                v["plugins"]["entries"]["rivault"]["config"]["apiKey"],
                "rv_live_test"
            );
            assert_eq!(
                v["plugins"]["entries"]["rivault"]["config"]["apiUrl"],
                "https://api.rivault.ai"
            );
            assert!(v["plugins"]["allow"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x == "rivault"));
        });
    }

    #[test]
    fn write_preserves_other_plugins_and_unrelated_keys() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            let oc = dir.path().join(".openclaw");
            fs::create_dir_all(&oc).unwrap();
            fs::write(
                oc.join("openclaw.json"),
                r#"{
                  "skills": { "entries": { "rivault": { "enabled": true } } },
                  "plugins": {
                    "allow": ["telegram", "whatsapp"],
                    "entries": { "telegram": { "enabled": true } }
                  }
                }"#,
            )
            .unwrap();

            write_credentials("rv_live_x", "https://api.rivault.ai").unwrap();

            let v: Value = serde_json::from_str(
                &fs::read_to_string(oc.join("openclaw.json")).unwrap(),
            )
            .unwrap();
            // Pre-existing keys survive untouched.
            assert_eq!(v["skills"]["entries"]["rivault"]["enabled"], true);
            assert_eq!(v["plugins"]["entries"]["telegram"]["enabled"], true);
            let allow = v["plugins"]["allow"].as_array().unwrap();
            assert!(allow.iter().any(|x| x == "telegram"));
            assert!(allow.iter().any(|x| x == "whatsapp"));
            assert!(allow.iter().any(|x| x == "rivault"));
            // Our key landed.
            assert_eq!(
                v["plugins"]["entries"]["rivault"]["config"]["apiKey"],
                "rv_live_x"
            );
        });
    }

    #[test]
    fn write_overwrites_existing_rivault_key() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            let oc = dir.path().join(".openclaw");
            fs::create_dir_all(&oc).unwrap();
            fs::write(
                oc.join("openclaw.json"),
                r#"{ "plugins": { "entries": { "rivault": { "config": { "apiKey": "rv_live_OLD" } } } } }"#,
            )
            .unwrap();
            write_credentials("rv_live_NEW", "https://api.rivault.ai").unwrap();
            let v: Value = serde_json::from_str(
                &fs::read_to_string(oc.join("openclaw.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                v["plugins"]["entries"]["rivault"]["config"]["apiKey"],
                "rv_live_NEW"
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
                r#"{ "plugins": { "entries": { "rivault": { "enabled": true, "config": { "apiKey": "rv_live_x", "apiUrl": "https://api.rivault.ai" } } } } }"#,
            )
            .unwrap();
            let r = clear_credentials().unwrap();
            assert!(r);
            let v: Value = serde_json::from_str(
                &fs::read_to_string(oc.join("openclaw.json")).unwrap(),
            )
            .unwrap();
            let cfg = &v["plugins"]["entries"]["rivault"]["config"];
            assert!(cfg.get("apiKey").is_none(), "apiKey must be removed");
            assert!(cfg.get("apiUrl").is_none(), "apiUrl must be removed");
            // The `enabled` flag is left intact — clearing the key shouldn't
            // disable the plugin; the user may want to re-enter later.
            assert_eq!(v["plugins"]["entries"]["rivault"]["enabled"], true);
        });
    }

    #[test]
    fn clear_is_noop_when_key_absent() {
        let dir = tempfile::tempdir().unwrap();
        with_home(dir.path(), || {
            let oc = dir.path().join(".openclaw");
            fs::create_dir_all(&oc).unwrap();
            fs::write(
                oc.join("openclaw.json"),
                r#"{ "plugins": { "entries": { "rivault": { "enabled": true } } } }"#,
            )
            .unwrap();
            let r = clear_credentials().unwrap();
            assert!(!r, "nothing to clear → false");
        });
    }
}
