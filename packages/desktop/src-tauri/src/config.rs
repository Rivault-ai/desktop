//! User configuration: API key + identity, persisted at
//! `~/Library/Application Support/Rivault/config.json` (mode 0600).
//!
//! Optional. The daemon ingests release events purely via authenticated IPC
//! and does not require an API key to function — this is for the dashboard
//! to display whose vault is wired up, and for future features that need
//! outbound calls (version checks, billing).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub api_key: String,
    pub base_url: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub api_key_id: Option<String>,
}

fn config_path() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .context("no data dir")?
        .join("Rivault");
    fs::create_dir_all(&dir).ok();
    Ok(dir.join("config.json"))
}

pub fn load() -> Result<Option<Config>> {
    let p = config_path()?;
    if !p.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&p)?;
    Ok(Some(serde_json::from_str(&raw)?))
}

pub fn save(cfg: &Config) -> Result<()> {
    let p = config_path()?;
    let body = serde_json::to_vec_pretty(cfg)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&p)?;
    f.write_all(&body)?;
    Ok(())
}

pub fn clear() -> Result<()> {
    let p = config_path()?;
    if p.exists() {
        fs::remove_file(p)?;
    }
    Ok(())
}

/// Validate an API key against the configured base URL.
///
/// Tries `/agent/me` first (returns `{userId, apiKeyId}` on a recent backend).
/// Falls back to `/agent/vault/search?q=.&limit=1` for older deploys — that
/// endpoint exists and authenticates the key, but doesn't expose identity,
/// so the resulting `MeResponse` has empty fields.
pub async fn validate(api_key: &str, base_url: &str) -> Result<MeResponse> {
    let base = base_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let timeout = std::time::Duration::from_secs(10);

    let me_res = client
        .get(format!("{base}/agent/me"))
        .bearer_auth(api_key)
        .timeout(timeout)
        .send()
        .await
        .context("network error contacting Rivault API")?;

    let status = me_res.status();
    if status.is_success() {
        let me: MeResponse = me_res
            .json()
            .await
            .context("decode /agent/me response")?;
        return Ok(me);
    }
    if status.as_u16() != 404 {
        anyhow::bail!("API rejected key (HTTP {})", status.as_u16());
    }

    // /agent/me missing — backend predates the endpoint. Probe an endpoint
    // that does exist and authenticates the key.
    let probe = client
        .get(format!("{base}/agent/vault/search"))
        .query(&[("q", ".")])
        .bearer_auth(api_key)
        .timeout(timeout)
        .send()
        .await
        .context("network error contacting Rivault API (fallback)")?;
    if !probe.status().is_success() {
        anyhow::bail!("API rejected key (HTTP {})", probe.status().as_u16());
    }
    Ok(MeResponse {
        user_id: String::new(),
        api_key_id: None,
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeResponse {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "apiKeyId")]
    pub api_key_id: Option<String>,
}
