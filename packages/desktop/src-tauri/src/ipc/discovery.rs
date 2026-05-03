//! Discovery file: clients (skill, MCP server, browser) read this to
//! locate the daemon and authenticate.
//!
//! Path: `<data dir>/Rivault/daemon.json` (mode 0600 on Unix). On macOS this
//! resolves to `~/Library/Application Support/Rivault/daemon.json`.
//!
//! Re-written on every daemon start so a stale file from a previous install
//! never surfaces a wrong port or a key that no longer matches the keychain.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct DiscoveryFile<'a> {
    pub schema_version: u32,
    pub http_port: Option<u16>,
    pub socket_path: String,
    pub hmac_key_hex: &'a str,
}

pub fn path() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .context("no data dir")?
        .join("Rivault");
    fs::create_dir_all(&dir).ok();
    Ok(dir.join("daemon.json"))
}

pub fn write(http_port: Option<u16>, socket_path: &str, hmac_key: &[u8]) -> Result<()> {
    let p = path()?;
    let body = DiscoveryFile {
        schema_version: 1,
        http_port,
        socket_path: socket_path.to_string(),
        hmac_key_hex: &hex::encode(hmac_key),
    };
    let json = serde_json::to_vec_pretty(&body)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&p)?;
    f.write_all(&json)?;
    Ok(())
}
