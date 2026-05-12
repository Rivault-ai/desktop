//! Per-install IPC HMAC secret storage.
//!
//! Stores a 32-byte random secret in a 0600 file under the app data directory.
//! On macOS: ~/Library/Application Support/Rivault/ipc-key
//! On Linux: ~/.local/share/Rivault/ipc-key
//!
//! The macOS Keychain approach was abandoned because kSecUseDataProtectionKeychain
//! requires entitlements only available to properly notarized/signed apps, and the
//! legacy SecKeychain API ties items to the binary's code-signature hash causing
//! password prompts on every rebuild.

use anyhow::{Context, Result};
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const KEY_LEN: usize = 32;

fn secret_path() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .context("cannot locate app data directory")?
        .join("Rivault");
    fs::create_dir_all(&dir).ok();
    Ok(dir.join("ipc-key"))
}

fn load_from_file() -> Result<Option<Vec<u8>>> {
    let p = secret_path()?;
    if !p.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read(p)?))
}

fn store_to_file(secret: &[u8]) -> Result<()> {
    let p = secret_path()?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&p)?;
    f.write_all(secret)?;
    Ok(())
}

/// Process-wide cache: the secret is immutable for a daemon's lifetime.
static SECRET: OnceLock<Vec<u8>> = OnceLock::new();

/// Load the per-install secret, or generate + persist a new one.
/// Result is cached in a process-wide OnceLock so disk is accessed at most once.
pub fn load_or_create_secret() -> Result<Vec<u8>> {
    if let Some(cached) = SECRET.get() {
        return Ok(cached.clone());
    }
    let secret = fetch_or_create()?;
    let _ = SECRET.set(secret.clone());
    Ok(secret)
}

fn fetch_or_create() -> Result<Vec<u8>> {
    if let Some(existing) = load_from_file()? {
        if existing.len() >= KEY_LEN {
            return Ok(existing);
        }
        tracing::warn!("existing IPC secret too short; regenerating");
    }
    let mut bytes = vec![0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    store_to_file(&bytes).context("persist new IPC secret")?;
    Ok(bytes)
}

/// Issue a one-time browser token (random 32 bytes hex-encoded).
pub fn one_time_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
