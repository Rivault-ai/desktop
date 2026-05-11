//! Per-install IPC HMAC secret storage.
//!
//! On macOS uses the system Keychain (`com.rivault.daemon.ipc-key`, scoped to
//! the current user). On other platforms falls back to a 0600 file in the app
//! data directory — sufficient for development; production targets macOS.

use anyhow::{Context, Result};
use rand::RngCore;

const SERVICE: &str = "com.rivault.daemon.ipc-key";
const ACCOUNT: &str = "default";
const KEY_LEN: usize = 32;

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
        PasswordOptions,
    };

    /// Build a PasswordOptions query that targets the Data Protection Keychain
    /// (kSecUseDataProtectionKeychain = true, available macOS 10.15+).
    ///
    /// The Data Protection Keychain does NOT use binary-hash ACLs. Any process
    /// running as the same user can read the item after the first login unlock —
    /// no password prompt on every launch, and no prompt after binary updates.
    /// This is the same keychain used by iOS/macOS app-extension sharing and
    /// SwiftUI apps.
    fn opts() -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        o.use_protected_keychain();
        o
    }

    pub fn load() -> Result<Option<Vec<u8>>> {
        match generic_password(opts()) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.code() == -25300 => Ok(None), // errSecItemNotFound
            Err(e) => Err(anyhow::anyhow!("keychain read: {e}")),
        }
    }

    pub fn store(secret: &[u8]) -> Result<()> {
        // Try update first (item already exists), then add.
        match set_generic_password_options(secret, opts()) {
            Ok(()) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("keychain write: {e}")),
        }
    }

    #[allow(dead_code)]
    pub fn purge() -> Result<()> {
        match delete_generic_password_options(opts()) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()),
            Err(e) => Err(anyhow::anyhow!("keychain delete: {e}")),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;
    use std::fs;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    fn path() -> Result<PathBuf> {
        let dir = dirs::data_dir()
            .context("no data dir")?
            .join("Rivault");
        fs::create_dir_all(&dir).ok();
        Ok(dir.join("ipc-key"))
    }

    pub fn load() -> Result<Option<Vec<u8>>> {
        let p = path()?;
        if !p.exists() {
            return Ok(None);
        }
        Ok(Some(fs::read(p)?))
    }

    pub fn store(secret: &[u8]) -> Result<()> {
        let p = path()?;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(&p)?;
        f.write_all(secret)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn purge() -> Result<()> {
        let p = path()?;
        if p.exists() {
            std::fs::remove_file(p)?;
        }
        Ok(())
    }
}

/// Load the per-install secret, or generate + persist a new one.
pub fn load_or_create_secret() -> Result<Vec<u8>> {
    if let Some(existing) = platform::load()? {
        if existing.len() >= KEY_LEN {
            return Ok(existing);
        }
        tracing::warn!("existing IPC secret too short; regenerating");
    }
    let mut bytes = vec![0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    platform::store(&bytes).context("persist new IPC secret")?;
    Ok(bytes)
}

/// Issue a one-time browser token (random 32 bytes hex-encoded).
pub fn one_time_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
