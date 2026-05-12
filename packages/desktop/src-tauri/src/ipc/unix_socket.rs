//! Unix domain socket server. Channel 1: local MCP server → daemon.
//!
//! Wire format (per connection): one JSON object per line.
//! ```json
//! { "signature": "<hex hmac-sha256 of payload bytes>", "payload": <ReleaseEvent> }
//! ```
//! Server replies one JSON object: `{ "release_id": "..." }` on accept,
//! `{ "error": "..." }` on reject. Connection then closes.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use super::auth::verify;
use super::IpcContext;
use crate::daemon::release::ReleaseEvent;
use crate::ledger::Channel;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    signature: String,
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Reply {
    Ok { release_id: String },
    Err { error: String },
}

pub fn socket_path() -> PathBuf {
    dirs::runtime_dir()
        .or_else(|| std::env::var_os("TMPDIR").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir)
        .join("rivault-daemon.sock")
}

pub async fn serve(ctx: IpcContext) -> Result<()> {
    let path = socket_path();
    if path.exists() {
        std::fs::remove_file(&path).ok();
    }
    let listener = UnixListener::bind(&path)?;
    tracing::info!("unix socket listening on {}", path.display());

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("accept: {e}");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, ctx).await {
                tracing::warn!("unix socket handler: {e:#}");
            }
        });
    }
}

async fn handle(stream: tokio::net::UnixStream, ctx: IpcContext) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }
    let reply = match handle_line(line.trim(), &ctx) {
        Ok(release_id) => Reply::Ok { release_id },
        Err(e) => Reply::Err {
            error: format!("{e:#}"),
        },
    };
    let bytes = serde_json::to_vec(&reply)?;
    write_half.write_all(&bytes).await?;
    write_half.write_all(b"\n").await?;
    Ok(())
}

fn handle_line(line: &str, ctx: &IpcContext) -> Result<String> {
    let env: Envelope = serde_json::from_str(line)?;
    let payload_bytes = serde_json::to_vec(&env.payload)?;
    if !verify(ctx.secret.as_slice(), &payload_bytes, &env.signature) {
        anyhow::bail!("hmac mismatch");
    }
    let event: ReleaseEvent = serde_json::from_value(env.payload)?;
    let daemon = ctx.daemon.clone();
    daemon.accept(event, Channel::Ipc)
}
