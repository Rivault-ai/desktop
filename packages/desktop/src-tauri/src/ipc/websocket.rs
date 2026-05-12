//! WebSocket client. Channel 3: Rivault server → daemon.
//!
//! Auth: the daemon registers with the API server using the user's Rivault
//! session token + a per-daemon registration ID; the API issues a daemon
//! token used to open the WebSocket. Inbound messages are then HMAC-signed
//! using the same per-install IPC key, so a compromised server alone cannot
//! inject forged release events.
//!
//! V0: connection management + reconnect-with-backoff is wired up; the
//! server-side endpoint (`packages/api/src/routes/daemon.ts`) is a follow-up,
//! so this stays inert unless `RIVAULT_DAEMON_WS_URL` is set in the env.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::auth::verify;
use super::IpcContext;
use crate::daemon::release::ReleaseEvent;
use crate::ledger::Channel;

pub fn spawn_if_configured(ctx: IpcContext) {
    let Ok(url) = std::env::var("RIVAULT_DAEMON_WS_URL") else {
        tracing::info!("RIVAULT_DAEMON_WS_URL unset; websocket channel disabled");
        return;
    };
    tokio::spawn(run(ctx, url));
}

async fn run(ctx: IpcContext, url: String) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_async(&url).await {
            Ok((mut stream, _)) => {
                tracing::info!("websocket connected to {url}");
                backoff = Duration::from_secs(1);
                while let Some(msg) = stream.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            if let Err(e) = handle_text(&text, &ctx) {
                                tracing::warn!("ws message rejected: {e:#}");
                            }
                        }
                        Ok(Message::Ping(p)) => {
                            let _ = stream.send(Message::Pong(p)).await;
                        }
                        Ok(Message::Close(_)) | Err(_) => break,
                        _ => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!("ws connect failed: {e}");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    signature: String,
    payload: serde_json::Value,
}

fn handle_text(text: &str, ctx: &IpcContext) -> Result<()> {
    let env: Envelope = serde_json::from_str(text)?;
    let payload_bytes = serde_json::to_vec(&env.payload)?;
    if !verify(ctx.secret.as_slice(), &payload_bytes, &env.signature) {
        anyhow::bail!("hmac mismatch");
    }
    let event: ReleaseEvent = serde_json::from_value(env.payload)?;
    ctx.daemon.clone().accept(event, Channel::Websocket)?;
    Ok(())
}
