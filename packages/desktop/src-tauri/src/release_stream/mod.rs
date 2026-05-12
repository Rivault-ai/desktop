//! Tier-C subscriber: long-poll the backend's per-API-key release stream
//! so the daemon learns about retrievals it didn't proxy itself.
//!
//! Use case: a user is on Claude Code's cloud-hosted MCP
//! (`mcp__claude_ai_Rivault__*`) and hasn't installed the local MCP
//! server. The cloud MCP path doesn't touch the daemon, but the
//! backend can — it sees every L1 plaintext as it's decrypted server-side.
//! By subscribing to `GET /agent/release-stream` (SSE), the daemon
//! receives the plaintext out-of-band and can scrub local transcripts
//! deterministically.
//!
//! Coverage: L1 only. L2 envelope decryption happens client-side; the
//! backend never sees the agent-decrypted plaintext, so L2 events
//! arrive metadata-only and the daemon surfaces them as
//! "L2 retrieved (install local MCP for redaction)" telemetry.

use anyhow::Result;
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::daemon::release::{AgentRuntime, ReleaseEvent, Tier};
use crate::daemon::Daemon;
use crate::ledger::Channel;
use crate::mcp::transcript::resolve_transcript_paths;

const MIN_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(120);

// NOTE: NOT `deny_unknown_fields`. The backend defines the SSE schema and may
// add fields before the daemon catches up; tolerating extras keeps an
// older daemon binary functional across backend deploys.
#[derive(Debug, Deserialize)]
struct StreamEvent {
    #[serde(rename = "itemId")]
    item_id: Option<String>,
    #[serde(rename = "valueHash", default)]
    _value_hash: Option<String>,
    plaintext: Option<String>,
    tier: String,
    #[serde(rename = "releasedAt")]
    released_at: String,
    #[allow(dead_code)]
    source: Option<String>,
}

/// Spawn the SSE subscriber as a background task.
///
/// Runs forever — reconnects on every disconnect with exponential
/// backoff so transient backend hiccups don't drop coverage. The task
/// only exits when the daemon process exits (no graceful cancellation
/// path today; daemon shutdown is process-level, so the OS reclaims).
///
/// Uses `tauri::async_runtime::spawn` instead of bare `tokio::spawn`
/// because this is invoked from Tauri's `setup` closure on the main
/// thread, where there's no thread-local tokio runtime context. Tauri's
/// async-runtime wrapper carries an explicit handle to the runtime it
/// owns, so it works from anywhere.
pub fn spawn(daemon: Arc<Daemon>, base_url: String, api_key: String, runtime: AgentRuntime) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = MIN_BACKOFF;
        loop {
            match run_once(&daemon, &base_url, &api_key, &runtime).await {
                Ok(()) => {
                    // run_once returned cleanly — server closed the stream.
                    // Reconnect with the minimum backoff (no error happened).
                    backoff = MIN_BACKOFF;
                }
                Err(e) => {
                    tracing::warn!(
                        "release-stream disconnected: {e:#}; retrying in {:?}",
                        backoff
                    );
                }
            }
            sleep(backoff).await;
            // Exponential backoff capped at MAX_BACKOFF.
            backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
        }
    });
}

async fn run_once(
    daemon: &Arc<Daemon>,
    base_url: &str,
    api_key: &str,
    runtime: &AgentRuntime,
) -> Result<()> {
    let url = format!("{base_url}/agent/release-stream");
    let client = reqwest::Client::builder()
        // No overall timeout — SSE is a long-lived connection. Read
        // timeout is enforced by the client's underlying TCP keepalive
        // and the server's heartbeat comments.
        .build()?;
    let res = client
        .get(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Accept", "text/event-stream")
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!("subscribe failed: HTTP {}", res.status());
    }

    let mut stream = eventsource_stream::EventStream::new(res.bytes_stream());
    while let Some(event) = stream.next().await {
        let event = event?;
        if event.event != "release" {
            // Ignore comments (heartbeats), unknown events.
            continue;
        }
        let parsed: StreamEvent = match serde_json::from_str(&event.data) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("malformed release-stream event: {e:#}");
                continue;
            }
        };
        if let Err(e) = handle_event(daemon, runtime, parsed).await {
            tracing::warn!("release-stream handle_event: {e:#}");
        }
    }
    Ok(())
}

async fn handle_event(
    daemon: &Arc<Daemon>,
    runtime: &AgentRuntime,
    event: StreamEvent,
) -> Result<()> {
    let tier = match event.tier.as_str() {
        "l1" => Tier::L1,
        "l2" => Tier::L2,
        other => {
            tracing::debug!("release-stream: unknown tier `{other}`; skipping");
            return Ok(());
        }
    };

    // L2 events from this stream are metadata-only — backend never sees
    // the agent-decrypted plaintext. There's nothing to scrub; the
    // event is recorded for UI telemetry only. Today we just log.
    let Some(plaintext) = event.plaintext else {
        if matches!(tier, Tier::L2) {
            tracing::info!(
                "release-stream: L2 retrieval observed (no plaintext available; \
                 install local MCP for L2 redaction)"
            );
        }
        return Ok(());
    };

    let release_id = uuid::Uuid::new_v4().to_string();
    let value_hash = hex::encode(Sha256::digest(plaintext.as_bytes()));
    let transcript_paths = resolve_transcript_paths(runtime);

    let release = ReleaseEvent {
        release_id,
        // Stream events don't carry an MCP session id (they're per
        // API-key, not per-session). Stamp a synthetic session so the
        // ledger can group by item id; the trigger races still fire
        // correctly with this.
        session_id: format!(
            "stream-{}",
            event.item_id.as_deref().unwrap_or("unknown")
        ),
        tier,
        agent_runtime: runtime.clone(),
        mcp_mode: None,
        value_plaintext: Some(plaintext),
        value_hash,
        encoded_variants: Vec::new(),
        transcript_paths,
        released_at: event.released_at,
        rotation_supported: false,
    };

    daemon
        .clone()
        .accept(release, Channel::Localhost)
        .map(|_| ())
}
