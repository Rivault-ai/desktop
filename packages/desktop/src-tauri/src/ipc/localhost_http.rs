//! Localhost HTTP server. Channel 2: local browser tab → daemon
//! (L2 Face ID flow on same machine).
//!
//! Bound to 127.0.0.1 only, with a fixed port range (47318..=47338) so the
//! Rivault web app can probe and discover it. The browser tab presents a
//! one-time token (issued by the desktop app) in `X-Rivault-Token`; the
//! request body is HMAC-signed in `X-Rivault-Signature`.

use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

use time::OffsetDateTime;

use super::auth::{freshness_ok, verify};
use super::IpcContext;
use crate::daemon::orchestrator::StopScope;
use crate::daemon::release::ReleaseEvent;
use crate::ledger::Channel;

const PORT_RANGE: std::ops::RangeInclusive<u16> = 47318..=47338;

#[derive(Debug, Serialize)]
struct Health {
    ok: bool,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct AcceptOk {
    release_id: String,
}

#[derive(Debug, Serialize)]
struct ErrBody {
    error: String,
}

#[derive(Debug, Deserialize)]
struct StopBody {
    #[serde(default)]
    release_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    /// ISO 8601 timestamp the caller produced this body at. Bounded
    /// against the daemon's clock by `auth::freshness_ok` (60s window)
    /// so a captured (body, signature) pair can't be replayed
    /// indefinitely.
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct StopOk {
    /// Number of open releases that were signalled to scrub immediately.
    /// Zero is a valid response — the matching releases may have already
    /// been scrubbed by the watcher or hard cap.
    fired: usize,
}

pub async fn serve(ctx: IpcContext, mcp_router: Option<Router>) -> Result<u16> {
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/release", post(release))
        .route("/stop", post(stop))
        .with_state(Arc::new(ctx));

    if let Some(mcp) = mcp_router {
        app = app.merge(mcp);
    }

    for port in PORT_RANGE {
        let addr = format!("127.0.0.1:{port}");
        if let Ok(listener) = TcpListener::bind(&addr).await {
            tracing::info!("localhost http listening on {addr}");
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!("localhost http exited: {e:#}");
                }
            });
            return Ok(port);
        }
    }
    anyhow::bail!("no localhost port in {:?} available", PORT_RANGE)
}

async fn health() -> impl IntoResponse {
    Json(Health {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn release(
    State(ctx): State<Arc<IpcContext>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Accept either:
    //   - HMAC-signed body (skill / local MCP — proof: read `daemon.json` mode 0600)
    //   - Browser one-time token (web tab issued from desktop app)
    let signature = headers
        .get("x-rivault-signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let token = headers
        .get("x-rivault-token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let hmac_ok =
        !signature.is_empty() && verify(ctx.secret.as_slice(), body.as_bytes(), signature);
    let token_ok = !token.is_empty() && token == ctx.browser_token.as_str();

    if !hmac_ok && !token_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrBody {
                error: "missing or invalid auth (need X-Rivault-Signature or X-Rivault-Token)"
                    .into(),
            }),
        )
            .into_response();
    }
    let event: ReleaseEvent = match serde_json::from_str(&body) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrBody {
                    error: format!("decode: {e}"),
                }),
            )
                .into_response();
        }
    };
    // Replay guard: ReleaseEvent already carries `released_at` (ISO
    // 8601), so we don't add a new field — we just enforce that the
    // value lands inside the 60s window. A captured HMAC payload
    // becomes inert one minute after it was first produced.
    if !freshness_ok(&event.released_at, OffsetDateTime::now_utc()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrBody {
                error: "released_at outside replay window".into(),
            }),
        )
            .into_response();
    }
    match ctx.daemon.clone().accept(event, Channel::Localhost) {
        Ok(release_id) => (StatusCode::OK, Json(AcceptOk { release_id })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrBody {
                error: format!("{e:#}"),
            }),
        )
            .into_response(),
    }
}

/// Force any matching open release(s) to scrub immediately.
///
/// Called by the local MCP server on agent disconnect, by the OpenClaw
/// plugin's exit hook, and (optionally) by Claude Code's `Stop` hook.
/// HMAC-only — the browser channel deliberately can't trigger scrubs,
/// since the only legitimate caller is the local agent runtime, which
/// already has access to `daemon.json` (mode 0600).
async fn stop(
    State(ctx): State<Arc<IpcContext>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let signature = headers
        .get("x-rivault-signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if signature.is_empty() || !verify(ctx.secret.as_slice(), body.as_bytes(), signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrBody {
                error: "missing or invalid X-Rivault-Signature".into(),
            }),
        )
            .into_response();
    }
    let req: StopBody = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrBody {
                    error: format!("decode: {e}"),
                }),
            )
                .into_response();
        }
    };
    if !freshness_ok(&req.timestamp, OffsetDateTime::now_utc()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrBody {
                error: "timestamp outside replay window".into(),
            }),
        )
            .into_response();
    }
    let scope = StopScope {
        release_id: req.release_id,
        session_id: req.session_id,
    };
    if scope.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrBody {
                error: "must provide release_id or session_id".into(),
            }),
        )
            .into_response();
    }
    let fired = ctx.daemon.trigger_stop(&scope);
    (StatusCode::OK, Json(StopOk { fired })).into_response()
}
