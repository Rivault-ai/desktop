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
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;

use super::auth::verify;
use super::IpcContext;
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

pub async fn serve(ctx: IpcContext) -> Result<u16> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/release", post(release))
        .with_state(Arc::new(ctx));

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
