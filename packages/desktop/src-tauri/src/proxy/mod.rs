//! Tier-B fallback: transparent reverse proxy for `api.rivault.ai/agent/*`.
//!
//! For users who haven't (or can't) wire the local MCP server, setting
//! `RIVAULT_API_URL=http://127.0.0.1:<port>` makes every `curl` (and the
//! OpenClaw plugin's `RivaultClient`) talk to the daemon instead. The
//! daemon proxies the request upstream, peeks the response on the way
//! back, and inserts a ledger row whenever plaintext crosses through —
//! same observable event the local MCP path produces.
//!
//! L1 detection is exact: `GET /agent/vault/{id}` with an L1 item
//! returns `{value, label}` in the response body, so we can hash and
//! ledger-insert before relaying. L2 envelope endpoints
//! (`/agent/auth-request/*/status`, `/hybrid-request/*/status`,
//! `/login-request/*/status`) return ciphertext only — the daemon can
//! see "an L2 envelope was returned" but cannot decrypt without owning
//! the agent's ephemeral keypair, which lives client-side in the
//! curl-flavored flow today. For deterministic L2 redaction the user
//! must use local MCP. The proxy still records L2 metadata so the UI
//! can surface "L2 retrieved (not redactable from this path)".
//!
//! Auth: pass-through. The agent already owns the API key — we just
//! forward `Authorization: Bearer …` headers verbatim. The proxy never
//! reads the daemon's own configured API key.

use anyhow::Result;
use axum::body::{to_bytes, Body};
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Router;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::daemon::release::{AgentRuntime, ReleaseEvent, Tier};
use crate::daemon::Daemon;
use crate::ledger::Channel;
use crate::mcp::transcript::resolve_transcript_paths;

/// Default backend the proxy forwards to. Override via the `RivaultProxy`
/// constructor for tests / staging environments.
const DEFAULT_BACKEND: &str = "https://api.rivault.ai";

/// Hard ceiling on response body size we'll buffer for ledger inspection.
/// Above this, we stream-relay without inspection (no ledger row written).
/// 4 MiB is a comfortable safety margin: typical /agent/* responses are
/// kilobytes; anything larger is almost certainly not a vault item.
const MAX_INSPECT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct ProxyState {
    daemon: Arc<Daemon>,
    /// Runtime label for releases observed by this proxy. Same convention
    /// as the local MCP server: the desktop setup flow tells us which
    /// runtime the user wired the env var for.
    runtime: AgentRuntime,
    backend: Arc<str>,
    http: Client,
}

impl ProxyState {
    pub fn new(daemon: Arc<Daemon>, runtime: AgentRuntime) -> Result<Self> {
        Self::with_backend(daemon, runtime, DEFAULT_BACKEND)
    }

    pub fn with_backend(
        daemon: Arc<Daemon>,
        runtime: AgentRuntime,
        backend: &str,
    ) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Self {
            daemon,
            runtime,
            backend: backend.into(),
            http,
        })
    }
}

/// Build the Tier-B proxy router. Returned router is intended to be
/// `merged` into the daemon's existing localhost HTTP app at the same
/// `serve()` site as the local MCP router.
pub fn router(state: ProxyState) -> Router {
    let s = Arc::new(state);
    Router::new()
        // Specific paths first so they win when the wildcard would also match.
        .route("/agent/vault/search", get(forward_passthrough))
        .route("/agent/vault/logins", get(forward_passthrough))
        // L1 retrieval — the only path where plaintext lands in the
        // response body, so the only path with bespoke ledger logic.
        .route("/agent/vault/:item_id", get(forward_l1_retrieve))
        // Catch-all for everything else under /agent/*. Includes the
        // envelope-mode L2 endpoints (auth-request, hybrid-request,
        // login-request) plus their /status counterparts.
        .route("/agent/*rest", any(forward_passthrough))
        .with_state(s)
}

/// L1 retrieval: forward, parse `{value, label}` from the response body
/// if present, and log a release row before relaying back to the agent.
async fn forward_l1_retrieve(
    State(s): State<Arc<ProxyState>>,
    AxumPath(item_id): AxumPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let path = uri.path();
    let query = uri.query();
    let url = build_upstream_url(&s.backend, path, query);

    let res = match relay(&s.http, &method, &url, &headers, body).await {
        Ok(r) => r,
        Err(e) => return upstream_error(e),
    };
    let status = res.status();
    let response_headers = res.headers().clone();
    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(e) => return upstream_error(anyhow::anyhow!("read body: {e}")),
    };

    if status.is_success() && bytes.len() <= MAX_INSPECT_BYTES {
        if let Some(plaintext) = peek_l1_value(&bytes) {
            if let Err(e) = log_release(&s, Tier::L1, &plaintext, item_id.as_str()) {
                tracing::warn!(
                    item_id = %item_id,
                    "proxy L1 release log failed (will not be scrubbed): {e:#}",
                );
            }
        }
    }

    build_axum_response(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK), response_headers, bytes.to_vec())
}

/// Pass-through for /agent/* paths that don't carry L1 plaintext. We
/// peek the body to surface L2-envelope-was-returned events for the UI,
/// but we cannot redact L2 in this path (we don't own the keypair).
async fn forward_passthrough(
    State(s): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let path = uri.path();
    let query = uri.query();
    let url = build_upstream_url(&s.backend, path, query);

    let res = match relay(&s.http, &method, &url, &headers, body).await {
        Ok(r) => r,
        Err(e) => return upstream_error(e),
    };
    let status = res.status();
    let response_headers = res.headers().clone();
    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(e) => return upstream_error(anyhow::anyhow!("read body: {e}")),
    };

    if status.is_success() && bytes.len() <= MAX_INSPECT_BYTES {
        // Surface L2 envelope deliveries so the UI can show
        // "L2 secret retrieved — install local MCP to redact".
        if peek_has_envelope(&bytes) {
            log_l2_observation(&s);
        }
    }

    build_axum_response(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK), response_headers, bytes.to_vec())
}

// ---- helpers --------------------------------------------------------------

fn build_upstream_url(backend: &str, path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{backend}{path}?{q}"),
        None => format!("{backend}{path}"),
    }
}

async fn relay(
    http: &Client,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<reqwest::Response> {
    let body_bytes = to_bytes(body, MAX_INSPECT_BYTES * 2)
        .await
        .unwrap_or_default()
        .to_vec();
    let upstream_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut rb = http.request(upstream_method, url);
    // Forward headers (including Authorization), but drop hop-by-hop ones.
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("host") {
            continue;
        }
        if let (Ok(hk), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            rb = rb.header(hk, hv);
        }
    }
    if !body_bytes.is_empty() {
        rb = rb.body(body_bytes);
    }
    let res = rb.send().await?;
    Ok(res)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn build_axum_response(
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
) -> axum::response::Response {
    let mut builder = axum::http::Response::builder().status(status);
    for (k, v) in headers.iter() {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_bytes());
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| axum::http::Response::new(Body::empty()))
}

fn upstream_error(e: anyhow::Error) -> axum::response::Response {
    (
        StatusCode::BAD_GATEWAY,
        format!("rivault proxy: upstream error: {e:#}"),
    )
        .into_response()
}

#[derive(Deserialize)]
struct L1Body {
    value: Option<String>,
}

fn peek_l1_value(bytes: &[u8]) -> Option<String> {
    let parsed: L1Body = serde_json::from_slice(bytes).ok()?;
    parsed.value.filter(|v| !v.is_empty())
}

fn peek_has_envelope(bytes: &[u8]) -> bool {
    // Cheap surface check: the JSON includes any field literally named
    // `envelope`. Matches /auth-request/{id}/status, /login-request/{id}/status,
    // and the per-item envelopes inside /hybrid-request/{id}/status.
    let Ok(s) = std::str::from_utf8(bytes) else {
        return false;
    };
    s.contains("\"envelope\"") || s.contains("\"formEnvelopes\"")
}

fn log_release(
    state: &ProxyState,
    tier: Tier,
    plaintext: &str,
    item_id_or_session: &str,
) -> Result<()> {
    let release_id = uuid::Uuid::new_v4().to_string();
    let value_hash = hex::encode(Sha256::digest(plaintext.as_bytes()));
    let transcript_paths = resolve_transcript_paths(&state.runtime);
    let released_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let event = ReleaseEvent {
        release_id,
        // Best-effort session id: the proxy can't see the agent's
        // session header, so we stamp the item id as a fallback for
        // grouping. The trigger races still work correctly with this.
        session_id: format!("proxy-{item_id_or_session}"),
        tier,
        agent_runtime: state.runtime.clone(),
        mcp_mode: None,
        value_plaintext: Some(plaintext.to_string()),
        value_hash,
        encoded_variants: Vec::new(),
        transcript_paths,
        released_at,
        rotation_supported: false,
    };

    state
        .daemon
        .clone()
        .accept(event, Channel::Localhost)
        .map(|_| ())
}

/// Record an L2-envelope-delivery observation. Today this is a no-op
/// beyond a log line — the daemon doesn't have plaintext, so there's
/// nothing it can scrub. The eventual UI will surface this as
/// "L2 retrieved via curl flow — install local MCP to redact".
fn log_l2_observation(_state: &ProxyState) {
    tracing::info!(
        "proxy observed L2 envelope delivery — no plaintext available; \
         install local MCP for deterministic L2 redaction"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_l1_value_extracts_plaintext() {
        let body = br#"{"value":"alice@example.com","label":"Email"}"#;
        assert_eq!(
            peek_l1_value(body).as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn peek_l1_value_ignores_l2_response() {
        let body = br#"{"requires_auth":true,"sensitivity_level":2,"label":"Bank password"}"#;
        assert!(peek_l1_value(body).is_none());
    }

    #[test]
    fn peek_l1_value_ignores_garbage() {
        assert!(peek_l1_value(b"not json").is_none());
        assert!(peek_l1_value(b"").is_none());
        assert!(peek_l1_value(br#"{"value":""}"#).is_none());
    }

    #[test]
    fn peek_has_envelope_matches_status_payloads() {
        let auth_status =
            br#"{"status":"approved","type":"general","envelope":{"iv":"x","ciphertext":"y","mobileEphemeralPublicKey":"z"}}"#;
        assert!(peek_has_envelope(auth_status));

        let hybrid_status =
            br#"{"status":"submitted","formEnvelopes":{"k":{}},"authorizedItems":{}}"#;
        assert!(peek_has_envelope(hybrid_status));

        let pending = br#"{"status":"pending"}"#;
        assert!(!peek_has_envelope(pending));
    }

    #[test]
    fn build_upstream_url_handles_query() {
        assert_eq!(
            build_upstream_url("https://api", "/agent/vault/search", Some("q=email")),
            "https://api/agent/vault/search?q=email"
        );
        assert_eq!(
            build_upstream_url("https://api", "/agent/vault/x", None),
            "https://api/agent/vault/x"
        );
    }

    #[test]
    fn hop_by_hop_filter_excludes_connection() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("authorization"));
        assert!(!is_hop_by_hop("content-type"));
    }
}
