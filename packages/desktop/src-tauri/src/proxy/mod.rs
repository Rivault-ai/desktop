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
//! ledger-insert before relaying.
//!
//! L2 path is also handled transparently. When a `POST /agent/auth-request`
//! or `/agent/hybrid-request` arrives without `agentEphemeralPublicKey`,
//! the proxy mints an ephemeral keypair (using the upstream `KeypairStore`),
//! injects the public SPKI into the request body, forwards upstream, and
//! stashes the private key under the upstream-issued request id. On the
//! matching `/status` poll, if an envelope is present, the proxy decrypts
//! locally, rewrites the response to put plaintext in `value` /
//! `formValues` / `authorizedValues`, and inserts a ledger row. Same
//! redaction guarantees as the local MCP path — the OpenClaw plugin
//! gets L2 plaintext back exactly as `pollAuth` / `pollHybrid` expect,
//! and the daemon owns the entire crypto lifecycle.
//!
//! Callers that already supply their own pubkey are passed through
//! unchanged and decrypt themselves (the curl-flavoured manual mode).
//!
//! Auth: pass-through. The agent already owns the API key — we just
//! forward `Authorization: Bearer …` headers verbatim. The proxy never
//! reads the daemon's own configured API key.

use anyhow::Result;
use axum::body::{to_bytes, Body};
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use axum::Router;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::daemon::release::{AgentRuntime, ReleaseEvent, Tier};
use crate::daemon::Daemon;
use crate::ledger::Channel;
use crate::mcp::transcript::resolve_transcript_paths;
use crate::upstream::envelope::{decrypt_with, Envelope, Keypair};
use crate::upstream::keypair_store::KeypairStore;

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
    /// Stores ephemeral private keys minted on L2 create-request paths,
    /// keyed by the upstream-issued request id. `take()` is now
    /// non-destructive: retries of `rivault_poll_hybrid` after a timeout
    /// still decrypt successfully.
    keypairs: KeypairStore,
    /// `(hybrid_request_id, value_hash)` pairs that have already been
    /// logged to the ledger. Multiple polls of the same hybrid (because
    /// `take()` is non-destructive) decrypt the same envelopes again
    /// and again — without this guard we'd log duplicate release rows
    /// on every retry. The set is in-memory (cleared on daemon restart);
    /// after a restart, the worst case is one duplicate row per
    /// hybrid-item, far less noisy than the 6-row burst that motivated
    /// this dedup.
    logged_releases: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
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
            keypairs: KeypairStore::new(),
            logged_releases: Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
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
        // L1 retrieval — plaintext lands in the response body.
        .route("/agent/vault/:item_id", get(forward_l1_retrieve))
        // L2 auth flow: daemon mints keypair on create, decrypts on poll.
        .route("/agent/auth-request", post(forward_request_auth))
        .route(
            "/agent/auth-request/:auth_request_id/status",
            get(forward_auth_status),
        )
        // L2 hybrid flow: same shape, but the status response carries
        // multiple envelopes (formEnvelopes + authorizedItems).
        .route("/agent/hybrid-request", post(forward_request_hybrid))
        .route(
            "/agent/hybrid-request/:hybrid_request_id/status",
            get(forward_hybrid_status),
        )
        // Public token-based status endpoints used by the OpenClaw
        // skill plugin's detached background poller. These hit the
        // public (unauthenticated) Rivault API to check whether the
        // user has approved an auth/hybrid/login/form request without
        // consuming Redis values. Pure passthrough — no plaintext
        // crosses these endpoints, just status strings.
        //
        // ORDER MATTERS: these MUST be registered BEFORE the
        // `/agent/*rest` wildcard. With axum 0.7's matchit-based router,
        // a wildcard route registered earlier in the chain blocks
        // sibling-segment matchers that follow. Without this ordering
        // the routes silently 404 even though `strings <binary>` shows
        // them present.
        .route("/auth-request/:token", get(forward_passthrough))
        .route("/hybrid-request/:token", get(forward_passthrough))
        .route("/form-request/:token", get(forward_passthrough))
        .route("/login-request/:token", get(forward_passthrough))
        // Catch-all for everything else under /agent/* (form-request,
        // login-request, anything new the backend ships). MUST come
        // LAST among the proxy's routes — see the comment block above.
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
            // RFC 7230 §4.4 spells the response header `Trailer`
            // (singular). Stripping it matters when the proxy
            // rewrites the body — the upstream-declared trailers
            // won't be present after our rewrite, and a client that
            // honours `Trailer` would hang waiting. The plural
            // `trailers` is also accepted because it can appear as a
            // value of `TE` in HTTP/1.1; keeping both names in the
            // match keeps the strip defensive.
            | "trailer"
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
        let name = k.as_str();
        if is_hop_by_hop(name) {
            continue;
        }
        // Strip Content-Length and Content-Encoding from the upstream
        // response. We've decrypted envelopes / rewritten JSON in place
        // so the upstream-declared byte count no longer matches what
        // we're about to send. Without this strip, an upstream that
        // returned 82 bytes (envelope JSON) followed by our 80-byte
        // decrypted rewrite causes the client to wait for 2 extra
        // bytes that never arrive — which is exactly what made every
        // `rivault_poll_hybrid` time out at 15s. Axum/hyper will set a
        // fresh Content-Length on the way out based on what we
        // actually send.
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("content-encoding")
        {
            continue;
        }
        builder = builder.header(name, v.as_bytes());
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

// NOTE: NOT `deny_unknown_fields`. The backend defines this response and may
// add fields the daemon doesn't yet understand (e.g. `label`, `category`);
// silently ignoring them keeps decode forward-compatible.
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
    let value_hash = hex::encode(Sha256::digest(plaintext.as_bytes()));
    // Dedup: a single hybrid request can be polled multiple times (the
    // skill plugin retries on timeout, and the keypair store is now
    // non-destructive). Each poll re-runs `transform_hybrid_status`
    // and would otherwise log a fresh release row for every envelope
    // every time. Track `(scope, value_hash)` pairs so we only log
    // the first successful decrypt per item, not the Nth.
    let dedup_key = format!("{item_id_or_session}|{value_hash}");
    {
        let mut seen = state.logged_releases.lock().unwrap();
        if !seen.insert(dedup_key) {
            return Ok(()); // already logged — skip the duplicate
        }
    }
    let release_id = uuid::Uuid::new_v4().to_string();
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

/// Record an L2-envelope-delivery observation on paths the proxy
/// can't decrypt (e.g. login-request before that flow's L2-decrypt
/// handler is wired). The dedicated `forward_auth_status` /
/// `forward_hybrid_status` handlers below DO decrypt and ledger-log.
fn log_l2_observation(_state: &ProxyState) {
    tracing::info!(
        "proxy observed L2 envelope delivery on a path without bespoke \
         decryption — install local MCP for deterministic L2 redaction"
    );
}

// ---- L2: auth-request ----------------------------------------------------

/// `POST /agent/auth-request` — mint an ephemeral keypair if the caller
/// didn't supply one, inject the public SPKI into the request body, and
/// stash the private key under the upstream-issued `authRequestId`.
async fn forward_request_auth(
    State(s): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    forward_l2_create(&s, &method, &uri, &headers, body, "authRequestId").await
}

/// `GET /agent/auth-request/:id/status` — forward, then if the response
/// carries an envelope and we minted a keypair earlier, decrypt locally
/// and rewrite the body so the agent gets `value` (matching the skill's
/// `pollAuth` typing). Inserts a ledger row on the rewritten plaintext.
async fn forward_auth_status(
    State(s): State<Arc<ProxyState>>,
    AxumPath(auth_request_id): AxumPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let url = build_upstream_url(&s.backend, uri.path(), uri.query());
    let res = match relay(&s.http, &method, &url, &headers, body).await {
        Ok(r) => r,
        Err(e) => return upstream_error(e),
    };
    let status = res.status();
    let response_headers = res.headers().clone();
    let bytes = match res.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => return upstream_error(anyhow::anyhow!("read body: {e}")),
    };

    let final_bytes = if status.is_success() && bytes.len() <= MAX_INSPECT_BYTES {
        match transform_auth_status(&s, &auth_request_id, &bytes) {
            Some(rewritten) => rewritten,
            None => bytes,
        }
    } else {
        bytes
    };

    build_axum_response(
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        response_headers,
        final_bytes,
    )
}

// ---- L2: hybrid-request --------------------------------------------------

async fn forward_request_hybrid(
    State(s): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    forward_l2_create(&s, &method, &uri, &headers, body, "hybridRequestId").await
}

async fn forward_hybrid_status(
    State(s): State<Arc<ProxyState>>,
    AxumPath(hybrid_request_id): AxumPath<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let url = build_upstream_url(&s.backend, uri.path(), uri.query());
    let res = match relay(&s.http, &method, &url, &headers, body).await {
        Ok(r) => r,
        Err(e) => return upstream_error(e),
    };
    let status = res.status();
    let response_headers = res.headers().clone();
    let bytes = match res.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => return upstream_error(anyhow::anyhow!("read body: {e}")),
    };

    let final_bytes = if status.is_success() && bytes.len() <= MAX_INSPECT_BYTES {
        match transform_hybrid_status(&s, &hybrid_request_id, &bytes) {
            Some(rewritten) => rewritten,
            None => bytes,
        }
    } else {
        bytes
    };

    build_axum_response(
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        response_headers,
        final_bytes,
    )
}

// ---- shared L2 helpers ---------------------------------------------------

/// Common path for L2 create requests. Reads the body, injects a
/// daemon-minted `agentEphemeralPublicKey` if absent, forwards upstream,
/// and on success stashes the keypair under the response's `id_field`
/// (`authRequestId` / `hybridRequestId`).
async fn forward_l2_create(
    s: &Arc<ProxyState>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Body,
    id_field: &str,
) -> axum::response::Response {
    let body_bytes = to_bytes(body, MAX_INSPECT_BYTES * 2)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();

    // Parse JSON, mint+inject if needed.
    let (final_body, our_keypair) = match maybe_inject_pubkey(&body_bytes) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!("proxy L2 create: body inject failed: {e:#}; forwarding as-is");
            (body_bytes, None)
        }
    };

    let url = build_upstream_url(&s.backend, uri.path(), uri.query());
    let res = match relay_bytes(&s.http, method, &url, headers, final_body).await {
        Ok(r) => r,
        Err(e) => return upstream_error(e),
    };
    let status = res.status();
    let response_headers = res.headers().clone();
    let response_bytes = match res.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => return upstream_error(anyhow::anyhow!("read body: {e}")),
    };

    // Stash keypair under upstream-issued request id, only on success.
    if status.is_success() {
        if let Some(kp) = our_keypair {
            if let Some(request_id) = extract_string_field(&response_bytes, id_field) {
                s.keypairs.store(&request_id, kp);
            } else {
                tracing::warn!(
                    "proxy L2 create: upstream response missing `{id_field}`; \
                     keypair dropped (status will fail to decrypt)"
                );
            }
        }
    }

    build_axum_response(
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        response_headers,
        response_bytes,
    )
}

/// Inspect the request body. If `agentEphemeralPublicKey` is missing,
/// mint a fresh keypair, inject the SPKI base64, and return the rewritten
/// body bytes plus the keypair (so the caller can stash it once the
/// upstream returns the request id).
fn maybe_inject_pubkey(body_bytes: &[u8]) -> Result<(Vec<u8>, Option<Keypair>)> {
    if body_bytes.is_empty() {
        return Ok((body_bytes.to_vec(), None));
    }
    let mut v: Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => return Ok((body_bytes.to_vec(), None)), // leave non-JSON alone
    };
    if v.get("agentEphemeralPublicKey")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        // Caller already supplied their own pubkey; pass through and let
        // them decrypt locally. We don't even buffer their keypair.
        return Ok((body_bytes.to_vec(), None));
    }
    let kp = Keypair::generate()?;
    let pub_b64 = kp.public_spki_b64();
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "agentEphemeralPublicKey".to_string(),
            Value::String(pub_b64),
        );
    }
    Ok((serde_json::to_vec(&v)?, Some(kp)))
}

/// Look up the value of a top-level string field in a JSON body. Used
/// to extract the upstream-issued `authRequestId` / `hybridRequestId`.
fn extract_string_field(bytes: &[u8], field: &str) -> Option<String> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    v.get(field)?.as_str().map(|s| s.to_string())
}

/// Decrypt the auth-status response and rewrite to put plaintext on
/// `value`. Returns None if the response isn't approved-with-envelope
/// or we don't have a stored keypair (caller supplied their own).
fn transform_auth_status(s: &ProxyState, auth_request_id: &str, body: &[u8]) -> Option<Vec<u8>> {
    let mut v: Value = serde_json::from_slice(body).ok()?;
    if v.get("status")?.as_str()? != "approved" {
        return None;
    }
    let envelope_value = v.get("envelope").cloned()?;
    let envelope: Envelope = serde_json::from_value(envelope_value).ok()?;
    let kp = s.keypairs.take(auth_request_id)?;
    let plaintext_bytes = decrypt_with(kp.secret(), &envelope).ok()?;
    drop(kp);
    let plaintext = String::from_utf8_lossy(&plaintext_bytes).into_owned();

    if let Err(e) = log_release(s, Tier::L2, &plaintext, auth_request_id) {
        tracing::warn!(
            auth_request_id = %auth_request_id,
            "proxy auth_status: ledger insert failed: {e:#}"
        );
    }

    if let Some(obj) = v.as_object_mut() {
        obj.remove("envelope");
        obj.insert("value".to_string(), Value::String(plaintext));
    }
    serde_json::to_vec(&v).ok()
}

/// Decrypt every envelope in a hybrid-status response and rewrite to
/// the shape the OpenClaw skill's `pollHybrid` expects:
/// `{ status, formValues, authorizedValues, createdItemIds }`.
fn transform_hybrid_status(s: &ProxyState, hybrid_request_id: &str, body: &[u8]) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_slice(body).ok()?;
    if v.get("status")?.as_str()? != "submitted" {
        return None;
    }
    let kp = s.keypairs.take(hybrid_request_id)?;
    let secret = kp.secret();

    let mut form_values = serde_json::Map::new();
    if let Some(form_envelopes) = v.get("formEnvelopes").and_then(|f| f.as_object()) {
        for (key, env_value) in form_envelopes {
            if let Ok(env) = serde_json::from_value::<Envelope>(env_value.clone()) {
                if let Ok(pt) = decrypt_with(secret, &env) {
                    let plaintext = String::from_utf8_lossy(&pt).into_owned();
                    if let Err(e) = log_release(s, Tier::L2, &plaintext, hybrid_request_id) {
                        tracing::warn!(
                            hybrid_request_id = %hybrid_request_id,
                            field = %key,
                            "proxy hybrid_status: ledger insert (form) failed: {e:#}"
                        );
                    }
                    form_values.insert(key.clone(), Value::String(plaintext));
                }
            }
        }
    }

    let mut authorized_values = serde_json::Map::new();
    if let Some(authorized) = v.get("authorizedItems").and_then(|a| a.as_object()) {
        for (item_id, entry) in authorized {
            let env_value = match entry.get("envelope") {
                Some(e) => e.clone(),
                None => continue,
            };
            let Ok(env) = serde_json::from_value::<Envelope>(env_value) else {
                continue;
            };
            if let Ok(pt) = decrypt_with(secret, &env) {
                let plaintext = String::from_utf8_lossy(&pt).into_owned();
                if let Err(e) = log_release(s, Tier::L2, &plaintext, hybrid_request_id) {
                    tracing::warn!(
                        hybrid_request_id = %hybrid_request_id,
                        item_id = %item_id,
                        "proxy hybrid_status: ledger insert (auth) failed: {e:#}"
                    );
                }
                authorized_values.insert(item_id.clone(), Value::String(plaintext));
            }
        }
    }
    drop(kp);

    let created_item_ids = v
        .get("createdItemIds")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));

    let rewritten = json!({
        "status": "submitted",
        "formValues": form_values,
        "authorizedValues": authorized_values,
        "createdItemIds": created_item_ids,
    });
    serde_json::to_vec(&rewritten).ok()
}

/// Like `relay`, but the body is already buffered into bytes (we
/// modified it for L2 pubkey injection).
async fn relay_bytes(
    http: &Client,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    body_bytes: Vec<u8>,
) -> Result<reqwest::Response> {
    let upstream_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);
    let mut rb = http.request(upstream_method, url);
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("host") {
            continue;
        }
        // Drop the Content-Length too — we may have changed the body
        // size by injecting `agentEphemeralPublicKey`. reqwest sets a
        // fresh one based on the buffer we hand it.
        if name.eq_ignore_ascii_case("content-length") {
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

    #[test]
    fn hop_by_hop_filter_excludes_trailer_and_te() {
        // Both names must be stripped: the proxy rewrites bodies
        // (envelope → plaintext), so any upstream-declared `Trailer:`
        // won't be present in the rewritten response and a strict
        // client would hang waiting for it. Same shape of bug as the
        // Content-Length mismatch that caused the v0.2.5 poll-timeout.
        assert!(is_hop_by_hop("Trailer"));
        assert!(is_hop_by_hop("trailer"));
        assert!(is_hop_by_hop("Trailers"));
        assert!(is_hop_by_hop("TE"));
        assert!(is_hop_by_hop("te"));
    }

    #[test]
    fn build_axum_response_strips_trailer_and_te() {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("trailer"),
            HeaderValue::from_static("X-Custom-Hash"),
        );
        headers.insert(
            HeaderName::from_static("te"),
            HeaderValue::from_static("trailers"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let resp = build_axum_response(StatusCode::OK, headers, b"{}".to_vec());
        let out = resp.headers();
        assert!(!out.contains_key("trailer"), "Trailer must be stripped");
        assert!(!out.contains_key("te"), "TE must be stripped");
        assert_eq!(
            out.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "non-hop-by-hop headers must survive"
        );
    }

    #[test]
    fn maybe_inject_pubkey_adds_when_absent() {
        let body = br#"{"itemId":"abc","reason":"test"}"#;
        let (out, kp) = maybe_inject_pubkey(body).unwrap();
        assert!(kp.is_some(), "should mint a keypair when absent");
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let pk = parsed["agentEphemeralPublicKey"].as_str().unwrap();
        assert!(pk.len() > 80, "pubkey base64 should be sizeable");
        assert_eq!(parsed["itemId"], "abc");
        assert_eq!(parsed["reason"], "test");
    }

    #[test]
    fn maybe_inject_pubkey_passes_through_when_present() {
        let body =
            br#"{"itemId":"abc","reason":"test","agentEphemeralPublicKey":"USER_SPKI"}"#;
        let (out, kp) = maybe_inject_pubkey(body).unwrap();
        assert!(kp.is_none(), "caller-supplied pubkey -> no mint");
        // Body byte-equal to input (no rewrite).
        assert_eq!(out, body);
    }

    #[test]
    fn maybe_inject_pubkey_passes_through_on_garbage() {
        let body = b"not json";
        let (out, kp) = maybe_inject_pubkey(body).unwrap();
        assert!(kp.is_none());
        assert_eq!(out, body);
    }

    #[test]
    fn extract_string_field_pulls_request_id() {
        let body = br#"{"authRequestId":"areq_xyz","authUrl":"u","expiresAt":"x"}"#;
        assert_eq!(
            extract_string_field(body, "authRequestId").as_deref(),
            Some("areq_xyz")
        );
        assert_eq!(extract_string_field(body, "missing"), None);
    }

    #[tokio::test]
    async fn transform_auth_status_decrypts_and_rewrites() {
        use crate::upstream::envelope::Keypair;
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        // Set up a state with a known stored keypair.
        let daemon = Arc::new(crate::daemon::Daemon::new(
            crate::ledger::Ledger::open_in_memory().unwrap(),
        ));
        let state = ProxyState::with_backend(
            daemon,
            AgentRuntime::Openclaw,
            "https://example.invalid",
        )
        .unwrap();
        let kp = Keypair::generate().unwrap();
        let pub_b64 = kp.public_spki_b64();
        state.keypairs.store("areq_xyz", kp);

        // Build an envelope addressed to that keypair (mirror the
        // backend's encryption flow inline).
        use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng, Payload};
        use aes_gcm::Aes256Gcm;
        use hkdf::Hkdf;
        use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
        use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
        use rand::rngs::OsRng;
        use sha2::Sha256;

        let der = B64.decode(pub_b64.as_bytes()).unwrap();
        let daemon_pub = PublicKey::from_public_key_der(&der).unwrap();
        let peer = SecretKey::random(&mut OsRng);
        let peer_pub_der = peer.public_key().to_public_key_der().unwrap().into_vec();
        let shared = diffie_hellman(peer.to_nonzero_scalar(), daemon_pub.as_affine());
        let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"rivault-envelope-v1", &mut key).unwrap();
        let cipher = Aes256Gcm::new(&key.into());
        let iv = Aes256Gcm::generate_nonce(&mut AeadOsRng);
        let ct = cipher
            .encrypt(
                &iv,
                Payload {
                    msg: b"hunter2",
                    aad: &[],
                },
            )
            .unwrap();

        let body = serde_json::json!({
            "status": "approved",
            "type": "general",
            "envelope": {
                "mobileEphemeralPublicKey": B64.encode(&peer_pub_der),
                "iv": B64.encode(&iv),
                "ciphertext": B64.encode(&ct),
            }
        })
        .to_string();

        let rewritten =
            transform_auth_status(&state, "areq_xyz", body.as_bytes()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(parsed["status"], "approved");
        assert_eq!(parsed["value"], "hunter2");
        assert!(
            parsed.get("envelope").is_none(),
            "envelope must be replaced"
        );
        // Keypair stays in the store after take(): a poll retry after
        // a timeout still needs to be able to decrypt. The same envelope
        // bytes will decrypt to the same plaintext, so this is safe.
        let rewritten2 =
            transform_auth_status(&state, "areq_xyz", body.as_bytes()).unwrap();
        let parsed2: serde_json::Value =
            serde_json::from_slice(&rewritten2).unwrap();
        assert_eq!(parsed2["value"], "hunter2");
    }

    #[test]
    fn transform_auth_status_skips_pending() {
        let daemon = Arc::new(crate::daemon::Daemon::new(
            crate::ledger::Ledger::open_in_memory().unwrap(),
        ));
        let state = ProxyState::with_backend(
            daemon,
            AgentRuntime::Openclaw,
            "https://example.invalid",
        )
        .unwrap();
        let body = br#"{"status":"pending"}"#;
        assert!(transform_auth_status(&state, "any", body).is_none());
    }
}
