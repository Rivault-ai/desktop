//! Browser-handoff API key pairing.
//!
//! Passkeys are origin-bound, so the Tauri WebView (origin `tauri://localhost`)
//! cannot use a passkey registered for `app.rivault.ai`. To pair without
//! manual copy-paste we open the user's real browser to a "desktop pair"
//! page; the page logs the user in with their passkey, mints a fresh API
//! key, and POSTs it back to a one-shot HTTP listener on loopback here.
//!
//! Security:
//! - listener binds 127.0.0.1 only
//! - random ephemeral port
//! - 32-byte nonce in the URL, constant-time compared in the callback
//! - server shuts down on first valid delivery, 5-minute timeout, or
//!   explicit cancel from the UI

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use rand::RngCore;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

pub mod openclaw_export;
pub mod openclaw_import;

const PAIRING_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PAIRING_PAGE_DEFAULT: &str = "https://www.rivault.ai/desktop-pair";

/// Override target for the browser handoff. Used to point at a Vercel
/// preview deploy or a local `pnpm dev` while the production page is
/// still in review.
const PAIRING_PAGE_ENV: &str = "RIVAULT_PAIR_URL";

fn pairing_page() -> String {
    std::env::var(PAIRING_PAGE_ENV).unwrap_or_else(|_| PAIRING_PAGE_DEFAULT.to_string())
}

/// In-flight pairing session. Shared between two delivery paths:
/// (a) the localhost POST handler the browser usually hits, (b) the
/// `rivault://pair?...` deep-link handler that bypasses extensions
/// blocking the loopback fetch. Either path can complete the same
/// `oneshot::Sender<String>` — first valid arrival wins.
#[derive(Clone)]
pub struct PairingState {
    pub nonce: Arc<[u8; 32]>,
    pub tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
}

#[derive(Deserialize)]
struct CallbackBody {
    nonce: String,
    #[serde(rename = "apiKey")]
    api_key: String,
}

fn cors_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type"),
    );
    h
}

async fn preflight() -> Response {
    (StatusCode::NO_CONTENT, cors_headers()).into_response()
}

async fn callback(State(state): State<PairingState>, body: String) -> Response {
    // Parse JSON manually so a malformed body still returns CORS headers
    // (Json extractor errors render without CORS, which trips the browser).
    let parsed: Result<CallbackBody, _> = serde_json::from_str(&body);
    let body = match parsed {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, cors_headers(), "bad body").into_response(),
    };

    let received = match hex::decode(body.nonce.trim()) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::UNAUTHORIZED, cors_headers(), "bad nonce").into_response(),
    };
    if state.nonce.ct_eq(received.as_slice()).unwrap_u8() != 1 {
        return (StatusCode::UNAUTHORIZED, cors_headers(), "nonce mismatch").into_response();
    }
    let api_key = body.api_key.trim().to_string();
    if api_key.is_empty() {
        return (StatusCode::BAD_REQUEST, cors_headers(), "missing apiKey").into_response();
    }

    let mut guard = state.tx.lock().await;
    if let Some(tx) = guard.take() {
        let _ = tx.send(api_key);
    }
    (StatusCode::OK, cors_headers(), "paired").into_response()
}

/// Deliver an API key into the active pairing session via a `rivault://`
/// deep-link URL. Used when a browser extension (uBlock, AdBlock, Brave
/// shields, …) blocks the page's POST to 127.0.0.1, so the page falls
/// through to `window.location = "rivault://pair?nonce=...&apiKey=..."`
/// instead.
///
/// Returns:
///   - `Ok(true)` when the URL matched the active session and the key was
///     handed off.
///   - `Ok(false)` when there's no in-flight session, the URL scheme is
///     wrong, or the nonce doesn't match — caller can ignore.
///   - `Err(_)` for malformed input.
pub async fn deliver_via_url(
    shared_state: &Arc<Mutex<Option<PairingState>>>,
    url: &url::Url,
) -> Result<bool> {
    if url.scheme() != "rivault" {
        return Ok(false);
    }
    // Accept either `rivault://pair?...` or `rivault:pair?...` shapes.
    let host = url.host_str().unwrap_or("");
    let path = url.path().trim_start_matches('/');
    let is_pair = host == "pair" || path == "pair" || url.as_str().starts_with("rivault:pair");
    if !is_pair {
        return Ok(false);
    }
    let mut nonce_hex: Option<String> = None;
    let mut api_key: Option<String> = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "nonce" => nonce_hex = Some(v.into_owned()),
            "apiKey" | "api_key" | "key" => api_key = Some(v.into_owned()),
            _ => {}
        }
    }
    let Some(nonce_hex) = nonce_hex else { return Ok(false) };
    let Some(api_key) = api_key.filter(|s| !s.is_empty()) else { return Ok(false) };

    let received = match hex::decode(nonce_hex.trim()) {
        Ok(b) if b.len() == 32 => b,
        _ => return Ok(false),
    };

    let mut guard = shared_state.lock().await;
    let Some(state) = guard.as_ref() else {
        // No in-flight pairing — the user clicked an old link or hit the
        // URL directly. Not an error; nothing to do.
        return Ok(false);
    };
    if state.nonce.ct_eq(received.as_slice()).unwrap_u8() != 1 {
        return Ok(false);
    }
    let mut tx_guard = state.tx.lock().await;
    if let Some(tx) = tx_guard.take() {
        let _ = tx.send(api_key);
        // Drop the state slot so the loopback handler doesn't try to
        // deliver again into a now-empty channel.
        drop(tx_guard);
        *guard = None;
        return Ok(true);
    }
    Ok(false)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let bin = "open";
    #[cfg(target_os = "linux")]
    let bin = "xdg-open";
    #[cfg(target_os = "windows")]
    let bin = "explorer";
    std::process::Command::new(bin)
        .arg(url)
        .spawn()
        .with_context(|| format!("spawn `{bin}` for {url}"))?;
    Ok(())
}

pub struct PairingHandle {
    rx: oneshot::Receiver<String>,
}

impl PairingHandle {
    /// Wait for the browser to deliver the API key, or for the listener to
    /// shut down (cancel or timeout).
    pub async fn wait(self) -> Result<String> {
        match self.rx.await {
            Ok(key) => Ok(key),
            Err(_) => anyhow::bail!("pairing cancelled or timed out"),
        }
    }
}

/// Begin a pairing session: bind the listener, open the browser, return a
/// handle whose `wait()` resolves to the received API key.
///
/// `cancel_rx`: fires from the UI's "Cancel" button; the listener shuts down
/// without delivering, causing `wait()` to return an error.
pub async fn start(
    cancel_rx: oneshot::Receiver<()>,
    shared_state: Arc<Mutex<Option<PairingState>>>,
) -> Result<PairingHandle> {
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind loopback listener")?;
    let port = listener.local_addr()?.port();

    let (deliver_tx, deliver_rx) = oneshot::channel::<String>();
    let state = PairingState {
        nonce: Arc::new(nonce_bytes),
        tx: Arc::new(Mutex::new(Some(deliver_tx))),
    };
    // Publish the state so the deep-link handler in lib.rs can find it
    // for `rivault://pair?...` deliveries that bypass the loopback fetch.
    *shared_state.lock().await = Some(state.clone());

    let app = Router::new()
        .route("/", post(callback).options(preflight))
        .with_state(state);

    let shared_for_shutdown = Arc::clone(&shared_state);
    let shutdown = async move {
        tokio::select! {
            _ = cancel_rx => tracing::info!("pairing cancelled by UI"),
            _ = tokio::time::sleep(PAIRING_TIMEOUT) => tracing::info!("pairing timed out"),
        }
        // Clear the shared slot so a late deep-link delivery doesn't try to
        // complete a sender that's already been dropped.
        *shared_for_shutdown.lock().await = None;
    };

    let base = pairing_page();
    let url = format!("{base}?cb=http://127.0.0.1:{port}/&nonce={nonce_hex}");
    open_browser(&url).context("open browser")?;
    tracing::info!("pairing listener on 127.0.0.1:{port}, browser opened");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
        {
            tracing::warn!("pairing server exited with error: {e}");
        }
    });

    Ok(PairingHandle { rx: deliver_rx })
}

