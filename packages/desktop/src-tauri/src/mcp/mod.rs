//! Local MCP server hosted by the desktop daemon.
//!
//! Mounted at `/mcp` on the same 127.0.0.1 listener that already serves
//! `/health`, `/release`, and `/stop`. Agents are configured (per-runtime
//! by the desktop app's setup flow) to point their MCP client at this
//! URL instead of the cloud-hosted Rivault MCP. Result: every retrieval
//! is observable by the daemon, enabling deterministic scrub.

pub mod runtime_nonce;
pub mod server;
pub mod transcript;

use std::sync::Arc;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};

pub use runtime_nonce::RuntimeNonceMap;
pub use server::RivaultMcp;

use crate::daemon::Daemon;
use crate::upstream::UpstreamClient;

/// Build an axum router that serves Rivault's MCP tool surface at `/mcp`.
///
/// One handler instance is constructed per session by the streamable-http
/// service, so the components passed in must be cheap to clone (the
/// `Daemon` holds `Arc`s; `UpstreamClient` holds `Arc<str>` + a `reqwest`
/// `Client` which is itself `Arc`-backed).
///
/// All inbound requests pass through `require_runtime_nonce`, which
/// rejects any URL without a valid `?nonce=<hex>` query param. The
/// matched `AgentRuntime` is injected as a request extension so the
/// inner handler can read it without re-parsing the URI.
///
/// The returned router is intended to be `merged` into the daemon's
/// existing localhost HTTP app — see `ipc::localhost_http::serve`.
pub fn router(
    daemon: Arc<Daemon>,
    upstream: UpstreamClient,
    nonces: Arc<RuntimeNonceMap>,
) -> Router {
    let service = StreamableHttpService::new(
        move || Ok(RivaultMcp::new(daemon.clone(), upstream.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let nonces_for_mw = Arc::clone(&nonces);
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let nonces = Arc::clone(&nonces_for_mw);
            async move { require_runtime_nonce(nonces, req, next).await }
        }))
}

/// Reject any request whose `?nonce=` query param is missing or does not
/// match a derived runtime nonce. On success, stash the matched
/// `AgentRuntime` in the request's extensions for downstream handlers.
async fn require_runtime_nonce(
    nonces: Arc<RuntimeNonceMap>,
    mut req: Request,
    next: Next,
) -> Response {
    let candidate = req.uri().query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == "nonce" {
                Some(v.to_string())
            } else {
                None
            }
        })
    });
    let Some(candidate) = candidate else {
        return (StatusCode::UNAUTHORIZED, "missing runtime nonce").into_response();
    };
    let Some(runtime) = nonces.runtime_for(&candidate) else {
        return (StatusCode::UNAUTHORIZED, "invalid runtime nonce").into_response();
    };
    req.extensions_mut().insert(runtime);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request as AxumRequest, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;

    use crate::daemon::release::AgentRuntime;

    /// Build a minimal axum router with the nonce middleware applied and
    /// a leaf handler at `/mcp` that echoes the resolved runtime so
    /// tests can assert which one was injected.
    fn test_router(nonces: Arc<RuntimeNonceMap>) -> Router {
        async fn echo(req: AxumRequest<Body>) -> String {
            match req.extensions().get::<AgentRuntime>() {
                Some(rt) => format!("{rt:?}"),
                None => "missing".to_string(),
            }
        }
        let nonces_for_mw = Arc::clone(&nonces);
        Router::new()
            .route("/mcp", get(echo))
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                let nonces = Arc::clone(&nonces_for_mw);
                async move { require_runtime_nonce(nonces, req, next).await }
            }))
    }

    fn nonces() -> Arc<RuntimeNonceMap> {
        Arc::new(RuntimeNonceMap::from_secret(&[0x42u8; 32]))
    }

    async fn send(router: Router, uri: &str) -> (StatusCode, String) {
        let resp = router
            .oneshot(
                AxumRequest::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn rejects_missing_nonce() {
        let (status, _) = send(test_router(nonces()), "/mcp").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_blank_nonce() {
        let (status, _) = send(test_router(nonces()), "/mcp?nonce=").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_unknown_nonce() {
        let (status, _) = send(
            test_router(nonces()),
            "/mcp?nonce=00000000000000000000000000000000",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_runtime_query_param_without_nonce() {
        // The pre-fix URL shape — `?runtime=claude_code` — must no
        // longer authenticate. This is the actual attack surface the
        // nonce gate closes.
        let (status, _) = send(test_router(nonces()), "/mcp?runtime=claude_code").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accepts_valid_nonce_and_injects_runtime() {
        let n = nonces();
        let codex = n.nonce_for("codex").unwrap().to_string();
        let (status, body) =
            send(test_router(Arc::clone(&n)), &format!("/mcp?nonce={codex}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "Codex");
    }

    #[tokio::test]
    async fn each_runtime_resolves_to_its_own_nonce() {
        let n = nonces();
        for (label, expected) in [
            ("claude_code", "ClaudeCode"),
            ("claude_desktop", "ClaudeDesktop"),
            ("codex", "Codex"),
            ("openclaw", "Openclaw"),
        ] {
            let nonce = n.nonce_for(label).unwrap().to_string();
            let (status, body) =
                send(test_router(Arc::clone(&n)), &format!("/mcp?nonce={nonce}")).await;
            assert_eq!(status, StatusCode::OK, "{label}");
            assert_eq!(body, expected, "{label}");
        }
    }

    #[tokio::test]
    async fn nonce_from_a_different_install_is_rejected() {
        // Simulates an attacker who learned the nonce from another
        // machine and tries to replay it against this daemon.
        let local = nonces();
        let foreign = Arc::new(RuntimeNonceMap::from_secret(&[0x99u8; 32]));
        let foreign_nonce = foreign.nonce_for("codex").unwrap().to_string();
        let (status, _) = send(
            test_router(local),
            &format!("/mcp?nonce={foreign_nonce}"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
