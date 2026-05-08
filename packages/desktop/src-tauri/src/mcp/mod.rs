//! Local MCP server hosted by the desktop daemon.
//!
//! Mounted at `/mcp` on the same 127.0.0.1 listener that already serves
//! `/health`, `/release`, and `/stop`. Agents are configured (per-runtime
//! by the desktop app's setup flow) to point their MCP client at this
//! URL instead of the cloud-hosted Rivault MCP. Result: every retrieval
//! is observable by the daemon, enabling deterministic scrub.

pub mod server;
pub mod transcript;

use std::sync::Arc;

use axum::Router;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};

pub use server::RivaultMcp;

use crate::daemon::release::AgentRuntime;
use crate::daemon::Daemon;
use crate::upstream::UpstreamClient;

/// Build an axum router that serves Rivault's MCP tool surface at `/mcp`.
///
/// One handler instance is constructed per session by the streamable-http
/// service, so the components passed in must be cheap to clone (the
/// `Daemon` holds `Arc`s; `UpstreamClient` holds `Arc<str>` + a `reqwest`
/// `Client` which is itself `Arc`-backed).
///
/// The returned router is intended to be `merged` into the daemon's
/// existing localhost HTTP app — see `ipc::localhost_http::serve`.
pub fn router(
    daemon: Arc<Daemon>,
    upstream: UpstreamClient,
    runtime: AgentRuntime,
) -> Router {
    let service = StreamableHttpService::new(
        move || Ok(RivaultMcp::new(daemon.clone(), upstream.clone(), runtime.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    Router::new().nest_service("/mcp", service)
}
