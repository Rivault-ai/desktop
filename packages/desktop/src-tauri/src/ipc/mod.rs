//! IPC surface: three authenticated channels feed release events into the
//! daemon.
//!
//! - `unix_socket`: local MCP server → daemon (Claude Code MCP, custom local MCP)
//! - `localhost_http`: local browser tab → daemon (L2 Face ID flow on same machine)
//! - `websocket`: Rivault server → daemon (OpenClaw bash+curl, Codex CLI,
//!   Claude Desktop / claude.ai web server-transient-plaintext path)
//!
//! All inbound messages are HMAC-signed with a per-install secret stored in
//! macOS Keychain (`com.rivault.daemon.ipc-key`).

pub mod auth;
pub mod discovery;
pub mod localhost_http;
pub mod unix_socket;
pub mod websocket;

use crate::daemon::Daemon;
use std::sync::Arc;

#[derive(Clone)]
pub struct IpcContext {
    pub daemon: Arc<Daemon>,
    pub secret: Arc<Vec<u8>>,
    /// Localhost HTTP one-time browser token, rotated on app launch.
    pub browser_token: Arc<String>,
}
