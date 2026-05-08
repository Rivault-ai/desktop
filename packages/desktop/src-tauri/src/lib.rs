pub mod config;
pub mod daemon;
pub mod ipc;
pub mod keychain;
pub mod ledger;
pub mod mcp;
pub mod proxy;
pub mod release_stream;
pub mod scrubber;
pub mod setup;
pub mod triggers;
pub mod upstream;

use std::sync::Arc;

use serde::Serialize;
use tauri::Manager;

use crate::daemon::Daemon;
use crate::ipc::IpcContext;
use crate::ledger::{Ledger, LedgerEntry};

pub struct AppState {
    pub daemon: Arc<Daemon>,
    pub ipc: IpcContext,
    pub http_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DaemonStatus {
    pub socket_path: String,
    pub http_port: Option<u16>,
    pub browser_token_prefix: String,
    pub websocket_configured: bool,
}

#[tauri::command]
async fn list_releases(
    state: tauri::State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<LedgerEntry>, String> {
    state
        .daemon
        .ledger()
        .list_recent(limit.unwrap_or(50))
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn daemon_status(state: tauri::State<'_, AppState>) -> Result<DaemonStatus, String> {
    Ok(DaemonStatus {
        socket_path: ipc::unix_socket::socket_path().display().to_string(),
        http_port: state.http_port,
        browser_token_prefix: state.ipc.browser_token.chars().take(8).collect(),
        websocket_configured: std::env::var_os("RIVAULT_DAEMON_WS_URL").is_some(),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigStatus {
    pub configured: bool,
    pub user_id: Option<String>,
    pub api_key_masked: Option<String>,
    pub base_url: Option<String>,
}

#[tauri::command]
async fn get_config_status() -> Result<ConfigStatus, String> {
    let cfg = config::load().map_err(|e| e.to_string())?;
    match cfg {
        Some(c) => Ok(ConfigStatus {
            configured: true,
            user_id: c.user_id,
            api_key_masked: Some(mask_key(&c.api_key)),
            base_url: Some(c.base_url),
        }),
        None => Ok(ConfigStatus {
            configured: false,
            user_id: None,
            api_key_masked: None,
            base_url: None,
        }),
    }
}

fn mask_key(k: &str) -> String {
    if k.len() <= 12 {
        return "•".repeat(k.len());
    }
    let head: String = k.chars().take(8).collect();
    let tail: String = k.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("{}…{}", head, tail)
}

#[tauri::command]
async fn save_config(api_key: String, base_url: Option<String>) -> Result<ConfigStatus, String> {
    let base = base_url.unwrap_or_else(|| "https://api.rivault.ai".to_string());
    let me = config::validate(&api_key, &base)
        .await
        .map_err(|e| e.to_string())?;
    let cfg = config::Config {
        api_key: api_key.clone(),
        base_url: base.clone(),
        user_id: Some(me.user_id.clone()),
        api_key_id: me.api_key_id.clone(),
    };
    config::save(&cfg).map_err(|e| e.to_string())?;
    Ok(ConfigStatus {
        configured: true,
        user_id: cfg.user_id,
        api_key_masked: Some(mask_key(&api_key)),
        base_url: Some(base),
    })
}

#[tauri::command]
async fn clear_config() -> Result<(), String> {
    config::clear().map_err(|e| e.to_string())
}

#[tauri::command]
async fn mcp_install_status() -> Result<setup::McpInstallStatus, String> {
    Ok(setup::probe_status())
}

/// Install the local-MCP entry for the named runtime. The `runtime`
/// string is one of `"claude_code" | "claude_desktop" | "codex" | "openclaw"`.
#[tauri::command]
async fn mcp_install(state: tauri::State<'_, AppState>, runtime: String) -> Result<(), String> {
    let port = state
        .http_port
        .ok_or_else(|| "daemon HTTP port not bound".to_string())?;
    let res = match runtime.as_str() {
        "claude_code" => setup::claude_code::install(port),
        "claude_desktop" => setup::claude_desktop::install(port),
        "codex" => setup::codex::install(port),
        "openclaw" => setup::openclaw::install(port),
        other => return Err(format!("unknown runtime: {other}")),
    };
    res.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
async fn mcp_uninstall(runtime: String) -> Result<(), String> {
    let res = match runtime.as_str() {
        "claude_code" => setup::claude_code::uninstall(),
        "claude_desktop" => setup::claude_desktop::uninstall(),
        "codex" => setup::codex::uninstall(),
        "openclaw" => setup::openclaw::uninstall(),
        other => return Err(format!("unknown runtime: {other}")),
    };
    res.map_err(|e| format!("{e:#}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "rivault_desktop=info,desktop_lib=info,info",
                )
            }),
        )
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let secret = keychain::load_or_create_secret()?;
            let ledger = Ledger::open()?;
            let daemon = Arc::new(Daemon::new(ledger));
            let browser_token = keychain::one_time_token();

            let ipc = IpcContext {
                daemon: Arc::clone(&daemon),
                secret: Arc::new(secret),
                browser_token: Arc::new(browser_token),
            };

            // Recover orphaned releases from a prior run.
            if let Err(e) = daemon.recover_unscrubbed() {
                tracing::warn!("recover_unscrubbed: {e:#}");
            }

            // Unix socket listener (background loop).
            let ipc_unix = ipc.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = ipc::unix_socket::serve(ipc_unix).await {
                    tracing::error!("unix socket exited: {e:#}");
                }
            });

            // If config is present, spin up the local MCP server so it
            // mounts on the same listener as /release and /stop. This
            // keeps the desktop daemon a single-process app — the agent
            // talks to one address for everything.
            //
            // No config = no API key = no upstream calls possible, so
            // we skip the MCP mount; once the user signs in, the next
            // app launch will bring it up. Live re-mount-without-restart
            // is a future improvement (gate at tool-call time on a
            // current-config snapshot).
            let (mcp_router, proxy_router): (Option<axum::Router>, Option<axum::Router>) =
                match config::load() {
                    Ok(Some(cfg)) => {
                        let mcp = match crate::upstream::UpstreamClient::new(
                            cfg.base_url.clone(),
                            cfg.api_key.clone(),
                        ) {
                            Ok(client) => Some(crate::mcp::router(
                                Arc::clone(&daemon),
                                client,
                                // Runtime is per-MCP-entry — Setup will
                                // register separate /mcp paths per agent
                                // later. For now, OpenClaw is the
                                // safest default; other runtimes get
                                // added explicitly via Setup UX.
                                crate::daemon::release::AgentRuntime::Openclaw,
                            )),
                            Err(e) => {
                                tracing::warn!("upstream client init failed: {e:#}");
                                None
                            }
                        };
                        // Tier-B proxy lives alongside /mcp; it forwards
                        // /agent/* with the agent's own Bearer header so
                        // it doesn't depend on the daemon's configured
                        // key matching the agent's.
                        let proxy = match crate::proxy::ProxyState::with_backend(
                            Arc::clone(&daemon),
                            crate::daemon::release::AgentRuntime::Openclaw,
                            &cfg.base_url,
                        ) {
                            Ok(state) => Some(crate::proxy::router(state)),
                            Err(e) => {
                                tracing::warn!("proxy init failed: {e:#}");
                                None
                            }
                        };
                        (mcp, proxy)
                    }
                    Ok(None) => {
                        tracing::info!("no config — skipping MCP/proxy mount until sign-in");
                        (None, None)
                    }
                    Err(e) => {
                        tracing::warn!("config load failed: {e:#}");
                        (None, None)
                    }
                };
            // Merge MCP + proxy into one router for the localhost listener.
            let extra_router: Option<axum::Router> = match (mcp_router, proxy_router) {
                (Some(m), Some(p)) => Some(m.merge(p)),
                (Some(m), None) => Some(m),
                (None, Some(p)) => Some(p),
                (None, None) => None,
            };

            // Localhost HTTP — bind synchronously to capture the port, then
            // serve() spawns the axum server onto the runtime internally.
            let ipc_http = ipc.clone();
            let http_port: Option<u16> = tauri::async_runtime::block_on(async move {
                match ipc::localhost_http::serve(ipc_http, extra_router).await {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::error!("localhost http bind: {e:#}");
                        None
                    }
                }
            });

            // Auto-point every supported runtime that's installed on
            // this machine at the daemon. Idempotent: skips when the
            // user has a deliberate non-localhost value, no-ops when
            // already correct, only writes on a real change.
            if let Some(port) = http_port {
                crate::setup::auto_install(port);
            }

            // Tier-C: subscribe to the backend's per-API-key release
            // stream so the daemon learns about cloud-MCP retrievals
            // it didn't proxy itself. Spawn only when config is loaded.
            if let Ok(Some(cfg)) = config::load() {
                crate::release_stream::spawn(
                    Arc::clone(&daemon),
                    cfg.base_url.clone(),
                    cfg.api_key.clone(),
                    crate::daemon::release::AgentRuntime::Openclaw,
                );
            }

            // WebSocket client — only runs if RIVAULT_DAEMON_WS_URL is set.
            ipc::websocket::spawn_if_configured(ipc.clone());

            // Persist discovery file so local clients (skill, browser) can find us.
            let socket_path_str = ipc::unix_socket::socket_path().display().to_string();
            if let Err(e) = ipc::discovery::write(http_port, &socket_path_str, ipc.secret.as_slice())
            {
                tracing::warn!("discovery file write failed: {e:#}");
            }

            app.manage(AppState {
                daemon: Arc::clone(&daemon),
                ipc,
                http_port,
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_releases,
            daemon_status,
            get_config_status,
            save_config,
            clear_config,
            mcp_install_status,
            mcp_install,
            mcp_uninstall
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
