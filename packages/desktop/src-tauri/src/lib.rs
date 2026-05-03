pub mod config;
pub mod daemon;
pub mod ipc;
pub mod keychain;
pub mod ledger;
pub mod scrubber;
pub mod triggers;

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

            // Localhost HTTP — bind synchronously to capture the port, then
            // serve() spawns the axum server onto the runtime internally.
            let ipc_http = ipc.clone();
            let http_port: Option<u16> = tauri::async_runtime::block_on(async move {
                match ipc::localhost_http::serve(ipc_http).await {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::error!("localhost http bind: {e:#}");
                        None
                    }
                }
            });

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
            clear_config
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
