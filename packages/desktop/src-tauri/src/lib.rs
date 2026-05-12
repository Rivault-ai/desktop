pub mod config;
pub mod daemon;
pub mod ipc;
pub mod keychain;
pub mod ledger;
pub mod mcp;
pub mod pairing;
pub mod proxy;
pub mod release_stream;
pub mod scrubber;
pub mod setup;
pub mod triggers;
pub mod upstream;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;
use tauri_plugin_opener::OpenerExt;
use tokio::sync::oneshot;

/// Where "View Vault" opens. Same canonical URL as the web app.
const VAULT_URL: &str = "https://www.rivault.ai/dashboard";

use crate::daemon::Daemon;
use crate::ipc::IpcContext;
use crate::ledger::{Ledger, LedgerEntry};

/// Set when the daemon auto-imported a key from OpenClaw at startup.
/// Read-once: `get_config_status` clears it after returning true once.
static OPENCLAW_IMPORT_TOAST: AtomicBool = AtomicBool::new(false);

pub struct AppState {
    pub daemon: Arc<Daemon>,
    pub ipc: IpcContext,
    pub http_port: Option<u16>,
    /// Per-runtime nonces gating the MCP endpoint. Setup commands embed
    /// the matching nonce in each runtime's MCP URL; the daemon rejects
    /// any inbound request without a valid nonce. See
    /// `mcp::runtime_nonce` for the derivation.
    pub nonces: Arc<crate::mcp::RuntimeNonceMap>,
    /// Holds the cancel handle while a passkey pairing flow is active.
    /// `Some(_)` = pairing in progress; `None` = idle.
    pub pairing_cancel: StdMutex<Option<oneshot::Sender<()>>>,
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
    /// `true` the first time the UI asks after a successful startup
    /// auto-import from OpenClaw; cleared on read.
    pub imported_from_openclaw: bool,
}

#[tauri::command]
async fn get_config_status() -> Result<ConfigStatus, String> {
    let cfg = config::load().map_err(|e| e.to_string())?;
    let imported = OPENCLAW_IMPORT_TOAST.swap(false, Ordering::Relaxed);
    match cfg {
        Some(c) => Ok(ConfigStatus {
            configured: true,
            user_id: c.user_id,
            api_key_masked: Some(mask_key(&c.api_key)),
            base_url: Some(c.base_url),
            imported_from_openclaw: imported,
        }),
        None => Ok(ConfigStatus {
            configured: false,
            user_id: None,
            api_key_masked: None,
            base_url: None,
            imported_from_openclaw: false,
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
async fn save_config(
    app: AppHandle,
    api_key: String,
    base_url: Option<String>,
) -> Result<ConfigStatus, String> {
    let base = base_url.unwrap_or_else(|| "https://api.rivault.ai".to_string());
    let me = config::validate(&api_key, &base)
        .await
        .map_err(|e| e.to_string())?;
    let cfg = config::Config {
        api_key: api_key.clone(),
        base_url: base.clone(),
        user_id: if me.user_id.is_empty() { None } else { Some(me.user_id.clone()) },
        api_key_id: me.api_key_id.clone(),
    };
    config::save(&cfg).map_err(|e| e.to_string())?;
    enable_autostart_silent(&app);
    Ok(ConfigStatus {
        configured: true,
        user_id: cfg.user_id,
        api_key_masked: Some(mask_key(&api_key)),
        base_url: Some(base),
        imported_from_openclaw: false,
    })
}

#[tauri::command]
async fn clear_config() -> Result<(), String> {
    config::clear().map_err(|e| e.to_string())
}

/// Begin a passkey-based pairing flow. Opens the user's browser to the
/// Rivault web app's `/desktop-pair` page; the page mints a fresh API
/// key and POSTs it to a one-shot listener on `127.0.0.1:<random>`.
///
/// Blocks until: the browser delivers a valid key, the user cancels via
/// `cancel_pairing`, or a 5-minute timeout fires.
#[tauri::command]
async fn start_pairing(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    base_url: Option<String>,
) -> Result<ConfigStatus, String> {
    let base = base_url.unwrap_or_else(|| "https://api.rivault.ai".to_string());

    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    {
        let mut guard = state.pairing_cancel.lock().unwrap();
        if guard.is_some() {
            return Err("pairing already in progress".to_string());
        }
        *guard = Some(cancel_tx);
    }

    let handle = pairing::start(cancel_rx).await.map_err(|e| e.to_string());
    let result = match handle {
        Ok(h) => match h.wait().await {
            Ok(api_key) => match config::validate(&api_key, &base).await {
                Ok(me) => {
                    let cfg = config::Config {
                        api_key: api_key.clone(),
                        base_url: base.clone(),
                        user_id: if me.user_id.is_empty() { None } else { Some(me.user_id.clone()) },
                        api_key_id: me.api_key_id.clone(),
                    };
                    match config::save(&cfg) {
                        Ok(()) => {
                            enable_autostart_silent(&app);
                            Ok(ConfigStatus {
                                configured: true,
                                user_id: cfg.user_id,
                                api_key_masked: Some(mask_key(&api_key)),
                                base_url: Some(base),
                                imported_from_openclaw: false,
                            })
                        }
                        Err(e) => Err(format!("save config: {e}")),
                    }
                }
                Err(e) => Err(format!("validate received key: {e}")),
            },
            Err(e) => Err(e.to_string()),
        },
        Err(e) => Err(e),
    };

    state.pairing_cancel.lock().unwrap().take();
    result
}

#[tauri::command]
fn cancel_pairing(state: tauri::State<'_, AppState>) -> Result<(), String> {
    if let Some(tx) = state.pairing_cancel.lock().unwrap().take() {
        let _ = tx.send(());
    }
    Ok(())
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
    let nonces = &state.nonces;
    let res = match runtime.as_str() {
        "claude_code" => setup::claude_code::install(port, nonces),
        "claude_desktop" => setup::claude_desktop::install(port, nonces),
        "codex" => setup::codex::install(port, nonces),
        "openclaw" => setup::openclaw::install(port, nonces),
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

// ----- window + tray helpers ------------------------------------------------

/// Reveal the main window, raise it to the foreground, and switch the app to
/// the regular activation policy so the Dock icon appears.
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    }
}

/// Hide the main window and switch to Accessory policy — Dock icon goes away,
/// the daemon stays alive, only the menu bar icon remains visible.
fn hide_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
    }
}

/// Enable Login Item registration via tauri-plugin-autostart. Best-effort —
/// we never surface the result to the UI; if macOS rejects the call (e.g.
/// the user disabled it earlier and the plugin's TCC bit is gone), we just
/// log and move on.
fn enable_autostart_silent(app: &AppHandle) {
    let manager = app.autolaunch();
    match manager.is_enabled() {
        Ok(true) => {}
        Ok(false) => {
            if let Err(e) = manager.enable() {
                tracing::warn!("autostart enable failed: {e}");
            } else {
                tracing::info!("autostart enabled");
            }
        }
        Err(e) => tracing::warn!("autostart probe failed: {e}"),
    }
}

/// Tauri command invoked by the tray's "Quit Rivault" item. Bypasses the
/// `RunEvent::ExitRequested` interceptor by calling `app.exit(0)` directly.
#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

/// Tauri command for the tray's "Open Rivault" — show + focus the window.
#[tauri::command]
fn show_window(app: AppHandle) {
    show_main_window(&app);
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

    // Detect "launched at login" mode so we know whether to show the window
    // up front. The autostart plugin appends `--silent` to the LaunchAgent
    // ProgramArguments, so its presence tells us "user didn't click to open."
    let launched_silently =
        std::env::args().any(|a| a == "--silent");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // Second-instance attempt → foreground the running window.
            show_main_window(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--silent"]),
        ))
        .setup(move |app| {
            let secret = keychain::load_or_create_secret()?;
            let nonces = Arc::new(crate::mcp::RuntimeNonceMap::from_secret(&secret));
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

            // Spin up the cross-runtime transcript scanner now that we have an
            // `AppHandle`. The scanner uses the handle to emit a
            // `rivault://scanner-failure` Tauri event on persistent scrub
            // failures so the UI can surface them as a banner.
            daemon.start_cross_runtime_scanner(Some(app.handle().clone()));

            // Auto-import: if there is no Rivault config but OpenClaw already
            // has a working API key, save it now so the user skips Setup.
            // Best-effort: any failure logs and falls through.
            if config::load().ok().flatten().is_none() {
                if let Some(api_key) = pairing::openclaw_import::detect_api_key() {
                    let base = "https://api.rivault.ai".to_string();
                    match tauri::async_runtime::block_on(config::validate(&api_key, &base)) {
                        Ok(me) => {
                            let cfg = config::Config {
                                api_key,
                                base_url: base,
                                user_id: if me.user_id.is_empty() { None } else { Some(me.user_id) },
                                api_key_id: me.api_key_id,
                            };
                            match config::save(&cfg) {
                                Ok(()) => {
                                    tracing::info!("openclaw auto-import: configured");
                                    OPENCLAW_IMPORT_TOAST.store(true, Ordering::Relaxed);
                                }
                                Err(e) => tracing::warn!(
                                    "openclaw auto-import save failed: {e:#}"
                                ),
                            }
                        }
                        Err(e) => tracing::warn!("openclaw auto-import rejected: {e:#}"),
                    }
                }
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
                                // Per-runtime nonce authentication: every
                                // inbound request is matched against this
                                // table by middleware, which stashes the
                                // resolved AgentRuntime in the request
                                // extensions before the handler runs.
                                Arc::clone(&nonces),
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
                crate::setup::auto_install(port, &nonces);
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
                nonces: Arc::clone(&nonces),
                pairing_cancel: StdMutex::new(None),
            });

            // ----- menu bar tray --------------------------------------------
            let handle = app.handle().clone();
            let open_item = MenuItem::with_id(app, "open", "Open Rivault", true, None::<&str>)?;
            let vault_item =
                MenuItem::with_id(app, "vault", "View Vault", true, None::<&str>)?;
            let signout_item =
                MenuItem::with_id(app, "signout", "Sign Out", true, None::<&str>)?;
            let quit_item =
                MenuItem::with_id(app, "quit", "Quit Rivault", true, None::<&str>)?;
            let sep1 = PredefinedMenuItem::separator(app)?;
            let sep2 = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(
                app,
                &[
                    &open_item,
                    &vault_item,
                    &sep1,
                    &signout_item,
                    &sep2,
                    &quit_item,
                ],
            )?;

            // Embed the menu-bar template image at compile time so we don't
            // depend on Tauri's bundle resource directory layout.
            const MENUBAR_ICON_PNG: &[u8] =
                include_bytes!("../icons/menubar-Template@2x.png");
            let tray_icon = tauri::image::Image::from_bytes(MENUBAR_ICON_PNG)?;
            let _tray = TrayIconBuilder::with_id("rivault-tray")
                .icon(tray_icon)
                .icon_as_template(true)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "open" => show_main_window(app),
                    "vault" => {
                        if let Err(e) = app.opener().open_url(VAULT_URL, None::<&str>) {
                            tracing::warn!("open vault failed: {e:#}");
                        }
                    }
                    "signout" => {
                        if let Err(e) = config::clear() {
                            tracing::warn!("signout clear failed: {e:#}");
                        }
                        show_main_window(app);
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            // ----- window close = hide, not quit ----------------------------
            if let Some(win) = app.get_webview_window("main") {
                let close_handle = handle.clone();
                win.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        hide_main_window(&close_handle);
                    }
                });
            }

            // ----- autostart + initial visibility ---------------------------
            // Enable Login Item once we have a config. (No config = no point
            // launching at login; only the Setup screen would appear.)
            if config::load().ok().flatten().is_some() {
                enable_autostart_silent(&handle);
            }

            // If we were launched by the LaunchAgent at login, start hidden
            // and headless. The user can pop the window via the tray icon.
            if launched_silently {
                hide_main_window(&handle);
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_releases,
            daemon_status,
            get_config_status,
            save_config,
            clear_config,
            start_pairing,
            cancel_pairing,
            quit_app,
            show_window,
            mcp_install_status,
            mcp_install,
            mcp_uninstall
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        // Intercept Cmd+Q and the Dock context-menu Quit so they only hide
        // the window. The tray's "Quit Rivault" calls `app.exit(0)` which
        // skips this handler.
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                    hide_main_window(app);
                }
            }
        });
}
