//! Tauri shell for ClamAV Control.
//!
//! Boot sequence:
//! 1. Spawn the legacy Node-based helper on `proxy_port` (loopback only).
//!    It will continue to serve any /api/* route not yet ported to Rust.
//! 2. Start the in-process **axum** HTTP server on the public `port`.
//!    Axum serves native handlers for ported routes, proxies the rest to
//!    the Node helper, and serves the React static bundle for everything
//!    that is not /api/*.
//! 3. Wait until axum answers `/api/health` (the Node helper handles
//!    `/api/health` until that route is ported).
//! 4. Open a Tauri webview pointed at `http://127.0.0.1:<port>/`.
//!
//! The strangler proxy + Node spawn disappear once the last endpoint is
//! native; until then the UI keeps full functionality with no behavioral
//! changes.

pub mod features;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::features::api::state::{AppState, AppStateInner};
use crate::features::server::ServerHandle;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = env_logger::try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let handle = app.handle().clone();

            tauri::async_runtime::spawn(async move {
                let port = features::server::port_from_env();
                let proxy_port = features::server::proxy_port_from_env();

                let user_log = features::paths::server_log_path(&handle);
                let scan_root = features::paths::scan_root(&handle);
                let resources_root = features::paths::resources_root(&handle);
                let client_dist = resources_root.join("client").join("dist");
                let host_paths = features::paths::clamav_conf_paths();
                let quarantine_dir = features::paths::quarantine_dir(&handle);

                // 1. Spawn the legacy Node helper on the *internal* port.
                let server = match ServerHandle::start(
                    &resources_root,
                    &scan_root,
                    &quarantine_dir,
                    &user_log,
                    proxy_port,
                    port,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("could not spawn local server: {e}");
                        let _ = features::ui::show_fatal(
                            &handle,
                            "ClamAV Control — could not start",
                            &format!("{e}\n\nDetails may be in:\n{}", user_log.display()),
                        );
                        handle.exit(1);
                        return;
                    }
                };
                handle.manage(server);

                // 2. Build axum app state and bind on the *public* port.
                let app_state = AppState::new(AppStateInner {
                    clamd_conf: host_paths.clamd,
                    freshclam_conf: host_paths.freshclam,
                    scan_root: scan_root.clone(),
                    quarantine_dir,
                    client_dist,
                    public_port: port,
                    proxy_port: Some(proxy_port),
                    http: reqwest::Client::builder()
                        .pool_idle_timeout(Duration::from_secs(30))
                        .build()
                        .expect("build reqwest client"),
                });

                let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                tokio::spawn({
                    let state = app_state.clone();
                    async move {
                        if let Err(e) = features::api::serve(bind, state).await {
                            log::error!("axum server crashed: {e}");
                        }
                    }
                });

                // 3. Wait until something on the public port answers /api/health
                // (today: proxied to Node; tomorrow: native).
                if let Err(e) = features::server::await_health(port).await {
                    log::error!("server never became healthy: {e}");
                    let _ = features::ui::show_fatal(
                        &handle,
                        "ClamAV Control — could not start",
                        &format!("{e}\n\nDetails may be in:\n{}", user_log.display()),
                    );
                    handle.exit(1);
                    return;
                }

                // 4. Open the main window pointed at the public port.
                if let Err(e) = features::ui::open_main_window(&handle, port).await {
                    log::error!("could not open main window: {e}");
                    handle.exit(1);
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                if window.label() == "main" {
                    if let Some(server) = window.app_handle().try_state::<ServerHandle>() {
                        server.shutdown();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
