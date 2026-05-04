//! Tauri shell for ClamAV Control.
//!
//! Responsibilities:
//! * Spawn the Node-based local server (the existing Express app).
//! * Wait until it answers `/api/health` on `127.0.0.1:<port>`.
//! * Open a Tauri webview pointed at `http://127.0.0.1:<port>/`.
//!
//! Native ClamAV/DNS/cron commands stay in Node for now and will migrate
//! to Rust commands incrementally (strangler pattern).

mod features;

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

                let user_log = features::paths::server_log_path(&handle);
                let scan_root = features::paths::scan_root(&handle);
                let resources_root = features::paths::resources_root(&handle);

                let server = match ServerHandle::start(
                    &resources_root,
                    &scan_root,
                    &user_log,
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
