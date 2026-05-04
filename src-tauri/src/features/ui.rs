//! Window creation and user-facing error dialogs.

use tauri::{AppHandle, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

const WINDOW_LABEL: &str = "main";

pub async fn open_main_window(handle: &AppHandle, port: u16) -> Result<(), String> {
    let url = format!("http://127.0.0.1:{port}/");
    let parsed = url::Url::parse(&url).map_err(|e| format!("invalid url {url}: {e}"))?;

    WebviewWindowBuilder::new(handle, WINDOW_LABEL, WebviewUrl::External(parsed))
        .title("ClamAV Control")
        .inner_size(1120.0, 820.0)
        .min_inner_size(720.0, 520.0)
        .resizable(true)
        .visible(true)
        .build()
        .map(|_| ())
        .map_err(|e| format!("failed to build main window: {e}"))
}

/// Show a native error dialog. Falls back to stderr if the dialog plugin is
/// not initialized yet (e.g. the app failed before plugin setup completed).
pub fn show_fatal(handle: &AppHandle, title: &str, body: &str) -> Result<(), String> {
    eprintln!("[fatal] {title}: {body}");
    handle
        .dialog()
        .message(body)
        .title(title)
        .kind(MessageDialogKind::Error)
        .blocking_show();
    Ok(())
}
