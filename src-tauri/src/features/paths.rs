//! Path resolution for dev runs vs packaged app bundles.

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

/// Where the Node server source lives (dev: repo, packaged: bundled resources).
pub fn resources_root(handle: &AppHandle) -> PathBuf {
    if let Ok(dir) = handle.path().resource_dir() {
        let bundled = dir.join("resources");
        if bundled.join("server").join("index.js").exists() {
            return bundled;
        }
    }
    // Dev fallback: repo root, two levels up from src-tauri/.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(&manifest).to_path_buf()
}

/// Per-user log file path. Mirrors the Electron app's location semantics by
/// using Tauri's app-local-data dir, which maps to:
///   macOS:   ~/Library/Application Support/<bundleId>/server.log
///   Windows: %APPDATA%/<bundleId>/server.log
///   Linux:   ~/.config/<bundleId>/server.log
pub fn server_log_path(handle: &AppHandle) -> PathBuf {
    let dir = handle
        .path()
        .app_local_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let _ = std::fs::create_dir_all(&dir);
    dir.join("server.log")
}

/// Where ClamAV scans by default. Mirrors Electron app behavior so existing
/// users keep the same scan folder.
pub fn scan_root(handle: &AppHandle) -> PathBuf {
    let documents = handle
        .path()
        .document_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let scan = documents.join("ClamAV-Scan");
    let _ = std::fs::create_dir_all(&scan);
    scan
}
