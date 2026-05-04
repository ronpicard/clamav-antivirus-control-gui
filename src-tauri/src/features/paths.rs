//! Path resolution for dev runs vs packaged app bundles.

use std::path::{Path, PathBuf};

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

/// Default quarantine directory (`~/Documents/ClamAV-Quarantine`).
/// Mirrors `server/index.js` § `QUARANTINE_DIR`.
pub fn quarantine_dir(handle: &AppHandle) -> PathBuf {
    let documents = handle
        .path()
        .document_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    documents.join("ClamAV-Quarantine")
}

/// Resolved paths to `clamd.conf` / `freshclam.conf` for the host platform.
/// Mirrors `server/index.js` § `hostDefaultConfPaths()`.
pub struct ClamavConfPaths {
    pub clamd: PathBuf,
    pub freshclam: PathBuf,
}

pub fn clamav_conf_paths() -> ClamavConfPaths {
    if cfg!(target_os = "macos") {
        let arm = Path::new("/opt/homebrew/etc/clamav");
        let intel = Path::new("/usr/local/etc/clamav");
        if arm.join("clamd.conf").exists() {
            return ClamavConfPaths {
                clamd: arm.join("clamd.conf"),
                freshclam: arm.join("freshclam.conf"),
            };
        }
        if intel.join("clamd.conf").exists() {
            return ClamavConfPaths {
                clamd: intel.join("clamd.conf"),
                freshclam: intel.join("freshclam.conf"),
            };
        }
        return ClamavConfPaths {
            clamd: arm.join("clamd.conf"),
            freshclam: arm.join("freshclam.conf"),
        };
    }
    if cfg!(target_os = "windows") {
        let pf = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        return ClamavConfPaths {
            clamd: pf.join("ClamAV").join("clamd.conf"),
            freshclam: pf.join("ClamAV").join("freshclam.conf"),
        };
    }
    ClamavConfPaths {
        clamd: PathBuf::from("/etc/clamav/clamd.conf"),
        freshclam: PathBuf::from("/etc/clamav/freshclam.conf"),
    }
}
