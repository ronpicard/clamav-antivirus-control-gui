//! Shared application state injected into every axum handler.

use std::path::PathBuf;
use std::sync::Arc;

/// Cheap-to-clone (`Arc` inside) application state.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    /// Resolved path to `clamd.conf` (env override or platform default).
    pub clamd_conf: PathBuf,
    /// Resolved path to `freshclam.conf` (env override or platform default).
    pub freshclam_conf: PathBuf,
    /// User scan root (`~/Documents/ClamAV-Scan` by default).
    pub scan_root: PathBuf,
    /// Quarantine directory (`~/Documents/ClamAV-Quarantine` by default).
    pub quarantine_dir: PathBuf,
    /// Where the React build sits on disk (used by the static service).
    pub client_dist: PathBuf,
    /// Public port the webview connects to. Used by the local-origin guard to
    /// build the set of allowed same-origin values.
    pub public_port: u16,
    /// Port the legacy Node helper listens on while we strangle it.
    /// `None` once the helper is gone.
    pub proxy_port: Option<u16>,
    /// Pre-built reqwest client used by the proxy fallback.
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(inner: AppStateInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl std::ops::Deref for AppState {
    type Target = AppStateInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
impl AppState {
    /// State rooted at a temp directory, no proxy — shared by the unit
    /// tests in the sibling handler modules.
    pub fn for_tests(root: &std::path::Path) -> Self {
        Self::new(AppStateInner {
            clamd_conf: root.join("clamd.conf"),
            freshclam_conf: root.join("freshclam.conf"),
            scan_root: root.join("scan"),
            quarantine_dir: root.join("quarantine"),
            client_dist: root.join("dist"),
            public_port: 38471,
            proxy_port: None,
            http: reqwest::Client::new(),
        })
    }
}
