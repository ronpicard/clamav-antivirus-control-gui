//! Manages the Node-based local server child process.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

const DEFAULT_PORT: u16 = 38471;
const HEALTH_TIMEOUT_MS: u64 = 15_000;
const HEALTH_POLL_MS: u64 = 150;

/// Resolve the port from the `CLAMAV_GUI_PORT` env var or fall back.
pub fn port_from_env() -> u16 {
    std::env::var("CLAMAV_GUI_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Owned handle to the spawned Node process.
pub struct ServerHandle {
    child: Mutex<Option<Child>>,
}

impl ServerHandle {
    pub fn start(
        resources_root: &Path,
        scan_root: &Path,
        log_path: &Path,
        port: u16,
    ) -> Result<Self, String> {
        let server_dir = resources_root.join("server");
        let server_entry = server_dir.join("index.js");
        let client_dist = resources_root.join("client").join("dist");

        if !server_entry.exists() {
            return Err(format!(
                "Node server entry not found at {}. Run `npm run build --prefix client` and ensure the server bundle is present.",
                server_entry.display()
            ));
        }

        if !client_dist.exists() {
            return Err(format!(
                "Built UI not found at {}. Run `npm run build --prefix client`.",
                client_dist.display()
            ));
        }

        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            log_path,
            format!("--- start {}\n", chrono_like_now()).as_bytes(),
        );

        let stdout = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| format!("opening server log: {e}"))?;
        let stderr = stdout
            .try_clone()
            .map_err(|e| format!("dup server log handle: {e}"))?;

        let node = locate_node()?;

        let child = Command::new(&node)
            .arg(&server_entry)
            .current_dir(&server_dir)
            .env("PORT", port.to_string())
            .env("BIND_HOST", "127.0.0.1")
            .env("CLIENT_DIST", &client_dist)
            .env("SCAN_ROOT", scan_root)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| {
                format!(
                    "could not start `{}`: {e}. Install Node.js 20+ and ensure `node` is on PATH.",
                    node.display()
                )
            })?;

        log::info!("spawned server pid={} on port {}", child.id(), port);

        Ok(Self {
            child: Mutex::new(Some(child)),
        })
    }

    pub fn shutdown(&self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Poll `/api/health` until success or timeout.
pub async fn await_health(port: u16) -> Result<(), String> {
    let url = format!("http://127.0.0.1:{port}/api/health");
    let attempts = HEALTH_TIMEOUT_MS / HEALTH_POLL_MS;
    for _ in 0..attempts {
        if tcp_probe(port).await {
            // Even after a successful TCP connect, Express may still be wiring
            // routes — give a tiny grace before declaring "ready".
            tokio::time::sleep(Duration::from_millis(50)).await;
            if http_probe(&url).await {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(HEALTH_POLL_MS)).await;
    }
    Err(format!(
        "Local app server did not become healthy on 127.0.0.1:{port} within {} ms.",
        HEALTH_TIMEOUT_MS
    ))
}

async fn tcp_probe(port: u16) -> bool {
    use tokio::net::TcpStream;
    matches!(
        tokio::time::timeout(
            Duration::from_millis(150),
            TcpStream::connect(("127.0.0.1", port))
        )
        .await,
        Ok(Ok(_))
    )
}

async fn http_probe(url: &str) -> bool {
    // Avoid pulling reqwest just for one request; do a minimal raw HTTP/1.1 GET.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let host = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => return false,
    };
    let port = parsed.port().unwrap_or(80);
    let path = if parsed.path().is_empty() { "/" } else { parsed.path() };

    let mut stream = match tokio::time::timeout(
        Duration::from_millis(300),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nUser-Agent: clamav-control/health-probe\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 64];
    let read = match tokio::time::timeout(
        Duration::from_millis(500),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        _ => return false,
    };

    let head = String::from_utf8_lossy(&buf[..read]);
    head.starts_with("HTTP/1.1 2") || head.starts_with("HTTP/1.0 2")
}

fn locate_node() -> Result<PathBuf, String> {
    if let Some(p) = which("node") {
        return Ok(p);
    }
    Err("`node` was not found on PATH. Install Node.js 20+ and try again.".into())
}

#[cfg(unix)]
fn which(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(windows)]
fn which(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT".to_string());
    for dir in std::env::split_paths(&path) {
        for ext in pathext.split(';') {
            let mut candidate = dir.join(cmd);
            if !ext.is_empty() {
                candidate.set_extension(ext.trim_start_matches('.'));
            }
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let bare = dir.join(cmd);
        if bare.is_file() {
            return Some(bare);
        }
    }
    None
}

/// Cheap RFC3339-ish timestamp without pulling chrono.
fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("epoch:{secs}")
}
