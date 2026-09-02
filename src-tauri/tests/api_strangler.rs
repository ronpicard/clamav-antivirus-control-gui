//! Integration test: boot the axum router with a Node helper running on a
//! known port, then verify:
//!   * native handlers respond (DNS presets, scan history, quarantine, config GET)
//!   * unported routes still reach the Node helper via the proxy fallback
//!
//! The test is gated behind the `CLAMAV_GUI_NODE_PORT` env var. When set, we
//! assume `node server/index.js` is already listening on that loopback port
//! and run the assertions against it. When unset, the test skips. This keeps
//! `cargo test` deterministic in CI without spawning Node ourselves.
//!
//! Local invocation:
//!   ```bash
//!   make stage
//!   cd server && PORT=38470 BIND_HOST=127.0.0.1 \
//!       CLIENT_DIST="$PWD/../client/dist" \
//!       SCAN_ROOT="$HOME/Documents/ClamAV-Scan" \
//!       node index.js &
//!   CLAMAV_GUI_NODE_PORT=38470 cargo test --test api_strangler -- --nocapture
//!   ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::Duration;

use clamav_control_lib::features::api::{
    self,
    state::{AppState, AppStateInner},
};

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("addr").port()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn node_port() -> Option<u16> {
    std::env::var("CLAMAV_GUI_NODE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
}

fn build_state(proxy_port: Option<u16>, public_port: u16) -> AppState {
    let root = workspace_root();
    let host = clamav_control_lib::features::paths::clamav_conf_paths();
    AppState::new(AppStateInner {
        clamd_conf: host.clamd,
        freshclam_conf: host.freshclam,
        scan_root: dirs::document_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("ClamAV-Scan"),
        quarantine_dir: dirs::document_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("ClamAV-Quarantine"),
        client_dist: root.join("client").join("dist"),
        public_port,
        proxy_port,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("reqwest"),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn native_routes_and_proxy_fallthrough() {
    let proxy_port = node_port();
    let port = pick_port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let state = build_state(proxy_port, port);

    tokio::spawn({
        let state = state.clone();
        async move {
            let _ = api::serve(addr, state).await;
        }
    });

    // Wait until axum is listening.
    for _ in 0..50 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let client = reqwest::Client::new();

    // -------- native handlers --------
    let r = client
        .get(format!("http://{addr}/api/dns/presets"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "/api/dns/presets");
    let body: serde_json::Value = r.json().await.unwrap();
    let items = body.get("items").and_then(|v| v.as_array()).expect("items[]");
    assert!(items.iter().any(|p| p["id"] == "automatic"));
    assert!(items.iter().any(|p| p["id"] == "cloudflare"));

    let r = client
        .get(format!("http://{addr}/api/scan/history"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "/api/scan/history");
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(body.get("items").is_some_and(|v| v.is_array()));

    let r = client
        .get(format!("http://{addr}/api/quarantine"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "/api/quarantine");
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(body.get("items").is_some_and(|v| v.is_array()));

    // /api/config/clamd may 404 if the user has no clamd.conf — that is also
    // an Express-parity outcome. Either 200 with `content` or 404 with `error`.
    let r = client
        .get(format!("http://{addr}/api/config/clamd"))
        .send()
        .await
        .unwrap();
    assert!(matches!(r.status().as_u16(), 200 | 404), "/api/config/clamd");

    // Bogus name MUST be 400 — that is a native check, not a proxy fall.
    let r = client
        .get(format!("http://{addr}/api/config/bogus"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "/api/config/bogus");

    // -------- proxy fallthrough (only when Node is up) --------
    // Verifies that an un-ported route actually reaches the Node helper via
    // the strangler proxy and round-trips the JSON body intact. Skipped when
    // `CLAMAV_GUI_NODE_PORT` is unset so this test is safe in CI.
    if proxy_port.is_some() {
        let r = client
            .get(format!("http://{addr}/api/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "/api/health proxied to Node");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["ok"], serde_json::Value::Bool(true));
        assert!(body.get("clamav").is_some());
    } else {
        eprintln!("CLAMAV_GUI_NODE_PORT unset — skipping proxy assertions");
    }
}

/// HTML must be served with `Cache-Control: no-store` so WKWebView never
/// shows a stale `index.html` (and through it an old JS bundle) after an
/// update. Hashed assets carry no such header — their names change instead.
#[tokio::test(flavor = "multi_thread")]
async fn html_is_served_with_no_store() {
    let port = pick_port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let state = build_state(None, port);

    tokio::spawn({
        let state = state.clone();
        async move {
            let _ = api::serve(addr, state).await;
        }
    });

    for _ in 0..50 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Requires `make stage` (client/dist present), same as the other tests.
    let r = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "GET / serves index.html");
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("text/html"), "content-type was {ct:?}");
    let cc = r
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cc.contains("no-store"),
        "index.html must be no-store, got {cc:?}"
    );
}

/// The local-origin guard must reject cross-origin browser traffic before it
/// reaches any handler, while still allowing the app's own same-origin
/// requests. This is the fix for the permissive-CORS / drive-by-CSRF hole.
#[tokio::test(flavor = "multi_thread")]
async fn guard_blocks_cross_origin_but_allows_same_origin() {
    let port = pick_port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let state = build_state(None, port);

    tokio::spawn({
        let state = state.clone();
        async move {
            let _ = api::serve(addr, state).await;
        }
    });

    for _ in 0..50 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/dns/presets");

    // A page on another site: browser sends a foreign Origin → 403.
    let r = client
        .get(&url)
        .header("Origin", "http://evil.com")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "foreign Origin must be rejected");

    // Modern engines tag cross-origin requests even without an Origin header.
    let r = client
        .get(&url)
        .header("Sec-Fetch-Site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "Sec-Fetch-Site: cross-site must be rejected");

    // DNS-rebinding: attacker domain resolves to loopback, but Host is foreign.
    let r = client
        .get(&url)
        .header("Host", "evil.com")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "non-loopback Host must be rejected");

    // The app itself: same-origin Origin + loopback Host → allowed.
    let r = client
        .get(&url)
        .header("Origin", format!("http://127.0.0.1:{port}"))
        .header("Sec-Fetch-Site", "same-origin")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "same-origin request must pass");
}
