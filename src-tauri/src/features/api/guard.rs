//! Local-origin guard for the public HTTP server.
//!
//! The server binds to loopback, but any browser tab on the machine can still
//! reach `http://127.0.0.1:<port>/api/*`. Without a check, a random web page
//! could issue cross-origin requests that drive privileged actions (change
//! DNS, disable the firewall, overwrite clamd.conf, install cron jobs). This
//! middleware rejects any request that is not same-origin with the app:
//!
//! * `Host` header must name a loopback host — defeats DNS-rebinding, where an
//!   attacker domain resolves to `127.0.0.1` but the browser still sends
//!   `Host: attacker.com`.
//! * `Sec-Fetch-Site` (sent by every modern engine, including the WKWebView /
//!   WebView2 that host this app) must not be `cross-site` / `same-site` —
//!   this also blocks no-`Origin` cross-origin GETs (`<img>`, `<script>`).
//! * `Origin`, when present, must be one of the app's own loopback origins.
//!
//! Requests with no browser fingerprint at all (the Rust health probe, the
//! integration tests, curl) carry a loopback `Host`, no `Origin`, and no
//! `Sec-Fetch-Site`, so they pass.

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::state::AppState;

/// Strip the port (and any IPv6 brackets), then match against loopback names.
fn host_is_loopback(host_header: &str) -> bool {
    let h = host_header.trim();
    // Bracketed IPv6: `[::1]` or `[::1]:port`.
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next() == Some("::1");
    }
    // Otherwise strip a trailing `:port`, but only when the remainder isn't
    // itself a bare IPv6 literal (which would still contain a colon, e.g.
    // `::1`).
    let host = match h.rsplit_once(':') {
        Some((left, right))
            if !right.is_empty()
                && right.chars().all(|c| c.is_ascii_digit())
                && !left.contains(':') =>
        {
            left
        }
        _ => h,
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn origin_is_allowed(origin: &str, port: u16) -> bool {
    [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
    ]
    .iter()
    .any(|allowed| allowed == origin)
}

fn forbidden(detail: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": format!("Forbidden: {detail}") })),
    )
        .into_response()
}

/// Reject cross-origin browser requests before they reach any handler.
pub async fn require_local_origin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    let port = state.public_port;

    if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        if !host_is_loopback(host) {
            return forbidden("request Host is not a loopback address");
        }
    }

    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        if site.eq_ignore_ascii_case("cross-site") || site.eq_ignore_ascii_case("same-site") {
            return forbidden("cross-origin request blocked");
        }
    }

    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !origin_is_allowed(origin, port) {
            return forbidden("origin not allowed");
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts_are_accepted_with_or_without_port() {
        assert!(host_is_loopback("127.0.0.1:38471"));
        assert!(host_is_loopback("127.0.0.1"));
        assert!(host_is_loopback("localhost:38471"));
        assert!(host_is_loopback("localhost"));
        assert!(host_is_loopback("[::1]:38471"));
        assert!(host_is_loopback("::1"));
    }

    #[test]
    fn non_loopback_hosts_are_rejected() {
        assert!(!host_is_loopback("evil.com"));
        assert!(!host_is_loopback("evil.com:38471"));
        assert!(!host_is_loopback("10.0.0.5:38471"));
        assert!(!host_is_loopback("attacker.127.0.0.1.nip.io:38471"));
    }

    #[test]
    fn only_own_loopback_origins_are_allowed() {
        assert!(origin_is_allowed("http://127.0.0.1:38471", 38471));
        assert!(origin_is_allowed("http://localhost:38471", 38471));
        assert!(!origin_is_allowed("http://127.0.0.1:38472", 38471));
        assert!(!origin_is_allowed("http://evil.com", 38471));
        assert!(!origin_is_allowed("https://127.0.0.1:38471", 38471));
    }
}
