//! In-process HTTP server replacing the Node Express helper, one feature at
//! a time. The router has two halves:
//!
//! * `/api/*` — native axum handlers; unmatched paths fall through to the
//!   strangler proxy that forwards to the legacy Node helper.
//! * `/`, `/*` — static `client/dist` with SPA fallback to `index.html`.
//!
//! Each ported feature lives in its own module and exposes
//! `routes() -> Router<AppState>`. To bring a feature on, import its module
//! and `.merge(feature::routes())` below — the proxy fallback then stops
//! taking those paths automatically.
//!
//! Once the last route is native we remove the `proxy` module, `proxy_port`
//! field, and the Node spawn in `features::server`.

pub mod config;
pub mod dns;
pub mod error;
pub mod exec;
pub mod guard;
pub mod proxy;
pub mod quarantine;
pub mod scan;
pub mod state;

use std::net::SocketAddr;

use axum::{
    extract::Request,
    http::header,
    middleware::Next,
    response::Response,
    Router,
};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

use self::state::AppState;

/// Forbid caching of HTML responses, mirroring the Node helper's static
/// config. Without this, WKWebView's disk cache can keep showing a stale
/// `index.html` (and through it, an old JS bundle) across app launches.
/// Hashed assets are safe to cache — their filenames change with content.
async fn no_cache_html(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let is_html = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    if is_html {
        res.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
    }
    res
}

/// Build the public axum router for the GUI.
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        // ---- ported feature routers ----
        .merge(config::routes())
        .merge(dns::routes())
        .merge(quarantine::routes())
        .merge(scan::routes())
        // ---- strangler fallback ----
        .fallback(proxy::forward)
        .with_state(state.clone());

    let index = state.client_dist.join("index.html");
    let static_service = ServeDir::new(&state.client_dist).fallback(ServeFile::new(index));

    Router::new()
        .nest("/api", api)
        .fallback_service(static_service)
        .layer(axum::middleware::from_fn(no_cache_html))
        // Reject cross-origin browser traffic before it reaches any handler.
        // The app is a same-origin SPA, so it needs no CORS; a permissive CORS
        // layer here would instead expose every privileged route to drive-by
        // requests from any web page the user has open.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            guard::require_local_origin,
        ))
}

/// Bind the router to `addr` and serve forever.
pub async fn serve(addr: SocketAddr, state: AppState) -> Result<(), String> {
    let app = build_router(state).into_make_service();
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    log::info!("axum listening on {addr}");
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("axum serve error: {e}"))
}
