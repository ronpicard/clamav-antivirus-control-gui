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
pub mod proxy;
pub mod quarantine;
pub mod scan;
pub mod state;

use std::net::SocketAddr;

use axum::Router;
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

use self::state::AppState;

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
        .layer(tower_http::cors::CorsLayer::very_permissive())
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
