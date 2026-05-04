//! Native port of `GET /api/dns/presets` (purely static data).
//!
//! Mirrors `server/index.js` § `DNS_PRESETS` and the `/api/dns/presets`
//! handler verbatim — same `id`, `label`, `servers` fields, same order.

use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use super::state::AppState;

#[derive(Serialize)]
struct PresetItem {
    id: &'static str,
    label: &'static str,
    servers: Option<&'static [&'static str]>,
}

#[derive(Serialize)]
struct PresetsResponse {
    items: Vec<PresetItem>,
}

const PRESETS: &[PresetItem] = &[
    PresetItem {
        id: "automatic",
        label: "Automatic (router / DHCP)",
        servers: None,
    },
    PresetItem {
        id: "opendns",
        label: "OpenDNS",
        servers: Some(&["208.67.222.222", "208.67.220.220"]),
    },
    PresetItem {
        id: "opendns-family",
        label: "OpenDNS FamilyShield",
        servers: Some(&["208.67.222.123", "208.67.220.123"]),
    },
    PresetItem {
        id: "google",
        label: "Google Public DNS",
        servers: Some(&["8.8.8.8", "8.8.4.4"]),
    },
    PresetItem {
        id: "cloudflare",
        label: "Cloudflare (1.1.1.1)",
        servers: Some(&["1.1.1.1", "1.0.0.1"]),
    },
    PresetItem {
        id: "cloudflare-family",
        label: "Cloudflare for Families (1.1.1.3)",
        servers: Some(&["1.1.1.3", "1.0.0.3"]),
    },
    PresetItem {
        id: "custom",
        label: "Custom",
        servers: None,
    },
];

async fn presets() -> Json<PresetsResponse> {
    let items = PRESETS
        .iter()
        .map(|p| PresetItem {
            id: p.id,
            label: p.label,
            servers: p.servers,
        })
        .collect();
    Json(PresetsResponse { items })
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/dns/presets", get(presets))
}
