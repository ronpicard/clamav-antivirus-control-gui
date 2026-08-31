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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn presets_returns_all_seven_in_express_order() {
        let Json(body) = presets().await;

        let ids: Vec<&str> = body.items.iter().map(|p| p.id).collect();
        assert_eq!(
            ids,
            [
                "automatic",
                "opendns",
                "opendns-family",
                "google",
                "cloudflare",
                "cloudflare-family",
                "custom",
            ]
        );
    }

    #[tokio::test]
    async fn automatic_and_custom_presets_have_no_servers() {
        let Json(body) = presets().await;

        for p in &body.items {
            match p.id {
                "automatic" | "custom" => assert!(p.servers.is_none(), "{} has servers", p.id),
                _ => assert_eq!(
                    p.servers.map(|s| s.len()),
                    Some(2),
                    "{} should list primary + secondary",
                    p.id
                ),
            }
        }
    }

    #[tokio::test]
    async fn presets_serialize_with_express_field_names() {
        let Json(body) = presets().await;

        let json = serde_json::to_value(&body.items[1]).unwrap();
        assert_eq!(json["id"], "opendns");
        assert_eq!(json["label"], "OpenDNS");
        assert_eq!(json["servers"][0], "208.67.222.222");
    }
}
