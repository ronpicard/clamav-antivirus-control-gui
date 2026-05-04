//! Native port of `GET /api/quarantine` — list quarantined files.
//!
//! Mirrors `server/index.js` route at line ~3576: ensure the quarantine
//! directory exists, list non-dotfile entries, return name/path/size/mtime,
//! sorted by `quarantinedAt` descending.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::json;

use super::error::{ApiError, ApiResult};
use super::state::AppState;

#[derive(Serialize)]
struct QuarantineEntry {
    name: String,
    path: String,
    size: u64,
    #[serde(rename = "quarantinedAt")]
    quarantined_at: f64,
}

async fn list(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let dir = &state.quarantine_dir;
    tokio::fs::create_dir_all(dir).await.map_err(|e| {
        ApiError::Internal(format!("create {}: {e}", dir.display()))
    })?;

    let mut read = match tokio::fs::read_dir(dir).await {
        Ok(r) => r,
        Err(e) => return Err(ApiError::Internal(format!("read {}: {e}", dir.display()))),
    };

    let mut items: Vec<QuarantineEntry> = Vec::new();
    while let Some(entry) = read.next_entry().await.map_err(|e| {
        ApiError::Internal(format!("read entry: {e}"))
    })? {
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let full = entry.path();
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        let mtime_ms = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .unwrap_or(0.0)
            });
        items.push(QuarantineEntry {
            name,
            path: full.to_string_lossy().into_owned(),
            size: meta.len(),
            quarantined_at: mtime_ms,
        });
    }

    items.sort_by(|a, b| b.quarantined_at.total_cmp(&a.quarantined_at));

    Ok(Json(json!({
        "dir": dir.to_string_lossy(),
        "items": items,
    })))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/quarantine", get(list))
}
