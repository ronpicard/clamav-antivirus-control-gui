//! Native port of `GET /api/scan/history`.
//!
//! Mirrors `server/index.js` § `readHistoryFile()` and the matching route.
//! On read errors or missing file we return an empty list (parity with
//! Express).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;

use super::error::ApiResult;
use super::state::AppState;

const HISTORY_BASENAME: &str = ".clamav-gui-scan-history.json";

async fn history(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let path = state.scan_root.join(HISTORY_BASENAME);
    let items: Vec<Value> = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Array(arr)) => arr,
            _ => Vec::new(),
        },
        Err(_) => Vec::new(),
    };
    Ok(Json(serde_json::json!({ "items": items })))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/scan/history", get(history))
}
