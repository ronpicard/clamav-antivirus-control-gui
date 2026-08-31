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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::api::state::AppState;

    async fn history_items(state: AppState) -> Vec<Value> {
        let Json(body) = history(State(state)).await.unwrap();
        body["items"].as_array().unwrap().clone()
    }

    fn write_history(state: &AppState, raw: &str) {
        std::fs::create_dir_all(&state.scan_root).unwrap();
        std::fs::write(state.scan_root.join(HISTORY_BASENAME), raw).unwrap();
    }

    #[tokio::test]
    async fn history_returns_stored_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(tmp.path());
        write_history(&state, r#"[{"target":"/tmp","infected":0}]"#);

        let items = history_items(state).await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["target"], "/tmp");
    }

    #[tokio::test]
    async fn history_is_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(tmp.path());

        assert!(history_items(state).await.is_empty());
    }

    #[tokio::test]
    async fn history_is_empty_on_corrupt_json() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(tmp.path());
        write_history(&state, "not json {");

        assert!(history_items(state).await.is_empty());
    }

    #[tokio::test]
    async fn history_is_empty_when_json_is_not_an_array() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(tmp.path());
        write_history(&state, r#"{"items": []}"#);

        assert!(history_items(state).await.is_empty());
    }
}
