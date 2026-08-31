//! Native port of `GET /api/config/:which`.
//!
//! Mirrors `server/index.js` § `app.get("/api/config/:which", ...)`:
//! * `:which` MUST be `clamd` or `freshclam`; otherwise `400 Invalid config name`.
//! * On read failure, `404 { error }`. On success, `{ path, content }`.
//!
//! `PUT /api/config/:which` (write) and `POST /api/config/reset` are still
//! served by Node and will land in a later phase.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use super::error::{ApiError, ApiResult};
use super::state::AppState;

async fn get_config(
    State(state): State<AppState>,
    Path(which): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let file = match which.as_str() {
        "clamd" => state.clamd_conf.clone(),
        "freshclam" => state.freshclam_conf.clone(),
        _ => return Err(ApiError::BadRequest("Invalid config name".into())),
    };

    match tokio::fs::read_to_string(&file).await {
        Ok(content) => Ok(Json(json!({
            "path": file.to_string_lossy(),
            "content": content,
        }))),
        // Express returns 404 with the raw read error body. Match that.
        Err(e) => Err(ApiError::NotFound(format!("read {}: {e}", file.display()))),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/config/{which}", get(get_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_config_returns_path_and_content_when_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(tmp.path());
        std::fs::write(&state.clamd_conf, "LogFile /tmp/clamd.log\n").unwrap();

        let Json(body) = get_config(State(state.clone()), Path("clamd".into()))
            .await
            .unwrap();

        assert_eq!(body["path"], state.clamd_conf.to_string_lossy().as_ref());
        assert_eq!(body["content"], "LogFile /tmp/clamd.log\n");
    }

    #[tokio::test]
    async fn get_config_rejects_unknown_name_with_bad_request() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(tmp.path());

        let err = get_config(State(state), Path("bogus".into()))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn get_config_returns_not_found_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState::for_tests(tmp.path());

        let err = get_config(State(state), Path("freshclam".into()))
            .await
            .unwrap_err();

        assert!(matches!(err, ApiError::NotFound(_)), "got {err:?}");
    }
}
