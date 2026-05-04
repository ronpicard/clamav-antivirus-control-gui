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
