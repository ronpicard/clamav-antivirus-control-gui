//! Single error type for handlers; converts into a JSON response.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    NotFound(String),

    /// Returned by handlers that are stubbed during the Express → Rust
    /// migration. Currently unused because un-ported routes proxy to Node;
    /// kept so individual feature modules can opt into "explicit 501" once
    /// the proxy is removed.
    #[allow(dead_code)]
    #[error("{0}")]
    NotImplemented(String),

    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::Internal(format!("io: {e}"))
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_variant_maps_to_its_http_status() {
        assert_eq!(
            ApiError::BadRequest("x".into()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(ApiError::NotFound("x".into()).status(), StatusCode::NOT_FOUND);
        assert_eq!(
            ApiError::NotImplemented("x".into()).status(),
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            ApiError::Internal("x".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn response_body_is_json_error_object() {
        let resp = ApiError::NotFound("no such file".into()).into_response();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "no such file");
    }

    #[test]
    fn io_errors_convert_to_internal_with_context() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");

        let err = ApiError::from(io);

        assert!(matches!(err, ApiError::Internal(_)));
        assert!(err.to_string().starts_with("io: "), "got {err}");
    }

    #[test]
    fn anyhow_errors_convert_to_internal() {
        let err = ApiError::from(anyhow::anyhow!("boom"));

        assert!(matches!(err, ApiError::Internal(_)));
        assert_eq!(err.to_string(), "boom");
    }
}
