// src/api/errors.rs
use axum::{response::{IntoResponse, Response}, http::StatusCode, Json};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Authentication required")]
    Unauthorized,
    #[error("Access forbidden: {0}")]
    Forbidden(String),
    #[error("Resource not found: {0}")]
    NotFound(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    // 其他錯誤...
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}