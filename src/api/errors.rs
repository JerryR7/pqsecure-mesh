use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json
};
use serde_json::json;
use std::fmt;
use chrono::Utc;

/// API specific error types
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Authentication required
    #[error("Authentication required")]
    Unauthorized,

    /// Access forbidden
    #[error("Access forbidden: {0}")]
    Forbidden(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Bad request
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Internal server error
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Service unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg.clone()),
        };

        // Create JSON response
        let body = Json(json!({
            "success": false,
            "error": error_message,
            "timestamp": Utc::now().to_rfc3339()
        }));

        // Return response with status code and JSON body
        (status, body).into_response()
    }
}

// Conversion from standard Error to ApiError
impl From<crate::error::Error> for ApiError {
    fn from(err: crate::error::Error) -> Self {
        match err {
            crate::error::Error::InvalidRequest(msg) => ApiError::BadRequest(msg),
            crate::error::Error::NotFound(msg) => ApiError::NotFound(msg),
            crate::error::Error::AccessDenied(msg) => ApiError::Forbidden(msg),
            crate::error::Error::Config(msg) => ApiError::Internal(format!("Configuration error: {}", msg)),
            crate::error::Error::Serialization(msg) => ApiError::BadRequest(format!("Serialization error: {}", msg)),
            crate::error::Error::Identity(msg) => ApiError::Internal(format!("Identity error: {}", msg)),
            crate::error::Error::Policy(msg) => ApiError::Internal(format!("Policy error: {}", msg)),
            crate::error::Error::Ca(msg) => ApiError::ServiceUnavailable(format!("CA service error: {}", msg)),
            _ => ApiError::Internal(format!("Unexpected error: {}", err)),
        }
    }
}

/// Result type for API handlers
pub type ApiResult<T> = Result<T, ApiError>;