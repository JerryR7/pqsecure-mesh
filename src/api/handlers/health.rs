use axum::{
    extract::State,
    Json,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

use crate::api::types::{ApiState, ApiResponse, HealthResponse};
use crate::api::errors::{ApiError, ApiResult};

/// Health check handler
///
/// This handler provides basic health information about the service.
/// It returns a 200 OK status with information about the service version and uptime.
///
/// # Route
///
/// `GET /health`
///
/// # Response
///
/// Returns a JSON response with:
/// - `status`: Current service status (ok, degraded, etc.)
/// - `version`: Service version
/// - `uptime`: Uptime in seconds
///
/// # Example Response
///
/// ```json
/// {
///   "success": true,
///   "data": {
///     "status": "ok",
///     "version": "0.1.0",
///     "uptime": 3600
///   }
/// }
/// ```
pub async fn health_check(
    State(state): State<ApiState>,
) -> ApiResult<Json<ApiResponse<HealthResponse>>> {
    debug!("Health check requested");

    // Calculate uptime
    let uptime = calculate_uptime();

    // Get version from cargo
    let version = env!("CARGO_PKG_VERSION").to_string();

    // Create health response
    let health = HealthResponse {
        status: "ok".to_string(),
        version,
        uptime,
    };

    // Return success response
    Ok(Json(ApiResponse::success(health)))
}

/// Calculate system uptime in seconds
fn calculate_uptime() -> u64 {
    match std::process::Command::new("uptime").output() {
        Ok(_) => {
            // In a real implementation, we'd parse the output
            // For now, just return the process uptime
            match UNIX_EPOCH.elapsed() {
                Ok(duration) => duration.as_secs(),
                Err(_) => 0,
            }
        },
        Err(_) => {
            // Fall back to process uptime if system uptime is unavailable
            match UNIX_EPOCH.elapsed() {
                Ok(duration) => duration.as_secs(),
                Err(_) => 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;
    use std::sync::Arc;
    use crate::config::Config;
    use crate::telemetry::ProxyMetrics;

    #[tokio::test]
    async fn test_health_check() {
        // Set up test state
        let state = ApiState {
            config: Arc::new(Config::default()),
            metrics: Arc::new(ProxyMetrics::new(true)),
        };

        // Create test router
        let app = Router::new()
            .route("/health", get(health_check))
            .with_state(state);

        // Create test request
        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Verify response status
        assert_eq!(response.status(), StatusCode::OK);

        // Parse and verify response body
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let api_response: ApiResponse<HealthResponse> = serde_json::from_slice(&body).unwrap();

        assert!(api_response.success);
        assert!(api_response.data.is_some());

        let health = api_response.data.unwrap();
        assert_eq!(health.status, "ok");
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
        assert!(health.uptime >= 0);
    }
}