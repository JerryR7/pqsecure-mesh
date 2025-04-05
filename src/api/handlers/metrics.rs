use axum::Json;
use axum::extract::State;

use crate::api::types::{ApiState, ApiResponse, MetricsResponse};
use crate::error::Error;

/// Get metrics
pub async fn get_metrics(
    State(state): State<ApiState>,
) -> Json<ApiResponse<MetricsResponse>> {
    // Get stats
    let stats = state.metrics.get_stats().await;
    
    // Create metrics response
    let metrics = MetricsResponse {
        total_requests: stats.total_requests,
        successful_requests: stats.successful_requests,
        failed_requests: stats.failed_requests,
        client_connections: stats.client_connections,
        active_connections: stats.active_connections,
        total_bytes: stats.total_bytes,
        last_updated_at: stats.last_updated_at,
    };
    
    Json(ApiResponse::success(metrics))
}