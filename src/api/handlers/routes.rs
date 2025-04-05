use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use crate::error::Error;
use crate::config::Config;
use crate::telemetry::ProxyMetrics;
use crate::api::types::ApiState;
use crate::api::handlers::{
    health::health_check,
    identity::{request_identity, revoke_identity, check_identity},
    policy::{get_policy, update_policy},
    metrics::get_metrics,
};

/// Create router with all API routes
pub fn create_router(
    config: Arc<Config>,
    metrics: Arc<ProxyMetrics>,
) -> Result<Router, Error> {
    // Get API path prefix
    let prefix = &config.api.path_prefix;
    
    // Create shared state
    let state = ApiState {
        config: config.clone(),
        metrics: metrics.clone(),
    };
    
    // Create the router
    let router = Router::new()
        // Health routes
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics))
        
        // Identity routes
        .route(&format!("{}/identity/request", prefix), post(request_identity))
        .route(&format!("{}/identity/revoke", prefix), post(revoke_identity))
        .route(&format!("{}/identity/check", prefix), post(check_identity))
        
        // Policy routes
        .route(&format!("{}/policy", prefix), get(get_policy))
        .route(&format!("{}/policy", prefix), post(update_policy))
        
        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
        )
        .with_state(state);
    
    Ok(router)
}