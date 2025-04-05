use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};
use axum::middleware;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use crate::error::Error;
use crate::config::Config;
use crate::telemetry::ProxyMetrics;
use crate::api::types::ApiState;
use crate::api::middlewares::{
    cors_middleware,
    request_id_middleware,
    logging_middleware,
    error_handling_middleware
};
use crate::api::handlers::{
    health::health_check,
    identity::{request_identity, revoke_identity, check_identity},
    policy::{get_policy, update_policy},
    metrics::get_metrics,
};

/// Create router with all API routes
///
/// # Arguments
///
/// * `config` - Application configuration
/// * `metrics` - Metrics collector
///
/// # Returns
///
/// A configured Axum router with all API routes
///
/// # Errors
///
/// Returns an error if the router cannot be created
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

    // Define public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics));

    // Define identity API routes
    let identity_routes = Router::new()
        .route("/request", post(request_identity))
        .route("/revoke", post(revoke_identity))
        .route("/check", post(check_identity));

    // Define policy API routes
    let policy_routes = Router::new()
        .route("/", get(get_policy))
        .route("/", post(update_policy));

    // Combine all routes
    let api_routes = Router::new()
        .nest("/identity", identity_routes)
        .nest("/policy", policy_routes);

    // Global middleware stack
    let middleware_stack = ServiceBuilder::new()
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn(logging_middleware))
        .layer(middleware::from_fn(error_handling_middleware))
        .layer(middleware::from_fn(cors_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new());

    // Create the final router
    let router = Router::new()
        .merge(public_routes)
        .nest(prefix, api_routes)
        .layer(middleware_stack)
        .with_state(state);

    Ok(router)
}

/// Create a test router
///
/// This is used for testing API endpoints with minimal middleware
///
/// # Arguments
///
/// * `config` - Application configuration
/// * `metrics` - Metrics collector
///
/// # Returns
///
/// A configured Axum router for testing
pub fn create_test_router(
    config: Arc<Config>,
    metrics: Arc<ProxyMetrics>,
) -> Router {
    // Create shared state
    let state = ApiState {
        config,
        metrics,
    };

    // Create a minimal router with all handlers but minimal middleware
    Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics))
        .route("/api/v1/identity/request", post(request_identity))
        .route("/api/v1/identity/revoke", post(revoke_identity))
        .route("/api/v1/identity/check", post(check_identity))
        .route("/api/v1/policy", get(get_policy))
        .route("/api/v1/policy", post(update_policy))
        .with_state(state)
}