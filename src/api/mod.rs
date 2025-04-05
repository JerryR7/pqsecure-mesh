pub mod server;
pub mod handlers;
pub mod routes;
pub mod types;

use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use crate::error::Error;
use crate::config::Config;
use crate::telemetry::ProxyMetrics;
use self::handlers::{
    health::health_check,
    identity::{request_identity, revoke_identity, check_identity},
    policy::{get_policy, update_policy},
    metrics::get_metrics,
};

/// Creates an API server instance
pub fn create_api_server(
    config: Arc<Config>,
    metrics: Arc<ProxyMetrics>,
) -> Result<axum::Server<hyper::server::conn::AddrIncoming, Router>, Error> {
    // Create router with all routes
    let router = create_router(config.clone(), metrics)?;

    // Create server
    let address = config.api_address().parse()
        .map_err(|e| Error::Config(format!("Invalid API address: {}", e)))?;

    let server = axum::Server::bind(&address)
        .serve(router.into_make_service());

    Ok(server)
}

/// Create router with all API routes
fn create_router(
    config: Arc<Config>,
    metrics: Arc<ProxyMetrics>,
) -> Result<Router, Error> {
    // Get API path prefix
    let prefix = &config.api.path_prefix;

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
        .with_state(types::ApiState {
            config: config.clone(),
            metrics: metrics.clone(),
        });

    Ok(router)
}

// Helper function to create the API server
pub fn create_api_server_with_router(router: Router) -> Result<axum::Server<hyper::server::conn::AddrIncoming, Router>, Error> {
    // Create a default address
    let address = "0.0.0.0:8080".parse()
        .map_err(|e| Error::Config(format!("Invalid API address: {}", e)))?;

    let server = axum::Server::bind(&address)
        .serve(router.into_make_service());

    Ok(server)
}