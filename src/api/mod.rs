pub mod server;
pub mod handlers;
pub mod routes;
pub mod types;
pub mod errors;
pub mod middlewares;

use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use crate::error::Error;
use crate::config::Config;
use crate::telemetry::ProxyMetrics;
use self::routes::create_router;

/// Creates an API server instance
///
/// # Arguments
///
/// * `config` - Application configuration
/// * `metrics` - Metrics collector
///
/// # Returns
///
/// A configured HTTP server ready to start
///
/// # Errors
///
/// Returns an error if the server cannot be created
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

/// Helper function to create the API server with a pre-configured router
///
/// This is useful for testing or when you need custom router configuration
///
/// # Arguments
///
/// * `router` - Pre-configured router
///
/// # Returns
///
/// A configured HTTP server ready to start
///
/// # Errors
///
/// Returns an error if the server cannot be created
pub fn create_api_server_with_router(router: Router) -> Result<axum::Server<hyper::server::conn::AddrIncoming, Router>, Error> {
    // Create a default address
    let address = "0.0.0.0:8080".parse()
        .map_err(|e| Error::Config(format!("Invalid API address: {}", e)))?;

    let server = axum::Server::bind(&address)
        .serve(router.into_make_service());

    Ok(server)
}