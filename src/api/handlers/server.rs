use std::sync::Arc;
use std::net::SocketAddr;
use axum::Router;
use tracing::{info, error};

use crate::error::Error;
use crate::config::Config;
use crate::telemetry::ProxyMetrics;
use crate::api::routes;

/// API server
pub struct ApiServer {
    /// Application configuration
    config: Arc<Config>,
    /// Metrics collector
    metrics: Arc<ProxyMetrics>,
    /// Listening address
    address: SocketAddr,
    /// Router
    router: Router,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(
        config: Arc<Config>,
        metrics: Arc<ProxyMetrics>,
    ) -> Result<Self, Error> {
        // Parse API address
        let address = config.api_address().parse::<SocketAddr>()
            .map_err(|e| Error::Config(format!("Invalid API address: {}", e)))?;
        
        // Create router
        let router = routes::create_router(config.clone(), metrics.clone())?;
        
        Ok(Self {
            config,
            metrics,
            address,
            router,
        })
    }
    
    /// Start the API server
    pub async fn start(self) -> Result<(), Error> {
        info!("Starting API server on {}", self.address);
        
        // Serve the API
        let server = axum::Server::bind(&self.address)
            .serve(self.router.into_make_service());
        
        if let Err(e) = server.await {
            error!("API server error: {}", e);
            return Err(Error::ApiServerError(e.to_string()));
        }
        
        Ok(())
    }
    
    /// Get the API address
    pub fn address(&self) -> &SocketAddr {
        &self.address
    }
}