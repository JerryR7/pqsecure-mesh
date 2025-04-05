use std::sync::Arc;
use std::net::SocketAddr;
use axum::Router;
use tokio::signal;
use tracing::{info, error, debug};

use crate::error::Error;
use crate::config::Config;
use crate::telemetry::ProxyMetrics;
use crate::api::routes;

/// API server configuration and runtime management
///
/// The `ApiServer` handles configuration, startup, and shutdown of the API server.
/// It provides methods for creating and running the server with proper signal handling.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use pqsecure_mesh::config::Config;
/// use pqsecure_mesh::telemetry::ProxyMetrics;
/// use pqsecure_mesh::api::server::ApiServer;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = Arc::new(Config::default());
///     let metrics = Arc::new(ProxyMetrics::new(true));
///
///     let server = ApiServer::new(config, metrics)?;
///     server.start_with_shutdown().await?;
///
///     Ok(())
/// }
/// ```
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
    /// Create a new API server with default configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Application configuration
    /// * `metrics` - Metrics collector
    ///
    /// # Returns
    ///
    /// A new configured API server instance
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be configured
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

    /// Create a new API server with custom router
    ///
    /// # Arguments
    ///
    /// * `config` - Application configuration
    /// * `metrics` - Metrics collector
    /// * `router` - Custom router instance
    ///
    /// # Returns
    ///
    /// A new API server instance with custom router
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be configured
    pub fn with_router(
        config: Arc<Config>,
        metrics: Arc<ProxyMetrics>,
        router: Router,
    ) -> Result<Self, Error> {
        // Parse API address
        let address = config.api_address().parse::<SocketAddr>()
            .map_err(|e| Error::Config(format!("Invalid API address: {}", e)))?;

        Ok(Self {
            config,
            metrics,
            address,
            router,
        })
    }

    /// Start the API server
    ///
    /// This method starts the server and blocks until it is shut down
    ///
    /// # Returns
    ///
    /// Ok if the server started and shut down successfully, an error otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start or encounters an error while running
    pub async fn start(&self) -> Result<(), Error> {
        info!("Starting API server on {}", self.address);

        // Serve the API
        let server = axum::Server::bind(&self.address)
            .serve(self.router.clone().into_make_service());

        if let Err(e) = server.await {
            error!("API server error: {}", e);
            return Err(Error::ApiServerError(e.to_string()));
        }

        Ok(())
    }

    /// Start the API server with graceful shutdown handling
    ///
    /// This method starts the server and waits for shutdown signals
    ///
    /// # Returns
    ///
    /// Ok if the server started and shut down successfully, an error otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start or encounters an error while running
    pub async fn start_with_shutdown(&self) -> Result<(), Error> {
        info!("Starting API server on {} with graceful shutdown", self.address);

        // Serve the API with graceful shutdown
        let server = axum::Server::bind(&self.address)
            .serve(self.router.clone().into_make_service());

        // Set up shutdown signal handler
        let shutdown_future = server.with_graceful_shutdown(Self::shutdown_signal());

        if let Err(e) = shutdown_future.await {
            error!("API server error: {}", e);
            return Err(Error::ApiServerError(e.to_string()));
        }

        info!("API server shut down gracefully");
        Ok(())
    }

    /// Wait for shutdown signal
    ///
    /// This method waits for CTRL+C or SIGTERM signals
    async fn shutdown_signal() {
        // Wait for either CTRL+C or SIGTERM
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
            debug!("Received Ctrl+C signal");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
            debug!("Received SIGTERM signal");
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        info!("Shutdown signal received, starting graceful shutdown");
    }

    /// Get the API address
    ///
    /// # Returns
    ///
    /// The socket address the server is listening on
    pub fn address(&self) -> &SocketAddr {
        &self.address
    }

    /// Get the router
    ///
    /// # Returns
    ///
    /// A clone of the router
    pub fn router(&self) -> Router {
        self.router.clone()
    }
}