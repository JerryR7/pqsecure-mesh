pub mod metrics;
pub mod logging;
pub mod tracing;

use std::sync::Arc;

use crate::error::Error;
use crate::config::Config;
use self::metrics::MetricsCollector;

/// Telemetry service
pub struct TelemetryService {
    /// Application configuration
    config: Arc<Config>,
    /// Metrics collector
    metrics: Option<MetricsCollector>,
}

impl TelemetryService {
    /// Create a new telemetry service
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            metrics: None,
        }
    }
    
    /// Initialize the telemetry service
    pub async fn init(&mut self) -> Result<(), Error> {
        // Initialize logging
        logging::init_logging(&self.config)?;
        
        // Initialize distributed tracing
        tracing::init_tracing(&self.config)?;
        
        // Initialize metrics collection
        if self.config.telemetry.enable_metrics {
            let metrics = MetricsCollector::new(self.config.clone())?;
            metrics.start_metrics_server().await?;
            self.metrics = Some(metrics);
        }
        
        Ok(())
    }
    
    /// Get the metrics collector
    pub fn metrics(&self) -> Option<&MetricsCollector> {
        self.metrics.as_ref()
    }
    
    /// Shutdown the telemetry service
    pub fn shutdown(&self) {
        // Shutdown the tracer
        tracing::shutdown_tracer();
    }
}

/// Set up the telemetry system
pub fn setup_telemetry(config: Arc<Config>) -> Result<Arc<ProxyMetrics>, Error> {
    // Create a proxy metrics collector
    let metrics = Arc::new(proxy::types::ProxyMetrics::new(
        config.telemetry.enable_metrics,
    ));
    
    Ok(metrics)
}

// Re-export key types
pub use crate::proxy::types::ProxyMetrics;