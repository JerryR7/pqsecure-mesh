pub mod metrics;
pub mod logging;
pub mod tracing;

use std::sync::Arc;

use crate::error::Error;
use crate::config::Config;
use self::metrics::{MetricsCollector, DefaultMetricsCollector, PrometheusMetricsCollector, MetricsData};

/// Telemetry service
pub struct TelemetryService {
    /// Application configuration
    config: Arc<Config>,
    /// Metrics collector
    metrics: Arc<dyn MetricsCollector>,
}

impl TelemetryService {
    /// Create a new telemetry service with default metrics collector
    pub fn new(config: Arc<Config>) -> Self {
        let metrics = if config.telemetry.enable_metrics {
            match PrometheusMetricsCollector::new(config.clone()) {
                Ok(collector) => Arc::new(collector) as Arc<dyn MetricsCollector>,
                Err(_) => Arc::new(DefaultMetricsCollector::new(true)) as Arc<dyn MetricsCollector>,
            }
        } else {
            Arc::new(DefaultMetricsCollector::new(false)) as Arc<dyn MetricsCollector>
        };

        Self {
            config,
            metrics,
        }
    }

    /// Create a new telemetry service with a specific metrics collector
    pub fn with_metrics_collector<M: MetricsCollector + 'static>(
        config: Arc<Config>,
        metrics: Arc<M>,
    ) -> Self {
        Self {
            config,
            metrics,
        }
    }

    /// Initialize the telemetry service
    pub async fn init(&self) -> Result<(), Error> {
        // Initialize logging
        logging::init_logging(&self.config)?;

        // Initialize distributed tracing
        tracing::init_tracing(&self.config)?;

        // Start metrics server if using prometheus
        if self.config.telemetry.enable_metrics {
            if let Some(prometheus) = self.metrics.as_any().downcast_ref::<PrometheusMetricsCollector>() {
                prometheus.start_metrics_server(self.config.clone()).await?;
            } else if let Some(default) = self.metrics.as_any().downcast_ref::<DefaultMetricsCollector>() {
                default.start_metrics_server(self.config.clone()).await?;
            }
        }

        Ok(())
    }

    /// Get the metrics collector
    pub fn metrics(&self) -> Arc<dyn MetricsCollector> {
        self.metrics.clone()
    }

    /// Shutdown the telemetry service
    pub fn shutdown(&self) {
        // Shutdown the tracer
        tracing::shutdown_tracer();
    }
}

/// Extension trait to support downcasting
pub trait AsAny: Send + Sync {
    fn as_any(&self) -> &dyn std::any::Any;
}

impl<T: Send + Sync + 'static> AsAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Extend the MetricsCollector trait to include AsAny
pub trait MetricsCollectorExt: MetricsCollector + AsAny {}

impl<T: MetricsCollector + AsAny> MetricsCollectorExt for T {}

/// Set up telemetry and return a metrics collector
pub fn setup_telemetry(config: Arc<Config>) -> Result<Arc<dyn MetricsCollector>, Error> {
    // Create a metrics collector
    let metrics: Arc<dyn MetricsCollector> = if config.telemetry.enable_metrics {
        match PrometheusMetricsCollector::new(config.clone()) {
            Ok(collector) => Arc::new(collector),
            Err(_) => Arc::new(DefaultMetricsCollector::new(true)),
        }
    } else {
        Arc::new(DefaultMetricsCollector::new(false))
    };

    Ok(metrics)
}