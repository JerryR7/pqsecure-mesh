use std::sync::Arc;
use std::net::SocketAddr;
use prometheus::{
    Registry, Gauge, GaugeVec, Counter, CounterVec,
    Opts, register_counter, register_counter_vec, register_gauge,
    register_gauge_vec,
};
use tokio::task;

use crate::common::{Error, Result};
use crate::config::Settings;

/// Metrics collector
pub struct MetricsCollector {
    /// Registry
    registry: Registry,
    /// Active connections
    active_connections: Gauge,
    /// Total connections
    total_connections: Counter,
    /// Total requests
    total_requests: Counter,
    /// Rejected requests
    rejected_requests: Counter,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        // Create metrics
        let active_connections = register_gauge!(
            Opts::new("pqsm_active_connections", "Number of active connections"),
            registry.clone()
        )?;

        let total_connections = register_counter!(
            Opts::new("pqsm_total_connections", "Total number of connections"),
            registry.clone()
        )?;

        let total_requests = register_counter!(
            Opts::new("pqsm_total_requests", "Total number of requests"),
            registry.clone()
        )?;

        let rejected_requests = register_counter!(
            Opts::new("pqsm_rejected_requests", "Number of rejected requests"),
            registry.clone()
        )?;

        Ok(Self {
            registry,
            active_connections,
            total_connections,
            total_requests,
            rejected_requests,
        })
    }

    /// Start metrics server
    pub fn start_metrics_server(self: Arc<Self>, config: Arc<Settings>) -> Result<()> {
        // Check if metrics collection is enabled
        if !config.telemetry.enable_metrics {
            return Ok(());
        }

        let addr = format!("0.0.0.0:{}", config.telemetry.metrics_port);
        let addr = addr.parse::<SocketAddr>()
            .map_err(|e| Error::Config(format!("Invalid metrics address: {}", e)))?;

        let registry = self.registry.clone();

        // Start the metrics server
        task::spawn(async move {
            let app = warp::path("metrics").map(move || {
                let encoder = prometheus::TextEncoder::new();
                let metric_families = registry.gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                String::from_utf8(buffer).unwrap()
            });

            warp::serve(app).run(addr).await;
        });

        Ok(())
    }

    /// Increment active connections
    pub fn inc_active_connections(&self) {
        self.active_connections.inc();
        self.total_connections.inc();
    }

    /// Decrement active connections
    pub fn dec_active_connections(&self) {
        self.active_connections.dec();
    }

    /// Increment total requests
    pub fn inc_total_requests(&self) {
        self.total_requests.inc();
    }

    /// Increment rejected requests
    pub fn inc_rejected_requests(&self) {
        self.rejected_requests.inc();
    }
}