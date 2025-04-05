use std::sync::Arc;
use std::net::SocketAddr;
use prometheus::{
    Registry, Gauge, GaugeVec, Counter, CounterVec, Histogram, HistogramVec,
    Opts, register_counter, register_counter_vec, register_gauge,
    register_gauge_vec, register_histogram, register_histogram_vec,
};
use tokio::task;
use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;

use crate::error::Error;
use crate::config::Config;

/// Metrics collector trait - defines the interface for metrics collection
#[async_trait]
pub trait MetricsCollector: Send + Sync {
    /// Record a request
    async fn record_request(&self, success: bool, time_ms: f64);

    /// Record a rejected request
    async fn record_rejected(&self) -> Result<(), Error>;

    /// Record a client connection
    async fn record_client_connection(&self, pqc: bool) -> Result<(), Error>;

    /// Record a client disconnection
    async fn record_client_disconnection(&self) -> Result<(), Error>;

    /// Record an upstream connection
    async fn record_upstream_connection(&self) -> Result<(), Error>;

    /// Record data transfer
    async fn record_data_transfer(&self, to_upstream: bool, bytes: usize) -> Result<(), Error>;

    /// Record CPU usage
    async fn record_cpu_usage(&self, usage: f64) -> Result<(), Error>;

    /// Record memory usage
    async fn record_memory_usage(&self, usage: f64) -> Result<(), Error>;

    /// Reset metrics
    async fn reset(&self) -> Result<(), Error>;
}

/// Basic metrics data structure
#[derive(Debug, Clone)]
pub struct MetricsData {
    /// Total number of requests
    pub total_requests: u64,
    /// Number of successful requests
    pub successful_requests: u64,
    /// Number of failed requests
    pub failed_requests: u64,
    /// Number of rejected requests
    pub rejected_requests: u64,
    /// Average request processing time (milliseconds)
    pub avg_request_time_ms: f64,
    /// Number of upstream connections
    pub upstream_connections: u64,
    /// Number of client connections
    pub client_connections: u64,
    /// Number of connections using PQC
    pub pqc_connections: u64,
    /// Current number of active connections
    pub active_connections: u64,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Bytes received from upstream
    pub upstream_received_bytes: u64,
    /// Bytes sent to upstream
    pub upstream_sent_bytes: u64,
    /// Last updated time
    pub last_updated_at: chrono::DateTime<chrono::Utc>,
}

impl Default for MetricsData {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            rejected_requests: 0,
            avg_request_time_ms: 0.0,
            upstream_connections: 0,
            client_connections: 0,
            pqc_connections: 0,
            active_connections: 0,
            total_bytes: 0,
            upstream_received_bytes: 0,
            upstream_sent_bytes: 0,
            last_updated_at: chrono::Utc::now(),
        }
    }
}

/// Default metrics collector implementation
pub struct DefaultMetricsCollector {
    /// Whether metrics collection is enabled
    enabled: bool,
    /// Metrics data
    data: RwLock<MetricsData>,
    /// Registry for prometheus metrics
    registry: Option<Registry>,
}

impl DefaultMetricsCollector {
    /// Create a new metrics collector
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            data: RwLock::new(MetricsData::default()),
            registry: if enabled { Some(Registry::new()) } else { None },
        }
    }

    /// Create a new metrics collector with configuration
    pub fn with_config(config: Arc<Config>) -> Result<Self, Error> {
        let enabled = config.telemetry.enable_metrics;
        let registry = if enabled { Some(Registry::new()) } else { None };

        Ok(Self {
            enabled,
            data: RwLock::new(MetricsData::default()),
            registry,
        })
    }

    /// Get the current metrics data
    pub async fn get_data(&self) -> MetricsData {
        self.data.read().await.clone()
    }

    /// Get the prometheus registry
    pub fn registry(&self) -> Option<&Registry> {
        self.registry.as_ref()
    }

    /// Start the metrics server
    pub async fn start_metrics_server(&self, config: Arc<Config>) -> Result<(), Error> {
        // Check if metrics collection is enabled
        if !config.telemetry.enable_metrics || self.registry.is_none() {
            return Ok(());
        }

        let addr = format!("{}:{}", "0.0.0.0", config.telemetry.metrics_port);
        let addr = addr.parse::<SocketAddr>()
            .map_err(|e| Error::Config(format!("Invalid metrics address: {}", e)))?;

        let registry = self.registry.as_ref().unwrap().clone();

        // Start the metrics server
        task::spawn(async move {
            let metrics_handler = || {
                let encoder = prometheus::TextEncoder::new();
                async {
                    let metric_families = registry.gather();
                    let mut buffer = Vec::new();
                    encoder.encode(&metric_families, &mut buffer).unwrap();
                    hyper::Response::builder()
                        .status(hyper::StatusCode::OK)
                        .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                        .body(hyper::Body::from(buffer))
                        .unwrap()
                }
            };

            let service = hyper::service::make_service_fn(|_| {
                async {
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |_| metrics_handler()))
                }
            });

            let server = hyper::Server::bind(&addr).serve(service);

            if let Err(e) = server.await {
                eprintln!("Metrics server error: {}", e);
            }
        });

        Ok(())
    }
}

#[async_trait]
impl MetricsCollector for DefaultMetricsCollector {
    async fn record_request(&self, success: bool, time_ms: f64) {
        if !self.enabled {
            return;
        }

        let mut data = self.data.write().await;
        data.total_requests += 1;

        if success {
            data.successful_requests += 1;
        } else {
            data.failed_requests += 1;
        }

        // Update average processing time
        let total = data.successful_requests + data.failed_requests;
        if total > 0 {
            data.avg_request_time_ms = ((data.avg_request_time_ms * (total - 1) as f64) + time_ms) / total as f64;
        }

        data.last_updated_at = chrono::Utc::now();
    }

    async fn record_rejected(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        let mut data = self.data.write().await;
        data.total_requests += 1;
        data.rejected_requests += 1;
        data.last_updated_at = chrono::Utc::now();

        Ok(())
    }

    async fn record_client_connection(&self, pqc: bool) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        let mut data = self.data.write().await;
        data.client_connections += 1;
        data.active_connections += 1;

        if pqc {
            data.pqc_connections += 1;
        }

        data.last_updated_at = chrono::Utc::now();

        Ok(())
    }

    async fn record_client_disconnection(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        let mut data = self.data.write().await;
        if data.active_connections > 0 {
            data.active_connections -= 1;
        }

        data.last_updated_at = chrono::Utc::now();

        Ok(())
    }

    async fn record_upstream_connection(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        let mut data = self.data.write().await;
        data.upstream_connections += 1;
        data.last_updated_at = chrono::Utc::now();

        Ok(())
    }

    async fn record_data_transfer(&self, to_upstream: bool, bytes: usize) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        let mut data = self.data.write().await;
        data.total_bytes += bytes as u64;

        if to_upstream {
            data.upstream_sent_bytes += bytes as u64;
        } else {
            data.upstream_received_bytes += bytes as u64;
        }

        data.last_updated_at = chrono::Utc::now();

        Ok(())
    }

    async fn record_cpu_usage(&self, usage: f64) -> Result<(), Error> {
        // In a real implementation, we would record this to a gauge
        Ok(())
    }

    async fn record_memory_usage(&self, usage: f64) -> Result<(), Error> {
        // In a real implementation, we would record this to a gauge
        Ok(())
    }

    async fn reset(&self) -> Result<(), Error> {
        let mut data = self.data.write().await;
        *data = MetricsData::default();

        Ok(())
    }
}

/// Create a prometheus based metrics collector
pub struct PrometheusMetricsCollector {
    /// Whether metrics collection is enabled
    enabled: bool,
    /// Registry
    registry: Registry,
    /// Number of active connections
    active_connections: GaugeVec,
    /// Total number of requests
    total_requests: CounterVec,
    /// Number of rejected requests
    rejected_requests: CounterVec,
    /// Request processing time
    request_duration: HistogramVec,
    /// Number of failed requests
    failed_requests: CounterVec,
    /// Number of bytes transferred
    transferred_bytes: CounterVec,
    /// System resources
    system_resources: GaugeVec,
    /// Days until certificate expiry
    cert_expiry_days: GaugeVec,
    /// Internal metrics data for queries
    data: RwLock<MetricsData>,
}

impl PrometheusMetricsCollector {
    /// Create a new prometheus metrics collector
    pub fn new(config: Arc<Config>) -> Result<Self, Error> {
        // Create metrics registry
        let registry = Registry::new();

        // Create metrics
        let active_connections = register_gauge_vec!(
            Opts::new("pqsm_active_connections", "Number of active connections"),
            &["tenant", "service", "protocol"],
            registry.clone(),
        )?;

        let total_requests = register_counter_vec!(
            Opts::new("pqsm_total_requests", "Total number of requests"),
            &["tenant", "service", "protocol", "method"],
            registry.clone(),
        )?;

        let rejected_requests = register_counter_vec!(
            Opts::new("pqsm_rejected_requests", "Number of rejected requests"),
            &["tenant", "service", "protocol", "reason"],
            registry.clone(),
        )?;

        let request_duration = register_histogram_vec!(
            Opts::new("pqsm_request_duration_seconds", "Request duration in seconds"),
            &["tenant", "service", "protocol", "method"],
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
            registry.clone(),
        )?;

        let failed_requests = register_counter_vec!(
            Opts::new("pqsm_failed_requests", "Number of failed requests"),
            &["tenant", "service", "protocol", "error_type"],
            registry.clone(),
        )?;

        let transferred_bytes = register_counter_vec!(
            Opts::new("pqsm_transferred_bytes", "Number of bytes transferred"),
            &["tenant", "service", "protocol", "direction"],
            registry.clone(),
        )?;

        let system_resources = register_gauge_vec!(
            Opts::new("pqsm_system_resources", "System resource usage"),
            &["tenant", "service", "resource_type"],
            registry.clone(),
        )?;

        let cert_expiry_days = register_gauge_vec!(
            Opts::new("pqsm_cert_expiry_days", "Days until certificate expiry"),
            &["tenant", "service", "cert_type"],
            registry.clone(),
        )?;

        Ok(Self {
            enabled: config.telemetry.enable_metrics,
            registry,
            active_connections,
            total_requests,
            rejected_requests,
            request_duration,
            failed_requests,
            transferred_bytes,
            system_resources,
            cert_expiry_days,
            data: RwLock::new(MetricsData::default()),
        })
    }

    /// Get the prometheus registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Start metrics server
    pub async fn start_metrics_server(&self, config: Arc<Config>) -> Result<(), Error> {
        // Check if metrics collection is enabled
        if !self.enabled {
            return Ok(());
        }

        let addr = format!("{}:{}", "0.0.0.0", config.telemetry.metrics_port);
        let addr = addr.parse::<SocketAddr>()
            .map_err(|e| Error::Config(format!("Invalid metrics address: {}", e)))?;

        let registry = self.registry.clone();

        // Start the metrics server
        task::spawn(async move {
            let metrics_handler = || {
                let encoder = prometheus::TextEncoder::new();
                async {
                    let metric_families = registry.gather();
                    let mut buffer = Vec::new();
                    encoder.encode(&metric_families, &mut buffer).unwrap();
                    hyper::Response::builder()
                        .status(hyper::StatusCode::OK)
                        .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                        .body(hyper::Body::from(buffer))
                        .unwrap()
                }
            };

            let service = hyper::service::make_service_fn(|_| {
                async {
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |_| metrics_handler()))
                }
            });

            let server = hyper::Server::bind(&addr).serve(service);

            if let Err(e) = server.await {
                eprintln!("Metrics server error: {}", e);
            }
        });

        Ok(())
    }

    /// Get current metrics data
    pub async fn get_data(&self) -> MetricsData {
        self.data.read().await.clone()
    }
}

#[async_trait]
impl MetricsCollector for PrometheusMetricsCollector {
    async fn record_request(&self, success: bool, time_ms: f64) {
        if !self.enabled {
            return;
        }

        // Update internal metrics data
        let mut data = self.data.write().await;
        data.total_requests += 1;

        if success {
            data.successful_requests += 1;
        } else {
            data.failed_requests += 1;
        }

        // Update average processing time
        let total = data.successful_requests + data.failed_requests;
        if total > 0 {
            data.avg_request_time_ms = ((data.avg_request_time_ms * (total - 1) as f64) + time_ms) / total as f64;
        }

        data.last_updated_at = chrono::Utc::now();

        // Update prometheus metrics (in a real implementation, we would also update tenant/service/protocol/method labels)
        self.total_requests
            .with_label_values(&["default", "default", "http", "default"])
            .inc();

        self.request_duration
            .with_label_values(&["default", "default", "http", "default"])
            .observe(time_ms / 1000.0); // Convert to seconds
    }

    async fn record_rejected(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update internal metrics data
        let mut data = self.data.write().await;
        data.total_requests += 1;
        data.rejected_requests += 1;
        data.last_updated_at = chrono::Utc::now();

        // Update prometheus metrics
        self.rejected_requests
            .with_label_values(&["default", "default", "http", "policy"])
            .inc();

        Ok(())
    }

    async fn record_client_connection(&self, pqc: bool) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update internal metrics data
        let mut data = self.data.write().await;
        data.client_connections += 1;
        data.active_connections += 1;

        if pqc {
            data.pqc_connections += 1;
        }

        data.last_updated_at = chrono::Utc::now();

        // Update prometheus metrics
        self.active_connections
            .with_label_values(&["default", "default", "http"])
            .set(data.active_connections as f64);

        Ok(())
    }

    async fn record_client_disconnection(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update internal metrics data
        let mut data = self.data.write().await;
        if data.active_connections > 0 {
            data.active_connections -= 1;
        }

        data.last_updated_at = chrono::Utc::now();

        // Update prometheus metrics
        self.active_connections
            .with_label_values(&["default", "default", "http"])
            .set(data.active_connections as f64);

        Ok(())
    }

    async fn record_upstream_connection(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update internal metrics data
        let mut data = self.data.write().await;
        data.upstream_connections += 1;
        data.last_updated_at = chrono::Utc::now();

        Ok(())
    }

    async fn record_data_transfer(&self, to_upstream: bool, bytes: usize) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update internal metrics data
        let mut data = self.data.write().await;
        data.total_bytes += bytes as u64;

        if to_upstream {
            data.upstream_sent_bytes += bytes as u64;
        } else {
            data.upstream_received_bytes += bytes as u64;
        }

        data.last_updated_at = chrono::Utc::now();

        // Update prometheus metrics
        let direction = if to_upstream { "upstream" } else { "downstream" };
        self.transferred_bytes
            .with_label_values(&["default", "default", "http", direction])
            .inc_by(bytes as f64);

        Ok(())
    }

    async fn record_cpu_usage(&self, usage: f64) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update prometheus metrics
        self.system_resources
            .with_label_values(&["default", "default", "cpu"])
            .set(usage);

        Ok(())
    }

    async fn record_memory_usage(&self, usage: f64) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update prometheus metrics
        self.system_resources
            .with_label_values(&["default", "default", "memory"])
            .set(usage);

        Ok(())
    }

    async fn reset(&self) -> Result<(), Error> {
        // Reset internal metrics data
        let mut data = self.data.write().await;
        *data = MetricsData::default();

        // Note: Prometheus doesn't allow resetting counters, this is just for the internal state

        Ok(())
    }
}