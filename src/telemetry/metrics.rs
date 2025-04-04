use std::sync::Arc;
use std::net::SocketAddr;
use prometheus::{
    Registry, Gauge, GaugeVec, Counter, CounterVec, Histogram, HistogramVec,
    Opts, register_counter, register_counter_vec, register_gauge,
    register_gauge_vec, register_histogram, register_histogram_vec,
};
use tokio::task;

use crate::error::Error;
use crate::config::Config;

/// Metrics collector
#[derive(Clone)]
pub struct MetricsCollector {
    /// Application configuration
    config: Arc<Config>,
    /// Metrics registry
    registry: Arc<Registry>,
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
    /// System resource usage
    system_resources: GaugeVec,
    /// Days until certificate expiry
    cert_expiry_days: GaugeVec,
    /// Service status
    service_status: GaugeVec,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: Arc<Config>) -> Result<Self, Error> {
        // Create metrics registry
        let registry = Registry::new();
        
        // Create metrics
        let active_connections = register_gauge_vec!(
            Opts::new("pqsm_active_connections", "Number of active connections"),
            &["tenant", "service", "protocol"]
        )?;
        
        let total_requests = register_counter_vec!(
            Opts::new("pqsm_total_requests", "Total number of requests"),
            &["tenant", "service", "protocol", "method"]
        )?;
        
        let rejected_requests = register_counter_vec!(
            Opts::new("pqsm_rejected_requests", "Number of rejected requests"),
            &["tenant", "service", "protocol", "reason"]
        )?;
        
        let request_duration = register_histogram_vec!(
            Opts::new("pqsm_request_duration_seconds", "Request duration in seconds"),
            &["tenant", "service", "protocol", "method"],
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
        )?;
        
        let failed_requests = register_counter_vec!(
            Opts::new("pqsm_failed_requests", "Number of failed requests"),
            &["tenant", "service", "protocol", "error_type"]
        )?;
        
        let transferred_bytes = register_counter_vec!(
            Opts::new("pqsm_transferred_bytes", "Number of bytes transferred"),
            &["tenant", "service", "protocol", "direction"]
        )?;
        
        let system_resources = register_gauge_vec!(
            Opts::new("pqsm_system_resources", "System resource usage"),
            &["tenant", "service", "resource_type"]
        )?;
        
        let cert_expiry_days = register_gauge_vec!(
            Opts::new("pqsm_cert_expiry_days", "Days until certificate expiry"),
            &["tenant", "service", "cert_type"]
        )?;
        
        let service_status = register_gauge_vec!(
            Opts::new("pqsm_service_status", "Service status (1 = healthy, 0 = unhealthy)"),
            &["tenant", "service"]
        )?;
        
        // Register metrics
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(total_requests.clone()))?;
        registry.register(Box::new(rejected_requests.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(failed_requests.clone()))?;
        registry.register(Box::new(transferred_bytes.clone()))?;
        registry.register(Box::new(system_resources.clone()))?;
        registry.register(Box::new(cert_expiry_days.clone()))?;
        registry.register(Box::new(service_status.clone()))?;
        
        Ok(Self {
            config,
            registry: Arc::new(registry),
            active_connections,
            total_requests,
            rejected_requests,
            request_duration,
            failed_requests,
            transferred_bytes,
            system_resources,
            cert_expiry_days,
            service_status,
        })
    }
    
    /// Record the number of active connections
    pub fn record_active_connections(&self, tenant: &str, service: &str, protocol: &str, count: i64) {
        self.active_connections
            .with_label_values(&[tenant, service, protocol])
            .set(count as f64);
    }
    
    /// Record a request
    pub fn record_request(&self, tenant: &str, service: &str, protocol: &str, method: &str) {
        self.total_requests
            .with_label_values(&[tenant, service, protocol, method])
            .inc();
    }
    
    /// Record request processing time
    pub fn record_request_duration(&self, tenant: &str, service: &str, protocol: &str, method: &str, duration_seconds: f64) {
        self.request_duration
            .with_label_values(&[tenant, service, protocol, method])
            .observe(duration_seconds);
    }
    
    /// Record a rejected request
    pub fn record_rejected_request(&self, tenant: &str, service: &str, protocol: &str, reason: &str) {
        self.rejected_requests
            .with_label_values(&[tenant, service, protocol, reason])
            .inc();
    }
    
    /// Record a failed request
    pub fn record_failed_request(&self, tenant: &str, service: &str, protocol: &str, error_type: &str) {
        self.failed_requests
            .with_label_values(&[tenant, service, protocol, error_type])
            .inc();
    }
    
    /// Record the number of bytes transferred
    pub fn record_transferred_bytes(&self, tenant: &str, service: &str, protocol: &str, direction: &str, bytes: u64) {
        self.transferred_bytes
            .with_label_values(&[tenant, service, protocol, direction])
            .inc_by(bytes as f64);
    }
    
    /// Record system resource usage
    pub fn record_system_resource(&self, tenant: &str, service: &str, resource_type: &str, value: f64) {
        self.system_resources
            .with_label_values(&[tenant, service, resource_type])
            .set(value);
    }
    
    /// Record the number of days until certificate expiry
    pub fn record_cert_expiry_days(&self, tenant: &str, service: &str, cert_type: &str, days: f64) {
        self.cert_expiry_days
            .with_label_values(&[tenant, service, cert_type])
            .set(days);
    }
    
    /// Record service status
    pub fn record_service_status(&self, tenant: &str, service: &str, healthy: bool) {
        self.service_status
            .with_label_values(&[tenant, service])
            .set(if healthy { 1.0 } else { 0.0 });
    }
    
    /// Get the metrics registry
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }
    
    /// Start the metrics server
    pub async fn start_metrics_server(&self) -> Result<(), Error> {
        // Check if metrics collection is enabled
        if !self.config.telemetry.enable_metrics {
            return Ok(());
        }
        
        let addr = format!("{}:{}", "0.0.0.0", self.config.telemetry.metrics_port);
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
    
    /// Record CPU usage
    pub fn record_cpu_usage(&self, tenant: &str, service: &str, usage: f64) {
        self.record_system_resource(tenant, service, "cpu", usage);
    }
    
    /// Record memory usage
    pub fn record_memory_usage(&self, tenant: &str, service: &str, usage: f64) {
        self.record_system_resource(tenant, service, "memory", usage);
    }
    
    /// Record disk usage
    pub fn record_disk_usage(&self, tenant: &str, service: &str, usage: f64) {
        self.record_system_resource(tenant, service, "disk", usage);
    }
    
    /// Record certificate status
    pub fn update_cert_metrics(&self, tenant: &str, service: &str, expiry_days: f64) {
        self.record_cert_expiry_days(tenant, service, "main", expiry_days);
    }
}