use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::types::ProtocolType;
use crate::error::Error;
use crate::telemetry::metrics::{MetricsCollector};
use crate::telemetry::AsAny;

/// Sidecar configuration
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Sidecar listening address
    pub listen_addr: String,
    /// Sidecar listening port
    pub listen_port: u16,
    /// Upstream service address
    pub upstream_addr: String,
    /// Upstream service port
    pub upstream_port: u16,
    /// Tenant ID
    pub tenant_id: String,
    /// Service ID
    pub service_id: String,
    /// Protocol type (HTTP, gRPC, TCP)
    pub protocol: ProtocolType,
    /// mTLS configuration
    pub mtls_config: MtlsConfig,
    /// Policy configuration
    pub policy_config: PolicyConfig,
}

/// mTLS configuration
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Enable mTLS
    pub enable_mtls: bool,
    /// Enable post-quantum cryptography
    pub enable_pqc: bool,
}

/// Policy configuration
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Policy file path
    pub policy_path: PathBuf,
}

/// Proxy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
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

impl Default for ProxyStats {
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

/// Proxy metrics collector
#[derive(Clone)]
pub struct ProxyMetrics {
    /// Base metrics collector
    base: Arc<dyn MetricsCollector>,
    /// Proxy statistics for direct querying
    stats: Arc<RwLock<ProxyStats>>,
    /// Whether metrics collection is enabled
    enabled: bool,
}

impl ProxyMetrics {
    /// Create a new proxy metrics collector
    pub fn new(enabled: bool) -> Self {
        Self {
            base: Arc::new(crate::telemetry::metrics::DefaultMetricsCollector::new(enabled)),
            stats: Arc::new(RwLock::new(ProxyStats::default())),
            enabled,
        }
    }

    /// Create a new proxy metrics collector with a base collector
    pub fn with_base_collector<M: MetricsCollector + 'static>(base: Arc<M>) -> Self {
        Self {
            base,
            stats: Arc::new(RwLock::new(ProxyStats::default())),
            enabled: true,
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> ProxyStats {
        self.stats.read().await.clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) -> Result<(), Error> {
        let mut stats = self.stats.write().await;
        *stats = ProxyStats::default();
        self.base.reset().await?;
        Ok(())
    }
}

impl AsAny for ProxyMetrics {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[async_trait]
impl MetricsCollector for ProxyMetrics {
    async fn record_request(&self, success: bool, time_ms: f64) {
        if !self.enabled {
            return;
        }

        // Update local stats
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;

        if success {
            stats.successful_requests += 1;
        } else {
            stats.failed_requests += 1;
        }

        // Update average processing time
        let total = stats.successful_requests + stats.failed_requests;
        if total > 0 {
            stats.avg_request_time_ms = ((stats.avg_request_time_ms * (total - 1) as f64) + time_ms) / total as f64;
        }

        stats.last_updated_at = chrono::Utc::now();

        // Forward to base collector
        self.base.record_request(success, time_ms).await;
    }

    async fn record_rejected(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update local stats
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.rejected_requests += 1;
        stats.last_updated_at = chrono::Utc::now();

        // Forward to base collector
        self.base.record_rejected().await
    }

    async fn record_client_connection(&self, pqc: bool) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update local stats
        let mut stats = self.stats.write().await;
        stats.client_connections += 1;
        stats.active_connections += 1;

        if pqc {
            stats.pqc_connections += 1;
        }

        stats.last_updated_at = chrono::Utc::now();

        // Forward to base collector
        self.base.record_client_connection(pqc).await
    }

    async fn record_client_disconnection(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update local stats
        let mut stats = self.stats.write().await;
        if stats.active_connections > 0 {
            stats.active_connections -= 1;
        }

        stats.last_updated_at = chrono::Utc::now();

        // Forward to base collector
        self.base.record_client_disconnection().await
    }

    async fn record_upstream_connection(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update local stats
        let mut stats = self.stats.write().await;
        stats.upstream_connections += 1;
        stats.last_updated_at = chrono::Utc::now();

        // Forward to base collector
        self.base.record_upstream_connection().await
    }

    async fn record_data_transfer(&self, to_upstream: bool, bytes: usize) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        // Update local stats
        let mut stats = self.stats.write().await;
        stats.total_bytes += bytes as u64;

        if to_upstream {
            stats.upstream_sent_bytes += bytes as u64;
        } else {
            stats.upstream_received_bytes += bytes as u64;
        }

        stats.last_updated_at = chrono::Utc::now();

        // Forward to base collector
        self.base.record_data_transfer(to_upstream, bytes).await
    }

    async fn record_cpu_usage(&self, usage: f64) -> Result<(), Error> {
        // Forward to base collector
        self.base.record_cpu_usage(usage).await
    }

    async fn record_memory_usage(&self, usage: f64) -> Result<(), Error> {
        // Forward to base collector
        self.base.record_memory_usage(usage).await
    }

    async fn reset(&self) -> Result<(), Error> {
        // Reset local stats
        let mut stats = self.stats.write().await;
        *stats = ProxyStats::default();

        // Forward to base collector
        self.base.reset().await
    }
}