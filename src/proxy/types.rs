use serde::{Serialize, Deserialize};
use crate::common::ProtocolType;

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
    /// Protocol type (HTTP, gRPC)
    pub protocol: ProtocolType,
    /// mTLS configuration
    pub mtls_config: MtlsConfig,
}

/// mTLS configuration
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Enable mTLS
    pub enable_mtls: bool,
    /// Enable post-quantum cryptography
    pub enable_pqc: bool,
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
    /// Number of client connections
    pub client_connections: u64,
    /// Number of active connections
    pub active_connections: u64,
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
            client_connections: 0,
            active_connections: 0,
            last_updated_at: chrono::Utc::now(),
        }
    }
}

/// Metrics collector for the proxy
#[derive(Clone)]
pub struct ProxyMetrics {
    /// Statistics
    stats: Arc<tokio::sync::RwLock<ProxyStats>>,
}

impl ProxyMetrics {
    /// Create a new proxy metrics collector
    pub fn new() -> Self {
        Self {
            stats: Arc::new(tokio::sync::RwLock::new(ProxyStats::default())),
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> ProxyStats {
        self.stats.read().await.clone()
    }

    /// Record request
    pub async fn record_request(&self, success: bool) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;

        if success {
            stats.successful_requests += 1;
        } else {
            stats.failed_requests += 1;
        }

        stats.last_updated_at = chrono::Utc::now();
    }

    /// Record rejected request
    pub async fn record_rejected(&self) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.rejected_requests += 1;
        stats.last_updated_at = chrono::Utc::now();
    }

    /// Record client connection
    pub async fn record_client_connection(&self) {
        let mut stats = self.stats.write().await;
        stats.client_connections += 1;
        stats.active_connections += 1;
        stats.last_updated_at = chrono::Utc::now();
    }

    /// Record client disconnection
    pub async fn record_client_disconnection(&self) {
        let mut stats = self.stats.write().await;
        if stats.active_connections > 0 {
            stats.active_connections -= 1;
        }
        stats.last_updated_at = chrono::Utc::now();
    }
}