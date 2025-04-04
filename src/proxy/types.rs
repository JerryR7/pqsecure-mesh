use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use crate::types::ProtocolType;

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
#[derive(Debug, Clone)]
pub struct ProxyMetrics {
    /// Proxy statistics
    pub stats: std::sync::Arc<tokio::sync::RwLock<ProxyStats>>,
    /// Whether metrics collection is enabled
    pub enabled: bool,
}

impl ProxyMetrics {
    /// Create a new metrics collector
    pub fn new(enabled: bool) -> Self {
        Self {
            stats: std::sync::Arc::new(tokio::sync::RwLock::new(ProxyStats::default())),
            enabled,
        }
    }
    
    /// Record a request
    pub async fn record_request(&self, success: bool, time_ms: f64) {
        if !self.enabled {
            return;
        }
        
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
    }
    
    /// Record a rejected request
    pub async fn record_rejected(&self) {
        if !self.enabled {
            return;
        }
        
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.rejected_requests += 1;
        stats.last_updated_at = chrono::Utc::now();
    }
    
    /// Record a client connection
    pub async fn record_client_connection(&self, pqc: bool) {
        if !self.enabled {
            return;
        }
        
        let mut stats = self.stats.write().await;
        stats.client_connections += 1;
        stats.active_connections += 1;
        
        if pqc {
            stats.pqc_connections += 1;
        }
        
        stats.last_updated_at = chrono::Utc::now();
    }
    
    /// Record a client disconnection
    pub async fn record_client_disconnection(&self) {
        if !self.enabled {
            return;
        }
        
        let mut stats = self.stats.write().await;
        if stats.active_connections > 0 {
            stats.active_connections -= 1;
        }
        
        stats.last_updated_at = chrono::Utc::now();
    }
    
    /// Record an upstream connection
    pub async fn record_upstream_connection(&self) {
        if !self.enabled {
            return;
        }
        
        let mut stats = self.stats.write().await;
        stats.upstream_connections += 1;
        stats.last_updated_at = chrono::Utc::now();
    }
    
    /// Record data transfer
    pub async fn record_data_transfer(&self, to_upstream: bool, bytes: usize) {
        if !self.enabled {
            return;
        }
        
        let mut stats = self.stats.write().await;
        stats.total_bytes += bytes as u64;
        
        if to_upstream {
            stats.upstream_sent_bytes += bytes as u64;
        } else {
            stats.upstream_received_bytes += bytes as u64;
        }
        
        stats.last_updated_at = chrono::Utc::now();
    }
    
    /// Get current statistics
    pub async fn get_stats(&self) -> ProxyStats {
        self.stats.read().await.clone()
    }
    
    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = ProxyStats::default();
    }
}