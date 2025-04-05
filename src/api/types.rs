use std::sync::Arc;
use serde::{Serialize, Deserialize};
use crate::config::Config;
use crate::telemetry::ProxyMetrics;
use crate::identity::types::{SpiffeId, ServiceIdentity, IdentityStatus};
use crate::policy::AccessPolicy;

/// API state shared between handlers
#[derive(Clone)]
pub struct ApiState {
    /// Application configuration
    pub config: Arc<Config>,
    /// Metrics collector
    pub metrics: Arc<ProxyMetrics>,
}

/// API response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Success status
    pub success: bool,
    /// Response data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    /// Create a success response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    /// Create an error response
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Identity request payload
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityRequest {
    /// Service name
    pub service_name: String,
    /// Namespace/tenant (optional, defaults to 'default')
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// DNS names (optional)
    #[serde(default)]
    pub dns_names: Vec<String>,
    /// IP addresses (optional)
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    /// Enable post-quantum cryptography (optional)
    #[serde(default)]
    pub pqc_enabled: bool,
}

/// Default namespace function
fn default_namespace() -> String {
    "default".to_string()
}

/// Identity response
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityResponse {
    /// SPIFFE ID
    pub spiffe_id: String,
    /// Fingerprint
    pub fingerprint: String,
    /// Serial number
    pub serial: String,
    /// Issued time
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// Expiration time
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Certificate PEM (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    /// Private key PEM (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
}

/// Identity revocation request
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeRequest {
    /// SPIFFE ID to revoke
    pub spiffe_id: String,
    /// Revocation reason
    pub reason: String,
}

/// Identity check request
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckRequest {
    /// SPIFFE ID to check
    pub spiffe_id: String,
}

/// Identity check response
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResponse {
    /// SPIFFE ID
    pub spiffe_id: String,
    /// Status
    pub status: IdentityStatus,
    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Serial number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

/// Convert from ServiceIdentity to IdentityResponse
impl From<ServiceIdentity> for IdentityResponse {
    fn from(identity: ServiceIdentity) -> Self {
        Self {
            spiffe_id: identity.spiffe_id.uri,
            fingerprint: identity.fingerprint,
            serial: identity.serial,
            issued_at: chrono::DateTime::<chrono::Utc>::from(identity.issued_at),
            expires_at: chrono::DateTime::<chrono::Utc>::from(identity.expires_at),
            cert_pem: Some(identity.cert_pem),
            key_pem: Some(identity.key_pem),
        }
    }
}

/// Policy request payload
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// Tenant ID
    pub tenant: String,
}

/// Health response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Status
    pub status: String,
    /// Version
    pub version: String,
    /// Uptime in seconds
    pub uptime: u64,
}

/// Metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    /// Total requests
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Client connections
    pub client_connections: u64,
    /// Active connections
    pub active_connections: u64,
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Last updated time
    pub last_updated_at: chrono::DateTime<chrono::Utc>,
}