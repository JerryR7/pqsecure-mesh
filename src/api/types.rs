use std::sync::Arc;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

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
///
/// Standard response format for all API endpoints
/// providing a consistent structure with success flag
/// and optional data/error fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Success status
    pub success: bool,
    /// Response data (present when success is true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Error message (present when success is false)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    /// Create a success response with data
    ///
    /// # Arguments
    ///
    /// * `data` - The data to include in the response
    ///
    /// # Returns
    ///
    /// A new ApiResponse with success flag set to true and the provided data
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    /// Create an error response
    ///
    /// # Arguments
    ///
    /// * `message` - The error message
    ///
    /// # Returns
    ///
    /// A new ApiResponse with success flag set to false and the provided error message
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            timestamp: Utc::now(),
        }
    }
}

/// Identity request payload
///
/// Used to request a new service identity
#[derive(Debug, Clone, Serialize, Deserialize)]
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
///
/// Contains information about a provisioned identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityResponse {
    /// SPIFFE ID
    pub spiffe_id: String,
    /// Fingerprint
    pub fingerprint: String,
    /// Serial number
    pub serial: String,
    /// Issued time
    pub issued_at: DateTime<Utc>,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// Certificate PEM (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    /// Private key PEM (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
}

/// Identity revocation request
///
/// Used to revoke an existing identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    /// SPIFFE ID to revoke
    pub spiffe_id: String,
    /// Revocation reason
    pub reason: String,
}

/// Identity check request
///
/// Used to check the status of an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRequest {
    /// SPIFFE ID to check
    pub spiffe_id: String,
}

/// Identity check response
///
/// Contains status information about an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResponse {
    /// SPIFFE ID
    pub spiffe_id: String,
    /// Status
    pub status: IdentityStatus,
    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
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
            issued_at: DateTime::<Utc>::from(identity.issued_at),
            expires_at: DateTime::<Utc>::from(identity.expires_at),
            cert_pem: Some(identity.cert_pem),
            key_pem: Some(identity.key_pem),
        }
    }
}

/// Policy request payload
///
/// Used to request a policy for a specific tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// Tenant ID
    pub tenant: String,
}

/// Health response
///
/// Contains basic health information about the service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Status
    pub status: String,
    /// Version
    pub version: String,
    /// Uptime in seconds
    pub uptime: u64,
}

/// Metrics response
///
/// Contains system metrics information
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub last_updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let data = "test data";
        let response = ApiResponse::success(data);

        assert!(response.success);
        assert_eq!(response.data, Some(data));
        assert_eq!(response.error, None);
    }

    #[test]
    fn test_api_response_error() {
        let error = "test error";
        let response = ApiResponse::<()>::error(error);

        assert!(!response.success);
        assert_eq!(response.data, None);
        assert_eq!(response.error, Some(error.to_string()));
    }

    #[test]
    fn test_default_namespace() {
        assert_eq!(default_namespace(), "default");
    }

    #[test]
    fn test_identity_response_from_service_identity() {
        let now = SystemTime::now();
        let expires = now + std::time::Duration::from_secs(3600);

        let service_identity = ServiceIdentity {
            spiffe_id: SpiffeId {
                uri: "spiffe://test/service".to_string(),
                tenant: "test".to_string(),
                service: "service".to_string(),
            },
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            chain_pem: Some("chain".to_string()),
            fingerprint: "fingerprint".to_string(),
            issued_at: now,
            expires_at: expires,
            signature_algorithm: "algorithm".to_string(),
            is_post_quantum: true,
            serial: "serial".to_string(),
        };

        let response = IdentityResponse::from(service_identity);

        assert_eq!(response.spiffe_id, "spiffe://test/service");
        assert_eq!(response.fingerprint, "fingerprint");
        assert_eq!(response.serial, "serial");
        assert_eq!(response.cert_pem, Some("cert".to_string()));
        assert_eq!(response.key_pem, Some("key".to_string()));
    }
}