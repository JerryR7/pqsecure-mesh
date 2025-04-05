use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use crate::common::Error;

/// Represents a SPIFFE identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpiffeId {
    /// Full SPIFFE URI (e.g. "spiffe://tenant-a/service-b")
    pub uri: String,
    /// Tenant ID
    pub tenant: String,
    /// Service name
    pub service: String,
}

/// Represents a complete service identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIdentity {
    /// SPIFFE identity
    pub spiffe_id: SpiffeId,
    /// X.509 certificate PEM
    pub cert_pem: String,
    /// Private key PEM
    pub key_pem: String,
    /// Certificate chain PEM (optional)
    pub chain_pem: Option<String>,
    /// Certificate fingerprint
    pub fingerprint: String,
    /// Issued time
    pub issued_at: SystemTime,
    /// Expiration time
    pub expires_at: SystemTime,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Whether it is a post-quantum certificate
    pub is_post_quantum: bool,
}

/// Identity request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRequest {
    /// Service name
    pub service_name: String,
    /// Namespace/tenant
    pub namespace: String,
    /// DNS names
    pub dns_names: Vec<String>,
    /// IP addresses
    pub ip_addresses: Vec<String>,
    /// Request PQC
    pub request_pqc: bool,
}

/// Identity status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    /// Valid
    Valid,
    /// Revoked
    Revoked,
    /// Expired
    Expired,
    /// Unknown
    Unknown,
}

impl SpiffeId {
    /// Parse from SPIFFE URI
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        // Parse "spiffe://tenant-a/service-b" format
        let uri_obj = url::Url::parse(uri)
            .map_err(|e| Error::InvalidSpiffeId(format!("Invalid URI: {}", e)))?;

        if uri_obj.scheme() != "spiffe" {
            return Err(Error::InvalidSpiffeId("Invalid scheme, must be 'spiffe'".into()));
        }

        let host = uri_obj.host_str()
            .ok_or_else(|| Error::InvalidSpiffeId("Missing host component (tenant)".into()))?;

        let path = uri_obj.path();
        if path.is_empty() || path == "/" {
            return Err(Error::InvalidSpiffeId("Missing path component (service)".into()));
        }

        let service = path.trim_start_matches('/').to_string();

        Ok(Self {
            uri: uri.to_string(),
            tenant: host.to_string(),
            service,
        })
    }

    /// Create new SPIFFE ID
    pub fn new(tenant: &str, service: &str) -> Self {
        let uri = format!("spiffe://{}/{}", tenant, service);
        Self {
            uri,
            tenant: tenant.to_string(),
            service: service.to_string(),
        }
    }
}

impl ServiceIdentity {
    /// Check if identity is valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();
        now >= self.issued_at && now < self.expires_at
    }

    /// Get status
    pub fn status(&self) -> IdentityStatus {
        let now = SystemTime::now();

        if now < self.issued_at {
            // Certificate not yet valid
            IdentityStatus::Unknown
        } else if now >= self.expires_at {
            // Certificate expired
            IdentityStatus::Expired
        } else {
            // Certificate valid
            IdentityStatus::Valid
        }
    }

    /// Get remaining valid time percentage
    pub fn remaining_valid_percent(&self) -> f64 {
        let now = SystemTime::now();

        if now < self.issued_at {
            return 100.0;
        }

        if now >= self.expires_at {
            return 0.0;
        }

        // Calculate total duration and remaining duration
        let total_duration = match self.expires_at.duration_since(self.issued_at) {
            Ok(duration) => duration.as_secs_f64(),
            Err(_) => return 0.0,
        };

        let remaining_duration = match self.expires_at.duration_since(now) {
            Ok(duration) => duration.as_secs_f64(),
            Err(_) => return 0.0,
        };

        // Calculate percentage
        (remaining_duration / total_duration) * 100.0
    }

    /// Check if identity needs rotation
    pub fn needs_rotation(&self, threshold_pct: u8) -> bool {
        self.remaining_valid_percent() <= threshold_pct as f64
    }
}