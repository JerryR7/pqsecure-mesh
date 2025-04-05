use std::time::SystemTime;
use serde::{Serialize, Deserialize};

/// Certificate request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// Service name (Common Name)
    pub service_name: String,
    /// Namespace/tenant
    pub namespace: String,
    /// List of DNS names
    pub dns_names: Vec<String>,
    /// List of IP addresses
    pub ip_addresses: Vec<String>,
    /// Request post-quantum cryptography
    pub request_pqc: bool,
    /// CSR (optional)
    pub csr: Option<String>,
}

/// Certificate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    /// Certificate PEM
    pub certificate: String,
    /// Private key PEM
    pub private_key: String,
    /// Certificate chain PEM (optional)
    pub certificate_chain: Option<String>,
    /// Certificate fingerprint
    pub fingerprint: String,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Whether it is a post-quantum certificate
    pub is_post_quantum: bool,
}

/// Certificate status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateStatus {
    /// Valid certificate
    Valid,
    /// Revoked certificate
    Revoked {
        /// Revocation reason
        reason: String,
        /// Revocation time
        revoked_at: SystemTime,
    },
    /// Unknown certificate
    Unknown,
}