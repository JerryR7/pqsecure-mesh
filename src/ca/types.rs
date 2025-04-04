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
    /// Certificate serial number
    pub serial: String,
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
    /// Expired certificate
    Expired {
        /// Expiration time
        expired_at: SystemTime,
    },
    /// Unknown/missing certificate
    Unknown,
}

/// Revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    /// Certificate serial number
    pub serial: String,
    /// Revocation reason
    pub reason: String,
}

/// Revocation reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Unspecified
    Unspecified = 0,
    /// Key compromise
    KeyCompromise = 1,
    /// CA compromise
    CACompromise = 2,
    /// Affiliation changed
    AffiliationChanged = 3,
    /// Superseded
    Superseded = 4,
    /// Cessation of operation
    CessationOfOperation = 5,
    /// Certificate hold
    CertificateHold = 6,
    /// Removed from CRL
    RemoveFromCRL = 8,
    /// Privilege withdrawn
    PrivilegeWithdrawn = 9,
    /// AA compromise
    AACompromise = 10,
}

impl RevocationReason {
    /// Convert from string to revocation reason
    pub fn from_str(reason: &str) -> Self {
        match reason.to_lowercase().as_str() {
            "unspecified" => Self::Unspecified,
            "keycompromise" | "key compromise" => Self::KeyCompromise,
            "cacompromise" | "ca compromise" => Self::CACompromise,
            "affiliationchanged" | "affiliation changed" => Self::AffiliationChanged,
            "superseded" => Self::Superseded,
            "cessationofoperation" | "cessation of operation" => Self::CessationOfOperation,
            "certificatehold" | "certificate hold" => Self::CertificateHold,
            "removefromcrl" | "remove from crl" => Self::RemoveFromCRL,
            "privilegewithdrawn" | "privilege withdrawn" => Self::PrivilegeWithdrawn,
            "aacompromise" | "aa compromise" => Self::AACompromise,
            _ => Self::Unspecified,
        }
    }
    
    /// Convert to string
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CACompromise => "cACompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::RemoveFromCRL => "removeFromCRL",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AACompromise => "aACompromise",
        }
    }
}