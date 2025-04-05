use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use rand::Rng;
use tracing::{info, debug};

use crate::common::{Error, Result};
use crate::config::Settings;
use crate::ca::provider::CaProvider;
use crate::ca::types::{CertificateRequest, CertificateResponse, CertificateStatus};
use crate::crypto::pqc::PqcUtils;

/// Mock certificate information
#[derive(Debug, Clone)]
struct MockCertInfo {
    /// Certificate fingerprint
    fingerprint: String,
    /// Certificate PEM
    cert_pem: String,
    /// Private key PEM
    key_pem: String,
    /// Certificate chain PEM
    chain_pem: String,
    /// Issued time
    issued_at: SystemTime,
    /// Validity period
    validity: Duration,
    /// Whether the certificate is revoked
    revoked: bool,
    /// Revocation reason
    revocation_reason: Option<String>,
    /// Revocation time
    revoked_at: Option<SystemTime>,
}

/// Mock CA client for testing
pub struct MockCaClient {
    /// Application configuration
    config: Arc<Settings>,
    /// Issued certificates
    issued_certs: Mutex<HashMap<String, MockCertInfo>>,
}

impl MockCaClient {
    /// Create a new mock CA client
    pub fn new(config: Arc<Settings>) -> Self {
        Self {
            config,
            issued_certs: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a mock certificate
    fn generate_mock_certificate(
        req: &CertificateRequest,
        is_pqc: bool,
    ) -> String {
        let pqc_indicator = if is_pqc { "DILITHIUM" } else { "RSA" };
        let subject = format!("CN={}.{}", req.service_name, req.namespace);
        let spiffe_uri = format!("spiffe://{}/{}", req.namespace, req.service_name);

        format!(
            "-----BEGIN CERTIFICATE-----\n\
            MIIEXXXXXXXXXXXXXXXXXXXXXXXXX\n\
            Algorithm: {}\n\
            Subject: {}\n\
            URI: {}\n\
            -----END CERTIFICATE-----",
            pqc_indicator, subject, spiffe_uri
        )
    }

    /// Generate a mock private key
    fn generate_mock_private_key(is_pqc: bool) -> String {
        let pqc_indicator = if is_pqc { "DILITHIUM" } else { "RSA" };

        format!(
            "-----BEGIN PRIVATE KEY-----\n\
            MIIEXXXXXXXXXXXXXXXXXXXXXXXXX\n\
            Algorithm: {}\n\
            -----END PRIVATE KEY-----",
            pqc_indicator
        )
    }

    /// Generate a mock CA certificate
    fn generate_mock_ca_cert() -> String {
        "-----BEGIN CERTIFICATE-----\n\
        MIIEXXXXXXXXXXXXXXXXXXXXXXXXX\n\
        Subject: CN=Mock CA\n\
        -----END CERTIFICATE-----".to_string()
    }
}

#[async_trait]
impl CaProvider for MockCaClient {
    async fn request_certificate(&self, req: &CertificateRequest) -> Result<CertificateResponse> {
        debug!("Mock CA: Requesting certificate for {}/{}", req.namespace, req.service_name);

        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Determine whether to use PQC
        let is_pqc = req.request_pqc;

        // Generate mock certificate content
        let cert_pem = Self::generate_mock_certificate(req, is_pqc);
        let key_pem = Self::generate_mock_private_key(is_pqc);
        let chain_pem = Self::generate_mock_ca_cert();

        // Calculate fingerprint
        use md5::{Md5, Digest};
        let mut hasher = Md5::new();
        hasher.update(cert_pem.as_bytes());
        let fingerprint = format!("SHA256:{:x}", hasher.finalize());

        // Store certificate information
        let cert_info = MockCertInfo {
            fingerprint: fingerprint.clone(),
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            chain_pem: chain_pem.clone(),
            issued_at: SystemTime::now(),
            validity: Duration::from_secs(self.config.cert.cert_duration_hours * 3600),
            revoked: false,
            revocation_reason: None,
            revoked_at: None,
        };

        {
            let mut certs = self.issued_certs.lock().unwrap();
            certs.insert(fingerprint.clone(), cert_info);
        }

        // Return response
        Ok(CertificateResponse {
            certificate: cert_pem,
            private_key: key_pem,
            certificate_chain: Some(chain_pem),
            fingerprint,
            signature_algorithm: if is_pqc { "dilithium".to_string() } else { "rsa-sha256".to_string() },
            is_post_quantum: is_pqc,
        })
    }

    async fn revoke_certificate(&self, fingerprint: &str, reason: &str) -> Result<bool> {
        debug!("Mock CA: Revoking certificate with fingerprint {}", fingerprint);

        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut certs = self.issued_certs.lock().unwrap();

        if let Some(cert_info) = certs.get_mut(fingerprint) {
            cert_info.revoked = true;
            cert_info.revocation_reason = Some(reason.to_string());
            cert_info.revoked_at = Some(SystemTime::now());
            Ok(true)
        } else {
            // Certificate not found, but simulate success
            Ok(true)
        }
    }

    async fn check_certificate_status(&self, fingerprint: &str) -> Result<CertificateStatus> {
        debug!("Mock CA: Checking certificate status for fingerprint {}", fingerprint);

        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(30)).await;

        let certs = self.issued_certs.lock().unwrap();

        if let Some(cert_info) = certs.get(fingerprint) {
            if cert_info.revoked {
                return Ok(CertificateStatus::Revoked {
                    reason: cert_info.revocation_reason.clone().unwrap_or_else(|| "unknown".to_string()),
                    revoked_at: cert_info.revoked_at.unwrap_or_else(SystemTime::now),
                });
            }

            let now = SystemTime::now();
            let expiry = cert_info.issued_at + cert_info.validity;

            if now > expiry {
                return Ok(CertificateStatus::Unknown);
            }

            return Ok(CertificateStatus::Valid);
        }

        // Not found
        Ok(CertificateStatus::Unknown)
    }
}