use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use rand::Rng;
use tracing::{info, debug};

use crate::config::Config;
use crate::error::Error;
use crate::ca::provider::CaProvider;
use crate::ca::types::{CertificateRequest, CertificateResponse, CertificateStatus};
use crate::crypto::pqc::PqcUtils;

/// Mock certificate information
#[derive(Debug, Clone)]
struct MockCertInfo {
    /// Certificate serial number
    serial: String,
    /// Certificate PEM
    cert_pem: String,
    /// Issued time
    issued_at: SystemTime,
    /// Validity period (seconds)
    validity: Duration,
    /// Whether the certificate is revoked
    revoked: bool,
    /// Revocation reason
    revocation_reason: Option<String>,
    /// Revocation time
    revoked_at: Option<SystemTime>,
}

/// Mock CA client
pub struct MockCaClient {
    /// Application configuration
    config: Arc<Config>,
    /// Issued certificates
    issued_certs: Mutex<HashMap<String, MockCertInfo>>,
}

impl MockCaClient {
    /// Create a new mock CA client
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            issued_certs: Mutex::new(HashMap::new()),
        }
    }
    
    /// Generate a random serial number
    fn generate_serial() -> String {
        let mut rng = rand::thread_rng();
        let serial = format!("MOCK{:016X}", rng.r#gen::<u64>());
        serial
    }
    
    /// Generate a mock certificate
    fn generate_mock_certificate(
        req: &CertificateRequest,
        serial: &str,
        is_pqc: bool,
    ) -> String {
        let pqc_indicator = if is_pqc { "DILITHIUM" } else { "RSA" };
        let subject = format!("CN={}.{}", req.service_name, req.namespace);
        let spiffe_uri = format!("spiffe://{}/{}", req.namespace, req.service_name);
        
        format!(
            "-----BEGIN CERTIFICATE-----\n\
            MIIEpDCCAowCCQDMlK8ZNZ1OgDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n\
            b2NhbGhvc3QwHhcNMjAwMzI5MTkyNDQwWhcNMjEwMzI5MTkyNDQwWjAUMRIwEAYD\n\
            Serial: {}\n\
            Algorithm: {}\n\
            Subject: {}\n\
            URI: {}\n\
            -----END CERTIFICATE-----",
            serial, pqc_indicator, subject, spiffe_uri
        )
    }
    
    /// Generate a mock private key
    fn generate_mock_private_key(is_pqc: bool) -> String {
        let pqc_indicator = if is_pqc { "DILITHIUM" } else { "RSA" };
        
        format!(
            "-----BEGIN PRIVATE KEY-----\n\
            MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj\n\
            Algorithm: {}\n\
            ... (truncated) ...\n\
            -----END PRIVATE KEY-----",
            pqc_indicator
        )
    }
    
    /// Generate a mock CA certificate
    fn generate_mock_ca_cert() -> String {
        "-----BEGIN CERTIFICATE-----\n\
        MIIEpDCCAowCCQDMlK8ZNZ1OgDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n\
        b2NhbGhvc3QwHhcNMjAwMzI5MTkyNDQwWhcNMjEwMzI5MTkyNDQwWjAUMRIwEAYD\n\
        VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7\n\
        MOCK CA CERTIFICATE\n\
        -----END CERTIFICATE-----".to_string()
    }
}

#[async_trait]
impl CaProvider for MockCaClient {
    async fn request_certificate(&self, req: &CertificateRequest) -> Result<CertificateResponse, Error> {
        debug!("Mock CA: Requesting certificate for {}/{}", req.namespace, req.service_name);
        
        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        // Generate a random serial number
        let serial = Self::generate_serial();
        
        // Determine whether to use PQC
        let is_pqc = req.request_pqc;
        
        // Generate mock certificate content
        let cert_pem = Self::generate_mock_certificate(req, &serial, is_pqc);
        let key_pem = Self::generate_mock_private_key(is_pqc);
        let ca_pem = Self::generate_mock_ca_cert();
        
        // Store certificate information
        let cert_info = MockCertInfo {
            serial: serial.clone(),
            cert_pem: cert_pem.clone(),
            issued_at: SystemTime::now(),
            validity: Duration::from_secs(self.config.cert.cert_duration_hours * 3600),
            revoked: false,
            revocation_reason: None,
            revoked_at: None,
        };
        
        {
            let mut certs = self.issued_certs.lock().unwrap();
            certs.insert(serial.clone(), cert_info);
        }
        
        // Return response
        Ok(CertificateResponse {
            certificate: cert_pem,
            private_key: key_pem,
            certificate_chain: Some(ca_pem),
            fingerprint: format!("SHA256:{:x}", md5::compute(&serial)),
            serial,
            signature_algorithm: if is_pqc { "dilithium".to_string() } else { "rsa-sha256".to_string() },
            is_post_quantum: is_pqc,
        })
    }
    
    async fn revoke_certificate(&self, serial: &str, reason: &str) -> Result<bool, Error> {
        debug!("Mock CA: Revoking certificate with serial {}", serial);
        
        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(300)).await;
        
        let mut certs = self.issued_certs.lock().unwrap();
        
        if let Some(cert_info) = certs.get_mut(serial) {
            cert_info.revoked = true;
            cert_info.revocation_reason = Some(reason.to_string());
            cert_info.revoked_at = Some(SystemTime::now());
            Ok(true)
        } else {
            // Certificate not found, but simulate success
            Ok(true)
        }
    }
    
    async fn check_certificate_status(&self, serial: &str) -> Result<CertificateStatus, Error> {
        debug!("Mock CA: Checking certificate status for serial {}", serial);
        
        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        let certs = self.issued_certs.lock().unwrap();
        
        if let Some(cert_info) = certs.get(serial) {
            if cert_info.revoked {
                return Ok(CertificateStatus::Revoked {
                    reason: cert_info.revocation_reason.clone().unwrap_or_else(|| "unknown".to_string()),
                    revoked_at: cert_info.revoked_at.unwrap_or_else(SystemTime::now),
                });
            }
            
            let now = SystemTime::now();
            let expiry = cert_info.issued_at + cert_info.validity;
            
            if now > expiry {
                return Ok(CertificateStatus::Expired {
                    expired_at: expiry,
                });
            }
            
            return Ok(CertificateStatus::Valid);
        }
        
        // Special case simulation: serials starting with "REV" are considered revoked
        if serial.starts_with("REV") {
            return Ok(CertificateStatus::Revoked {
                reason: "Key compromise".to_string(),
                revoked_at: SystemTime::now() - Duration::from_secs(3600),
            });
        }
        
        // Other cases are considered not found
        Ok(CertificateStatus::Unknown)
    }
    
    async fn renew_certificate(&self, serial: &str, req: &CertificateRequest) -> Result<CertificateResponse, Error> {
        debug!("Mock CA: Renewing certificate with serial {}", serial);
        
        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(400)).await;
        
        // Directly request a new certificate
        self.request_certificate(req).await
    }
    
    async fn generate_csr(&self, req: &CertificateRequest) -> Result<String, Error> {
        debug!("Mock CA: Generating CSR for {}/{}", req.namespace, req.service_name);
        
        // Simulate processing delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Generate a fake CSR
        let is_pqc = req.request_pqc;
        let pqc_indicator = if is_pqc { "DILITHIUM" } else { "RSA" };
        let subject = format!("CN={}.{}", req.service_name, req.namespace);
        
        Ok(format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n\
            MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj\n\
            Algorithm: {}\n\
            Subject: {}\n\
            ... (truncated) ...\n\
            -----END CERTIFICATE REQUEST-----",
            pqc_indicator, subject
        ))
    }
}