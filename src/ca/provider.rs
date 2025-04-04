use async_trait::async_trait;
use crate::error::Error;
use crate::ca::types::{CertificateRequest, CertificateResponse, CertificateStatus};

/// CA provider interface
#[async_trait]
pub trait CaProvider: Send + Sync {
    /// Request a new certificate
    async fn request_certificate(
        &self, 
        req: &CertificateRequest
    ) -> Result<CertificateResponse, Error>;
    
    /// Revoke a certificate
    async fn revoke_certificate(
        &self, 
        serial: &str, 
        reason: &str
    ) -> Result<bool, Error>;
    
    /// Check certificate status
    async fn check_certificate_status(
        &self, 
        serial: &str
    ) -> Result<CertificateStatus, Error>;
    
    /// Renew a certificate
    async fn renew_certificate(
        &self,
        serial: &str,
        req: &CertificateRequest
    ) -> Result<CertificateResponse, Error>;
    
    /// Generate a CSR
    async fn generate_csr(
        &self, 
        req: &CertificateRequest
    ) -> Result<String, Error>;
}

/// Create a CA provider
pub fn create_ca_provider(config: std::sync::Arc<crate::config::Config>) -> Result<std::sync::Arc<dyn CaProvider>, Error> {
    match config.cert.ca_type.as_str() {
        "smallstep" => {
            let ca = crate::ca::smallstep::SmallstepCaClient::new(config)?;
            Ok(std::sync::Arc::new(ca))
        },
        "mock" => {
            let ca = crate::ca::mock::MockCaClient::new(config);
            Ok(std::sync::Arc::new(ca))
        },
        _ => Err(Error::Config(format!("Unsupported CA type: {}", config.cert.ca_type))),
    }
}