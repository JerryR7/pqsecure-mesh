use async_trait::async_trait;
use std::sync::Arc;
use crate::common::Result;
use crate::ca::types::{CertificateRequest, CertificateResponse, CertificateStatus};
use crate::config::Settings;

/// CA provider interface
#[async_trait]
pub trait CaProvider: Send + Sync {
    /// Request a new certificate
    async fn request_certificate(&self, req: &CertificateRequest) -> Result<CertificateResponse>;

    /// Revoke a certificate
    async fn revoke_certificate(&self, fingerprint: &str, reason: &str) -> Result<bool>;

    /// Check certificate status
    async fn check_certificate_status(&self, fingerprint: &str) -> Result<CertificateStatus>;
}

/// Create a CA provider based on configuration
pub fn create_ca_provider(config: Arc<Settings>) -> Result<Arc<dyn CaProvider>> {
    match config.cert.ca_type.as_str() {
        "smallstep" => {
            let ca = crate::ca::smallstep::SmallstepCaClient::new(config)?;
            Ok(Arc::new(ca))
        },
        "mock" => {
            let ca = crate::ca::mock::MockCaClient::new(config);
            Ok(Arc::new(ca))
        },
        _ => Err(crate::common::Error::Config(format!("Unsupported CA type: {}", config.cert.ca_type))),
    }
}