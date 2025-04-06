use anyhow::{Context, Result};
use rustls::server::ClientCertVerified;
use rustls::{Certificate, Error};
use spiffe::workload::SpiffeId;
use std::sync::Arc;
use tracing::{debug, error, trace};
use x509_parser::prelude::*;

use crate::common::{PqSecureError, ServiceIdentity};

/// Trait for extracting identity from different sources
#[async_trait::async_trait]
pub trait IdentityExtractor: Send + Sync {
    async fn extract_identity(&self, cert: &Certificate) -> Result<ServiceIdentity>;
}

/// SPIFFE ID verifier for X.509 certificates
#[derive(Debug, Clone)]
pub struct SpiffeVerifier {
    /// Trusted domain for SPIFFE IDs
    trusted_domain: String,
}

impl SpiffeVerifier {
    /// Create a new SPIFFE verifier with the given trusted domain
    pub fn new(trusted_domain: String) -> Self {
        Self { trusted_domain }
    }

    /// Extract and verify SPIFFE ID from X.509 certificate
    pub fn extract_spiffe_id(&self, cert: &Certificate) -> Result<ServiceIdentity> {
        // Parse the certificate
        let (_, cert) = X509Certificate::from_der(cert.as_ref())
            .context("Failed to parse X.509 certificate")?;

        // Extract SAN extensions
        let extensions = cert.extensions();
        for ext in extensions {
            if ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
                let san = GeneralNames::from_der(ext.value)
                    .context("Failed to parse SAN extension")?;

                // Look for URI SAN entries
                for name in san.1.iter() {
                    if let GeneralName::URI(uri) = name {
                        trace!("Found URI SAN: {}", uri);

                        // Parse as SPIFFE ID
                        let spiffe_id = SpiffeId::parse(uri)
                            .map_err(|e| PqSecureError::SpiffeIdError(e.to_string()))?;

                        // Validate trust domain
                        if spiffe_id.trust_domain().to_string() != self.trusted_domain {
                            return Err(PqSecureError::AuthenticationError(format!(
                                "SPIFFE ID trust domain '{}' does not match trusted domain '{}'",
                                spiffe_id.trust_domain(),
                                self.trusted_domain
                            )).into());
                        }

                        debug!("Valid SPIFFE ID found: {}", spiffe_id);
                        return Ok(ServiceIdentity {
                            spiffe_id: uri.to_string(),
                            trust_domain: spiffe_id.trust_domain().to_string(),
                            path: spiffe_id.path().to_string(),
                        });
                    }
                }
            }
        }

        Err(PqSecureError::AuthenticationError(
            "No valid SPIFFE ID found in certificate".to_string(),
        ).into())
    }

    /// Verify client certificate (for rustls integration)
    pub fn verify_client_cert(
        &self,
        cert: &Certificate,
    ) -> Result<ClientCertVerified, Error> {
        match self.extract_spiffe_id(cert) {
            Ok(_) => Ok(ClientCertVerified::assertion()),
            Err(e) => {
                error!("Certificate SPIFFE ID verification failed: {}", e);
                Err(Error::General("Invalid SPIFFE ID".to_string()))
            }
        }
    }
}

#[async_trait::async_trait]
impl IdentityExtractor for SpiffeVerifier {
    async fn extract_identity(&self, cert: &Certificate) -> Result<ServiceIdentity> {
        self.extract_spiffe_id(cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Certificate as RcgenCert, CertificateParams, DnType, SanType};

    fn generate_test_cert(spiffe_id: &str) -> Certificate {
        let mut params = CertificateParams::new(vec!["test.example.com".to_string()]);
        params.distinguished_name.push(DnType::CommonName, "Test");
        params.subject_alt_names.push(SanType::URI(spiffe_id.to_string()));

        let cert = RcgenCert::from_params(params).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        Certificate(cert_der)
    }

    #[test]
    fn test_valid_spiffe_id() {
        let verifier = SpiffeVerifier::new("example.org".to_string());
        let cert = generate_test_cert("spiffe://example.org/service/test");

        let result = verifier.extract_spiffe_id(&cert);
        assert!(result.is_ok());

        let identity = result.unwrap();
        assert_eq!(identity.spiffe_id, "spiffe://example.org/service/test");
        assert_eq!(identity.trust_domain, "example.org");
        assert_eq!(identity.path, "/service/test");
    }

    #[test]
    fn test_invalid_trust_domain() {
        let verifier = SpiffeVerifier::new("example.org".to_string());
        let cert = generate_test_cert("spiffe://wrong-domain.org/service/test");

        let result = verifier.extract_spiffe_id(&cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_spiffe_id_format() {
        let verifier = SpiffeVerifier::new("example.org".to_string());
        let cert = generate_test_cert("invalid-spiffe-id");

        let result = verifier.extract_spiffe_id(&cert);
        assert!(result.is_err());
    }
}