use anyhow::{Context, Result};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
use rustls::server::ServerConfig;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{error, warn};
use x509_parser::prelude::*;

use crate::identity::SpiffeVerifier;

// Custom certificate verifier
#[derive(Debug)]
pub struct CustomClientCertVerifier {
    spiffe_verifier: Arc<SpiffeVerifier>,
}

impl CustomClientCertVerifier {
    pub fn new(spiffe_verifier: Arc<SpiffeVerifier>) -> Self {
        Self { spiffe_verifier }
    }

    // Check certificate validity
    fn check_validity(&self, cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let (_, cert) = match X509Certificate::from_der(cert.as_ref()) {
            Ok(cert) => cert,
            Err(e) => {
                error!("Failed to parse certificate: {}", e);
                return Err(rustls::Error::General("Invalid certificate format".to_string()));
            }
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| rustls::Error::General("System time error".to_string()))?
            .as_secs() as i64;

        // Check if the certificate has expired
        if cert.validity.not_after.timestamp() < now {
            warn!("Certificate is expired");
            return Err(rustls::Error::General("Certificate is expired".to_string()));
        }

        // Check if the certificate is not yet valid
        if cert.validity.not_before.timestamp() > now {
            warn!("Certificate is not yet valid");
            return Err(rustls::Error::General("Certificate is not yet valid".to_string()));
        }

        Ok(())
    }

    // Get the SpiffeVerifier instance
    pub fn spiffe_verifier(&self) -> &SpiffeVerifier {
        &self.spiffe_verifier
    }
}

impl ClientCertVerifier for CustomClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Check certificate validity
        self.check_validity(end_entity)?;

        // Verify SPIFFE ID
        match self.spiffe_verifier.verify_client_cert(end_entity) {
            Ok(_) => Ok(ClientCertVerified::assertion()),
            Err(e) => {
                error!("SPIFFE ID verification failed: {}", e);
                Err(rustls::Error::General("Invalid SPIFFE ID".to_string()))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Build TLS configuration for server with PQC support
pub fn build_tls_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    spiffe_verifier: Arc<SpiffeVerifier>,
) -> Result<Arc<ServerConfig>> {
    // Create custom certificate verifier
    let client_cert_verifier = Arc::new(CustomClientCertVerifier::new(spiffe_verifier));

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(cert_chain, private_key)
        .context("Failed to set up server certificate")?;

    // Configure ALPN protocols
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SpiffeVerifier;
    use rcgen::{CertificateParams, DnType, SanType, KeyPair};
    use std::time::{SystemTime, Duration};

    // Helper to generate a test certificate with a SPIFFE ID
    fn generate_test_cert(spiffe_id: &str, valid: bool) -> CertificateDer<'static> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "Test");
        params.subject_alt_names.push(SanType::URI(rcgen::Ia5String::try_from(spiffe_id).unwrap()));

        // Set validity period
        if !valid {
            // Create an expired certificate
            let now = SystemTime::now();
            let past = now - Duration::from_secs(30 * 24 * 60 * 60); // 30 days ago
            let even_more_past = past - Duration::from_secs(30 * 24 * 60 * 60); // 60 days ago

            params.not_before = past.into();
            params.not_after = even_more_past.into(); // Invalid: not_after before not_before
        }

        // Generate key pair
        let key_pair = KeyPair::generate().unwrap();

        // Create the certificate with the key pair
        let cert = params.self_signed(&key_pair).unwrap();
        // Clone the DER data to create a new CertificateDer
        let der_bytes = cert.der().as_ref().to_vec();
        CertificateDer::from(der_bytes)
    }

    #[test]
    fn test_cert_validity_check() {
        let spiffe_verifier = Arc::new(SpiffeVerifier::new("example.org".to_string()));
        let verifier = CustomClientCertVerifier::new(spiffe_verifier);

        // Valid certificate
        let valid_cert = generate_test_cert("spiffe://example.org/service/test", true);
        assert!(verifier.check_validity(&valid_cert).is_ok());

        // Invalid certificate (expired)
        let invalid_cert = generate_test_cert("spiffe://example.org/service/test", false);
        assert!(verifier.check_validity(&invalid_cert).is_err());
    }

    #[test]
    fn test_spiffe_id_verification() {
        let spiffe_verifier = Arc::new(SpiffeVerifier::new("example.org".to_string()));
        let verifier = CustomClientCertVerifier::new(spiffe_verifier);

        // Valid certificate with correct trust domain
        let valid_cert = generate_test_cert("spiffe://example.org/service/test", true);
        assert!(verifier.spiffe_verifier().extract_spiffe_id(&valid_cert).is_ok());

        // Valid certificate with incorrect trust domain
        let invalid_domain_cert = generate_test_cert("spiffe://wrong-domain.org/service/test", true);
        assert!(verifier.spiffe_verifier().extract_spiffe_id(&invalid_domain_cert).is_err());

        // Valid certificate with invalid SPIFFE ID format
        let invalid_format_cert = generate_test_cert("not-a-spiffe-id", true);
        assert!(verifier.spiffe_verifier().extract_spiffe_id(&invalid_format_cert).is_err());
    }
}