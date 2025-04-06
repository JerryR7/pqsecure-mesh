use anyhow::{Context, Result};
use rustls::{Certificate, DistinguishedName, RootCertStore, ServerConfig};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, trace, warn};
use x509_parser::prelude::*;

use crate::identity::SpiffeVerifier;

// Custom certificate verifier
pub struct CustomClientCertVerifier {
    spiffe_verifier: Arc<SpiffeVerifier>,
}

impl CustomClientCertVerifier {
    pub fn new(spiffe_verifier: Arc<SpiffeVerifier>) -> Self {
        Self { spiffe_verifier }
    }

    // Check certificate validity
    fn check_validity(&self, cert: &Certificate) -> Result<(), rustls::Error> {
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
}

impl rustls::server::ClientCertVerifier for CustomClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Check certificate validity
        self.check_validity(end_entity)?;

        // Verify SPIFFE ID
        self.spiffe_verifier.verify_client_cert(end_entity)?;

        // If all checks pass, return verification success
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
}

/// Build TLS configuration for server with PQC support
pub fn build_tls_config(
    cert_chain: Vec<Certificate>,
    private_key: rustls::PrivateKey,
    spiffe_verifier: Arc<SpiffeVerifier>,
) -> Result<Arc<ServerConfig>> {
    // Create an empty root certificate store
    let mut root_store = RootCertStore::empty();

    // Create custom certificate verifier
    let client_cert_verifier = Arc::new(CustomClientCertVerifier::new(spiffe_verifier));

    // Start building server configuration
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(cert_chain, private_key)
        .context("Failed to set up server certificate")?;

    // Configure ALPN protocols
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}
