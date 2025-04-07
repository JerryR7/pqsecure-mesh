use std::str::FromStr;
use anyhow::{Context, Result};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use tracing::debug;

/// Generate a CSR with SPIFFE ID as a SAN URI
pub fn generate_csr(spiffe_id: &str) -> Result<(String, Vec<u8>)> {
    debug!("Generating CSR with SPIFFE ID: {}", spiffe_id);

    // Generate key pair without algorithm parameter (uses P-256 by default)
    let key_pair = KeyPair::generate()
        .context("Failed to generate key pair")?;

    // Create certificate parameters
    let mut params = CertificateParams::default();

    // Set common name to a generic value (SPIFFE ID is in SAN)
    params.distinguished_name.push(DnType::CommonName, "pqsecure-mesh");

    // Add SPIFFE ID as a SAN URI directly
    params.subject_alt_names.push(SanType::URI(rcgen::Ia5String::from_str(spiffe_id)?));

    // Set key usage for client authentication
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyAgreement,
    ];

    // Set extended key usage for client authentication
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];

    // Set CSR flag - not a CA certificate
    params.is_ca = rcgen::IsCa::NoCa;

    // Build the certificate object with our parameters and key pair
    let cert = params.serialize_request(&key_pair)
        .context("Failed to create certificate signing request")?;

    // Get CSR in PEM format
    let csr_pem = cert.pem()
        .context("Failed to serialize CSR to PEM")?;

    // Extract private key in DER format
    let key_der = key_pair.serialize_der();

    debug!("CSR generated successfully");
    Ok((csr_pem, key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csr() {
        let spiffe_id = "spiffe://example.org/service/test";
        let result = generate_csr(spiffe_id);

        assert!(result.is_ok());
        let (csr_pem, key_der) = result.unwrap();

        // Check that we got a PEM-formatted CSR
        assert!(csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(csr_pem.ends_with("-----END CERTIFICATE REQUEST-----\n"));

        // Check that we got a non-empty private key
        assert!(!key_der.is_empty());
    }
}