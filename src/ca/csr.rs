use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, KeyPairAlg, SanType};
use tracing::debug;

/// Generate a CSR with SPIFFE ID as a SAN URI
pub fn generate_csr(spiffe_id: &str) -> Result<(String, Vec<u8>)> {
    debug!("Generating CSR with SPIFFE ID: {}", spiffe_id);

    // Generate a fresh key pair
    let key_pair = KeyPair::generate(&KeyPairAlg::ECDSA_P256_SHA256)
        .context("Failed to generate key pair")?;

    // Create certificate parameters
    let mut params = CertificateParams::new(vec![]);

    // Set common name to a generic value (SPIFFE ID is in SAN)
    params.distinguished_name.push(DnType::CommonName, "pqsecure-mesh");

    // Add SPIFFE ID as a SAN URI
    params.subject_alt_names.push(SanType::URI(spiffe_id.to_string()));

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

    // Set CSR flag
    params.is_ca = false;

    // Build the certificate object
    let cert = Certificate::from_params(params)
        .context("Failed to create certificate")?;

    // Generate CSR in PEM format
    let csr_pem = cert.serialize_request_pem()
        .context("Failed to serialize CSR")?;

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