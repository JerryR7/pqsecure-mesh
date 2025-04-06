#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CaConfig;
    use std::path::PathBuf;
    use tempfile::tempdir;

    // Simple test to check certificate loading logic
    #[tokio::test]
    async fn test_load_existing_cert() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        // Write sample certificate and key
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIIBVzCB/qADAgECAhQdO9C416X0lIcAMCHJLdZ+9s92pDAKBggqhkjOPQQDAjAP
MQ0wCwYDVQQDEwR0ZXN0MB4XDTIzMDMxMDE4MDk1OVoXDTIzMDMxMDE4MTk1OVow
DzENMAsGA1UEAxMEdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHxArjl/
sSgCvQYWaNRMeH9RZ6yNjkHhcFSn+OxKlA6rtFHbrEwi9DYg0sMCgAjE9NjhWCVv
jnHqTmPNQJYrMuujNTAzMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
BQcDAjAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCMXCT/6Y/vzqWE
Pb41T7rFCTrjx0EyVxKK0mw+UyEZnwIgaWnyE5CE0/RMXkurYSwJd0MykJ97ybM6
xOmUhpuFnrY=
-----END CERTIFICATE-----
"#;

        let key_pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaW6UZvV1wtP5vZ0j
TtXJ+jlllT/9BJd3LAIqO4w3JU+hRANCAASFRQFxV0o+L+iQg7gASkw68p0Tx6bF
vZB8EpnLbJZhXMGnTgOHxJF6Ej8zgVIL5SXDNWrZPD7nM9QukXZMF/w0
-----END PRIVATE KEY-----
"#;

        fs::write(&cert_path, cert_pem).await.unwrap();
        fs::write(&key_path, key_pem).await.unwrap();

        // Create client config
        let config = CaConfig {
            api_url: "https://example.com".to_string(),
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            token: "test-token".to_string(),
            spiffe_id: "spiffe://example.org/service/test".to_string(),
        };

        let client = SmallstepClient::new(&config).unwrap();
        let result = client.load_cert_and_key().await;

        assert!(result.is_ok());
        let (certs, key) = result.unwrap();
        assert!(!certs.is_empty());
        assert!(!key.0.is_empty());
    }
}
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

use crate::ca::csr::generate_csr;
use crate::common::{read_file_string, write_file_bytes, PqSecureError};
use crate::config::CaConfig;

/// Client for interacting with Smallstep CA
#[derive(Debug, Clone)]
pub struct SmallstepClient {
    /// HTTP client for API requests
    client: reqwest::Client,
    /// Base URL for Smallstep CA API
    base_url: String,
    /// Authorization token for API requests
    token: String,
    /// Path to store certificate
    cert_path: String,
    /// Path to store private key
    key_path: String,
    /// SPIFFE ID to use in CSR
    spiffe_id: String,
}

/// Request payload for certificate signing
#[derive(Serialize, Deserialize)]
struct SignRequest {
    csr: String,
    ott: String,
}

/// Response from certificate signing request
#[derive(Serialize, Deserialize)]
struct SignResponse {
    crt: String,
    ca: String,
}

impl SmallstepClient {
    /// Create a new Smallstep CA client
    pub fn new(config: &CaConfig) -> Result<Self> {
        // Create HTTP client with default settings
        let client = reqwest::Client::builder()
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: config.api_url.clone(),
            token: config.token.clone(),
            cert_path: config.cert_path.display().to_string(),
            key_path: config.key_path.display().to_string(),
            spiffe_id: config.spiffe_id.clone(),
        })
    }

    /// Load existing certificate and key or request new ones
    pub async fn load_or_request_cert(&self) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
        // Check if certificate and key files exist
        if Path::new(&self.cert_path).exists() && Path::new(&self.key_path).exists() {
            debug!("Loading existing certificate and key");
            return self.load_cert_and_key().await;
        }

        // Request new certificate
        info!("Requesting new certificate from CA");
        self.request_cert().await?;
        self.load_cert_and_key().await
    }

    /// Load certificate and key from files
    async fn load_cert_and_key(&self) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
        // Load certificate from file
        let cert_pem = fs::read_to_string(&self.cert_path)
            .await
            .context("Failed to read certificate file")?;

        // Parse PEM certificate chain
        let mut cert_data = cert_pem.as_bytes();
        let certs = rustls_pemfile::certs(&mut cert_data)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse certificate PEM")?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        // Load private key from file
        let key_bytes = fs::read(&self.key_path)
            .await
            .context("Failed to read private key file")?;

        // Parse PKCS8 private key
        let key = if key_bytesuse anyhow::{Context, Result};
        use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
        use serde::{Deserialize, Serialize};
        use std::path::Path;
        use tokio::fs;
        use tracing::{debug, info};

        use crate::ca::csr::generate_csr;
        use crate::common::{read_file_string, write_file_bytes, PqSecureError};
        use crate::config::CaConfig;

        /// Client for interacting with Smallstep CA
        #[derive(Debug, Clone)]
        pub struct SmallstepClient {
            /// HTTP client for API requests
            client: reqwest::Client,
            /// Base URL for Smallstep CA API
            base_url: String,
            /// Authorization token for API requests
            token: String,
            /// Path to store certificate
            cert_path: String,
            /// Path to store private key
            key_path: String,
            /// SPIFFE ID to use in CSR
            spiffe_id: String,
        }

        /// Request payload for certificate signing
        #[derive(Serialize, Deserialize)]
        struct SignRequest {
            csr: String,
            ott: String,
        }

        /// Response from certificate signing request
        #[derive(Serialize, Deserialize)]
        struct SignResponse {
            crt: String,
            ca: String,
        }

        impl SmallstepClient {
            /// Create a new Smallstep CA client
            pub fn new(config: &CaConfig) -> Result<Self> {
                // Create HTTP client with default settings
                let client = reqwest::Client::builder()
                    .build()
                    .context("Failed to create HTTP client")?;

                Ok(Self {
                    client,
                    base_url: config.api_url.clone(),
                    token: config.token.clone(),
                    cert_path: config.cert_path.display().to_string(),
                    key_path: config.key_path.display().to_string(),
                    spiffe_id: config.spiffe_id.clone(),
                })
            }

            /// Load existing certificate and key or request new ones
            pub async fn load_or_request_cert(&self) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
                // Check if certificate and key files exist
                if Path::new(&self.cert_path).exists() && Path::new(&self.key_path).exists() {
                    debug!("Loading existing certificate and key");
                    return self.load_cert_and_key().await;
                }

                // Request new certificate
                info!("Requesting new certificate from CA");
                self.request_cert().await?;
                self.load_cert_and_key().await
            }

            /// Load certificate and key from files
            async fn load_cert_and_key(&self) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
                // Load certificate from file
                let cert_pem = fs::read_to_string(&self.cert_path)
                    .await
                    .context("Failed to read certificate file")?;

                // Parse PEM certificate chain
                let mut cert_data = cert_pem.as_bytes();
                let certs = rustls_pemfile::certs(&mut cert_data)
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse certificate PEM")?
                    .into_iter()
                    .map(rustls::Certificate)
                    .collect();

                // Load private key from file
                let key_bytes = fs::read(&self.key_path)
                    .await
                    .context("Failed to read private key file")?;

                // Parse PKCS8 private key
                let key = if key_bytes.starts_with(b"-----BEGIN") {
                    // PEM format
                    let mut key_cursor = std::io::Cursor::new(key_bytes);
                    let key_item = rustls_pemfile::pkcs8_private_keys(&mut key_cursor)
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("No private key found in file"))?
                        .context("Failed to parse private key PEM")?;

                    rustls::PrivateKey(key_item)
                } else {
                    // DER format
                    rustls::PrivateKey(key_bytes)
                };

                Ok((certs, key))
            }

            /// Request a new certificate from the CA
            async fn request_cert(&self) -> Result<()> {
                // Generate CSR and private key
                let (csr_pem, key_der) = generate_csr(&self.spiffe_id)
                    .context("Failed to generate CSR")?;

                // Set up headers for API request
                let mut headers = HeaderMap::new();
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {}", self.token))
                        .context("Invalid token")?,
                );
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );

                // Create request payload
                let sign_request = SignRequest {
                    csr: csr_pem,
                    ott: self.token.clone(),
                };

                // Make API request
                let response = self.client
                    .post(&format!("{}/1.0/sign", self.base_url))
                    .headers(headers)
                    .json(&sign_request)
                    .send()
                    .await
                    .context("Failed to send CSR to CA")?;

                // Check response status
                if !response.status().is_success() {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    return Err(PqSecureError::CaClientError(format!(
                        "CA returned error: {} - {}", status, text
                    )).into());
                }

                // Parse response
                let sign_response: SignResponse = response
                    .json()
                    .await
                    .context("Failed to parse CA response")?;

                // Combine certificate with CA certificate
                let cert_chain = format!("{}\n{}", sign_response.crt, sign_response.ca);

                // Save certificate and key to files
                write_file_bytes(&self.cert_path, cert_chain.as_bytes())
                    .context("Failed to write certificate file")?;

                write_file_bytes(&self.key_path, &key_der)
                    .context("Failed to write private key file")?;

                info!("Certificate and key saved successfully");
                Ok(())
            }
        }.starts_with(b"-----BEGIN") {
            // PEM format
            let mut key_cursor = std::io::Cursor::new(key_bytes);
            let key = rustls_pemfile::pkcs8_private_keys(&mut key_cursor)
                .next()
                .ok_or_else(|| anyhow::anyhow!("No private key found in file"))?
                .context("Failed to parse private key PEM")?;
            rustls::PrivateKey(key)
        } else {
            // DER format
            rustls::PrivateKey(key_bytes)
        };

        Ok((certs, key))
    }

    /// Request a new certificate from the CA
    async fn request_cert(&self) -> Result<()> {
        // Generate CSR and private key
        let (csr_pem, key_der) = generate_csr(&self.spiffe_id)
            .context("Failed to generate CSR")?;

        // Set up headers for API request
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.token))
                .context("Invalid token")?,
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        // Create request payload
        let sign_request = SignRequest {
            csr: csr_pem,
            ott: self.token.clone(),
        };

        // Make API request
        let response = self.client
            .post(&format!("{}/1.0/sign", self.base_url))
            .headers(headers)
            .json(&sign_request)
            .send()
            .await
            .context("Failed to send CSR to CA")?;

        // Check response status
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(PqSecureError::CaClientError(format!(
                "CA returned error: {} - {}", status, text
            )).into());
        }

        // Parse response
        let sign_response: SignResponse = response
            .json()
            .await
            .context("Failed to parse CA response")?;

        // Combine certificate with CA certificate
        let cert_chain = format!("{}\n{}", sign_response.crt, sign_response.ca);

        // Save certificate and key to files
        write_file_bytes(&self.cert_path, cert_chain.as_bytes())
            .context("Failed to write certificate file")?;

        write_file_bytes(&self.key_path, &key_der)
            .context("Failed to write private key file")?;

        info!("Certificate and key saved successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CaConfig;
    use mockall::predicate::*;
    use mockall::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    // A stateful mock for HTTP responses
    mock! {
        HttpClient {}
        
        impl Clone for HttpClient {
            fn clone(&self) -> Self;
        }
        
        #[async_trait::async_trait]
        trait MockHttpClient {
            async fn post(&self, url: &str) -> MockHttpResponse;
        }
    }

    mock! {
        HttpResponse {}
        
        #[async_trait::async_trait]
        trait MockHttpResponse {
            fn status(&self) -> u16;
            async fn json<T: for<'de> Deserialize<'de>>(&self) -> T;
            async fn text(&self) -> String;
        }
    }

    // Simple test to check certificate loading logic
    #[tokio::test]
    async fn test_load_existing_cert() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        // Write sample certificate and key
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIIBVzCB/qADAgECAhQdO9C416X0lIcAMCHJLdZ+9s92pDAKBggqhkjOPQQDAjAP
MQ0wCwYDVQQDEwR0ZXN0MB4XDTIzMDMxMDE4MDk1OVoXDTIzMDMxMDE4MTk1OVow
DzENMAsGA1UEAxMEdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHxArjl/
sSgCvQYWaNRMeH9RZ6yNjkHhcFSn+OxKlA6rtFHbrEwi9DYg0sMCgAjE9NjhWCVv
jnHqTmPNQJYrMuujNTAzMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
BQcDAjAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCMXCT/6Y/vzqWE
Pb41T7rFCTrjx0EyVxKK0mw+UyEZnwIgaWnyE5CE0/RMXkurYSwJd0MykJ97ybM6
xOmUhpuFnrY=
-----END CERTIFICATE-----
"#;

        let key_pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaW6UZvV1wtP5vZ0j
TtXJ+jlllT/9BJd3LAIqO4w3JU+hRANCAASFRQFxV0o+L+iQg7gASkw68p0Tx6bF
vZB8EpnLbJZhXMGnTgOHxJF6Ej8zgVIL5SXDNWrZPD7nM9QukXZMF/w0
-----END PRIVATE KEY-----
"#;

        fs::write(&cert_path, cert_pem).await.unwrap();
        fs::write(&key_path, key_pem).await.unwrap();

        // Create client config
        let config = CaConfig {
            api_url: "https://example.com".to_string(),
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            token: "test-token".to_string(),
            spiffe_id: "spiffe://example.org/service/test".to_string(),
        };

        let client = SmallstepClient::new(&config).unwrap();
        let result = client.load_cert_and_key().await;

        assert!(result.is_ok());
        let (certs, key) = result.unwrap();
        assert!(!certs.is_empty());
        assert!(!key.0.is_empty());
    }
}