use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use reqwest::{Client, header::{HeaderMap, HeaderValue, CONTENT_TYPE, AUTHORIZATION}};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug, error};

use crate::common::{Error, Result};
use crate::config::Settings;
use crate::ca::provider::CaProvider;
use crate::ca::types::{CertificateRequest, CertificateResponse, CertificateStatus};
use crate::identity::x509::X509Utils;
use crate::crypto::pqc::PqcUtils;

/// Request format for Smallstep CA
#[derive(Debug, Serialize)]
struct StepCertRequest {
    #[serde(rename = "csr")]
    csr: String,
    #[serde(rename = "sans")]
    sans: Vec<String>,
    #[serde(rename = "validityHours")]
    validity_hours: u64,
}

/// Response format for Smallstep CA
#[derive(Debug, Deserialize)]
struct StepCertResponse {
    #[serde(rename = "crt")]
    cert: String,
    #[serde(rename = "key")]
    key: Option<String>,
    #[serde(rename = "ca")]
    ca: String,
}

/// Revocation request format for Smallstep CA
#[derive(Debug, Serialize)]
struct StepRevokeRequest {
    #[serde(rename = "fingerprint")]
    fingerprint: String,
    #[serde(rename = "reason")]
    reason: String,
}

/// Smallstep CA client
pub struct SmallstepCaClient {
    /// HTTP client
    client: Client,
    /// CA URL
    ca_url: String,
    /// Authentication token
    token: Option<String>,
    /// Application configuration
    config: Arc<Settings>,
}

impl SmallstepCaClient {
    /// Create a new Smallstep CA client
    pub fn new(config: Arc<Settings>) -> Result<Self> {
        let ca_url = match &config.cert.ca_url {
            Some(url) => url.clone(),
            None => return Err(Error::Config("Smallstep CA URL not configured".into())),
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            ca_url,
            token: None, // In real implementation, we would get this from config
            config,
        })
    }

    /// Create authorization headers
    fn create_auth_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if let Some(token) = &self.token {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|e| Error::Internal(format!("Invalid token: {}", e)))?
            );
        }

        Ok(headers)
    }

    /// Generate a CSR
    async fn generate_csr(&self, req: &CertificateRequest) -> Result<String> {
        debug!("Generating CSR for {}/{}", req.namespace, req.service_name);

        // Choose different CSR generation methods based on whether PQC is requested
        if req.request_pqc {
            PqcUtils::create_pqc_csr(
                &req.service_name,
                &req.namespace,
                &req.dns_names,
                &req.ip_addresses,
                &self.config.cert.pqc_algorithm,
            )
        } else {
            PqcUtils::create_standard_csr(
                &req.service_name,
                &req.namespace,
                &req.dns_names,
                &req.ip_addresses,
            )
        }
    }
}

#[async_trait]
impl CaProvider for SmallstepCaClient {
    async fn request_certificate(&self, req: &CertificateRequest) -> Result<CertificateResponse> {
        debug!("Requesting certificate from Smallstep CA for {}/{}", req.namespace, req.service_name);

        // Obtain or generate CSR
        let csr = match &req.csr {
            Some(csr) => csr.clone(),
            None => self.generate_csr(req).await?,
        };

        // Combine all DNS and IP SAN lists
        let mut sans = req.dns_names.clone();
        for ip in &req.ip_addresses {
            sans.push(format!("IP:{}", ip));
        }

        // Add SPIFFE ID as URI SAN
        let spiffe_uri = format!("spiffe://{}/{}", req.namespace, req.service_name);
        sans.push(format!("URI:{}", spiffe_uri));

        // Prepare request content
        let step_request = StepCertRequest {
            csr,
            sans,
            validity_hours: self.config.cert.cert_duration_hours,
        };

        // Prepare HTTP request headers
        let headers = self.create_auth_headers()?;

        // Send request to Smallstep CA
        let response = self.client.post(&format!("{}/1.0/sign", self.ca_url))
            .headers(headers)
            .json(&step_request)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Failed to send request to Smallstep CA: {}", e)))?;

        // Handle response
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Ca(format!("Smallstep CA returned error {}: {}", status, error_text)));
        }

        // Parse response content
        let cert_response: StepCertResponse = response.json().await
            .map_err(|e| Error::Serialization(format!("Failed to parse response from Smallstep CA: {}", e)))?;

        // Extract various information
        let cert_pem = cert_response.cert;
        let key_pem = cert_response.key.unwrap_or_default();
        let chain_pem = Some(cert_response.ca);

        let fingerprint = X509Utils::extract_fingerprint(&cert_pem)?;
        let signature_algorithm = X509Utils::extract_signature_algorithm(&cert_pem)?;
        let is_post_quantum = X509Utils::is_post_quantum(&cert_pem, &signature_algorithm);

        // Return certificate response
        Ok(CertificateResponse {
            certificate: cert_pem,
            private_key: key_pem,
            certificate_chain: chain_pem,
            fingerprint,
            signature_algorithm,
            is_post_quantum,
        })
    }

    async fn revoke_certificate(&self, fingerprint: &str, reason: &str) -> Result<bool> {
        debug!("Revoking certificate with fingerprint {} from Smallstep CA", fingerprint);

        // Prepare HTTP request headers
        let headers = self.create_auth_headers()?;

        // Prepare request content
        let revoke_request = StepRevokeRequest {
            fingerprint: fingerprint.to_string(),
            reason: reason.to_string(),
        };

        // Send request to Smallstep CA
        let response = self.client.post(&format!("{}/1.0/revoke", self.ca_url))
            .headers(headers)
            .json(&revoke_request)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Failed to send revoke request to Smallstep CA: {}", e)))?;

        // Handle response
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Ca(format!("Smallstep CA returned error {}: {}", status, error_text)));
        }

        Ok(true)
    }

    async fn check_certificate_status(&self, fingerprint: &str) -> Result<CertificateStatus> {
        debug!("Checking certificate status with fingerprint {} from Smallstep CA", fingerprint);

        // Prepare HTTP request headers
        let headers = self.create_auth_headers()?;

        // Send request to Smallstep CA
        let response = self.client.get(&format!("{}/1.0/status/{}", self.ca_url, fingerprint))
            .headers(headers)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Failed to send status request to Smallstep CA: {}", e)))?;

        // Determine based on HTTP status
        match response.status().as_u16() {
            200 => Ok(CertificateStatus::Valid),
            410 => {
                // Revoked, try to get more information
                let body: serde_json::Value = response.json().await
                    .map_err(|e| Error::Serialization(format!("Failed to parse status response: {}", e)))?;

                let reason = body["reason"].as_str().unwrap_or("unknown").to_string();
                let revoked_at = SystemTime::now(); // Actual implementation should parse the timestamp

                Ok(CertificateStatus::Revoked { reason, revoked_at })
            }
            _ => Ok(CertificateStatus::Unknown),
        }
    }
}