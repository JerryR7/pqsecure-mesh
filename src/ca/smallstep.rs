use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use reqwest::{Client, header::{HeaderMap, HeaderValue, CONTENT_TYPE, AUTHORIZATION}};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug, error};

use crate::config::Config;
use crate::error::Error;
use crate::ca::provider::CaProvider;
use crate::ca::types::{CertificateRequest, CertificateResponse, CertificateStatus, RevocationReason};
use crate::identity::x509::X509Utils;
use crate::crypto::pqc::PqcUtils;

/// Request format for Smallstep CA
#[derive(Debug, Serialize)]
struct StepCertRequest {
    #[serde(rename = "csr")]
    csr: Option<String>,
    #[serde(rename = "commonName")]
    common_name: String,
    #[serde(rename = "sans")]
    sans: Vec<String>,
    #[serde(rename = "validityHours")]
    validity_hours: u64,
    #[serde(rename = "backdate")]
    backdate: u64,
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
    #[serde(rename = "certChain")]
    cert_chain: Option<String>,
}

/// Revocation request format for Smallstep CA
#[derive(Debug, Serialize)]
struct StepRevokeRequest {
    #[serde(rename = "serial")]
    serial: String,
    #[serde(rename = "reasonCode")]
    reason_code: i32,
    #[serde(rename = "reason")]
    reason: String,
    #[serde(rename = "passive")]
    passive: bool,
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
    config: Arc<Config>,
}

impl SmallstepCaClient {
    /// Create a new Smallstep CA client
    pub fn new(config: Arc<Config>) -> Result<Self, Error> {
        let ca_url = match &config.cert.ca_url {
            Some(url) => url.clone(),
            None => return Err(Error::Config("Smallstep CA URL not configured".into())),
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::HttpClient(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            ca_url,
            token: config.cert.ca_token.clone(),
            config,
        })
    }

    /// Create authorization headers
    fn create_auth_headers(&self) -> Result<HeaderMap, Error> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        
        if let Some(token) = &self.token {
            headers.insert(
                AUTHORIZATION, 
                HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|e| Error::HttpClient(format!("Invalid token: {}", e)))?
            );
        }
        
        Ok(headers)
    }
    
    /// Convert reason code to RFC 5280 compliant format
    fn reason_to_code(reason: &str) -> i32 {
        RevocationReason::from_str(reason) as i32
    }
}

#[async_trait]
impl CaProvider for SmallstepCaClient {
    async fn request_certificate(&self, req: &CertificateRequest) -> Result<CertificateResponse, Error> {
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
            csr: Some(csr),
            common_name: req.service_name.clone(),
            sans,
            validity_hours: self.config.cert.cert_duration_hours,
            backdate: 60, // Backdate 60 seconds to avoid time synchronization issues
        };
        
        // Prepare HTTP request headers
        let headers = self.create_auth_headers()?;
        
        // Send request to Smallstep CA
        let response = self.client.post(&format!("{}/1.0/sign", self.ca_url))
            .headers(headers)
            .json(&step_request)
            .send()
            .await
            .map_err(|e| Error::HttpClient(format!("Failed to send request to Smallstep CA: {}", e)))?;
        
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
        let chain_pem = Some(cert_response.ca.clone());
        
        let fingerprint = X509Utils::extract_fingerprint(&cert_pem)?;
        let signature_algorithm = X509Utils::extract_signature_algorithm(&cert_pem)?;
        let serial = X509Utils::extract_serial(&cert_pem)?;
        let is_post_quantum = X509Utils::is_post_quantum(&cert_pem, &signature_algorithm);
        
        // Return certificate response
        Ok(CertificateResponse {
            certificate: cert_pem,
            private_key: key_pem,
            certificate_chain: chain_pem,
            fingerprint,
            serial,
            signature_algorithm,
            is_post_quantum,
        })
    }
    
    async fn revoke_certificate(&self, serial: &str, reason: &str) -> Result<bool, Error> {
        debug!("Revoking certificate with serial {} from Smallstep CA", serial);
        
        // Prepare HTTP request headers
        let headers = self.create_auth_headers()?;
        
        // Prepare request content
        let revoke_request = StepRevokeRequest {
            serial: serial.to_string(),
            reason_code: Self::reason_to_code(reason),
            reason: reason.to_string(),
            passive: false,
        };
        
        // Send request to Smallstep CA
        let response = self.client.post(&format!("{}/1.0/revoke", self.ca_url))
            .headers(headers)
            .json(&revoke_request)
            .send()
            .await
            .map_err(|e| Error::HttpClient(format!("Failed to send revoke request to Smallstep CA: {}", e)))?;
        
        // Handle response
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Ca(format!("Smallstep CA returned error {}: {}", status, error_text)));
        }
        
        Ok(true)
    }
    
    async fn check_certificate_status(&self, serial: &str) -> Result<CertificateStatus, Error> {
        debug!("Checking certificate status with serial {} from Smallstep CA", serial);
        
        // Prepare HTTP request headers
        let headers = self.create_auth_headers()?;
        
        // Send request to Smallstep CA
        let response = self.client.get(&format!("{}/1.0/status/{}", self.ca_url, serial))
            .headers(headers)
            .send()
            .await
            .map_err(|e| Error::HttpClient(format!("Failed to send status request to Smallstep CA: {}", e)))?;
        
        // Determine based on HTTP status
        match response.status().as_u16() {
            200 => Ok(CertificateStatus::Valid),
            404 => Ok(CertificateStatus::Unknown),
            410 => {
                // Revoked, try to get more information
                let body: serde_json::Value = response.json().await
                    .map_err(|e| Error::Serialization(format!("Failed to parse status response: {}", e)))?;
                
                let reason = body["reason"].as_str().unwrap_or("unknown").to_string();
                let revoked_at = SystemTime::now(); // Actual implementation should parse the timestamp
                
                Ok(CertificateStatus::Revoked { reason, revoked_at })
            }
            _ => {
                let status = response.status();
                let error_text = response.text().await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(Error::Ca(format!("Smallstep CA returned error {}: {}", status, error_text)))
            }
        }
    }
    
    async fn renew_certificate(&self, serial: &str, req: &CertificateRequest) -> Result<CertificateResponse, Error> {
        // Simple implementation: renew by requesting a new certificate
        debug!("Renewing certificate with serial {} from Smallstep CA", serial);
        self.request_certificate(req).await
    }
    
    async fn generate_csr(&self, req: &CertificateRequest) -> Result<String, Error> {
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