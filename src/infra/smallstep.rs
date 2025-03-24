use std::error::Error;
use std::sync::Arc;
use std::time::SystemTime;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, AUTHORIZATION};

use crate::config::Config;
use crate::domain::{CertIdentity, CertProvider, CertRequest, CertStatus};

/// Smallstep CA API 的實現
pub struct SmallstepClient {
    /// HTTP 客戶端
    client: Client,
    /// Smallstep CA URL
    ca_url: String,
    /// 認證令牌
    token: String,
    /// 應用程序配置
    config: Arc<Config>,
}

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

impl SmallstepClient {
    /// 建立新的 Smallstep 客戶端
    pub fn new(config: Arc<Config>) -> Result<Self, Box<dyn Error>> {
        let ca_url = config.cert.smallstep_url.clone()
            .ok_or("Smallstep URL not configured")?;

        let token = config.cert.smallstep_token.clone()
            .ok_or("Smallstep token not configured")?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            ca_url,
            token,
            config,
        })
    }

    /// 轉換內部的錯誤格式
    fn map_error<E: Error + 'static>(err: E) -> Box<dyn Error + Send + Sync> {
        Box::new(err)
    }

    /// 將理由代碼轉換為 RFC 5280 符合格式
    fn reason_to_code(reason: &str) -> i32 {
        match reason.to_lowercase().as_str() {
            "unspecified" => 0,
            "keycompromise" | "key compromise" => 1,
            "cacompromise" | "ca compromise" => 2,
            "affiliationchanged" | "affiliation changed" => 3,
            "superseded" => 4,
            "cessationofoperation" | "cessation of operation" => 5,
            "certificatehold" | "certificate hold" => 6,
            "removefromcrl" | "remove from crl" => 8,
            "privilegewithdrawn" | "privilege withdrawn" => 9,
            "aacompromise" | "aa compromise" => 10,
            _ => 0,
        }
    }

    /// 產生 CSR（如果客戶端沒有提供）
    async fn generate_csr(&self, req: &CertRequest) -> Result<String, Box<dyn Error + Send + Sync>> {
        // 在實際產品中，這裡應該使用 OpenSSL 或其他加密庫生成 CSR
        // 本範例簡化處理，實際上應該產生真正的 CSR

        // 注意：實際實現應使用 rcgen 或 rustls-pemfile 等庫創建 CSR
        Err("CSR generation not implemented yet".into())
    }

    /// 從回應中提取憑證指紋（SHA-256）
    fn extract_fingerprint(cert_pem: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        // 這裡應該使用 OpenSSL 或其他加密庫提取憑證指紋
        // 簡化實現：只返回一個虛構的指紋
        Ok("SHA256:01234567890123456789012345678901234567890123456789".to_string())
    }

    /// 從回應中提取簽名演算法
    fn extract_signature_algorithm(cert_pem: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        // 這裡應該解析 PEM 並提取簽名演算法
        // 簡化實現，根據請求的 PQC 類型返回不同結果

        if cert_pem.contains("DILITHIUM") || cert_pem.contains("KYBER") {
            Ok("dilithium5-rsa-sha256".to_string())
        } else {
            Ok("ecdsa-with-SHA256".to_string())
        }
    }

    /// 從回應中提取憑證序號
    fn extract_serial(cert_pem: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        // 這裡應該解析 PEM 並提取序號
        // 簡化實現
        Ok("0123456789ABCDEF0123456789ABCDEF01234567".to_string())
    }

    /// 檢查憑證是否使用後量子加密算法
    fn is_post_quantum(cert_pem: &str, signature_algorithm: &str) -> bool {
        // 檢查憑證是否使用後量子加密算法
        signature_algorithm.contains("dilithium") ||
            signature_algorithm.contains("falcon") ||
            signature_algorithm.contains("kyber") ||
            cert_pem.contains("DILITHIUM") ||
            cert_pem.contains("FALCON") ||
            cert_pem.contains("KYBER")
    }
}

#[async_trait]
impl CertProvider for SmallstepClient {
    async fn request_certificate(&self, req: &CertRequest) -> Result<CertIdentity, Box<dyn Error + Send + Sync>> {
        // 準備 HTTP 請求頭
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", self.token))
            .map_err(Self::map_error)?);

        // 獲取或產生 CSR
        let csr = match &req.csr {
            Some(csr) => csr.clone(),
            None => self.generate_csr(req).await?,
        };

        // 組合所有 DNS 和 IP SAN 列表
        let mut sans = req.dns_names.clone();
        for ip in &req.ip_addresses {
            sans.push(format!("IP:{}", ip));
        }

        // 準備請求內容
        let step_request = StepCertRequest {
            csr: Some(csr),
            common_name: req.service_name.clone(),
            sans,
            validity_hours: req.requested_duration.as_secs() / 3600,
            backdate: 60, // 回溯 60 秒以避免時間同步問題
        };

        // 發送請求到 Smallstep CA
        let response = self.client.post(&format!("{}/1.0/sign", self.ca_url))
            .headers(headers)
            .json(&step_request)
            .send()
            .await
            .map_err(Self::map_error)?;

        // 處理回應
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Smallstep CA returned error {}: {}", status, error_text).into());
        }

        // 解析回應內容
        let cert_response: StepCertResponse = response.json().await.map_err(Self::map_error)?;

        // 提取各種資訊
        let cert_pem = cert_response.cert;
        let key_pem = cert_response.key.unwrap_or_default();
        let chain_pem = Some(cert_response.ca.clone());

        let fingerprint = Self::extract_fingerprint(&cert_pem)?;
        let signature_algorithm = Self::extract_signature_algorithm(&cert_pem)?;
        let serial = Self::extract_serial(&cert_pem)?;
        let is_post_quantum = Self::is_post_quantum(&cert_pem, &signature_algorithm);

        // 建立憑證身份
        Ok(CertIdentity {
            common_name: req.service_name.clone(),
            serial,
            cert_pem,
            key_pem,
            chain_pem,
            valid_duration: req.requested_duration,
            issued_at: SystemTime::now(),
            fingerprint,
            signature_algorithm,
            is_post_quantum,
        })
    }

    async fn revoke_certificate(&self, serial: &str, reason: &str) -> Result<bool, Box<dyn Error + Send + Sync>> {
        // 準備 HTTP 請求頭
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", self.token))
            .map_err(Self::map_error)?);

        // 準備請求內容
        let revoke_request = StepRevokeRequest {
            serial: serial.to_string(),
            reason_code: Self::reason_to_code(reason),
            reason: reason.to_string(),
            passive: false,
        };

        // 發送請求到 Smallstep CA
        let response = self.client.post(&format!("{}/1.0/revoke", self.ca_url))
            .headers(headers)
            .json(&revoke_request)
            .send()
            .await
            .map_err(Self::map_error)?;

        // 處理回應
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Smallstep CA returned error {}: {}", status, error_text).into());
        }

        Ok(true)
    }

    async fn check_certificate_status(&self, serial: &str) -> Result<CertStatus, Box<dyn Error + Send + Sync>> {
        // 準備 HTTP 請求頭
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", self.token))
            .map_err(Self::map_error)?);

        // 發送請求到 Smallstep CA
        let response = self.client.get(&format!("{}/1.0/status/{}", self.ca_url, serial))
            .headers(headers)
            .send()
            .await
            .map_err(Self::map_error)?;

        // 根據 HTTP 狀態判斷
        match response.status().as_u16() {
            200 => Ok(CertStatus::Valid),
            404 => Ok(CertStatus::Unknown),
            410 => {
                // 已撤銷，嘗試獲取更多資訊
                let body: serde_json::Value = response.json().await.map_err(Self::map_error)?;
                let reason = body["reason"].as_str().unwrap_or("unknown").to_string();
                let revoked_at = SystemTime::now(); // 實際實現應解析時間戳

                Ok(CertStatus::Revoked { reason, revoked_at })
            }
            _ => {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Smallstep CA returned error {}: {}", status, error_text).into())
            }
        }
    }
}

/// 模擬的 Smallstep Client，用於開發和測試
pub struct MockSmallstepClient {
    config: Arc<Config>,
}

impl MockSmallstepClient {
    /// 建立模擬客戶端
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl CertProvider for MockSmallstepClient {
    async fn request_certificate(&self, req: &CertRequest) -> Result<CertIdentity, Box<dyn Error + Send + Sync>> {
        // 模擬延遲
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // 生成模擬的 PEM 資料
        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n\
            MIIEpDCCAowCCQDMlK8ZNZ1OgDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n\
            b2NhbGhvc3QwHhcNMjAwMzI5MTkyNDQwWhcNMjEwMzI5MTkyNDQwWjAUMRIwEAYD\n\
            ... (truncated) ...\n\
            CN={}.{}\n\
            -----END CERTIFICATE-----",
            req.service_name, req.namespace
        );

        let key_pem = "-----BEGIN PRIVATE KEY-----\n\
            MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj\n\
            ... (truncated) ...\n\
            -----END PRIVATE KEY-----".to_string();

        let chain_pem = Some(
            "-----BEGIN CERTIFICATE-----\n\
            MIIEpDCCAowCCQDMlK8ZNZ1OgDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n\
            ... (truncated) ...\n\
            -----END CERTIFICATE-----".to_string()
        );

        // 根據是否請求 PQC 來模擬不同的簽名演算法
        let (signature_algorithm, is_post_quantum) = if req.request_pqc {
            ("dilithium5-rsa-sha256", true)
        } else {
            ("ecdsa-with-SHA256", false)
        };

        // 建立憑證身份
        Ok(CertIdentity {
            common_name: req.service_name.clone(),
            serial: format!("MOCK{:08x}", rand::random::<u32>()),
            cert_pem,
            key_pem,
            chain_pem,
            valid_duration: req.requested_duration,
            issued_at: SystemTime::now(),
            fingerprint: format!("SHA256:{:064x}", rand::random::<u64>()),
            signature_algorithm: signature_algorithm.to_string(),
            is_post_quantum,
        })
    }

    async fn revoke_certificate(&self, serial: &str, _reason: &str) -> Result<bool, Box<dyn Error + Send + Sync>> {
        // 模擬延遲
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // 總是成功
        Ok(true)
    }

    async fn check_certificate_status(&self, serial: &str) -> Result<CertStatus, Box<dyn Error + Send + Sync>> {
        // 模擬延遲
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // 模擬檢查：如果序號以 "MOCK" 開頭，則有效
        if serial.starts_with("MOCK") {
            Ok(CertStatus::Valid)
        } else if serial.starts_with("REV") {
            Ok(CertStatus::Revoked {
                reason: "Key compromise".to_string(),
                revoked_at: SystemTime::now() - std::time::Duration::from_secs(3600),
            })
        } else {
            Ok(CertStatus::Unknown)
        }
    }
}