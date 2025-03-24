use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use std::error::Error;

/// 代表一個 X.509 憑證身份，包含全部 TLS 必要組件
#[derive(Debug, Clone)]
pub struct CertIdentity {
    /// 憑證實體名稱 (CN)
    pub common_name: String,
    /// 憑證序號 (Serial Number)
    pub serial: String,
    /// 憑證 PEM 內容
    pub cert_pem: String,
    /// 私鑰 PEM 內容
    pub key_pem: String,
    /// 憑證鏈 PEM 內容（若有）
    pub chain_pem: Option<String>,
    /// 憑證有效期限（從現在開始）
    pub valid_duration: Duration,
    /// 簽發時間
    pub issued_at: SystemTime,
    /// 憑證指紋 (SHA256)
    pub fingerprint: String,
    /// 使用的簽名演算法
    pub signature_algorithm: String,
    /// 是否為後量子加密 (PQC) 憑證
    pub is_post_quantum: bool,
}

impl CertIdentity {
    /// 檢查憑證是否有效（未過期）
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();
        match self.issued_at.checked_add(self.valid_duration) {
            Some(expiry) => now < expiry,
            None => false,
        }
    }

    /// 獲取距離過期的剩餘時間
    pub fn remaining_time(&self) -> Option<Duration> {
        let now = SystemTime::now();
        let expiry = self.issued_at.checked_add(self.valid_duration)?;

        if now < expiry {
            expiry.duration_since(now).ok()
        } else {
            None
        }
    }

    /// 將憑證材料儲存到特定路徑
    pub fn save_to_files(&self, cert_path: &PathBuf, key_path: &PathBuf, chain_path: Option<&PathBuf>) -> Result<(), Box<dyn Error>> {
        use std::fs::write;

        write(cert_path, &self.cert_pem)?;
        write(key_path, &self.key_pem)?;

        if let (Some(chain_pem), Some(path)) = (&self.chain_pem, chain_path) {
            write(path, chain_pem)?;
        }

        Ok(())
    }
}

/// 憑證請求資訊，用於申請新憑證
#[derive(Debug, Clone)]
pub struct CertRequest {
    /// 請求的服務名稱 (Common Name)
    pub service_name: String,
    /// 服務命名空間/租戶
    pub namespace: String,
    /// 請求的 DNS 名稱列表（SAN 擴展）
    pub dns_names: Vec<String>,
    /// IP 位址列表（SAN 擴展）
    pub ip_addresses: Vec<String>,
    /// 要求的憑證有效期限
    pub requested_duration: Duration,
    /// 是否要求使用後量子加密
    pub request_pqc: bool,
    /// 憑證簽名請求 (CSR) (可選，如果由客戶端生成)
    pub csr: Option<String>,
}

/// 代表一個 CA 服務或憑證提供者，可實現為本地 CA 或 Smallstep 整合
#[async_trait::async_trait]
pub trait CertProvider: Send + Sync {
    /// 請求新憑證
    async fn request_certificate(&self, req: &CertRequest) -> Result<CertIdentity, Box<dyn Error + Send + Sync>>;

    /// 撤銷憑證
    async fn revoke_certificate(&self, serial: &str, reason: &str) -> Result<bool, Box<dyn Error + Send + Sync>>;

    /// 檢查憑證狀態
    async fn check_certificate_status(&self, serial: &str) -> Result<CertStatus, Box<dyn Error + Send + Sync>>;
}

/// 憑證狀態類型
#[derive(Debug, Clone, PartialEq)]
pub enum CertStatus {
    /// 有效憑證
    Valid,
    /// 已撤銷憑證
    Revoked { reason: String, revoked_at: SystemTime },
    /// 過期憑證
    Expired { expired_at: SystemTime },
    /// 未知/找不到憑證
    Unknown,
}