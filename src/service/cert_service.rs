use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::domain::{CertIdentity, CertProvider, CertRequest, CertStatus};

/// 憑證服務，用於管理 TLS 憑證的生命週期
pub struct CertService {
    /// 使用的憑證提供者
    cert_provider: Arc<dyn CertProvider>,
    /// 應用程序配置
    config: Arc<Config>,
    /// 憑證路徑
    certs_dir: PathBuf,
}

impl CertService {
    /// 建立一個新的憑證服務
    pub fn new(cert_provider: Arc<dyn CertProvider>, config: Arc<Config>) -> Self {
        let certs_dir = config.cert.certs_dir.clone();

        // 確保憑證目錄存在
        std::fs::create_dir_all(&certs_dir).expect("Failed to create certificates directory");

        Self {
            cert_provider,
            config,
            certs_dir,
        }
    }

    /// 請求新憑證
    pub async fn request_certificate(&self, service_name: &str, namespace: &str) -> Result<CertIdentity, Box<dyn Error + Send + Sync>> {
        // 準備憑證請求
        let req = CertRequest {
            service_name: service_name.to_string(),
            namespace: namespace.to_string(),
            dns_names: vec![
                format!("{}.{}", service_name, namespace),
                format!("{}.{}.svc", service_name, namespace),
                format!("{}.{}.svc.cluster.local", service_name, namespace),
            ],
            ip_addresses: vec![],
            requested_duration: self.config.cert_duration(),
            request_pqc: self.config.cert.enable_pqc,
            csr: None,
        };

        // 請求憑證
        let cert_identity = self.cert_provider.request_certificate(&req).await?;

        // 儲存憑證到本地
        self.store_certificate(&cert_identity, service_name, namespace)?;

        Ok(cert_identity)
    }

    /// 儲存憑證到本地檔案系統
    fn store_certificate(&self, cert: &CertIdentity, service_name: &str, namespace: &str) -> Result<(), Box<dyn Error>> {
        // 建立服務命名空間目錄
        let service_dir = self.certs_dir.join(namespace).join(service_name);
        std::fs::create_dir_all(&service_dir)?;

        // 設定路徑
        let cert_path = service_dir.join("cert.pem");
        let key_path = service_dir.join("key.pem");
        let chain_path = service_dir.join("chain.pem");

        // 儲存憑證材料
        cert.save_to_files(&cert_path, &key_path, Some(&chain_path))?;

        // 儲存元數據
        let metadata = serde_json::json!({
            "common_name": cert.common_name,
            "serial": cert.serial,
            "fingerprint": cert.fingerprint,
            "issued_at": cert.issued_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            "valid_duration": cert.valid_duration.as_secs(),
            "signature_algorithm": cert.signature_algorithm,
            "is_post_quantum": cert.is_post_quantum,
        });

        let metadata_path = service_dir.join("metadata.json");
        std::fs::write(metadata_path, serde_json::to_string_pretty(&metadata)?)?;

        Ok(())
    }

    /// 撤銷憑證
    pub async fn revoke_certificate(&self, serial: &str, reason: &str) -> Result<bool, Box<dyn Error + Send + Sync>> {
        self.cert_provider.revoke_certificate(serial, reason).await
    }

    /// 檢查憑證狀態
    pub async fn check_certificate_status(&self, serial: &str) -> Result<CertStatus, Box<dyn Error + Send + Sync>> {
        self.cert_provider.check_certificate_status(serial).await
    }

    /// 檢查並自動更新即將過期的憑證
    pub async fn auto_renew_certificate(&self, service_name: &str, namespace: &str) -> Result<Option<CertIdentity>, Box<dyn Error + Send + Sync>> {
        // 載入現有憑證
        let service_dir = self.certs_dir.join(namespace).join(service_name);
        let metadata_path = service_dir.join("metadata.json");

        if !metadata_path.exists() {
            return Ok(None); // 無憑證，需要初次發行
        }

        // 讀取元數據
        let metadata_str = std::fs::read_to_string(&metadata_path)?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_str)?;

        // 解析已發行時間和有效期限
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(metadata["issued_at"].as_u64().unwrap_or(0));
        let valid_duration = Duration::from_secs(metadata["valid_duration"].as_u64().unwrap_or(0));
        let expiry = issued_at + valid_duration;

        // 計算剩餘有效期百分比
        let now = SystemTime::now();
        if now > expiry {
            // 已過期，需要更新
            return self.request_certificate(service_name, namespace).await.map(Some);
        }

        let total_duration = valid_duration.as_secs() as f64;
        let remaining_duration = match expiry.duration_since(now) {
            Ok(duration) => duration.as_secs() as f64,
            Err(_) => 0.0,
        };

        let remaining_percent = (remaining_duration / total_duration) * 100.0;

        // 檢查是否需要更新
        if remaining_percent <= self.config.cert.cert_renew_threshold_pct as f64 {
            // 需要更新
            return self.request_certificate(service_name, namespace).await.map(Some);
        }

        // 不需要更新
        Ok(None)
    }
}