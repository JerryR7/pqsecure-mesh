use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// 應用程序全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 一般設定
    pub general: GeneralConfig,
    /// REST API 設定
    pub api: ApiConfig,
    /// Proxy 設定
    pub proxy: ProxyConfig,
    /// 憑證相關設定
    pub cert: CertConfig,
}

/// 一般設定
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// 應用程序名稱
    pub app_name: String,
    /// 日誌層級 (trace, debug, info, warn, error)
    pub log_level: String,
    /// 資料目錄
    pub data_dir: PathBuf,
}

/// REST API 設定
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// 監聽位址
    pub listen_addr: String,
    /// 監聽埠號
    pub listen_port: u16,
    /// API 路徑前綴
    pub path_prefix: String,
    /// 啟用 HTTP/2
    pub enable_http2: bool,
    /// 如果有，則啟用 API TLS
    pub tls_cert: Option<PathBuf>,
    /// TLS 私鑰路徑
    pub tls_key: Option<PathBuf>,
}

/// Proxy 設定
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy 監聽位址
    pub listen_addr: String,
    /// Proxy 埠號
    pub listen_port: u16,
    /// 上游服務位址
    pub upstream_addr: String,
    /// 上游服務埠號
    pub upstream_port: u16,
    /// 啟用 gRPC 支援
    pub enable_grpc: bool,
    /// 啟用 HTTP 支援
    pub enable_http: bool,
    /// 最大閒置連線時間 (秒)
    pub idle_timeout_seconds: u64,
    /// 每個上游連線的最大請求數
    pub max_requests_per_connection: Option<u32>,
}

/// 憑證相關設定
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    /// 是否啟用 mTLS
    pub enable_mtls: bool,
    /// 是否啟用後量子加密
    pub enable_pqc: bool,
    /// CA 類型 (local, smallstep)
    pub ca_type: String,
    /// Smallstep CA URL
    pub smallstep_url: Option<String>,
    /// Smallstep CA 令牌
    pub smallstep_token: Option<String>,
    /// 本地 CA 路徑
    pub local_ca_path: Option<PathBuf>,
    /// 憑證存儲目錄
    pub certs_dir: PathBuf,
    /// 憑證有效期限（小時）
    pub cert_duration_hours: u64,
    /// 憑證自動更新閾值（剩餘有效期的百分比）
    pub cert_renew_threshold_pct: u8,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            general: GeneralConfig {
                app_name: "PQSecure Mesh".to_string(),
                log_level: "info".to_string(),
                data_dir: PathBuf::from("./data"),
            },
            api: ApiConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
                path_prefix: "/api/v1".to_string(),
                enable_http2: true,
                tls_cert: None,
                tls_key: None,
            },
            proxy: ProxyConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 9090,
                upstream_addr: "127.0.0.1".to_string(),
                upstream_port: 8000,
                enable_grpc: true,
                enable_http: true,
                idle_timeout_seconds: 300,
                max_requests_per_connection: Some(1000),
            },
            cert: CertConfig {
                enable_mtls: true,
                enable_pqc: true,
                ca_type: "smallstep".to_string(),
                smallstep_url: Some("https://ca.example.com".to_string()),
                smallstep_token: None,
                local_ca_path: None,
                certs_dir: PathBuf::from("./data/certs"),
                cert_duration_hours: 8760, // 1 年
                cert_renew_threshold_pct: 20,
            },
        }
    }
}

impl Config {
    /// 從環境變數和配置文件載入配置
    pub fn load() -> Result<Self, config::ConfigError> {
        use config::{Config as ConfigBuilder, Environment, File};
        use std::env;

        let mut builder = ConfigBuilder::builder();

        // 基本默認值
        builder = builder.set_default("general.app_name", "PQSecure Mesh")?;

        // 從配置文件載入
        if let Ok(config_path) = env::var("CONFIG_FILE") {
            builder = builder.add_source(File::with_name(&config_path));
        } else {
            // 嘗試從默認位置載入
            builder = builder.add_source(File::with_name("config/default").required(false));

            let env = env::var("APP_ENV").unwrap_or_else(|_| "development".into());
            builder = builder.add_source(File::with_name(&format!("config/{}", env)).required(false));
        }

        // 從環境變數載入，使用前綴並支援巢狀屬性
        builder = builder.add_source(Environment::with_prefix("PQSM").separator("__"));

        // 構建最終配置
        let config = builder.build()?;

        // 轉換為強類型配置
        config.try_deserialize()
    }

    /// 獲取憑證有效期限
    pub fn cert_duration(&self) -> Duration {
        Duration::from_secs(self.cert.cert_duration_hours * 3600)
    }

    /// 獲取 REST API 完整地址
    pub fn api_address(&self) -> String {
        format!("{}:{}", self.api.listen_addr, self.api.listen_port)
    }

    /// 獲取 Proxy 完整地址
    pub fn proxy_address(&self) -> String {
        format!("{}:{}", self.proxy.listen_addr, self.proxy.listen_port)
    }
}