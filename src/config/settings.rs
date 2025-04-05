use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::common::Result;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// General configuration
    #[serde(default)]
    pub general: GeneralConfig,

    /// Identity configuration
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Proxy configuration
    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Certificate configuration
    #[serde(default)]
    pub cert: CertConfig,

    /// Policy configuration
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Telemetry configuration
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

/// General configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Application name
    pub app_name: String,

    /// Execution mode (sidecar, controller)
    pub mode: String,

    /// Log level
    pub log_level: String,

    /// Data directory
    pub data_dir: PathBuf,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            app_name: "PQSecure Mesh".to_string(),
            mode: "sidecar".to_string(),
            log_level: "info".to_string(),
            data_dir: PathBuf::from("./data"),
        }
    }
}

/// Identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Tenant ID
    pub tenant: String,

    /// Service ID
    pub service: String,

    /// Identity storage path
    pub identity_dir: PathBuf,

    /// Certificate renew threshold (percentage)
    pub renew_threshold_pct: u8,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            tenant: "default".to_string(),
            service: "pqsecure-mesh".to_string(),
            identity_dir: PathBuf::from("./data/identity"),
            renew_threshold_pct: 20,
        }
    }
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy listen address
    pub listen_addr: String,

    /// Proxy listen port
    pub listen_port: u16,

    /// Upstream service address
    pub upstream_addr: String,

    /// Upstream service port
    pub upstream_port: u16,

    /// Protocol type (http, grpc)
    pub protocol: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 9090,
            upstream_addr: "127.0.0.1".to_string(),
            upstream_port: 8000,
            protocol: "http".to_string(),
        }
    }
}

/// Certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    /// Enable mTLS
    pub enable_mtls: bool,

    /// Enable PQC
    pub enable_pqc: bool,

    /// PQC algorithm
    pub pqc_algorithm: String,

    /// CA type (smallstep, file, mock)
    pub ca_type: String,

    /// Smallstep CA URL
    pub ca_url: Option<String>,

    /// Certificate storage directory
    pub certs_dir: PathBuf,

    /// Certificate duration (hours)
    pub cert_duration_hours: u64,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            enable_mtls: true,
            enable_pqc: true,
            pqc_algorithm: "Kyber768".to_string(),
            ca_type: "smallstep".to_string(),
            ca_url: None,
            certs_dir: PathBuf::from("./data/certs"),
            cert_duration_hours: 8760, // 1 year
        }
    }
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy file path
    pub policy_path: PathBuf,

    /// Policy evaluation mode (strict, permissive)
    pub evaluation_mode: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_path: PathBuf::from("./config/policy.yaml"),
            evaluation_mode: "strict".to_string(),
        }
    }
}

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable metrics collection
    pub enable_metrics: bool,

    /// Metrics port
    pub metrics_port: u16,

    /// Enable structured logging
    pub structured_logging: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            metrics_port: 9091,
            structured_logging: true,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            identity: IdentityConfig::default(),
            proxy: ProxyConfig::default(),
            cert: CertConfig::default(),
            policy: PolicyConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

impl Settings {
    /// Load configuration from environment variables and configuration files
    pub fn load() -> Result<Self> {
        use config::{Config, Environment, File};
        use std::env;

        let mut builder = Config::builder();

        // Add default values
        builder = builder.add_source(config::Config::try_from(&Self::default())?);

        // Add configuration from files
        if let Ok(config_path) = env::var("CONFIG_FILE") {
            builder = builder.add_source(File::with_name(&config_path));
        } else {
            // Try to load from default locations
            builder = builder.add_source(File::with_name("config/default").required(false));

            let env = env::var("APP_ENV").unwrap_or_else(|_| "development".into());
            builder = builder.add_source(File::with_name(&format!("config/{}", env)).required(false));
        }

        // Add environment variables
        builder = builder.add_source(Environment::with_prefix("PQSM").separator("__"));

        // Build and convert
        let config = builder.build()?;
        let settings: Settings = config.try_deserialize()?;

        Ok(settings)
    }

    /// Get API address string
    pub fn api_address(&self) -> String {
        format!("{}:{}", "0.0.0.0", 8080) // Simplified API address
    }

    /// Get proxy address string
    pub fn proxy_address(&self) -> String {
        format!("{}:{}", self.proxy.listen_addr, self.proxy.listen_port)
    }

    /// Check if configuration is valid
    pub fn validate(&self) -> Result<()> {
        // Basic validation
        if self.identity.tenant.is_empty() {
            return Err(crate::common::Error::Config("Tenant name cannot be empty".into()));
        }

        if self.identity.service.is_empty() {
            return Err(crate::common::Error::Config("Service name cannot be empty".into()));
        }

        if self.cert.ca_type == "smallstep" && self.cert.ca_url.is_none() {
            return Err(crate::common::Error::Config("Smallstep CA URL must be provided".into()));
        }

        Ok(())
    }
}