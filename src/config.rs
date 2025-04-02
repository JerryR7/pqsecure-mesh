use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use crate::error::Error;

/// Application global configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
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
    /// API configuration
    #[serde(default)]
    pub api: ApiConfig,
    /// Telemetry configuration
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

/// General configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Application name
    pub app_name: String,
    /// Execution mode (sidecar, controller, api_server)
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
    /// Identity provider type (smallstep, file, mock)
    pub provider_type: String,
    /// Renew threshold (percentage)
    pub renew_threshold_pct: u8,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            tenant: "default".to_string(),
            service: "pqsecure-mesh".to_string(),
            identity_dir: PathBuf::from("./data/identity"),
            provider_type: "smallstep".to_string(),
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
    /// Protocol type (http, grpc, tcp)
    pub protocol: String,
    /// Maximum idle connection timeout (seconds)
    pub idle_timeout_seconds: u64,
    /// Maximum requests per upstream connection
    pub max_requests_per_connection: Option<u32>,
    /// Enable compression
    pub enable_compression: bool,
    /// Propagate trace headers
    pub propagate_trace_headers: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 9090,
            upstream_addr: "127.0.0.1".to_string(),
            upstream_port: 8000,
            protocol: "http".to_string(),
            idle_timeout_seconds: 300,
            max_requests_per_connection: Some(1000),
            enable_compression: true,
            propagate_trace_headers: true,
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
    /// CA type (smallstep, local, mock)
    pub ca_type: String,
    /// Smallstep CA URL
    pub ca_url: Option<String>,
    /// Smallstep CA token
    pub ca_token: Option<String>,
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
            ca_url: Some("https://ca.example.com".to_string()),
            ca_token: None,
            certs_dir: PathBuf::from("./data/certs"),
            cert_duration_hours: 8760, // 1 年
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
    /// Policy refresh interval (seconds)
    pub refresh_interval_seconds: u64,
    /// Use WASM plugins
    pub use_wasm_plugins: bool,
    /// WASM plugins directory
    pub wasm_plugins_dir: Option<PathBuf>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_path: PathBuf::from("./config/policy.yaml"),
            evaluation_mode: "strict".to_string(),
            refresh_interval_seconds: 60,
            use_wasm_plugins: false,
            wasm_plugins_dir: None,
        }
    }
}

/// API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Listen address
    pub listen_addr: String,
    /// Listen port
    pub listen_port: u16,
    /// API path prefix
    pub path_prefix: String,
    /// Enable HTTP/2
    pub enable_http2: bool,
    /// If provided, enable API TLS
    pub tls_cert: Option<PathBuf>,
    /// TLS private key path
    pub tls_key: Option<PathBuf>,
    /// CORS allow origins
    pub cors_allow_origin: Vec<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 8080,
            path_prefix: "/api/v1".to_string(),
            enable_http2: true,
            tls_cert: None,
            tls_key: None,
            cors_allow_origin: vec!["*".to_string()],
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
    /// Enable distributed tracing
    pub enable_tracing: bool,
    /// Tracing collector address
    pub tracing_endpoint: Option<String>,
    /// Tracing sampling rate (0.0-1.0)
    pub tracing_sampling_rate: f64,
    /// Enable structured logging
    pub structured_logging: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            metrics_port: 9091,
            enable_tracing: false,
            tracing_endpoint: None,
            tracing_sampling_rate: 0.1,
            structured_logging: true,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            identity: IdentityConfig::default(),
            proxy: ProxyConfig::default(),
            cert: CertConfig::default(),
            policy: PolicyConfig::default(),
            api: ApiConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables and configuration files
    pub fn load() -> Result<Self, config::ConfigError> {
        use config::{Config as ConfigBuilder, Environment, File};
        use std::env;

        let mut builder = ConfigBuilder::builder();

        // Basic default values
        builder = builder.set_default("general.app_name", "PQSecure Mesh")?;
        builder = builder.set_default("general.mode", "sidecar")?;

        // Load configuration from configuration files
        if let Ok(config_path) = env::var("CONFIG_FILE") {
            builder = builder.add_source(File::with_name(&config_path));
        } else {
            // Try to load from default location
            builder = builder.add_source(File::with_name("config/default").required(false));

            let env = env::var("APP_ENV").unwrap_or_else(|_| "development".into());
            builder = builder.add_source(File::with_name(&format!("config/{}", env)).required(false));
        }

        // Load from environment variables, using prefix and supporting nested properties
        builder = builder.add_source(Environment::with_prefix("PQSM").separator("__"));

        // Build final configuration
        let config = builder.build()?;

        // Convert to strongly-typed configuration
        config.try_deserialize()
    }
    
    /// Get certificate duration
    pub fn cert_duration(&self) -> Duration {
        Duration::from_secs(self.cert.cert_duration_hours * 3600)
    }
    
    /// Get API full address
    pub fn api_address(&self) -> String {
        format!("{}:{}", self.api.listen_addr, self.api.listen_port)
    }
    
    /// Get Proxy full address
    pub fn proxy_address(&self) -> String {
        format!("{}:{}", self.proxy.listen_addr, self.proxy.listen_port)
    }
    
    /// Get SPIFFE ID root path
    pub fn spiffe_id_prefix(&self) -> String {
        format!("spiffe://{}", self.identity.tenant)
    }
    
    /// Check configuration validity
    pub fn validate(&self) -> Result<(), Error> {
        // Check tenant name
        if self.identity.tenant.is_empty() {
            return Err(Error::Config("Tenant name cannot be empty".into()));
        }
        
        // Check service name
        if self.identity.service.is_empty() {
            return Err(Error::Config("Service name cannot be empty".into()));
        }
        
        // Check CA type configuration
        if self.cert.ca_type == "smallstep" && self.cert.ca_url.is_none() {
            return Err(Error::Config("Smallstep CA URL must be provided".into()));
        }
        
        Ok(())
    }
}