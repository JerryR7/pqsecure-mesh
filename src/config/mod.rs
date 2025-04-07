use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Main configuration structure for PQSecure Mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// CA related configuration
    pub ca: CaConfig,

    /// Identity verification configuration
    pub identity: IdentityConfig,

    /// Policy engine configuration
    pub policy: PolicyConfig,

    /// Proxy service configuration
    pub proxy: ProxyConfig,

    /// Telemetry configuration
    pub telemetry: TelemetryConfig,
}

/// Certificate Authority configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    /// Smallstep CA API endpoint
    pub api_url: String,

    /// Path to store/load certificate
    pub cert_path: PathBuf,

    /// Path to store/load private key
    pub key_path: PathBuf,

    /// Bearer token for authentication with CA
    pub token: String,

    /// SPIFFE ID to use when generating CSR
    pub spiffe_id: String,
}

/// Identity verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Trusted domain for SPIFFE IDs
    pub trusted_domain: String,
}

/// Policy engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Path to policy definition file
    pub path: PathBuf,
}

/// Proxy service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address to listen on for incoming connections
    pub listen_addr: SocketAddr,

    /// Backend service configuration
    pub backend: BackendConfig,

    /// Enabled protocols
    pub protocols: ProtocolsConfig,
}

/// Backend service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend service address
    pub address: String,

    /// Connection timeout in seconds
    pub timeout_seconds: u64,
}

/// Protocol enablement configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolsConfig {
    /// Enable TCP protocol
    pub tcp: bool,

    /// Enable HTTP protocol
    pub http: bool,

    /// Enable gRPC protocol
    pub grpc: bool,
}

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// OpenTelemetry collector endpoint
    pub otel_endpoint: Option<String>,

    /// Service name for telemetry
    pub service_name: String,
}

/// Load configuration from file and environment variables
pub fn load_config() -> Result<Config> {
    // 1. Determine config path from environment or use default
    let config_path = env::var("PQSECURE_CONFIG")
        .unwrap_or_else(|_| "config/config.yaml.example".to_string());

    debug!("Loading configuration from {}", config_path);

    // 2. Read and parse YAML configuration
    let config_str = fs::read_to_string(&config_path)
        .context(format!("Failed to read config file: {}", config_path))?;

    let mut config: Config = serde_yaml::from_str(&config_str)
        .context("Failed to parse YAML configuration")?;

    // 3. Override with environment variables if present
    apply_env_overrides(&mut config);

    // 4. Validate configuration
    validate_config(&config)?;

    info!("Configuration loaded successfully");
    Ok(config)
}

/// Apply environment variable overrides to configuration
fn apply_env_overrides(config: &mut Config) {
    if let Ok(url) = env::var("PQSECURE_CA_API_URL") {
        config.ca.api_url = url;
    }

    if let Ok(token) = env::var("PQSECURE_CA_TOKEN") {
        config.ca.token = token;
    }

    if let Ok(addr) = env::var("PQSECURE_LISTEN_ADDR") {
        if let Ok(socket_addr) = addr.parse() {
            config.proxy.listen_addr = socket_addr;
        }
    }

    if let Ok(backend) = env::var("PQSECURE_BACKEND_ADDR") {
        config.proxy.backend.address = backend;
    }

    if let Ok(otel) = env::var("PQSECURE_OTEL_ENDPOINT") {
        config.telemetry.otel_endpoint = Some(otel);
    }
}

/// Validate configuration values
fn validate_config(config: &Config) -> Result<()> {
    // Validate CA configuration
    if config.ca.api_url.is_empty() {
        return Err(anyhow::anyhow!("CA API URL cannot be empty"));
    }

    if config.ca.token.is_empty() {
        return Err(anyhow::anyhow!("CA token cannot be empty"));
    }

    if config.ca.spiffe_id.is_empty() {
        return Err(anyhow::anyhow!("SPIFFE ID cannot be empty"));
    }

    // Validate identity configuration
    if config.identity.trusted_domain.is_empty() {
        return Err(anyhow::anyhow!("Trusted domain cannot be empty"));
    }

    // Validate policy configuration
    if !Path::new(&config.policy.path).exists() {
        return Err(anyhow::anyhow!(
            "Policy file does not exist: {}",
            config.policy.path.display()
        ));
    }

    // Validate proxy configuration
    if config.proxy.backend.address.is_empty() {
        return Err(anyhow::anyhow!("Backend address cannot be empty"));
    }

    if config.proxy.backend.timeout_seconds == 0 {
        return Err(anyhow::anyhow!("Backend timeout cannot be zero"));
    }

    if !config.proxy.protocols.tcp && !config.proxy.protocols.http && !config.proxy.protocols.grpc {
        return Err(anyhow::anyhow!("At least one protocol must be enabled"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_load_valid_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.yaml.example");

        let config_content = r#"
ca:
  api_url: "https://ca.example.com"
  cert_path: "./certs/cert.pem"
  key_path: "./certs/key.pem"
  token: "abc123"
  spiffe_id: "spiffe://example.org/service/test"
identity:
  trusted_domain: "example.org"
policy:
  path: "./policy.yaml.example"
proxy:
  listen_addr: "127.0.0.1:8443"
  backend:
    address: "127.0.0.1:8080"
    timeout_seconds: 30
  protocols:
    tcp: true
    http: true
    grpc: false
telemetry:
  otel_endpoint: "http://otel-collector:4317"
  service_name: "pqsecure-mesh"
"#;

        let mut file = File::create(&config_path).unwrap();
        file.write_all(config_content.as_bytes()).unwrap();

        // Create policy file
        let policy_path = dir.path().join("policy.yaml.example");
        File::create(&policy_path).unwrap();

        // Set environment variable to point to our test config
        env::set_var("PQSECURE_CONFIG", config_path.to_str().unwrap());

        // Test loading the config
        let config = load_config();
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.ca.api_url, "https://ca.example.com");
        assert_eq!(config.identity.trusted_domain, "example.org");
        assert_eq!(config.proxy.listen_addr.to_string(), "127.0.0.1:8443");
        assert_eq!(config.proxy.protocols.tcp, true);
        assert_eq!(config.proxy.protocols.grpc, false);
    }
}