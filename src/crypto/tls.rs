use std::sync::Arc;
use std::io;
use std::path::Path;
use tokio::fs;
use rustls::{Certificate, PrivateKey, ServerConfig, ClientConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

use crate::error::Error;
use crate::identity::ServiceIdentity;

/// TLS configuration type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsConfigType {
    /// Server configuration
    Server,
    /// Client configuration
    Client,
}

/// TLS utilities
pub struct TlsUtils;

impl TlsUtils {
    /// Load certificates from a PEM string
    pub fn load_certificates(cert_pem: &str) -> Result<Vec<Certificate>, Error> {
        let mut cert_reader = io::BufReader::new(cert_pem.as_bytes());
        let certs = certs(&mut cert_reader)
            .map_err(|e| Error::Tls(format!("Failed to load certificates: {}", e)))?
            .into_iter()
            .map(Certificate)
            .collect();
        
        Ok(certs)
    }
    
    /// Load private key from a PEM string
    pub fn load_private_key(key_pem: &str) -> Result<PrivateKey, Error> {
        let mut key_reader = io::BufReader::new(key_pem.as_bytes());
        let keys = pkcs8_private_keys(&mut key_reader)
            .map_err(|e| Error::Tls(format!("Failed to load private key: {}", e)))?;
            
        if keys.is_empty() {
            return Err(Error::Tls("No private key found".into()));
        }
        
        Ok(PrivateKey(keys[0].clone()))
    }
    
    /// Load certificates from a file
    pub async fn load_certificates_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<Certificate>, Error> {
        let cert_pem = fs::read_to_string(path).await?;
        Self::load_certificates(&cert_pem)
    }
    
    /// Load private key from a file
    pub async fn load_private_key_from_file<P: AsRef<Path>>(path: P) -> Result<PrivateKey, Error> {
        let key_pem = fs::read_to_string(path).await?;
        Self::load_private_key(&key_pem)
    }
    
    /// Create TLS configuration from identity
    pub fn create_tls_config(
        identity: &ServiceIdentity,
        config_type: TlsConfigType,
        require_client_auth: bool,
    ) -> Result<Arc<dyn std::any::Any>, Error> {
        match config_type {
            TlsConfigType::Server => {
                let certs = Self::load_certificates(&identity.cert_pem)?;
                let key = Self::load_private_key(&identity.key_pem)?;
                
                let mut server_config = ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth();
                
                // If mTLS, require client authentication
                if require_client_auth {
                    let mut client_auth_roots = rustls::RootCertStore::empty();
                    
                    // Load CA certificates
                    if let Some(chain_pem) = &identity.chain_pem {
                        let ca_certs = Self::load_certificates(chain_pem)?;
                        for cert in ca_certs {
                            client_auth_roots.add(&cert)
                                .map_err(|e| Error::Tls(format!("Failed to add CA cert: {}", e)))?;
                        }
                    }
                    
                    server_config = ServerConfig::builder()
                        .with_safe_defaults()
                        .with_client_cert_verifier(
                            Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots))
                        );
                }
                
                // Add certificate chain and private key
                server_config.set_single_cert(certs, key)
                    .map_err(|e| Error::Tls(format!("Failed to set certificate: {}", e)))?;
                
                Ok(Arc::new(server_config))
            },
            TlsConfigType::Client => {
                let certs = Self::load_certificates(&identity.cert_pem)?;
                let key = Self::load_private_key(&identity.key_pem)?;
                
                let mut root_store = rustls::RootCertStore::empty();
                
                // Load CA certificates
                if let Some(chain_pem) = &identity.chain_pem {
                    let ca_certs = Self::load_certificates(chain_pem)?;
                    for cert in ca_certs {
                        root_store.add(&cert)
                            .map_err(|e| Error::Tls(format!("Failed to add CA cert: {}", e)))?;
                    }
                }
                
                // Create client configuration
                let client_config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_single_cert(certs, key)
                    .map_err(|e| Error::Tls(format!("Failed to set certificate: {}", e)))?;
                
                Ok(Arc::new(client_config))
            }
        }
    }
    
    /// Create TLS configuration from files
    pub async fn create_tls_config_from_files<P1, P2, P3>(
        cert_path: P1,
        key_path: P2,
        ca_path: Option<P3>,
        config_type: TlsConfigType,
        require_client_auth: bool,
    ) -> Result<Arc<dyn std::any::Any>, Error>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        P3: AsRef<Path>,
    {
        // Load certificates
        let certs = Self::load_certificates_from_file(cert_path).await?;
        let key = Self::load_private_key_from_file(key_path).await?;
        
        match config_type {
            TlsConfigType::Server => {
                let mut server_config = ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth();
                
                // If mTLS, require client authentication
                if require_client_auth {
                    let mut client_auth_roots = rustls::RootCertStore::empty();
                    
                    // Load CA certificates
                    if let Some(ca_path) = ca_path {
                        let ca_pem = fs::read_to_string(ca_path).await?;
                        let ca_certs = Self::load_certificates(&ca_pem)?;
                        for cert in ca_certs {
                            client_auth_roots.add(&cert)
                                .map_err(|e| Error::Tls(format!("Failed to add CA cert: {}", e)))?;
                        }
                    }
                    
                    server_config = ServerConfig::builder()
                        .with_safe_defaults()
                        .with_client_cert_verifier(
                            Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(client_auth_roots))
                        );
                }
                
                // Add certificate chain and private key
                server_config.set_single_cert(certs, key)
                    .map_err(|e| Error::Tls(format!("Failed to set certificate: {}", e)))?;
                
                Ok(Arc::new(server_config))
            },
            TlsConfigType::Client => {
                let mut root_store = rustls::RootCertStore::empty();
                
                // Load CA certificates
                if let Some(ca_path) = ca_path {
                    let ca_pem = fs::read_to_string(ca_path).await?;
                    let ca_certs = Self::load_certificates(&ca_pem)?;
                    for cert in ca_certs {
                        root_store.add(&cert)
                            .map_err(|e| Error::Tls(format!("Failed to add CA cert: {}", e)))?;
                    }
                }
                
                // Create client configuration
                let client_config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_store)
                    .with_single_cert(certs, key)
                    .map_err(|e| Error::Tls(format!("Failed to set certificate: {}", e)))?;
                
                Ok(Arc::new(client_config))
            }
        }
    }
    
    /// Check if the TLS connection uses post-quantum cryptography
    pub fn is_pqc_connection(_conn: &impl std::any::Any) -> bool {
        // Note: This is a placeholder implementation
        // The actual implementation should check the connection's cipher suite
        false
    }
}