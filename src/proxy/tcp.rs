use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn, debug, error, trace};

use crate::error::Error;
use crate::proxy::types::{ProxyMetrics, SidecarConfig, MtlsConfig};
use crate::identity::{ServiceIdentity, IdentityProvider};
use crate::policy::PolicyEngine;
use crate::crypto::tls::{TlsUtils, TlsConfigType};

/// TCP Proxy
pub struct TcpProxy {
    /// Sidecar configuration
    pub config: SidecarConfig,
    /// Identity provider
    pub identity_provider: Arc<dyn IdentityProvider>,
    /// Policy engine
    pub policy_engine: Arc<PolicyEngine>,
    /// Metrics collector
    pub metrics: Arc<ProxyMetrics>,
}

impl TcpProxy {
    /// Create a new TCP proxy
    pub fn new(
        config: SidecarConfig,
        identity_provider: Arc<dyn IdentityProvider>,
        policy_engine: Arc<PolicyEngine>,
        metrics: Arc<ProxyMetrics>,
    ) -> Self {
        Self {
            config,
            identity_provider,
            policy_engine,
            metrics,
        }
    }
    
    /// Start the TCP proxy
    pub async fn start(&self) -> Result<(), Error> {
        // Obtain or generate identity
        let identity = self.identity_provider.provision_identity(
            &self.config.tenant_id,
            &self.config.service_id,
        ).await?;
        
        // Create listening address
        let listen_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        info!("Starting TCP proxy on {} -> {}:{}", 
              listen_addr, self.config.upstream_addr, self.config.upstream_port);
        
        // Create TLS configuration (if mTLS is enabled)
        let server_tls_config = if self.config.mtls_config.enable_mtls {
            Some(self.create_server_tls_config(&identity)?)
        } else {
            None
        };
        
        // Start listening
        let listener = TcpListener::bind(&listen_addr).await
            .map_err(|e| Error::Proxy(format!("Failed to bind to {}: {}", listen_addr, e)))?;
        
        info!("TCP proxy is listening on {}", listen_addr);
        
        loop {
            // Accept new connections
            let (client_socket, client_addr) = match listener.accept().await {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };
            
            debug!("Accepted connection from {}", client_addr);
            
            // If mTLS is enabled, handle TLS connection
            let server_tls_config_clone = server_tls_config.clone();
            let identity_clone = identity.clone();
            let policy_engine_clone = self.policy_engine.clone();
            let mtls_config = self.config.mtls_config.clone();
            let upstream_addr = format!("{}:{}", self.config.upstream_addr, self.config.upstream_port);
            let metrics_clone = self.metrics.clone();
            
            // Record client connection
            self.metrics.record_client_connection(false).await;
            
            // Start a task to handle the connection
            tokio::spawn(async move {
                let start_time = Instant::now();
                
                let result = if let Some(tls_config) = server_tls_config_clone {
                    handle_tls_connection(
                        client_socket,
                        client_addr.to_string(),
                        &upstream_addr,
                        tls_config,
                        &identity_clone,
                        policy_engine_clone,
                        &mtls_config,
                        metrics_clone.clone(),
                    ).await
                } else {
                    handle_plain_connection(
                        client_socket,
                        client_addr.to_string(),
                        &upstream_addr,
                        metrics_clone.clone(),
                    ).await
                };
                
                // Record the result
                let success = result.is_ok();
                let elapsed = start_time.elapsed().as_millis() as f64;
                metrics_clone.record_request(success, elapsed).await;
                metrics_clone.record_client_disconnection().await;
                
                if let Err(e) = result {
                    error!("Connection handling error: {}", e);
                }
            });
        }
    }
    
    /// Create TLS server configuration
    fn create_server_tls_config(&self, identity: &ServiceIdentity) -> Result<Arc<rustls::ServerConfig>, Error> {
        let tls_config = TlsUtils::create_tls_config(
            identity,
            TlsConfigType::Server,
            self.config.mtls_config.enable_mtls,
        )?;
        
        match tls_config.downcast::<rustls::ServerConfig>() {
            Ok(config) => Ok(config),
            Err(_) => Err(Error::Tls("Failed to downcast to ServerConfig".into())),
        }
    }
}

/// Handle plain TCP connection
async fn handle_plain_connection(
    mut client_socket: TcpStream,
    client_addr: String,
    upstream_addr: &str,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Error> {
    // Connect to upstream service
    let mut upstream_socket = TcpStream::connect(upstream_addr).await
        .map_err(|e| Error::Proxy(format!("Failed to connect to upstream {}: {}", upstream_addr, e)))?;
    
    debug!("Connected to upstream {}", upstream_addr);
    metrics.record_upstream_connection().await;
    
    // Set socket parameters
    client_socket.set_nodelay(true)
        .map_err(|e| Error::Proxy(format!("Failed to set nodelay on client socket: {}", e)))?;
    upstream_socket.set_nodelay(true)
        .map_err(|e| Error::Proxy(format!("Failed to set nodelay on upstream socket: {}", e)))?;
    
    // Bidirectional data copy
    match copy_bidirectional(&mut client_socket, &mut upstream_socket).await {
        Ok((from_client, from_upstream)) => {
            debug!("Connection closed: client {} <-> upstream {}, bytes client->upstream: {}, bytes upstream->client: {}", 
                   client_addr, upstream_addr, from_client, from_upstream);
            
            // Record data transfer
            metrics.record_data_transfer(true, from_client as usize).await;
            metrics.record_data_transfer(false, from_upstream as usize).await;
            
            Ok(())
        },
        Err(e) => {
            warn!("Error during data transfer: client {} <-> upstream {}: {}", 
                  client_addr, upstream_addr, e);
            Err(Error::Proxy(format!("Data transfer error: {}", e)))
        }
    }
}

/// Handle TLS connection
#[allow(clippy::too_many_arguments)]
async fn handle_tls_connection(
    client_socket: TcpStream,
    client_addr: String,
    upstream_addr: &str,
    tls_config: Arc<rustls::ServerConfig>,
    identity: &ServiceIdentity,
    policy_engine: Arc<PolicyEngine>,
    mtls_config: &MtlsConfig,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Error> {
    debug!("Starting TLS handshake with client {}", client_addr);
    
    // Establish TLS connection
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let tls_stream = tls_acceptor.accept(client_socket).await
        .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;
    
    debug!("TLS handshake completed with client {}", client_addr);
    
    // If mTLS is enabled, verify client certificate
    if mtls_config.enable_mtls {
        // Get client certificate
        let (client_socket, server_session) = tls_stream.get_ref();
        
        // Check if client certificate exists
        if let Some(client_cert) = server_session.peer_certificates().and_then(|certs| certs.first()) {
            // Extract SPIFFE ID
            let client_cert_pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                                        base64::encode(&client_cert.0));
            
            // Extract SPIFFE ID
            let spiffe_id = match crate::identity::x509::X509Utils::extract_spiffe_id(&client_cert_pem)? {
                Some(id) => id,
                None => return Err(Error::AccessDenied("Client certificate does not contain a valid SPIFFE ID".into())),
            };
            
            debug!("Client certificate has SPIFFE ID: {}", spiffe_id.uri);
            
            // Evaluate policy
            let allowed = policy_engine.evaluate_request(&spiffe_id, "CONNECT", "", crate::types::ProtocolType::Tcp).await?;
            
            if !allowed {
                metrics.record_rejected().await;
                return Err(Error::AccessDenied(format!("Policy denied access for SPIFFE ID: {}", spiffe_id.uri)));
            }
            
            debug!("Policy allowed access for SPIFFE ID: {}", spiffe_id.uri);
        } else if mtls_config.enable_mtls {
            metrics.record_rejected().await;
            return Err(Error::AccessDenied("Client did not provide a certificate but mTLS is required".into()));
        }
    }
    
    // Connect to upstream service
    let mut upstream_socket = TcpStream::connect(upstream_addr).await
        .map_err(|e| Error::Proxy(format!("Failed to connect to upstream {}: {}", upstream_addr, e)))?;
    
    debug!("Connected to upstream {}", upstream_addr);
    metrics.record_upstream_connection().await;
    
    // Set socket parameters
    upstream_socket.set_nodelay(true)
        .map_err(|e| Error::Proxy(format!("Failed to set nodelay on upstream socket: {}", e)))?;
    
    // If upstream also requires TLS
    let (mut client_reader, mut client_writer) = tokio::io::split(tls_stream);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_socket);
    
    // Create two tasks for bidirectional data transfer
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    match upstream_writer.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!("Client -> Upstream: {} bytes", n);
                        },
                        Err(e) => return Err(Error::Proxy(format!("Failed to write to upstream: {}", e))),
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from client: {}", e))),
            }
        }
        
        // Ensure all data is written
        upstream_writer.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush upstream: {}", e)))?;
        
        // Close write after completion
        upstream_writer.shutdown().await
            .map_err(|e| Error::Proxy(format!("Failed to shutdown upstream: {}", e)))?;
        
        Ok::<usize, Error>(total_bytes)
    };
    
    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match upstream_reader.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    match client_writer.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!("Upstream -> Client: {} bytes", n);
                        },
                        Err(e) => return Err(Error::Proxy(format!("Failed to write to client: {}", e))),
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from upstream: {}", e))),
            }
        }
        
        // Ensure all data is written
        client_writer.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush client: {}", e)))?;
        
        // Close write after completion
        client_writer.shutdown().await
            .map_err(|e| Error::Proxy(format!("Failed to shutdown client: {}", e)))?;
        
        Ok::<usize, Error>(total_bytes)
    };
    
    // Run bidirectional data transfer simultaneously
    match tokio::try_join!(client_to_upstream, upstream_to_client) {
        Ok((client_to_upstream_bytes, upstream_to_client_bytes)) => {
            debug!("Connection closed: client {} <-> upstream {}, bytes client->upstream: {}, bytes upstream->client: {}", 
                   client_addr, upstream_addr, client_to_upstream_bytes, upstream_to_client_bytes);
            
            // Record data transfer
            metrics.record_data_transfer(true, client_to_upstream_bytes).await;
            metrics.record_data_transfer(false, upstream_to_client_bytes).await;
            
            Ok(())
        },
        Err(e) => Err(e),
    }
}