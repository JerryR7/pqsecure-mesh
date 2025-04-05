use bytes::{Bytes, BytesMut};
use h2::client::SendRequest;
use h2::server::SendResponse;
use http::{HeaderMap, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, trace, warn};

use crate::error::Error;
use crate::identity::{IdentityProvider, ServiceIdentity, SpiffeId};
use crate::policy::PolicyEngine;
use crate::proxy::types::{MtlsConfig, ProxyMetrics, SidecarConfig};

/// gRPC Proxy
pub struct GrpcProxy {
    /// Sidecar configuration
    pub config: SidecarConfig,
    /// Identity provider
    pub identity_provider: Arc<dyn IdentityProvider>,
    /// Policy engine
    pub policy_engine: Arc<PolicyEngine>,
    /// Metrics collector
    pub metrics: Arc<ProxyMetrics>,
}

impl GrpcProxy {
    /// Create a new gRPC proxy
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

    /// Start the gRPC proxy
    pub async fn start(&self) -> Result<(), Error> {
        // Obtain or generate identity
        let identity = self
            .identity_provider
            .provision_identity(&self.config.tenant_id, &self.config.service_id)
            .await?;

        // Create listening address
        let listen_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        info!(
            "Starting gRPC proxy on {} -> {}:{}",
            listen_addr, self.config.upstream_addr, self.config.upstream_port
        );

        // Create TCP listener
        let listener = TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| Error::Proxy(format!("Failed to bind to {}: {}", listen_addr, e)))?;

        info!("gRPC proxy listening on {}", listen_addr);

        // Create TLS configuration (if mTLS is enabled)
        let tls_config = if self.config.mtls_config.enable_mtls {
            Some(self.create_server_tls_config(&identity)?)
        } else {
            None
        };

        // Handle connections
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("Accepted connection from {}", addr);

                    // Record client connection
                    self.metrics.record_client_connection(false).await;

                    let policy_engine = self.policy_engine.clone();
                    let metrics = self.metrics.clone();
                    let upstream_addr = format!(
                        "{}:{}",
                        self.config.upstream_addr, self.config.upstream_port
                    );
                    let mtls_config = self.config.mtls_config.clone();
                    let tls_config_clone = tls_config.clone();
                    let identity_clone = identity.clone();

                    tokio::spawn(async move {
                        let start_time = Instant::now();

                        let result = if let Some(tls_config) = tls_config_clone {
                            handle_tls_grpc_connection(
                                socket,
                                addr.to_string(),
                                &upstream_addr,
                                tls_config,
                                &identity_clone,
                                policy_engine,
                                &mtls_config,
                                metrics.clone(),
                            )
                            .await
                        } else {
                            handle_plain_grpc_connection(
                                socket,
                                addr.to_string(),
                                &upstream_addr,
                                metrics.clone(),
                            )
                            .await
                        };

                        // Record result
                        let success = result.is_ok();
                        let elapsed = start_time.elapsed().as_millis() as f64;
                        metrics.record_request(success, elapsed).await;
                        metrics.record_client_disconnection().await;

                        if let Err(e) = result {
                            error!("gRPC connection handling error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            }
        }
    }

    /// Create TLS server configuration
    fn create_server_tls_config(
        &self,
        identity: &ServiceIdentity,
    ) -> Result<Arc<rustls::ServerConfig>, Error> {
        let tls_config = crate::crypto::tls::TlsUtils::create_tls_config(
            identity,
            crate::crypto::tls::TlsConfigType::Server,
            self.config.mtls_config.enable_mtls,
        )?;

        match tls_config.downcast::<rustls::ServerConfig>() {
            Ok(config) => Ok(config),
            Err(_) => Err(Error::Tls("Failed to downcast to ServerConfig".into())),
        }
    }
}

/// Handle plain gRPC connection
async fn handle_plain_grpc_connection(
    mut client_socket: TcpStream,
    client_addr: String,
    upstream_addr: &str,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Error> {
    debug!("Handling plain gRPC connection from {}", client_addr);

    // Connect to upstream service
    let mut upstream_socket = TcpStream::connect(upstream_addr).await.map_err(|e| {
        Error::Proxy(format!(
            "Failed to connect to upstream {}: {}",
            upstream_addr, e
        ))
    })?;

    debug!("Connected to upstream gRPC server at {}", upstream_addr);
    metrics.record_upstream_connection().await;

    // Set socket parameters
    client_socket
        .set_nodelay(true)
        .map_err(|e| Error::Proxy(format!("Failed to set nodelay on client socket: {}", e)))?;
    upstream_socket
        .set_nodelay(true)
        .map_err(|e| Error::Proxy(format!("Failed to set nodelay on upstream socket: {}", e)))?;

    // Forward data in both directions
    let (mut client_read, mut client_write) = client_socket.split();
    let (mut upstream_read, mut upstream_write) = upstream_socket.split();

    // Create two tasks to forward data
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;

        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => match upstream_write.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        total_bytes += n;
                        trace!("Client -> Upstream: {} bytes", n);
                    }
                    Err(e) => {
                        return Err(Error::Proxy(format!("Failed to write to upstream: {}", e)))
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from client: {}", e))),
            }
        }

        // Ensure all data is written
        upstream_write
            .flush()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to flush upstream: {}", e)))?;

        Ok::<usize, Error>(total_bytes)
    };

    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;

        loop {
            match upstream_read.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => match client_write.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        total_bytes += n;
                        trace!("Upstream -> Client: {} bytes", n);
                    }
                    Err(e) => {
                        return Err(Error::Proxy(format!("Failed to write to client: {}", e)))
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from upstream: {}", e))),
            }
        }

        // Ensure all data is written
        client_write
            .flush()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to flush client: {}", e)))?;

        Ok::<usize, Error>(total_bytes)
    };

    // Run data forwarding in both directions simultaneously
    match tokio::try_join!(client_to_upstream, upstream_to_client) {
        Ok((client_to_upstream_bytes, upstream_to_client_bytes)) => {
            debug!("gRPC connection closed: client {} <-> upstream {}, bytes client->upstream: {}, bytes upstream->client: {}", 
                   client_addr, upstream_addr, client_to_upstream_bytes, upstream_to_client_bytes);

            // Record data transfer
            metrics
                .record_data_transfer(true, client_to_upstream_bytes)
                .await;
            metrics
                .record_data_transfer(false, upstream_to_client_bytes)
                .await;

            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Handle TLS gRPC connection
#[allow(clippy::too_many_arguments)]
async fn handle_tls_grpc_connection(
    client_socket: TcpStream,
    client_addr: String,
    upstream_addr: &str,
    tls_config: Arc<rustls::ServerConfig>,
    identity: &ServiceIdentity,
    policy_engine: Arc<PolicyEngine>,
    mtls_config: &MtlsConfig,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Error> {
    debug!("Handling TLS gRPC connection from {}", client_addr);

    // Establish TLS connection
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let tls_stream = tls_acceptor
        .accept(client_socket)
        .await
        .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;

    debug!("TLS handshake completed with client {}", client_addr);

    // If mTLS is enabled, verify client certificate
    if mtls_config.enable_mtls {
        // Get client certificate
        let (_, server_session) = tls_stream.get_ref();

        // Check if client certificate exists
        if let Some(client_cert) = server_session
            .peer_certificates()
            .and_then(|certs| certs.first())
        {
            // Extract SPIFFE ID
            let client_cert_pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                base64::encode(&client_cert.0)
            );

            // Extract SPIFFE ID
            let spiffe_id =
                match crate::identity::x509::X509Utils::extract_spiffe_id(&client_cert_pem)? {
                    Some(id) => id,
                    None => {
                        return Err(Error::AccessDenied(
                            "Client certificate does not contain a valid SPIFFE ID".into(),
                        ))
                    }
                };

            debug!("Client certificate has SPIFFE ID: {}", spiffe_id.uri);

            // Evaluate policy
            // For gRPC, we can't easily get the method name at this level, so we just evaluate connection permission
            let allowed = policy_engine
                .evaluate_request(&spiffe_id, "CONNECT", "", crate::types::ProtocolType::Grpc)
                .await?;

            if !allowed {
                metrics.record_rejected().await;
                return Err(Error::AccessDenied(format!(
                    "Policy denied access for SPIFFE ID: {}",
                    spiffe_id.uri
                )));
            }

            debug!("Policy allowed access for SPIFFE ID: {}", spiffe_id.uri);
        } else if mtls_config.enable_mtls {
            metrics.record_rejected().await;
            return Err(Error::AccessDenied(
                "Client did not provide a certificate but mTLS is required".into(),
            ));
        }
    }

    // Connect to upstream service
    let mut upstream_socket = TcpStream::connect(upstream_addr).await.map_err(|e| {
        Error::Proxy(format!(
            "Failed to connect to upstream {}: {}",
            upstream_addr, e
        ))
    })?;

    debug!("Connected to upstream gRPC server at {}", upstream_addr);
    metrics.record_upstream_connection().await;

    // Set socket parameters
    upstream_socket
        .set_nodelay(true)
        .map_err(|e| Error::Proxy(format!("Failed to set nodelay on upstream socket: {}", e)))?;

    // Split TLS stream into read and write parts
    let (mut client_reader, mut client_writer) = tokio::io::split(tls_stream);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_socket);

    // Create two tasks to forward data
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;

        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => match upstream_writer.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        total_bytes += n;
                        trace!("Client -> Upstream: {} bytes", n);
                    }
                    Err(e) => {
                        return Err(Error::Proxy(format!("Failed to write to upstream: {}", e)))
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from client: {}", e))),
            }
        }

        // Ensure all data is written
        upstream_writer
            .flush()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to flush upstream: {}", e)))?;

        // Close write end
        upstream_writer
            .shutdown()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to shutdown upstream writer: {}", e)))?;

        Ok::<usize, Error>(total_bytes)
    };

    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;

        loop {
            match upstream_reader.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => match client_writer.write_all(&buffer[..n]).await {
                    Ok(_) => {
                        total_bytes += n;
                        trace!("Upstream -> Client: {} bytes", n);
                    }
                    Err(e) => {
                        return Err(Error::Proxy(format!("Failed to write to client: {}", e)))
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from upstream: {}", e))),
            }
        }

        // Ensure all data is written
        client_writer
            .flush()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to flush client: {}", e)))?;

        // Close write end
        client_writer
            .shutdown()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to shutdown client writer: {}", e)))?;

        Ok::<usize, Error>(total_bytes)
    };

    // Run data forwarding in both directions simultaneously
    match tokio::try_join!(client_to_upstream, upstream_to_client) {
        Ok((client_to_upstream_bytes, upstream_to_client_bytes)) => {
            debug!("TLS gRPC connection closed: client {} <-> upstream {}, bytes client->upstream: {}, bytes upstream->client: {}", 
                   client_addr, upstream_addr, client_to_upstream_bytes, upstream_to_client_bytes);

            // Record data transfer
            metrics
                .record_data_transfer(true, client_to_upstream_bytes)
                .await;
            metrics
                .record_data_transfer(false, upstream_to_client_bytes)
                .await;

            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Extract SPIFFE ID from headers
fn extract_spiffe_id_from_headers(headers: &HeaderMap) -> Option<SpiffeId> {
    if let Some(header) = headers.get("x-spiffe-id") {
        if let Ok(value) = header.to_str() {
            if let Ok(id) = SpiffeId::from_uri(value) {
                return Some(id);
            }
        }
    }

    None
}

/// Extract service and method from gRPC path
fn extract_grpc_service_method(path: &str) -> Option<(String, String)> {
    // gRPC path format: /package.Service/Method
    let path = path.trim_start_matches('/');

    if let Some(idx) = path.rfind('/') {
        let service = path[..idx].to_string();
        let method = path[(idx + 1)..].to_string();
        return Some((service, method));
    }

    None
}