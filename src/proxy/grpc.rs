use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, debug, error};

use crate::common::{Error, Result, ProtocolType};
use crate::proxy::types::{ProxyMetrics, SidecarConfig, MtlsConfig};
use crate::identity::{ServiceIdentity, IdentityProvider};
use crate::policy::PolicyEngine;

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
    pub async fn start(&self) -> Result<()> {
        // This is a simplified implementation that forwards all gRPC traffic
        // A full implementation would need to parse the gRPC protocol and apply policies

        // Obtain or generate identity
        let identity = self.identity_provider.provision_identity(
            &self.config.tenant_id,
            &self.config.service_id,
        ).await?;

        // Create listening address
        let listen_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);

        info!("Starting gRPC proxy on {} -> {}:{}",
              listen_addr, self.config.upstream_addr, self.config.upstream_port);

        // Create TCP listener
        let listener = TcpListener::bind(&listen_addr).await
            .map_err(|e| Error::Proxy(format!("Failed to bind to {}: {}", listen_addr, e)))?;

        // Accept and handle connections
        while let Ok((client_socket, addr)) = listener.accept().await {
            debug!("Accepted connection from {}", addr);

            // Record client connection
            self.metrics.record_client_connection().await;

            // Get configuration and dependencies for this connection
            let upstream_addr = format!("{}:{}", self.config.upstream_addr, self.config.upstream_port);
            let metrics = self.metrics.clone();

            // Start a task to handle the connection
            tokio::spawn(async move {
                // Connect to upstream
                let upstream_socket = match TcpStream::connect(&upstream_addr).await {
                    Ok(socket) => socket,
                    Err(e) => {
                        error!("Failed to connect to upstream {}: {}", upstream_addr, e);
                        metrics.record_request(false).await;
                        metrics.record_client_disconnection().await;
                        return;
                    }
                };

                // Process the connection
                if let Err(e) = handle_grpc_connection(client_socket, upstream_socket).await {
                    error!("Error handling gRPC connection: {}", e);
                    metrics.record_request(false).await;
                } else {
                    metrics.record_request(true).await;
                }

                metrics.record_client_disconnection().await;
            });
        }

        Ok(())
    }
}

/// Handle gRPC connection by forwarding data in both directions
async fn handle_grpc_connection(mut client: TcpStream, mut upstream: TcpStream) -> Result<()> {
    // Set TCP_NODELAY for better performance
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;

    // Split sockets for reading and writing
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    // Forward data in both directions
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];

        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    if let Err(e) = upstream_write.write_all(&buffer[..n]).await {
                        return Err(Error::Proxy(format!("Failed to forward to upstream: {}", e)));
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from client: {}", e))),
            }
        }

        // Shutdown the write side
        let _ = upstream_write.shutdown().await;
        Ok(())
    };

    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];

        loop {
            match upstream_read.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    if let Err(e) = client_write.write_all(&buffer[..n]).await {
                        return Err(Error::Proxy(format!("Failed to forward to client: {}", e)));
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from upstream: {}", e))),
            }
        }

        // Shutdown the write side
        let _ = client_write.shutdown().await;
        Ok(())
    };

    // Process both directions concurrently
    tokio::select! {
        result = client_to_upstream => {
            if let Err(e) = result {
                return Err(e);
            }
        },
        result = upstream_to_client => {
            if let Err(e) = result {
                return Err(e);
            }
        },
    }

    Ok(())
}