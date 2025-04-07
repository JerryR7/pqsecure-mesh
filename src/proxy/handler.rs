use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{error, info};

use crate::common::{ConnectionInfo, ProtocolType, PqSecureError, ServiceIdentity};
use crate::config::BackendConfig;
use crate::identity::SpiffeVerifier;
use crate::policy::PolicyEngine;
use crate::proxy::forwarder::Forwarder;

/// Trait for handling client connections
#[async_trait::async_trait]
pub trait ConnectionHandler: Send + Sync {
    async fn handle(&self, stream: TcpStream) -> anyhow::Result<()>;
}

/// Trait for default connection handling logic
#[async_trait::async_trait]
pub trait DefaultConnectionHandler: ConnectionHandler {
    /// Protocol-specific name for identification
    fn protocol_name(&self) -> &'static str;

    /// Check if this handler should process this connection
    async fn can_handle(&self, stream: &TcpStream) -> bool;
}

/// Base handler with common functionality for all protocol handlers
pub struct BaseHandler {
    /// Backend configuration
    pub backend_config: BackendConfig,

    /// Policy engine
    pub policy_engine: Arc<dyn PolicyEngine>,

    /// SPIFFE verifier
    pub spiffe_verifier: Arc<SpiffeVerifier>,

    /// Data forwarder
    pub forwarder: Forwarder,
}

impl BaseHandler {
    /// Create a new base handler
    pub fn new(
        backend_config: BackendConfig,
        policy_engine: Arc<dyn PolicyEngine>,
        spiffe_verifier: Arc<SpiffeVerifier>,
    ) -> Result<Self> {
        let forwarder = Forwarder::new(backend_config.timeout_seconds);

        Ok(Self {
            backend_config,
            policy_engine,
            spiffe_verifier,
            forwarder,
        })
    }
    
    /// Extract SPIFFE ID from certificate
    pub fn extract_spiffe_id(&self, cert: &rustls::pki_types::CertificateDer<'_>) -> Result<ServiceIdentity> {
        self.spiffe_verifier.extract_spiffe_id(cert)
    }

    /// Connect to backend and forward data
    pub async fn connect_and_forward(
        &self, 
        client_stream: TcpStream, 
        connection_info: &ConnectionInfo,
        spiffe_id: &str, 
        method: &str,
        allowed: bool
    ) -> Result<()> {
        if !allowed {
            error!(
                "Connection denied by policy: {} -> {} (method: {})",
                spiffe_id, self.backend_config.address, method
            );
            return Err(PqSecureError::AuthorizationError(
                format!("{:?} request denied by policy", connection_info.protocol_type)
            ).into());
        }

        // Connect to backend
        let backend_stream = self.forwarder.connect_to_backend(&self.backend_config.address).await?;

        // Get client address for logging
        let client_addr = connection_info.source_addr.to_string();

        // Forward data with appropriate log message based on protocol type
        match connection_info.protocol_type {
            ProtocolType::Http => {
                info!(
                    "Forwarding HTTP connection from {} to {} ({})",
                    client_addr, self.backend_config.address, method
                );
            },
            ProtocolType::Grpc => {
                info!(
                    "Forwarding gRPC connection from {} to {} (method: {})",
                    client_addr, self.backend_config.address, method
                );
            },
            ProtocolType::Tcp => {
                info!(
                    "Forwarding TCP connection from {} to {}",
                    client_addr, self.backend_config.address
                );
            },
        }

        self.forwarder.forward(client_stream, backend_stream, connection_info).await
    }
}