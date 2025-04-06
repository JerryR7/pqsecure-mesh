use anyhow::Result;
use rustls::Certificate;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use crate::common::{ConnectionInfo, ProtocolType, ServiceIdentity, PqSecureError};
use crate::config::BackendConfig;
use crate::identity::{IdentityExtractor, SpiffeVerifier};
use crate::policy::PolicyEngine;
use crate::proxy::{forwarder::Forwarder, handler::DefaultConnectionHandler};
use crate::telemetry;

/// Handler for raw TCP connections
pub struct TcpHandler {
    /// Backend configuration
    backend_config: BackendConfig,

    /// Policy engine
    policy_engine: Arc<dyn PolicyEngine>,

    /// SPIFFE verifier
    spiffe_verifier: Arc<SpiffeVerifier>,

    /// Data forwarder
    forwarder: Forwarder,
}

impl TcpHandler {
    /// Create a new TCP handler
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
}

#[async_trait::async_trait]
impl DefaultConnectionHandler for TcpHandler {
    fn protocol_name(&self) -> &'static str {
        "TCP"
    }

    async fn can_handle(&self, _stream: &TcpStream) -> bool {
        // TCP handler can handle any connection
        true
    }
}

#[async_trait::async_trait]
impl crate::proxy::handler::ConnectionHandler for TcpHandler {
    async fn handle(&self, client_stream: TcpStream) -> Result<()> {
        // Get client address
        let client_addr = client_stream.peer_addr()?;

        // Create connection info
        let mut connection_info = ConnectionInfo::new(client_addr, ProtocolType::Tcp);

        // Extract client certificate and identity
        // For this simplified version, we'll assume the identity has already been verified
        // during TLS handshake

        // Policy check with generic method for TCP
        let method = "connect";
        let spiffe_id = format!("spiffe://example.org/service/client"); // Placeholder

        let allowed = self.policy_engine.allow(&spiffe_id, method);
        telemetry::record_policy_decision(&spiffe_id, method, allowed);

        if !allowed {
            error!(
                "Connection denied by policy: {} -> {} (method: {})",
                spiffe_id, self.backend_config.address, method
            );
            return Err(PqSecureError::AuthorizationError(
                "Connection denied by policy".to_string(),
            ).into());
        }

        // Connect to backend
        let backend_stream = self.forwarder.connect_to_backend(&self.backend_config.address).await?;

        // Forward data
        info!(
            "Forwarding TCP connection from {} to {}",
            client_addr, self.backend_config.address
        );

        self.forwarder.forward(client_stream, backend_stream, &connection_info).await
    }
}