use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpStream;

use crate::common::{ConnectionInfo, ProtocolType, PqSecureError};
use crate::config::BackendConfig;
use crate::identity::SpiffeVerifier;
use crate::policy::PolicyEngine;
use crate::proxy::handler::{BaseHandler, DefaultConnectionHandler};
use crate::proxy::pqc_acceptor::get_current_client_cert;
use crate::telemetry;

/// Handler for raw TCP connections
pub struct TcpHandler {
    /// Common base handler with shared functionality
    base: BaseHandler,
}

impl TcpHandler {
    /// Create a new TCP handler
    pub fn new(
        backend_config: BackendConfig,
        policy_engine: Arc<dyn PolicyEngine>,
        spiffe_verifier: Arc<SpiffeVerifier>,
    ) -> Result<Self> {
        let base = BaseHandler::new(backend_config, policy_engine, spiffe_verifier)?;
        Ok(Self { base })
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

        // Get client certificate from thread-local storage
        let client_cert = get_current_client_cert()
            .ok_or_else(|| PqSecureError::AuthenticationError("No client certificate found".to_string()))?;

        // Extract SPIFFE ID from certificate
        let identity = self.base.extract_spiffe_id(&client_cert)
            .context("Failed to extract SPIFFE ID from certificate")?;

        // Update connection info with identity
        connection_info = connection_info.with_identity(identity.clone());

        // Policy check with generic method for TCP
        let method = "connect";
        let spiffe_id = &identity.spiffe_id;

        // Check if the connection is allowed by policy
        let allowed = self.base.policy_engine.allow(spiffe_id, method);
        telemetry::record_policy_decision(spiffe_id, method, allowed);

        // Use base handler to connect and forward
        self.base.connect_and_forward(client_stream, &connection_info, spiffe_id, method, allowed).await
    }
}