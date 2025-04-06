use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

use crate::common::{ConnectionInfo, ProtocolType, PqSecureError};
use crate::config::BackendConfig;
use crate::identity::SpiffeVerifier;
use crate::policy::PolicyEngine;
use crate::proxy::{forwarder::Forwarder, handler::DefaultConnectionHandler};
use crate::telemetry;

/// Handler for gRPC connections
pub struct GrpcHandler {
    /// Backend configuration
    backend_config: BackendConfig,

    /// Policy engine
    policy_engine: Arc<dyn PolicyEngine>,

    /// SPIFFE verifier
    spiffe_verifier: Arc<SpiffeVerifier>,

    /// Data forwarder
    forwarder: Forwarder,
}

impl GrpcHandler {
    /// Create a new gRPC handler
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

    /// Detect if the connection is a gRPC connection
    async fn is_grpc(&self, stream: &TcpStream) -> bool {
        // In a real implementation, we would peek at the stream to check for gRPC headers
        // For now, we'll just assume it's gRPC as a placeholder
        true
    }

    /// Extract method from gRPC request
    async fn extract_method(&self, _stream: &TcpStream) -> Option<String> {
        // In a real implementation, we would parse the gRPC headers to extract the method
        // For this simplified version, we'll just return a placeholder
        Some("placeholder.method".to_string())
    }
}

#[async_trait::async_trait]
impl DefaultConnectionHandler for GrpcHandler {
    fn protocol_name(&self) -> &'static str {
        "gRPC"
    }

    async fn can_handle(&self, stream: &TcpStream) -> bool {
        self.is_grpc(stream).await
    }
}

#[async_trait::async_trait]
impl crate::proxy::handler::ConnectionHandler for GrpcHandler {
    async fn handle(&self, client_stream: TcpStream) -> Result<()> {
        // Get client address
        let client_addr = client_stream.peer_addr()?;

        // Create connection info
        let mut connection_info = ConnectionInfo::new(client_addr, ProtocolType::Grpc);

        // Extract method (in a real implementation, this would be parsed from the gRPC headers)
        let method = self.extract_method(&client_stream).await
            .unwrap_or_else(|| "unknown".to_string());

        // For this simplified version, we'll use a placeholder SPIFFE ID
        let spiffe_id = "spiffe://example.org/service/client".to_string();

        // Check policy
        let allowed = self.policy_engine.allow(&spiffe_id, &method);
        telemetry::record_policy_decision(&spiffe_id, &method, allowed);

        if !allowed {
            error!(
                "gRPC request denied by policy: {} -> {} (method: {})",
                spiffe_id, self.backend_config.address, method
            );
            return Err(PqSecureError::AuthorizationError(
                "gRPC request denied by policy".to_string(),
            ).into());
        }

        // Connect to backend
        let backend_stream = self.forwarder.connect_to_backend(&self.backend_config.address).await?;

        // Forward data
        info!(
            "Forwarding gRPC connection from {} to {} (method: {})",
            client_addr, self.backend_config.address, method
        );

        self.forwarder.forward(client_stream, backend_stream, &connection_info).await
    }
}