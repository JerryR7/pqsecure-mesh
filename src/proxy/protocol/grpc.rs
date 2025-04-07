use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpStream;

use crate::common::{ConnectionInfo, PqSecureError, ProtocolType};
use crate::config::BackendConfig;
use crate::identity::SpiffeVerifier;
use crate::policy::PolicyEngine;
use crate::proxy::handler::{BaseHandler, DefaultConnectionHandler};
use crate::proxy::pqc_acceptor::get_current_client_cert;
use crate::telemetry;

/// Handler for gRPC connections
pub struct GrpcHandler {
    /// Common base handler with shared functionality
    base: BaseHandler,
}

impl GrpcHandler {
    /// Create a new gRPC handler
    pub fn new(
        backend_config: BackendConfig,
        policy_engine: Arc<dyn PolicyEngine>,
        spiffe_verifier: Arc<SpiffeVerifier>,
    ) -> Result<Self> {
        let base = BaseHandler::new(backend_config, policy_engine, spiffe_verifier)?;

        Ok(Self { base })
    }

    /// Detect if the connection is a gRPC connection
    async fn is_grpc(&self, stream: &TcpStream) -> bool {
        // Create a peek buffer - HTTP/2 preface is "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        let mut buf = [0u8; 24];

        // Use the stream reference
        let peek_stream = stream;

        // Set to non-blocking to prevent hanging
        if let Err(_) = peek_stream.set_nodelay(true) {
            return false;
        }

        // Peek at the first few bytes
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            peek_stream.peek(&mut buf)
        ).await {
            Ok(Ok(n)) if n >= 3 => {
                // Check for HTTP/2 preface
                if n >= 24 {
                    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                    return &buf[0..24] == preface;
                }

                // Alternative check for HTTP/2 settings frame
                // HTTP/2 settings frames start with a length (3 bytes), followed by type (1 byte, value 4 for settings)
                // and flags (1 byte), then stream identifier (4 bytes, usually 0)
                // This is a simplified check
                if n >= 5 && buf[3] == 4 {
                    return true;
                }

                false
            },
            _ => false,
        }
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

        // Get client certificate from thread-local storage
        let client_cert = get_current_client_cert()
            .ok_or_else(|| PqSecureError::AuthenticationError("No client certificate found".to_string()))?;

        // Extract SPIFFE ID from certificate
        let identity = self.base.extract_spiffe_id(&client_cert)
            .context("Failed to extract SPIFFE ID from certificate")?;

        // Update connection info with identity
        connection_info = connection_info.with_identity(identity.clone());

        // Extract method (in a real implementation, this would be parsed from the gRPC headers)
        let method = self.extract_method(&client_stream).await
            .unwrap_or_else(|| "unknown".to_string());

        // Update connection info with method
        connection_info = connection_info.with_method(method.clone());

        // Get SPIFFE ID for policy check
        let spiffe_id = &identity.spiffe_id;

        // Check policy
        let allowed = self.base.policy_engine.allow(spiffe_id, &method);
        telemetry::record_policy_decision(spiffe_id, &method, allowed);

        // Use base handler to connect and forward
        self.base.connect_and_forward(client_stream, &connection_info, spiffe_id, &method, allowed).await
    }
}