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

/// Handler for HTTP/HTTPS connections
pub struct HttpHandler {
    /// Backend configuration
    backend_config: BackendConfig,

    /// Policy engine
    policy_engine: Arc<dyn PolicyEngine>,

    /// SPIFFE verifier
    spiffe_verifier: Arc<SpiffeVerifier>,

    /// Data forwarder
    forwarder: Forwarder,
}

impl HttpHandler {
    /// Create a new HTTP handler
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

    /// Detect if the connection is an HTTP connection
    async fn is_http(&self, stream: &TcpStream) -> bool {
        // In a real implementation, we would peek at the stream to check for HTTP headers
        // For this simplified version, we'll return true if it's not detected as gRPC
        // This is a placeholder as proper protocol detection requires more complex logic
        true
    }

    /// Extract method and path from HTTP request
    async fn extract_method_and_path(&self, _stream: &TcpStream) -> Option<(String, String)> {
        // In a real implementation, we would parse the HTTP headers to extract method and path
        // For this simplified version, we'll just return a placeholder
        Some(("GET".to_string(), "/api/v1/resource".to_string()))
    }
}

#[async_trait::async_trait]
impl DefaultConnectionHandler for HttpHandler {
    fn protocol_name(&self) -> &'static str {
        "HTTP"
    }

    async fn can_handle(&self, stream: &TcpStream) -> bool {
        self.is_http(stream).await
    }
}

#[async_trait::async_trait]
impl crate::proxy::handler::ConnectionHandler for HttpHandler {
    async fn handle(&self, client_stream: TcpStream) -> Result<()> {
        // Get client address
        let client_addr = client_stream.peer_addr()?;

        // Create connection info
        let mut connection_info = ConnectionInfo::new(client_addr, ProtocolType::Http);

        // Extract method and path (in a real implementation, this would be parsed from HTTP headers)
        let (method, path) = self.extract_method_and_path(&client_stream).await
            .unwrap_or_else(|| ("unknown".to_string(), "/".to_string()));

        // Combine method and path for policy check
        let method_path = format!("{} {}", method, path);

        // For this simplified version, we'll use a placeholder SPIFFE ID
        let spiffe_id = "spiffe://example.org/service/client".to_string();

        // Check policy
        let allowed = self.policy_engine.allow(&spiffe_id, &method_path);
        telemetry::record_policy_decision(&spiffe_id, &method_path, allowed);

        if !allowed {
            error!(
                "HTTP request denied by policy: {} -> {} ({})",
                spiffe_id, self.backend_config.address, method_path
            );
            return Err(PqSecureError::AuthorizationError(
                "HTTP request denied by policy".to_string(),
            ).into());
        }

        // Connect to backend
        let backend_stream = self.forwarder.connect_to_backend(&self.backend_config.address).await?;

        // Forward data
        info!(
            "Forwarding HTTP connection from {} to {} ({})",
            client_addr, self.backend_config.address, method_path
        );

        self.forwarder.forward(client_stream, backend_stream, &connection_info).await
    }
}