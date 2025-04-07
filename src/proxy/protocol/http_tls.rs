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

/// Handler for HTTP/HTTPS connections
pub struct HttpHandler {
    /// Common base handler with shared functionality
    base: BaseHandler,
}

impl HttpHandler {
    /// Create a new HTTP handler
    pub fn new(
        backend_config: BackendConfig,
        policy_engine: Arc<dyn PolicyEngine>,
        spiffe_verifier: Arc<SpiffeVerifier>,
    ) -> Result<Self> {
        let base = BaseHandler::new(backend_config, policy_engine, spiffe_verifier)?;
        
        Ok(Self { base })
    }

    /// Detect if the connection is an HTTP connection
    async fn is_http(&self, stream: &TcpStream) -> bool {

        // Create a peek buffer
        let mut buf = [0u8; 8];
        
        // Clone the stream
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
                // Check for common HTTP method prefixes
                // GET, POST, PUT, HEAD, etc.
                let start = String::from_utf8_lossy(&buf[0..3]).to_ascii_uppercase();
                matches!(start.as_ref(), "GET" | "POS" | "PUT" | "HEA" | "DEL" | "OPT" | "PAT")
            },
            _ => false,
        }
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

        // Get client certificate from thread-local storage
        let client_cert = get_current_client_cert()
            .ok_or_else(|| PqSecureError::AuthenticationError("No client certificate found".to_string()))?;

        // Extract SPIFFE ID from certificate
        let identity = self.base.extract_spiffe_id(&client_cert)
            .context("Failed to extract SPIFFE ID from certificate")?;

        // Update connection info with identity
        connection_info = connection_info.with_identity(identity.clone());

        // Extract method and path (in a real implementation, this would be parsed from HTTP headers)
        let (method, path) = self.extract_method_and_path(&client_stream).await
            .unwrap_or_else(|| ("unknown".to_string(), "/".to_string()));

        // Combine method and path for policy check
        let method_path = format!("{} {}", method, path);
        
        // Update connection info with method
        connection_info = connection_info.with_method(method_path.clone());

        // Get SPIFFE ID for policy check
        let spiffe_id = &identity.spiffe_id;

        // Check policy
        let allowed = self.base.policy_engine.allow(spiffe_id, &method_path);
        telemetry::record_policy_decision(spiffe_id, &method_path, allowed);

        // Use base handler to connect and forward
        self.base.connect_and_forward(client_stream, &connection_info, spiffe_id, &method_path, allowed).await
    }
}