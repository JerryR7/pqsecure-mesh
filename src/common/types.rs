use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Service identity with SPIFFE ID validation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceIdentity {
    /// The SPIFFE ID URI string
    pub spiffe_id: String,
    /// The trust domain extracted from the SPIFFE ID
    pub trust_domain: String,
    /// The path component of the SPIFFE ID
    pub path: String,
}

/// Represents the type of protocol for connection handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolType {
    /// Raw TCP connection
    Tcp,
    /// HTTP/HTTPS connection
    Http,
    /// gRPC connection
    Grpc,
}

/// Information about a connection for logging and policy decisions
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Unique identifier for this connection
    pub id: String,
    /// Source address of the connection
    pub source_addr: SocketAddr,
    /// Identity of the connecting service
    pub identity: Option<ServiceIdentity>,
    /// Type of protocol used
    pub protocol_type: ProtocolType,
    /// Protocol-specific method or path (if applicable)
    pub method: Option<String>,
}

impl ConnectionInfo {
    /// Create a new connection info with a generated UUID
    pub fn new(source_addr: SocketAddr, protocol_type: ProtocolType) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_addr,
            identity: None,
            protocol_type,
            method: None,
        }
    }

    /// Set the identity for this connection
    pub fn with_identity(mut self, identity: ServiceIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Set the method or path for this connection
    pub fn with_method(mut self, method: String) -> Self {
        self.method = Some(method);
        self
    }
}