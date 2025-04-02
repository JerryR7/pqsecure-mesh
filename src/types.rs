use std::fmt;
use serde::{Serialize, Deserialize};

/// Project-wide Result type
pub type Result<T> = std::result::Result<T, crate::error::Error>;

/// Proxy protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolType {
    /// HTTP/1.1 or HTTP/2 protocol
    Http,
    /// gRPC protocol (based on HTTP/2)
    Grpc,
    /// Generic TCP protocol
    Tcp,
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::Http => write!(f, "http"),
            ProtocolType::Grpc => write!(f, "grpc"),
            ProtocolType::Tcp => write!(f, "tcp"),
        }
    }
}

impl Default for ProtocolType {
    fn default() -> Self {
        ProtocolType::Http
    }
}

/// Sidecar processing result type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarHandle {
    /// Sidecar ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Service ID
    pub service_id: String,
    /// Listen address
    pub listen_addr: String,
    /// Listen port
    pub listen_port: u16,
    /// Sidecar status
    pub status: SidecarStatus,
}

/// Sidecar status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SidecarStatus {
    /// Starting
    Starting,
    /// Running
    Running,
    /// Stopping
    Stopping,
    /// Stopped
    Stopped,
    /// Error
    Error,
}

impl fmt::Display for SidecarStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SidecarStatus::Starting => write!(f, "starting"),
            SidecarStatus::Running => write!(f, "running"),
            SidecarStatus::Stopping => write!(f, "stopping"),
            SidecarStatus::Stopped => write!(f, "stopped"),
            SidecarStatus::Error => write!(f, "error"),
        }
    }
}