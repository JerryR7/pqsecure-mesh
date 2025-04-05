use std::fmt;
use serde::{Serialize, Deserialize};

/// Project-wide Result type
pub type Result<T> = std::result::Result<T, crate::common::error::Error>;

/// Proxy protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolType {
    /// HTTP protocol
    Http,
    /// gRPC protocol
    Grpc,
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::Http => write!(f, "http"),
            ProtocolType::Grpc => write!(f, "grpc"),
        }
    }
}

impl Default for ProtocolType {
    fn default() -> Self {
        ProtocolType::Http
    }
}