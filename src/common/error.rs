use thiserror::Error;
use std::io;

/// Generic error type for the application
#[derive(Error, Debug)]
pub enum Error {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// CA error
    #[error("CA error: {0}")]
    Ca(String),

    /// Identity error
    #[error("Identity error: {0}")]
    Identity(String),

    /// Invalid SPIFFE ID
    #[error("Invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),

    /// Proxy error
    #[error("Proxy error: {0}")]
    Proxy(String),

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Policy error
    #[error("Policy error: {0}")]
    Policy(String),

    /// Access denied
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::Internal(format!("HTTP request error: {}", error))
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Serialization(format!("JSON error: {}", error))
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(error: serde_yaml::Error) -> Self {
        Error::Serialization(format!("YAML error: {}", error))
    }
}

impl From<config::ConfigError> for Error {
    fn from(error: config::ConfigError) -> Self {
        Error::Config(error.to_string())
    }
}