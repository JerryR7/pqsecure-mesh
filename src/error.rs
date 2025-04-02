use thiserror::Error;
use std::io;
use std::str::Utf8Error;

/// Generic error type
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

    /// API error
    #[error("API error: {0}")]
    ApiError(String),

    /// API server error
    #[error("API server error: {0}")]
    ApiServerError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Certificate error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Unsupported operation
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// HTTP client error
    #[error("HTTP client error: {0}")]
    HttpClient(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// YAML error
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// URL parse error
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// UTF8 error
    #[error("UTF8 error: {0}")]
    Utf8(#[from] Utf8Error),
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Self {
        Error::Config(err.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::HttpClient(err.to_string())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for Error {
    fn from(err: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Error::Internal(format!("Channel send error: {}", err))
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Error::Internal(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Internal(err)
    }
}