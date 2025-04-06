use thiserror::Error;

#[derive(Error, Debug)]
pub enum PqSecureError {
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("Invalid SPIFFE ID: {0}")]
    SpiffeIdError(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Policy error: {0}")]
    PolicyError(String),

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("CA client error: {0}")]
    CaClientError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Authorization failed: {0}")]
    AuthorizationError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Convert any error to an appropriate PqSecureError
pub fn map_err_to_pqsecure<E: std::fmt::Display>(err: E, context: &str) -> PqSecureError {
    PqSecureError::UnexpectedError(format!("{}: {}", context, err))
}