use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, trace};

use crate::common::{ConnectionInfo, PqSecureError};
use crate::telemetry;
use std::time::Duration;

/// Bidirectional data forwarder
pub struct Forwarder {
    /// Connection timeout in seconds
    timeout_seconds: u64,
}

impl Forwarder {
    /// Create a new forwarder
    pub fn new(timeout_seconds: u64) -> Self {
        Self { timeout_seconds }
    }

    /// Forward data between client and backend
    pub async fn forward<C, B>(&self, client: C, backend: B, connection_info: &ConnectionInfo) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Duration::from_secs(self.timeout_seconds);

        // Use tokio's built-in bidirectional copy
        debug!(
            "Starting bidirectional forwarding for {} ({})",
            connection_info.id, connection_info.source_addr
        );

        match timeout(
            timeout_duration,
            tokio::io::copy_bidirectional(client, backend)
        ).await {
            Ok(Ok((from_client, from_backend))) => {
                debug!(
                    "Bidirectional forwarding completed for {} ({}): {} bytes from client, {} bytes from backend",
                    connection_info.id, connection_info.source_addr, from_client, from_backend
                );

                telemetry::record_data_transfer(from_client as usize, from_backend as usize);
                Ok(())
            }
            Ok(Err(e)) => {
                error!(
                    "Bidirectional forwarding error for {} ({}): {}",
                    connection_info.id, connection_info.source_addr, e
                );
                Err(PqSecureError::ConnectionError(e.to_string()).into())
            }
            Err(_) => {
                error!(
                    "Bidirectional forwarding timeout for {} ({})",
                    connection_info.id, connection_info.source_addr
                );
                Err(PqSecureError::ConnectionError("Connection timed out".to_string()).into())
            }
        }
    }

    /// Connect to backend
    pub async fn connect_to_backend(&self, backend_addr: &str) -> Result<TcpStream> {
        trace!("Connecting to backend: {}", backend_addr);

        // Set a timeout for the connection attempt
        match timeout(
            Duration::from_secs(self.timeout_seconds),
            TcpStream::connect(backend_addr)
        ).await {
            Ok(Ok(stream)) => {
                debug!("Connected to backend: {}", backend_addr);
                Ok(stream)
            }
            Ok(Err(e)) => {
                error!("Failed to connect to backend {}: {}", backend_addr, e);
                Err(PqSecureError::ConnectionError(format!(
                    "Failed to connect to backend {}: {}", backend_addr, e
                )).into())
            }
            Err(_) => {
                error!("Timeout connecting to backend: {}", backend_addr);
                Err(PqSecureError::ConnectionError(format!(
                    "Timeout connecting to backend: {}", backend_addr
                )).into())
            }
        }
    }
}