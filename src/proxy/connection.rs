use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace, error, warn};

use crate::error::Error;
use crate::proxy::types::ProxyMetrics;

/// Connection handling context
pub struct ConnectionContext {
    /// Connection ID
    pub id: String,
    /// Client address
    pub client_addr: String,
    /// Upstream address
    pub upstream_addr: String,
    /// Protocol used
    pub protocol: &'static str,
    /// Metrics collector
    pub metrics: Arc<ProxyMetrics>,
    /// Connection start time
    pub start_time: Instant,
}

/// Manages connection data transfer
pub struct ConnectionHandler<'a, R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Source reader
    pub source_reader: &'a mut R,
    /// Target writer
    pub target_writer: &'a mut W,
    /// Source label
    pub source_label: &'static str,
    /// Target label
    pub target_label: &'static str,
    /// Connection context
    pub context: &'a ConnectionContext,
    /// Buffer size
    pub buffer_size: usize,
    /// Whether it is upstream direction
    pub is_upstream: bool,
}

impl<'a, R, W> ConnectionHandler<'a, R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Create a new connection handler
    pub fn new(
        source_reader: &'a mut R,
        target_writer: &'a mut W,
        source_label: &'static str,
        target_label: &'static str,
        context: &'a ConnectionContext,
        is_upstream: bool,
    ) -> Self {
        Self {
            source_reader,
            target_writer,
            source_label,
            target_label,
            context,
            buffer_size: 8192,
            is_upstream,
        }
    }
    
    /// Handle connection data transfer
    pub async fn handle(&mut self) -> Result<usize, Error> {
        let mut buffer = vec![0u8; self.buffer_size];
        let mut total_bytes = 0usize;
        
        loop {
            match self.source_reader.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    match self.target_writer.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!(
                                "{} -> {}: {} bytes (total: {})",
                                self.source_label,
                                self.target_label,
                                n,
                                total_bytes
                            );
                        },
                        Err(e) => {
                            return Err(Error::Proxy(format!(
                                "Failed to write to {}: {}",
                                self.target_label,
                                e
                            )));
                        }
                    }
                },
                Err(e) => {
                    return Err(Error::Proxy(format!(
                        "Failed to read from {}: {}",
                        self.source_label,
                        e
                    )));
                }
            }
        }
        
        // Ensure all data is written
        self.target_writer.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush {}: {}", self.target_label, e)))?;
        
        // Record data transfer
        self.context.metrics.record_data_transfer(self.is_upstream, total_bytes).await;
        
        Ok(total_bytes)
    }
}

/// Handle TCP connection
pub async fn handle_bidirectional_transfer<A, B>(
    client_io: &mut A,
    upstream_io: &mut B,
    context: &ConnectionContext,
) -> Result<(usize, usize), Error>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // Split streams for independent reading and writing
    let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_io);
    
    // Create two tasks to forward data
    let mut client_to_upstream = ConnectionHandler::new(
        &mut client_reader,
        &mut upstream_writer,
        "client",
        "upstream",
        context,
        true,
    );
    
    let mut upstream_to_client = ConnectionHandler::new(
        &mut upstream_reader,
        &mut client_writer,
        "upstream",
        "client",
        context,
        false,
    );
    
    // Run data forwarding in both directions simultaneously
    let (client_to_upstream_bytes, upstream_to_client_bytes) = tokio::join!(
        client_to_upstream.handle(),
        upstream_to_client.handle(),
    );
    
    // Check if both directions succeeded
    match (client_to_upstream_bytes, upstream_to_client_bytes) {
        (Ok(c2u), Ok(u2c)) => Ok((c2u, u2c)),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
    }
}

/// Gracefully shut down connection from client or upstream
pub async fn graceful_shutdown<T: AsyncWrite + Unpin>(
    io: &mut T,
    label: &str,
) -> Result<(), Error> {
    io.shutdown().await
        .map_err(|e| Error::Proxy(format!("Failed to shutdown {}: {}", label, e)))
}