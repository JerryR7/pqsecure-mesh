use anyhow::Result;
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
    pub async fn forward<C, B>(&self, mut client: C, mut backend: B, connection_info: &ConnectionInfo) -> Result<()>
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
            tokio::io::copy_bidirectional(&mut client, &mut backend)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, ErrorKind};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use crate::common::ProtocolType;

    // Custom reader/writer for testing
    struct TestStream {
        read_data: Cursor<Vec<u8>>,
        write_data: Vec<u8>,
    }

    impl TestStream {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data: Cursor::new(read_data),
                write_data: Vec::new(),
            }
        }

        fn written_data(&self) -> &[u8] {
            &self.write_data
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            let max_bytes = buf.remaining();
            let mut read_buf = vec![0u8; max_bytes];

            // Use std::io::Read implementation for Cursor
            match std::io::Read::read(&mut me.read_data, &mut read_buf[..max_bytes]) {
                Ok(n) => {
                    if n == 0 {
                        // EOF
                        std::task::Poll::Ready(Ok(()))
                    } else {
                        buf.put_slice(&read_buf[..n]);
                        std::task::Poll::Ready(Ok(()))
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    std::task::Poll::Pending
                }
                Err(e) => std::task::Poll::Ready(Err(e)),
            }
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let me = self.get_mut();
            me.write_data.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_bidirectional_copy() {
        // Create a forwarder
        let forwarder = Forwarder::new(5);

        // Create test streams
        let client_data = b"Hello from client!".to_vec();
        let backend_data = b"Hello from backend!".to_vec();

        let mut client_stream = TestStream::new(client_data.clone());
        let mut backend_stream = TestStream::new(backend_data.clone());

        // Create connection info
        let conn_info = ConnectionInfo::new(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ProtocolType::Tcp,
        );

        // Forward data
        let result = forwarder.forward(&mut client_stream, &mut backend_stream, &conn_info).await;

        // Verify result
        assert!(result.is_ok());

        // Verify data has been copied correctly
        assert_eq!(client_stream.written_data(), &backend_data[..]);
        assert_eq!(backend_stream.written_data(), &client_data[..]);
    }

    #[tokio::test]
    async fn test_connect_to_backend() {
        // Start a test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_addr = format!("127.0.0.1:{}", addr.port());

        // Spawn a task to accept one connection
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"Hello from test server!").await.unwrap();
        });

        // Create a forwarder
        let forwarder = Forwarder::new(5);

        // Connect to backend
        let result = forwarder.connect_to_backend(&server_addr).await;

        // Verify result
        assert!(result.is_ok());

        // Read data from backend
        let mut stream = result.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();

        assert_eq!(&buf[..n], b"Hello from test server!");
    }
}