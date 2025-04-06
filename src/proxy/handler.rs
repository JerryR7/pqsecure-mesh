use anyhow::Result;
use tokio::net::TcpStream;

/// Trait for handling client connections
#[async_trait::async_trait]
pub trait ConnectionHandler: Send + Sync {
    async fn handle(&self, stream: TcpStream) -> anyhow::Result<()>;
}

/// Trait for default connection handling logic
#[async_trait::async_trait]
pub trait DefaultConnectionHandler: ConnectionHandler {
    /// Protocol-specific name for identification
    fn protocol_name(&self) -> &'static str;

    /// Check if this handler should process this connection
    async fn can_handle(&self, stream: &TcpStream) -> bool;
}