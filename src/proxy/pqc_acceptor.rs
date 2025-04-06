use anyhow::{Context, Result};
use rustls::ServerConfig;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::common::PqSecureError;
use crate::proxy::handler::DefaultConnectionHandler;
use crate::telemetry;

/// PQC TLS connection acceptor
pub struct PqcAcceptor {
    /// Address to listen on
    listen_addr: String,

    /// TLS acceptor
    tls_acceptor: TlsAcceptor,

    /// Protocol handlers
    handlers: Vec<Arc<dyn DefaultConnectionHandler>>,
}

impl PqcAcceptor {
    /// Create a new PQC acceptor
    pub fn new(
        listen_addr: String,
        tls_config: Arc<ServerConfig>,
        handlers: Vec<Arc<dyn DefaultConnectionHandler>>,
    ) -> Result<Self> {
        // Create TLS acceptor
        let tls_acceptor = TlsAcceptor::from(tls_config);

        // Validate we have at least one handler
        if handlers.is_empty() {
            return Err(PqSecureError::ConfigError(
                "At least one protocol handler must be configured".to_string(),
            ).into());
        }

        Ok(Self {
            listen_addr,
            tls_acceptor,
            handlers,
        })
    }

    /// Run the acceptor
    pub async fn run(&self) -> Result<()> {
        // 將字串解析為 SocketAddr
        let addr = self.listen_addr.to_socket_addrs()
            .context(format!("Failed to parse address: {}", self.listen_addr))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve address: {}", self.listen_addr))?;

        // Create TCP listener
        let listener = TcpListener::bind(addr)
            .await
            .context(format!("Failed to bind to {}", self.listen_addr))?;

        info!("PQC acceptor listening on {}", self.listen_addr);

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New connection from {}", addr);

                    // Clone handlers and acceptor for the task
                    let handlers = self.handlers.clone();
                    let acceptor = self.tls_acceptor.clone();

                    // Spawn a task to handle the connection
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, addr.to_string(), acceptor, handlers).await {
                            error!("Connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Handle a single connection
    async fn handle_connection(
        stream: TcpStream,
        client_addr: String,
        acceptor: TlsAcceptor,
        handlers: Vec<Arc<dyn DefaultConnectionHandler>>,
    ) -> Result<()> {
        // Perform TLS handshake
        let tls_stream = match acceptor.accept(stream).await {
            Ok(s) => {
                telemetry::record_connection_attempt(&client_addr, true);
                debug!("TLS handshake successful from {}", client_addr);
                s
            }
            Err(e) => {
                telemetry::record_connection_attempt(&client_addr, false);
                return Err(anyhow::anyhow!("TLS handshake failed: {}", e));
            }
        };

        // Get the TCP stream back for protocol detection
        let (_, tcp_stream) = tls_stream.into_inner();

        // Try each handler
        for handler in handlers {
            if handler.can_handle(&tcp_stream).await {
                debug!("Using {} handler for connection from {}", handler.protocol_name(), client_addr);
                return handler.handle(tcp_stream).await;
            }
        }

        // Return an error when no handler can process the connection
        warn!("No suitable handler found for connection from {}", client_addr);
        Err(PqSecureError::ProxyError(
            "No suitable protocol handler found".to_string(),
        ).into())
    }
}