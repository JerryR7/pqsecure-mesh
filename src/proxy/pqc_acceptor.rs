use anyhow::{Context, Result};
use rustls::{ServerConfig, pki_types::CertificateDer};
use std::cell::RefCell;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::common::PqSecureError;
use crate::proxy::handler::DefaultConnectionHandler;
use crate::telemetry;

// Thread-local storage for client certificate during connection handling
thread_local! {
    static CURRENT_CLIENT_CERT: RefCell<Option<CertificateDer<'static>>> = RefCell::new(None);
}

/// Get the current client certificate from thread-local storage
pub fn get_current_client_cert() -> Option<CertificateDer<'static>> {
    CURRENT_CLIENT_CERT.with(|cell| cell.borrow().clone())
}

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
                    let client_addr = addr.to_string();

                    // Spawn a task to handle the connection
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, client_addr, acceptor, handlers).await {
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
        original_stream: TcpStream,
        client_addr: String,
        acceptor: TlsAcceptor,
        handlers: Vec<Arc<dyn DefaultConnectionHandler>>,
    ) -> Result<()> {
        // Clone the TCP stream for protocol detection after TLS handshake
        let std_stream = original_stream.into_std().expect("Failed to convert to std TcpStream");
        let std_stream_clone = std_stream.try_clone().expect("Failed to clone TcpStream");
        let stream_for_detection = TcpStream::from_std(std_stream_clone).expect("Failed to convert from std TcpStream");
        let original_stream = TcpStream::from_std(std_stream).expect("Failed to convert back to tokio TcpStream");
        
        // Perform TLS handshake first - this is essential for the Zero Trust model
        let tls_stream = match acceptor.accept(original_stream).await {
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
        
        // Extract client certificate and SPIFFE ID
        let client_cert = match tls_stream.get_ref().1.peer_certificates() {
            Some(certs) if !certs.is_empty() => {
                certs[0].clone()
            },
            _ => {
                error!("No client certificate found in TLS session from {}", client_addr);
                return Err(anyhow::anyhow!("No client certificate found"));
            }
        };
        
        // Store client certificate in thread local storage for handlers to access
        CURRENT_CLIENT_CERT.with(|cell| {
            *cell.borrow_mut() = Some(client_cert);
        });
        
        // After successful TLS handshake, try each protocol handler
        for handler in handlers.iter() {
            if handler.can_handle(&stream_for_detection).await {
                debug!("Using {} handler for connection from {}", handler.protocol_name(), client_addr);
                
                // Call handler with the stream for protocol-specific handling
                let result = handler.handle(stream_for_detection).await;
                
                // Clear the thread local certificate after handling
                CURRENT_CLIENT_CERT.with(|cell| {
                    *cell.borrow_mut() = None;
                });
                
                return result;
            }
        }

        // Clear the thread local certificate if no handler was found
        CURRENT_CLIENT_CERT.with(|cell| {
            *cell.borrow_mut() = None;
        });

        // Return an error when no handler can process the connection
        warn!("No suitable handler found for connection from {}", client_addr);
        Err(PqSecureError::ProxyError(
            "No suitable protocol handler found".to_string(),
        ).into())
    }
}