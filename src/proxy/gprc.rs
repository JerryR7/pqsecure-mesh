use std::sync::Arc;
use std::time::Instant;
use std::net::SocketAddr;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use http::{Request, Response, HeaderMap, StatusCode};
use h2::server::SendResponse;
use h2::client::SendRequest;
use tracing::{info, warn, debug, error, trace};

use crate::error::Error;
use crate::proxy::types::{ProxyMetrics, SidecarConfig, MtlsConfig};
use crate::identity::{ServiceIdentity, IdentityProvider, SpiffeId};
use crate::policy::PolicyEngine;

/// gRPC 代理
pub struct GrpcProxy {
    /// 側邊車配置
    pub config: SidecarConfig,
    /// 身份提供者
    pub identity_provider: Arc<dyn IdentityProvider>,
    /// 政策引擎
    pub policy_engine: Arc<PolicyEngine>,
    /// 指標收集器
    pub metrics: Arc<ProxyMetrics>,
}

impl GrpcProxy {
    /// 創建新的 gRPC 代理
    pub fn new(
        config: SidecarConfig,
        identity_provider: Arc<dyn IdentityProvider>,
        policy_engine: Arc<PolicyEngine>,
        metrics: Arc<ProxyMetrics>,
    ) -> Self {
        Self {
            config,
            identity_provider,
            policy_engine,
            metrics,
        }
    }
    
    /// 啟動 gRPC 代理
    pub async fn start(&self) -> Result<(), Error> {
        // 獲取或生成身份
        let identity = self.identity_provider.provision_identity(
            &self.config.tenant_id,
            &self.config.service_id,
        ).await?;
        
        // 創建監聽地址
        let listen_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        info!("Starting gRPC proxy on {} -> {}:{}", 
              listen_addr, self.config.upstream_addr, self.config.upstream_port);
              
        // 創建 TCP 監聽器
        let listener = TcpListener::bind(&listen_addr).await
            .map_err(|e| Error::Proxy(format!("Failed to bind to {}: {}", listen_addr, e)))?;
        
        info!("gRPC proxy listening on {}", listen_addr);
        
        // 創建 TLS 配置（如果啟用 mTLS）
        let tls_config = if self.config.mtls_config.enable_mtls {
            Some(self.create_server_tls_config(&identity)?)
        } else {
            None
        };
        
        // 處理連接
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("Accepted connection from {}", addr);
                    
                    // 記錄客戶端連接
                    self.metrics.record_client_connection(false).await;
                    
                    let policy_engine = self.policy_engine.clone();
                    let metrics = self.metrics.clone();
                    let upstream_addr = format!("{}:{}", self.config.upstream_addr, self.config.upstream_port);
                    let mtls_config = self.config.mtls_config.clone();
                    let tls_config_clone = tls_config.clone();
                    let identity_clone = identity.clone();
                    
                    tokio::spawn(async move {
                        let start_time = Instant::now();
                        
                        let result = if let Some(tls_config) = tls_config_clone {
                            handle_tls_grpc_connection(
                                socket,
                                addr.to_string(),
                                &upstream_addr,
                                tls_config,
                                &identity_clone,
                                policy_engine,
                                &mtls_config,
                                metrics.clone(),
                            ).await
                        } else {
                            handle_plain_grpc_connection(
                                socket,
                                addr.to_string(),
                                &upstream_addr,
                                metrics.clone(),
                            ).await
                        };
                        
                        // 記錄結果
                        let success = result.is_ok();
                        let elapsed = start_time.elapsed().as_millis() as f64;
                        metrics.record_request(success, elapsed).await;
                        metrics.record_client_disconnection().await;
                        
                        if let Err(e) = result {
                            error!("gRPC connection handling error: {}", e);
                        }
                    });
                },
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            }
        }
    }
    
    /// 創建 TLS 服務器配置
    fn create_server_tls_config(&self, identity: &ServiceIdentity) -> Result<Arc<rustls::ServerConfig>, Error> {
        let tls_config = crate::crypto::tls::TlsUtils::create_tls_config(
            identity,
            crate::crypto::tls::TlsConfigType::Server,
            self.config.mtls_config.enable_mtls,
        )?;
        
        match tls_config.downcast::<rustls::ServerConfig>() {
            Ok(config) => Ok(config),
            Err(_) => Err(Error::Tls("Failed to downcast to ServerConfig".into())),
        }
    }
}

/// 處理明文 gRPC 連接
async fn handle_plain_grpc_connection(
    mut client_socket: TcpStream,
    client_addr: String,
    upstream_addr: &str,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Error> {
    debug!("Handling plain gRPC connection from {}", client_addr);
    
    // 連接到上游服務
    let mut upstream_socket = TcpStream::connect(upstream_addr).await
        .map_err(|e| Error::Proxy(format!("Failed to connect to upstream {}: {}", upstream_addr, e)))?;
    
    debug!("Connected to upstream gRPC server at {}", upstream_addr);
    metrics.record_upstream_connection().await;
    
    // 設置 socket 參數
    client_socket.set_nodelay(true)?;
    upstream_socket.set_nodelay(true)?;
    
    // 雙向轉發數據
    let (mut client_read, mut client_write) = client_socket.split();
    let (mut upstream_read, mut upstream_write) = upstream_socket.split();
    
    // 創建兩個任務轉發數據
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => break, // 連接關閉
                Ok(n) => {
                    match upstream_write.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!("Client -> Upstream: {} bytes", n);
                        },
                        Err(e) => return Err(Error::Proxy(format!("Failed to write to upstream: {}", e))),
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from client: {}", e))),
            }
        }
        
        // 確保所有資料都寫入
        upstream_write.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush upstream: {}", e)))?;
        
        Ok::<usize, Error>(total_bytes)
    };
    
    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match upstream_read.read(&mut buffer).await {
                Ok(0) => break, // 連接關閉
                Ok(n) => {
                    match client_write.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!("Upstream -> Client: {} bytes", n);
                        },
                        Err(e) => return Err(Error::Proxy(format!("Failed to write to client: {}", e))),
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from upstream: {}", e))),
            }
        }
        
        // 確保所有資料都寫入
        client_write.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush client: {}", e)))?;
        
        Ok::<usize, Error>(total_bytes)
    };
    
    // 同時運行兩個方向的資料轉發
    match tokio::try_join!(client_to_upstream, upstream_to_client) {
        Ok((client_to_upstream_bytes, upstream_to_client_bytes)) => {
            debug!("gRPC connection closed: client {} <-> upstream {}, bytes client->upstream: {}, bytes upstream->client: {}", 
                   client_addr, upstream_addr, client_to_upstream_bytes, upstream_to_client_bytes);
            
            // 記錄資料傳輸
            metrics.record_data_transfer(true, client_to_upstream_bytes).await;
            metrics.record_data_transfer(false, upstream_to_client_bytes).await;
            
            Ok(())
        },
        Err(e) => Err(e),
    }
}

/// 處理 TLS gRPC 連接
#[allow(clippy::too_many_arguments)]
async fn handle_tls_grpc_connection(
    client_socket: TcpStream,
    client_addr: String,
    upstream_addr: &str,
    tls_config: Arc<rustls::ServerConfig>,
    identity: &ServiceIdentity,
    policy_engine: Arc<PolicyEngine>,
    mtls_config: &MtlsConfig,
    metrics: Arc<ProxyMetrics>,
) -> Result<(), Error> {
    debug!("Handling TLS gRPC connection from {}", client_addr);
    
    // 建立 TLS 連接
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let tls_stream = tls_acceptor.accept(client_socket).await
        .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;
    
    debug!("TLS handshake completed with client {}", client_addr);
    
    // 如果啟用 mTLS，則驗證客戶端憑證
    if mtls_config.enable_mtls {
        // 獲取客戶端憑證
        let (_, server_session) = tls_stream.get_ref();
        
        // 檢查是否有客戶端憑證
        if let Some(client_cert) = server_session.peer_certificates().and_then(|certs| certs.first()) {
            // 提取 SPIFFE ID
            let client_cert_pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                                        base64::encode(&client_cert.0));
            
            // 提取 SPIFFE ID
            let spiffe_id = match crate::identity::x509::X509Utils::extract_spiffe_id(&client_cert_pem)? {
                Some(id) => id,
                None => return Err(Error::AccessDenied("Client certificate does not contain a valid SPIFFE ID".into())),
            };
            
            debug!("Client certificate has SPIFFE ID: {}", spiffe_id.uri);
            
            // 評估政策
            // 對於 gRPC，我們無法在這個層級輕易獲取方法名稱，所以只評估連接權限
            let allowed = policy_engine.evaluate_request(&spiffe_id, "CONNECT", "", crate::types::ProtocolType::Grpc).await?;
            
            if !allowed {
                metrics.record_rejected().await;
                return Err(Error::AccessDenied(format!("Policy denied access for SPIFFE ID: {}", spiffe_id.uri)));
            }
            
            debug!("Policy allowed access for SPIFFE ID: {}", spiffe_id.uri);
        } else if mtls_config.enable_mtls {
            metrics.record_rejected().await;
            return Err(Error::AccessDenied("Client did not provide a certificate but mTLS is required".into()));
        }
    }
    
    // 連接到上游服務
    let mut upstream_socket = TcpStream::connect(upstream_addr).await
        .map_err(|e| Error::Proxy(format!("Failed to connect to upstream {}: {}", upstream_addr, e)))?;
    
    debug!("Connected to upstream gRPC server at {}", upstream_addr);
    metrics.record_upstream_connection().await;
    
    // 設置 socket 參數
    upstream_socket.set_nodelay(true)?;
    
    // 將 TLS 流分割為讀取和寫入部分
    let (mut client_reader, mut client_writer) = tokio::io::split(tls_stream);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_socket);
    
    // 創建兩個任務轉發數據
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break, // 連接關閉
                Ok(n) => {
                    match upstream_writer.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!("Client -> Upstream: {} bytes", n);
                        },
                        Err(e) => return Err(Error::Proxy(format!("Failed to write to upstream: {}", e))),
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from client: {}", e))),
            }
        }
        
        // 確保所有資料都寫入
        upstream_writer.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush upstream: {}", e)))?;
        
        // 關閉寫入端
        upstream_writer.shutdown().await
            .map_err(|e| Error::Proxy(format!("Failed to shutdown upstream writer: {}", e)))?;
        
        Ok::<usize, Error>(total_bytes)
    };
    
    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match upstream_reader.read(&mut buffer).await {
                Ok(0) => break, // 連接關閉
                Ok(n) => {
                    match client_writer.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!("Upstream -> Client: {} bytes", n);
                        },
                        Err(e) => return Err(Error::Proxy(format!("Failed to write to client: {}", e))),
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from upstream: {}", e))),
            }
        }
        
        // 確保所有資料都寫入
        client_writer.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush client: {}", e)))?;
        
        // 關閉寫入端
        client_writer.shutdown().await
            .map_err(|e| Error::Proxy(format!("Failed to shutdown client writer: {}", e)))?;
        
        Ok::<usize, Error>(total_bytes)
    };
    
    // 同時運行兩個方向的資料轉發
    match tokio::try_join!(client_to_upstream, upstream_to_client) {
        Ok((client_to_upstream_bytes, upstream_to_client_bytes)) => {
            debug!("TLS gRPC connection closed: client {} <-> upstream {}, bytes client->upstream: {}, bytes upstream->client: {}", 
                   client_addr, upstream_addr, client_to_upstream_bytes, upstream_to_client_bytes);
            
            // 記錄資料傳輸
            metrics.record_data_transfer(true, client_to_upstream_bytes).await;
            metrics.record_data_transfer(false, upstream_to_client_bytes).await;
            
            Ok(())
        },
        Err(e) => Err(e),
    }
}

/// 從請求頭部提取 SPIFFE ID
fn extract_spiffe_id_from_headers(headers: &HeaderMap) -> Option<SpiffeId> {
    if let Some(header) = headers.get("x-spiffe-id") {
        if let Ok(value) = header.to_str() {
            if let Ok(id) = SpiffeId::from_uri(value) {
                return Some(id);
            }
        }
    }
    
    None
}

/// 從 gRPC 路徑提取服務和方法
fn extract_grpc_service_method(path: &str) -> Option<(String, String)> {
    // gRPC 路徑格式: /package.Service/Method
    let path = path.trim_start_matches('/');
    
    if let Some(idx) = path.rfind('/') {
        let service = path[..idx].to_string();
        let method = path[(idx + 1)..].to_string();
        return Some((service, method));
    }
    
    None
}ls_config.enable_mtls {
            metrics.record_rejected().await;
            return Err(Error::AccessDenied("Client did not provide a certificate but mTLS is required".into()));
        }
    }
    
    // 連接到上游服務
    let mut upstream_socket = TcpStream::connect(upstream_addr).await
        .map_err(|e| Error::Proxy(format!("Failed to connect to upstream {}: {}", upstream_addr, e)))?;
    
    debug!("Connected to upstream gRPC server at {}", upstream_addr);
    metrics.record_upstream_connection().await;
    
    // 設置 socket 參數
    upstream_socket.set_nodelay(true)?;
    
    // 將 TLS 流分割為讀取和寫入部分
    let (mut client_reader, mut client_writer) = tokio::io::split(tls_stream);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_socket);
    
    // 創建兩個任務轉發數據
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break, // 連接關閉
                Ok(n) => {
                    match upstream_writer.write_all(&buffer[..n]).await {
                        Ok(_) => {
                            total_bytes += n;
                            trace!("Client -> Upstream: {} bytes", n);
                        },
                        Err(e) => return Err(Error::Proxy(format!("Failed to write to upstream: {}", e))),
                    }
                },
                Err(e) => return Err(Error::Proxy(format!("Failed to read from client: {}", e))),
            }
        }
        
        // 確保所有資料都寫入
        upstream_writer.flush().await
            .map_err(|e| Error::Proxy(format!("Failed to flush upstream: {}", e)))?;
        
        // 關閉寫入端
        upstream_writer.shutdown().await
            .map_err(|e| Error::Proxy(format!("Failed to shutdown upstream writer: {}", e)))?;
        
        Ok::<usize, Error>(total_bytes)
    };
    
    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0usize;
        
        loop {
            match upstream_reader.read(&mut buffer).await {
                Ok(0) => break, // 連接關閉
                Ok(n) => {
                    match client_writer.write_all(&