use std::sync::Arc;
use std::time::Instant;
use std::net::SocketAddr;
use http::{Request, Response, HeaderMap, StatusCode};
use hyper::{Body, Server, Client};
use hyper::service::{make_service_fn, service_fn};
use hyper::client::HttpConnector;
use hyper::server::conn::AddrStream;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tower_http::compression::CompressionLayer;
use tracing::{info, warn, debug, error, trace, Span};

use crate::error::Error;
use crate::proxy::types::{ProxyMetrics, SidecarConfig, MtlsConfig};
use crate::identity::{ServiceIdentity, IdentityProvider, SpiffeId};
use crate::policy::PolicyEngine;

/// HTTP Proxy
pub struct HttpProxy {
    /// Sidecar configuration
    pub config: SidecarConfig,
    /// Identity provider
    pub identity_provider: Arc<dyn IdentityProvider>,
    /// Policy engine
    pub policy_engine: Arc<PolicyEngine>,
    /// Metrics collector
    pub metrics: Arc<ProxyMetrics>,
}

impl HttpProxy {
    /// Create a new HTTP proxy
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
    
    /// Start the HTTP proxy
    pub async fn start(&self) -> Result<(), Error> {
        // Obtain or generate identity
        let identity = self.identity_provider.provision_identity(
            &self.config.tenant_id,
            &self.config.service_id,
        ).await?;
        
        // Create listening address
        let listen_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listen_addr = listen_addr.parse::<SocketAddr>()
            .map_err(|e| Error::Proxy(format!("Invalid listen address: {}", e)))?;
        
        info!("Starting HTTP proxy on {} -> {}:{}", 
              listen_addr, self.config.upstream_addr, self.config.upstream_port);
        
        // Create HTTP client
        let client = Client::builder()
            .build(HttpConnector::new());
        
        // Create upstream address
        let upstream_uri = format!("http://{}:{}", self.config.upstream_addr, self.config.upstream_port);
        
        // Get configuration references
        let metrics = self.metrics.clone();
        let policy_engine = self.policy_engine.clone();
        let tenant_id = self.config.tenant_id.clone();
        let enable_compression = self.config.proxy.enable_compression;
        
        // Create service function
        let make_svc = make_service_fn(move |conn: &AddrStream| {
            let remote_addr = conn.remote_addr();
            let client = client.clone();
            let metrics = metrics.clone();
            let policy_engine = policy_engine.clone();
            let tenant_id = tenant_id.clone();
            let upstream_uri = upstream_uri.clone();
            
            // Record client connection
            let metrics_clone = metrics.clone();
            tokio::spawn(async move {
                metrics_clone.record_client_connection(false).await;
            });
            
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                    let client = client.clone();
                    let metrics = metrics.clone();
                    let policy_engine = policy_engine.clone();
                    let tenant_id = tenant_id.clone();
                    let upstream_uri = upstream_uri.clone();
                    let start_time = Instant::now();
                    
                    async move {
                        trace!("Received request: {} {}", req.method(), req.uri());
                        
                        // Evaluate policy
                        let method = req.method().as_str();
                        let path = req.uri().path();
                        
                        // Extract SPIFFE ID from request headers (if any)
                        let spiffe_id = extract_spiffe_id_from_headers(req.headers());
                        
                        // Evaluate policy (if SPIFFE ID exists)
                        if let Some(id) = &spiffe_id {
                            debug!("Request has SPIFFE ID: {}", id.uri);
                            
                            match policy_engine.evaluate_request(
                                id, 
                                method,
                                path,
                                crate::types::ProtocolType::Http
                            ).await {
                                Ok(true) => {
                                    debug!("Policy allowed access for SPIFFE ID: {}", id.uri);
                                },
                                Ok(false) => {
                                    warn!("Policy denied access for SPIFFE ID: {}", id.uri);
                                    metrics.record_rejected().await;
                                    
                                    return Ok(Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .body(Body::from("Access denied by policy"))
                                        .unwrap());
                                },
                                Err(e) => {
                                    error!("Error evaluating policy: {}", e);
                                    
                                    return Ok(Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("Internal policy error"))
                                        .unwrap());
                                }
                            }
                        }
                        
                        // Build upstream request
                        let uri = format!("{}{}", upstream_uri, req.uri().path_and_query().map(|p| p.as_str()).unwrap_or(""));
                        
                        let (parts, body) = req.into_parts();
                        
                        let mut upstream_req = Request::builder()
                            .method(parts.method)
                            .uri(uri);
                        
                        // Copy all headers
                        let headers = upstream_req.headers_mut().unwrap();
                        for (key, value) in parts.headers {
                            if let Some(key) = key {
                                // Exclude headers that should not be forwarded
                                if !should_skip_header(key.as_str()) {
                                    headers.insert(key, value);
                                }
                            }
                        }
                        
                        // Add additional headers
                        headers.insert("x-forwarded-for", parts.uri.host().unwrap_or("unknown").parse().unwrap());
                        headers.insert("x-forwarded-proto", "http".parse().unwrap());
                        
                        // Add SPIFFE ID header
                        if let Some(id) = &spiffe_id {
                            headers.insert("x-spiffe-id", id.uri.parse().unwrap());
                        }
                        
                        let upstream_req = upstream_req.body(body).unwrap();
                        
                        // Send request to upstream
                        match client.request(upstream_req).await {
                            Ok(res) => {
                                // Record successful request
                                let elapsed = start_time.elapsed().as_millis() as f64;
                                metrics.record_request(true, elapsed).await;
                                
                                trace!("Upstream response: {:?}", res.status());
                                
                                // Forward upstream response
                                Ok(res)
                            },
                            Err(e) => {
                                error!("Upstream request error: {}", e);
                                
                                // Record failed request
                                let elapsed = start_time.elapsed().as_millis() as f64;
                                metrics.record_request(false, elapsed).await;
                                
                                // Return error response
                                Ok(Response::builder()
                                    .status(StatusCode::BAD_GATEWAY)
                                    .body(Body::from(format!("Bad Gateway: {}", e)))
                                    .unwrap())
                            }
                        }
                    }
                }))
            }
        });
        
        // Create HTTP server
        let server = Server::bind(&listen_addr)
            .serve(make_svc);
        
        // Start server
        info!("HTTP proxy server started on {}", listen_addr);
        
        // Run server
        if let Err(e) = server.await {
            error!("HTTP proxy server error: {}", e);
            return Err(Error::Proxy(format!("HTTP server error: {}", e)));
        }
        
        Ok(())
    }
}

/// Extract SPIFFE ID from request headers
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

/// Determine whether to skip certain headers
fn should_skip_header(name: &str) -> bool {
    match name.to_lowercase().as_str() {
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" |
        "te" | "trailers" | "transfer-encoding" | "upgrade" | "host" => true,
        _ => false,
    }
}