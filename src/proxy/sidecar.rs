use std::sync::Arc;
use tracing::{info, warn, debug, error};

use crate::common::{Error, Result, ProtocolType};
use crate::proxy::types::{ProxyMetrics, SidecarConfig};
use crate::proxy::{http::HttpProxy, grpc::GrpcProxy};
use crate::identity::IdentityProvider;
use crate::policy::PolicyEngine;

/// Sidecar proxy service
pub struct SidecarProxy {
    /// Sidecar configuration
    pub config: SidecarConfig,
    /// Identity provider
    pub identity_provider: Arc<dyn IdentityProvider>,
    /// Policy engine
    pub policy_engine: Arc<PolicyEngine>,
    /// Metrics collector
    pub metrics: Arc<ProxyMetrics>,
}

impl SidecarProxy {
    /// Create a new sidecar proxy
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

    /// Start the sidecar proxy
    pub async fn start(&self) -> Result<()> {
        info!("Starting {} sidecar proxy for {}/{}",
              self.config.protocol, self.config.tenant_id, self.config.service_id);

        // Select different proxy implementations based on the protocol type
        match self.config.protocol {
            ProtocolType::Http => self.start_http_proxy().await,
            ProtocolType::Grpc => self.start_grpc_proxy().await,
        }
    }

    /// Start the HTTP proxy
    async fn start_http_proxy(&self) -> Result<()> {
        let proxy = HttpProxy::new(
            self.config.clone(),
            self.identity_provider.clone(),
            self.policy_engine.clone(),
            self.metrics.clone(),
        );

        proxy.start().await
    }

    /// Start the gRPC proxy
    async fn start_grpc_proxy(&self) -> Result<()> {
        let proxy = GrpcProxy::new(
            self.config.clone(),
            self.identity_provider.clone(),
            self.policy_engine.clone(),
            self.metrics.clone(),
        );

        proxy.start().await
    }
}