use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use tracing::{info, warn, debug, error};

use crate::error::Error;
use crate::config::Config;
use crate::identity::IdentityProvider;
use crate::policy::PolicyEngine;
use crate::proxy::{SidecarProxy, SidecarConfig, ProxyMetrics, SidecarResult};
use crate::types::ProtocolType;
use crate::telemetry::TelemetryService;

/// Sidecar controller
pub struct SidecarController {
    /// Configuration
    config: Arc<Config>,
    /// Identity provider
    identity_provider: Arc<dyn IdentityProvider>,
    /// Policy engine
    policy_engine: Arc<PolicyEngine>,
    /// Metrics collector
    metrics: Arc<ProxyMetrics>,
    /// Sidecar instances
    sidecars: Mutex<HashMap<String, SidecarHandle>>,
    /// Telemetry service
    telemetry: Arc<TelemetryService>,
}

/// Sidecar handle
pub struct SidecarHandle {
    /// Sidecar ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Service ID
    pub service_id: String,
    /// Listening address
    pub listen_addr: String,
    /// Listening port
    pub listen_port: u16,
    /// Sidecar status
    pub status: SidecarResult,
    /// Task handle
    pub task_handle: Option<tokio::task::JoinHandle<Result<(), Error>>>,
}

impl SidecarController {
    /// Create a new sidecar controller
    pub fn new(
        config: Arc<Config>,
        identity_provider: Arc<dyn IdentityProvider>,
        policy_engine: Arc<PolicyEngine>,
        metrics: Arc<ProxyMetrics>,
    ) -> Self {
        let telemetry = Arc::new(TelemetryService::new(config.clone()));
        
        Self {
            config,
            identity_provider,
            policy_engine,
            metrics,
            sidecars: Mutex::new(HashMap::new()),
            telemetry,
        }
    }
    
    /// Start a sidecar
    pub async fn start_sidecar(&self, config: SidecarConfig) -> Result<SidecarHandle, Error> {
        info!("Starting sidecar for {}/{}", config.tenant_id, config.service_id);
        
        // Generate sidecar ID
        let id = Uuid::new_v4().to_string();
        
        // Create sidecar proxy
        let proxy = SidecarProxy::new(
            config.clone(),
            self.identity_provider.clone(),
            self.policy_engine.clone(),
            self.metrics.clone(),
        );
        
        // Create sidecar handle
        let handle = SidecarHandle {
            id: id.clone(),
            tenant_id: config.tenant_id.clone(),
            service_id: config.service_id.clone(),
            listen_addr: config.listen_addr.clone(),
            listen_port: config.listen_port,
            status: SidecarResult::Running,
            task_handle: None,
        };
        
        // Start the proxy
        let task_handle = tokio::spawn(async move {
            if let Err(e) = proxy.start().await {
                error!("Sidecar proxy error: {}", e);
                return Err(e);
            }
            Ok(())
        });
        
        // Update handle
        let mut handle = handle;
        handle.task_handle = Some(task_handle);
        
        // Store handle
        {
            let mut sidecars = self.sidecars.lock().unwrap();
            sidecars.insert(id.clone(), handle.clone());
        }
        
        info!("Sidecar started: id={}, tenant={}, service={}", 
             id, config.tenant_id, config.service_id);
        
        Ok(handle)
    }
    
    /// Stop a sidecar
    pub async fn stop_sidecar(&self, handle: SidecarHandle) -> Result<(), Error> {
        info!("Stopping sidecar: id={}, tenant={}, service={}", 
             handle.id, handle.tenant_id, handle.service_id);
        
        // Abort the task
        if let Some(task_handle) = handle.task_handle {
            task_handle.abort();
        }
        
        // Remove handle
        {
            let mut sidecars = self.sidecars.lock().unwrap();
            sidecars.remove(&handle.id);
        }
        
        Ok(())
    }
    
    /// Get all sidecars
    pub fn get_all_sidecars(&self) -> Vec<SidecarHandle> {
        let sidecars = self.sidecars.lock().unwrap();
        sidecars.values().cloned().collect()
    }
    
    /// Get a specific sidecar
    pub fn get_sidecar(&self, id: &str) -> Option<SidecarHandle> {
        let sidecars = self.sidecars.lock().unwrap();
        sidecars.get(id).cloned()
    }
    
    /// Get all sidecars for a specific tenant
    pub fn get_tenant_sidecars(&self, tenant: &str) -> Vec<SidecarHandle> {
        let sidecars = self.sidecars.lock().unwrap();
        sidecars.values()
            .filter(|h| h.tenant_id == tenant)
            .cloned()
            .collect()
    }
}

impl Clone for SidecarHandle {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            service_id: self.service_id.clone(),
            listen_addr: self.listen_addr.clone(),
            listen_port: self.listen_port,
            status: self.status.clone(),
            task_handle: None, // Task handle cannot be cloned
        }
    }
}

impl Clone for SidecarResult {
    fn clone(&self) -> Self {
        match self {
            Self::Running => Self::Running,
            Self::Stopped => Self::Stopped,
            Self::Error(msg) => Self::Error(msg.clone()),
        }
    }
}