use std::collections::HashMap;
use std::sync::{Arc, RwLock, Mutex};
use std::time::{Duration, Instant};
use tokio::time;
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error};

use crate::error::Error;
use crate::config::Config;
use crate::controller::sidecar::SidecarHandle;

/// Health check controller
pub struct HealthController {
    /// Configuration
    config: Arc<Config>,
    /// Service health status
    service_health: RwLock<HashMap<String, ServiceHealth>>,
    /// Last check time
    last_check: Mutex<Instant>,
    /// Whether it is running
    running: Mutex<bool>,
}

/// Service health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    /// Service ID
    pub service_id: String,
    /// Health status
    pub status: HealthStatus,
    /// Last check time
    pub last_checked: chrono::DateTime<chrono::Utc>,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Detailed information
    pub details: HashMap<String, String>,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Healthy
    #[serde(rename = "healthy")]
    Healthy,
    /// Unhealthy
    #[serde(rename = "unhealthy")]
    Unhealthy,
    /// Degraded
    #[serde(rename = "degraded")]
    Degraded,
    /// Initializing
    #[serde(rename = "initializing")]
    Initializing,
    /// Unknown
    #[serde(rename = "unknown")]
    Unknown,
}

impl HealthController {
    /// Create a new health check controller
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            service_health: RwLock::new(HashMap::new()),
            last_check: Mutex::new(Instant::now()),
            running: Mutex::new(false),
        }
    }
    
    /// Start the health check controller
    pub fn start(self: Arc<Self>, check_interval: Duration) {
        // Ensure it only starts once
        let mut running = self.running.lock().unwrap();
        if *running {
            return;
        }
        *running = true;
        
        // Start the health check task
        tokio::spawn(async move {
            let mut interval = time::interval(check_interval);
            
            loop {
                interval.tick().await;
                
                // Update the last check time
                {
                    let mut last_check = self.last_check.lock().unwrap();
                    *last_check = Instant::now();
                }
                
                // Check all services
                if let Err(e) = self.check_all_services().await {
                    error!("Failed to check services health: {}", e);
                }
            }
        });
    }
    
    /// Check all services
    async fn check_all_services(&self) -> Result<(), Error> {
        debug!("Checking all services health");
        
        // Get all services
        let services = {
            let services = self.service_health.read().unwrap();
            services.keys().cloned().collect::<Vec<_>>()
        };
        
        // Check each service
        for service_id in services {
            if let Err(e) = self.check_service(&service_id).await {
                warn!("Failed to check service health {}: {}", service_id, e);
            }
        }
        
        Ok(())
    }
    
    /// Check a single service
    async fn check_service(&self, service_id: &str) -> Result<(), Error> {
        debug!("Checking service health: {}", service_id);
        
        // Attempt to perform a health check
        let status = self.perform_health_check(service_id).await;
        
        // Update the service health status
        let mut services = self.service_health.write().unwrap();
        if let Some(health) = services.get_mut(service_id) {
            health.status = status;
            health.last_checked = chrono::Utc::now();
            health.uptime_seconds += check_interval_as_seconds(health.last_checked, health.last_checked);
        }
        
        Ok(())
    }
    
    /// Perform a health check
    async fn perform_health_check(&self, service_id: &str) -> HealthStatus {
        // This is a simulated implementation. In practice, a request should be sent to the service's health check endpoint.
        // For simplicity, we assume 70% of the checks result in a healthy status.
        
        if rand::random::<f32>() < 0.7 {
            HealthStatus::Healthy
        } else if rand::random::<f32>() < 0.5 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        }
    }
    
    /// Register a service
    pub fn register_service(&self, service_id: &str) -> Result<(), Error> {
        info!("Registering service for health check: {}", service_id);
        
        let mut services = self.service_health.write().unwrap();
        services.insert(service_id.to_string(), ServiceHealth {
            service_id: service_id.to_string(),
            status: HealthStatus::Initializing,
            last_checked: chrono::Utc::now(),
            uptime_seconds: 0,
            details: HashMap::new(),
        });
        
        Ok(())
    }
    
    /// Unregister a service
    pub fn unregister_service(&self, service_id: &str) -> Result<(), Error> {
        info!("Unregistering service from health check: {}", service_id);
        
        let mut services = self.service_health.write().unwrap();
        services.remove(service_id);
        
        Ok(())
    }
    
    /// Get the health status of a service
    pub fn get_service_health(&self, service_id: &str) -> Option<ServiceHealth> {
        let services = self.service_health.read().unwrap();
        services.get(service_id).cloned()
    }
    
    /// Get the health status of all services
    pub fn get_all_services_health(&self) -> HashMap<String, ServiceHealth> {
        let services = self.service_health.read().unwrap();
        services.clone()
    }
    
    /// Update the health status of a service
    pub fn update_service_health(
        &self,
        service_id: &str,
        status: HealthStatus,
        details: HashMap<String, String>,
    ) -> Result<(), Error> {
        let mut services = self.service_health.write().unwrap();
        
        if let Some(health) = services.get_mut(service_id) {
            health.status = status;
            health.last_checked = chrono::Utc::now();
            health.details = details;
        } else {
            services.insert(service_id.to_string(), ServiceHealth {
                service_id: service_id.to_string(),
                status,
                last_checked: chrono::Utc::now(),
                uptime_seconds: 0,
                details,
            });
        }
        
        Ok(())
    }
    
    /// Get the overall system health status
    pub fn get_system_health(&self) -> HealthStatus {
        let services = self.service_health.read().unwrap();
        
        if services.is_empty() {
            return HealthStatus::Unknown;
        }
        
        let mut has_unhealthy = false;
        let mut has_degraded = false;
        let mut has_initializing = false;
        
        for health in services.values() {
            match health.status {
                HealthStatus::Unhealthy => has_unhealthy = true,
                HealthStatus::Degraded => has_degraded = true,
                HealthStatus::Initializing => has_initializing = true,
                _ => {}
            }
        }
        
        if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else if has_initializing {
            HealthStatus::Initializing
        } else {
            HealthStatus::Healthy
        }
    }
    
    /// Register services from sidecar handles
    pub fn register_services_from_sidecars(&self, sidecars: &[SidecarHandle]) -> Result<(), Error> {
        for sidecar in sidecars {
            self.register_service(&sidecar.service_id)?;
        }
        
        Ok(())
    }
}

/// Calculate the number of seconds between two time points
fn check_interval_as_seconds(a: chrono::DateTime<chrono::Utc>, b: chrono::DateTime<chrono::Utc>) -> u64 {
    let duration = if a > b { a - b } else { b - a };
    duration.num_seconds() as u64
}