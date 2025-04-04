use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::time;
use tracing::{debug, info, warn, error};

use crate::error::Error;
use crate::config::Config;
use crate::identity::{IdentityProvider, ServiceIdentity, IdentityStatus};

/// Certificate rotation controller
pub struct RotationController {
    /// Configuration
    config: Arc<Config>,
    /// Identity provider
    identity_provider: Arc<dyn IdentityProvider>,
    /// Managed identities
    managed_identities: RwLock<HashMap<String, ManagedIdentity>>,
    /// Last check time
    last_check: Mutex<Instant>,
    /// Whether it is running
    running: Mutex<bool>,
}

/// Managed identity
struct ManagedIdentity {
    /// Service identity
    identity: ServiceIdentity,
    /// Last rotation time
    last_rotation: Instant,
    /// Next check time
    next_check: Instant,
}

impl RotationController {
    /// Create a new certificate rotation controller
    pub fn new(
        config: Arc<Config>,
        identity_provider: Arc<dyn IdentityProvider>,
    ) -> Self {
        Self {
            config,
            identity_provider,
            managed_identities: RwLock::new(HashMap::new()),
            last_check: Mutex::new(Instant::now()),
            running: Mutex::new(false),
        }
    }
    
    /// Start the certificate rotation controller
    pub fn start(self: Arc<Self>, check_interval: Duration) {
        // Ensure it only starts once
        let mut running = self.running.lock().unwrap();
        if *running {
            return;
        }
        *running = true;
        
        // Start the rotation task
        tokio::spawn(async move {
            let mut interval = time::interval(check_interval);
            
            loop {
                interval.tick().await;
                
                // Update the last check time
                {
                    let mut last_check = self.last_check.lock().unwrap();
                    *last_check = Instant::now();
                }
                
                // Check all identities
                if let Err(e) = self.check_all_identities().await {
                    error!("Failed to check identities: {}", e);
                }
            }
        });
    }
    
    /// Check all identities
    async fn check_all_identities(&self) -> Result<(), Error> {
        debug!("Checking all identities for rotation");
        
        // Get all managed identities
        let identities = {
            let identities = self.managed_identities.read().unwrap();
            identities.keys().cloned().collect::<Vec<_>>()
        };
        
        // Check each identity
        for spiffe_id in identities {
            if let Err(e) = self.check_identity(&spiffe_id).await {
                warn!("Failed to check identity {}: {}", spiffe_id, e);
            }
        }
        
        Ok(())
    }
    
    /// Check a single identity
    async fn check_identity(&self, spiffe_id: &str) -> Result<(), Error> {
        // Check if it needs to be checked
        let needs_check = {
            let identities = self.managed_identities.read().unwrap();
            if let Some(managed) = identities.get(spiffe_id) {
                Instant::now() >= managed.next_check
            } else {
                false
            }
        };
        
        if !needs_check {
            return Ok(());
        }
        
        debug!("Checking identity for rotation: {}", spiffe_id);
        
        // Load the identity
        let identity = match self.identity_provider.load_identity(spiffe_id).await? {
            Some(identity) => identity,
            None => {
                warn!("Identity not found: {}", spiffe_id);
                // Remove non-existent identity
                let mut identities = self.managed_identities.write().unwrap();
                identities.remove(spiffe_id);
                return Ok(());
            }
        };
        
        // Check the identity status
        match self.identity_provider.check_identity_status(&identity).await? {
            IdentityStatus::Valid => {
                // Check if it needs rotation
                if identity.needs_rotation(self.config.identity.renew_threshold_pct) {
                    info!("Identity needs rotation: {}", spiffe_id);
                    self.rotate_identity(&identity).await?;
                } else {
                    debug!("Identity does not need rotation: {}", spiffe_id);
                    
                    // Update the next check time
                    let mut identities = self.managed_identities.write().unwrap();
                    if let Some(managed) = identities.get_mut(spiffe_id) {
                        // Calculate the next check time: adjust based on remaining validity percentage
                        let remaining_percent = identity.remaining_valid_percent();
                        let check_interval = if remaining_percent < 50.0 {
                            // Check more frequently when validity is low
                            Duration::from_secs(3600) // 1 hour
                        } else if remaining_percent < 80.0 {
                            // Check daily when validity is moderate
                            Duration::from_secs(24 * 3600) // 1 day
                        } else {
                            // Check weekly when validity is sufficient
                            Duration::from_secs(7 * 24 * 3600) // 1 week
                        };
                        
                        managed.next_check = Instant::now() + check_interval;
                    }
                }
            },
            IdentityStatus::Expired => {
                info!("Identity expired, rotating: {}", spiffe_id);
                self.rotate_identity(&identity).await?;
            },
            IdentityStatus::Revoked => {
                warn!("Identity revoked, removing from managed identities: {}", spiffe_id);
                
                // Remove revoked identity
                let mut identities = self.managed_identities.write().unwrap();
                identities.remove(spiffe_id);
            },
            IdentityStatus::Unknown => {
                warn!("Identity status unknown, removing from managed identities: {}", spiffe_id);
                
                // Remove identity with unknown status
                let mut identities = self.managed_identities.write().unwrap();
                identities.remove(spiffe_id);
            },
        }
        
        Ok(())
    }
    
    /// Rotate an identity
    async fn rotate_identity(&self, identity: &ServiceIdentity) -> Result<(), Error> {
        info!("Rotating identity: {}", identity.spiffe_id.uri);
        
        // Rotate the identity
        let new_identity = self.identity_provider.rotate_identity(identity).await?;
        
        // Update the managed identity
        let mut identities = self.managed_identities.write().unwrap();
        identities.insert(new_identity.spiffe_id.uri.clone(), ManagedIdentity {
            identity: new_identity,
            last_rotation: Instant::now(),
            next_check: Instant::now() + Duration::from_secs(24 * 3600), // Check again in 1 day
        });
        
        info!("Identity rotation completed: {}", identity.spiffe_id.uri);
        
        Ok(())
    }
    
    /// Add a managed identity
    pub async fn add_managed_identity(&self, identity: ServiceIdentity) -> Result<(), Error> {
        let spiffe_id = identity.spiffe_id.uri.clone();
        
        info!("Adding managed identity: {}", spiffe_id);
        
        // Add to managed identities
        let mut identities = self.managed_identities.write().unwrap();
        identities.insert(spiffe_id.clone(), ManagedIdentity {
            identity,
            last_rotation: Instant::now(),
            next_check: Instant::now() + Duration::from_secs(3600), // Check in 1 hour
        });
        
        Ok(())
    }
    
    /// Remove a managed identity
    pub fn remove_managed_identity(&self, spiffe_id: &str) -> Result<(), Error> {
        info!("Removing managed identity: {}", spiffe_id);
        
        // Remove from managed identities
        let mut identities = self.managed_identities.write().unwrap();
        identities.remove(spiffe_id);
        
        Ok(())
    }
    
    /// Get all managed identities
    pub fn get_managed_identities(&self) -> Vec<String> {
        let identities = self.managed_identities.read().unwrap();
        identities.keys().cloned().collect()
    }
    
    /// Get the count of managed identities
    pub fn get_managed_identity_count(&self) -> usize {
        let identities = self.managed_identities.read().unwrap();
        identities.len()
    }
}
        let needs_check = {