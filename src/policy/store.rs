use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use async_trait::async_trait;
use tokio::fs;
use tokio::time;
use tracing::{debug, warn, error, info};

use crate::common::{Error, Result};
use crate::config::Settings;
use crate::policy::types::{AccessPolicy, AllowedIdentity, AllowedMethod};

/// Policy storage interface
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Get policy for a tenant
    async fn get_policy(&self, tenant: &str) -> Result<AccessPolicy>;

    /// Update policy
    async fn update_policy(&self, policy: AccessPolicy) -> Result<()>;

    /// Reload policies
    async fn reload(&self) -> Result<()>;
}

/// File-based policy storage
pub struct FilePolicyStore {
    /// Application configuration
    config: Arc<Settings>,
    /// Policy mapping table (tenant -> policy)
    policies: RwLock<HashMap<String, AccessPolicy>>,
}

impl FilePolicyStore {
    /// Create a new file-based policy store
    pub fn new(config: Arc<Settings>) -> Self {
        let store = Self {
            config,
            policies: RwLock::new(HashMap::new()),
        };

        store
    }

    /// Start periodic reload task
    pub fn start_reload_task(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut interval = time::interval(interval);

            loop {
                interval.tick().await;
                debug!("Auto-reloading policies");

                if let Err(e) = self.reload().await {
                    error!("Failed to reload policies: {}", e);
                }
            }
        });
    }

    /// Load policy from file
    async fn load_policy_from_file(path: &PathBuf) -> Result<AccessPolicy> {
        debug!("Loading policy from file: {:?}", path);

        // Check if the file exists
        if !path.exists() {
            return Err(Error::Policy(format!("Policy file not found: {:?}", path)));
        }

        // Read file content
        let content = fs::read_to_string(path).await
            .map_err(|e| Error::Policy(format!("Failed to read policy file: {}", e)))?;

        // Attempt to parse YAML
        let policy: AccessPolicy = serde_yaml::from_str(&content)
            .map_err(|e| Error::Policy(format!("Failed to parse policy file: {}", e)))?;

        Ok(policy)
    }

    /// Get policy file path
    fn get_policy_path(&self, tenant: &str) -> PathBuf {
        let mut path = self.config.policy.policy_path.clone();

        if path.is_dir() {
            path = path.join(format!("{}.yaml", tenant));
        }

        path
    }

    /// Create default policy
    fn create_default_policy(&self, tenant: &str) -> AccessPolicy {
        AccessPolicy {
            id: format!("{}-default", tenant),
            allow_from: vec![
                AllowedIdentity { id: format!("spiffe://{}/controller", tenant) },
                AllowedIdentity { id: format!("spiffe://{}/monitoring", tenant) },
            ],
            allow_methods: vec![
                AllowedMethod::Http(vec!["GET".to_string(), "/health".to_string()]),
                AllowedMethod::Http(vec!["GET".to_string(), "/metrics".to_string()]),
            ],
            deny_rules: vec![],
        }
    }

    /// Save policy to file
    async fn save_policy_to_file(&self, policy: &AccessPolicy, tenant: &str) -> Result<()> {
        let path = self.get_policy_path(tenant);

        // Ensure the directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await
                .map_err(|e| Error::Policy(format!("Failed to create directory: {}", e)))?;
        }

        // Serialize policy to YAML
        let content = serde_yaml::to_string(policy)
            .map_err(|e| Error::Policy(format!("Failed to serialize policy: {}", e)))?;

        // Write to file
        fs::write(&path, content).await
            .map_err(|e| Error::Policy(format!("Failed to write policy file: {}", e)))?;

        debug!("Saved policy to file: {:?}", path);
        Ok(())
    }
}

#[async_trait]
impl PolicyStore for FilePolicyStore {
    async fn get_policy(&self, tenant: &str) -> Result<AccessPolicy> {
        // First check if the policy exists in memory
        {
            let policies = self.policies.read().unwrap();
            if let Some(policy) = policies.get(tenant) {
                return Ok(policy.clone());
            }
        }

        // Attempt to load from file
        let path = self.get_policy_path(tenant);
        let policy = match Self::load_policy_from_file(&path).await {
            Ok(policy) => {
                // Update the policy in memory
                let mut policies = self.policies.write().unwrap();
                let policy_clone = policy.clone();
                policies.insert(tenant.to_string(), policy);
                policy_clone
            },
            Err(e) => {
                warn!("Failed to load policy for tenant {}: {}", tenant, e);

                // If no policy exists, create a default policy
                let default_policy = self.create_default_policy(tenant);

                // Update the policy in memory
                let mut policies = self.policies.write().unwrap();
                let policy_clone = default_policy.clone();
                policies.insert(tenant.to_string(), default_policy);

                // Attempt to save the default policy to file
                if let Err(e) = self.save_policy_to_file(&policy_clone, tenant).await {
                    warn!("Failed to save default policy for tenant {}: {}", tenant, e);
                }

                policy_clone
            }
        };

        Ok(policy)
    }

    async fn update_policy(&self, policy: AccessPolicy) -> Result<()> {
        let id = policy.id.clone();

        // Extract tenant from ID
        let tenant = if let Some(idx) = id.find('-') {
            id[..idx].to_string()
        } else {
            id.clone()
        };

        // Update the policy in memory
        {
            let mut policies = self.policies.write().unwrap();
            policies.insert(tenant.clone(), policy.clone());
        }

        // Save to file
        self.save_policy_to_file(&policy, &tenant).await
    }

    async fn reload(&self) -> Result<()> {
        debug!("Reloading policies");

        // Clear the policies in memory
        {
            let mut policies = self.policies.write().unwrap();
            policies.clear();
        }

        // Check if the policy path is a directory
        let policy_path = &self.config.policy.policy_path;
        if policy_path.is_dir() {
            // Read all files in the directory
            let mut entries = fs::read_dir(policy_path).await
                .map_err(|e| Error::Policy(format!("Failed to read policy directory: {}", e)))?;

            while let Some(entry) = entries.next_entry().await
                .map_err(|e| Error::Policy(format!("Failed to read directory entry: {}", e)))? {

                let path = entry.path();

                // Only process YAML files
                if path.extension().map(|ext| ext == "yaml" || ext == "yml").unwrap_or(false) {
                    // Extract tenant from file name
                    if let Some(tenant) = path.file_stem().and_then(|s| s.to_str()) {
                        match Self::load_policy_from_file(&path).await {
                            Ok(policy) => {
                                // Update the policy in memory
                                let mut policies = self.policies.write().unwrap();
                                policies.insert(tenant.to_string(), policy);
                                debug!("Loaded policy for tenant: {}", tenant);
                            },
                            Err(e) => {
                                warn!("Failed to load policy for tenant {}: {}", tenant, e);
                            }
                        }
                    }
                }
            }
        } else {
            // Single policy file, attempt to load
            if policy_path.exists() {
                match Self::load_policy_from_file(policy_path).await {
                    Ok(policy) => {
                        // Extract tenant from ID
                        let tenant = if let Some(idx) = policy.id.find('-') {
                            policy.id[..idx].to_string()
                        } else {
                            policy.id.clone()
                        };

                        // Update the policy in memory
                        let mut policies = self.policies.write().unwrap();
                        policies.insert(tenant, policy);
                        debug!("Loaded policy from single file");
                    },
                    Err(e) => {
                        warn!("Failed to load policy from single file: {}", e);
                    }
                }
            }
        }

        info!("Policies reloaded successfully");
        Ok(())
    }
}