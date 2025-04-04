use std::sync::Arc;
use tracing::{debug, warn, error};

use crate::error::Error;
use crate::types::ProtocolType;
use crate::identity::SpiffeId;
use crate::policy::types::{AccessPolicy, PolicyEvaluator};
use crate::policy::store::PolicyStore;

/// Policy engine
pub struct PolicyEngine {
    /// Policy store
    store: Arc<dyn PolicyStore>,
    /// Policy evaluator
    evaluator: Arc<PolicyEvaluator>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(store: Arc<dyn PolicyStore>, evaluator: Arc<PolicyEvaluator>) -> Self {
        Self { store, evaluator }
    }
    
    /// Evaluate whether the request is allowed
    pub async fn evaluate_request(
        &self,
        client_id: &SpiffeId,
        method: &str,
        path: &str,
        protocol: ProtocolType,
    ) -> Result<bool, Error> {
        debug!(
            "Evaluating request: client_id={}, method={}, path={}, protocol={}",
            client_id.uri, method, path, protocol
        );
        
        // Retrieve the policy for the tenant
        let policy = self.store.get_policy(&client_id.tenant).await?;
        
        // Evaluate identity
        if !self.evaluator.evaluate_identity(&policy, client_id) {
            debug!("Identity not allowed: {}", client_id.uri);
            return Ok(false);
        }
        
        // Evaluate method based on protocol type
        let method_allowed = match protocol {
            ProtocolType::Http => {
                self.evaluator.evaluate_http_method(&policy, method, path)
            },
            ProtocolType::Grpc => {
                self.evaluator.evaluate_grpc_method(&policy, method)
            },
            ProtocolType::Tcp => {
                // TCP has no concept of methods, allow if identity is permitted
                true
            },
        };
        
        if !method_allowed {
            debug!("Method not allowed: {} {}", method, path);
            return Ok(false);
        }
        
        // Evaluate deny rules
        if self.evaluator.evaluate_deny_rules(&policy, None, method, path) {
            debug!("Request denied by deny rules");
            return Ok(false);
        }
        
        debug!("Request allowed");
        Ok(true)
    }
    
    /// Reload policies
    pub async fn reload_policies(&self) -> Result<(), Error> {
        self.store.reload().await
    }
    
    /// Retrieve the policy for a specific tenant
    pub async fn get_policy(&self, tenant: &str) -> Result<AccessPolicy, Error> {
        self.store.get_policy(tenant).await
    }
    
    /// Update a policy
    pub async fn update_policy(&self, policy: AccessPolicy) -> Result<(), Error> {
        self.store.update_policy(policy).await
    }
}