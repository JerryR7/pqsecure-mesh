use tracing::{debug, trace};
use crate::error::Error;
use crate::identity::SpiffeId;
use crate::types::ProtocolType;
use crate::policy::types::{AccessPolicy, PolicyEvaluator};

/// Extended policy evaluator
pub struct PolicyEvaluatorService {
    /// Policy evaluator
    evaluator: PolicyEvaluator,
    /// Evaluation mode (strict, permissive)
    strict_mode: bool,
}

impl PolicyEvaluatorService {
    /// Create a new policy evaluator service
    pub fn new(strict_mode: bool) -> Self {
        Self {
            evaluator: PolicyEvaluator::new(),
            strict_mode,
        }
    }
    
    /// Evaluate a request
    pub async fn evaluate(
        &self,
        policy: &AccessPolicy,
        client_id: &SpiffeId,
        method: &str,
        path: &str,
        protocol: ProtocolType,
        client_ip: Option<&str>,
    ) -> Result<bool, Error> {
        debug!(
            "Evaluating request: client_id={}, method={}, path={}, protocol={}",
            client_id.uri, method, path, protocol
        );
        
        // Evaluate identity
        if !self.evaluator.evaluate_identity(policy, client_id) {
            debug!("Identity not allowed: {}", client_id.uri);
            return Ok(false);
        }
        
        // Evaluate method based on protocol type
        let method_allowed = match protocol {
            ProtocolType::Http => {
                self.evaluator.evaluate_http_method(policy, method, path)
            },
            ProtocolType::Grpc => {
                self.evaluator.evaluate_grpc_method(policy, method)
            },
            ProtocolType::Tcp => {
                // TCP has no concept of methods, as long as the identity is allowed
                true
            },
        };
        
        if !method_allowed {
            debug!("Method not allowed: {} {}", method, path);
            return Ok(false);
        }
        
        // Evaluate deny rules
        if self.evaluator.evaluate_deny_rules(policy, client_ip, method, path) {
            debug!("Request denied by deny rules");
            return Ok(false);
        }
        
        debug!("Request allowed");
        Ok(true)
    }
    
    /// Evaluate a request in non-strict mode
    pub async fn evaluate_permissive(
        &self,
        policy: &AccessPolicy,
        client_id: &SpiffeId,
        method: &str,
        path: &str,
        protocol: ProtocolType,
        client_ip: Option<&str>,
    ) -> Result<bool, Error> {
        // Get the standard evaluation result
        let normal_result = self.evaluate(
            policy,
            client_id,
            method,
            path,
            protocol,
            client_ip,
        ).await?;
        
        // If non-strict mode and the request is denied, check for special paths or methods
        if !normal_result && !self.strict_mode {
            // Check if it is a health check or metrics path
            if (method == "GET" && (path == "/health" || path == "/metrics" || path.starts_with("/api/v1/health"))) ||
               (protocol == ProtocolType::Tcp) {
                debug!("Allowing request in permissive mode for health/metrics path");
                return Ok(true);
            }
            
            // Check if it is from an internal service
            if client_id.uri.contains("/controller") || 
               client_id.uri.contains("/monitoring") ||
               client_id.tenant == "system" {
                debug!("Allowing request in permissive mode for system service");
                return Ok(true);
            }
        }
        
        Ok(normal_result)
    }
    
    /// Set evaluation mode
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }
    
    /// Get the current evaluation mode
    pub fn is_strict_mode(&self) -> bool {
        self.strict_mode
    }
}