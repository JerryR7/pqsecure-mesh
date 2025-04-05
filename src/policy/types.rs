use serde::{Serialize, Deserialize};
use crate::identity::SpiffeId;

/// Access control policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Policy ID
    pub id: String,
    /// List of allowed identities
    pub allow_from: Vec<AllowedIdentity>,
    /// List of allowed methods
    pub allow_methods: Vec<AllowedMethod>,
    /// Deny rules
    #[serde(default)]
    pub deny_rules: Vec<DenyRule>,
}

/// Allowed identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedIdentity {
    /// SPIFFE ID (e.g. "spiffe://tenant-a/service-b")
    pub id: String,
}

/// Allowed methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AllowedMethod {
    /// HTTP method (e.g. ["GET", "/api/v1/resource"])
    #[serde(rename = "Http")]
    Http(Vec<String>),
    /// gRPC method (e.g. "service.Method")
    #[serde(rename = "Grpc")]
    Grpc(String),
}

/// Deny rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum DenyRule {
    /// IP address or subnet
    #[serde(rename = "ip")]
    IpRule(String),
    /// HTTP method and path
    #[serde(rename = "http")]
    HttpRule { method: String, path: String },
}

/// Policy evaluator
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new() -> Self {
        Self
    }

    /// Evaluate whether the SPIFFE ID is allowed
    pub fn evaluate_identity(&self, policy: &AccessPolicy, spiffe_id: &SpiffeId) -> bool {
        // Check if the SPIFFE ID is in the allowed list
        for allowed in &policy.allow_from {
            if allowed.id == "*" || allowed.id == spiffe_id.uri {
                return true;
            }

            // Check if wildcard is supported
            if allowed.id.ends_with("/*") {
                let prefix = allowed.id.trim_end_matches("/*");
                if spiffe_id.uri.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }

    /// Evaluate whether the HTTP method and path are allowed
    pub fn evaluate_http_method(
        &self,
        policy: &AccessPolicy,
        method: &str,
        path: &str,
    ) -> bool {
        for allowed in &policy.allow_methods {
            if let AllowedMethod::Http(http_method) = allowed {
                if http_method.len() == 2 {
                    let allowed_method = &http_method[0];
                    let allowed_path = &http_method[1];

                    // Check if the method matches
                    if allowed_method == "*" || allowed_method == method {
                        // Check if the path matches
                        if allowed_path == "*" || allowed_path == path ||
                            (allowed_path.ends_with("/*") && path.starts_with(&allowed_path[..allowed_path.len() - 2])) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Evaluate whether the gRPC method is allowed
    pub fn evaluate_grpc_method(
        &self,
        policy: &AccessPolicy,
        method: &str,
    ) -> bool {
        for allowed in &policy.allow_methods {
            if let AllowedMethod::Grpc(allowed_method) = allowed {
                if allowed_method == "*" || allowed_method == method {
                    return true;
                }

                // Check if wildcard is supported
                if allowed_method.ends_with(".*") {
                    let prefix = allowed_method.trim_end_matches(".*");
                    if method.starts_with(prefix) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Evaluate deny rules
    pub fn evaluate_deny_rules(
        &self,
        policy: &AccessPolicy,
        client_ip: Option<&str>,
        method: &str,
        path: &str,
    ) -> bool {
        for rule in &policy.deny_rules {
            match rule {
                DenyRule::IpRule(ip) => {
                    if let Some(client_ip) = client_ip {
                        if client_ip == ip {
                            return true;
                        }
                    }
                },
                DenyRule::HttpRule { method: deny_method, path: deny_path } => {
                    if (deny_method == "*" || deny_method == method) &&
                        (deny_path == "*" || deny_path == path ||
                            path.starts_with(deny_path)) {
                        return true;
                    }
                },
            }
        }

        false
    }
}