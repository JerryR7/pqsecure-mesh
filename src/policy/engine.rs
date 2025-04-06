use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, trace};

use crate::common::PqSecureError;
use crate::policy::model::*;

/// Policy engine trait for access control decisions
pub trait PolicyEngine: Send + Sync {
    /// Check if a request is allowed
    fn allow(&self, spiffe_id: &str, method: &str) -> bool;
}

/// YAML-based policy engine
pub struct YamlPolicyEngine {
    /// Compiled policy
    policy: CompiledPolicy,

    /// Cached regex patterns
    regex_cache: Mutex<HashMap<String, Regex>>,
}

impl YamlPolicyEngine {
    /// Create a new policy engine from a YAML file
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .context(format!("Failed to read policy file: {}", path.as_ref().display()))?;

        Self::from_yaml(&content)
    }

    /// Create a new policy engine from YAML content
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let policy_def: PolicyDefinition = serde_yaml::from_str(yaml)
            .context("Failed to parse policy YAML")?;

        Self::from_definition(policy_def)
    }

    /// Create a new policy engine from a policy definition
    pub fn from_definition(def: PolicyDefinition) -> Result<Self> {
        let mut compiled_rules = Vec::with_capacity(def.rules.len());

        for rule in def.rules {
            let spiffe_id = if rule.spiffe_id.starts_with("regex:") {
                let pattern = &rule.spiffe_id[6..];
                // Validate regex
                Regex::new(pattern)
                    .context(format!("Invalid regex pattern: {}", pattern))?;
                SpiffeIdPattern::Regex(pattern.to_string())
            } else if rule.spiffe_id == "*" {
                SpiffeIdPattern::Any
            } else {
                SpiffeIdPattern::Exact(rule.spiffe_id)
            };

            let protocol = match rule.protocol {
                Some(ref p) if p == "*" => ProtocolPattern::Any,
                Some(ref p) => ProtocolPattern::Exact(p.clone()),
                None => ProtocolPattern::Any,
            };

            let method = match rule.method {
                Some(ref m) if m.starts_with("regex:") => {
                    let pattern = &m[6..];
                    // Validate regex
                    Regex::new(pattern)
                        .context(format!("Invalid regex pattern: {}", pattern))?;
                    MethodPattern::Regex(pattern.to_string())
                },
                Some(ref m) if m == "*" => MethodPattern::Any,
                Some(ref m) => MethodPattern::Exact(m.clone()),
                None => MethodPattern::Any,
            };

            compiled_rules.push(CompiledRule {
                spiffe_id,
                protocol,
                method,
                allow: rule.allow,
            });
        }

        Ok(Self {
            policy: CompiledPolicy {
                default_action: def.default_action,
                rules: compiled_rules,
            },
            regex_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Match a SPIFFE ID against a pattern
    fn match_spiffe_id(&self, pattern: &SpiffeIdPattern, spiffe_id: &str) -> bool {
        match pattern {
            SpiffeIdPattern::Any => true,
            SpiffeIdPattern::Exact(expected) => expected == spiffe_id,
            SpiffeIdPattern::Regex(regex_str) => {
                let mut cache = self.regex_cache.lock().unwrap();
                let regex = match cache.get(regex_str) {
                    Some(r) => r,
                    None => {
                        let r = match Regex::new(regex_str) {
                            Ok(r) => r,
                            Err(_) => return false,
                        };
                        cache.insert(regex_str.clone(), r);
                        cache.get(regex_str).unwrap()
                    }
                };
                regex.is_match(spiffe_id)
            }
        }
    }

    /// Match a method against a pattern
    fn match_method(&self, pattern: &MethodPattern, method: &str) -> bool {
        match pattern {
            MethodPattern::Any => true,
            MethodPattern::Exact(expected) => expected == method,
            MethodPattern::Regex(regex_str) => {
                let mut cache = self.regex_cache.lock().unwrap();
                let regex = match cache.get(regex_str) {
                    Some(r) => r,
                    None => {
                        let r = match Regex::new(regex_str) {
                            Ok(r) => r,
                            Err(_) => return false,
                        };
                        cache.insert(regex_str.clone(), r);
                        cache.get(regex_str).unwrap()
                    }
                };
                regex.is_match(method)
            }
        }
    }

    /// Match protocol against a pattern
    fn match_protocol(&self, pattern: &ProtocolPattern, protocol: &str) -> bool {
        match pattern {
            ProtocolPattern::Any => true,
            ProtocolPattern::Exact(expected) => expected.to_lowercase() == protocol.to_lowercase(),
        }
    }
}

impl PolicyEngine for YamlPolicyEngine {
    fn allow(&self, spiffe_id: &str, method: &str) -> bool {
        trace!("Evaluating policy for SPIFFE ID: {}, method: {}", spiffe_id, method);

        // Default to TCP protocol for simple policy evaluation
        let protocol = "tcp";

        // Evaluate each rule in order
        for rule in &self.policy.rules {
            // Check if SPIFFE ID matches
            if !self.match_spiffe_id(&rule.spiffe_id, spiffe_id) {
                continue;
            }

            // Check if protocol matches
            if !self.match_protocol(&rule.protocol, protocol) {
                continue;
            }

            // Check if method matches
            if !self.match_method(&rule.method, method) {
                continue;
            }

            // Rule matched, return its action
            debug!(
                "Policy rule matched - SPIFFE ID: {}, method: {}, allow: {}",
                spiffe_id, method, rule.allow
            );
            return rule.allow;
        }

        // No rules matched, use default action
        debug!(
            "No policy rules matched - SPIFFE ID: {}, method: {}, using default action: {}",
            spiffe_id, method, self.policy.default_action
        );
        self.policy.default_action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_exact_match() {
        let yaml = r#"
        default_action: false
        rules:
          - spiffe_id: "spiffe://example.org/service/allowed"
            allow: true
          - spiffe_id: "spiffe://example.org/service/denied"
            allow: false
        "#;

        let engine = YamlPolicyEngine::from_yaml(yaml).unwrap();

        assert!(engine.allow("spiffe://example.org/service/allowed", "any"));
        assert!(!engine.allow("spiffe://example.org/service/denied", "any"));
        assert!(!engine.allow("spiffe://example.org/service/unknown", "any"));
    }

    #[test]
    fn test_policy_regex_match() {
        let yaml = r#"
        default_action: false
        rules:
          - spiffe_id: "regex:spiffe://example.org/service/.*"
            method: "regex:^get.*$"
            allow: true
          - spiffe_id: "regex:spiffe://example.org/admin/.*"
            allow: false
        "#;

        let engine = YamlPolicyEngine::from_yaml(yaml).unwrap();

        assert!(engine.allow("spiffe://example.org/service/web", "get_users"));
        assert!(!engine.allow("spiffe://example.org/service/web", "delete"));
        assert!(!engine.allow("spiffe://example.org/admin/root", "any"));
    }

    #[test]
    fn test_policy_default_action() {
        let yaml = r#"
        default_action: true
        rules:
          - spiffe_id: "spiffe://example.org/service/denied"
            allow: false
        "#;

        let engine = YamlPolicyEngine::from_yaml(yaml).unwrap();

        assert!(!engine.allow("spiffe://example.org/service/denied", "any"));
        assert!(engine.allow("spiffe://example.org/service/other", "any"));
    }
}