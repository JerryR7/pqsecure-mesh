use serde::{Deserialize, Serialize};

/// Policy rule for access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// SPIFFE ID pattern to match (exact string or regex)
    pub spiffe_id: String,

    /// Protocol for this rule (tcp, http, grpc)
    pub protocol: Option<String>,

    /// Method or path pattern (for HTTP/gRPC)
    pub method: Option<String>,

    /// Whether to allow or deny the request
    #[serde(default = "default_action")]
    pub allow: bool,
}

/// Default action for policy rules
fn default_action() -> bool {
    true
}

/// Full policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    /// Default action when no rules match
    #[serde(default = "default_deny")]
    pub default_action: bool,

    /// List of policy rules
    pub rules: Vec<PolicyRule>,
}

/// Default action for overall policy
fn default_deny() -> bool {
    false
}

/// Type for methods/paths with special handling
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MethodPattern {
    /// Match any method
    Any,
    /// Match exact method name
    Exact(String),
    /// Match regex pattern
    Regex(String),
}

impl From<&str> for MethodPattern {
    fn from(s: &str) -> Self {
        match s {
            "*" => MethodPattern::Any,
            _ if s.starts_with("regex:") => {
                MethodPattern::Regex(s[6..].to_string())
            },
            _ => MethodPattern::Exact(s.to_string()),
        }
    }
}

/// Type for SPIFFE ID patterns with special handling
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpiffeIdPattern {
    /// Match any SPIFFE ID
    Any,
    /// Match exact SPIFFE ID
    Exact(String),
    /// Match regex pattern
    Regex(String),
}

impl From<&str> for SpiffeIdPattern {
    fn from(s: &str) -> Self {
        match s {
            "*" => SpiffeIdPattern::Any,
            _ if s.starts_with("regex:") => {
                SpiffeIdPattern::Regex(s[6..].to_string())
            },
            _ => SpiffeIdPattern::Exact(s.to_string()),
        }
    }
}

/// Type for protocol matching
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolPattern {
    /// Match any protocol
    Any,
    /// Match specific protocol
    Exact(String),
}

impl From<&str> for ProtocolPattern {
    fn from(s: &str) -> Self {
        match s {
            "*" => ProtocolPattern::Any,
            _ => ProtocolPattern::Exact(s.to_string()),
        }
    }
}

/// Compiled policy rule for efficient matching
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// SPIFFE ID pattern
    pub spiffe_id: SpiffeIdPattern,

    /// Protocol pattern
    pub protocol: ProtocolPattern,

    /// Method pattern
    pub method: MethodPattern,

    /// Allow or deny
    pub allow: bool,
}

/// Compiled policy for efficient evaluation
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Default action
    pub default_action: bool,

    /// Compiled rules
    pub rules: Vec<CompiledRule>,
}