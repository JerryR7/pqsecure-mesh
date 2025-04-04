use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Serialize, Deserialize};
use crate::identity::SpiffeId;
use crate::types::ProtocolType;

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
#[serde(untagged)]
pub enum AllowedMethod {
    /// HTTP method (e.g. ["GET", "/api/v1/resource"])
    Http(Vec<String>),
    /// gRPC method (e.g. "service.Method")
    Grpc(String),
}

/// Deny rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DenyRule {
    /// IP address or subnet
    IpRule { ip: String },
    /// HTTP method and path
    HttpRule { method: String, path: String },
    /// Time restriction
    TimeRule { start_hour: u8, end_hour: u8 },
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
                DenyRule::IpRule { ip } => {
                    if let Some(client_ip) = client_ip {
                        if self.is_ip_match(client_ip, ip) {
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
                DenyRule::TimeRule { start_hour, end_hour } => {
                    let now = chrono::Local::now();
                    let current_hour = now.hour() as u8;
                    
                    if *start_hour <= current_hour && current_hour <= *end_hour {
                        return true;
                    }
                },
            }
        }
        
        false
    }
    
    /// Check if the IP address matches
    fn is_ip_match(&self, client_ip: &str, ip_rule: &str) -> bool {
        // Simple IP matching
        if client_ip == ip_rule {
            return true;
        }
        
        // CIDR range matching
        if ip_rule.contains('/') {
            if let Ok(client_addr) = client_ip.parse::<IpAddr>() {
                if let Ok(network) = cidr_utils::cidr::IpCidr::from_str(ip_rule) {
                    return network.contains(&client_addr);
                }
            }
        }
        
        false
    }
}

/// Simple CIDR utilities
mod cidr_utils {
    pub mod cidr {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use std::str::FromStr;
        
        pub enum IpCidr {
            V4(Ipv4Cidr),
            V6(Ipv6Cidr),
        }
        
        pub struct Ipv4Cidr {
            pub base: Ipv4Addr,
            pub prefix_len: u8,
            pub mask: u32,
        }
        
        pub struct Ipv6Cidr {
            pub base: Ipv6Addr,
            pub prefix_len: u8,
        }
        
        impl IpCidr {
            pub fn from_str(s: &str) -> Result<Self, &'static str> {
                // Parse CIDR format
                let parts: Vec<&str> = s.split('/').collect();
                if parts.len() != 2 {
                    return Err("Invalid CIDR format");
                }
                
                let ip = parts[0].parse::<IpAddr>().map_err(|_| "Invalid IP address")?;
                let prefix_len = parts[1].parse::<u8>().map_err(|_| "Invalid prefix length")?;
                
                match ip {
                    IpAddr::V4(ipv4) => {
                        if prefix_len > 32 {
                            return Err("Invalid IPv4 prefix length");
                        }
                        
                        let mask = if prefix_len == 0 {
                            0
                        } else {
                            !0u32 << (32 - prefix_len)
                        };
                        
                        Ok(IpCidr::V4(Ipv4Cidr {
                            base: ipv4,
                            prefix_len,
                            mask,
                        }))
                    },
                    IpAddr::V6(ipv6) => {
                        if prefix_len > 128 {
                            return Err("Invalid IPv6 prefix length");
                        }
                        
                        Ok(IpCidr::V6(Ipv6Cidr {
                            base: ipv6,
                            prefix_len,
                        }))
                    },
                }
            }
            
            pub fn contains(&self, ip: &IpAddr) -> bool {
                // Check if the IP address is within the CIDR range
                match (self, ip) {
                    (IpCidr::V4(cidr), IpAddr::V4(ip)) => {
                        let ip_u32 = u32::from(*ip);
                        let base_u32 = u32::from(cidr.base);
                        
                        (ip_u32 & cidr.mask) == (base_u32 & cidr.mask)
                    },
                    (IpCidr::V6(cidr), IpAddr::V6(ip)) => {
                        let ip_segments = ip.segments();
                        let base_segments = cidr.base.segments();
                        
                        // Calculate the number of fully matching bytes
                        let full_bytes = cidr.prefix_len / 8;
                        
                        // Calculate the remaining bits
                        let remainder_bits = cidr.prefix_len % 8;
                        
                        // Check all fully matching bytes
                        for i in 0..(full_bytes as usize) {
                            let segment_idx = i / 2;
                            let hi_byte = i % 2 == 0;
                            
                            let ip_byte = if hi_byte {
                                (ip_segments[segment_idx] >> 8) as u8
                            } else {
                                ip_segments[segment_idx] as u8
                            };
                            
                            let base_byte = if hi_byte {
                                (base_segments[segment_idx] >> 8) as u8
                            } else {
                                base_segments[segment_idx] as u8
                            };
                            
                            if ip_byte != base_byte {
                                return false;
                            }
                        }
                        
                        // Check remaining bits
                        if remainder_bits > 0 {
                            let segment_idx = (full_bytes as usize) / 2;
                            let hi_byte = (full_bytes as usize) % 2 == 0;
                            
                            let ip_byte = if hi_byte {
                                (ip_segments[segment_idx] >> 8) as u8
                            } else {
                                ip_segments[segment_idx] as u8
                            };
                            
                            let base_byte = if hi_byte {
                                (base_segments[segment_idx] >> 8) as u8
                            } else {
                                base_segments[segment_idx] as u8
                            };
                            
                            let mask = !0u8 << (8 - remainder_bits);
                            
                            if (ip_byte & mask) != (base_byte & mask) {
                                return false;
                            }
                        }
                        
                        true
                    },
                    _ => false, // IPv4 and IPv6 do not match
                }
            }
        }
    }
}