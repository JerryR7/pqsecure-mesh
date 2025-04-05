use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::net::lookup_host;

use crate::error::Error;

/// Network utilities
pub struct NetUtils;

impl NetUtils {
    /// Attempt to resolve a hostname or IP address
    pub async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr, Error> {
        // Attempt to directly parse the IP address
        if let Ok(ip) = IpAddr::from_str(host) {
            return Ok(SocketAddr::new(ip, port));
        }
        
        // Attempt to resolve the hostname
        let addr_iter = lookup_host(format!("{}:{}", host, port)).await
            .map_err(|e| Error::Internal(format!("Failed to resolve host: {}", e)))?;
        
        // Get the first valid address
        let addr = addr_iter.into_iter().next()
            .ok_or_else(|| Error::Internal(format!("No addresses found for {}", host)))?;
        
        Ok(addr)
    }
    
    /// Check if a port is available
    pub async fn is_port_available(host: &str, port: u16) -> bool {
        match tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    /// Get the local IP address
    pub fn get_local_ip() -> Result<IpAddr, Error> {
        // Determine the local IP by communicating with an external server
        // This is a simplified implementation; real applications may require more complex logic
        
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| Error::Internal(format!("Failed to bind UDP socket: {}", e)))?;
        
        // Attempt to connect to Google's DNS server (no actual data is sent)
        socket.connect("8.8.8.8:80")
            .map_err(|e| Error::Internal(format!("Failed to connect socket: {}", e)))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| Error::Internal(format!("Failed to get local address: {}", e)))?;
        
        Ok(local_addr.ip())
    }
    
    /// Check if an IP address is a public IP
    pub fn is_public_ip(ip: &IpAddr) -> bool {
        !ip.is_loopback() && !ip.is_private() && !ip.is_link_local()
    }
    
    /// Check if an IP address is a private IP
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        ip.is_private()
    }
    
    /// Parse a CIDR block
    pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), Error> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidRequest(format!("Invalid CIDR format: {}", cidr)));
        }
        
        let ip = IpAddr::from_str(parts[0])
            .map_err(|e| Error::InvalidRequest(format!("Invalid IP address: {}", e)))?;
        
        let prefix_len = u8::from_str(parts[1])
            .map_err(|e| Error::InvalidRequest(format!("Invalid prefix length: {}", e)))?;
        
        match ip {
            IpAddr::V4(_) => {
                if prefix_len > 32 {
                    return Err(Error::InvalidRequest(format!("Invalid IPv4 prefix length: {}", prefix_len)));
                }
            },
            IpAddr::V6(_) => {
                if prefix_len > 128 {
                    return Err(Error::InvalidRequest(format!("Invalid IPv6 prefix length: {}", prefix_len)));
                }
            },
        }
        
        Ok((ip, prefix_len))
    }
    
    /// Check if an IP is within a specified CIDR range
    pub fn is_ip_in_cidr(ip: &IpAddr, cidr: &str) -> Result<bool, Error> {
        let (network_ip, prefix_len) = Self::parse_cidr(cidr)?;
        
        // Ensure the IP and network types match
        if (ip.is_ipv4() && network_ip.is_ipv6()) || (ip.is_ipv6() && network_ip.is_ipv4()) {
            return Ok(false);
        }
        
        match (ip, network_ip) {
            (IpAddr::V4(ip), IpAddr::V4(network_ip)) => {
                // Convert IP addresses to u32
                let ip_u32 = u32::from(ip);
                let network_u32 = u32::from(network_ip);
                
                // Calculate the mask
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                
                // Check if within the network range
                Ok((ip_u32 & mask) == (network_u32 & mask))
            },
            (IpAddr::V6(ip), IpAddr::V6(network_ip)) => {
                // Convert IP addresses to [u8; 16]
                let ip_bytes = ip.octets();
                let network_bytes = network_ip.octets();
                
                // Calculate the number of fully matched bytes
                let full_bytes = prefix_len / 8;
                
                // Check if within the network range
                for i in 0..full_bytes {
                    if ip_bytes[i as usize] != network_bytes[i as usize] { // 修正：移除了額外的括號
                        return Ok(false);
                    }
                }
                
                // Check remaining bits
                let remainder_bits = prefix_len % 8;
                if remainder_bits > 0 {
                    let byte_idx = full_bytes as usize;
                    let mask = !0u8 << (8 - remainder_bits);
                    
                    if (ip_bytes[byte_idx] & mask) != (network_bytes[byte_idx] & mask) {
                        return Ok(false);
                    }
                }
                
                Ok(true)
            },
            _ => unreachable!(),
        }
    }
}