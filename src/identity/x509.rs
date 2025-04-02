use std::collections::HashMap;
use crate::identity::types::SpiffeId;
use crate::error::Error;

/// SPIFFE utility functions and constants
pub struct SpiffeUtils;

impl SpiffeUtils {
    /// SPIFFE URI scheme
    pub const SCHEME: &'static str = "spiffe";
    
    /// Check if URI is a valid SPIFFE ID
    pub fn is_valid_spiffe_uri(uri: &str) -> bool {
        if let Ok(url) = url::Url::parse(uri) {
            return url.scheme() == Self::SCHEME && 
                   url.host_str().is_some() && 
                   !url.path().is_empty() && 
                   url.path() != "/";
        }
        false
    }
    
    /// Extract tenant from SPIFFE ID
    pub fn extract_tenant(uri: &str) -> Result<String, Error> {
        let spiffe_id = SpiffeId::from_uri(uri)?;
        Ok(spiffe_id.tenant)
    }
    
    /// Extract service from SPIFFE ID
    pub fn extract_service(uri: &str) -> Result<String, Error> {
        let spiffe_id = SpiffeId::from_uri(uri)?;
        Ok(spiffe_id.service)
    }
    
    /// Encode SPIFFE ID to X.509 SAN
    pub fn encode_to_san(spiffe_id: &SpiffeId) -> Result<String, Error> {
        Ok(format!("URI:{}", spiffe_id.uri))
    }
    
    /// Decode SPIFFE ID from X.509 SAN
    pub fn decode_from_san(san: &str) -> Result<SpiffeId, Error> {
        if san.starts_with("URI:") {
            let uri = &san[4..];
            SpiffeId::from_uri(uri)
        } else {
            Err(Error::InvalidSpiffeId(format!("Invalid SAN format: {}", san)))
        }
    }
    
    /// 從 URI 清單中提取 SPIFFE ID 
    pub fn extract_from_uri_list(uris: &[String]) -> Result<Option<SpiffeId>, Error> {
        for uri in uris {
            if uri.starts_with("URI:spiffe://") || uri.starts_with("spiffe://") {
                let clean_uri = uri.strip_prefix("URI:").unwrap_or(uri);
                return Ok(Some(SpiffeId::from_uri(clean_uri)?));
            }
        }
        Ok(None)
    }
    
    /// 生成 SPIFFE ID 路徑
    pub fn generate_path(tenant: &str, service: &str) -> String {
        format!("{}/{}", tenant, service)
    }
    
    /// 生成多個 DNS SANs
    pub fn generate_dns_sans(service: &str, namespace: &str) -> Vec<String> {
        vec![
            format!("{}", service),
            format!("{}.{}", service, namespace),
            format!("{}.{}.svc", service, namespace),
            format!("{}.{}.svc.cluster.local", service, namespace),
        ]
    }
    
    /// 從憑證中提取 SPIFFE ID
    pub fn extract_from_certificate(cert_pem: &str) -> Result<Option<SpiffeId>, Error> {
        // 注意：這是一個簡化的實現，實際應該使用 X.509 解析庫
        // 目前我們只檢查 PEM 內容中的 SPIFFE ID 字符串
        
        // 嘗試匹配 URI:spiffe:// 格式
        if let Some(start) = cert_pem.find("URI:spiffe://") {
            let uri_part = &cert_pem[start + 4..]; // 跳過 "URI:"
            if let Some(end) = uri_part.find('"') {
                let uri = &uri_part[..end];
                return Ok(Some(SpiffeId::from_uri(uri)?));
            }
        }
        
        // 嘗試匹配 spiffe:// 格式
        if let Some(start) = cert_pem.find("spiffe://") {
            let uri_part = &cert_pem[start..];
            if let Some(end) = uri_part.find('"') {
                let uri = &uri_part[..end];
                return Ok(Some(SpiffeId::from_uri(uri)?));
            }
        }
        
        Ok(None)
    }
    
    /// 驗證 SPIFFE ID 是否屬於指定租戶
    pub fn validate_tenant_access(spiffe_id: &SpiffeId, allowed_tenant: &str) -> bool {
        if allowed_tenant == "*" {
            return true;
        }
        spiffe_id.tenant == allowed_tenant
    }
    
    /// 驗證 SPIFFE ID 是否屬於指定服務
    pub fn validate_service_access(spiffe_id: &SpiffeId, allowed_service: &str) -> bool {
        if allowed_service == "*" {
            return true;
        }
        spiffe_id.service == allowed_service
    }
    
    /// 驗證 SPIFFE ID 格式
    pub fn validate_format(uri: &str) -> bool {
        Self::is_valid_spiffe_uri(uri)
    }
}