use crate::common::Error;
use crate::identity::types::SpiffeId;

/// SPIFFE utility functions
pub struct SpiffeUtils;

impl SpiffeUtils {
    /// Check if URI is a valid SPIFFE ID
    pub fn is_valid_spiffe_uri(uri: &str) -> bool {
        if let Ok(url) = url::Url::parse(uri) {
            return url.scheme() == "spiffe" &&
                url.host_str().is_some() &&
                !url.path().is_empty() &&
                url.path() != "/";
        }
        false
    }

    /// Generate DNS SANs for a service
    pub fn generate_dns_sans(service: &str, namespace: &str) -> Vec<String> {
        vec![
            format!("{}", service),
            format!("{}.{}", service, namespace),
            format!("{}.{}.svc", service, namespace),
            format!("{}.{}.svc.cluster.local", service, namespace),
        ]
    }

    /// Extract SPIFFE ID from certificate
    pub fn extract_from_certificate(cert_pem: &str) -> Result<Option<SpiffeId>, Error> {
        // Try to match URI:spiffe:// format
        if let Some(start) = cert_pem.find("URI:spiffe://") {
            let uri_part = &cert_pem[start + 4..]; // Skip "URI:"
            if let Some(end) = uri_part.find('"') {
                let uri = &uri_part[..end];
                return Ok(Some(SpiffeId::from_uri(uri)?));
            }
        }

        // Try to match spiffe:// format
        if let Some(start) = cert_pem.find("spiffe://") {
            let uri_part = &cert_pem[start..];
            if let Some(end) = uri_part.find('"') {
                let uri = &uri_part[..end];
                return Ok(Some(SpiffeId::from_uri(uri)?));
            }
        }

        Ok(None)
    }
}