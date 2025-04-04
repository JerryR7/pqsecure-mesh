use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use tokio::fs;
use tracing::{info, warn, error, debug};
use serde_json;

use crate::config::Config;
use crate::error::Error;
use crate::ca::CaProvider;
use crate::identity::{
    provider::IdentityProvider,
    types::{ServiceIdentity, SpiffeId, IdentityRequest, IdentityStatus},
    spiffe::SpiffeUtils,
};

/// Provides identity management services
pub struct IdentityService {
    /// CA provider
    ca_provider: Arc<dyn CaProvider>,
    /// Configuration
    config: Arc<Config>,
    /// Identity storage directory
    identity_dir: PathBuf,
}

impl IdentityService {
    /// Creates a new identity service
    pub fn new(ca_provider: Arc<dyn CaProvider>, config: Arc<Config>) -> Self {
        let identity_dir = config.identity.identity_dir.clone();
        
        // Ensure the identity directory exists
        std::fs::create_dir_all(&identity_dir).unwrap_or_else(|e| {
            warn!("Failed to create identity directory: {}", e);
        });
        
        Self {
            ca_provider,
            config,
            identity_dir,
        }
    }
    
    /// Generates a list of DNS names for the request
    fn generate_dns_names(&self, service: &str, namespace: &str) -> Vec<String> {
        SpiffeUtils::generate_dns_sans(service, namespace)
    }
    
    /// Generates a list of corresponding IP addresses (if any)
    fn generate_ip_addresses(&self) -> Vec<String> {
        // Typically obtained from configuration or environment, simplified here as an empty list
        vec![]
    }
    
    /// Creates the identity storage path
    fn get_identity_path(&self, tenant: &str, service: &str) -> PathBuf {
        self.identity_dir.join(tenant).join(service).join("identity.json")
    }
    
    /// Creates a new identity request
    fn create_identity_request(&self, tenant: &str, service: &str) -> IdentityRequest {
        IdentityRequest {
            service_name: service.to_string(),
            namespace: tenant.to_string(),
            dns_names: self.generate_dns_names(service, tenant),
            ip_addresses: self.generate_ip_addresses(),
            request_pqc: self.config.cert.enable_pqc,
            csr: None,
        }
    }
    
    /// Saves the identity to a file
    async fn save_identity_to_file(&self, identity: &ServiceIdentity) -> Result<(), Error> {
        let tenant = &identity.spiffe_id.tenant;
        let service = &identity.spiffe_id.service;
        let path = self.get_identity_path(tenant, service);
        
        // Ensure the directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        // Serialize the identity
        let json = serde_json::to_string_pretty(identity)
            .map_err(|e| Error::Serialization(format!("Failed to serialize identity: {}", e)))?;
        
        // Write to the file
        fs::write(&path, json).await
            .map_err(|e| Error::Io(e))
    }
    
    /// Loads the identity from a file
    async fn load_identity_from_file(&self, tenant: &str, service: &str) -> Result<Option<ServiceIdentity>, Error> {
        let path = self.get_identity_path(tenant, service);
        
        // Check if the file exists
        if !path.exists() {
            return Ok(None);
        }
        
        // Read the file
        let json = fs::read_to_string(&path).await
            .map_err(|e| Error::Io(e))?;
        
        // Deserialize the identity
        let identity: ServiceIdentity = serde_json::from_str(&json)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize identity: {}", e)))?;
        
        Ok(Some(identity))
    }
}

#[async_trait]
impl IdentityProvider for IdentityService {
    async fn provision_identity(&self, tenant: &str, service: &str) -> Result<ServiceIdentity, Error> {
        info!("Provisioning identity for service {} in tenant {}", service, tenant);
        
        // Check if the identity already exists
        if let Ok(Some(existing)) = self.load_identity_from_file(tenant, service).await {
            // Check if the identity is valid
            if existing.is_valid() {
                // Check if rotation is needed
                if !existing.needs_rotation(self.config.identity.renew_threshold_pct) {
                    debug!("Using existing valid identity for {}/{}", tenant, service);
                    return Ok(existing);
                }
                
                // Rotation is needed
                info!("Identity for {}/{} needs rotation", tenant, service);
                return self.rotate_identity(&existing).await;
            }
            
            // Identity is invalid, request a new one
            info!("Existing identity for {}/{} is invalid, requesting new one", tenant, service);
        }
        
        // Create the request
        let request = self.create_identity_request(tenant, service);
        self.provision_identity_with_params(request).await
    }
    
    async fn provision_identity_with_params(&self, request: IdentityRequest) -> Result<ServiceIdentity, Error> {
        debug!("Requesting new certificate for {}/{}", request.namespace, request.service_name);
        
        // Create SPIFFE ID
        let spiffe_id = SpiffeId::new(&request.namespace, &request.service_name);
        
        // Request the certificate
        let cert_response = self.ca_provider.request_certificate(&request).await?;
        
        // Build the identity
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.config.cert.cert_duration_hours * 3600);
        
        let identity = ServiceIdentity {
            spiffe_id,
            cert_pem: cert_response.certificate,
            key_pem: cert_response.private_key,
            chain_pem: cert_response.certificate_chain,
            fingerprint: cert_response.fingerprint,
            issued_at: now,
            expires_at,
            signature_algorithm: cert_response.signature_algorithm,
            is_post_quantum: cert_response.is_post_quantum,
            serial: cert_response.serial,
        };
        
        // Save the identity
        self.save_identity_to_file(&identity).await?;
        
        info!("Successfully provisioned identity for {}/{}", 
              request.namespace, request.service_name);
        
        Ok(identity)
    }
    
    async fn rotate_identity(&self, identity: &ServiceIdentity) -> Result<ServiceIdentity, Error> {
        info!("Rotating identity for {}/{}", 
              identity.spiffe_id.tenant, identity.spiffe_id.service);
        
        // Create a new request
        let request = self.create_identity_request(
            &identity.spiffe_id.tenant, 
            &identity.spiffe_id.service
        );
        
        // Request a new certificate
        let new_identity = self.provision_identity_with_params(request).await?;
        
        info!("Successfully rotated identity for {}/{}", 
              identity.spiffe_id.tenant, identity.spiffe_id.service);
        
        Ok(new_identity)
    }
    
    async fn revoke_identity(&self, identity: &ServiceIdentity, reason: &str) -> Result<bool, Error> {
        info!("Revoking identity for {}/{}: {}",
              identity.spiffe_id.tenant, identity.spiffe_id.service, reason);
        
        // Call CA to revoke the certificate
        let result = self.ca_provider.revoke_certificate(&identity.serial, reason).await?;
        
        if result {
            // Delete the local file
            let path = self.get_identity_path(&identity.spiffe_id.tenant, &identity.spiffe_id.service);
            if path.exists() {
                if let Err(e) = fs::remove_file(&path).await {
                    warn!("Failed to remove revoked identity file: {}", e);
                }
            }
            
            info!("Successfully revoked identity for {}/{}", 
                  identity.spiffe_id.tenant, identity.spiffe_id.service);
        } else {
            warn!("Failed to revoke identity for {}/{}", 
                  identity.spiffe_id.tenant, identity.spiffe_id.service);
        }
        
        Ok(result)
    }
    
    async fn check_identity_status(&self, identity: &ServiceIdentity) -> Result<IdentityStatus, Error> {
        // Check local status
        let status = identity.status();
        
        // If the local status is valid, also check if the CA has revoked it
        if status == IdentityStatus::Valid {
            match self.ca_provider.check_certificate_status(&identity.serial).await {
                Ok(ca_status) => {
                    use crate::ca::types::CertificateStatus;
                    match ca_status {
                        CertificateStatus::Valid => Ok(IdentityStatus::Valid),
                        CertificateStatus::Revoked { .. } => Ok(IdentityStatus::Revoked),
                        CertificateStatus::Expired { .. } => Ok(IdentityStatus::Expired),
                        CertificateStatus::Unknown => Ok(IdentityStatus::Unknown),
                    }
                }
                Err(_) => {
                    // If unable to connect to CA, use local status
                    warn!("Cannot connect to CA, using local status for {}/{}", 
                          identity.spiffe_id.tenant, identity.spiffe_id.service);
                    Ok(status)
                }
            }
        } else {
            // If the local status is already invalid, return it directly
            Ok(status)
        }
    }
    
    async fn check_spiffe_id_status(&self, spiffe_id: &str) -> Result<IdentityStatus, Error> {
        // Parse SPIFFE ID
        let id = SpiffeId::from_uri(spiffe_id)?;
        
        // Try to load the identity
        match self.load_identity_from_file(&id.tenant, &id.service).await? {
            Some(identity) => self.check_identity_status(&identity).await,
            None => Ok(IdentityStatus::Unknown),
        }
    }
    
    async fn load_identity(&self, spiffe_id: &str) -> Result<Option<ServiceIdentity>, Error> {
        // Parse SPIFFE ID
        let id = SpiffeId::from_uri(spiffe_id)?;
        
        // Load the identity
        self.load_identity_from_file(&id.tenant, &id.service).await
    }
    
    async fn save_identity(&self, identity: &ServiceIdentity) -> Result<(), Error> {
        self.save_identity_to_file(identity).await
    }
}