use async_trait::async_trait;
use crate::error::Error;
use crate::identity::types::{ServiceIdentity, IdentityRequest, IdentityStatus};

/// Identity provider trait
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Request new identity
    async fn provision_identity(&self, tenant: &str, service: &str) -> Result<ServiceIdentity, Error>;
    
    /// Request new identity (with full parameters)
    async fn provision_identity_with_params(&self, request: IdentityRequest) -> Result<ServiceIdentity, Error>;
    
    /// Rotate existing identity
    async fn rotate_identity(&self, identity: &ServiceIdentity) -> Result<ServiceIdentity, Error>;
    
    /// Revoke identity
    async fn revoke_identity(&self, identity: &ServiceIdentity, reason: &str) -> Result<bool, Error>;
    
    /// Check identity status
    async fn check_identity_status(&self, identity: &ServiceIdentity) -> Result<IdentityStatus, Error>;
    
    /// Check specified SPIFFE ID status
    async fn check_spiffe_id_status(&self, spiffe_id: &str) -> Result<IdentityStatus, Error>;
    
    /// Load existing identity by SPIFFE ID
    async fn load_identity(&self, spiffe_id: &str) -> Result<Option<ServiceIdentity>, Error>;
    
    /// Save identity
    async fn save_identity(&self, identity: &ServiceIdentity) -> Result<(), Error>;
}