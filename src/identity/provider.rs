use async_trait::async_trait;
use crate::common::Result;
use crate::identity::types::{ServiceIdentity, IdentityRequest, IdentityStatus};

/// Identity provider trait
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Request new identity
    async fn provision_identity(&self, tenant: &str, service: &str) -> Result<ServiceIdentity>;

    /// Request new identity with full parameters
    async fn provision_identity_with_params(&self, request: IdentityRequest) -> Result<ServiceIdentity>;

    /// Rotate existing identity
    async fn rotate_identity(&self, identity: &ServiceIdentity) -> Result<ServiceIdentity>;

    /// Revoke identity
    async fn revoke_identity(&self, identity: &ServiceIdentity, reason: &str) -> Result<bool>;

    /// Check identity status
    async fn check_identity_status(&self, identity: &ServiceIdentity) -> Result<IdentityStatus>;

    /// Load existing identity by SPIFFE ID
    async fn load_identity(&self, spiffe_id: &str) -> Result<Option<ServiceIdentity>>;

    /// Save identity
    async fn save_identity(&self, identity: &ServiceIdentity) -> Result<()>;
}