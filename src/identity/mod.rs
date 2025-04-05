pub mod types;
pub mod provider;
pub mod service;
pub mod spiffe;

// Re-export key types
pub use types::{ServiceIdentity, SpiffeId, IdentityRequest, IdentityStatus};
pub use provider::IdentityProvider;
pub use service::IdentityService;