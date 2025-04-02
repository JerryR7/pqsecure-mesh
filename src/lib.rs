//! PQSecure Mesh - Post-Quantum Secure Zero Trust Proxy for Microservices
//!
//! Provides a PQC-protected service mesh based on SPIFFE identity

// Public main modules
pub mod config;
pub mod error;
pub mod types;

pub mod identity;
pub mod crypto;
pub mod proxy;
pub mod policy;
pub mod ca;
pub mod api;
pub mod controller;
pub mod telemetry;
pub mod utils;

// Public key types
pub use crate::config::Config;
pub use crate::error::Error;
pub use crate::types::{Result, ProtocolType};
pub use crate::identity::{ServiceIdentity, SpiffeId, IdentityProvider};
pub use crate::policy::{AccessPolicy, PolicyEngine};
pub use crate::proxy::SidecarProxy;
pub use crate::controller::SidecarController;