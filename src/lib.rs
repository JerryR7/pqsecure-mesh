//! PQSecure Mesh - Post-Quantum Secure Zero Trust Proxy for Microservices
//!
//! Provides a PQC-protected service mesh based on SPIFFE identity

// Foundational layer
pub mod error;
pub mod types;
pub mod utils;
pub mod telemetry;

// Core layer
pub mod crypto;
pub mod identity;
pub mod ca;

// Application layer
pub mod policy;
pub mod proxy;
pub mod controller;

// Interface layer
pub mod api;

// Public key types
pub use crate::error::Error;
pub use crate::types::{Result, ProtocolType};
pub use crate::identity::{ServiceIdentity, SpiffeId, IdentityProvider};
pub use crate::policy::{AccessPolicy, PolicyEngine};
pub use crate::proxy::SidecarProxy;
pub use crate::controller::SidecarController;
pub use crate::telemetry::metrics::MetricsCollector;