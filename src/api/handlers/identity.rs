use axum::Json;
use axum::extract::State;
use std::sync::Arc;

use crate::api::types::{ApiState, ApiResponse, IdentityRequest, IdentityResponse, RevokeRequest, CheckRequest, CheckResponse};
use crate::error::Error;
use crate::identity::{IdentityProvider, ServiceIdentity, SpiffeId, IdentityRequest as ServiceIdentityRequest};
use crate::ca::{create_ca_provider, CaProvider};
use crate::identity::service::IdentityService;

/// Request a new identity
pub async fn request_identity(
    State(state): State<ApiState>,
    Json(request): Json<IdentityRequest>,
) -> Json<ApiResponse<IdentityResponse>> {
    // Create CA provider
    let ca_provider = match create_ca_provider(state.config.clone()) {
        Ok(provider) => provider,
        Err(e) => {
            return Json(ApiResponse::error(format!("Failed to create CA provider: {}", e)));
        }
    };
    
    // Create identity provider
    let identity_provider = Arc::new(IdentityService::new(
        ca_provider,
        state.config.clone(),
    ));
    
    // Create identity request
    let service_request = ServiceIdentityRequest {
        service_name: request.service_name.clone(),
        namespace: request.namespace.clone(),
        dns_names: request.dns_names.clone(),
        ip_addresses: request.ip_addresses.clone(),
        request_pqc: request.pqc_enabled,
        csr: None,
    };
    
    // Request identity
    match identity_provider.provision_identity_with_params(service_request).await {
        Ok(identity) => Json(ApiResponse::success(IdentityResponse::from(identity))),
        Err(e) => Json(ApiResponse::error(format!("Failed to provision identity: {}", e))),
    }
}

/// Revoke an identity
pub async fn revoke_identity(
    State(state): State<ApiState>,
    Json(request): Json<RevokeRequest>,
) -> Json<ApiResponse<bool>> {
    // Create CA provider
    let ca_provider = match create_ca_provider(state.config.clone()) {
        Ok(provider) => provider,
        Err(e) => {
            return Json(ApiResponse::error(format!("Failed to create CA provider: {}", e)));
        }
    };
    
    // Create identity provider
    let identity_provider = Arc::new(IdentityService::new(
        ca_provider,
        state.config.clone(),
    ));
    
    // Load identity
    let identity = match identity_provider.load_identity(&request.spiffe_id).await {
        Ok(Some(identity)) => identity,
        Ok(None) => {
            return Json(ApiResponse::error(format!("Identity not found: {}", request.spiffe_id)));
        },
        Err(e) => {
            return Json(ApiResponse::error(format!("Failed to load identity: {}", e)));
        }
    };
    
    // Revoke identity
    match identity_provider.revoke_identity(&identity, &request.reason).await {
        Ok(true) => Json(ApiResponse::success(true)),
        Ok(false) => Json(ApiResponse::error("Failed to revoke identity")),
        Err(e) => Json(ApiResponse::error(format!("Failed to revoke identity: {}", e))),
    }
}

/// Check identity status
pub async fn check_identity(
    State(state): State<ApiState>,
    Json(request): Json<CheckRequest>,
) -> Json<ApiResponse<CheckResponse>> {
    // Create CA provider
    let ca_provider = match create_ca_provider(state.config.clone()) {
        Ok(provider) => provider,
        Err(e) => {
            return Json(ApiResponse::error(format!("Failed to create CA provider: {}", e)));
        }
    };
    
    // Create identity provider
    let identity_provider = Arc::new(IdentityService::new(
        ca_provider,
        state.config.clone(),
    ));
    
    // Check identity status
    match identity_provider.check_spiffe_id_status(&request.spiffe_id).await {
        Ok(status) => {
            let response = if let Ok(spiffe_id) = SpiffeId::from_uri(&request.spiffe_id) {
                // Try to load identity to get more details
                if let Ok(Some(identity)) = identity_provider.load_identity(&request.spiffe_id).await {
                    CheckResponse {
                        spiffe_id: request.spiffe_id,
                        status,
                        expires_at: Some(chrono::DateTime::<chrono::Utc>::from(identity.expires_at)),
                        serial: Some(identity.serial),
                    }
                } else {
                    CheckResponse {
                        spiffe_id: request.spiffe_id,
                        status,
                        expires_at: None,
                        serial: None,
                    }
                }
            } else {
                CheckResponse {
                    spiffe_id: request.spiffe_id,
                    status,
                    expires_at: None,
                    serial: None,
                }
            };
            
            Json(ApiResponse::success(response))
        },
        Err(e) => Json(ApiResponse::error(format!("Failed to check identity status: {}", e))),
    }
}