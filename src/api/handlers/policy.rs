use axum::Json;
use axum::extract::{State, Query};
use std::sync::Arc;

use crate::api::types::{ApiState, ApiResponse, PolicyRequest};
use crate::error::Error;
use crate::policy::{PolicyEngine, AccessPolicy, FilePolicyStore, PolicyStore};

/// Get policy
pub async fn get_policy(
    State(state): State<ApiState>,
    Query(query): Query<PolicyRequest>,
) -> Json<ApiResponse<AccessPolicy>> {
    // Create policy store
    let policy_store = Arc::new(FilePolicyStore::new(state.config.clone()));
    
    // Get policy for tenant
    match policy_store.get_policy(&query.tenant).await {
        Ok(policy) => Json(ApiResponse::success(policy)),
        Err(e) => Json(ApiResponse::error(format!("Failed to get policy: {}", e))),
    }
}

/// Update policy
pub async fn update_policy(
    State(state): State<ApiState>,
    Json(policy): Json<AccessPolicy>,
) -> Json<ApiResponse<bool>> {
    // Create policy store
    let policy_store = Arc::new(FilePolicyStore::new(state.config.clone()));
    
    // Update policy
    match policy_store.update_policy(policy).await {
        Ok(_) => Json(ApiResponse::success(true)),
        Err(e) => Json(ApiResponse::error(format!("Failed to update policy: {}", e))),
    }
}