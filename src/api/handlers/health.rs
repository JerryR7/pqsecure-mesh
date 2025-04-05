use axum::Json;
use axum::extract::State;
use std::time::{Duration, SystemTime};

use crate::api::types::{ApiState, ApiResponse, HealthResponse};
use crate::error::Error;

/// Health check handler
pub async fn health_check(
    State(state): State<ApiState>,
) -> Json<ApiResponse<HealthResponse>> {
    // Get uptime
    let uptime = match std::time::UNIX_EPOCH.elapsed() {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    };
    
    // Create health response
    let health = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime,
    };
    
    Json(ApiResponse::success(health))
}

// src/api/handlers/health.rs
// ... 現有代碼 ...

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;
    
    #[tokio::test]
    async fn test_health_check() {
        // 設置模擬狀態
        let state = ApiState {
            config: Arc::new(Config::default()),
            metrics: Arc::new(ProxyMetrics::new(true)),
        };
        
        // 建立測試路由
        let app = Router::new()
            .route("/health", get(health_check))
            .with_state(state);
            
        // 創建測試請求
        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
            
        // 驗證結果
        assert_eq!(response.status(), StatusCode::OK);
        
        // 解析並驗證響應內容
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let api_response: ApiResponse<HealthResponse> = serde_json::from_slice(&body).unwrap();
        
        assert!(api_response.success);
        assert!(api_response.data.is_some());
        assert_eq!(api_response.data.unwrap().status, "ok");
    }
}