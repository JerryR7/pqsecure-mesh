use std::sync::Arc;
use std::error::Error;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::service::CertService;

/// API 伺服器狀態
#[derive(Clone)]
pub struct ApiState {
    /// 憑證服務
    pub cert_service: Arc<CertService>,
    /// 應用程序配置
    pub config: Arc<Config>,
}

/// API 錯誤類型
pub enum ApiError {
    /// 請求資料無效
    InvalidRequest(String),
    /// 憑證服務錯誤
    CertificateError(String),
    /// 內部伺服器錯誤
    InternalError(String),
    /// 找不到資源
    NotFound(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::CertificateError(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };

        let body = Json(serde_json::json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

impl From<Box<dyn Error + Send + Sync>> for ApiError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        ApiError::InternalError(err.to_string())
    }
}

/// 憑證請求的資料結構
#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    /// 服務名稱
    pub service_name: String,
    /// 命名空間
    pub namespace: String,
    /// 額外的 DNS 名稱（可選）
    #[serde(default)]
    pub dns_names: Vec<String>,
    /// 額外的 IP 位址（可選）
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    /// 是否要求後量子加密（可選）
    #[serde(default)]
    pub post_quantum: Option<bool>,
    /// 是否自動儲存憑證（可選）
    #[serde(default)]
    pub save_certificate: Option<bool>,
    /// CSR（可選）
    pub csr: Option<String>,
}

/// 憑證回應的資料結構
#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    /// 身份名稱
    pub common_name: String,
    /// 序號
    pub serial: String,
    /// 憑證內容
    pub certificate: String,
    /// 私鑰內容
    pub private_key: String,
    /// 憑證鏈
    pub certificate_chain: Option<String>,
    /// 指紋
    pub fingerprint: String,
    /// 簽名演算法
    pub signature_algorithm: String,
    /// 是否為後量子加密
    pub is_post_quantum: bool,
    /// 儲存路徑（如果有儲存）
    pub saved_path: Option<String>,
}

/// 撤銷請求的資料結構
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// 憑證序號
    pub serial: String,
    /// 撤銷原因
    pub reason: String,
}

/// 建立 API 路由
pub fn create_api_router(state: ApiState) -> Router {
    Router::new()
        .route("/certs/request", post(request_certificate))
        .route("/certs/revoke", post(revoke_certificate))
        .route("/certs/status/:serial", get(check_certificate_status))
        .route("/health", get(health_check))
        .with_state(state)
}

/// 健康檢查端點
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// 請求憑證端點
async fn request_certificate(
    State(state): State<ApiState>,
    Json(req): Json<CertificateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 驗證請求
    if req.service_name.is_empty() {
        return Err(ApiError::InvalidRequest("Service name is required".into()));
    }
    if req.namespace.is_empty() {
        return Err(ApiError::InvalidRequest("Namespace is required".into()));
    }

    // 從服務中請求憑證
    let cert = state.cert_service.request_certificate(&req.service_name, &req.namespace).await
        .map_err(|e| ApiError::CertificateError(format!("Failed to request certificate: {}", e)))?;

    // 準備回應
    let response = CertificateResponse {
        common_name: cert.common_name,
        serial: cert.serial,
        certificate: cert.cert_pem,
        private_key: cert.key_pem,
        certificate_chain: cert.chain_pem,
        fingerprint: cert.fingerprint,
        signature_algorithm: cert.signature_algorithm,
        is_post_quantum: cert.is_post_quantum,
        saved_path: Some(format!("{}/{}", req.namespace, req.service_name)),
    };

    Ok(Json(response))
}

/// 撤銷憑證端點
async fn revoke_certificate(
    State(state): State<ApiState>,
    Json(req): Json<RevokeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 驗證請求
    if req.serial.is_empty() {
        return Err(ApiError::InvalidRequest("Certificate serial is required".into()));
    }

    // 從服務中撤銷憑證
    let success = state.cert_service.revoke_certificate(&req.serial, &req.reason).await
        .map_err(|e| ApiError::CertificateError(format!("Failed to revoke certificate: {}", e)))?;

    if success {
        Ok(Json(serde_json::json!({
            "status": "revoked",
            "serial": req.serial
        })))
    } else {
        Err(ApiError::CertificateError("Failed to revoke certificate".into()))
    }
}

/// 檢查憑證狀態端點
async fn check_certificate_status(
    State(state): State<ApiState>,
    Path(serial): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // 驗證請求
    if serial.is_empty() {
        return Err(ApiError::InvalidRequest("Certificate serial is required".into()));
    }

    // 從服務中檢查憑證狀態
    let status = state.cert_service.check_certificate_status(&serial).await
        .map_err(|e| ApiError::CertificateError(format!("Failed to check certificate status: {}", e)))?;

    // 將狀態轉換為 JSON 回應
    let status_json = match status {
        crate::domain::CertStatus::Valid => serde_json::json!({
            "status": "valid",
            "serial": serial
        }),
        crate::domain::CertStatus::Revoked { reason, revoked_at } => {
            let timestamp = revoked_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            serde_json::json!({
                "status": "revoked",
                "serial": serial,
                "reason": reason,
                "revoked_at": timestamp
            })
        },
        crate::domain::CertStatus::Expired { expired_at } => {
            let timestamp = expired_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            serde_json::json!({
                "status": "expired",
                "serial": serial,
                "expired_at": timestamp
            })
        },
        crate::domain::CertStatus::Unknown => serde_json::json!({
            "status": "unknown",
            "serial": serial
        }),
    };

    Ok(Json(status_json))
}