mod config;
mod domain;
mod service;
mod infra;
mod interface;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::signal;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::Config;
use crate::domain::CertProvider;
use crate::service::CertService;
use crate::infra::{SmallstepClient, MockSmallstepClient};
use crate::interface::{create_api_router, ApiState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日誌系統
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting PQSecure Mesh");

    // 載入配置
    let config = match Config::load() {
        Ok(cfg) => {
            info!("Configuration loaded successfully");
            Arc::new(cfg)
        },
        Err(e) => {
            warn!("Failed to load configuration: {}", e);
            warn!("Using default configuration");
            Arc::new(Config::default())
        }
    };

    // 初始化憑證提供者
    let cert_provider: Arc<dyn CertProvider> = match config.cert.ca_type.as_str() {
        "smallstep" => {
            info!("Using Smallstep CA provider");
            match SmallstepClient::new(config.clone()) {
                Ok(client) => Arc::new(client),
                Err(e) => {
                    error!("Failed to initialize Smallstep client: {}", e);
                    info!("Falling back to mock provider for development");
                    Arc::new(MockSmallstepClient::new(config.clone()))
                }
            }
        },
        _ => {
            info!("Using mock CA provider for development");
            Arc::new(MockSmallstepClient::new(config.clone()))
        }
    };

    // 初始化憑證服務
    let cert_service = Arc::new(CertService::new(cert_provider, config.clone()));

    // 建立 API 伺服器狀態
    let api_state = ApiState {
        cert_service: cert_service.clone(),
        config: config.clone(),
    };

    // 建立 API 路由
    let app = create_api_router(api_state);

    // 獲取 API 伺服器位址
    let addr: SocketAddr = config.api_address().parse()?;

    // 啟動 API 伺服器
    info!("Starting REST API server at {}", addr);

    // 使用 axum 啟動 HTTP 伺服器
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("PQSecure Mesh shutting down");
    Ok(())
}

/// 等待中斷信號
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Received shutdown signal");
}