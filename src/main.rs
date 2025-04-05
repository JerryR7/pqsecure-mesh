use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn, error};

mod common;
mod config;
mod identity;
mod crypto;
mod ca;
mod policy;
mod proxy;
mod telemetry;

use common::{Error, Result, ProtocolType};
use config::Settings;
use identity::IdentityService;
use policy::{PolicyEngine, PolicyEvaluator, FilePolicyStore};
use proxy::{SidecarProxy, SidecarConfig, MtlsConfig, ProxyMetrics};

/// Run mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    /// Sidecar mode
    Sidecar,
    /// Controller mode (not implemented in simplified version)
    Controller,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = match Settings::load() {
        Ok(cfg) => {
            Arc::new(cfg)
        },
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            eprintln!("Using default configuration");
            Arc::new(Settings::default())
        }
    };

    // Initialize logging system
    telemetry::init_logging(&config)?;

    info!("Starting PQSecure Mesh");

    // Parse run mode
    let mode = match config.general.mode.as_str() {
        "sidecar" => RunMode::Sidecar,
        "controller" => RunMode::Controller,
        _ => {
            warn!("Unknown mode: {}, defaulting to sidecar", config.general.mode);
            RunMode::Sidecar
        }
    };

    match mode {
        RunMode::Sidecar => {
            // Run in sidecar mode
            info!("Starting in sidecar mode");
            run_sidecar_mode(config).await?;
        },
        RunMode::Controller => {
            // Run in controller mode (not implemented in simplified version)
            info!("Controller mode not implemented in this version");
            return Err(Error::Internal("Controller mode not implemented".into()));
        },
    }

    info!("PQSecure Mesh shutting down");
    Ok(())
}

/// Sidecar mode run logic
async fn run_sidecar_mode(config: Arc<Settings>) -> Result<()> {
    // Create metrics collector
    let metrics = Arc::new(ProxyMetrics::new());

    // Create CA provider
    let ca_provider = ca::create_ca_provider(config.clone())?;

    // Create identity provider
    let identity_provider = Arc::new(IdentityService::new(
        ca_provider,
        config.clone(),
    ));

    // Create policy engine
    let policy_store = Arc::new(FilePolicyStore::new(config.clone()));
    let policy_evaluator = Arc::new(PolicyEvaluator::new());
    let policy_engine = Arc::new(PolicyEngine::new(
        policy_store,
        policy_evaluator,
    ));

    // Create sidecar configuration
    let protocol = match config.proxy.protocol.as_str() {
        "http" => ProtocolType::Http,
        "grpc" => ProtocolType::Grpc,
        _ => {
            warn!("Unknown protocol: {}, defaulting to HTTP", config.proxy.protocol);
            ProtocolType::Http
        }
    };

    let sidecar_config = SidecarConfig {
        listen_addr: config.proxy.listen_addr.clone(),
        listen_port: config.proxy.listen_port,
        upstream_addr: config.proxy.upstream_addr.clone(),
        upstream_port: config.proxy.upstream_port,
        tenant_id: config.identity.tenant.clone(),
        service_id: config.identity.service.clone(),
        protocol,
        mtls_config: MtlsConfig {
            enable_mtls: config.cert.enable_mtls,
            enable_pqc: config.cert.enable_pqc,
        },
    };

    // Create and start sidecar proxy
    let sidecar = SidecarProxy::new(
        sidecar_config,
        identity_provider,
        policy_engine,
        metrics,
    );

    // Start the proxy
    tokio::select! {
        result = sidecar.start() => {
            if let Err(e) = result {
                error!("Sidecar proxy error: {}", e);
                return Err(e);
            }
        },
        _ = wait_for_shutdown_signal() => {
            info!("Received shutdown signal, stopping sidecar");
        }
    }

    Ok(())
}

/// Wait for shutdown signal
async fn wait_for_shutdown_signal() {
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

    info!("Shutdown signal received");
}