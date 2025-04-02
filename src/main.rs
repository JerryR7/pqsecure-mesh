use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn, error, Level};

use pqsecure_mesh::{
    Config, Error, Result,
    telemetry::{setup_telemetry, init_logging},
    ca::{create_ca_provider, CaProvider},
    identity::IdentityService,
    policy::{PolicyEngine, PolicyEvaluator, FilePolicyStore},
    controller::SidecarController,
    proxy::{SidecarConfig, MtlsConfig, ProtocolType, PolicyConfig},
};

/// Run mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    /// Sidecar mode
    Sidecar,
    /// Controller mode
    Controller,
    /// API server mode
    ApiServer,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging system
    init_logging()?;
    
    info!("Starting PQSecure Mesh");
    
    // Load configuration
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
    
    // Parse run mode
    let mode = match config.general.mode.as_str() {
        "sidecar" => RunMode::Sidecar,
        "controller" => RunMode::Controller,
        "api_server" => RunMode::ApiServer,
        _ => {
            warn!("Unknown mode: {}, defaulting to sidecar", config.general.mode);
            RunMode::Sidecar
        }
    };
    
    match mode {
        RunMode::Sidecar => {
            // Run single sidecar mode
            info!("Starting in sidecar mode");
            run_sidecar_mode(config).await?;
        },
        RunMode::Controller => {
            // Run controller mode
            info!("Starting in controller mode");
            run_controller_mode(config).await?;
        },
        RunMode::ApiServer => {
            // Run only API server mode
            info!("Starting in API server mode");
            run_api_server_mode(config).await?;
        },
    }
    
    info!("PQSecure Mesh shutting down");
    Ok(())
}

/// Sidecar mode run logic
async fn run_sidecar_mode(config: Arc<Config>) -> Result<()> {
    // Initialize telemetry
    let metrics = setup_telemetry(config.clone())?;
    
    // Create CA client
    let ca_provider = create_ca_provider(config.clone())?;
    
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
    
    // Create sidecar controller
    let controller = SidecarController::new(
        config.clone(),
        identity_provider,
        policy_engine,
        metrics,
    );
    
    // Get sidecar config
    let sidecar_config = SidecarConfig {
        listen_addr: config.proxy.listen_addr.clone(),
        listen_port: config.proxy.listen_port,
        upstream_addr: config.proxy.upstream_addr.clone(),
        upstream_port: config.proxy.upstream_port,
        tenant_id: config.identity.tenant.clone(),
        service_id: config.identity.service.clone(),
        protocol: match config.proxy.protocol.as_str() {
            "http" => ProtocolType::Http,
            "grpc" => ProtocolType::Grpc,
            _ => ProtocolType::Tcp,
        },
        mtls_config: MtlsConfig {
            enable_mtls: config.cert.enable_mtls,
            enable_pqc: config.cert.enable_pqc,
        },
        policy_config: PolicyConfig {
            policy_path: config.policy.policy_path.clone(),
        },
    };
    
    // Start sidecar
    let handle = controller.start_sidecar(sidecar_config).await?;
    
    // Wait for shutdown signal
    wait_for_shutdown_signal().await;
    
    // Stop sidecar
    controller.stop_sidecar(handle).await?;
    
    Ok(())
}

/// Controller mode run logic
async fn run_controller_mode(config: Arc<Config>) -> Result<()> {
    // Initialize telemetry
    let metrics = setup_telemetry(config.clone())?;
    
    // Create API server
    let api_server = pqsecure_mesh::api::create_api_server(config.clone(), metrics.clone())?;
    
    // Start API server
    let api_addr = format!("{}:{}", config.api.listen_addr, config.api.listen_port);
    info!("Starting API server on {}", api_addr);
    
    // Start server and wait for shutdown signal
    tokio::select! {
        result = api_server.serve(api_addr.parse()?) => {
            if let Err(e) = result {
                error!("API server error: {}", e);
                return Err(Error::ApiServerError(e.to_string()));
            }
        },
        _ = wait_for_shutdown_signal() => {
            info!("Received shutdown signal");
        }
    }
    
    Ok(())
}

/// API server mode run logic
async fn run_api_server_mode(config: Arc<Config>) -> Result<()> {
    // Similar to controller mode, but does not start rotation controller
    run_controller_mode(config).await
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

    info!("Received shutdown signal");
}