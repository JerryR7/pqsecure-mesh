use anyhow::Result;
use pqsecure_mesh::{
    ca::SmallstepClient,
    config::load_config,
    crypto::build_tls_config,
    identity::SpiffeVerifier,
    policy::YamlPolicyEngine,
    proxy::{
        handler::DefaultConnectionHandler,
        pqc_acceptor::PqcAcceptor,
        protocol::{grpc::GrpcHandler, http_tls::HttpHandler, raw_tcp::TcpHandler},
    },
    telemetry,
};
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize telemetry first
    telemetry::init()?;
    info!("Starting PQSecure Mesh...");

    // 2. Load configuration
    let config = load_config()?;
    info!("Configuration loaded successfully");

    // 3. Create directories for certificates if they don't exist
    std::fs::create_dir_all(std::path::Path::new(&config.ca.cert_path).parent().unwrap_or(std::path::Path::new("./certs"))).ok();

    // 4. Initialize Smallstep CA client and fetch certificates
    let ca_client = SmallstepClient::new(&config.ca)?;
    let (cert_chain, private_key) = ca_client.load_or_request_cert().await?;
    info!("Certificate loaded successfully");

    // 5. Initialize policy engine
    let policy_engine = Arc::new(YamlPolicyEngine::from_path(&config.policy.path)?);
    info!("Policy engine initialized with rules from {}", config.policy.path.display());

    // 6. Setup SPIFFE verifier
    let spiffe_verifier = Arc::new(SpiffeVerifier::new(config.identity.trusted_domain.clone()));

    // 7. Setup TLS configuration
    let tls_config = build_tls_config(cert_chain, private_key, spiffe_verifier.clone())?;
    info!("TLS configuration built successfully");

    // 8. Setup protocol handlers based on config
    let mut handlers = Vec::new();
    if config.proxy.protocols.tcp {
        let tcp_handler = TcpHandler::new(
            config.proxy.backend.clone(),
            policy_engine.clone(),
            spiffe_verifier.clone(),
        )?;
        handlers.push(Arc::new(tcp_handler) as Arc<dyn DefaultConnectionHandler>);
        info!("TCP protocol handler initialized");
    }

    if config.proxy.protocols.http {
        let http_handler = HttpHandler::new(
            config.proxy.backend.clone(),
            policy_engine.clone(),
            spiffe_verifier.clone(),
        )?;
        handlers.push(Arc::new(http_handler) as Arc<dyn DefaultConnectionHandler>);
        info!("HTTP protocol handler initialized");
    }

    if config.proxy.protocols.grpc {
        let grpc_handler = GrpcHandler::new(
            config.proxy.backend.clone(),
            policy_engine.clone(),
            spiffe_verifier.clone(),
        )?;
        handlers.push(Arc::new(grpc_handler) as Arc<dyn DefaultConnectionHandler>);
        info!("gRPC protocol handler initialized");
    }

    // 9. Create connection acceptor
    let acceptor = PqcAcceptor::new(
        config.proxy.listen_addr.to_string(),
        tls_config,
        handlers,
    )?;

    // 10. Start the proxy
    let proxy_task = tokio::spawn(async move {
        if let Err(e) = acceptor.run().await {
            error!("Proxy error: {}", e);
        }
    });

    // 11. Wait for shutdown signal
    info!("PQSecure Mesh started successfully and listening on {}", config.proxy.listen_addr);
    signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping PQSecure Mesh...");

    // Proper cleanup before exit
    proxy_task.abort();
    info!("PQSecure Mesh stopped successfully");

    Ok(())
}