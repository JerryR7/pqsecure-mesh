use anyhow::Result;
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize telemetry (logging and metrics)
pub fn init() -> Result<()> {
    // Get log level from environment variable or default to info
    let env_filter = EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| {
        EnvFilter::new("pqsecure_mesh=info,tokio=warn,rustls=warn")
    });

    // Set up a simple log format, removing references to JSON
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(std::io::stdout));

    // Install the subscriber globally
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    debug!("Telemetry initialized");
    Ok(())
}

/// Record a connection attempt
pub fn record_connection_attempt(source: &str, success: bool) {
    if success {
        info!(source = %source, "Connection successful");
    } else {
        info!(source = %source, "Connection failed");
    }
}

/// Record a policy decision
pub fn record_policy_decision(spiffe_id: &str, method: &str, allowed: bool) {
    info!(
        spiffe_id = %spiffe_id,
        method = %method,
        allowed = %allowed,
        "Policy decision"
    );
}

/// Record data transfer
pub fn record_data_transfer(bytes_received: usize, bytes_sent: usize) {
    debug!(
        bytes_received = %bytes_received,
        bytes_sent = %bytes_sent,
        "Data transfer"
    );
}