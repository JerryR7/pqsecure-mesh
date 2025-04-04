use std::sync::Arc;
use tracing_subscriber::{
    fmt::{self, format::{FmtSpan, Format}},
    EnvFilter, Registry,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing::{Level, Subscriber};

use crate::error::Error;
use crate::config::Config;

/// Initialize the logging system
pub fn init_logging(config: &Config) -> Result<(), Error> {
    // Parse log level
    let log_level = match config.general.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    
    // Whether to use JSON format
    let use_json = config.telemetry.structured_logging;
    
    // Create environment filter
    let filter = EnvFilter::from_default_env()
        .add_directive(log_level.into());
    
    // Create formatting layer
    let subscriber = if use_json {
        create_json_subscriber(filter)
    } else {
        create_text_subscriber(filter)
    };
    
    // Set global default
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| Error::Internal(format!("Failed to set global default subscriber: {}", e)))?;
    
    Ok(())
}

/// Create a text-based subscriber
fn create_text_subscriber<S>(filter: EnvFilter) -> impl Subscriber + Send + Sync
where
    S: Subscriber + Send + Sync + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let fmt_layer = fmt::Layer::default()
        .with_target(true)
        .with_thread_ids(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_ansi(true);
    
    Registry::default()
        .with(filter)
        .with(fmt_layer)
}

/// Create a JSON-based subscriber
fn create_json_subscriber<S>(filter: EnvFilter) -> impl Subscriber + Send + Sync
where
    S: Subscriber + Send + Sync + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let fmt_layer = fmt::Layer::default()
        .with_target(true)
        .with_thread_ids(true)
        .with_span_events(FmtSpan::CLOSE)
        .json();
    
    Registry::default()
        .with(filter)
        .with(fmt_layer)
}

/// Create a test logging subscriber
#[cfg(test)]
pub fn init_test_logging() {
    use tracing_subscriber::fmt::TestWriter;
    
    let filter = EnvFilter::from_default_env()
        .add_directive(Level::DEBUG.into());
    
    let fmt_layer = fmt::Layer::default()
        .with_test_writer()
        .with_target(true)
        .with_ansi(false);
    
    Registry::default()
        .with(filter)
        .with(fmt_layer)
        .init();
}