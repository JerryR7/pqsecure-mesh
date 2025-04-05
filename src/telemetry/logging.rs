use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    EnvFilter,
    Registry,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use tracing::Level;

use crate::common::{Error, Result};
use crate::config::Settings;

/// Initialize the logging system
pub fn init_logging(config: &Settings) -> Result<()> {
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
    if use_json {
        let fmt_layer = fmt::Layer::default()
            .with_target(true)
            .with_span_events(FmtSpan::CLOSE)
            .json();

        Registry::default()
            .with(filter)
            .with(fmt_layer)
            .init();
    } else {
        let fmt_layer = fmt::Layer::default()
            .with_target(true)
            .with_span_events(FmtSpan::CLOSE);

        Registry::default()
            .with(filter)
            .with(fmt_layer)
            .init();
    }

    Ok(())
}