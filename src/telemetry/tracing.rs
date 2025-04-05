use std::sync::Arc;
use opentelemetry::{
    sdk::{trace, Resource},
    trace::TracerProvider as _,
};
use tracing_subscriber::{layer::SubscriberExt, prelude::*};

use crate::error::Error;
use crate::config::Config;

/// Initialize distributed tracing
pub fn init_tracing(config: &Config) -> Result<(), Error> {
    // Check if tracing is enabled
    if !config.telemetry.enable_tracing {
        return Ok(());
    }

    // Get the tracing endpoint
    let endpoint = match &config.telemetry.tracing_endpoint {
        Some(endpoint) => endpoint.clone(),
        None => return Ok(()), // No endpoint, do not enable tracing
    };

    // Create and install tracer
    let tracer = init_jaeger_tracer(&config.general.app_name, &endpoint, config.telemetry.tracing_sampling_rate)?;

    // Create OpenTelemetry tracing layer
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    // Get the current subscriber
    let subscriber = tracing_subscriber::registry()
        .with(telemetry);

    // Set global default
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| Error::Internal(format!("Failed to set global default subscriber: {}", e)))?;

    Ok(())
}

/// Initialize a Jaeger tracer
fn init_jaeger_tracer(service_name: &str, endpoint: &str, sampling_ratio: f64) -> Result<trace::Tracer, Error> {
    // Use the jaeger-specific builder
    let tracer = opentelemetry_jaeger::new_pipeline()
        .with_service_name(service_name.to_owned())
        .with_agent_endpoint(endpoint)
        .with_trace_config(trace::config()
            .with_sampler(if sampling_ratio < 1.0 {
                trace::Sampler::TraceIdRatioBased(sampling_ratio)
            } else {
                trace::Sampler::AlwaysOn
            })
            .with_resource(Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", service_name.to_owned()),
            ]))
        )
        .install_batch(opentelemetry::runtime::Tokio)
        .map_err(|e| Error::Internal(format!("Failed to install Jaeger tracer: {}", e)))?;

    Ok(tracer)
}

/// Shutdown the tracer (called when the program exits)
pub fn shutdown_tracer() {
    opentelemetry::global::shutdown_tracer_provider();
}