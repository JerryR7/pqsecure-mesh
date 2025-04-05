use axum::{
    body::{Body, BoxBody},
    http::{Request, Response, StatusCode, HeaderValue, header},
    middleware::Next,
    response::{IntoResponse},
    extract::State,
};
use chrono::Utc;
use std::time::Instant;
use tracing::{info, warn, error, Span, span, Level};
use uuid::Uuid;

use crate::api::types::ApiState;
use crate::api::errors::ApiError;

/// CORS middleware
pub async fn cors_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (parts, body) = request.into_parts();

    // Create new request from parts and body
    let request = Request::from_parts(parts, body);

    // Get response from next middleware or handler
    let mut response = next.run(request).await;

    // Add CORS headers
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type, Authorization"));

    Ok(response)
}

/// Request ID middleware
pub async fn request_id_middleware<B>(
    mut request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Generate a unique request ID
    let request_id = Uuid::new_v4().to_string();

    // Add request ID to extensions
    request.extensions_mut().insert(request_id.clone());

    // Create tracing span with request ID
    let span = span!(Level::INFO, "request", request_id = %request_id);
    let _guard = span.enter();

    // Get response from next middleware or handler
    let mut response = next.run(request).await;

    // Add request ID to response headers
    response.headers_mut().insert("X-Request-ID", HeaderValue::from_str(&request_id).unwrap());

    Ok(response)
}

/// Logging middleware
pub async fn logging_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, (StatusCode, String)>
where
    B: Send + 'static,
{
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let start_time = Instant::now();

    info!("Request started: {} {}", method, path);

    let response = next.run(request).await;

    let duration = start_time.elapsed();
    let status = response.status();

    // Log different levels based on status code
    if status.is_success() {
        info!("Request completed: {} {} {} - {:?}", method, path, status, duration);
    } else if status.is_client_error() {
        warn!("Client error: {} {} {} - {:?}", method, path, status, duration);
    } else if status.is_server_error() {
        error!("Server error: {} {} {} - {:?}", method, path, status, duration);
    } else {
        info!("Request completed: {} {} {} - {:?}", method, path, status, duration);
    }

    Ok(response)
}

/// Error handling middleware
pub async fn error_handling_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let path = request.uri().path().to_owned();

    // Try to process the request
    let response = next.run(request).await;

    // Check if we got a server error
    if response.status().is_server_error() {
        error!("Server error occurred handling path: {}", path);
    }

    Ok(response)
}

/// Authentication middleware
pub async fn auth_middleware<B>(
    State(state): State<ApiState>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, ApiError> {
    // Get authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(auth) if auth.starts_with("Bearer ") => {
            let token = &auth[7..]; // Skip "Bearer " prefix

            // TODO: Implement proper token validation
            if token.len() < 10 {
                return Err(ApiError::Unauthorized);
            }

            // Add authenticated user info to request extensions
            request.extensions_mut().insert("user_id".to_string());

            // Continue with the request
            Ok(next.run(request).await)
        },
        _ => Err(ApiError::Unauthorized),
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware<B>(
    State(state): State<ApiState>,
    request: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, ApiError> {
    // Get client IP address from request
    let client_ip = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    // TODO: Implement actual rate limiting logic
    // This would typically use Redis or another store to track request counts

    // For now, always allow the request
    Ok(next.run(request).await)
}