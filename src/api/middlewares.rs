// src/api/middlewares.rs
use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing::{info, error};
use std::time::Instant;

pub async fn logging_middleware<B>(
    req: Request<B>,
    next: Next<B>
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    
    let start = Instant::now();
    info!("Request started: {} {}", method, path);
    
    let res = next.run(req).await;
    
    let duration = start.elapsed();
    info!("Request completed: {} {} - {:?}", method, path, duration);
    
    Ok(res)
}

// Other middlewares can be added here
// For example, authentication, authorization, etc.