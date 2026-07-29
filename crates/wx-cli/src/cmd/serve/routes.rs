use std::sync::Arc;

use axum::middleware;
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

use super::auth;
use super::handlers;
use super::state::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/health", get(handlers::handler_health))
        .route("/api/v1/sessions", get(handlers::handler_sessions))
        .route("/api/v1/contacts", get(handlers::handler_contacts))
        .route("/api/v1/messages", get(handlers::handler_messages))
        .route("/api/v1/timeline", get(handlers::handler_timeline))
        .route("/api/v1/media", get(handlers::handler_media))
        .route("/api/v1/search", get(handlers::handler_search))
        .route("/api/v1/events", get(handlers::handler_sse))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::bearer_auth,
        ))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
