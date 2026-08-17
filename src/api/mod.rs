//! Axum REST API.

pub mod auth;
pub mod routes;
pub mod state;

pub use state::AppState;

use std::sync::Arc;

use axum::extract::State;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use tower_http::trace::TraceLayer;

use crate::api::auth::api_key_middleware;

/// Build the REST API router. All mail/account routes are protected by the
/// API-key middleware; `/health` is open for load balancers.
pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/accounts", get(routes::list_accounts))
        .route("/accounts/connect", post(routes::connect_account))
        .route("/accounts/{id}", delete(routes::disconnect_account))
        .route("/accounts/{id}/emails", get(routes::list_emails))
        .route(
            "/accounts/{id}/emails/{message_id}",
            get(routes::get_email),
        )
        .route("/accounts/{id}/send", post(routes::send_email))
        .route("/unified/inbox", get(routes::unified_inbox))
        .layer(from_fn_with_state(state.clone(), api_key_middleware));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Liveness probe.
async fn health(State(_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
