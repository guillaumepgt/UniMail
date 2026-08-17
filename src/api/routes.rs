//! Axum REST API handlers.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::api::auth::Tenant;
use crate::api::state::AppState;
use crate::error::{AppError, Result};
use crate::provider::models::{SendMailRequest, UnifiedEmail};
use crate::provider::{aggregate_unified_inbox, Email};
use crate::storage::models::Account;

/// Default page size for email listings.
const DEFAULT_LIMIT: usize = 20;
/// Hard cap on page size (rate-limit friendly).
const MAX_LIMIT: usize = 200;

/// GET /accounts — list connected accounts for the tenant.
pub async fn list_accounts(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
) -> Result<Json<Vec<Account>>> {
    let accounts = state.accounts.list(&tenant.0)?;
    Ok(Json(accounts))
}

/// POST /accounts/connect — start the OAuth flow for a new account.
pub async fn connect_account(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
) -> Result<Json<serde_json::Value>> {
    let auth_url = state.token_manager.begin_flow(&tenant.0)?;
    Ok(Json(serde_json::json!({ "auth_url": auth_url.to_string() })))
}

/// DELETE /accounts/{id} — disconnect an account (keep the row for audit).
pub async fn disconnect_account(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let account = state.accounts.get(&tenant.0, &id)?;
    state.token_manager.disconnect(&account)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /accounts/{id}/emails?limit=&query= — list emails via the provider.
pub async fn list_emails(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Query(query): Query<EmailQuery>,
) -> Result<Json<Vec<Email>>> {
    let account = state.accounts.get(&tenant.0, &id)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let emails = state
        .provider
        .list_messages(&account, limit, query.query.as_deref())
        .await?;
    Ok(Json(emails))
}

/// GET /accounts/{id}/emails/{messageId} — read a single email.
pub async fn get_email(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path((id, message_id)): Path<(String, String)>,
) -> Result<Json<Email>> {
    let account = state.accounts.get(&tenant.0, &id)?;
    let email = state.provider.get_message(&account, &message_id).await?;
    Ok(Json(email))
}

/// POST /accounts/{id}/send — send an email from the account.
pub async fn send_email(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Path(id): Path<String>,
    Json(body): Json<SendMailRequest>,
) -> Result<StatusCode> {
    let account = state.accounts.get(&tenant.0, &id)?;
    state
        .provider
        .send_message(&account, &body.to, &body.subject, &body.body)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

/// GET /unified/inbox?limit= — aggregate every account's inbox into one list.
pub async fn unified_inbox(
    State(state): State<Arc<AppState>>,
    Extension(tenant): Extension<Tenant>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<Vec<UnifiedEmail>>> {
    let accounts = state.accounts.list(&tenant.0)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let inbox = aggregate_unified_inbox(&state.provider, &accounts, limit).await?;
    Ok(Json(inbox))
}

#[derive(Debug, Deserialize)]
pub struct EmailQuery {
    pub limit: Option<usize>,
    pub query: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    pub limit: Option<usize>,
}

/// Map application errors to HTTP status codes for the API surface.
fn status_for(error: &AppError) -> StatusCode {
    match error {
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::Auth(_) | AppError::TokenExpired(_) => StatusCode::UNAUTHORIZED,
        AppError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
        AppError::Provider(_) => StatusCode::BAD_GATEWAY,
        AppError::Config(_)
        | AppError::Storage(_)
        | AppError::Internal(_)
        | AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = status_for(&self);
        // Avoid leaking internal details; log the full error server-side.
        tracing::error!(error = %self, "request failed");
        let message = match self {
            AppError::Internal(_) | AppError::Storage(_) | AppError::Io(_) => {
                "internal error".to_string()
            }
            other => other.to_string(),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
