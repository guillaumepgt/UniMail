//! Local HTTP callback server that receives the OAuth redirect from Microsoft.
//!
//! Azure sends the browser to `REDIRECT_URI?code=...&state=...` after consent.
//! This server captures those parameters, completes the flow via
//! [`TokenManager::complete_flow`], and shows a short HTML page so the user can
//! close the tab. It is shared by the CLI (`add-account`) and the REST API.

use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::auth::token::TokenManager;
use crate::error::{AppError, Result};
use crate::storage::models::Account;

/// Query parameters Microsoft sends back to the redirect URI.
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    #[serde(rename = "error_description")]
    error_description: Option<String>,
}

/// State shared by the callback handlers.
#[derive(Clone)]
struct CallbackState {
    manager: Arc<TokenManager>,
    /// When set (CLI mode), signals "one callback handled" to shut the server down.
    done: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

/// Build a persistent callback router (used by the REST API server).
pub fn callback_router(manager: Arc<TokenManager>) -> Router {
    let state = CallbackState {
        manager,
        done: Arc::new(Mutex::new(None)),
    };
    Router::new()
        .route("/", get(handle_callback))
        .fallback(get(handle_callback))
        .with_state(state)
}

/// Serve exactly one callback and then shut down (used by `add-account`).
pub async fn serve_callback_once(
    manager: Arc<TokenManager>,
    addr: std::net::SocketAddr,
) -> Result<()> {
    let (tx, rx) = oneshot::channel::<()>();
    let state = CallbackState {
        manager,
        done: Arc::new(Mutex::new(Some(tx))),
    };
    let app = Router::new()
        .route("/", get(handle_callback))
        .fallback(get(handle_callback))
        .with_state(state);

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::Io(std::io::Error::new(e.kind(), format!("bind {addr}: {e}"))))?;
    tracing::info!(%addr, "waiting for OAuth callback");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = rx.await;
        })
        .await
        .map_err(|e| AppError::Io(std::io::Error::new(e.kind(), format!("callback server: {e}"))))
}

async fn handle_callback(
    State(state): State<CallbackState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let response = complete_callback(state.manager.as_ref(), &params).await;

    // In CLI mode, shut down after the first callback.
    if let Some(tx) = state.done.lock().expect("done channel poisoned").take() {
        let _ = tx.send(());
    }

    response
}

async fn complete_callback(manager: &TokenManager, params: &CallbackParams) -> Response {
    // The user denied consent, or Microsoft reported another error.
    if let Some(error) = &params.error {
        let detail = params
            .error_description
            .as_deref()
            .map(|d| format!(" — {d}"))
            .unwrap_or_default();
        return error_response(&format!("Authorization failed: {error}{detail}"));
    }

    match (&params.code, &params.state) {
        (Some(code), Some(state)) => match manager.complete_flow(code, state).await {
            Ok(account) => success_response(&account),
            Err(e) => error_response(&e.to_string()),
        },
        _ => error_response("Missing code or state parameter in callback"),
    }
}

fn success_response(account: &Account) -> Response {
    let body = format!(
        "<html><head><title>UniMail — Connected</title></head>\
         <body style=\"font-family:sans-serif;max-width:640px;margin:4rem auto;text-align:center\">\
         <h1 style=\"color:#16a34a\">✅ Account connected</h1>\
         <p><strong>{email}</strong> is now connected to your unified inbox.</p>\
         <p style=\"color:#64748b\">You can close this tab and return to UniMail.</p>\
         </body></html>",
        email = escape_html(&account.email_address),
    );
    (axum::http::StatusCode::OK, Html(body)).into_response()
}

fn error_response(message: &str) -> Response {
    let body = format!(
        "<html><head><title>UniMail — Error</title></head>\
         <body style=\"font-family:sans-serif;max-width:640px;margin:4rem auto;text-align:center\">\
         <h1 style=\"color:#dc2626\">❌ Connection failed</h1>\
         <p>{message}</p>\
         <p style=\"color:#64748b\">Close this tab and try again.</p>\
         </body></html>",
        message = escape_html(message),
    );
    (axum::http::StatusCode::BAD_REQUEST, Html(body)).into_response()
}

/// Minimal HTML-escaping for values echoed back into the success/error pages.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
