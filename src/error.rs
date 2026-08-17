//! Shared error type used across all layers.
//!
//! Every module returns [`AppError`] so the REST API and MCP server can render
//! consistent, user-facing messages while retaining structured context for logs.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, AppError>;

/// Top-level application error.
#[derive(Debug, Error)]
pub enum AppError {
    /// Invalid or missing configuration (missing env vars, bad URLs, etc.).
    #[error("configuration error: {0}")]
    Config(String),

    /// An account, token, or message was not found.
    #[error("{0}")]
    NotFound(String),

    /// The OAuth / authorization flow failed (user cancelled, bad state, etc.).
    #[error("authorization error: {0}")]
    Auth(String),

    /// The stored access token could not be refreshed (e.g. the account needs
    /// to be re-connected via the consent popup).
    #[error("authentication expired: {0}")]
    TokenExpired(String),

    /// Upstream provider (Microsoft Graph) returned an error.
    #[error("provider error: {0}")]
    Provider(String),

    /// Storage (SQLite) or encryption failure.
    #[error("storage error: {0}")]
    Storage(String),

    /// Invalid input supplied by the caller.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Generic internal error with an optional source chain.
    #[error("internal error: {0}")]
    Internal(String),

    /// I/O failure (binding sockets, opening files, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl AppError {
    /// Build a 404-style "not found" error with a friendly message.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    /// Build an authentication-expired error (accounts need re-consent).
    pub fn token_expired(msg: impl Into<String>) -> Self {
        Self::TokenExpired(msg.into())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::Provider(e.to_string())
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Storage(e.to_string())
    }
}

impl From<oauth2::url::ParseError> for AppError {
    fn from(e: oauth2::url::ParseError) -> Self {
        AppError::Config(format!("invalid URL: {e}"))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(format!("json error: {e}"))
    }
}
