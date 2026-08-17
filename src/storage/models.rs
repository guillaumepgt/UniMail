//! Persisted domain models.
//!
//! Timestamps are stored and exchanged as RFC 3339 strings to keep the models
//! trivial to (de)serialise from SQLite rows and JSON without a custom SQL
//! codec. Callers that need to compare times convert via `chrono` locally.

use serde::{Deserialize, Serialize};

/// A connected email account belonging to a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Stable unique id (UUID v4).
    pub id: String,
    /// Owning tenant id (multi-tenancy).
    pub tenant_id: String,
    /// Primary email address of the account (e.g. `user@hotmail.com`).
    pub email_address: String,
    /// Human display name, if the provider returned one.
    pub display_name: Option<String>,
    /// Provider discriminator (`microsoft` today; kept opaque on purpose).
    pub provider: String,
    /// Connection state.
    pub status: AccountStatus,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-updated timestamp.
    pub updated_at: String,
}

/// Whether an account is currently usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Connected and usable.
    Active,
    /// Explicitly disconnected (kept for audit; must be re-consented).
    Disconnected,
}

impl AccountStatus {
    /// Parse from the stored string.
    pub fn parse(s: &str) -> Self {
        match s {
            "disconnected" => AccountStatus::Disconnected,
            _ => AccountStatus::Active,
        }
    }

    /// Stored string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            AccountStatus::Active => "active",
            AccountStatus::Disconnected => "disconnected",
        }
    }
}
