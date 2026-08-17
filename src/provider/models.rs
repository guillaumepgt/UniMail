//! Provider-agnostic email models.
//!
//! These are the shapes exposed by the REST API and MCP tools. They carry no
//! Microsoft/Graph-specific fields, so a future provider returns the same
//! structs and no API contract changes.

use serde::{Deserialize, Serialize};

/// A named email address (`from` / `to` fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub address: String,
}

/// A single email message, normalised across providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
    /// Provider message id.
    pub id: String,
    pub subject: Option<String>,
    pub from: Option<EmailAddress>,
    pub to: Vec<EmailAddress>,
    /// Short preview (only populated on list results).
    pub body_preview: Option<String>,
    /// Full body (only populated when reading a single message).
    pub body: Option<String>,
    /// RFC 3339 timestamp.
    pub received_at: Option<String>,
    pub is_read: bool,
}

/// Summary of the account a unified-inbox message belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSummary {
    pub id: String,
    pub email: String,
}

/// A message in the unified inbox: normalised email plus its owning account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedEmail {
    #[serde(flatten)]
    pub email: Email,
    pub account: AccountSummary,
}

/// Request body for sending a message.
#[derive(Debug, Clone, Deserialize)]
pub struct SendMailRequest {
    pub to: String,
    pub subject: String,
    pub body: String,
}
