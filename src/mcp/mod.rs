//! Model Context Protocol server (stdio transport).
//!
//! Exposes the same accounts/tokens/mail as the REST API by sharing the same
//! [`AppState`] (and therefore the same SQLite database). Tools return JSON
//! strings; domain errors are surfaced as tool-level errors so the caller's
//! client shows the message.

use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{
    schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt,
    transport::stdio,
};
use serde::Serialize;

use crate::api::AppState;
use crate::error::AppError;
use crate::provider::aggregate_unified_inbox;
use crate::storage::models::Account;

/// Default page size for email listings.
const DEFAULT_LIMIT: usize = 20;

// --- Tool parameter schemas --------------------------------------------------

#[derive(Debug, schemars::JsonSchema, serde::Deserialize)]
pub struct AccountParam {
    /// Account id or email address.
    pub account: String,
}

#[derive(Debug, schemars::JsonSchema, serde::Deserialize)]
pub struct ListEmailsParams {
    /// Account id or email address.
    pub account: String,
    /// Maximum number of messages to return.
    pub limit: Option<usize>,
}

#[derive(Debug, schemars::JsonSchema, serde::Deserialize)]
pub struct SearchEmailsParams {
    /// Account id or email address.
    pub account: String,
    /// Search query (Microsoft Graph KQL, e.g. `subject:invoice`).
    pub query: String,
}

#[derive(Debug, schemars::JsonSchema, serde::Deserialize)]
pub struct ReadEmailParams {
    /// Account id or email address.
    pub account: String,
    /// Provider message id.
    pub message_id: String,
}

#[derive(Debug, schemars::JsonSchema, serde::Deserialize)]
pub struct SendEmailParams {
    /// Account id or email address to send from.
    pub account: String,
    /// Recipient email address.
    pub to: String,
    /// Email subject.
    pub subject: String,
    /// Plain-text email body.
    pub body: String,
}

#[derive(Debug, schemars::JsonSchema, serde::Deserialize)]
pub struct UnifiedInboxParams {
    /// Maximum number of messages to return across all accounts.
    pub limit: Option<usize>,
}

// --- Server ------------------------------------------------------------------

/// The MCP server. Holds shared app state; cheap to clone.
#[derive(Clone)]
pub struct MailServer {
    state: Arc<AppState>,
}

#[tool_router]
impl MailServer {
    /// List all connected email accounts.
    #[tool(description = "List all connected email accounts (id + email address)")]
    async fn list_accounts(&self) -> Result<CallToolResult, ErrorData> {
        let accounts = self
            .state
            .accounts
            .list(&self.state.config.default_tenant_id)
            .map_err(to_protocol_error)?;
        Ok(tool_ok(&accounts))
    }

    /// List recent emails for one account.
    #[tool(description = "List recent emails for a connected account, newest first")]
    async fn list_emails(
        &self,
        Parameters(params): Parameters<ListEmailsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let account = match self.resolve_account(&params.account) {
            Ok(a) => a,
            Err(e) => return Ok(tool_error(&e)),
        };
        let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(200);
        match self.state.provider.list_messages(&account, limit, None).await {
            Ok(emails) => Ok(tool_ok(&emails)),
            Err(e) => Ok(tool_error(&e)),
        }
    }

    /// Search emails for one account.
    #[tool(description = "Search a connected account's emails (Graph KQL query)")]
    async fn search_emails(
        &self,
        Parameters(params): Parameters<SearchEmailsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let account = match self.resolve_account(&params.account) {
            Ok(a) => a,
            Err(e) => return Ok(tool_error(&e)),
        };
        match self
            .state
            .provider
            .list_messages(&account, 50, Some(&params.query))
            .await
        {
            Ok(emails) => Ok(tool_ok(&emails)),
            Err(e) => Ok(tool_error(&e)),
        }
    }

    /// Read a single email.
    #[tool(description = "Read a single email (including body) by message id")]
    async fn read_email(
        &self,
        Parameters(params): Parameters<ReadEmailParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let account = match self.resolve_account(&params.account) {
            Ok(a) => a,
            Err(e) => return Ok(tool_error(&e)),
        };
        match self.state.provider.get_message(&account, &params.message_id).await {
            Ok(email) => Ok(tool_ok(&email)),
            Err(e) => Ok(tool_error(&e)),
        }
    }

    /// Send an email.
    #[tool(description = "Send an email from a connected account")]
    async fn send_email(
        &self,
        Parameters(params): Parameters<SendEmailParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let account = match self.resolve_account(&params.account) {
            Ok(a) => a,
            Err(e) => return Ok(tool_error(&e)),
        };
        match self
            .state
            .provider
            .send_message(&account, &params.to, &params.subject, &params.body)
            .await
        {
            Ok(()) => Ok(tool_ok(&serde_json::json!({ "sent": true }))),
            Err(e) => Ok(tool_error(&e)),
        }
    }

    /// Aggregate the unified inbox.
    #[tool(description = "Aggregate recent email from ALL connected accounts into one date-sorted inbox")]
    async fn unified_inbox(
        &self,
        Parameters(params): Parameters<UnifiedInboxParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let accounts = self
            .state
            .accounts
            .list(&self.state.config.default_tenant_id)
            .map_err(to_protocol_error)?;
        let limit = params.limit.unwrap_or(50).min(500);
        match aggregate_unified_inbox(&self.state.provider, &accounts, limit).await {
            Ok(inbox) => Ok(tool_ok(&inbox)),
            Err(e) => Ok(tool_error(&e)),
        }
    }
}

/// Custom server metadata.
#[tool_handler(name = "unimail", version = "0.1.0", instructions = "Unified inbox for personal Microsoft email accounts.")]
impl ServerHandler for MailServer {}

impl MailServer {
    /// Resolve an account by id or email address within the default tenant.
    fn resolve_account(&self, id_or_email: &str) -> crate::error::Result<Account> {
        let tenant = &self.state.config.default_tenant_id;
        match self.state.accounts.get(tenant, id_or_email) {
            Ok(a) => Ok(a),
            Err(_) => self.state.accounts.get_by_email(tenant, id_or_email),
        }
    }
}

/// Serve the MCP server over stdio until the client disconnects.
pub async fn serve_stdio(state: Arc<AppState>) -> crate::error::Result<()> {
    let server = MailServer { state };
    let service = server
        .serve(stdio())
        .await
        .map_err(|e| AppError::Internal(format!("MCP initialization failed: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| AppError::Internal(format!("MCP server stopped: {e}")))?;
    Ok(())
}

// --- Result helpers ----------------------------------------------------------

/// Serialize a value to pretty JSON and wrap it as a successful tool result.
fn tool_ok(value: &impl Serialize) -> CallToolResult {
    let text = serde_json::to_string_pretty(value)
        .unwrap_or_else(|_| "{}".to_string());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

/// Wrap a domain error as a caller-visible tool-level error.
fn tool_error(error: &impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(error.to_string())])
}

/// Convert an application error into an MCP protocol error (opaque to callers).
fn to_protocol_error(error: AppError) -> ErrorData {
    tracing::error!(error = %error, "MCP request failed");
    ErrorData::internal_error("internal server error", None)
}

