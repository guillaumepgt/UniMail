//! Shared application state and dependency wiring.
//!
//! [`AppState`] is the single object that assembles the storage, auth, and
//! provider layers. It is shared by the REST API, the MCP server, and the CLI
//! so all three see the same accounts, tokens, and database.

use std::sync::Arc;

use crate::auth::{FlowStore, OAuthClient, ProfileResolver, TokenManager};
use crate::config::Config;
use crate::error::{AppError, Result};
use crate::provider::graph::{GraphIdentityResolver, MicrosoftGraph};
use crate::provider::EmailProvider;
use crate::storage::{AccountStore, SqliteAccountStore, SqliteTokenStore, TokenStore};

/// Central runtime state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub accounts: Arc<dyn AccountStore>,
    pub tokens: Arc<dyn TokenStore>,
    pub provider: Arc<dyn EmailProvider>,
    pub token_manager: Arc<TokenManager>,
    pub flows: FlowStore,
}

impl AppState {
    /// Wire everything together from configuration.
    pub fn build(config: Config) -> Result<Self> {
        let http = build_http_client()?;

        // Storage.
        let db = crate::storage::Database::open(&config.database_path)?;
        let accounts: Arc<dyn AccountStore> =
            Arc::new(SqliteAccountStore::new(db.shared()));
        let tokens: Arc<dyn TokenStore> =
            Arc::new(SqliteTokenStore::new(db.shared(), config.encryption_key));

        // Auth.
        let oauth = OAuthClient::new(&config, http.clone());
        let flows = FlowStore::default();
        let profile: Arc<dyn ProfileResolver> =
            Arc::new(GraphIdentityResolver::new(&config, http.clone()));
        let token_manager = Arc::new(TokenManager::new(
            oauth,
            accounts.clone(),
            tokens.clone(),
            flows.clone(),
            profile,
        ));

        // Provider.
        let provider: Arc<dyn EmailProvider> =
            Arc::new(MicrosoftGraph::new(&config, http, token_manager.clone()));

        Ok(Self {
            config: Arc::new(config),
            accounts,
            tokens,
            provider,
            token_manager,
            flows,
        })
    }
}

/// Build a rustls-based HTTP client. Redirects are disabled so OAuth token
/// requests never follow a redirect to an unexpected host.
fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!("unimail/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AppError::Internal(format!("could not build HTTP client: {e}")))
}
