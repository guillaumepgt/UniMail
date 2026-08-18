//! Token lifecycle management.
//!
//! [`TokenManager`] is the single place that (a) completes the OAuth consent
//! flow and persists a new account, and (b) hands out valid access tokens,
//! transparently refreshing them when they expire or when Graph rejects them.
//!
//! It depends only on the provider-agnostic storage traits and a
//! [`ProfileResolver`], so the refresh/caching logic is reusable for any OAuth
//! provider.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, Utc};

use crate::storage::flows::{FlowError, FlowStore};
use crate::auth::oauth::OAuthClient;
use crate::error::{AppError, Result};
use crate::storage::models::{Account, AccountStatus};
use crate::storage::{AccountStore, StoredToken, TokenStore};

/// How far ahead of `expires_at` a cached token is considered "expired"
/// (a safety margin so we never send a token that dies mid-request).
const EXPIRY_SKEW: Duration = Duration::minutes(5);

/// How often to bump `last_used_at` on a cache hit (limits write amplification).
const USAGE_WRITE_INTERVAL: Duration = Duration::hours(6);

/// Resolves the identity (email + display name) of a freshly authorized
/// account. Implemented by the provider layer (e.g. Graph `/me`).
#[async_trait]
pub trait ProfileResolver: Send + Sync {
    async fn resolve(&self, access_token: &str) -> Result<ResolvedIdentity>;
}

/// Identity information returned by a [`ProfileResolver`].
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    pub email: String,
    pub display_name: Option<String>,
}

/// The result of refreshing a single account.
pub type RefreshOutcome = (Account, Result<()>);

/// Token lifecycle manager.
pub struct TokenManager {
    oauth: OAuthClient,
    accounts: Arc<dyn AccountStore>,
    tokens: Arc<dyn TokenStore>,
    flows: FlowStore,
    profile: Arc<dyn ProfileResolver>,
    /// Per-account mutexes to avoid racing refresh requests.
    refresh_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl TokenManager {
    /// Create the manager from its dependencies.
    pub fn new(
        oauth: OAuthClient,
        accounts: Arc<dyn AccountStore>,
        tokens: Arc<dyn TokenStore>,
        flows: FlowStore,
        profile: Arc<dyn ProfileResolver>,
    ) -> Self {
        Self {
            oauth,
            accounts,
            tokens,
            flows,
            profile,
            refresh_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Begin an OAuth flow for a tenant and return the consent URL to open.
    pub fn begin_flow(&self, tenant_id: &str) -> Result<url::Url> {
        let (auth_url, verifier, state) = self.oauth.authorize_url()?;
        // The `state` embedded in the consent URL is the CSRF token the
        // provider echoes back; it must be the same key we store the flow
        // under, otherwise the callback can never match it.
        self.flows.insert(verifier, tenant_id.to_string(), state);
        Ok(auth_url)
    }

    /// Complete a flow: validate state, exchange the code, resolve identity and
    /// persist the account + its (encrypted) token.
    pub async fn complete_flow(&self, code: &str, state: &str) -> Result<Account> {
        let flow = self.flows.take(state).map_err(|e| match e {
            FlowError::UnknownState => AppError::Auth("unknown or already-used state".into()),
            FlowError::Expired => AppError::Auth("authorization flow expired".into()),
            FlowError::Storage(msg) => AppError::Storage(msg),
        })?;

        let token_set = self.oauth.exchange_code(code, flow.verifier).await?;
        let refresh_token = token_set.refresh_token.clone().ok_or_else(|| {
            AppError::Auth(
                "no refresh token returned (ensure the 'offline_access' scope was granted)".into(),
            )
        })?;

        let identity = self.profile.resolve(&token_set.access_token).await?;

        let account = match self
            .accounts
            .get_by_email(&flow.tenant_id, &identity.email)
        {
            Ok(mut existing) => {
                // Re-consent: update identity + status, reuse the account id.
                existing.display_name = identity.display_name;
                existing.status = AccountStatus::Active;
                existing.updated_at = crate::storage::now();
                existing
            }
            Err(AppError::NotFound(_)) => Account {
                id: uuid::Uuid::new_v4().to_string(),
                tenant_id: flow.tenant_id.clone(),
                email_address: identity.email,
                display_name: identity.display_name,
                provider: "microsoft".to_string(),
                status: AccountStatus::Active,
                created_at: crate::storage::now(),
                updated_at: crate::storage::now(),
            },
            Err(e) => return Err(e),
        };

        let stored = StoredToken {
            access_token: token_set.access_token,
            refresh_token,
            scope: token_set.scopes.map(|s| s.join(" ")),
            expires_at: token_set.expires_at,
            last_used_at: Some(Utc::now()),
            updated_at: Utc::now(),
        };

        // Insert-or-update the account, then persist the token.
        if self.accounts.get(&flow.tenant_id, &account.id).is_err() {
            self.accounts.create(&account)?;
        }
        self.tokens.upsert(&account.id, &stored)?;

        Ok(account)
    }

    /// Return a valid access token for an account, refreshing transparently.
    pub async fn get_access_token(&self, account_id: &str) -> Result<String> {
        if let Some(token) = self.tokens.get(account_id)? {
            if let Some(expires_at) = token.expires_at {
                if expires_at > Utc::now() + EXPIRY_SKEW {
                    self.bump_last_used(account_id, &token);
                    return Ok(token.access_token);
                }
            }
            // Token missing expiry or expired -> refresh below.
        }

        self.refresh_account(account_id).await?;
        self.tokens
            .get(account_id)?
            .map(|t| t.access_token)
            .ok_or_else(|| AppError::token_expired("account is not connected (no token stored)"))
    }

    /// Force a refresh of the account's token and persist the new set.
    pub async fn refresh_account(&self, account_id: &str) -> Result<()> {
        // Serialise refreshes per account to avoid thundering-herd duplicates.
        let lock = self.account_lock(account_id);
        let _guard = lock.lock().await;

        let current = self.tokens.get(account_id)?.ok_or_else(|| {
            AppError::token_expired("account is not connected (no token stored)")
        })?;
        let token_set = self.oauth.refresh(&current.refresh_token).await?;

        // Some providers rotate refresh tokens; keep the old one if absent.
        let refresh_token = token_set.refresh_token.unwrap_or(current.refresh_token);
        let stored = StoredToken {
            access_token: token_set.access_token,
            refresh_token,
            scope: token_set.scopes.map(|s| s.join(" ")),
            expires_at: token_set.expires_at,
            last_used_at: Some(Utc::now()),
            updated_at: Utc::now(),
        };
        self.tokens.upsert(account_id, &stored)?;
        Ok(())
    }

    /// Refresh every active account. Failures are returned per-account so the
    /// caller can report them; a single bad account never aborts the batch.
    pub async fn refresh_all(&self) -> Vec<RefreshOutcome> {
        let accounts = match self.accounts.list_all() {
            Ok(a) => a,
            Err(e) => return vec![(dummy_account(), Err(e))],
        };
        let mut outcomes = Vec::with_capacity(accounts.len());
        for account in accounts {
            if account.status == AccountStatus::Disconnected {
                continue;
            }
            let result = self.refresh_account(&account.id).await;
            outcomes.push((account, result));
        }
        outcomes
    }

    /// Refresh accounts whose token has not been used for `inactivity_days`.
    /// Returns the number of successful refreshes.
    pub async fn refresh_stale(&self, inactivity_days: i64) -> usize {
        let cutoff = Utc::now() - Duration::days(inactivity_days);
        let ids = match self.tokens.list_inactive(cutoff) {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list inactive tokens");
                return 0;
            }
        };
        let mut refreshed = 0;
        for id in ids {
            match self.refresh_account(&id).await {
                Ok(()) => {
                    tracing::info!(account_id = %id, "renewed idle account token");
                    refreshed += 1;
                }
                Err(e) => {
                    tracing::warn!(account_id = %id, error = %e, "could not renew idle account token");
                }
            }
        }
        refreshed
    }

    /// Disconnect an account: drop its token and mark it disconnected.
    pub fn disconnect(&self, account: &Account) -> Result<()> {
        self.tokens.delete(&account.id)?;
        self.accounts
            .set_status(&account.tenant_id, &account.id, AccountStatus::Disconnected)
    }

    /// Best-effort activity bump so idle accounts are not needlessly renewed.
    fn bump_last_used(&self, account_id: &str, token: &StoredToken) {
        let should_write = match token.last_used_at {
            None => true,
            Some(last) => Utc::now() - last > USAGE_WRITE_INTERVAL,
        };
        if !should_write {
            return;
        }
        let mut updated = token.clone();
        updated.last_used_at = Some(Utc::now());
        updated.updated_at = Utc::now();
        if let Err(e) = self.tokens.upsert(account_id, &updated) {
            tracing::debug!(account_id = %account_id, error = %e, "failed to bump last_used_at");
        }
    }

    /// Get (or lazily create) the per-account refresh mutex.
    fn account_lock(&self, account_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.refresh_locks.lock().expect("refresh lock map poisoned");
        locks
            .entry(account_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

/// Sentinel account used when even listing accounts fails in `refresh_all`.
fn dummy_account() -> Account {
    Account {
        id: String::new(),
        tenant_id: String::new(),
        email_address: "unknown".into(),
        display_name: None,
        provider: "microsoft".into(),
        status: AccountStatus::Active,
        created_at: String::new(),
        updated_at: String::new(),
    }
}
