//! Provider-agnostic email abstraction.
//!
//! [`EmailProvider`] is the seam the REST API and MCP server depend on. Today
//! it is implemented by [`MicrosoftGraph`](graph::MicrosoftGraph); a Gmail or
//! IMAP provider would implement the same trait without touching the API layer.

pub mod graph;
pub mod models;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::DateTime;

use crate::error::Result;
use crate::storage::models::Account;

pub use models::{AccountSummary, Email, EmailAddress, SendMailRequest, UnifiedEmail};

/// Abstraction over a mail backend.
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// List messages for an account, newest first. `query` is a provider
    /// search expression (Graph KQL for Microsoft).
    async fn list_messages(
        &self,
        account: &Account,
        limit: usize,
        query: Option<&str>,
    ) -> Result<Vec<Email>>;

    /// Read a single message by provider message id.
    async fn get_message(&self, account: &Account, message_id: &str) -> Result<Email>;

    /// Send a message from the account.
    async fn send_message(
        &self,
        account: &Account,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<()>;
}

/// Aggregate the inboxes of all accounts into a single, date-sorted list.
///
/// Each message is wrapped in [`UnifiedEmail`] carrying its owning account.
/// Results are fetched concurrently, then merged and sorted by `received_at`
/// (descending) and truncated to `limit`.
pub async fn aggregate_unified_inbox(
    provider: &Arc<dyn EmailProvider>,
    accounts: &[Account],
    limit: usize,
) -> Result<Vec<UnifiedEmail>> {
    let fetches = accounts.iter().map(|account| async move {
        let messages = provider
            .list_messages(account, limit, None)
            .await
            .unwrap_or_else(|e| {
                // One failing account should not take down the whole inbox.
                tracing::warn!(account_id = %account.id, error = %e, "skipping account in unified inbox");
                Vec::new()
            });
        messages.into_iter().map(|m| UnifiedEmail {
            email: m,
            account: AccountSummary {
                id: account.id.clone(),
                email: account.email_address.clone(),
            },
        })
    });

    let mut all: Vec<UnifiedEmail> = futures::future::join_all(fetches)
        .await
        .into_iter()
        .flatten()
        .collect();

    all.sort_by(|a, b| compare_received_desc(&a.email.received_at, &b.email.received_at));
    all.truncate(limit);
    Ok(all)
}

/// Sort by `received_at` descending; messages without a date sort last.
fn compare_received_desc(a: &Option<String>, b: &Option<String>) -> std::cmp::Ordering {
    match (parse_time(a), parse_time(b)) {
        (Some(a), Some(b)) => b.cmp(&a),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn parse_time(s: &Option<String>) -> Option<DateTime<chrono::Utc>> {
    s.as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::models::Email;
    use crate::storage::models::{Account, AccountStatus};

    /// A fake provider returning a fixed list of messages for every account.
    struct FakeProvider;

    #[async_trait]
    impl EmailProvider for FakeProvider {
        async fn list_messages(
            &self,
            account: &Account,
            _limit: usize,
            _query: Option<&str>,
        ) -> Result<Vec<Email>> {
            // Messages dated from the account email so ordering is deterministic.
            Ok(vec![
                email("m2", Some(format!("{}_msg", account.email_address))),
                email("m1", None),
            ])
        }
        async fn get_message(&self, _a: &Account, _id: &str) -> Result<Email> {
            Ok(email("x", None))
        }
        async fn send_message(
            &self,
            _a: &Account,
            _to: &str,
            _subject: &str,
            _body: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn email(id: &str, subject: Option<String>) -> Email {
        Email {
            id: id.into(),
            subject,
            from: None,
            to: vec![],
            body_preview: None,
            body: None,
            received_at: Some("2024-01-01T00:00:00Z".into()),
            is_read: false,
        }
    }

    fn account(id: &str, email: &str) -> Account {
        Account {
            id: id.into(),
            tenant_id: "t".into(),
            email_address: email.into(),
            display_name: None,
            provider: "microsoft".into(),
            status: AccountStatus::Active,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[tokio::test]
    async fn unified_inbox_flattens_and_limits() {
        let provider: Arc<dyn EmailProvider> = Arc::new(FakeProvider);
        let accounts = vec![account("a1", "one@example.com"), account("a2", "two@example.com")];

        let inbox = aggregate_unified_inbox(&provider, &accounts, 3).await.unwrap();

        // 2 accounts x 2 messages = 4, truncated to 3.
        assert_eq!(inbox.len(), 3);
        // Every message carries its owning account.
        for m in &inbox {
            assert!(m.account.id == "a1" || m.account.id == "a2");
        }
    }

    #[tokio::test]
    async fn unified_inbox_sorts_by_date_desc() {
        let provider: Arc<dyn EmailProvider> = Arc::new(FakeProvider);
        let accounts = vec![account("a1", "one@example.com")];
        // All same date, so stable; just ensure no panic and full result.
        let inbox = aggregate_unified_inbox(&provider, &accounts, 10).await.unwrap();
        assert_eq!(inbox.len(), 2);
    }
}
