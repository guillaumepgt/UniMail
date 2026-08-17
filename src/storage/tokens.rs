//! OAuth token persistence, encrypted at rest with AES-256-GCM.

use chrono::{DateTime, Utc};

use crate::error::{AppError, Result};
use crate::storage::crypto::{decrypt, encrypt};
use crate::storage::db::SharedConn;

/// A decrypted token set for one account.
#[derive(Debug, Clone)]
pub struct StoredToken {
    /// Bearer access token for Microsoft Graph.
    pub access_token: String,
    /// Long-lived refresh token (encrypted at rest).
    pub refresh_token: String,
    /// Space-separated scopes granted, if known.
    pub scope: Option<String>,
    /// When the access token expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// When the token was last used (read/refreshed).
    pub last_used_at: Option<DateTime<Utc>>,
    /// When this record was last written.
    pub updated_at: DateTime<Utc>,
}

/// Provider-agnostic token repository. The concrete implementation encrypts
/// token material before writing it to disk.
pub trait TokenStore: Send + Sync {
    /// Fetch and decrypt the token for an account, if present.
    fn get(&self, account_id: &str) -> Result<Option<StoredToken>>;

    /// Insert or replace the token for an account.
    fn upsert(&self, account_id: &str, token: &StoredToken) -> Result<()>;

    /// Remove a token (used when an account is disconnected).
    fn delete(&self, account_id: &str) -> Result<()>;

    /// Account ids whose token has not been used since `cutoff`. Used by the
    /// background task to renew idle accounts so they stay connected.
    fn list_inactive(&self, cutoff: DateTime<Utc>) -> Result<Vec<String>>;
}

/// SQLite-backed, AES-256-GCM-encrypting [`TokenStore`].
pub struct SqliteTokenStore {
    conn: SharedConn,
    key: [u8; 32],
}

impl SqliteTokenStore {
    /// Create the store from a shared connection and the master encryption key.
    pub fn new(conn: SharedConn, key: [u8; 32]) -> Self {
        Self { conn, key }
    }
}

impl TokenStore for SqliteTokenStore {
    fn get(&self, account_id: &str) -> Result<Option<StoredToken>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT access_token_encrypted, refresh_token_encrypted, scope, expires_at, last_used_at, updated_at
                 FROM tokens WHERE account_id = ?1",
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let mut rows = stmt
            .query_map(rusqlite::params![account_id], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| AppError::Storage(e.to_string()))?;

        let Some(row) = rows.next() else {
            return Ok(None);
        };
        let (access_blob, refresh_blob, scope, expires_at, last_used_at, updated_at) =
            row.map_err(|e| AppError::Storage(e.to_string()))?;

        let access_token = decrypt(&self.key, &access_blob).map_err(|e| AppError::Storage(e))?;
        let refresh_token = decrypt(&self.key, &refresh_blob).map_err(|e| AppError::Storage(e))?;

        Ok(Some(StoredToken {
            access_token: String::from_utf8(access_token)
                .map_err(|e| AppError::Storage(format!("access token is not UTF-8: {e}")))?,
            refresh_token: String::from_utf8(refresh_token)
                .map_err(|e| AppError::Storage(format!("refresh token is not UTF-8: {e}")))?,
            scope,
            expires_at: expires_at.and_then(|s| parse_time(&s)),
            last_used_at: last_used_at.and_then(|s| parse_time(&s)),
            updated_at: parse_time(&updated_at).unwrap_or_else(Utc::now),
        }))
    }

    fn upsert(&self, account_id: &str, token: &StoredToken) -> Result<()> {
        let access_blob = encrypt(&self.key, token.access_token.as_bytes())
            .map_err(|e| AppError::Storage(e))?;
        let refresh_blob = encrypt(&self.key, token.refresh_token.as_bytes())
            .map_err(|e| AppError::Storage(e))?;

        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        conn.execute(
            "INSERT INTO tokens (account_id, access_token_encrypted, refresh_token_encrypted, scope, expires_at, last_used_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(account_id) DO UPDATE SET
                access_token_encrypted  = excluded.access_token_encrypted,
                refresh_token_encrypted = excluded.refresh_token_encrypted,
                scope                   = excluded.scope,
                expires_at              = excluded.expires_at,
                last_used_at            = excluded.last_used_at,
                updated_at              = excluded.updated_at",
            rusqlite::params![
                account_id,
                access_blob,
                refresh_blob,
                token.scope,
                token.expires_at.map(|t| t.to_rfc3339()),
                token.last_used_at.map(|t| t.to_rfc3339()),
                token.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    fn delete(&self, account_id: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        conn.execute(
            "DELETE FROM tokens WHERE account_id = ?1",
            rusqlite::params![account_id],
        )
        .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }

    fn list_inactive(&self, cutoff: DateTime<Utc>) -> Result<Vec<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        let cutoff = cutoff.to_rfc3339();
        let mut stmt = conn
            .prepare(
                "SELECT account_id FROM tokens WHERE last_used_at IS NULL OR last_used_at < ?1",
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let ids = stmt
            .query_map(rusqlite::params![cutoff], |row| row.get::<_, String>(0))
            .map_err(|e| AppError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for id in ids {
            out.push(id.map_err(|e| AppError::Storage(e.to_string()))?);
        }
        Ok(out)
    }
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::Database;

    /// Insert a minimal parent account so the foreign key on `tokens` is satisfied.
    fn seed_account(db: &Database, id: &str) {
        let conn = db.shared();
        let conn = conn.lock().unwrap();
        conn.execute(
            "INSERT INTO accounts (id, tenant_id, email_address, provider, status, created_at, updated_at)
             VALUES (?1, 't', ?2, 'microsoft', 'active', 'now', 'now')",
            rusqlite::params![id, format!("{id}@example.com")],
        )
        .unwrap();
    }

    #[test]
    fn upsert_and_get_round_trip() {
        let db = Database::open_in_memory().unwrap();
        seed_account(&db, "acc-1");
        let store = SqliteTokenStore::new(db.shared(), [5u8; 32]);

        let token = StoredToken {
            access_token: "access-123".into(),
            refresh_token: "refresh-456".into(),
            scope: Some("offline_access Mail.Read".into()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            last_used_at: Some(Utc::now()),
            updated_at: Utc::now(),
        };
        store.upsert("acc-1", &token).unwrap();

        let got = store.get("acc-1").unwrap().unwrap();
        assert_eq!(got.access_token, "access-123");
        assert_eq!(got.refresh_token, "refresh-456");
        assert_eq!(got.scope.as_deref(), Some("offline_access Mail.Read"));
    }

    #[test]
    fn missing_token_returns_none() {
        let db = Database::open_in_memory().unwrap();
        let store = SqliteTokenStore::new(db.shared(), [5u8; 32]);
        assert!(store.get("nope").unwrap().is_none());
    }

    #[test]
    fn list_inactive_respects_cutoff() {
        let db = Database::open_in_memory().unwrap();
        seed_account(&db, "fresh");
        seed_account(&db, "stale");
        let store = SqliteTokenStore::new(db.shared(), [5u8; 32]);
        let cutoff = Utc::now() - chrono::Duration::days(90);

        let fresh = StoredToken {
            access_token: "a".into(),
            refresh_token: "r".into(),
            scope: None,
            expires_at: None,
            last_used_at: Some(Utc::now()),
            updated_at: Utc::now(),
        };
        let stale = StoredToken {
            access_token: "a".into(),
            refresh_token: "r".into(),
            scope: None,
            expires_at: None,
            last_used_at: Some(cutoff - chrono::Duration::days(1)),
            updated_at: Utc::now(),
        };
        store.upsert("fresh", &fresh).unwrap();
        store.upsert("stale", &stale).unwrap();

        let inactive = store.list_inactive(cutoff).unwrap();
        assert_eq!(inactive, vec!["stale".to_string()]);
    }
}
