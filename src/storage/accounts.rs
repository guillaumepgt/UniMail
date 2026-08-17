//! Account persistence, scoped per tenant.

use crate::error::{AppError, Result};
use crate::storage::db::SharedConn;
use crate::storage::models::{Account, AccountStatus};

/// Provider-agnostic account repository. Swappable for a Postgres/etc. backend.
pub trait AccountStore: Send + Sync {
    /// Insert a new account. Fails if the same `(tenant, email)` already exists.
    fn create(&self, account: &Account) -> Result<()>;

    /// List all accounts for a tenant, most recently updated first.
    fn list(&self, tenant_id: &str) -> Result<Vec<Account>>;

    /// Fetch a single account owned by `tenant_id`.
    fn get(&self, tenant_id: &str, id: &str) -> Result<Account>;

    /// Fetch an account by email address.
    fn get_by_email(&self, tenant_id: &str, email: &str) -> Result<Account>;

    /// Update the connection status of an account.
    fn set_status(&self, tenant_id: &str, id: &str, status: AccountStatus) -> Result<()>;

    /// Delete an account. Returns `true` if a row was removed.
    fn delete(&self, tenant_id: &str, id: &str) -> Result<bool>;

    /// List every account across all tenants (background refresh task only).
    fn list_all(&self) -> Result<Vec<Account>>;

    /// Touch the `updated_at` timestamp.
    fn touch(&self, id: &str) -> Result<()>;
}

/// SQLite-backed [`AccountStore`].
pub struct SqliteAccountStore {
    conn: SharedConn,
}

impl SqliteAccountStore {
    /// Create the store from a shared connection handle.
    pub fn new(conn: SharedConn) -> Self {
        Self { conn }
    }
}

impl AccountStore for SqliteAccountStore {
    fn create(&self, account: &Account) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        conn.execute(
            "INSERT INTO accounts (id, tenant_id, email_address, display_name, provider, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                account.id,
                account.tenant_id,
                account.email_address,
                account.display_name,
                account.provider,
                account.status.as_str(),
                account.created_at,
                account.updated_at,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(inner, _)
                if inner.code == rusqlite::ErrorCode::ConstraintViolation =>
                AppError::InvalidRequest(format!(
                    "account {} is already connected for this tenant",
                    account.email_address
                )),
            other => AppError::Storage(other.to_string()),
        })?;
        Ok(())
    }

    fn list(&self, tenant_id: &str) -> Result<Vec<Account>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        query_accounts(&conn, "SELECT * FROM accounts WHERE tenant_id = ?1 ORDER BY updated_at DESC", rusqlite::params![tenant_id])
    }

    fn get(&self, tenant_id: &str, id: &str) -> Result<Account> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        query_accounts(
            &conn,
            "SELECT * FROM accounts WHERE tenant_id = ?1 AND id = ?2",
            rusqlite::params![tenant_id, id],
        )?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::not_found(format!("account {id} not found")))
    }

    fn get_by_email(&self, tenant_id: &str, email: &str) -> Result<Account> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        query_accounts(
            &conn,
            "SELECT * FROM accounts WHERE tenant_id = ?1 AND lower(email_address) = lower(?2)",
            rusqlite::params![tenant_id, email],
        )?
        .into_iter()
        .next()
        .ok_or_else(|| AppError::not_found(format!("account {email} not found")))
    }

    fn set_status(&self, tenant_id: &str, id: &str, status: AccountStatus) -> Result<()> {
        let now = crate::storage::now();
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        let n = conn
            .execute(
                "UPDATE accounts SET status = ?1, updated_at = ?2 WHERE tenant_id = ?3 AND id = ?4",
                rusqlite::params![status.as_str(), now, tenant_id, id],
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;
        if n == 0 {
            return Err(AppError::not_found(format!("account {id} not found")));
        }
        Ok(())
    }

    fn delete(&self, tenant_id: &str, id: &str) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        let n = conn
            .execute(
                "DELETE FROM accounts WHERE tenant_id = ?1 AND id = ?2",
                rusqlite::params![tenant_id, id],
            )
            .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(n > 0)
    }

    fn list_all(&self) -> Result<Vec<Account>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        query_accounts(&conn, "SELECT * FROM accounts ORDER BY updated_at DESC", [])
    }

    fn touch(&self, id: &str) -> Result<()> {
        let now = crate::storage::now();
        let conn = self
            .conn
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))?;
        conn.execute(
            "UPDATE accounts SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )
        .map_err(|e| AppError::Storage(e.to_string()))?;
        Ok(())
    }
}

/// Map rows from a query into [`Account`] values.
fn query_accounts(
    conn: &rusqlite::Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<Account>> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| AppError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(params, |row| {
            Ok(Account {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                email_address: row.get(2)?,
                display_name: row.get(3)?,
                provider: row.get(4)?,
                status: AccountStatus::parse(&row.get::<_, String>(5)?),
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })
        .map_err(|e| AppError::Storage(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| AppError::Storage(e.to_string()))?);
    }
    Ok(out)
}
