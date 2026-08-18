//! SQLite connection management and schema migration.

use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;

use crate::error::{AppError, Result};

/// Shared, thread-safe handle to the SQLite connection.
///
/// `rusqlite::Connection` is `Send` but not `Sync`, so it is shared behind a
/// `Mutex`. All storage operations are short and synchronous, and no lock is
/// ever held across an `.await`, which keeps this safe in the async runtime.
pub type SharedConn = Arc<Mutex<Connection>>;

/// Owns the underlying SQLite database.
#[derive(Clone)]
pub struct Database {
    inner: SharedConn,
}

impl Database {
    /// Open (creating if necessary) the database at `path` and run migrations.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| AppError::Storage(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| AppError::Storage(e.to_string()))?;
        migrate(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory database (used by tests).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| AppError::Storage(e.to_string()))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| AppError::Storage(e.to_string()))?;
        migrate(&conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    /// Clone a shareable handle to the underlying connection.
    pub fn shared(&self) -> SharedConn {
        self.inner.clone()
    }

    /// Lock the connection (short, synchronous critical section only).
    pub fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.inner
            .lock()
            .map_err(|_| AppError::Storage("database lock poisoned".to_string()))
    }
}

/// Schema. Idempotent `IF NOT EXISTS` statements make this safe to re-run.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    email_address TEXT NOT NULL,
    display_name  TEXT,
    provider      TEXT NOT NULL DEFAULT 'microsoft',
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (tenant_id, email_address)
);

CREATE INDEX IF NOT EXISTS idx_accounts_tenant ON accounts(tenant_id);

CREATE TABLE IF NOT EXISTS tokens (
    account_id              TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    access_token_encrypted  BLOB NOT NULL,
    refresh_token_encrypted BLOB NOT NULL,
    scope                   TEXT,
    expires_at              TEXT,
    last_used_at            TEXT,
    updated_at              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_last_used ON tokens(last_used_at);

CREATE TABLE IF NOT EXISTS oauth_flows (
    state      TEXT PRIMARY KEY,
    verifier   BLOB NOT NULL,
    tenant_id  TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_flows_created_at ON oauth_flows(created_at);
"#;

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)
        .map_err(|e| AppError::Storage(format!("migration failed: {e}")))
}
