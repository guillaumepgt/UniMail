//! Persistence layer: SQLite accounts + encrypted OAuth tokens.
//!
//! Nothing in this module knows about Microsoft or any specific provider. The
//! schema stores a `provider` discriminator string and an opaque `scope`, so a
//! future Gmail/IMAP/etc. provider can be added without schema changes.

pub mod accounts;
pub mod crypto;
pub mod db;
pub mod models;
pub mod tokens;

pub use accounts::{AccountStore, SqliteAccountStore};
pub use db::Database;
pub use models::{Account, AccountStatus};
pub use tokens::{SqliteTokenStore, StoredToken, TokenStore};

/// Current time as an RFC 3339 string (used for persisted timestamps).
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
