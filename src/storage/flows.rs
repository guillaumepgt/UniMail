//! SQLite-backed registry of in-flight OAuth authorization flows.
//!
//! Each `begin_flow` records the PKCE verifier and target tenant keyed by the
//! CSRF `state`, so the callback can (a) validate the state and (b) complete
//! the exchange without keeping the verifier in the browser URL.
//!
//! Flows are persisted (verifier encrypted at rest with the master key) so a
//! consent URL survives process or container restarts — the classic pitfall of
//! an in-memory registry, where a restart between link generation and the
//! callback rejects the state. Expired rows are purged opportunistically.

use oauth2::PkceCodeVerifier;

use crate::storage::crypto::{decrypt, encrypt};
use crate::storage::db::Database;

/// How long an uncompleted flow stays valid (seconds).
const FLOW_TTL_SECS: i64 = 600;

/// Everything needed to complete a flow once the callback arrives.
pub struct PendingFlow {
    /// PKCE verifier paired with the code challenge sent to the browser.
    pub verifier: PkceCodeVerifier,
    /// Tenant that will own the account.
    pub tenant_id: String,
    /// Unix timestamp (seconds) when the flow was created.
    pub created_at: i64,
}

/// Errors returned when resolving a pending flow.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("unknown or already-used state")]
    UnknownState,
    #[error("authorization flow expired")]
    Expired,
    #[error("flow storage error: {0}")]
    Storage(String),
}

/// Registry of pending flows, keyed by CSRF state, persisted in SQLite.
#[derive(Clone)]
pub struct FlowStore {
    db: Database,
    key: [u8; 32],
}

impl FlowStore {
    /// Create a flow store backed by `db`; verifiers are encrypted with `key`.
    pub fn new(db: Database, key: [u8; 32]) -> Self {
        Self { db, key }
    }

    /// Record a pending flow under the CSRF `state` that was embedded in the
    /// consent URL (the provider echoes this exact value back on callback).
    pub fn insert(&self, verifier: PkceCodeVerifier, tenant_id: String, state: String) {
        let created_at = unix_now();
        let verifier_blob = encrypt(&self.key, verifier.secret().as_bytes())
            .expect("AES-256-GCM encryption cannot fail with a valid key");

        let conn = self.db.lock().expect("database lock poisoned");
        // Opportunistic cleanup of expired flows keeps the table small.
        let _ = conn.execute(
            "DELETE FROM oauth_flows WHERE created_at <= ?1",
            [created_at - FLOW_TTL_SECS],
        );
        let _ = conn.execute(
            "INSERT INTO oauth_flows (state, verifier, tenant_id, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![state, verifier_blob, tenant_id, created_at],
        );
    }

    /// Remove and return a pending flow, rejecting unknown or expired states.
    pub fn take(&self, state: &str) -> Result<PendingFlow, FlowError> {
        let conn = self
            .db
            .lock()
            .map_err(|_| FlowError::Storage("database lock poisoned".into()))?;

        let (verifier_blob, tenant_id, created_at) = conn
            .query_row(
                "SELECT verifier, tenant_id, created_at FROM oauth_flows WHERE state = ?1",
                [state],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => FlowError::UnknownState,
                e => FlowError::Storage(e.to_string()),
            })?;

        // Consume the flow: a state is single-use.
        conn.execute("DELETE FROM oauth_flows WHERE state = ?1", [state])
            .map_err(|e| FlowError::Storage(e.to_string()))?;

        if unix_now().saturating_sub(created_at) > FLOW_TTL_SECS {
            return Err(FlowError::Expired);
        }

        let verifier = decrypt(&self.key, &verifier_blob)
            .map_err(|e| FlowError::Storage(format!("decrypt verifier: {e}")))?;
        let verifier = String::from_utf8(verifier)
            .map_err(|e| FlowError::Storage(format!("verifier is not valid UTF-8: {e}")))?;

        Ok(PendingFlow {
            verifier: PkceCodeVerifier::new(verifier),
            tenant_id,
            created_at,
        })
    }
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Database;

    fn store() -> FlowStore {
        FlowStore::new(Database::open_in_memory().unwrap(), [7u8; 32])
    }

    #[test]
    fn round_trip() {
        let store = store();
        store.insert(
            PkceCodeVerifier::new("verifier-123".into()),
            "tenant-a".into(),
            "state-123".into(),
        );
        let flow = store.take("state-123").unwrap();
        assert_eq!(flow.verifier.secret(), "verifier-123");
        assert_eq!(flow.tenant_id, "tenant-a");
    }

    #[test]
    fn unknown_state_rejected() {
        let store = store();
        assert!(matches!(store.take("nope"), Err(FlowError::UnknownState)));
    }

    #[test]
    fn state_is_single_use() {
        let store = store();
        store.insert(PkceCodeVerifier::new("v".into()), "t".into(), "s".into());
        store.take("s").unwrap();
        assert!(matches!(store.take("s"), Err(FlowError::UnknownState)));
    }

    #[test]
    fn flow_survives_store_reopen() {
        // A fresh FlowStore over the same database resolves the pending flow:
        // consent URLs survive process/container restarts.
        let db = Database::open_in_memory().unwrap();
        FlowStore::new(db.clone(), [7u8; 32]).insert(
            PkceCodeVerifier::new("v".into()),
            "t".into(),
            "s".into(),
        );
        let flow = FlowStore::new(db, [7u8; 32]).take("s").unwrap();
        assert_eq!(flow.verifier.secret(), "v");
    }

    #[test]
    fn expired_flow_rejected() {
        let db = Database::open_in_memory().unwrap();
        let store = FlowStore::new(db, [7u8; 32]);
        store.insert(PkceCodeVerifier::new("v".into()), "t".into(), "s".into());
        let conn = store.db.lock().unwrap();
        conn.execute(
            "UPDATE oauth_flows SET created_at = ?1",
            [unix_now() - FLOW_TTL_SECS - 1],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(store.take("s"), Err(FlowError::Expired)));
    }
}