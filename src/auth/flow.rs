//! In-memory registry of in-flight OAuth authorization flows.
//!
//! Each `begin_flow` records the PKCE verifier and target tenant keyed by the
//! CSRF `state`, so the callback can (a) validate the state and (b) complete
//! the exchange without keeping the verifier in the browser URL.
//!
//! This is intentionally in-memory: flows are short-lived and single-process.
//! A horizontally-scaled deployment would move this to a shared store (Redis).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use oauth2::PkceCodeVerifier;

/// How long an uncompleted flow stays valid (seconds).
const FLOW_TTL_SECS: u64 = 600;

/// Everything needed to complete a flow once the callback arrives.
pub struct PendingFlow {
    /// PKCE verifier paired with the code challenge sent to the browser.
    pub verifier: PkceCodeVerifier,
    /// Tenant that will own the account.
    pub tenant_id: String,
    /// Unix timestamp when the flow was created.
    pub created_at: u64,
}

/// Registry of pending flows, keyed by CSRF state. Flows are infrequent and
/// the critical section is tiny, so a plain `Mutex<HashMap>` is used.
#[derive(Clone, Default)]
pub struct FlowStore {
    pending: std::sync::Arc<Mutex<HashMap<String, PendingFlow>>>,
}

impl FlowStore {
    /// Record a pending flow and return a unique state string.
    pub fn insert(&self, verifier: PkceCodeVerifier, tenant_id: String) -> String {
        let state = uuid::Uuid::new_v4().to_string();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut pending = self.pending.lock().expect("flow store poisoned");
        pending.insert(
            state.clone(),
            PendingFlow {
                verifier,
                tenant_id,
                created_at,
            },
        );
        state
    }

    /// Remove and return a pending flow, rejecting unknown or expired states.
    pub fn take(&self, state: &str) -> Result<PendingFlow, FlowError> {
        let mut pending = self.pending.lock().expect("flow store poisoned");
        let entry = pending.remove(state).ok_or(FlowError::UnknownState)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(entry.created_at) > FLOW_TTL_SECS {
            return Err(FlowError::Expired);
        }
        Ok(entry)
    }
}

/// Errors returned when resolving a pending flow.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("unknown or already-used state")]
    UnknownState,
    #[error("authorization flow expired")]
    Expired,
}
