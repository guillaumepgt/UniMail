//! OAuth 2.0 (Authorization Code + PKCE) and token lifecycle management.
//!
//! The Microsoft-specific pieces (endpoints, scopes) live in [`oauth`]; the
//! token cache/refresh logic in [`token`] is provider-agnostic and works with
//! the storage traits and a [`ProfileResolver`].

pub mod callback;
pub mod oauth;
pub mod token;

pub use callback::{callback_router, serve_callback_once};
pub use oauth::{OAuthClient, TokenSet, SCOPES};
pub use crate::storage::flows::{FlowError, FlowStore, PendingFlow};
pub use token::{ProfileResolver, RefreshOutcome, ResolvedIdentity, TokenManager};
