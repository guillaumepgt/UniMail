//! API-key authentication and tenant resolution middleware.
//!
//! Requests are authenticated with a bearer token (`Authorization: Bearer …`)
//! or an `X-API-Key` header. Each key maps to a tenant id (see `API_KEYS` in
//! `.env.example`), which is attached to the request as a [`Tenant`] extension
//! so handlers can scope all queries per tenant.
//!
//! For local single-user use, if `API_KEYS` is empty the API is unauthenticated
//! and every request is scoped to `DEFAULT_TENANT_ID`. Set `API_KEYS` before
//! exposing the service.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::api::state::AppState;
use crate::config::Config;

/// Tenant id attached to authenticated requests.
#[derive(Debug, Clone)]
pub struct Tenant(pub String);

/// Middleware that validates the API key and resolves the tenant.
pub async fn api_key_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let key = extract_api_key(&request);
    match resolve_tenant(&state.config, key.as_deref()) {
        Some(tenant) => {
            request.extensions_mut().insert(Tenant(tenant));
            next.run(request).await
        }
        None => (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "invalid or missing API key" })),
        )
            .into_response(),
    }
}

/// Extract the API key from the `Authorization` or `X-API-Key` header.
fn extract_api_key(request: &Request) -> Option<String> {
    if let Some(value) = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(key) = value.strip_prefix("Bearer ") {
            return Some(key.trim().to_string());
        }
    }
    request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// Resolve the tenant for an API key, honouring the "open in dev" default.
fn resolve_tenant(config: &Config, key: Option<&str>) -> Option<String> {
    if config.api_keys.is_empty() {
        // No keys configured: open API, default tenant.
        return Some(config.default_tenant_id.clone());
    }
    let key = key?;
    match config.api_keys.get(key) {
        Some(tenant) if tenant.is_empty() => Some(config.default_tenant_id.clone()),
        Some(tenant) => Some(tenant.clone()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_with(keys: &[(&str, &str)]) -> Config {
        let mut cfg = Config::test_default();
        cfg.api_keys = keys
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        cfg
    }

    #[test]
    fn open_when_no_keys_configured() {
        let cfg = Config::test_default();
        assert_eq!(resolve_tenant(&cfg, None).as_deref(), Some("default"));
    }

    #[test]
    fn maps_key_to_tenant() {
        let cfg = config_with(&[("sk-a", "tenant-a"), ("sk-b", "")]);
        assert_eq!(resolve_tenant(&cfg, Some("sk-a")).as_deref(), Some("tenant-a"));
        assert_eq!(resolve_tenant(&cfg, Some("sk-b")).as_deref(), Some("default"));
        assert_eq!(resolve_tenant(&cfg, Some("unknown")), None);
    }
}
