//! Environment-driven configuration.
//!
//! All settings come from environment variables (loaded from `.env` by the
//! binary via [`dotenvy`]). Secrets are never hard-coded. See `.env.example`.

use std::collections::HashMap;

use base64::Engine as _;

use crate::error::{AppError, Result};

/// Microsoft identity platform endpoints for **personal (consumer) accounts**.
///
/// Personal accounts MUST use the `consumers` authority — not `/common` and not
/// a tenant id. App-only access is impossible for consumer accounts; every
/// account must go through an interactive consent popup.
const CONSUMERS_AUTH_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const CONSUMERS_TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";

/// Microsoft Graph base URL.
const GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";

/// Application configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// OAuth client id from the Azure Entra ID app registration.
    pub client_id: String,
    /// OAuth client secret (confidential "Web" app).
    pub client_secret: String,
    /// Redirect URI registered in Azure. The local callback server binds here.
    pub redirect_uri: String,
    /// Microsoft OAuth2 authorization endpoint.
    pub auth_url: String,
    /// Microsoft OAuth2 token endpoint.
    pub token_url: String,
    /// Microsoft Graph base URL.
    pub graph_base_url: String,
    /// 32-byte AES-256-GCM master key used to encrypt tokens at rest.
    pub encryption_key: [u8; 32],
    /// Path to the SQLite database.
    pub database_path: String,
    /// Map of API key -> tenant id.
    pub api_keys: HashMap<String, String>,
    /// Tenant id for accounts created without an explicit tenant.
    pub default_tenant_id: String,
    /// Address the REST API binds to.
    pub api_bind_addr: String,
    /// Refresh tokens unused for longer than this many days are renewed in the
    /// background so accounts stay connected.
    pub token_inactivity_days: i64,
    /// Period (seconds) between background refresh runs.
    pub refresh_interval_secs: u64,
}

impl Config {
    /// Load configuration from the environment.
    pub fn from_env() -> Result<Self> {
        let client_id = env("CLIENT_ID")?;
        let client_secret = env("CLIENT_SECRET")?;
        let redirect_uri = env("REDIRECT_URI").unwrap_or_else(|_| "http://localhost".to_string());

        let encryption_key = parse_key(&env("ENCRYPTION_KEY")?)?;

        let api_keys = parse_api_keys(env("API_KEYS").unwrap_or_default());

        Ok(Self {
            client_id,
            client_secret,
            redirect_uri,
            auth_url: env("AUTH_URL").unwrap_or_else(|_| CONSUMERS_AUTH_URL.to_string()),
            token_url: env("TOKEN_URL").unwrap_or_else(|_| CONSUMERS_TOKEN_URL.to_string()),
            graph_base_url: env("GRAPH_BASE_URL").unwrap_or_else(|_| GRAPH_BASE_URL.to_string()),
            encryption_key,
            database_path: env("DATABASE_PATH").unwrap_or_else(|_| "./unimail.db".to_string()),
            api_keys,
            default_tenant_id: env("DEFAULT_TENANT_ID").unwrap_or_else(|_| "default".to_string()),
            api_bind_addr: env("API_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            token_inactivity_days: env("TOKEN_INACTIVITY_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90),
            refresh_interval_secs: env("REFRESH_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(21600),
        })
    }

    /// Resolve the tenant id for a given API key, if the key is registered.
    pub fn tenant_for_key(&self, key: &str) -> Option<&str> {
        self.api_keys.get(key).map(|s| s.as_str())
    }

    /// Host/port the callback server should bind to, derived from the redirect
    /// URI so it always matches what Azure sends the browser back to.
    pub fn callback_addr(&self) -> Result<(String, u16)> {
        let url = oauth2::RedirectUrl::new(self.redirect_uri.clone())
            .map_err(|e| AppError::Config(format!("invalid REDIRECT_URI: {e}")))?;
        let host = url
            .url()
            .host_str()
            .map(|h| h.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let port = url
            .url()
            .port()
            .or_else(|| match url.url().scheme() {
                "https" => Some(443),
                _ => Some(80),
            })
            .unwrap_or(80);
        // "localhost" resolves to both v4/v6; bind explicitly for reliability.
        let bind_host = if host == "localhost" { "127.0.0.1".to_string() } else { host };
        Ok((bind_host, port))
    }
}

/// Read a required environment variable.
fn env(key: &str) -> Result<String> {
    std::env::var(key)
        .map_err(|_| AppError::Config(format!("missing required environment variable {key}")))
        .and_then(|v| {
            if v.trim().is_empty() {
                Err(AppError::Config(format!(
                    "environment variable {key} is empty"
                )))
            } else {
                Ok(v)
            }
        })
}

/// Parse a 32-byte key from a 64-char hex string (or raw 32-byte base64).
fn parse_key(raw: &str) -> Result<[u8; 32]> {
    let raw = raw.trim();
    if raw.len() == 64 {
        let mut out = [0u8; 32];
        hex_decode(raw, &mut out)
            .map_err(|_| AppError::Config("ENCRYPTION_KEY must be 64 hex characters".into()))?;
        return Ok(out);
    }
    // Fallback: allow a raw 32-byte key supplied as standard base64.
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw) {
        if decoded.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            return Ok(out);
        }
    }
    Err(AppError::Config(
        "ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars or base64)".into(),
    ))
}

fn hex_decode(input: &str, out: &mut [u8]) -> std::result::Result<(), ()> {
    if input.len() != out.len() * 2 {
        return Err(());
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = input.as_bytes()[i * 2];
        let lo = input.as_bytes()[i * 2 + 1];
        *byte = (hex_val(hi)? << 4) | hex_val(lo)?;
    }
    Ok(())
}

fn hex_val(c: u8) -> std::result::Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

/// Parse `API_KEYS` into a key -> tenant map.
///
/// Entries are comma-separated. `key=tenant` maps a key to a tenant; a bare
/// `key` maps to [`Config::default_tenant_id`] at lookup time (stored as "").
fn parse_api_keys(raw: String) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match part.split_once('=') {
            Some((key, tenant)) => {
                map.insert(key.trim().to_string(), tenant.trim().to_string());
            }
            None => {
                map.insert(part.to_string(), String::new());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_key() {
        let key = "00".repeat(32);
        let parsed = parse_key(&key).unwrap();
        assert_eq!(parsed, [0u8; 32]);
    }

    #[test]
    fn parse_key_rejects_bad_length() {
        assert!(parse_key("abcd").is_err());
        assert!(parse_key(&"00".repeat(31)).is_err());
    }

    #[test]
    fn api_keys_parse() {
        let map = parse_api_keys("sk-a=tenant-1, sk-b ,sk-c=tenant-2".into());
        assert_eq!(map.get("sk-a").unwrap(), "tenant-1");
        assert_eq!(map.get("sk-b").unwrap(), "");
        assert_eq!(map.get("sk-c").unwrap(), "tenant-2");
    }
}
