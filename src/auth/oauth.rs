//! OAuth 2.0 client for the Microsoft identity platform (personal accounts).
//!
//! Implements the Authorization Code + PKCE flow against the Microsoft
//! identity platform (`/common` authority). The client is a confidential
//! "Web" app, so the client secret is sent in the token request body
//! (`client_secret_post`).

use chrono::{DateTime, Utc};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, RedirectUrl, Scope, TokenUrl,
};
use oauth2::{TokenResponse as _};

use crate::config::Config;
use crate::error::{AppError, Result};

/// Scopes requested at consent time. `offline_access` yields a refresh token;
/// `User.Read` lets us resolve the account's email/name via Graph `/me`, and
/// the rest cover reading/sending mail.
pub const SCOPES: [&str; 8] = [
    "offline_access",
    "User.Read",
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "openid",
    "profile",
    "email",
];

/// The configured OAuth client (auth + token endpoints set).
type ConfiguredClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// A decrypted token set returned by the identity provider.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Option<Vec<String>>,
}

/// Microsoft-specific OAuth client.
#[derive(Clone)]
pub struct OAuthClient {
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl OAuthClient {
    /// Build the client from configuration.
    pub fn new(config: &Config, http: reqwest::Client) -> Self {
        Self {
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            auth_url: config.auth_url.clone(),
            token_url: config.token_url.clone(),
            redirect_uri: config.redirect_uri.clone(),
            http,
        }
    }

    /// Build a fully-configured `BasicClient`. `AuthType::RequestBody` is
    /// required by the Microsoft token endpoint (`client_secret_post`).
    fn client(&self) -> Result<ConfiguredClient> {
        let client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(self.auth_url.clone()).map_err(|e| {
                AppError::Config(format!("invalid AUTH_URL: {e}"))
            })?)
            .set_token_uri(TokenUrl::new(self.token_url.clone()).map_err(|e| {
                AppError::Config(format!("invalid TOKEN_URL: {e}"))
            })?)
            .set_redirect_uri(RedirectUrl::new(self.redirect_uri.clone()).map_err(|e| {
                AppError::Config(format!("invalid REDIRECT_URI: {e}"))
            })?)
            .set_auth_type(AuthType::RequestBody);
        Ok(client)
    }

    /// Begin the authorization flow: produce the consent URL the user opens in
    /// a browser, plus the PKCE verifier and CSRF state that must be retained
    /// until the callback arrives.
    pub fn authorize_url(&self) -> Result<(url::Url, PkceCodeVerifier, String)> {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let client = self.client()?;

        let mut request = client.authorize_url(CsrfToken::new_random);
        for scope in SCOPES {
            request = request.add_scope(Scope::new(scope.to_string()));
        }
        let (auth_url, csrf) = request.set_pkce_challenge(challenge).url();

        Ok((auth_url, verifier, csrf.secret().to_string()))
    }

    /// Exchange an authorization code for a token set.
    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: PkceCodeVerifier,
    ) -> Result<TokenSet> {
        let client = self.client()?;
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(verifier)
            .request_async(&self.http)
            .await
            .map_err(|e| AppError::Auth(format!("token exchange failed: {e}")))?;
        Ok(token_set_from(response))
    }

    /// Exchange a refresh token for a fresh token set.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenSet> {
        let client = self.client()?;
        let response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| AppError::TokenExpired(format!("refresh failed: {e}")))?;
        Ok(token_set_from(response))
    }
}

/// Map an oauth2 crate token response into our provider-agnostic [`TokenSet`].
fn token_set_from(
    response: oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
) -> TokenSet {
    let access_token = response.access_token().secret().to_string();
    let refresh_token = response.refresh_token().map(|t| t.secret().to_string());
    let expires_at = response.expires_in().map(|d| {
        Utc::now() + chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::hours(1))
    });
    let scopes = response
        .scopes()
        .map(|s| s.iter().map(|sc| sc.to_string()).collect());
    TokenSet {
        access_token,
        refresh_token,
        expires_at,
        scopes,
    }
}
