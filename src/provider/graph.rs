//! Microsoft Graph implementation of [`EmailProvider`] and [`ProfileResolver`].
//!
//! Mail operations use the `https://graph.microsoft.com/v1.0/me/...` endpoints
//! with a delegated (user) bearer token. Every request goes through a token
//! cache that transparently refreshes, and a 401 triggers one retry after a
//! forced refresh. `$select`/`$top` are used to keep payloads (and therefore
//! Graph throttling risk) small.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;

use crate::auth::{ProfileResolver, ResolvedIdentity, TokenManager};
use crate::config::Config;
use crate::error::{AppError, Result};
use crate::provider::models::{Email, EmailAddress};
use crate::provider::EmailProvider;
use crate::storage::models::Account;

/// Fields requested from Graph for list results (smaller = fewer throttles).
const MESSAGE_SELECT: &str = "id,subject,from,toRecipients,bodyPreview,receivedDateTime,isRead";

/// Microsoft Graph mail provider.
pub struct MicrosoftGraph {
    http: reqwest::Client,
    base_url: String,
    tokens: Arc<TokenManager>,
}

impl MicrosoftGraph {
    /// Build the provider from config and a token manager.
    pub fn new(config: &Config, http: reqwest::Client, tokens: Arc<TokenManager>) -> Self {
        Self {
            http,
            base_url: config.graph_base_url.clone(),
            tokens,
        }
    }

    /// Send a request with the account's bearer token, retrying once after a
    /// forced refresh if Graph reports 401 (expired access token).
    async fn send_authorized(
        &self,
        account: &Account,
        method: Method,
        url: &url::Url,
        body: Option<Value>,
    ) -> Result<reqwest::Response> {
        let mut token = self.tokens.get_access_token(&account.id).await?;
        let mut response = self.send(method.clone(), url, &token, body.as_ref()).await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            tracing::info!(account_id = %account.id, "Graph returned 401; forcing token refresh");
            self.tokens.refresh_account(&account.id).await?;
            token = self.tokens.get_access_token(&account.id).await?;
            response = self.send(method, url, &token, body.as_ref()).await?;
        }
        Ok(response)
    }

    /// Low-level send: attach the bearer token and optional JSON body.
    async fn send(
        &self,
        method: Method,
        url: &url::Url,
        token: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::Response> {
        let mut request = self
            .http
            .request(method, url.clone())
            .bearer_auth(token)
            .header("Accept", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        Ok(request.send().await?)
    }

    /// Convert a response into JSON, mapping non-2xx to a readable provider
    /// error (extracting Graph's own `error.message` where possible).
    async fn to_json(&self, response: reqwest::Response) -> Result<Value> {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::Provider(format!(
                "Graph {status}: {}",
                graph_error_message(&text)
            )));
        }
        serde_json::from_str(&text).map_err(|e| AppError::Provider(format!("invalid Graph response: {e}")))
    }

    /// GET a URL as JSON, with 401-retry handling.
    async fn get_json(&self, account: &Account, url: &url::Url) -> Result<Value> {
        let response = self
            .send_authorized(account, Method::GET, url, None)
            .await?;
        self.to_json(response).await
    }
}

#[async_trait]
impl EmailProvider for MicrosoftGraph {
    async fn list_messages(
        &self,
        account: &Account,
        limit: usize,
        query: Option<&str>,
    ) -> Result<Vec<Email>> {
        let mut url = url::Url::parse(&format!("{}/me/messages", self.base_url))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("$top", &limit.to_string());
            q.append_pair("$select", MESSAGE_SELECT);
            match query {
                Some(qs) if !qs.trim().is_empty() => {
                    q.append_pair("$search", &format!("\"{}\"", qs.replace('"', "")));
                }
                _ => {
                    q.append_pair("$orderby", "receivedDateTime desc");
                }
            }
        }

        let json = self.get_json(account, &url).await?;
        let messages = json
            .get("value")
            .and_then(Value::as_array)
            .map(|v| v.iter().filter_map(graph_message_to_email).collect())
            .unwrap_or_default();
        Ok(messages)
    }

    async fn get_message(&self, account: &Account, message_id: &str) -> Result<Email> {
        let mut url = url::Url::parse(&format!("{}/me/messages/", self.base_url))?;
        url.path_segments_mut()
            .map_err(|_| AppError::InvalidRequest("invalid message id".into()))?
            .push(message_id);

        let json = self.get_json(account, &url).await?;
        graph_message_to_email(&json).ok_or_else(|| AppError::Provider("unexpected Graph message shape".into()))
    }

    async fn send_message(
        &self,
        account: &Account,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<()> {
        let url = url::Url::parse(&format!("{}/me/sendMail", self.base_url))?;
        let payload = serde_json::json!({
            "message": {
                "subject": subject,
                "body": { "contentType": "Text", "content": body },
                "toRecipients": [ { "emailAddress": { "address": to } } ]
            },
            "saveToSentItems": true
        });

        let response = self
            .send_authorized(account, Method::POST, &url, Some(payload))
            .await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Provider(format!(
                "send failed ({status}): {}",
                graph_error_message(&text)
            )));
        }
        Ok(())
    }
}

/// Resolves a freshly-consented account's identity via Graph `/me`.
pub struct GraphIdentityResolver {
    http: reqwest::Client,
    base_url: String,
}

impl GraphIdentityResolver {
    pub fn new(config: &Config, http: reqwest::Client) -> Self {
        Self {
            http,
            base_url: config.graph_base_url.clone(),
        }
    }
}

#[async_trait]
impl ProfileResolver for GraphIdentityResolver {
    async fn resolve(&self, access_token: &str) -> Result<ResolvedIdentity> {
        fetch_profile(&self.http, &self.base_url, access_token).await
    }
}

/// Fetch `/me` and extract email + display name (personal accounts return
/// `mail` or `userPrincipalName`).
async fn fetch_profile(
    http: &reqwest::Client,
    base_url: &str,
    access_token: &str,
) -> Result<ResolvedIdentity> {
    let url = url::Url::parse(&format!("{base_url}/me"))?;
    let response = http
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await?;

    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(AppError::Auth(format!(
            "could not fetch account profile ({status}): {}",
            graph_error_message(&text)
        )));
    }

    #[derive(Deserialize)]
    struct Profile {
        mail: Option<String>,
        #[serde(rename = "userPrincipalName")]
        user_principal_name: Option<String>,
        #[serde(rename = "displayName")]
        display_name: Option<String>,
    }

    let profile: Profile =
        serde_json::from_str(&text).map_err(|e| AppError::Auth(format!("invalid profile: {e}")))?;
    let email = profile
        .mail
        .or(profile.user_principal_name)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Auth("account profile did not include an email address".into()))?;

    Ok(ResolvedIdentity {
        email,
        display_name: profile.display_name,
    })
}

/// Extract Graph's `error.message` from an error response body.
fn graph_error_message(body: &str) -> String {
    if let Ok(json) = serde_json::from_str::<Value>(body) {
        if let Some(message) = json.get("error").and_then(|e| e.get("message")).and_then(Value::as_str) {
            return message.to_string();
        }
    }
    body.chars().take(300).collect()
}

// --- Graph -> provider-agnostic mapping -------------------------------------

#[derive(Debug, Deserialize)]
struct GraphMessage {
    id: String,
    subject: Option<String>,
    from: Option<GraphRecipient>,
    #[serde(rename = "toRecipients", default)]
    to_recipients: Vec<GraphRecipient>,
    #[serde(rename = "bodyPreview")]
    body_preview: Option<String>,
    body: Option<GraphBody>,
    #[serde(rename = "receivedDateTime")]
    received_date_time: Option<String>,
    #[serde(rename = "isRead", default)]
    is_read: bool,
}

#[derive(Debug, Deserialize)]
struct GraphRecipient {
    #[serde(rename = "emailAddress")]
    email_address: Option<GraphEmailAddress>,
}

#[derive(Debug, Deserialize)]
struct GraphEmailAddress {
    name: Option<String>,
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphBody {
    content: Option<String>,
}

fn graph_message_to_email(value: &Value) -> Option<Email> {
    let message: GraphMessage = serde_json::from_value(value.clone()).ok()?;
    Some(Email {
        id: message.id,
        subject: message.subject,
        from: message.from.and_then(|r| r.email_address).and_then(|a| {
            a.address.map(|address| EmailAddress { name: a.name, address })
        }),
        to: message
            .to_recipients
            .into_iter()
            .filter_map(|r| r.email_address)
            .filter_map(|a| a.address.map(|address| EmailAddress { name: a.name, address }))
            .collect(),
        body_preview: message.body_preview,
        body: message.body.and_then(|b| b.content),
        received_at: message.received_date_time,
        is_read: message.is_read,
    })
}
