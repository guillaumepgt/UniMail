//! Command-line interface (clap).
//!
//! Subcommands: `add-account`, `list-accounts`, `remove-account`,
//! `refresh-all`, plus `serve` (REST API) and `mcp` (MCP server over stdio).

use std::sync::Arc;

use clap::{Parser, Subcommand};

use crate::api::{self, AppState};
use crate::auth::{callback_router, serve_callback_once};
use crate::config::Config;
use crate::error::{AppError, Result};

#[derive(Parser)]
#[command(
    name = "unimail",
    version,
    about = "Unified inbox for personal Microsoft accounts (REST API + MCP server)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Connect a new personal Microsoft account via the consent popup.
    AddAccount {
        /// Tenant id to own the account (defaults to DEFAULT_TENANT_ID).
        #[arg(long)]
        tenant: Option<String>,
    },
    /// List connected accounts.
    ListAccounts {
        /// Restrict to a tenant (defaults to DEFAULT_TENANT_ID).
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Remove an account (by id or email address) and its stored token.
    RemoveAccount {
        /// Account id or email address.
        account: String,
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Refresh tokens for every connected account.
    RefreshAll,
    /// Start the REST API server.
    Serve,
    /// Start the MCP server over stdio.
    Mcp,
}

/// Entry point: load config, build state, dispatch to the subcommand.
pub async fn run() -> Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let cli = Cli::parse();
    let config = Config::from_env()?;
    let state = Arc::new(AppState::build(config)?);

    match cli.command {
        Command::AddAccount { tenant } => add_account(&state, tenant.as_deref()).await,
        Command::ListAccounts { tenant } => list_accounts(&state, tenant.as_deref()),
        Command::RemoveAccount { account, tenant } => {
            remove_account(&state, &account, tenant.as_deref())
        }
        Command::RefreshAll => refresh_all(&state).await,
        Command::Serve => serve(&state).await,
        Command::Mcp => crate::mcp::serve_stdio(state).await,
    }
}

/// Connect a new account: open the consent popup and capture the redirect.
async fn add_account(state: &Arc<AppState>, tenant: Option<&str>) -> Result<()> {
    let tenant_id = tenant
        .map(str::to_string)
        .unwrap_or_else(|| state.config.default_tenant_id.clone());

    let auth_url = state.token_manager.begin_flow(&tenant_id)?;
    println!("Opening your browser to sign in to Microsoft...\n");
    println!("If it does not open automatically, visit:\n{auth_url}\n");

    open_browser(auth_url.as_str());

    let (host, port) = state.config.callback_addr()?;
    let addr: std::net::SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| AppError::Config(format!("invalid callback address {host}:{port}: {e}")))?;

    let account = serve_callback_once(state.token_manager.clone(), addr).await?;
    println!(
        "✅ Connected {} ({})",
        account.email_address,
        account.display_name.as_deref().unwrap_or("no display name")
    );
    Ok(())
}

fn list_accounts(state: &Arc<AppState>, tenant: Option<&str>) -> Result<()> {
    let tenant_id = tenant
        .map(str::to_string)
        .unwrap_or_else(|| state.config.default_tenant_id.clone());
    let accounts = state.accounts.list(&tenant_id)?;
    if accounts.is_empty() {
        println!("No connected accounts.");
        return Ok(());
    }
    for account in accounts {
        println!(
            "{}\t{}\t{}\t{}",
            account.id, account.email_address, account.status.as_str(), account.updated_at
        );
    }
    Ok(())
}

fn remove_account(state: &Arc<AppState>, account: &str, tenant: Option<&str>) -> Result<()> {
    let tenant_id = tenant
        .map(str::to_string)
        .unwrap_or_else(|| state.config.default_tenant_id.clone());

    let resolved = match state.accounts.get(&tenant_id, account) {
        Ok(a) => a,
        Err(_) => state.accounts.get_by_email(&tenant_id, account)?,
    };

    state.accounts.delete(&tenant_id, &resolved.id)?;
    println!("Removed account {}", resolved.email_address);
    Ok(())
}

async fn refresh_all(state: &Arc<AppState>) -> Result<()> {
    let outcomes = state.token_manager.refresh_all().await;
    for (account, result) in outcomes {
        match result {
            Ok(()) => println!("✅ refreshed {}", account.email_address),
            Err(e) => println!("❌ {} — {e}", account.email_address),
        }
    }
    Ok(())
}

/// Start the REST API, the OAuth callback listener, and the refresh loop.
async fn serve(state: &Arc<AppState>) -> Result<()> {
    let api_addr: std::net::SocketAddr = state.config.api_bind_addr.parse().map_err(|e| {
        AppError::Config(format!("invalid API_BIND_ADDR '{}': {e}", state.config.api_bind_addr))
    })?;

    // 1. Persistent OAuth callback listener for POST /accounts/connect.
    let (cb_host, cb_port) = state.config.callback_addr()?;
    let cb_addr: std::net::SocketAddr = format!("{cb_host}:{cb_port}")
        .parse()
        .map_err(|e| AppError::Config(format!("invalid callback address: {e}")))?;
    let cb_router = callback_router(state.token_manager.clone());
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(cb_addr).await {
            Ok(listener) => {
                tracing::info!(%cb_addr, "OAuth callback listener started");
                if let Err(e) = axum::serve(listener, cb_router).await {
                    tracing::error!(error = %e, "OAuth callback listener failed");
                }
            }
            Err(e) => {
                tracing::warn!(
                    %cb_addr, error = %e,
                    "could not bind OAuth callback listener; POST /accounts/connect will not complete"
                );
            }
        }
    });

    // 2. Background token refresh task.
    let refresh_state = state.clone();
    tokio::spawn(async move { refresh_loop(refresh_state).await });

    // 3. REST API.
    let app = api::router(state.clone());
    let listener = tokio::net::TcpListener::bind(api_addr)
        .await
        .map_err(|e| AppError::Io(std::io::Error::new(e.kind(), format!("bind {api_addr}: {e}"))))?;
    tracing::info!(%api_addr, "REST API listening");
    axum::serve(listener, app)
        .await
        .map_err(|e| AppError::Io(std::io::Error::new(e.kind(), e.to_string())))
}

/// Periodically renew tokens for accounts idle past the inactivity threshold.
async fn refresh_loop(state: Arc<AppState>) {
    let interval = std::time::Duration::from_secs(state.config.refresh_interval_secs.max(60));
    loop {
        let refreshed = state
            .token_manager
            .refresh_stale(state.config.token_inactivity_days)
            .await;
        tracing::info!(accounts_refreshed = refreshed, "background token refresh finished");
        tokio::time::sleep(interval).await;
    }
}

/// Initialise the tracing subscriber (RUST_LOG).
///
/// Logs are written to **stderr** so they never corrupt the MCP stdio protocol,
/// which uses stdout for JSON-RPC frames.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("unimail=info,tower_http=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Try to open the consent URL in a browser; the URL is always printed too.
fn open_browser(url: &str) {
    #[cfg(target_os = "linux")]
    const OPENERS: [&str; 2] = ["xdg-open", "sensible-browser"];
    #[cfg(target_os = "macos")]
    const OPENERS: [&str; 1] = ["open"];
    #[cfg(target_os = "windows")]
    const OPENERS: [&str; 2] = ["cmd", "start"];
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    const OPENERS: [&str; 0] = [];

    for opener in OPENERS {
        let mut cmd = std::process::Command::new(opener);
        #[cfg(target_os = "windows")]
        {
            cmd.arg("/C").arg("start");
        }
        cmd.arg(url);
        if cmd.spawn().is_ok() {
            return;
        }
    }
}
