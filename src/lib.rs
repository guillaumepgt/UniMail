//! UniMail — unified inbox SaaS core library.
//!
//! The crate is organised into provider-agnostic layers so the product can be
//! extended (and later sold) without hardwiring Microsoft-specific logic into
//! the storage or API surfaces:
//!
//! - [`config`] — environment-driven configuration.
//! - [`error`] — shared error type.
//! - [`storage`] — SQLite persistence (accounts + encrypted tokens).
//! - [`auth`] — OAuth 2.0 (Authorization Code + PKCE) and token management.
//! - [`provider`] — provider-agnostic email abstractions + Microsoft Graph impl.
//! - [`api`] — Axum REST API.
//! - [`mcp`] — Model Context Protocol server (rmcp).
//! - [`cli`] — command-line interface (clap).

pub mod api;
pub mod auth;
pub mod cli;
pub mod config;
pub mod error;
pub mod mcp;
pub mod provider;
pub mod storage;

pub use config::Config;
pub use error::{AppError, Result};
