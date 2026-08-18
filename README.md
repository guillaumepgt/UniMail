# UniMail

UniMail centralises 100+ **personal** Microsoft accounts (Hotmail / Outlook.com)
into a single unified inbox, exposed through a **REST API** and an **MCP
(Model Context Protocol) server** for AI agents.

It is designed as a sellable, multi-tenant SaaS: a provider-agnostic core
(Microsoft today, but the storage and API layers are not hardwired to it),
per-tenant data isolation via API keys, encrypted tokens at rest, and a clean
layered architecture.

---

## Features

- **One unified inbox** — aggregate every connected account into a single,
  date-sorted feed, each message tagged with its owning account.
- **OAuth 2.0 Authorization Code + PKCE** against the Microsoft identity
  platform `/common` authority (personal accounts — no app-only auth).
- **Encrypted storage** — refresh/access tokens are AES-256-GCM encrypted in
  SQLite using a master key from `.env`.
- **Restart-proof OAuth flows** — pending PKCE flows (state + verifier) are
  persisted in SQLite (verifier encrypted at rest), so a consent URL keeps
  working across process/container restarts (10-minute TTL).
- **Automatic refresh** — access tokens are refreshed transparently on expiry
  and on Graph `401`s; a background task renews accounts idle past a configurable
  threshold (default 90 days).
- **REST API** (Axum) with API-key auth and per-tenant scoping.
- **MCP server** (official Rust SDK — `rmcp`) sharing the same token storage.
- **CLI** for connecting/removing accounts and refreshing tokens.
- **Docker-ready**, with structured logging (`tracing`) and typed errors.

## Architecture

```
src/
├── auth/       OAuth2 (PKCE) client, token manager, local callback server
├── provider/   provider-agnostic EmailProvider trait + Microsoft Graph impl
├── storage/    SQLite persistence (accounts + AES-256-GCM encrypted tokens)
├── api/        Axum REST API (routes, API-key middleware, app state)
├── mcp/        MCP server over stdio (rmcp)
├── cli/        clap subcommands + background refresh task
├── config.rs   environment-driven configuration
├── error.rs    shared error type
└── main.rs     binary entry point
```

`EmailProvider` is the extension seam: the REST API and MCP server depend only on
that trait, so a Gmail/IMAP provider can be added without touching either layer.
The storage schema stores only a `provider` discriminator string and an opaque
`scope` — nothing Microsoft-specific.

## Prerequisites

- Rust (stable, 1.80+) — `rustup` recommended.
- An Azure Entra ID app registration with **Supported account types =
  "Accounts in any organizational directory and personal Microsoft accounts"**
  (`signInAudience: "AzureADandPersonalMicrosoftAccount"` — **not** the
  personal-only audience, which the `/consumers` endpoint rejects), with:
  - Platform: **Web**, Redirect URI: `http://localhost`
  - Delegated permissions: `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`,
    `User.Read`, `offline_access`, `openid`, `profile`, `email`
  - A client secret (Web apps are confidential clients).

> ⚠️ Personal (consumer) accounts **cannot** use app-only/client-credentials
> auth. Every account must complete an interactive consent popup once.

## Install & configure

```bash
git clone <this-repo> && cd <this-repo>
cp .env.example .env
# fill in CLIENT_ID, CLIENT_SECRET, and ENCRYPTION_KEY
```

Generate a 32-byte encryption key:

```bash
openssl rand -hex 32   # paste the 64 hex chars into ENCRYPTION_KEY
```

`.env` highlights:

| Variable                | Purpose                                              |
| ----------------------- | ---------------------------------------------------- |
| `CLIENT_ID`             | Azure app (client) id                                |
| `CLIENT_SECRET`         | Azure app client secret                              |
| `REDIRECT_URI`          | Must match Azure exactly (default `http://localhost`) |
| `ENCRYPTION_KEY`        | 32 bytes (64 hex chars) for AES-256-GCM token crypto |
| `DATABASE_PATH`         | SQLite file path (default `./unimail.db`)            |
| `API_KEYS`              | Comma-separated `key=tenant` pairs (see below)       |
| `DEFAULT_TENANT_ID`     | Tenant for keys/accounts without an explicit tenant  |
| `API_BIND_ADDR`         | REST API listen address (default `0.0.0.0:8080`)     |
| `CALLBACK_BIND_ADDR`    | OAuth callback bind address (default: derived from `REDIRECT_URI`; set `0.0.0.0:80` in Docker) |
| `TOKEN_INACTIVITY_DAYS` | Renew idle accounts after N days (default 90)        |
| `REFRESH_INTERVAL_SECS` | Background refresh period (default 21600)            |

## Commands

```bash
cargo run -- add-account              # open the consent popup, store the account
cargo run -- list-accounts            # list connected accounts
cargo run -- remove-account <id|email># remove an account + its token
cargo run -- refresh-all              # refresh every account's token
cargo run -- serve                    # start the REST API (and callback server)
cargo run -- mcp                      # start the MCP server over stdio
```

`add-account` opens your browser, shows Microsoft's consent screen, and a local
server bound to `REDIRECT_URI` captures the authorization code, exchanges it for
tokens (PKCE), fetches the profile via Graph `/me`, and stores the account.

## REST API

Start the server:

```bash
cargo run -- serve
```

Auth: send `Authorization: Bearer <key>` or `X-API-Key: <key>`. If `API_KEYS` is
empty the API is **open** (dev mode, scoped to `DEFAULT_TENANT_ID`). Set
`API_KEYS` before exposing it.

| Method   | Path                                   | Description                                   |
| -------- | -------------------------------------- | --------------------------------------------- |
| `GET`    | `/accounts`                            | List connected accounts                       |
| `POST`   | `/accounts/connect`                    | Start OAuth flow → `{ "auth_url": "…" }`      |
| `DELETE` | `/accounts/{id}`                       | Disconnect an account                         |
| `GET`    | `/accounts/{id}/emails?limit=&query=`  | List emails (Graph `GET /me/messages`)        |
| `GET`    | `/accounts/{id}/emails/{messageId}`    | Read one email                                |
| `POST`   | `/accounts/{id}/send`                  | Send `{ "to", "subject", "body" }`            |
| `GET`    | `/unified/inbox?limit=`                | Aggregate every account's inbox               |
| `GET`    | `/health`                              | Liveness probe                                |

Examples:

```bash
# Connect an account (returns an auth_url to open in a browser)
curl -X POST localhost:8080/accounts/connect

# Read the unified inbox
curl -H "Authorization: Bearer $API_KEY" "localhost:8080/unified/inbox?limit=25"

# List emails for one account
curl -H "Authorization: Bearer $API_KEY" "localhost:8080/accounts/$ID/emails?limit=10&query=invoice"

# Send an email
curl -X POST -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"to":"friend@example.com","subject":"hi","body":"hello"}' \
  localhost:8080/accounts/$ID/send
```

## MCP server

The MCP server exposes the same data as the API (same SQLite database) over
stdio, for use with Claude Desktop, Cursor, and other MCP clients:

- `list_accounts()`
- `list_emails(account, limit=20)`
- `search_emails(account, query)`
- `read_email(account, message_id)`
- `send_email(account, to, subject, body)`
- `unified_inbox(limit=50)`

`account` may be an account id or an email address. Tools are scoped to
`DEFAULT_TENANT_ID`.

Example client registration (Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "unimail": {
      "command": "cargo",
      "args": ["run", "--release", "--manifest-path", "/path/to/unimail/Cargo.toml", "--", "mcp"],
      "env": {
        "CLIENT_ID": "…",
        "CLIENT_SECRET": "…",
        "ENCRYPTION_KEY": "…",
        "DATABASE_PATH": "/path/to/unimail.db",
        "RUST_LOG": "unimail=warn"
      }
    }
  }
}
```

For a prebuilt binary, point `command` at `target/release/unimail` with
`"args": ["mcp"]`.

### MCP SDK choice & limitations

UniMail uses **`rmcp` 3.x** — the *official* Rust Model Context Protocol SDK
(moved under `modelcontextprotocol/rust-sdk`). It is the most mature, actively
maintained Rust MCP implementation. Known limitations to be aware of:

- The API is still evolving across minor versions, and the repository `main`
  branch's docs occasionally describe a newer API than the released crate. We
  **pin the version** via `Cargo.lock` (3.1.2) and target that exact API.
- This server uses the **stdio** transport only. `rmcp` also supports
  streamable-HTTP/SSE transports behind feature flags, but those are not
  enabled here to keep the default build minimal.
- The server negotiates protocol version `2025-11-25` (stable release);
  clients on that version work out of the box.

## Docker

```bash
docker build -t unimail .
docker run --rm -it -p 8080:8080 -v unimail-data:/data \
  -e CLIENT_ID=… -e CLIENT_SECRET=… -e ENCRYPTION_KEY=… \
  unimail serve
```

**Loopback-callback note:** OAuth consent redirects the *browser* to
`REDIRECT_URI` (`http://localhost`). For `POST /accounts/connect` to complete
inside a container, map the callback port to the host too (`-p 80:80`), keep
`REDIRECT_URI=http://localhost`, and set `CALLBACK_BIND_ADDR=0.0.0.0:80`
(already done in `docker-compose.yml` / the Dockerfile). Without that override
the callback binds to the container's loopback only, which docker-proxy cannot
reach — `POST /accounts/connect` returns an `auth_url` but the redirect dead-ends.
Alternatively, connect accounts with `unimail add-account` on the host machine
against the same `DATABASE_PATH`, and let the container only serve the API/MCP.

## Multi-tenancy

Accounts are scoped by `tenant_id` in the database. API keys map to tenants via
`API_KEYS=key=tenant`:

```
API_KEYS=sk-tenant-a=tenant-a,sk-tenant-b=tenant-b
DEFAULT_TENANT_ID=default
```

A bare key (no `=`) maps to `DEFAULT_TENANT_ID`. The API middleware resolves the
key to a tenant and scopes every query accordingly. For a fully isolated,
multi-tenant SaaS deployment you would additionally separate databases (or add a
tenant column to every table — the schema already carries `tenant_id`).

## Security notes

- Tokens are AES-256-GCM encrypted at rest with a fresh random nonce per write;
  a stolen database is useless without `ENCRYPTION_KEY`.
- No secrets are hard-coded; everything comes from `.env`.
- PKCE + CSRF `state` validation is enforced on every authorization flow.
- OAuth HTTP requests disable redirects to avoid token exfiltration.
- Set `API_KEYS` before exposing the API; the open-by-default mode is for local
  development only.

## Testing

```bash
cargo test        # unit tests: crypto, token storage, unified-inbox aggregation
cargo clippy      # lint
```

## Error handling

- Expired/revoked access tokens → transparent refresh via the refresh token.
- A refresh token that Microsoft rejects (e.g. revoked consent) → clear
  `authentication expired` error; reconnect the account with `add-account`.
- Disconnected accounts are kept in the DB with `status=disconnected` and no
  token, and are excluded from the unified inbox.
