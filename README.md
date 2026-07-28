# msoffice-mcp

Microsoft Graph and Office 365 Management Activity MCP server built on the same operational skeleton as [skeleton-mcp](https://github.com/LesterAJohn/skeleton-mcp), but specialized for Microsoft Graph and Office 365 audit/activity retrieval.

This repository keeps the skeleton’s core guarantees:

- Multi-user token handling.
- Secret material stored in Vault.
- Configuration stored in Postgres.
- Mutating tools protected by `MCP_ADMIN_AUTH_KEY` when configured.
- Redacted output by default.

## What This Server Does

The server exposes the official Microsoft Graph MCP discovery/read tools plus dedicated shortcuts for common Graph families. It also exposes the Office 365 Management Activity API operations for subscriptions, content, notifications, and DLP-friendly-name lookup.

The generic request tools provide full coverage because any documented REST path can be called directly. The dedicated tools exist for higher-signal prompts, safer defaults, and clearer LLM guidance.

User access tokens are stored per user in Vault with default-user fallback. Non-secret runtime configuration is stored per user in Postgres.

## Architecture

Runtime flow:

1. `src/index.js` boots stdio mode.
2. `src/http/index.js` boots HTTP mode.
3. `src/config/env.js` loads and validates environment configuration.
4. `src/services/configStore.js` persists config in Postgres.
5. `src/services/vault.js` persists secrets in Vault with write retries.
6. `src/services/graph.js` resolves Graph tokens and executes Graph requests.
7. `src/mcp/server.js` registers tools and applies authorization, redaction, and error shaping.
8. `src/http/server.js` exposes MCP over HTTP with auth, limits, and access logging.
9. `src/start-both.js` runs stdio and HTTP as separate child processes.

## Tool Catalog

All tools return MCP text content containing JSON. Success payloads use the shape below:

```json
{
  "ok": true,
  "status": 200,
  "data": {}
}
```

Errors are returned with `isError=true` and the shape below:

```json
{
  "ok": false,
  "status": 401,
  "error": "Unauthorized: invalid authorizationKey for mutating API operation"
}
```

### graph_connection_info

Read-only. Low risk. Use it when you need the resolved base URLs, default user, admin-auth state, and storage model details. Do not use it when you need live Graph data or token metadata. No prerequisites.

Example:

```json
{
  "name": "graph_connection_info",
  "arguments": {}
}
```

### graph_scope_info

Read-only. Low risk. Use it when you need to know which Vault path and Postgres scope a request will target. Do not use it when you only need the global runtime view. Optional `userId` defaults to `MCP_CONFIG_DEFAULT_USER_ID`.

Example:

```json
{
  "name": "graph_scope_info",
  "arguments": {
    "userId": "default"
  }
}
```

### graph_list_capabilities

Read-only. Low risk. Use it to inspect the Graph families this server curates. Do not use it for live data. No prerequisites.

### graph_health_check

Read-only. Low risk. Use it before operational calls to confirm the currently selected token can reach Graph. Do not use it for business data retrieval. Requires an active Graph token for the selected user.

### graph_api_request

Read-only or mutating depending on `method`. High risk for `POST`, `PUT`, `PATCH`, and `DELETE`. Use it when a dedicated tool does not exist or you need a beta or long-tail endpoint. Do not use it when a dedicated read or mutation tool already exists. Requires a valid active Graph token; mutating methods also require `authorizationKey` when `MCP_ADMIN_AUTH_KEY` is set.

Parameters:

- `method`: required string such as `GET` or `PATCH`.
- `path`: required relative Graph path.
- `query`: optional object of query parameters.
- `body`: optional JSON payload.
- `headers`: optional request headers.
- `userId`: optional user scope.
- `tokenId`: optional token selection.
- `useBetaBaseUrl`: optional boolean.
- `authorizationKey`: optional for mutating calls when admin auth is configured.

Example:

```json
{
  "name": "graph_api_request",
  "arguments": {
    "method": "GET",
    "path": "/users?$top=1"
  }
}
```

### Dedicated Read Tools

The dedicated read tools are `graph_me`, `graph_users_query`, `graph_groups_query`, `graph_mail_messages`, `graph_calendar_events`, `graph_drive_children`, `graph_security_alerts`, `graph_applications_query`, `graph_sites_query`, and `graph_devices_query`.

Use them when the intent is obvious and you want a narrower contract than the generic request tool. Each supports `userId` and `tokenId` selection where appropriate, plus common query fields like `top`, `select`, `filter`, `orderby`, `expand`, `search`, and `count`.

### graph_config_list, graph_config_get, graph_config_set, graph_config_delete

These tools manage non-secret Graph configuration in Postgres. Reads are low risk. `graph_config_set` and `graph_config_delete` are mutating and require `MCP_ADMIN_AUTH_KEY` when configured.

Use them for values such as Graph base URLs, default behaviors, or user-scoped runtime preferences. Do not use them for tokens or other secrets.

### graph_user_tokens_list, graph_user_token_upsert, graph_user_token_set_active, graph_user_token_delete

These tools manage multi-user Graph token state in Vault.

- `graph_user_tokens_list` is read-only and returns metadata only.
- `graph_user_token_upsert` is mutating and stores secret material in Vault.
- `graph_user_token_set_active` toggles token state without deleting the secret.
- `graph_user_token_delete` is destructive and removes the secret and index entry.

All token mutation tools require `MCP_ADMIN_AUTH_KEY` when configured.

## Environment Variables

Core:

- `APP_NAME`
- `MCP_SERVER_NAME`
- `MCP_SERVER_VERSION`
- `MCP_ALLOW_SENSITIVE_OUTPUT`
- `MCP_ADMIN_AUTH_KEY`
- `MCP_TRANSPORT_MODE` (`stdio`, `http`, or `both`)
- `MCP_CONFIG_DEFAULT_USER_ID`
- `GRAPH_API_BASE_URL`
- `GRAPH_API_BETA_BASE_URL`
- `GRAPH_DEFAULT_SCOPE`
- `GRAPH_DEFAULT_USER_ID`
- `O365_API_BASE_URL`
- `O365_DEFAULT_TENANT_ID`
- `O365_DEFAULT_PUBLISHER_IDENTIFIER`
- `O365_DEFAULT_CONTENT_TYPE`

Postgres:

- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_SSL`

Vault:

- `VAULT_ADDR`
- `VAULT_TOKEN`
- `VAULT_KV_MOUNT`
- `VAULT_WRITE_RETRY_ATTEMPTS`
- `VAULT_WRITE_RETRY_BASE_DELAY_MS`
- `VAULT_WRITE_RETRY_MAX_DELAY_MS`

HTTP transport:

- `MCP_HTTP_HOST`
- `MCP_HTTP_PORT`
- `MCP_HTTP_PATH`
- `MCP_HTTP_HEALTH_PATH`
- `MCP_HTTP_AUTH_MODE`
- `MCP_HTTP_AUTH_TOKENS`
- `MCP_HTTP_TRUST_PROXY`
- `MCP_HTTP_ALLOWED_ORIGINS`
- `MCP_HTTP_ALLOWED_IPS`
- `MCP_HTTP_MAX_BODY_BYTES`
- `MCP_HTTP_RATE_LIMIT_WINDOW_MS`
- `MCP_HTTP_RATE_LIMIT_MAX_REQUESTS`
- `MCP_HTTP_TLS_ENABLED`
- `MCP_HTTP_TLS_CERT_PATH`
- `MCP_HTTP_TLS_KEY_PATH`

## Quick Start

1. Install dependencies with `npm install`.
2. Copy `.env.example` to `.env` and set your Graph, Postgres, and Vault values.
3. Start the local infrastructure with `docker compose up -d`.
4. Seed at least one user token with `graph_user_token_upsert` or your own Vault workflow.
5. Start the server with `npm run start:stdio` or `npm run start:http`.
6. Run tests with `npm test`.

## Local Infrastructure

The local compose stack runs Postgres and Vault for development. The app connects to those services and persists config in Postgres while storing secrets in Vault.

If you already manage Postgres and Vault elsewhere, use the external compose file instead of the local stack.

## Transport Modes

- `npm run start:stdio` starts the MCP server over stdio.
- `npm run start:http` starts the HTTP MCP endpoint.
- `npm run start:both` starts both transports as separate child processes.

## Office 365 Management Activity API

The Office 365 surface is tenant-scoped and uses the tenant ID in the root URL. The server supports the documented activity feed operations:

- `office365_activity_connection_info`
- `office365_activity_scope_info`
- `office365_activity_list_content_types`
- `office365_activity_list_subscriptions`
- `office365_activity_start_subscription`
- `office365_activity_stop_subscription`
- `office365_activity_list_available_content`
- `office365_activity_list_notifications`
- `office365_activity_get_content`
- `office365_activity_list_resource_friendly_names`
- `office365_activity_api_request`

Use `office365_activity_start_subscription` to begin collecting content for a tenant/content type. Use `office365_activity_list_available_content` to discover content blobs, `office365_activity_get_content` to retrieve the blob payload, and `office365_activity_list_notifications` to inspect webhook attempts.

The request tools enforce the documented time-window constraints for content and notification listing, and mutating subscription tools require `MCP_ADMIN_AUTH_KEY` when configured.

## Tests

Test coverage includes:

- Graph token storage and default-user fallback.
- Graph request construction and authorization headers.
- MCP tool authorization for mutation tools.
- Generic Graph request normalization.

## Registering The Server

For Codex, VS Code, or Claude Desktop, point the client at this repository and use the stdio command:

```json
{
  "command": "npm",
  "args": ["run", "start:stdio"],
  "cwd": "/Users/lesterjohn/Documents/GitHub/msoffice-mcp"
}
```

If you prefer HTTP, start `npm run start:http` and point the client at `http://127.0.0.1:3000/mcp`.
