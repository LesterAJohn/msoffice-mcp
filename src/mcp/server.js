import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { redactObject } from "../services/security.js";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function normalizeMethod(method) {
  return String(method ?? "GET").trim().toUpperCase();
}

function normalizePath(path) {
  const raw = String(path ?? "").trim();
  if (!raw) {
    return "/";
  }
  return raw.startsWith("/") ? raw : `/${raw}`;
}

function asText(value) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value, null, 2)
      }
    ]
  };
}

function createErrorPayload(error) {
  const status = Number(error?.status ?? error?.statusCode ?? 500);
  const message = error instanceof Error ? error.message : String(error);
  return { ok: false, status: Number.isFinite(status) ? status : 500, error: message };
}

function buildToolDescription({ summary, useWhen, doNotUseWhen, permissions, environment, parameters, response, failures, safety, examples }) {
  return [
    summary,
    `Use when: ${useWhen}`,
    `Do not use when: ${doNotUseWhen}`,
    `Required permissions/prerequisites: ${permissions}`,
    `Environment behavior: ${environment}`,
    `Parameters: ${parameters}`,
    `Expected response shape: ${response}`,
    `Common failures: ${failures}`,
    safety ? `Safety warning: ${safety}` : null,
    `Recommended prerequisite tools: ${examples.prerequisite}`,
    `Recommended follow-up tools: ${examples.followUp}`,
    examples.short ? `Example: ${examples.short}` : null
  ]
    .filter(Boolean)
    .join("\n");
}

function withErrorHandling(allowSensitiveOutput, handler) {
  return async (args) => {
    try {
      return asText(redactObject(await handler(args), allowSensitiveOutput));
    } catch (error) {
      return {
        ...asText(createErrorPayload(error)),
        isError: true
      };
    }
  };
}

function assertAuthorized(adminAuthKey, authorizationKey) {
  if (!adminAuthKey) {
    return;
  }

  if (!authorizationKey || authorizationKey !== adminAuthKey) {
    const unauthorized = new Error("Unauthorized: invalid authorizationKey for mutating API operation");
    unauthorized.status = 401;
    throw unauthorized;
  }
}

function normalizeQuery(value) {
  if (!value) {
    return {};
  }

  const query = {};
  for (const [key, item] of Object.entries(value)) {
    if (item !== undefined && item !== null && item !== "") {
      query[key] = item;
    }
  }
  return query;
}

function toolText({ summary, useWhen, doNotUseWhen, permissions, environment, parameters, response, failures, safety = "", prerequisite = "none", followUp = "none", example }) {
  return buildToolDescription({
    summary,
    useWhen,
    doNotUseWhen,
    permissions,
    environment,
    parameters,
    response,
    failures,
    safety,
    examples: { prerequisite, followUp, short: example }
  });
}

function makeScopeModel({ appName, defaultUserId, userId }) {
  const effectiveUserId = String(userId ?? defaultUserId).trim() || defaultUserId;
  return {
    appName,
    userId: effectiveUserId,
    postgres: {
      tableName: `${appName}_config`,
      primaryKey: ["user_id", "key"],
      scope: "app_and_user"
    },
    vault: {
      tokenIndexPath: `${appName}/users/${effectiveUserId}/graph/auth/token-index`,
      tokenSecretPrefix: `${appName}/users/${effectiveUserId}/graph/tokens`,
      scope: "app_and_user"
    }
  };
}

export function createMcpServer({ name, version, graphClient, appName, defaultUserId, adminAuthKey, allowSensitiveOutput }) {
  const server = new McpServer({ name, version });

  const connectionInfo = () => ({
    ok: true,
    status: 200,
    data: {
      server: {
        name,
        version,
        adminAuthConfigured: Boolean(adminAuthKey),
        allowSensitiveOutput: Boolean(allowSensitiveOutput),
        scopeModel: makeScopeModel({ appName, defaultUserId })
      },
      graph: graphClient.getConnectionInfo()
    }
  });

  server.tool(
    "graph_connection_info",
    toolText({
      summary: "Return Microsoft Graph MCP runtime metadata and storage model details.",
      useWhen: "you need to confirm base URLs, default user selection, and whether mutating tools require admin authorization",
      doNotUseWhen: "you need to check Graph connectivity or list resources; use graph_health_check or a resource-specific tool instead",
      permissions: "none",
      environment: "reports the resolved app name, default user, Graph base URLs, and token/config storage models",
      parameters: "none",
      response: "ok/status/data with server and graph connection details",
      failures: "500 if metadata assembly fails",
      safety: "",
      prerequisite: "none",
      followUp: "graph_health_check, graph_list_capabilities",
      example: '{"name":"graph_connection_info","arguments":{}}'
    }),
    {},
    withErrorHandling(allowSensitiveOutput, async () => connectionInfo())
  );

  server.tool(
    "graph_scope_info",
    toolText({
      summary: "Return the effective app/user scope used for Vault token paths and Postgres config keys.",
      useWhen: "you need to determine which user namespace a token or config mutation will target",
      doNotUseWhen: "you only need the global runtime metadata; use graph_connection_info instead",
      permissions: "none",
      environment: "defaults userId to MCP_CONFIG_DEFAULT_USER_ID when omitted",
      parameters: "userId (optional string, non-empty)",
      response: "ok/status/data with appName, userId, Postgres table details, and Vault token paths",
      failures: "500 for normalization or path construction errors",
      safety: "",
      prerequisite: "none",
      followUp: "graph_config_get, graph_user_tokens_list",
      example: '{"name":"graph_scope_info","arguments":{"userId":"default"}}'
    }),
    { userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ userId }) => ({
      ok: true,
      status: 200,
      data: makeScopeModel({ appName, defaultUserId, userId })
    }))
  );

  server.tool(
    "graph_list_capabilities",
    toolText({
      summary: "List the Graph families and coverage patterns supported by this MCP server.",
      useWhen: "you want a safe discovery view before choosing a specialized or generic Graph call",
      doNotUseWhen: "you need live data; use a specific Graph read tool or graph_api_request instead",
      permissions: "none",
      environment: "static capability list bundled with the current build",
      parameters: "none",
      response: "ok/status/data.capabilities",
      failures: "500 if the capability list cannot be produced",
      safety: "",
      prerequisite: "graph_connection_info",
      followUp: "graph_api_request, graph_health_check",
      example: '{"name":"graph_list_capabilities","arguments":{}}'
    }),
    {},
    withErrorHandling(allowSensitiveOutput, async () => ({
      ok: true,
      status: 200,
      data: {
        capabilities: graphClient.listKnownCapabilities(),
        genericCoverage: true
      }
    }))
  );

  server.tool(
    "microsoft_graph_suggest_queries",
    toolText({
      summary: "Search a curated catalog of Microsoft Graph query examples that match the user's intent.",
      useWhen: "you need candidate Graph API calls before choosing a request path",
      doNotUseWhen: "you already know the exact endpoint and want to execute it directly",
      permissions: "none",
      environment: "reads from the built-in query example catalog and returns ranked suggestions",
      parameters: "prompt (required string)",
      response: "ok/status/data.prompt/data.suggestions with method, path, query, entity, and confidence",
      failures: "500 if suggestion ranking fails",
      safety: "",
      prerequisite: "graph_connection_info",
      followUp: "microsoft_graph_get or graph_api_request",
      example: '{"name":"microsoft_graph_suggest_queries","arguments":{"prompt":"How many users do we have?"}}'
    }),
    { prompt: z.string().min(1) },
    withErrorHandling(allowSensitiveOutput, async ({ prompt }) => ({
      ok: true,
      status: 200,
      data: graphClient.listSuggestedQueries(prompt)
    }))
  );

  server.tool(
    "microsoft_graph_list_properties",
    toolText({
      summary: "Retrieve the property and relationship schema for a Microsoft Graph entity.",
      useWhen: "you need schema guidance before constructing a Graph request",
      doNotUseWhen: "you only need a specific record; use microsoft_graph_get or a dedicated read tool instead",
      permissions: "none",
      environment: "returns a curated schema for common Graph identity and directory entities",
      parameters: "entity (required string)",
      response: "ok/status/data.entity/data.properties/data.relationships",
      failures: "500 if schema lookup fails",
      safety: "",
      prerequisite: "graph_connection_info",
      followUp: "microsoft_graph_suggest_queries, microsoft_graph_get",
      example: '{"name":"microsoft_graph_list_properties","arguments":{"entity":"user"}}'
    }),
    { entity: z.string().min(1) },
    withErrorHandling(allowSensitiveOutput, async ({ entity }) => ({
      ok: true,
      status: 200,
      data: graphClient.listProperties(entity)
    }))
  );

  server.tool(
    "microsoft_graph_get",
    toolText({
      summary: "Run a read-only Microsoft Graph API call for any Graph REST path.",
      useWhen: "you know the exact endpoint and want the official read-only Graph execution path",
      doNotUseWhen: "you need a write operation; this server intentionally keeps the official Graph surface read-only",
      permissions: "a valid active Graph token for the selected user",
      environment: "method is forced to GET and the selected token comes from Vault with default-user fallback",
      parameters: "path (required string), query (optional object), userId (optional string), tokenId (optional string), useBetaBaseUrl (optional boolean)",
      response: "ok/status/data plus request metadata and response headers",
      failures: "400 invalid path, 401 missing/invalid token, 403 upstream authorization failure, 404 resource not found, 429 rate limiting, 5xx upstream or transport failure",
      safety: "read-only by design",
      prerequisite: "microsoft_graph_suggest_queries or microsoft_graph_list_properties",
      followUp: "graph_api_request or dedicated read tools for narrower intent",
      example: '{"name":"microsoft_graph_get","arguments":{"path":"/users/$count"}}'
    }),
    {
      path: z.string().min(1),
      query: z.record(z.union([z.string(), z.number(), z.boolean(), z.array(z.string())])).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ path, query, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path,
        query,
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "graph_health_check",
    toolText({
      summary: "Verify Graph reachability using the currently selected user token.",
      useWhen: "you need an upstream connectivity and authorization check before a Graph call",
      doNotUseWhen: "you need actual data; use a dedicated read tool",
      permissions: "a valid active Graph token for the selected user",
      environment: "selects the active token for the requested user, then calls Graph $metadata",
      parameters: "userId (optional string), tokenId (optional string)",
      response: "ok/status/data with the upstream status and response metadata",
      failures: "401 when no active token exists, 5xx when Graph is unavailable, 403 when the token is under-scoped",
      safety: "",
      prerequisite: "graph_user_tokens_list or graph_connection_info",
      followUp: "graph_api_request, graph_me",
      example: '{"name":"graph_health_check","arguments":{"userId":"default"}}'
    }),
    { userId: z.string().min(1).optional(), tokenId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ userId, tokenId }) => ({
      ok: true,
      status: 200,
      data: await graphClient.healthCheck({ userId, tokenId })
    }))
  );

  server.tool(
    "graph_api_request",
    toolText({
      summary: "Generic Microsoft Graph REST call for any supported Graph API path.",
      useWhen: "a specialized tool does not exist for the endpoint you need, or you need to reach a beta or long-tail API path",
      doNotUseWhen: "a dedicated read or mutation tool already models the operation more safely",
      permissions: "a valid active Graph token for the selected user; mutating methods also need MCP_ADMIN_AUTH_KEY when configured",
      environment: "method is normalized to uppercase, path is forced to a relative Graph path, and the selected token comes from Vault with default-user fallback",
      parameters: "method (required string), path (required string), query (optional object), body (optional JSON), headers (optional object), userId (optional string), tokenId (optional string), useBetaBaseUrl (optional boolean), authorizationKey (optional string for mutating calls)",
      response: "ok/status/data plus request metadata and response headers",
      failures: "400 invalid path or payload, 401 missing/invalid token or admin key, 403 upstream authorization failure, 404 resource not found, 429 rate limiting, 5xx upstream or transport failure",
      safety: "treat POST, PUT, PATCH, and DELETE as destructive-capable operations",
      prerequisite: "graph_health_check",
      followUp: "a specialized read tool for verification or a GET graph_api_request call",
      example: '{"name":"graph_api_request","arguments":{"method":"GET","path":"/users?$top=1"}}'
    }),
    {
      method: z.string().min(1),
      path: z.string().min(1),
      query: z.record(z.union([z.string(), z.number(), z.boolean(), z.array(z.string())])).optional(),
      body: z.any().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ method, path, query, body, headers, userId, tokenId, useBetaBaseUrl, authorizationKey }) => {
      const normalizedMethod = normalizeMethod(method);
      const normalizedPath = normalizePath(path);

      if (MUTATING_METHODS.has(normalizedMethod)) {
        assertAuthorized(adminAuthKey, authorizationKey);
      }

      return {
        ok: true,
        status: 200,
        data: await graphClient.request({
          method: normalizedMethod,
          path: normalizedPath,
          query: normalizeQuery(query),
          body,
          headers,
          userId,
          tokenId,
          useBetaBaseUrl
        })
      };
    })
  );

  server.tool(
    "graph_me",
    toolText({
      summary: "Read the signed-in user's profile from /me.",
      useWhen: "you need the current Graph user profile, display name, or tenant context",
      doNotUseWhen: "you need another user's profile; use graph_api_request with /users/{id} instead",
      permissions: "a valid delegated Graph token with profile access",
      environment: "uses the active token selected by userId/tokenId with default-user fallback",
      parameters: "userId (optional string), tokenId (optional string)",
      response: "ok/status/data with the upstream /me response payload",
      failures: "401 if the token is missing or invalid, 403 if the token does not support /me",
      safety: "",
      prerequisite: "graph_health_check",
      followUp: "graph_api_request, graph_user_tokens_list",
      example: '{"name":"graph_me","arguments":{}}'
    }),
    { userId: z.string().min(1).optional(), tokenId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ userId, tokenId }) => ({
      ok: true,
      status: 200,
      data: await graphClient.userProfile({ userId, tokenId })
    }))
  );

  function registerCollectionTool({ name, path, summary, useWhen, doNotUseWhen, permissions, response, failures, prerequisite, followUp, example, beta = false, extraArgs = {} }) {
    server.tool(
      name,
      toolText({
        summary,
        useWhen,
        doNotUseWhen,
        permissions,
        environment: `uses ${beta ? "betaBaseUrl" : "baseUrl"} with Graph query parameters preserved`,
        parameters: `userId (optional string), tokenId (optional string), query parameters relevant to the endpoint${Object.keys(extraArgs).length ? `, plus ${Object.keys(extraArgs).join(", ")}` : ""}`,
        response,
        failures,
        safety: "",
        prerequisite,
        followUp,
        example
      }),
      {
        userId: z.string().min(1).optional(),
        tokenId: z.string().min(1).optional(),
        top: z.union([z.string(), z.number()]).optional(),
        select: z.string().min(1).optional(),
        filter: z.string().min(1).optional(),
        orderby: z.string().min(1).optional(),
        expand: z.string().min(1).optional(),
        search: z.string().min(1).optional(),
        count: z.union([z.boolean(), z.string()]).optional(),
        ...extraArgs
      },
      withErrorHandling(allowSensitiveOutput, async (args) => {
        const { userId, tokenId, top, select, filter, orderby, expand, search, count, ...rest } = args;
        const query = {
          $top: top,
          $select: select,
          $filter: filter,
          $orderby: orderby,
          $expand: expand,
          $search: search,
          $count: count,
          ...rest
        };
        return {
          ok: true,
          status: 200,
          data: await graphClient.queryCollection({ path, userId, tokenId, query, useBetaBaseUrl: beta })
        };
      })
    );
  }

  registerCollectionTool({
    name: "graph_users_query",
    path: "/users",
    summary: "Query directory users from /users.",
    useWhen: "you need a user directory listing, filtered user lookup, or paging through users",
    doNotUseWhen: "you only need the current signed-in user; use graph_me instead",
    permissions: "a token with User.Read or equivalent directory access",
    response: "ok/status/data with the Graph users collection payload",
    failures: "401 if the token is absent, 403 if directory read access is denied",
    prerequisite: "graph_health_check",
    followUp: "graph_api_request, graph_me",
    example: '{"name":"graph_users_query","arguments":{"top":5,"select":"id,displayName,mail"}}'
  });

  registerCollectionTool({
    name: "graph_groups_query",
    path: "/groups",
    summary: "Query Microsoft 365 groups from /groups.",
    useWhen: "you need group discovery, filtering, or paging through groups",
    doNotUseWhen: "you need a specific group by id; use graph_api_request /groups/{id} or a future dedicated lookup",
    permissions: "a token with Group.Read.All or equivalent access",
    response: "ok/status/data with the Graph groups collection payload",
    failures: "401 if the token is absent, 403 if group read access is denied",
    prerequisite: "graph_health_check",
    followUp: "graph_api_request, graph_users_query",
    example: '{"name":"graph_groups_query","arguments":{"top":10,"select":"id,displayName,mailNickname"}}'
  });

  registerCollectionTool({
    name: "graph_mail_messages",
    path: "/me/messages",
    summary: "Read the signed-in user's mail messages from /me/messages.",
    useWhen: "you need inbox message discovery or mail processing for the active user",
    doNotUseWhen: "you need another mailbox; use graph_api_request with /users/{id}/messages instead",
    permissions: "a delegated token with Mail.Read or Mail.ReadBasic",
    response: "ok/status/data with the Graph message collection payload",
    failures: "401 if the token is absent, 403 if mailbox access is denied",
    prerequisite: "graph_me",
    followUp: "graph_api_request, graph_users_query",
    example: '{"name":"graph_mail_messages","arguments":{"top":10,"select":"id,subject,from,receivedDateTime"}}'
  });

  registerCollectionTool({
    name: "graph_calendar_events",
    path: "/me/events",
    summary: "Read the signed-in user's calendar events from /me/events.",
    useWhen: "you need event lookup, scheduling context, or calendar exports for the current user",
    doNotUseWhen: "you need another user's calendar; use graph_api_request with /users/{id}/events instead",
    permissions: "a delegated token with Calendars.Read or Calendars.ReadWrite",
    response: "ok/status/data with the Graph event collection payload",
    failures: "401 if the token is absent, 403 if calendar access is denied",
    prerequisite: "graph_me",
    followUp: "graph_api_request, graph_mail_messages",
    example: '{"name":"graph_calendar_events","arguments":{"top":10,"select":"id,subject,start,end"}}'
  });

  registerCollectionTool({
    name: "graph_drive_children",
    path: "/me/drive/root/children",
    summary: "List files and folders under the current user's default drive root.",
    useWhen: "you need file discovery or drive inventory for the signed-in user",
    doNotUseWhen: "you need a specific drive or site document library; use graph_api_request instead",
    permissions: "a delegated token with Files.Read or Files.Read.All",
    response: "ok/status/data with the Graph driveItem collection payload",
    failures: "401 if the token is absent, 403 if drive access is denied",
    prerequisite: "graph_me",
    followUp: "graph_api_request, graph_sites_query",
    example: '{"name":"graph_drive_children","arguments":{"top":20,"select":"id,name,webUrl"}}'
  });

  registerCollectionTool({
    name: "graph_security_alerts",
    path: "/security/alerts_v2",
    summary: "Read Microsoft Graph security alerts from /security/alerts_v2.",
    useWhen: "you need alert triage, incident hunting, or security monitoring data",
    doNotUseWhen: "you are looking for non-security data; use another family-specific tool",
    permissions: "a token with SecurityAlert.Read.All or equivalent security access",
    response: "ok/status/data with the Graph security alert collection payload",
    failures: "401 if the token is absent, 403 if security access is denied",
    prerequisite: "graph_health_check",
    followUp: "graph_api_request, graph_users_query",
    example: '{"name":"graph_security_alerts","arguments":{"top":5,"select":"id,status,severity,title"}}'
  });

  registerCollectionTool({
    name: "graph_applications_query",
    path: "/applications",
    summary: "Query application registrations from /applications.",
    useWhen: "you need app registration discovery, filtering, or paging through registered applications",
    doNotUseWhen: "you only need a service principal; use graph_api_request with /servicePrincipals instead",
    permissions: "a token with Application.Read.All or equivalent directory access",
    response: "ok/status/data with the Graph applications collection payload",
    failures: "401 if the token is absent, 403 if application read access is denied",
    prerequisite: "graph_health_check",
    followUp: "graph_api_request, graph_users_query",
    example: '{"name":"graph_applications_query","arguments":{"top":10,"select":"id,displayName,appId"}}'
  });

  registerCollectionTool({
    name: "graph_sites_query",
    path: "/sites",
    summary: "Query SharePoint sites from /sites.",
    useWhen: "you need site discovery, filtering, or paging through SharePoint sites",
    doNotUseWhen: "you need a specific list or drive item; use graph_api_request with the more precise site path instead",
    permissions: "a token with Sites.Read.All or equivalent access",
    response: "ok/status/data with the Graph sites collection payload",
    failures: "401 if the token is absent, 403 if site read access is denied",
    prerequisite: "graph_health_check",
    followUp: "graph_drive_children, graph_api_request",
    example: '{"name":"graph_sites_query","arguments":{"top":10,"select":"id,displayName,webUrl"}}'
  });

  registerCollectionTool({
    name: "graph_devices_query",
    path: "/devices",
    summary: "Query directory devices from /devices.",
    useWhen: "you need device discovery, filtering, or paging through registered devices",
    doNotUseWhen: "you need device management actions; use graph_api_request for the exact endpoint instead",
    permissions: "a token with Device.Read.All or equivalent directory access",
    response: "ok/status/data with the Graph devices collection payload",
    failures: "401 if the token is absent, 403 if device read access is denied",
    prerequisite: "graph_health_check",
    followUp: "graph_api_request, graph_users_query",
    example: '{"name":"graph_devices_query","arguments":{"top":10,"select":"id,displayName,operatingSystem"}}'
  });

  server.tool(
    "graph_config_list",
    toolText({
      summary: "List the Postgres-backed Graph configuration records for a user scope.",
      useWhen: "you need to inspect stored Graph runtime configuration or defaults",
      doNotUseWhen: "you need token material; use graph_user_tokens_list instead",
      permissions: "none",
      environment: "reads from the app-scoped Postgres config table and applies default-user fallback only when resolving values",
      parameters: "userId (optional string)",
      response: "ok/status/data with config rows",
      failures: "500 if the database cannot be queried",
      safety: "",
      prerequisite: "graph_connection_info",
      followUp: "graph_config_get, graph_config_set",
      example: '{"name":"graph_config_list","arguments":{"userId":"default"}}'
    }),
    { userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ userId }) => ({
      ok: true,
      status: 200,
      data: await graphClient.configList({ userId })
    }))
  );

  server.tool(
    "graph_config_get",
    toolText({
      summary: "Resolve a single Graph configuration key from Postgres with user and default-user fallback.",
      useWhen: "you need the effective configuration value for a specific key",
      doNotUseWhen: "you want the entire config list; use graph_config_list instead",
      permissions: "none",
      environment: "first checks the requested user scope, then the default-user scope, then returns null if unresolved",
      parameters: "key (required string), userId (optional string)",
      response: "ok/status/data with the resolved config row and source",
      failures: "500 if the config lookup fails",
      safety: "",
      prerequisite: "graph_config_list",
      followUp: "graph_config_set, graph_config_delete",
      example: '{"name":"graph_config_get","arguments":{"key":"graph.baseUrl","userId":"default"}}'
    }),
    { key: z.string().min(1), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ key, userId }) => ({
      ok: true,
      status: 200,
      data: await graphClient.configGet({ key, userId })
    }))
  );

  server.tool(
    "graph_config_set",
    toolText({
      summary: "Create or update a Graph configuration value in Postgres.",
      useWhen: "you need to persist non-secret Graph runtime configuration",
      doNotUseWhen: "you need to store tokens or other secrets; use graph_user_token_upsert instead",
      permissions: "MCP_ADMIN_AUTH_KEY when configured",
      environment: "writes to the app-scoped Postgres config table using the selected user scope",
      parameters: "key (required string), value (required JSON), userId (optional string), authorizationKey (optional string)",
      response: "ok/status/data with the saved config row",
      failures: "401 when the admin authorization key is missing or invalid, 500 on database errors",
      safety: "configuration changes can alter future token selection and request routing",
      prerequisite: "graph_config_get",
      followUp: "graph_config_list, graph_api_request",
      example: '{"name":"graph_config_set","arguments":{"key":"graph.baseUrl","value":"https://graph.microsoft.com/v1.0","userId":"default"}}'
    }),
    { key: z.string().min(1), value: z.any(), userId: z.string().min(1).optional(), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ key, value, userId, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.configSet({ key, value, userId })
      };
    })
  );

  server.tool(
    "graph_config_delete",
    toolText({
      summary: "Delete a Graph configuration value from Postgres.",
      useWhen: "you need to remove a stored non-secret configuration key",
      doNotUseWhen: "you need to clear a token secret; use graph_user_token_delete instead",
      permissions: "MCP_ADMIN_AUTH_KEY when configured",
      environment: "removes the selected user-scope config entry",
      parameters: "key (required string), userId (optional string), authorizationKey (optional string)",
      response: "ok/status/data indicating whether a row was deleted",
      failures: "401 when the admin authorization key is missing or invalid, 500 on database errors",
      safety: "deletions affect future config resolution and can change runtime behavior",
      prerequisite: "graph_config_get",
      followUp: "graph_config_list, graph_connection_info",
      example: '{"name":"graph_config_delete","arguments":{"key":"graph.baseUrl","userId":"default"}}'
    }),
    { key: z.string().min(1), userId: z.string().min(1).optional(), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ key, userId, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.configDelete({ key, userId })
      };
    })
  );

  server.tool(
    "graph_user_tokens_list",
    toolText({
      summary: "List the Vault-backed Graph token records for a user.",
      useWhen: "you need to inspect token metadata, status, or expiration without reading the secret material",
      doNotUseWhen: "you need to rotate, store, or remove token material; use the token mutation tools instead",
      permissions: "none for reads; token material remains in Vault",
      environment: "reads the user-scoped Vault token index and applies default-user fallback when the user scope is omitted",
      parameters: "userId (optional string)",
      response: "ok/status/data with token metadata only",
      failures: "500 if the Vault token index cannot be read",
      safety: "",
      prerequisite: "graph_scope_info",
      followUp: "graph_user_token_upsert, graph_user_token_delete",
      example: '{"name":"graph_user_tokens_list","arguments":{"userId":"default"}}'
    }),
    { userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ userId }) => ({
      ok: true,
      status: 200,
      data: await graphClient.listTokens({ userId })
    }))
  );

  server.tool(
    "graph_user_token_upsert",
    toolText({
      summary: "Create or update a Vault-backed Graph access token record for a user.",
      useWhen: "you need to add a new user token, rotate an access token, or refresh token metadata",
      doNotUseWhen: "you only need to inspect metadata; use graph_user_tokens_list instead",
      permissions: "MCP_ADMIN_AUTH_KEY when configured",
      environment: "persists token material in Vault and metadata in the user token index; uses default-user fallback for omitted userId",
      parameters: "userId (required string), accessToken (required string), refreshToken (optional string), tokenId (optional string), expiresAt (optional ISO timestamp or epoch), scopes (optional array or string), audience (optional array or string), active (optional boolean), tenantId (optional string), accountType (optional string), tokenType (optional string), displayName (optional string), authorizationKey (optional string)",
      response: "ok/status/data with the saved token metadata",
      failures: "401 when the admin authorization key is missing or invalid, 500 on Vault write errors",
      safety: "stores secret material in Vault; verify user identity and token provenance before writing",
      prerequisite: "graph_user_tokens_list",
      followUp: "graph_user_token_set_active, graph_health_check",
      example: '{"name":"graph_user_token_upsert","arguments":{"userId":"default","accessToken":"<token>","scopes":["User.Read"],"authorizationKey":"<admin-key-if-required>"}}'
    }),
    {
      userId: z.string().min(1),
      accessToken: z.string().min(1),
      refreshToken: z.string().optional(),
      tokenId: z.string().min(1).optional(),
      expiresAt: z.union([z.string(), z.number()]).optional(),
      scopes: z.union([z.array(z.string()), z.string()]).optional(),
      audience: z.union([z.array(z.string()), z.string()]).optional(),
      active: z.boolean().optional(),
      tenantId: z.string().optional(),
      accountType: z.string().optional(),
      tokenType: z.string().optional(),
      displayName: z.string().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ authorizationKey, ...payload }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.updateToken(payload)
      };
    })
  );

  server.tool(
    "graph_user_token_set_active",
    toolText({
      summary: "Mark a stored Graph token active or inactive without deleting it.",
      useWhen: "you need to switch the active token selection for a user",
      doNotUseWhen: "you need to delete the token secret; use graph_user_token_delete instead",
      permissions: "MCP_ADMIN_AUTH_KEY when configured",
      environment: "updates both the Vault token secret and the index metadata",
      parameters: "userId (required string), tokenId (required string), active (required boolean), authorizationKey (optional string)",
      response: "ok/status/data with the updated token metadata",
      failures: "401 when the admin authorization key is missing or invalid, 404 if the token does not exist",
      safety: "changing the active token affects future Graph requests for the selected user",
      prerequisite: "graph_user_tokens_list",
      followUp: "graph_health_check, graph_api_request",
      example: '{"name":"graph_user_token_set_active","arguments":{"userId":"default","tokenId":"graph-123","active":true}}'
    }),
    { userId: z.string().min(1), tokenId: z.string().min(1), active: z.boolean(), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ userId, tokenId, active, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      if (!active) {
        const updated = await graphClient.deactivateToken({ userId, tokenId });
        if (!updated) {
          const error = new Error(`Token ${tokenId} not found for user ${userId}`);
          error.status = 404;
          throw error;
        }
        return { ok: true, status: 200, data: updated };
      }

      const secret = await graphClient.tokenStore.readTokenSecret(userId, tokenId);
      if (!secret?.accessToken) {
        const error = new Error(`Token ${tokenId} not found for user ${userId}`);
        error.status = 404;
        throw error;
      }

      const updated = await graphClient.updateToken({ userId, tokenId, accessToken: secret.accessToken, refreshToken: secret.refreshToken, expiresAt: secret.expiresAt, scopes: secret.scopes, audience: secret.audience, active: true, tenantId: secret.tenantId, accountType: secret.accountType, tokenType: secret.tokenType, displayName: secret.displayName });
      return { ok: true, status: 200, data: updated };
    })
  );

  server.tool(
    "graph_user_token_delete",
    toolText({
      summary: "Remove a stored Graph token from Vault and the token index.",
      useWhen: "you need to revoke a token record and erase the secret from Vault",
      doNotUseWhen: "you only need to disable future use; use graph_user_token_set_active instead",
      permissions: "MCP_ADMIN_AUTH_KEY when configured",
      environment: "deletes the token secret in Vault and removes the metadata entry from the user token index",
      parameters: "userId (required string), tokenId (required string), authorizationKey (optional string)",
      response: "ok/status/data with a deletion boolean",
      failures: "401 when the admin authorization key is missing or invalid, 404 if the token does not exist",
      safety: "destructive operation; confirm the token is no longer needed before deleting it",
      prerequisite: "graph_user_tokens_list",
      followUp: "graph_health_check, graph_user_token_upsert",
      example: '{"name":"graph_user_token_delete","arguments":{"userId":"default","tokenId":"graph-123"}}'
    }),
    { userId: z.string().min(1), tokenId: z.string().min(1), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ userId, tokenId, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      const deleted = await graphClient.removeToken({ userId, tokenId });
      if (!deleted) {
        const error = new Error(`Token ${tokenId} not found for user ${userId}`);
        error.status = 404;
        throw error;
      }
      return { ok: true, status: 200, data: { deleted } };
    })
  );

  return server;
}
