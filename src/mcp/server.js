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

export function createMcpServer({ name, version, graphClient, office365Client, appName, defaultUserId, adminAuthKey, allowSensitiveOutput }) {
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
      environment: "reads from the built-in query example catalog (including Copilot-focused patterns) and returns ranked suggestions",
      parameters: "prompt (required string)",
      response: "ok/status/data.prompt/data.suggestions with method, path, query, entity, mcpTool, and confidence",
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
      environment: "returns a curated schema for common Graph identity/directory entities plus Copilot entities",
      parameters: "entity (required string)",
      response: "ok/status/data.entity/data.properties/data.relationships/data.recommendedTools",
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

  function buildCopilotReportPath(functionName, period, version) {
    const normalizedPeriod = String(period ?? "").trim();
    if (!normalizedPeriod) {
      const error = new Error("period is required");
      error.status = 400;
      throw error;
    }

    const versionClause = version ? `, version='${String(version).trim()}'` : "";
    return `/copilot/reports/${functionName}(period='${normalizedPeriod}'${versionClause})`;
  }

  server.tool(
    "copilot_api_capabilities",
    toolText({
      summary: "List Microsoft 365 Copilot API families and their mapped Microsoft Graph paths.",
      useWhen: "you need a concise discovery map of the dedicated Copilot tools available in this MCP",
      doNotUseWhen: "you already know the target API operation and want to execute it",
      permissions: "none",
      environment: "static capability map for Copilot API coverage in this build",
      parameters: "none",
      response: "ok/status/data.capabilities",
      failures: "500 if capability map assembly fails",
      safety: "",
      prerequisite: "graph_connection_info",
      followUp: "copilot_retrieval_query, copilot_search_query, copilot_chat_create_conversation",
      example: '{"name":"copilot_api_capabilities","arguments":{}}'
    }),
    {},
    withErrorHandling(allowSensitiveOutput, async () => ({
      ok: true,
      status: 200,
      data: {
        capabilities: [
          { family: "retrieval", path: "/copilot/retrieval", methods: ["POST"], supportsV1: true, supportsBeta: true },
          { family: "search", path: "/copilot/search", methods: ["POST"], supportsV1: false, supportsBeta: true },
          { family: "chat", path: "/copilot/conversations", methods: ["POST"], supportsV1: false, supportsBeta: true },
          { family: "interaction-export", path: "/copilot/users/{id}/interactionHistory/getAllEnterpriseInteractions", methods: ["GET"], supportsV1: true, supportsBeta: true },
          { family: "meeting-insights", path: "/copilot/users/{userId}/onlineMeetings/{onlineMeetingId}/aiInsights", methods: ["GET"], supportsV1: true, supportsBeta: true },
          { family: "ai-change-notifications", path: "/subscriptions with /copilot/* resource", methods: ["POST"], supportsV1: true, supportsBeta: true },
          { family: "usage-reports", path: "/copilot/reports/getMicrosoft365Copilot*", methods: ["GET"], supportsV1: true, supportsBeta: true },
          { family: "package-management", path: "/copilot/admin/catalog/packages", methods: ["GET", "PATCH", "POST"], supportsV1: true, supportsBeta: true }
        ]
      }
    }))
  );

  server.tool(
    "copilot_retrieval_query",
    toolText({
      summary: "Call the Microsoft 365 Copilot Retrieval API.",
      useWhen: "you need grounding extracts from SharePoint, OneDrive for Business, or Copilot connectors",
      doNotUseWhen: "you need hybrid ranking for OneDrive-only search; use copilot_search_query instead",
      permissions: "delegated permissions for the chosen source, such as Files.Read.All and Sites.Read.All (and ExternalItem.Read.All for connectors)",
      environment: "POSTs /copilot/retrieval on v1.0 by default, with optional beta",
      parameters: "queryString (required string), dataSource (required enum), filterExpression (optional string), resourceMetadata (optional string array), maximumNumberOfResults (optional 1-25), dataSourceConfiguration (optional object), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data with retrievalHits",
      failures: "400 invalid body fields, 401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "retrieved data may include sensitive business content",
      prerequisite: "graph_health_check",
      followUp: "copilot_chat_send_message or graph_api_request",
      example: '{"name":"copilot_retrieval_query","arguments":{"queryString":"How to setup corporate VPN?","dataSource":"sharePoint"}}'
    }),
    {
      queryString: z.string().min(1).max(1500),
      dataSource: z.enum(["sharePoint", "oneDriveBusiness", "externalItem"]),
      filterExpression: z.string().min(1).optional(),
      resourceMetadata: z.array(z.string().min(1)).optional(),
      maximumNumberOfResults: z.number().int().min(1).max(25).optional(),
      dataSourceConfiguration: z.any().optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ queryString, dataSource, filterExpression, resourceMetadata, maximumNumberOfResults, dataSourceConfiguration, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "POST",
        path: "/copilot/retrieval",
        body: {
          queryString,
          dataSource,
          filterExpression,
          resourceMetadata,
          maximumNumberOfResults,
          dataSourceConfiguration
        },
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_search_query",
    toolText({
      summary: "Call the Microsoft 365 Copilot Search API (preview).",
      useWhen: "you need hybrid search over OneDrive for work or school content",
      doNotUseWhen: "you need retrieval extracts from SharePoint or external connectors; use copilot_retrieval_query instead",
      permissions: "delegated Files.Read.All and Sites.Read.All (or higher delegated equivalents)",
      environment: "POSTs /copilot/search on beta by default",
      parameters: "query (required string), pageSize (optional 1-100), dataSources (optional object), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data with searchHits and totalCount",
      failures: "400 invalid body fields, 401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "search results can expose sensitive file metadata and previews",
      prerequisite: "graph_health_check",
      followUp: "copilot_chat_send_message or graph_api_request",
      example: '{"name":"copilot_search_query","arguments":{"query":"quarterly budget analysis","pageSize":10}}'
    }),
    {
      query: z.string().min(1).max(1500),
      pageSize: z.number().int().min(1).max(100).optional(),
      dataSources: z.any().optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ query, pageSize, dataSources, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "POST",
        path: "/copilot/search",
        body: { query, pageSize, dataSources },
        userId,
        tokenId,
        useBetaBaseUrl: useBetaBaseUrl ?? true
      })
    }))
  );

  server.tool(
    "copilot_chat_create_conversation",
    toolText({
      summary: "Create a Microsoft 365 Copilot Chat conversation (preview).",
      useWhen: "you need a new conversation ID before sending synchronous or streamed chat turns",
      doNotUseWhen: "you already have a conversation ID and want to continue it",
      permissions: "delegated Chat API permissions required by Microsoft 365 Copilot",
      environment: "POSTs /copilot/conversations on beta by default",
      parameters: "userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data with conversation metadata including id",
      failures: "401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "graph_health_check",
      followUp: "copilot_chat_send_message, copilot_chat_send_message_stream",
      example: '{"name":"copilot_chat_create_conversation","arguments":{}}'
    }),
    {
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "POST",
        path: "/copilot/conversations",
        body: {},
        userId,
        tokenId,
        useBetaBaseUrl: useBetaBaseUrl ?? true
      })
    }))
  );

  server.tool(
    "copilot_chat_send_message",
    toolText({
      summary: "Send a synchronous Chat API turn to an existing Copilot conversation (preview).",
      useWhen: "you need a full Chat API response in one payload",
      doNotUseWhen: "you need server-sent event streaming; use copilot_chat_send_message_stream instead",
      permissions: "delegated Chat API permissions required by Microsoft 365 Copilot",
      environment: "POSTs /copilot/conversations/{conversationId}/chat on beta by default",
      parameters: "conversationId (required string), messageText (required string), locationHint (required object), additionalContext (optional array), contextualResources (optional object), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data with a copilotConversation payload",
      failures: "400 invalid body fields, 401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "responses are AI-generated and should be validated before operational use",
      prerequisite: "copilot_chat_create_conversation",
      followUp: "copilot_chat_send_message_stream, copilot_retrieval_query",
      example: '{"name":"copilot_chat_send_message","arguments":{"conversationId":"<id>","messageText":"What meeting do I have at 9 AM tomorrow morning?","locationHint":{"timeZone":"America/New_York"}}}'
    }),
    {
      conversationId: z.string().min(1),
      messageText: z.string().min(1),
      locationHint: z.record(z.any()),
      additionalContext: z.array(z.record(z.any())).optional(),
      contextualResources: z.record(z.any()).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ conversationId, messageText, locationHint, additionalContext, contextualResources, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "POST",
        path: `/copilot/conversations/${encodeURIComponent(conversationId)}/chat`,
        body: {
          message: { text: messageText },
          locationHint,
          additionalContext,
          contextualResources
        },
        userId,
        tokenId,
        useBetaBaseUrl: useBetaBaseUrl ?? true
      })
    }))
  );

  server.tool(
    "copilot_chat_send_message_stream",
    toolText({
      summary: "Send a streamed Chat API turn to an existing Copilot conversation (preview).",
      useWhen: "you need incremental server-sent event output from the Chat API",
      doNotUseWhen: "you need a single non-stream payload; use copilot_chat_send_message instead",
      permissions: "delegated Chat API permissions required by Microsoft 365 Copilot",
      environment: "POSTs /copilot/conversations/{conversationId}/chatOverStream on beta by default",
      parameters: "conversationId (required string), messageText (required string), locationHint (required object), additionalContext (optional array), contextualResources (optional object), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data with the upstream response content",
      failures: "400 invalid body fields, 401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "responses are AI-generated and should be validated before operational use",
      prerequisite: "copilot_chat_create_conversation",
      followUp: "copilot_chat_send_message, copilot_retrieval_query",
      example: '{"name":"copilot_chat_send_message_stream","arguments":{"conversationId":"<id>","messageText":"Summarize this document for me.","locationHint":{"timeZone":"America/New_York"}}}'
    }),
    {
      conversationId: z.string().min(1),
      messageText: z.string().min(1),
      locationHint: z.record(z.any()),
      additionalContext: z.array(z.record(z.any())).optional(),
      contextualResources: z.record(z.any()).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ conversationId, messageText, locationHint, additionalContext, contextualResources, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "POST",
        path: `/copilot/conversations/${encodeURIComponent(conversationId)}/chatOverStream`,
        body: {
          message: { text: messageText },
          locationHint,
          additionalContext,
          contextualResources
        },
        userId,
        tokenId,
        useBetaBaseUrl: useBetaBaseUrl ?? true
      })
    }))
  );

  server.tool(
    "copilot_interactions_list",
    toolText({
      summary: "List Microsoft 365 Copilot interactions for a specific user.",
      useWhen: "you need interaction export data for user prompts and Copilot responses",
      doNotUseWhen: "you need change notifications instead of pull-based listing",
      permissions: "application AiEnterpriseInteraction.Read.All",
      environment: "GETs /copilot/users/{id}/interactionHistory/getAllEnterpriseInteractions",
      parameters: "interactionUserId (required string), top (optional number/string), filter (optional string), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data.value with aiInteraction items",
      failures: "401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "interaction payloads can contain sensitive user prompts and generated content",
      prerequisite: "graph_health_check",
      followUp: "copilot_change_notifications_create_subscription, graph_api_request",
      example: '{"name":"copilot_interactions_list","arguments":{"interactionUserId":"<user-id>","top":100}}'
    }),
    {
      interactionUserId: z.string().min(1),
      top: z.union([z.string(), z.number()]).optional(),
      filter: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ interactionUserId, top, filter, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: `/copilot/users/${encodeURIComponent(interactionUserId)}/interactionHistory/getAllEnterpriseInteractions`,
        query: normalizeQuery({ $top: top, $filter: filter }),
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_meeting_insights_list",
    toolText({
      summary: "List AI insights for a Teams online meeting in the Copilot namespace.",
      useWhen: "you need all AI insight objects for a meeting before fetching a specific detail",
      doNotUseWhen: "you already know the insight ID and need the detailed object",
      permissions: "OnlineMeetingAiInsight.Read.All delegated or application permission",
      environment: "GETs /copilot/users/{userId}/onlineMeetings/{onlineMeetingId}/aiInsights",
      parameters: "meetingUserId (required string), onlineMeetingId (required string), select (optional string), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data.value with callAiInsight summaries",
      failures: "401/403 token or permission failures, 404 expired or missing meeting, 429 throttling, 5xx upstream errors",
      safety: "meeting insights can contain sensitive notes and action items",
      prerequisite: "graph_health_check",
      followUp: "copilot_meeting_insight_get, graph_api_request",
      example: '{"name":"copilot_meeting_insights_list","arguments":{"meetingUserId":"<user-id>","onlineMeetingId":"<meeting-id>"}}'
    }),
    {
      meetingUserId: z.string().min(1),
      onlineMeetingId: z.string().min(1),
      select: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ meetingUserId, onlineMeetingId, select, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: `/copilot/users/${encodeURIComponent(meetingUserId)}/onlineMeetings/${encodeURIComponent(onlineMeetingId)}/aiInsights`,
        query: normalizeQuery({ $select: select }),
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_meeting_insight_get",
    toolText({
      summary: "Get a specific AI insight object for a Teams online meeting.",
      useWhen: "you need full meeting notes, action items, and mention events for a specific insight",
      doNotUseWhen: "you need the insight list first; call copilot_meeting_insights_list",
      permissions: "OnlineMeetingAiInsight.Read.All delegated or application permission",
      environment: "GETs /copilot/users/{userId}/onlineMeetings/{onlineMeetingId}/aiInsights/{aiInsightId}",
      parameters: "meetingUserId (required string), onlineMeetingId (required string), aiInsightId (required string), select (optional string), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data with a callAiInsight object",
      failures: "401/403 token or permission failures, 404 insight not found or meeting expired, 429 throttling, 5xx upstream errors",
      safety: "meeting insights can contain sensitive notes and participant mentions",
      prerequisite: "copilot_meeting_insights_list",
      followUp: "copilot_change_notifications_create_subscription, graph_api_request",
      example: '{"name":"copilot_meeting_insight_get","arguments":{"meetingUserId":"<user-id>","onlineMeetingId":"<meeting-id>","aiInsightId":"<insight-id>"}}'
    }),
    {
      meetingUserId: z.string().min(1),
      onlineMeetingId: z.string().min(1),
      aiInsightId: z.string().min(1),
      select: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ meetingUserId, onlineMeetingId, aiInsightId, select, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: `/copilot/users/${encodeURIComponent(meetingUserId)}/onlineMeetings/${encodeURIComponent(onlineMeetingId)}/aiInsights/${encodeURIComponent(aiInsightId)}`,
        query: normalizeQuery({ $select: select }),
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_change_notifications_create_subscription",
    toolText({
      summary: "Create a Microsoft Graph subscription for Copilot AI interactions or AI insights change notifications.",
      useWhen: "you need push-based change notifications for Copilot interactions or meeting AI insights",
      doNotUseWhen: "you only need one-time data retrieval; use list/get tools instead",
      permissions: "permissions required by the selected Copilot notification resource and Graph subscriptions API",
      environment: "POSTs /subscriptions and forwards the subscription payload",
      parameters: "changeType (required string), notificationUrl (required string), resource (required string), includeResourceData (optional boolean), encryptionCertificate (optional string), encryptionCertificateId (optional string), expirationDateTime (required string), clientState (optional string), lifecycleNotificationUrl (optional string), userId/tokenId/useBetaBaseUrl (optional), authorizationKey (optional when MCP_ADMIN_AUTH_KEY is configured)",
      response: "ok/status/data with Graph subscription object",
      failures: "400 invalid subscription payload, 401 unauthorized admin key for mutation, 403 permission failures, 429 throttling, 5xx upstream errors",
      safety: "this mutates webhook subscription state and can deliver sensitive change notifications",
      prerequisite: "graph_health_check",
      followUp: "graph_api_request, copilot_interactions_list",
      example: '{"name":"copilot_change_notifications_create_subscription","arguments":{"changeType":"created,updated,deleted","notificationUrl":"https://example.com/webhook","resource":"/copilot/interactionHistory/getAllEnterpriseInteractions","expirationDateTime":"2026-12-01T00:00:00Z"}}'
    }),
    {
      changeType: z.string().min(1),
      notificationUrl: z.string().min(1),
      resource: z.string().min(1),
      includeResourceData: z.boolean().optional(),
      encryptionCertificate: z.string().min(1).optional(),
      encryptionCertificateId: z.string().min(1).optional(),
      expirationDateTime: z.string().min(1),
      clientState: z.string().min(1).optional(),
      lifecycleNotificationUrl: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ changeType, notificationUrl, resource, includeResourceData, encryptionCertificate, encryptionCertificateId, expirationDateTime, clientState, lifecycleNotificationUrl, userId, tokenId, useBetaBaseUrl, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.request({
          method: "POST",
          path: "/subscriptions",
          body: {
            changeType,
            notificationUrl,
            resource,
            includeResourceData,
            encryptionCertificate,
            encryptionCertificateId,
            expirationDateTime,
            clientState,
            lifecycleNotificationUrl
          },
          userId,
          tokenId,
          useBetaBaseUrl
        })
      };
    })
  );

  server.tool(
    "copilot_usage_report_user_count_summary",
    toolText({
      summary: "Get Microsoft 365 Copilot user count summary report.",
      useWhen: "you need aggregated enabled and active user counts for a reporting period",
      doNotUseWhen: "you need trend-by-day or per-user detail reports",
      permissions: "Reports.Read.All with required admin role for delegated usage reporting",
      environment: "GETs /copilot/reports/getMicrosoft365CopilotUserCountSummary(period, version)",
      parameters: "period (required enum D7,D28,D30,D90,D180,ALL), version (optional v1/v2), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data as CSV stream in v1 or JSON in beta",
      failures: "400 invalid period/version, 401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "graph_health_check",
      followUp: "copilot_usage_report_user_count_trend, copilot_usage_report_user_detail",
      example: '{"name":"copilot_usage_report_user_count_summary","arguments":{"period":"D7","version":"v2"}}'
    }),
    {
      period: z.enum(["D7", "D28", "D30", "D90", "D180", "ALL"]),
      version: z.enum(["v1", "v2"]).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ period, version, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: buildCopilotReportPath("getMicrosoft365CopilotUserCountSummary", period, version),
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_usage_report_user_count_trend",
    toolText({
      summary: "Get Microsoft 365 Copilot user count trend report.",
      useWhen: "you need daily trend of enabled and active users across the selected period",
      doNotUseWhen: "you only need a single aggregated summary row or per-user detail",
      permissions: "Reports.Read.All with required admin role for delegated usage reporting",
      environment: "GETs /copilot/reports/getMicrosoft365CopilotUserCountTrend(period, version)",
      parameters: "period (required enum D7,D28,D30,D90,D180,ALL), version (optional v1/v2), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data as CSV stream in v1 or JSON in beta",
      failures: "400 invalid period/version, 401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "graph_health_check",
      followUp: "copilot_usage_report_user_count_summary, copilot_usage_report_user_detail",
      example: '{"name":"copilot_usage_report_user_count_trend","arguments":{"period":"D30","version":"v2"}}'
    }),
    {
      period: z.enum(["D7", "D28", "D30", "D90", "D180", "ALL"]),
      version: z.enum(["v1", "v2"]).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ period, version, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: buildCopilotReportPath("getMicrosoft365CopilotUserCountTrend", period, version),
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_usage_report_user_detail",
    toolText({
      summary: "Get Microsoft 365 Copilot usage report by user.",
      useWhen: "you need per-user activity details and last-activity timestamps for Copilot usage",
      doNotUseWhen: "you only need aggregated summary or trend counts",
      permissions: "Reports.Read.All with required admin role for delegated usage reporting",
      environment: "GETs /copilot/reports/getMicrosoft365CopilotUsageUserDetail(period, version)",
      parameters: "period (required enum D7,D28,D30,D90,D180,ALL), version (optional v1/v2), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data as CSV stream in v1 or JSON in beta",
      failures: "400 invalid period/version, 401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "contains user-level activity details and should be handled as sensitive reporting data",
      prerequisite: "graph_health_check",
      followUp: "copilot_usage_report_user_count_summary, copilot_usage_report_user_count_trend",
      example: '{"name":"copilot_usage_report_user_detail","arguments":{"period":"D7","version":"v2"}}'
    }),
    {
      period: z.enum(["D7", "D28", "D30", "D90", "D180", "ALL"]),
      version: z.enum(["v1", "v2"]).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ period, version, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: buildCopilotReportPath("getMicrosoft365CopilotUsageUserDetail", period, version),
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_packages_list",
    toolText({
      summary: "List Copilot packages (agents) from the organization catalog.",
      useWhen: "you need organization-wide inventory of agents and package metadata",
      doNotUseWhen: "you need details for a specific package ID",
      permissions: "Copilot package management permissions and licensing in tenant",
      environment: "GETs /copilot/admin/catalog/packages",
      parameters: "filter/select/orderby/top/skip (optional), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data.value with package rows",
      failures: "401/403 token or permission failures, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "graph_health_check",
      followUp: "copilot_package_get, copilot_package_update",
      example: '{"name":"copilot_packages_list","arguments":{"top":25}}'
    }),
    {
      filter: z.string().min(1).optional(),
      select: z.string().min(1).optional(),
      orderby: z.string().min(1).optional(),
      top: z.union([z.string(), z.number()]).optional(),
      skip: z.union([z.string(), z.number()]).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ filter, select, orderby, top, skip, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: "/copilot/admin/catalog/packages",
        query: normalizeQuery({ $filter: filter, $select: select, $orderby: orderby, $top: top, $skip: skip }),
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_package_get",
    toolText({
      summary: "Get details for a specific Copilot package (agent).",
      useWhen: "you need metadata or element details for one package",
      doNotUseWhen: "you need a broad inventory list",
      permissions: "Copilot package management permissions and licensing in tenant",
      environment: "GETs /copilot/admin/catalog/packages/{id}",
      parameters: "packageId (required string), userId/tokenId/useBetaBaseUrl (optional)",
      response: "ok/status/data with package detail object",
      failures: "401/403 token or permission failures, 404 package not found, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "copilot_packages_list",
      followUp: "copilot_package_update, copilot_package_block",
      example: '{"name":"copilot_package_get","arguments":{"packageId":"<package-id>"}}'
    }),
    {
      packageId: z.string().min(1),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ packageId, userId, tokenId, useBetaBaseUrl }) => ({
      ok: true,
      status: 200,
      data: await graphClient.request({
        method: "GET",
        path: `/copilot/admin/catalog/packages/${encodeURIComponent(packageId)}`,
        userId,
        tokenId,
        useBetaBaseUrl
      })
    }))
  );

  server.tool(
    "copilot_package_update",
    toolText({
      summary: "Update metadata for a Copilot package (preview operation).",
      useWhen: "you need to patch package settings in the organization catalog",
      doNotUseWhen: "you only need read-only package inspection",
      permissions: "MCP_ADMIN_AUTH_KEY when configured plus Copilot package management permissions",
      environment: "PATCHes /copilot/admin/catalog/packages/{id}",
      parameters: "packageId (required string), body (required object), userId/tokenId/useBetaBaseUrl (optional), authorizationKey (optional when MCP_ADMIN_AUTH_KEY is configured)",
      response: "ok/status/data with upstream update response",
      failures: "400 invalid patch body, 401 unauthorized admin key, 403 package permission failures, 404 package not found, 429 throttling, 5xx upstream errors",
      safety: "this mutates package metadata and can impact tenant-wide agent behavior",
      prerequisite: "copilot_package_get",
      followUp: "copilot_package_get, copilot_packages_list",
      example: '{"name":"copilot_package_update","arguments":{"packageId":"<package-id>","body":{"displayName":"New Name"},"authorizationKey":"<admin-key-if-required>"}}'
    }),
    {
      packageId: z.string().min(1),
      body: z.record(z.any()),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ packageId, body, userId, tokenId, useBetaBaseUrl, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.request({
          method: "PATCH",
          path: `/copilot/admin/catalog/packages/${encodeURIComponent(packageId)}`,
          body,
          userId,
          tokenId,
          useBetaBaseUrl
        })
      };
    })
  );

  server.tool(
    "copilot_package_block",
    toolText({
      summary: "Block a Copilot package in the organization catalog (preview operation).",
      useWhen: "you need to disable package usage across the organization",
      doNotUseWhen: "you only need read-only inspection",
      permissions: "MCP_ADMIN_AUTH_KEY when configured plus Copilot package management permissions",
      environment: "POSTs /copilot/admin/catalog/packages/{id}/block",
      parameters: "packageId (required string), body (optional object), userId/tokenId/useBetaBaseUrl (optional), authorizationKey (optional when MCP_ADMIN_AUTH_KEY is configured)",
      response: "ok/status/data with upstream block response",
      failures: "401 unauthorized admin key, 403 package permission failures, 404 package not found, 429 throttling, 5xx upstream errors",
      safety: "this mutates package availability tenant-wide",
      prerequisite: "copilot_package_get",
      followUp: "copilot_package_get, copilot_package_unblock",
      example: '{"name":"copilot_package_block","arguments":{"packageId":"<package-id>","authorizationKey":"<admin-key-if-required>"}}'
    }),
    {
      packageId: z.string().min(1),
      body: z.record(z.any()).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ packageId, body, userId, tokenId, useBetaBaseUrl, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.request({
          method: "POST",
          path: `/copilot/admin/catalog/packages/${encodeURIComponent(packageId)}/block`,
          body: body ?? {},
          userId,
          tokenId,
          useBetaBaseUrl
        })
      };
    })
  );

  server.tool(
    "copilot_package_unblock",
    toolText({
      summary: "Unblock a Copilot package in the organization catalog (preview operation).",
      useWhen: "you need to re-enable package usage across the organization",
      doNotUseWhen: "you only need read-only inspection",
      permissions: "MCP_ADMIN_AUTH_KEY when configured plus Copilot package management permissions",
      environment: "POSTs /copilot/admin/catalog/packages/{id}/unblock",
      parameters: "packageId (required string), body (optional object), userId/tokenId/useBetaBaseUrl (optional), authorizationKey (optional when MCP_ADMIN_AUTH_KEY is configured)",
      response: "ok/status/data with upstream unblock response",
      failures: "401 unauthorized admin key, 403 package permission failures, 404 package not found, 429 throttling, 5xx upstream errors",
      safety: "this mutates package availability tenant-wide",
      prerequisite: "copilot_package_get",
      followUp: "copilot_package_get, copilot_package_block",
      example: '{"name":"copilot_package_unblock","arguments":{"packageId":"<package-id>","authorizationKey":"<admin-key-if-required>"}}'
    }),
    {
      packageId: z.string().min(1),
      body: z.record(z.any()).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ packageId, body, userId, tokenId, useBetaBaseUrl, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.request({
          method: "POST",
          path: `/copilot/admin/catalog/packages/${encodeURIComponent(packageId)}/unblock`,
          body: body ?? {},
          userId,
          tokenId,
          useBetaBaseUrl
        })
      };
    })
  );

  server.tool(
    "copilot_package_reassign",
    toolText({
      summary: "Reassign ownership of a Copilot package (preview operation).",
      useWhen: "you need to transfer package ownership",
      doNotUseWhen: "you only need read-only package inspection",
      permissions: "MCP_ADMIN_AUTH_KEY when configured plus Copilot package management permissions",
      environment: "POSTs /copilot/admin/catalog/packages/{id}/reassign",
      parameters: "packageId (required string), body (required object), userId/tokenId/useBetaBaseUrl (optional), authorizationKey (optional when MCP_ADMIN_AUTH_KEY is configured)",
      response: "ok/status/data with upstream reassign response",
      failures: "400 invalid request body, 401 unauthorized admin key, 403 package permission failures, 404 package not found, 429 throttling, 5xx upstream errors",
      safety: "this mutates ownership metadata and affects administrative control",
      prerequisite: "copilot_package_get",
      followUp: "copilot_package_get, copilot_packages_list",
      example: '{"name":"copilot_package_reassign","arguments":{"packageId":"<package-id>","body":{"newOwner":"<user-id>"},"authorizationKey":"<admin-key-if-required>"}}'
    }),
    {
      packageId: z.string().min(1),
      body: z.record(z.any()),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      useBetaBaseUrl: z.boolean().optional(),
      authorizationKey: z.string().min(1).optional()
    },
    withErrorHandling(allowSensitiveOutput, async ({ packageId, body, userId, tokenId, useBetaBaseUrl, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await graphClient.request({
          method: "POST",
          path: `/copilot/admin/catalog/packages/${encodeURIComponent(packageId)}/reassign`,
          body,
          userId,
          tokenId,
          useBetaBaseUrl
        })
      };
    })
  );

  server.tool(
    "office365_activity_connection_info",
    toolText({
      summary: "Return Office 365 Management Activity API runtime metadata and tenant scope defaults.",
      useWhen: "you need to confirm the base URL, default tenant, publisher identifier, or token model before a subscription or content call",
      doNotUseWhen: "you need live content or subscription data; use the specific Office 365 activity tools instead",
      permissions: "none",
      environment: "reports the resolved activity API base URL and default scope values",
      parameters: "none",
      response: "ok/status/data with server and Office 365 connection details",
      failures: "500 if metadata assembly fails",
      safety: "",
      prerequisite: "none",
      followUp: "office365_activity_list_content_types, office365_activity_list_subscriptions",
      example: '{"name":"office365_activity_connection_info","arguments":{}}'
    }),
    {},
    withErrorHandling(allowSensitiveOutput, async () => ({
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
        office365: office365Client.getConnectionInfo()
      }
    }))
  );

  server.tool(
    "office365_activity_scope_info",
    toolText({
      summary: "Return the effective tenant and publisher scope used by Office 365 Management Activity API calls.",
      useWhen: "you need to know which tenant and publisher identifier a request will target",
      doNotUseWhen: "you only need the runtime metadata; use office365_activity_connection_info instead",
      permissions: "none",
      environment: "defaults tenantId and publisherIdentifier from environment when omitted",
      parameters: "tenantId (optional string), publisherIdentifier (optional string), userId (optional string)",
      response: "ok/status/data with tenantId, publisherIdentifier, and token scope details",
      failures: "400 if tenant validation fails, 500 on normalization errors",
      safety: "",
      prerequisite: "none",
      followUp: "office365_activity_list_content_types, office365_activity_list_subscriptions",
      example: '{"name":"office365_activity_scope_info","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","publisherIdentifier":"11111111-1111-1111-1111-111111111111"}}'
    }),
    { tenantId: z.string().min(1).optional(), publisherIdentifier: z.string().min(1).optional(), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, publisherIdentifier, userId }) => ({
      ok: true,
      status: 200,
      data: office365Client.scope({ tenantId, publisherIdentifier, userId })
    }))
  );

  server.tool(
    "office365_activity_list_content_types",
    toolText({
      summary: "List the supported Office 365 Management Activity content types.",
      useWhen: "you need to discover which content types can be subscribed to or queried",
      doNotUseWhen: "you already know the target content type and want a subscription or content call",
      permissions: "none",
      environment: "static catalog bundled with the current build",
      parameters: "none",
      response: "ok/status/data.contentTypes",
      failures: "500 if the catalog cannot be produced",
      safety: "",
      prerequisite: "office365_activity_connection_info",
      followUp: "office365_activity_start_subscription, office365_activity_list_available_content",
      example: '{"name":"office365_activity_list_content_types","arguments":{}}'
    }),
    {},
    withErrorHandling(allowSensitiveOutput, async () => ({
      ok: true,
      status: 200,
      data: { contentTypes: office365Client.listContentTypes() }
    }))
  );

  server.tool(
    "office365_activity_list_subscriptions",
    toolText({
      summary: "List current Office 365 Management Activity subscriptions.",
      useWhen: "you need to inspect current subscription and webhook state",
      doNotUseWhen: "you need to modify a subscription; use start or stop instead",
      permissions: "a valid Office 365 Management Activity token",
      environment: "targets the tenant-scoped subscriptions/list endpoint",
      parameters: "tenantId (required string), publisherIdentifier (optional string), userId (optional string)",
      response: "ok/status/data with the current subscriptions array",
      failures: "401/403 invalid token or missing ActivityFeed.Read, 404 invalid tenant, 429 rate limiting, 5xx upstream errors",
      safety: "",
      prerequisite: "office365_activity_connection_info",
      followUp: "office365_activity_list_available_content, office365_activity_api_request",
      example: '{"name":"office365_activity_list_subscriptions","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000"}}'
    }),
    { tenantId: z.string().min(1), publisherIdentifier: z.string().min(1).optional(), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, publisherIdentifier, userId }) => ({
      ok: true,
      status: 200,
      data: await office365Client.listSubscriptions({ tenantId, publisherIdentifier, userId })
    }))
  );

  server.tool(
    "office365_activity_start_subscription",
    toolText({
      summary: "Start or update an Office 365 Management Activity subscription.",
      useWhen: "you want to begin retrieving content blobs for a tenant and content type or attach or update a webhook",
      doNotUseWhen: "you only need to inspect existing subscriptions; use list subscriptions instead",
      permissions: "MCP_ADMIN_AUTH_KEY when configured and a valid Office 365 Management Activity token",
      environment: "POSTs to /subscriptions/start with the tenant-scoped root and contentType query parameter",
      parameters: "tenantId (required string), contentType (required string), publisherIdentifier (optional string), webhook (optional object with address, authId, expiration), userId (optional string), authorizationKey (optional string)",
      response: "ok/status/data with the subscription and webhook state",
      failures: "401 when admin authorization is required, 400 invalid content type or webhook, 403 ActivityFeed.Read missing, 409/429 upstream throttling or state errors",
      safety: "this mutates tenant subscription state and can trigger webhook validation",
      prerequisite: "office365_activity_list_content_types",
      followUp: "office365_activity_list_subscriptions, office365_activity_list_available_content",
      example: '{"name":"office365_activity_start_subscription","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","contentType":"Audit.SharePoint"}}'
    }),
    { tenantId: z.string().min(1), contentType: z.string().min(1), publisherIdentifier: z.string().min(1).optional(), webhook: z.object({ address: z.string().min(1), authId: z.string().min(1).optional(), expiration: z.union([z.string(), z.null()]).optional() }).optional(), userId: z.string().min(1).optional(), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, contentType, publisherIdentifier, webhook, userId, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await office365Client.startSubscription({ tenantId, contentType, publisherIdentifier, webhook, userId })
      };
    })
  );

  server.tool(
    "office365_activity_stop_subscription",
    toolText({
      summary: "Stop an Office 365 Management Activity subscription.",
      useWhen: "you need to stop notifications and content retrieval for a tenant/content type subscription",
      doNotUseWhen: "you need to keep receiving content; use list or content tools instead",
      permissions: "MCP_ADMIN_AUTH_KEY when configured and a valid Office 365 Management Activity token",
      environment: "POSTs to /subscriptions/stop with the tenant-scoped root and contentType query parameter",
      parameters: "tenantId (required string), contentType (required string), publisherIdentifier (optional string), userId (optional string), authorizationKey (optional string)",
      response: "ok/status/data with the stop result",
      failures: "401 when admin authorization is required, 400 invalid content type, 403 ActivityFeed.Read missing, 404 no subscription found, 429/5xx upstream errors",
      safety: "this stops retrieval for the specified subscription and drops access to future content until restarted",
      prerequisite: "office365_activity_list_subscriptions",
      followUp: "office365_activity_start_subscription, office365_activity_list_available_content",
      example: '{"name":"office365_activity_stop_subscription","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","contentType":"Audit.SharePoint"}}'
    }),
    { tenantId: z.string().min(1), contentType: z.string().min(1), publisherIdentifier: z.string().min(1).optional(), userId: z.string().min(1).optional(), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, contentType, publisherIdentifier, userId, authorizationKey }) => {
      assertAuthorized(adminAuthKey, authorizationKey);
      return {
        ok: true,
        status: 200,
        data: await office365Client.stopSubscription({ tenantId, contentType, publisherIdentifier, userId })
      };
    })
  );

  server.tool(
    "office365_activity_list_available_content",
    toolText({
      summary: "List available Office 365 content blobs for a tenant and content type.",
      useWhen: "you need to discover which content blob URIs are ready for retrieval",
      doNotUseWhen: "you only need notification history; use the notifications tool instead",
      permissions: "a valid Office 365 Management Activity token",
      environment: "GETs /subscriptions/content with optional startTime and endTime window validation",
      parameters: "tenantId (required string), contentType (required string), publisherIdentifier (optional string), startTime (optional datetime), endTime (optional datetime), userId (optional string)",
      response: "ok/status/data with a content array and NextPageUri when paginated",
      failures: "401/403 invalid token or missing ActivityFeed.Read, 400 invalid content type or time window, 404 disabled subscription, 429/5xx upstream errors",
      safety: "",
      prerequisite: "office365_activity_start_subscription",
      followUp: "office365_activity_get_content, office365_activity_list_notifications",
      example: '{"name":"office365_activity_list_available_content","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","contentType":"Audit.SharePoint"}}'
    }),
    { tenantId: z.string().min(1), contentType: z.string().min(1), publisherIdentifier: z.string().min(1).optional(), startTime: z.union([z.string(), z.null()]).optional(), endTime: z.union([z.string(), z.null()]).optional(), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, contentType, publisherIdentifier, startTime, endTime, userId }) => ({
      ok: true,
      status: 200,
      data: await office365Client.listContent({ tenantId, contentType, publisherIdentifier, startTime, endTime, userId })
    }))
  );

  server.tool(
    "office365_activity_list_notifications",
    toolText({
      summary: "List Office 365 notification attempts for a tenant and content type.",
      useWhen: "you are investigating webhook delivery history or retry behavior",
      doNotUseWhen: "you need to determine what content is available right now; use list available content instead",
      permissions: "a valid Office 365 Management Activity token",
      environment: "GETs /subscriptions/notifications with optional startTime and endTime window validation",
      parameters: "tenantId (required string), contentType (required string), publisherIdentifier (optional string), startTime (optional datetime), endTime (optional datetime), userId (optional string)",
      response: "ok/status/data with a notification array and NextPageUri when paginated",
      failures: "401/403 invalid token or missing ActivityFeed.Read, 400 invalid content type or time window, 404 disabled subscription, 429/5xx upstream errors",
      safety: "",
      prerequisite: "office365_activity_start_subscription",
      followUp: "office365_activity_get_content, office365_activity_api_request",
      example: '{"name":"office365_activity_list_notifications","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","contentType":"Audit.SharePoint"}}'
    }),
    { tenantId: z.string().min(1), contentType: z.string().min(1), publisherIdentifier: z.string().min(1).optional(), startTime: z.union([z.string(), z.null()]).optional(), endTime: z.union([z.string(), z.null()]).optional(), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, contentType, publisherIdentifier, startTime, endTime, userId }) => ({
      ok: true,
      status: 200,
      data: await office365Client.listNotifications({ tenantId, contentType, publisherIdentifier, startTime, endTime, userId })
    }))
  );

  server.tool(
    "office365_activity_get_content",
    toolText({
      summary: "Retrieve an Office 365 Management Activity content blob by content URI.",
      useWhen: "you already have a contentUri from available content or a notification and want the actual activity records",
      doNotUseWhen: "you need to discover new content blobs; use list available content instead",
      permissions: "a valid Office 365 Management Activity token",
      environment: "GETs the exact contentUri and returns the JSON collection of records",
      parameters: "contentUri (required string), tenantId (required string), userId (optional string)",
      response: "ok/status/data with the content blob payload",
      failures: "401/403 invalid token or missing ActivityFeed.Read, 400 invalid contentUri, 404 expired or missing content, 429/5xx upstream errors",
      safety: "content blobs can contain sensitive audit data",
      prerequisite: "office365_activity_list_available_content",
      followUp: "office365_activity_api_request, office365_activity_list_notifications",
      example: '{"name":"office365_activity_get_content","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","contentUri":"https://manage.office.com/api/v1.0/..."}}'
    }),
    { tenantId: z.string().min(1), contentUri: z.string().min(1), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, contentUri, userId }) => ({
      ok: true,
      status: 200,
      data: await office365Client.getContent({ tenantId, contentUri, userId })
    }))
  );

  server.tool(
    "office365_activity_list_resource_friendly_names",
    toolText({
      summary: "Retrieve friendly names for Office 365 DLP sensitive types.",
      useWhen: "you need to map DLP GUIDs to friendly names or localize the display names",
      doNotUseWhen: "you need another resource type; the API currently supports DlpSensitiveType only",
      permissions: "a valid Office 365 Management Activity token and DLP sensitive data access where required",
      environment: "GETs /resources/dlpSensitiveTypes and optionally sends Accept-Language",
      parameters: "tenantId (required string), publisherIdentifier (optional string), acceptLanguage (optional string), userId (optional string)",
      response: "ok/status/data with id/name pairs",
      failures: "401/403 invalid token, 400 invalid Accept-Language, 429/5xx upstream errors",
      safety: "",
      prerequisite: "office365_activity_list_available_content",
      followUp: "office365_activity_get_content, office365_activity_api_request",
      example: '{"name":"office365_activity_list_resource_friendly_names","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","acceptLanguage":"en-US"}}'
    }),
    { tenantId: z.string().min(1), publisherIdentifier: z.string().min(1).optional(), acceptLanguage: z.string().min(1).optional(), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, publisherIdentifier, acceptLanguage, userId }) => ({
      ok: true,
      status: 200,
      data: await office365Client.listResourceFriendlyNames({ tenantId, publisherIdentifier, acceptLanguage, userId })
    }))
  );

  server.tool(
    "office365_activity_api_request",
    toolText({
      summary: "Run a generic Office 365 Management Activity API request.",
      useWhen: "you need a supported endpoint that is not covered by a dedicated Office 365 activity tool",
      doNotUseWhen: "a specialized Office 365 activity tool already models the operation more safely",
      permissions: "a valid Office 365 Management Activity token; mutating methods also need MCP_ADMIN_AUTH_KEY when configured",
      environment: "method is normalized to uppercase and path is resolved against the tenant-scoped activity feed root",
      parameters: "method (required string), path (required string), query (optional object), body (optional JSON), headers (optional object), tenantId (required string), publisherIdentifier (optional string), userId (optional string), tokenId (optional string), authorizationKey (optional string for mutating calls)",
      response: "ok/status/data plus request metadata and response headers",
      failures: "400 invalid path, time window, or body; 401 missing or invalid token or admin key; 403 upstream permission failure; 404 not found; 429 throttling; 5xx upstream or transport failure",
      safety: "treat POST, PUT, PATCH, and DELETE as destructive-capable operations",
      prerequisite: "office365_activity_connection_info",
      followUp: "office365_activity_get_content or another read tool for validation",
      example: '{"name":"office365_activity_api_request","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","method":"GET","path":"/subscriptions/list"}}'
    }),
    { method: z.string().min(1), path: z.string().min(1), query: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(), body: z.any().optional(), headers: z.record(z.string(), z.string()).optional(), tenantId: z.string().min(1), publisherIdentifier: z.string().min(1).optional(), userId: z.string().min(1).optional(), tokenId: z.string().min(1).optional(), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ method, path, query, body, headers, tenantId, publisherIdentifier, userId, tokenId, authorizationKey }) => {
      const normalizedMethod = normalizeMethod(method);
      if (MUTATING_METHODS.has(normalizedMethod)) {
        assertAuthorized(adminAuthKey, authorizationKey);
      }

      return {
        ok: true,
        status: 200,
        data: await office365Client.apiRequest({ method: normalizedMethod, path, query, body, headers, tenantId, publisherIdentifier, userId, tokenId, authorizationKey })
      };
    })
  );

  server.tool(
    "office365_service_comms_connection_info",
    toolText({
      summary: "Return Office 365 Service Communications API runtime metadata and tenant scope defaults.",
      useWhen: "you need to confirm the ServiceComms base URL, default tenant, or token model before reading service health data",
      doNotUseWhen: "you need live service status or message data; use the specific ServiceComms tools instead",
      permissions: "none",
      environment: "reports the resolved ServiceComms API base URL and default tenant scope",
      parameters: "none",
      response: "ok/status/data with server and ServiceComms connection details",
      failures: "500 if metadata assembly fails",
      safety: "",
      prerequisite: "none",
      followUp: "office365_service_comms_list_services, office365_service_comms_get_current_status",
      example: '{"name":"office365_service_comms_connection_info","arguments":{}}'
    }),
    {},
    withErrorHandling(allowSensitiveOutput, async () => ({
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
        serviceComms: {
          baseUrl: office365Client.baseUrl,
          defaultTenantId: office365Client.defaultTenantId || null,
          tokenModel: "multi-user-vault",
          api: "office-365-service-communications"
        }
      }
    }))
  );

  server.tool(
    "office365_service_comms_scope_info",
    toolText({
      summary: "Return the effective tenant scope used for Office 365 Service Communications API calls.",
      useWhen: "you need to know which tenant a service health or message query will target",
      doNotUseWhen: "you only need the runtime metadata; use office365_service_comms_connection_info instead",
      permissions: "none",
      environment: "defaults tenantId from environment when omitted",
      parameters: "tenantId (optional string), userId (optional string)",
      response: "ok/status/data with tenantId and token scope details",
      failures: "400 if tenant validation fails, 500 on normalization errors",
      safety: "",
      prerequisite: "none",
      followUp: "office365_service_comms_list_services, office365_service_comms_get_messages",
      example: '{"name":"office365_service_comms_scope_info","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000"}}'
    }),
    { tenantId: z.string().min(1).optional(), userId: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, userId }) => ({
      ok: true,
      status: 200,
      data: office365Client.scope({ tenantId, userId })
    }))
  );

  server.tool(
    "office365_service_comms_list_services",
    toolText({
      summary: "List subscribed Office 365 services from ServiceComms.",
      useWhen: "you need the catalog of subscribed services before drilling into health or incidents",
      doNotUseWhen: "you need service status or message timelines; use current or historical status instead",
      permissions: "a valid ServiceComms OAuth token with ServiceHealth.Read",
      environment: "GETs the tenant-scoped /ServiceComms/Services endpoint with optional $select",
      parameters: "tenantId (required string), userId (optional string), select (optional string)",
      response: "ok/status/data.value with Service entities",
      failures: "401/403 invalid token or missing ServiceHealth.Read, 404 invalid tenant, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "office365_service_comms_connection_info",
      followUp: "office365_service_comms_get_current_status, office365_service_comms_api_request",
      example: '{"name":"office365_service_comms_list_services","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000"}}'
    }),
    { tenantId: z.string().min(1), userId: z.string().min(1).optional(), select: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, userId, select }) => ({
      ok: true,
      status: 200,
      data: await office365Client.listServices({ tenantId, userId, select })
    }))
  );

  server.tool(
    "office365_service_comms_get_current_status",
    toolText({
      summary: "Get the current status of Office 365 services from ServiceComms.",
      useWhen: "you need a real-time view of service health and incidents for the tenant",
      doNotUseWhen: "you need a historical trend or message feed; use the historical or messages tool instead",
      permissions: "a valid ServiceComms OAuth token with ServiceHealth.Read",
      environment: "GETs the tenant-scoped /ServiceComms/CurrentStatus endpoint with optional workload filtering",
      parameters: "tenantId (required string), userId (optional string), workload (optional string), select (optional string)",
      response: "ok/status/data.value with WorkloadStatus entities",
      failures: "401/403 invalid token or missing ServiceHealth.Read, 404 invalid tenant, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "office365_service_comms_list_services",
      followUp: "office365_service_comms_get_historical_status, office365_service_comms_api_request",
      example: '{"name":"office365_service_comms_get_current_status","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","workload":"Exchange"}}'
    }),
    { tenantId: z.string().min(1), userId: z.string().min(1).optional(), workload: z.string().min(1).optional(), select: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, userId, workload, select }) => ({
      ok: true,
      status: 200,
      data: await office365Client.getCurrentStatus({ tenantId, userId, workload, select })
    }))
  );

  server.tool(
    "office365_service_comms_get_historical_status",
    toolText({
      summary: "Get the historical status timeline of Office 365 services from ServiceComms.",
      useWhen: "you need incident history or a day-by-day status view",
      doNotUseWhen: "you need the latest incident feed or messages; use current status or messages instead",
      permissions: "a valid ServiceComms OAuth token with ServiceHealth.Read",
      environment: "GETs the tenant-scoped /ServiceComms/HistoricalStatus endpoint with optional workload and statusTime filters",
      parameters: "tenantId (required string), userId (optional string), workload (optional string), statusTime (optional datetime), select (optional string)",
      response: "ok/status/data.value with WorkloadStatus entities",
      failures: "401/403 invalid token or missing ServiceHealth.Read, 404 invalid tenant, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "office365_service_comms_get_current_status",
      followUp: "office365_service_comms_get_messages, office365_service_comms_api_request",
      example: '{"name":"office365_service_comms_get_historical_status","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","workload":"Exchange"}}'
    }),
    { tenantId: z.string().min(1), userId: z.string().min(1).optional(), workload: z.string().min(1).optional(), statusTime: z.string().min(1).optional(), select: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, userId, workload, statusTime, select }) => ({
      ok: true,
      status: 200,
      data: await office365Client.getHistoricalStatus({ tenantId, userId, workload, statusTime, select })
    }))
  );

  server.tool(
    "office365_service_comms_get_messages",
    toolText({
      summary: "Get ServiceComms messages for incidents or message center updates.",
      useWhen: "you need incident details, message center communications, or change timelines",
      doNotUseWhen: "you need service status only; use the current or historical status tool instead",
      permissions: "a valid ServiceComms OAuth token with ServiceHealth.Read",
      environment: "GETs the tenant-scoped /ServiceComms/Messages endpoint with optional workload, time range, and paging filters",
      parameters: "tenantId (required string), userId (optional string), workload (optional string), startTime (optional datetime), endTime (optional datetime), messageType (optional string), id (optional string), top (optional integer), skip (optional integer), select (optional string)",
      response: "ok/status/data.value with Message entities",
      failures: "401/403 invalid token or missing ServiceHealth.Read, 400 invalid time window or paging constraints, 404 invalid tenant, 429 throttling, 5xx upstream errors",
      safety: "",
      prerequisite: "office365_service_comms_get_current_status",
      followUp: "office365_service_comms_api_request, office365_service_comms_list_services",
      example: '{"name":"office365_service_comms_get_messages","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","workload":"Exchange","top":10}}'
    }),
    { tenantId: z.string().min(1), userId: z.string().min(1).optional(), workload: z.string().min(1).optional(), startTime: z.string().min(1).optional(), endTime: z.string().min(1).optional(), messageType: z.string().min(1).optional(), id: z.string().min(1).optional(), top: z.union([z.number(), z.string()]).optional(), skip: z.union([z.number(), z.string()]).optional(), select: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ tenantId, userId, workload, startTime, endTime, messageType, id, top, skip, select }) => ({
      ok: true,
      status: 200,
      data: await office365Client.getMessages({ tenantId, userId, workload, startTime, endTime, messageType, id, top, skip, select })
    }))
  );

  server.tool(
    "office365_service_comms_api_request",
    toolText({
      summary: "Run a generic Office 365 Service Communications API request.",
      useWhen: "you need a supported ServiceComms endpoint that is not covered by a dedicated tool",
      doNotUseWhen: "a specialized ServiceComms tool already models the operation more safely",
      permissions: "a valid ServiceComms OAuth token with ServiceHealth.Read",
      environment: "method is normalized to uppercase and path is resolved against the tenant-scoped ServiceComms root",
      parameters: "method (required string), path (required string), query (optional object), body (optional JSON), headers (optional object), tenantId (required string), userId (optional string), tokenId (optional string), authorizationKey (optional string for mutating calls)",
      response: "ok/status/data plus request metadata and response headers",
      failures: "400 invalid path, query, or body; 401 missing or invalid token or admin key; 403 upstream permission failure; 404 not found; 429 throttling; 5xx upstream or transport failure",
      safety: "treat POST, PUT, PATCH, and DELETE as destructive-capable operations",
      prerequisite: "office365_service_comms_connection_info",
      followUp: "office365_service_comms_list_services or another read tool for validation",
      example: '{"name":"office365_service_comms_api_request","arguments":{"tenantId":"00000000-0000-0000-0000-000000000000","method":"GET","path":"/Messages"}}'
    }),
    { method: z.string().min(1), path: z.string().min(1), query: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(), body: z.any().optional(), headers: z.record(z.string(), z.string()).optional(), tenantId: z.string().min(1), userId: z.string().min(1).optional(), tokenId: z.string().min(1).optional(), authorizationKey: z.string().min(1).optional() },
    withErrorHandling(allowSensitiveOutput, async ({ method, path, query, body, headers, tenantId, userId, tokenId, authorizationKey }) => {
      const normalizedMethod = normalizeMethod(method);
      if (MUTATING_METHODS.has(normalizedMethod)) {
        assertAuthorized(adminAuthKey, authorizationKey);
      }

      return {
        ok: true,
        status: 200,
        data: await office365Client.requestServiceComms({ method: normalizedMethod, path, query, body, headers, tenantId, userId, tokenId, authorizationKey })
      };
    })
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
