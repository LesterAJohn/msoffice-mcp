import assert from "node:assert/strict";
import test from "node:test";

import { createMcpServer } from "../src/mcp/server.js";

function setEnv(updates) {
  const previous = {};
  for (const [key, value] of Object.entries(updates)) {
    previous[key] = process.env[key];
    if (value === undefined || value === null) {
      delete process.env[key];
    } else {
      process.env[key] = String(value);
    }
  }

  return () => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  };
}

function createGraphClientMock() {
  const calls = {
    request: [],
    healthCheck: 0,
    updateToken: [],
    deactivateToken: [],
    removeToken: [],
    configSet: [],
    configDelete: []
  };

  const client = {
    getConnectionInfo() {
      return {
        baseUrl: "https://graph.microsoft.com/v1.0",
        betaBaseUrl: "https://graph.microsoft.com/beta",
        defaultUserId: "default",
        tokenModel: "multi-user-vault",
        configModel: "postgres-key-value",
        genericCoverage: true
      };
    },
    listKnownCapabilities() {
      return [{ family: "users", examples: ["/users"] }];
    },
    listSuggestedQueries(prompt) {
      return {
        prompt,
        suggestions: [
          {
            description: "Count users in the tenant",
            method: "GET",
            path: "/users/$count",
            query: {},
            entity: "user",
            mcpTool: "microsoft_graph_get",
            confidence: 1
          }
        ]
      };
    },
    listProperties(entity) {
      const normalizedEntity = String(entity ?? "").trim().toLowerCase();
      if (normalizedEntity === "user") {
        return {
          entity: "user",
          properties: ["displayName", "id"],
          relationships: ["memberOf"],
          recommendedTools: ["graph_users_query", "microsoft_graph_get", "graph_api_request"]
        };
      }

      return {
        entity: normalizedEntity || null,
        properties: [],
        relationships: [],
        recommendedTools: [],
        knownEntities: ["user", "group", "application", "device", "copilot_package"]
      };
    },
    async healthCheck() {
      calls.healthCheck += 1;
      return { ok: true, status: 200 };
    },
    async request(payload) {
      calls.request.push(payload);
      return { status: 200, echoed: payload };
    },
    async userProfile(payload) {
      calls.request.push({ ...payload, path: "/me" });
      return { status: 200, me: true };
    },
    async queryCollection(payload) {
      calls.request.push(payload);
      return { status: 200, collection: true, payload };
    },
    async updateToken(payload) {
      calls.updateToken.push(payload);
      return { tokenId: payload.tokenId ?? "generated", userId: payload.userId, active: true };
    },
    async deactivateToken(payload) {
      calls.deactivateToken.push(payload);
      return { tokenId: payload.tokenId, userId: payload.userId, active: false };
    },
    async removeToken(payload) {
      calls.removeToken.push(payload);
      return true;
    },
    async listTokens() {
      return [{ tokenId: "graph-1", active: true }];
    },
    async configList() {
      return [{ user_id: "default", key: "graph.baseUrl", value: "https://graph.microsoft.com/v1.0" }];
    },
    async configGet({ key }) {
      return { key, source: "user", value: "https://graph.microsoft.com/v1.0" };
    },
    async configSet(payload) {
      calls.configSet.push(payload);
      return { user_id: payload.userId ?? "default", key: payload.key, value: payload.value };
    },
    async configDelete(payload) {
      calls.configDelete.push(payload);
      return true;
    },
    tokenStore: {
      async readTokenSecret() {
        return { accessToken: "secret-token" };
      }
    }
  };

  return { client, calls };
}

async function invokeTool(server, name, args = {}) {
  const registeredTools = server._registeredTools;
  assert.ok(registeredTools[name], `Expected tool ${name} to be registered`);
  const result = await registeredTools[name].handler(args);
  const payload = JSON.parse(result.content[0].text);
  return { result, payload };
}

test("graph_health_check returns ok", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });
  try {
    const { client, calls } = createGraphClientMock();
    const server = createMcpServer({
      name: "msoffice-mcp",
      version: "0.1.0",
      graphClient: client,
      appName: "msoffice",
      defaultUserId: "default",
      adminAuthKey: "",
      allowSensitiveOutput: false
    });

    const { payload } = await invokeTool(server, "graph_health_check");
    assert.equal(payload.ok, true);
    assert.equal(payload.status, 200);
    assert.equal(calls.healthCheck, 1);
  } finally {
    restoreEnv();
  }
});

test("mutating graph tools require authorizationKey when admin key is configured", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "super-secret" });
  try {
    const { client, calls } = createGraphClientMock();
    const server = createMcpServer({
      name: "msoffice-mcp",
      version: "0.1.0",
      graphClient: client,
      appName: "msoffice",
      defaultUserId: "default",
      adminAuthKey: "super-secret",
      allowSensitiveOutput: false
    });

    const unauthorized = await invokeTool(server, "graph_config_set", { key: "graph.baseUrl", value: "https://graph.microsoft.com/v1.0" });
    assert.equal(unauthorized.result.isError, true);
    assert.equal(unauthorized.payload.status, 401);

    const authorized = await invokeTool(server, "graph_config_set", {
      key: "graph.baseUrl",
      value: "https://graph.microsoft.com/v1.0",
      authorizationKey: "super-secret"
    });
    assert.equal(authorized.payload.ok, true);
    assert.equal(calls.configSet.length, 1);

    const tokenUnauthorized = await invokeTool(server, "graph_user_token_upsert", {
      userId: "default",
      accessToken: "secret-token"
    });
    assert.equal(tokenUnauthorized.result.isError, true);
    assert.equal(tokenUnauthorized.payload.status, 401);

    const tokenAuthorized = await invokeTool(server, "graph_user_token_upsert", {
      userId: "default",
      accessToken: "secret-token",
      authorizationKey: "super-secret"
    });
    assert.equal(tokenAuthorized.payload.ok, true);
    assert.equal(calls.updateToken.length, 1);

    const copilotMutationUnauthorized = await invokeTool(server, "copilot_package_block", {
      packageId: "pkg-1"
    });
    assert.equal(copilotMutationUnauthorized.result.isError, true);
    assert.equal(copilotMutationUnauthorized.payload.status, 401);

    const copilotMutationAuthorized = await invokeTool(server, "copilot_package_block", {
      packageId: "pkg-1",
      authorizationKey: "super-secret"
    });
    assert.equal(copilotMutationAuthorized.payload.ok, true);

    const subscriptionUnauthorized = await invokeTool(server, "copilot_change_notifications_create_subscription", {
      changeType: "created,updated,deleted",
      notificationUrl: "https://example.com/webhook",
      resource: "/copilot/interactionHistory/getAllEnterpriseInteractions",
      expirationDateTime: "2026-12-01T00:00:00Z"
    });
    assert.equal(subscriptionUnauthorized.result.isError, true);
    assert.equal(subscriptionUnauthorized.payload.status, 401);

    const subscriptionAuthorized = await invokeTool(server, "copilot_change_notifications_create_subscription", {
      changeType: "created,updated,deleted",
      notificationUrl: "https://example.com/webhook",
      resource: "/copilot/interactionHistory/getAllEnterpriseInteractions",
      expirationDateTime: "2026-12-01T00:00:00Z",
      authorizationKey: "super-secret"
    });
    assert.equal(subscriptionAuthorized.payload.ok, true);
  } finally {
    restoreEnv();
  }
});

test("graph_api_request normalizes method and path", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });
  try {
    const { client, calls } = createGraphClientMock();
    const server = createMcpServer({
      name: "msoffice-mcp",
      version: "0.1.0",
      graphClient: client,
      appName: "msoffice",
      defaultUserId: "default",
      adminAuthKey: "",
      allowSensitiveOutput: false
    });

    const { payload } = await invokeTool(server, "graph_api_request", { method: "get", path: "users?$top=1" });
    assert.equal(payload.ok, true);
    assert.equal(calls.request.length, 1);
    assert.equal(calls.request[0].method, "GET");
    assert.equal(calls.request[0].path, "/users?$top=1");
  } finally {
    restoreEnv();
  }
});

test("official Microsoft Graph tools are exposed", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });
  try {
    const { client, calls } = createGraphClientMock();
    const server = createMcpServer({
      name: "msoffice-mcp",
      version: "0.1.0",
      graphClient: client,
      appName: "msoffice",
      defaultUserId: "default",
      adminAuthKey: "",
      allowSensitiveOutput: false
    });

    const suggest = await invokeTool(server, "microsoft_graph_suggest_queries", { prompt: "How many users do we have?" });
    assert.equal(suggest.payload.ok, true);
    assert.ok(Array.isArray(suggest.payload.data.suggestions));
    assert.ok(suggest.payload.data.suggestions.length > 0);
    assert.equal(suggest.payload.data.suggestions[0].mcpTool, "microsoft_graph_get");

    const properties = await invokeTool(server, "microsoft_graph_list_properties", { entity: "user" });
    assert.equal(properties.payload.ok, true);
    assert.equal(properties.payload.data.entity, "user");
    assert.ok(properties.payload.data.properties.includes("displayName"));
    assert.ok(properties.payload.data.recommendedTools.includes("graph_users_query"));

    const unknownProperties = await invokeTool(server, "microsoft_graph_list_properties", { entity: "unknown_entity" });
    assert.equal(unknownProperties.payload.ok, true);
    assert.equal(unknownProperties.payload.data.entity, "unknown_entity");
    assert.ok(Array.isArray(unknownProperties.payload.data.recommendedTools));
    assert.equal(unknownProperties.payload.data.recommendedTools.length, 0);

    const readOnly = await invokeTool(server, "microsoft_graph_get", { path: "/users/$count" });
    assert.equal(readOnly.payload.ok, true);
    assert.equal(readOnly.payload.data.echoed.method, "GET");
    assert.equal(readOnly.payload.data.echoed.path, "/users/$count");

    const capabilities = await invokeTool(server, "copilot_api_capabilities");
    assert.equal(capabilities.payload.ok, true);
    assert.ok(Array.isArray(capabilities.payload.data.capabilities));
    assert.ok(capabilities.payload.data.capabilities.length > 0);

    const retrieval = await invokeTool(server, "copilot_retrieval_query", {
      queryString: "How to setup corporate VPN?",
      dataSource: "sharePoint"
    });
    assert.equal(retrieval.payload.ok, true);

    const search = await invokeTool(server, "copilot_search_query", {
      query: "quarterly budget analysis"
    });
    assert.equal(search.payload.ok, true);

    const createConversation = await invokeTool(server, "copilot_chat_create_conversation", {});
    assert.equal(createConversation.payload.ok, true);

    const syncChat = await invokeTool(server, "copilot_chat_send_message", {
      conversationId: "conversation-1",
      messageText: "What meeting do I have at 9 AM tomorrow morning?",
      locationHint: { timeZone: "America/New_York" }
    });
    assert.equal(syncChat.payload.ok, true);

    const streamChat = await invokeTool(server, "copilot_chat_send_message_stream", {
      conversationId: "conversation-1",
      messageText: "Summarize this document for me.",
      locationHint: { timeZone: "America/New_York" }
    });
    assert.equal(streamChat.payload.ok, true);

    const interactions = await invokeTool(server, "copilot_interactions_list", {
      interactionUserId: "user-1",
      top: 100
    });
    assert.equal(interactions.payload.ok, true);

    const meetingInsightsList = await invokeTool(server, "copilot_meeting_insights_list", {
      meetingUserId: "user-1",
      onlineMeetingId: "meeting-1"
    });
    assert.equal(meetingInsightsList.payload.ok, true);

    const meetingInsightGet = await invokeTool(server, "copilot_meeting_insight_get", {
      meetingUserId: "user-1",
      onlineMeetingId: "meeting-1",
      aiInsightId: "insight-1"
    });
    assert.equal(meetingInsightGet.payload.ok, true);

    const usageSummary = await invokeTool(server, "copilot_usage_report_user_count_summary", {
      period: "D7",
      version: "v2"
    });
    assert.equal(usageSummary.payload.ok, true);

    const usageTrend = await invokeTool(server, "copilot_usage_report_user_count_trend", {
      period: "D30"
    });
    assert.equal(usageTrend.payload.ok, true);

    const usageDetail = await invokeTool(server, "copilot_usage_report_user_detail", {
      period: "D90"
    });
    assert.equal(usageDetail.payload.ok, true);

    const packages = await invokeTool(server, "copilot_packages_list", {
      top: 25
    });
    assert.equal(packages.payload.ok, true);

    const packageGet = await invokeTool(server, "copilot_package_get", {
      packageId: "pkg-1"
    });
    assert.equal(packageGet.payload.ok, true);

    const packageUpdate = await invokeTool(server, "copilot_package_update", {
      packageId: "pkg-1",
      body: { displayName: "Updated Name" }
    });
    assert.equal(packageUpdate.payload.ok, true);

    const packageUnblock = await invokeTool(server, "copilot_package_unblock", {
      packageId: "pkg-1"
    });
    assert.equal(packageUnblock.payload.ok, true);

    const packageReassign = await invokeTool(server, "copilot_package_reassign", {
      packageId: "pkg-1",
      body: { newOwner: "user-2" }
    });
    assert.equal(packageReassign.payload.ok, true);

    const paths = calls.request.map((entry) => entry.path);
    assert.ok(paths.includes("/copilot/retrieval"));
    assert.ok(paths.includes("/copilot/search"));
    assert.ok(paths.includes("/copilot/conversations"));
    assert.ok(paths.includes("/copilot/conversations/conversation-1/chat"));
    assert.ok(paths.includes("/copilot/conversations/conversation-1/chatOverStream"));
    assert.ok(paths.includes("/copilot/users/user-1/interactionHistory/getAllEnterpriseInteractions"));
    assert.ok(paths.includes("/copilot/users/user-1/onlineMeetings/meeting-1/aiInsights"));
    assert.ok(paths.includes("/copilot/users/user-1/onlineMeetings/meeting-1/aiInsights/insight-1"));
    assert.ok(paths.includes("/copilot/reports/getMicrosoft365CopilotUserCountSummary(period='D7', version='v2')"));
    assert.ok(paths.includes("/copilot/reports/getMicrosoft365CopilotUserCountTrend(period='D30')"));
    assert.ok(paths.includes("/copilot/reports/getMicrosoft365CopilotUsageUserDetail(period='D90')"));
    assert.ok(paths.includes("/copilot/admin/catalog/packages"));
    assert.ok(paths.includes("/copilot/admin/catalog/packages/pkg-1"));
    assert.ok(paths.includes("/copilot/admin/catalog/packages/pkg-1/unblock"));
    assert.ok(paths.includes("/copilot/admin/catalog/packages/pkg-1/reassign"));
  } finally {
    restoreEnv();
  }
});
