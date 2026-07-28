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
            confidence: 1
          }
        ]
      };
    },
    listProperties(entity) {
      return {
        entity,
        properties: ["displayName", "id"],
        relationships: ["memberOf"]
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
    const { client } = createGraphClientMock();
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

    const properties = await invokeTool(server, "microsoft_graph_list_properties", { entity: "user" });
    assert.equal(properties.payload.ok, true);
    assert.equal(properties.payload.data.entity, "user");
    assert.ok(properties.payload.data.properties.includes("displayName"));

    const readOnly = await invokeTool(server, "microsoft_graph_get", { path: "/users/$count" });
    assert.equal(readOnly.payload.ok, true);
    assert.equal(readOnly.payload.data.echoed.method, "GET");
    assert.equal(readOnly.payload.data.echoed.path, "/users/$count");
  } finally {
    restoreEnv();
  }
});
