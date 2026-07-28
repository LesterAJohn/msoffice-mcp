import assert from "node:assert/strict";
import test from "node:test";

import { createMcpServer } from "../../src/mcp/server.js";
import { GraphServiceClient } from "../../src/services/graph.js";

const truthy = new Set(["1", "true", "yes", "on"]);

function isTruthy(value) {
  return truthy.has(String(value ?? "").trim().toLowerCase());
}

function requiredEnv(name) {
  const value = String(process.env[name] ?? "").trim();
  return value ? value : null;
}

function createOffice365ClientStub() {
  return {
    getConnectionInfo() {
      return {
        baseUrl: "https://manage.office.com/api/v1.0",
        defaultTenantId: "",
        defaultPublisherIdentifier: "",
        tokenModel: "multi-user-vault",
        api: "office-365-management-activity"
      };
    },
    listContentTypes() {
      return [];
    },
    scope(args = {}) {
      return { tenantId: args.tenantId ?? "", publisherIdentifier: args.publisherIdentifier ?? "", userId: args.userId ?? "default" };
    },
    async listSubscriptions() {
      return { status: 200, data: [] };
    },
    async startSubscription() {
      return { status: 200, data: {} };
    },
    async stopSubscription() {
      return { status: 200, data: {} };
    },
    async listContent() {
      return { status: 200, data: [] };
    },
    async listNotifications() {
      return { status: 200, data: [] };
    },
    async getContent() {
      return { status: 200, data: [] };
    },
    async listResourceFriendlyNames() {
      return { status: 200, data: [] };
    },
    async apiRequest() {
      return { status: 200, data: {} };
    },
    async listServices() {
      return { status: 200, data: [] };
    },
    async getCurrentStatus() {
      return { status: 200, data: [] };
    },
    async getHistoricalStatus() {
      return { status: 200, data: [] };
    },
    async getMessages() {
      return { status: 200, data: [] };
    },
    async requestServiceComms() {
      return { status: 200, data: {} };
    }
  };
}

async function invokeTool(server, name, args = {}) {
  const registeredTools = server._registeredTools;
  assert.ok(registeredTools[name], `Expected tool ${name} to be registered`);
  const result = await registeredTools[name].handler(args);
  const payload = JSON.parse(result.content[0].text);
  return { result, payload };
}

test("copilot usage report integration (live tenant)", async (t) => {
  if (!isTruthy(process.env.COPILOT_INTEGRATION_RUN)) {
    t.skip("Set COPILOT_INTEGRATION_RUN=true to enable live Copilot integration tests.");
    return;
  }

  const accessToken = requiredEnv("COPILOT_INTEGRATION_ACCESS_TOKEN");
  if (!accessToken) {
    t.skip("Missing COPILOT_INTEGRATION_ACCESS_TOKEN.");
    return;
  }

  const defaultUserId = String(process.env.COPILOT_INTEGRATION_USER_ID ?? "integration-user").trim() || "integration-user";
  const tokenId = String(process.env.COPILOT_INTEGRATION_TOKEN_ID ?? "integration-token").trim() || "integration-token";
  const period = String(process.env.COPILOT_INTEGRATION_PERIOD ?? "D7").trim() || "D7";
  const version = String(process.env.COPILOT_INTEGRATION_REPORT_VERSION ?? "v2").trim() || "v2";
  const useBetaBaseUrl = isTruthy(process.env.COPILOT_INTEGRATION_USE_BETA);

  const tokenStore = {
    async resolveActiveToken({ userId, tokenId: selectedTokenId }) {
      return {
        metadata: { tokenId: selectedTokenId ?? tokenId, userId: userId ?? defaultUserId },
        scope: { userId: userId ?? defaultUserId },
        secret: { accessToken }
      };
    }
  };

  const configStore = {
    async listConfigs() {
      return [];
    },
    async resolveConfig() {
      return null;
    },
    async setConfig() {
      return null;
    },
    async deleteConfig() {
      return false;
    }
  };

  const graphClient = new GraphServiceClient({
    baseUrl: String(process.env.COPILOT_INTEGRATION_GRAPH_BASE_URL ?? "https://graph.microsoft.com/v1.0").trim(),
    betaBaseUrl: String(process.env.COPILOT_INTEGRATION_GRAPH_BETA_BASE_URL ?? "https://graph.microsoft.com/beta").trim(),
    tokenStore,
    configStore,
    defaultUserId,
    allowSensitiveOutput: true
  });

  const server = createMcpServer({
    name: "msoffice-mcp",
    version: "0.1.0",
    graphClient,
    office365Client: createOffice365ClientStub(),
    appName: "msoffice",
    defaultUserId,
    adminAuthKey: "",
    allowSensitiveOutput: true
  });

  const report = await invokeTool(server, "copilot_usage_report_user_count_summary", {
    period,
    version,
    useBetaBaseUrl
  });

  if (report.result.isError) {
    const details = JSON.stringify(report.payload);
    assert.fail(`Live Copilot report call failed: ${details}`);
  }

  assert.equal(report.payload.ok, true);
  assert.equal(report.payload.status, 200);
});
