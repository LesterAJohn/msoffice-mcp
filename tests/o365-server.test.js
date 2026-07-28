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

function createOffice365ClientMock() {
  return {
    getConnectionInfo() {
      return {
        baseUrl: "https://manage.office.com/api/v1.0",
        defaultTenantId: "00000000-0000-0000-0000-000000000000",
        defaultPublisherIdentifier: "11111111-1111-1111-1111-111111111111",
        tokenModel: "multi-user-vault",
        api: "office-365-management-activity"
      };
    },
    listContentTypes() {
      return ["Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All"];
    },
    scope(args) {
      return {
        tenantId: args.tenantId ?? "00000000-0000-0000-0000-000000000000",
        publisherIdentifier: args.publisherIdentifier ?? "11111111-1111-1111-1111-111111111111",
        userId: args.userId ?? "default"
      };
    },
    async listSubscriptions() {
      return { status: 200, data: [{ contentType: "Audit.SharePoint", status: "enabled" }] };
    },
    async startSubscription() {
      return { status: 200, data: { contentType: "Audit.SharePoint", status: "enabled" } };
    },
    async stopSubscription() {
      return { status: 200, data: null };
    },
    async listContent() {
      return { status: 200, data: [{ contentType: "Audit.SharePoint", contentUri: "https://example/content" }] };
    },
    async listNotifications() {
      return { status: 200, data: [{ contentType: "Audit.SharePoint", notificationStatus: "success" }] };
    },
    async getContent() {
      return { status: 200, data: [{ Operation: "Add User." }] };
    },
    async listResourceFriendlyNames() {
      return { status: 200, data: [{ id: "guid", name: "CreditCardNumber" }] };
    },
    async apiRequest(payload) {
      return { status: 200, echoed: payload };
    },
    async listServices() {
      return { status: 200, data: [{ workload: "Exchange" }] };
    },
    async getCurrentStatus() {
      return { status: 200, data: [{ workload: "Exchange", status: "ServiceDegradation" }] };
    },
    async getHistoricalStatus() {
      return { status: 200, data: [{ workload: "Exchange", statusTime: "2024-01-01T00:00:00Z" }] };
    },
    async getMessages() {
      return { status: 200, data: [{ id: "msg-1", messageType: "Incident" }] };
    },
    async requestServiceComms(payload) {
      return { status: 200, echoed: payload };
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

test("official Office 365 management tools are exposed", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "super-secret" });
  try {
    const office365Client = createOffice365ClientMock();
    const server = createMcpServer({
      name: "msoffice-mcp",
      version: "0.1.0",
      graphClient: { getConnectionInfo() { return {}; }, listKnownCapabilities() { return []; }, listSuggestedQueries() { return { suggestions: [] }; }, listProperties() { return { properties: [] }; }, healthCheck() { return { ok: true }; }, request() { return { status: 200 }; }, userProfile() { return { status: 200 }; }, queryCollection() { return { status: 200 }; }, updateToken() { return {}; }, deactivateToken() { return {}; }, removeToken() { return true; }, listTokens() { return []; }, configList() { return []; }, configGet() { return null; }, configSet() { return {}; }, configDelete() { return true; }, tokenStore: { readTokenSecret() { return { accessToken: "secret-token" }; } } },
      office365Client,
      appName: "msoffice",
      defaultUserId: "default",
      adminAuthKey: "super-secret",
      allowSensitiveOutput: false
    });

    const connection = await invokeTool(server, "office365_activity_connection_info");
    assert.equal(connection.payload.ok, true);
    assert.equal(connection.payload.data.office365.api, "office-365-management-activity");

    const serviceConnection = await invokeTool(server, "office365_service_comms_connection_info");
    assert.equal(serviceConnection.payload.ok, true);
    assert.equal(serviceConnection.payload.data.serviceComms.api, "office-365-service-communications");

    const contentTypes = await invokeTool(server, "office365_activity_list_content_types");
    assert.equal(contentTypes.payload.ok, true);
    assert.ok(contentTypes.payload.data.contentTypes.includes("Audit.SharePoint"));

    const subscriptions = await invokeTool(server, "office365_activity_list_subscriptions", { tenantId: "22222222-2222-2222-2222-222222222222" });
    assert.equal(subscriptions.payload.ok, true);
    assert.equal(subscriptions.payload.data.status, 200);

    const start = await invokeTool(server, "office365_activity_start_subscription", { tenantId: "22222222-2222-2222-2222-222222222222", contentType: "Audit.SharePoint", authorizationKey: "super-secret" });
    assert.equal(start.payload.ok, true);

    const listContent = await invokeTool(server, "office365_activity_list_available_content", { tenantId: "22222222-2222-2222-2222-222222222222", contentType: "Audit.SharePoint" });
    assert.equal(listContent.payload.ok, true);

    const notifications = await invokeTool(server, "office365_activity_list_notifications", { tenantId: "22222222-2222-2222-2222-222222222222", contentType: "Audit.SharePoint" });
    assert.equal(notifications.payload.ok, true);

    const resourceNames = await invokeTool(server, "office365_activity_list_resource_friendly_names", { tenantId: "22222222-2222-2222-2222-222222222222" });
    assert.equal(resourceNames.payload.ok, true);

    const generic = await invokeTool(server, "office365_activity_api_request", { tenantId: "22222222-2222-2222-2222-222222222222", method: "GET", path: "/subscriptions/list" });
    assert.equal(generic.payload.ok, true);
    assert.equal(generic.payload.data.echoed.method, "GET");

    const serviceList = await invokeTool(server, "office365_service_comms_list_services", { tenantId: "22222222-2222-2222-2222-222222222222" });
    assert.equal(serviceList.payload.ok, true);

    const currentStatus = await invokeTool(server, "office365_service_comms_get_current_status", { tenantId: "22222222-2222-2222-2222-222222222222", workload: "Exchange" });
    assert.equal(currentStatus.payload.ok, true);

    const historicalStatus = await invokeTool(server, "office365_service_comms_get_historical_status", { tenantId: "22222222-2222-2222-2222-222222222222", workload: "Exchange" });
    assert.equal(historicalStatus.payload.ok, true);

    const messages = await invokeTool(server, "office365_service_comms_get_messages", { tenantId: "22222222-2222-2222-2222-222222222222", workload: "Exchange", top: 10 });
    assert.equal(messages.payload.ok, true);

    const serviceGeneric = await invokeTool(server, "office365_service_comms_api_request", { tenantId: "22222222-2222-2222-2222-222222222222", method: "GET", path: "/Messages" });
    assert.equal(serviceGeneric.payload.ok, true);
    assert.equal(serviceGeneric.payload.data.echoed.method, "GET");
  } finally {
    restoreEnv();
  }
});
