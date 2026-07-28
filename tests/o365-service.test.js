import assert from "node:assert/strict";
import test from "node:test";

import { Office365ManagementActivityClient } from "../src/services/o365.js";

function createVaultMock() {
  const store = new Map();
  return {
    async readSecret(path) {
      return store.get(path) ?? null;
    },
    async setSecret(path, value) {
      store.set(path, value);
      return { ok: true, path };
    },
    async deleteSecret(path) {
      store.delete(path);
      return { ok: true, path };
    }
  };
}

test("Office365 client builds tenant-scoped requests", async () => {
  const vault = createVaultMock();
  const tokenStore = {
    async resolveActiveToken() {
      return { secret: { accessToken: "o365-token" }, metadata: { tokenId: "tok-1" }, scope: { userId: "default" } };
    }
  };

  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init: { method: init.method, headers: Object.fromEntries(init.headers.entries()), body: init.body ?? null } });
    return new Response(JSON.stringify([{ contentType: "Audit.SharePoint" }]), { status: 200, headers: { "content-type": "application/json" } });
  };

  const client = new Office365ManagementActivityClient({
    baseUrl: "https://manage.office.com/api/v1.0",
    defaultTenantId: "00000000-0000-0000-0000-000000000000",
    defaultPublisherIdentifier: "11111111-1111-1111-1111-111111111111",
    tokenStore,
    configStore: { listConfigs: async () => [], resolveConfig: async () => null, setConfig: async () => null, deleteConfig: async () => false },
    defaultUserId: "default",
    allowSensitiveOutput: false,
    fetchImpl
  });

  const response = await client.listSubscriptions({ tenantId: "22222222-2222-2222-2222-222222222222" });
  assert.equal(response.status, 200);
  assert.equal(calls[0].url, "https://manage.office.com/api/v1.0/22222222-2222-2222-2222-222222222222/activity/feed/subscriptions/list?PublisherIdentifier=11111111-1111-1111-1111-111111111111");
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.authorization, "Bearer o365-token");
});

test("Office365 ServiceComms requests target the ServiceComms root", async () => {
  const tokenStore = {
    async resolveActiveToken() {
      return { secret: { accessToken: "o365-token" }, metadata: { tokenId: "tok-1" }, scope: { userId: "default" } };
    }
  };

  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init: { method: init.method, headers: Object.fromEntries(init.headers.entries()), body: init.body ?? null } });
    return new Response(JSON.stringify([{ workload: "Exchange", status: "ServiceDegradation" }]), { status: 200, headers: { "content-type": "application/json" } });
  };

  const client = new Office365ManagementActivityClient({
    baseUrl: "https://manage.office.com/api/v1.0",
    defaultTenantId: "00000000-0000-0000-0000-000000000000",
    defaultPublisherIdentifier: "11111111-1111-1111-1111-111111111111",
    tokenStore,
    configStore: { listConfigs: async () => [], resolveConfig: async () => null, setConfig: async () => null, deleteConfig: async () => false },
    defaultUserId: "default",
    allowSensitiveOutput: false,
    fetchImpl
  });

  await client.listServices({ tenantId: "22222222-2222-2222-2222-222222222222", select: "Id,Workload" });
  assert.equal(calls[0].url, "https://manage.office.com/api/v1.0/22222222-2222-2222-2222-222222222222/ServiceComms/Services?%24select=Id%2CWorkload");

  await client.getCurrentStatus({ tenantId: "22222222-2222-2222-2222-222222222222", workload: "Exchange" });
  assert.equal(calls[1].url, "https://manage.office.com/api/v1.0/22222222-2222-2222-2222-222222222222/ServiceComms/CurrentStatus?Workload=Exchange");

  await client.getHistoricalStatus({ tenantId: "22222222-2222-2222-2222-222222222222", workload: "Exchange", statusTime: "2024-01-01T00:00:00Z" });
  assert.equal(calls[2].url, "https://manage.office.com/api/v1.0/22222222-2222-2222-2222-222222222222/ServiceComms/HistoricalStatus?Workload=Exchange&StatusTime=2024-01-01T00%3A00%3A00Z");

  await client.getMessages({ tenantId: "22222222-2222-2222-2222-222222222222", workload: "Exchange", messageType: "Incident", top: 10, skip: 5, select: "Id,Title" });
  assert.equal(calls[3].url, "https://manage.office.com/api/v1.0/22222222-2222-2222-2222-222222222222/ServiceComms/Messages?Workload=Exchange&MessageType=Incident&%24top=10&%24skip=5&%24select=Id%2CTitle");
  assert.equal(calls[3].init.method, "GET");
});
