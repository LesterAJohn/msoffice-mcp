import assert from "node:assert/strict";
import test from "node:test";

import { GraphServiceClient, GraphTokenStore } from "../src/services/graph.js";

function createVaultMock() {
  const store = new Map();
  return {
    store,
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

test("GraphTokenStore stores tokens per user and falls back to default user", async () => {
  const vault = createVaultMock();
  const tokenStore = new GraphTokenStore({ vaultService: vault, appName: "msoffice", defaultUserId: "default" });

  const metadata = await tokenStore.upsertToken({ userId: "alice", tokenId: "tok-1", accessToken: "alice-access", scopes: ["User.Read"], audience: ["graph"] });
  assert.equal(metadata.tokenId, "tok-1");
  assert.equal(metadata.userId, "alice");

  const resolved = await tokenStore.resolveActiveToken({ userId: "alice" });
  assert.equal(resolved.secret.accessToken, "alice-access");

  const defaultMetadata = await tokenStore.upsertToken({ userId: "default", tokenId: "tok-default", accessToken: "default-access" });
  assert.equal(defaultMetadata.tokenId, "tok-default");

  const fallback = await tokenStore.resolveActiveToken({ userId: "missing-user" });
  assert.equal(fallback.secret.accessToken, "default-access");
});

test("GraphServiceClient request builds Graph URLs and attaches bearer tokens", async () => {
  const vault = createVaultMock();
  const tokenStore = new GraphTokenStore({ vaultService: vault, appName: "msoffice", defaultUserId: "default" });
  await tokenStore.upsertToken({ userId: "default", tokenId: "tok-default", accessToken: "default-access" });

  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init: { method: init.method, headers: Object.fromEntries(init.headers.entries()), body: init.body ?? null } });
    return new Response(JSON.stringify({ value: [] }), { status: 200, headers: { "content-type": "application/json" } });
  };

  const client = new GraphServiceClient({
    baseUrl: "https://graph.microsoft.com/v1.0",
    betaBaseUrl: "https://graph.microsoft.com/beta",
    tokenStore,
    configStore: { listConfigs: async () => [], resolveConfig: async () => null, setConfig: async () => null, deleteConfig: async () => false },
    defaultUserId: "default",
    allowSensitiveOutput: false,
    fetchImpl
  });

  const response = await client.request({ method: "get", path: "users?$top=1" });
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://graph.microsoft.com/v1.0/users?$top=1");
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.headers.authorization, "Bearer default-access");
});
