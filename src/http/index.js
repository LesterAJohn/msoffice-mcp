import { env } from "../config/env.js";
import { ConfigStore } from "../services/configStore.js";
import { GraphServiceClient, GraphTokenStore } from "../services/graph.js";
import { VaultService } from "../services/vault.js";
import { createMcpServer } from "../mcp/server.js";
import { createHttpMcpServer } from "./server.js";

async function main() {
  if (env.transport.http.tls.enabled) {
    throw new Error("MCP_HTTP_TLS_ENABLED=true is not supported in this process mode. Terminate TLS at a reverse proxy or load balancer.");
  }

  const vaultService = new VaultService({
    endpoint: env.vault.addr,
    token: env.vault.token,
    kvMount: env.vault.kvMount,
    writeRetryAttempts: env.vault.writeRetryAttempts,
    writeRetryBaseDelayMs: env.vault.writeRetryBaseDelayMs,
    writeRetryMaxDelayMs: env.vault.writeRetryMaxDelayMs
  });

  const configStore = new ConfigStore(env.postgres, { appName: env.appName, defaultUserId: env.defaultUserId, tableName: env.identifiers.configTable });
  await configStore.init();

  const tokenStore = new GraphTokenStore({ vaultService, appName: env.appName, defaultUserId: env.defaultUserId });
  const graphClient = new GraphServiceClient({
    baseUrl: env.graph.baseUrl,
    betaBaseUrl: env.graph.betaBaseUrl,
    tokenStore,
    configStore,
    defaultUserId: env.defaultUserId,
    allowSensitiveOutput: env.allowSensitiveOutput
  });

  const httpServer = createHttpMcpServer({
    host: env.transport.http.host,
    port: env.transport.http.port,
    mcpPath: env.transport.http.mcpPath,
    healthPath: env.transport.http.healthPath,
    authMode: env.transport.http.authMode,
    authTokens: env.transport.http.authTokens,
    trustedProxy: env.transport.http.trustedProxy,
    allowedOrigins: env.transport.http.allowedOrigins,
    allowedIps: env.transport.http.allowedIps,
    maxBodyBytes: env.transport.http.maxBodyBytes,
    rateLimitWindowMs: env.transport.http.rateLimitWindowMs,
    rateLimitMaxRequests: env.transport.http.rateLimitMaxRequests,
    createMcpServer: () =>
      createMcpServer({
        name: env.mcpServerName,
        version: env.mcpServerVersion,
        graphClient,
        appName: env.appName,
        defaultUserId: env.defaultUserId,
        adminAuthKey: env.adminAuthKey,
        allowSensitiveOutput: env.allowSensitiveOutput
      })
  });

  await httpServer.start();

  console.log(`HTTP MCP server listening on http://${httpServer.host}:${httpServer.port}${httpServer.mcpPath}`);

  const shutdown = async () => {
    await httpServer.close();
    await configStore.close().catch(() => undefined);
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("HTTP MCP server failed to start", error);
  process.exit(1);
});
