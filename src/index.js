import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { env } from "./config/env.js";
import { ConfigStore } from "./services/configStore.js";
import { GraphServiceClient, GraphTokenStore } from "./services/graph.js";
import { VaultService } from "./services/vault.js";
import { createMcpServer } from "./mcp/server.js";

async function main() {
  if (env.transport.mode === "http") {
    await import("./http/index.js");
    return;
  }

  if (env.transport.mode === "both") {
    await import("./start-both.js");
    return;
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

  const server = createMcpServer({
    name: env.mcpServerName,
    version: env.mcpServerVersion,
    graphClient,
    appName: env.appName,
    defaultUserId: env.defaultUserId,
    adminAuthKey: env.adminAuthKey,
    allowSensitiveOutput: env.allowSensitiveOutput
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  const shutdown = async () => {
    await server.close();
    await configStore.close().catch(() => undefined);
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("MCP server failed to start", error);
  process.exit(1);
});
