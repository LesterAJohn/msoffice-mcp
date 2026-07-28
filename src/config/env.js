import dotenv from "dotenv";

dotenv.config();

const TRANSPORT_MODES = new Set(["stdio", "http", "both"]);
const HTTP_AUTH_MODES = new Set(["token", "oauth2", "both"]);

function enumValue(name, fallback, allowedValues) {
  const value = String(process.env[name] ?? fallback).trim().toLowerCase();
  if (!allowedValues.has(value)) {
    throw new Error(`Environment variable ${name} must be one of: ${Array.from(allowedValues).join(", ")}`);
  }
  return value;
}

function required(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function portNumber(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Environment variable ${name} must be an integer between 1 and 65535`);
  }
  return value;
}

function positiveNumber(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`Environment variable ${name} must be a non-negative number`);
  }
  return value;
}

function booleanValue(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }

  const value = String(raw).trim().toLowerCase();
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }

  throw new Error(`Environment variable ${name} must be either true or false`);
}

function parseCsv(name, fallback = "") {
  return String(process.env[name] ?? fallback)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeAppName(value, fallback = "msoffice") {
  return String(value ?? fallback).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-") || fallback;
}

function normalizeIdentifier(value, fallback) {
  const candidate = String(value ?? fallback).trim().toLowerCase().replace(/[^a-z0-9_]/g, "_");
  if (!candidate || !/^[a-z][a-z0-9_]*$/.test(candidate)) {
    throw new Error(`Invalid identifier: ${value}`);
  }
  return candidate;
}

const transportMode = enumValue("MCP_TRANSPORT_MODE", "stdio", TRANSPORT_MODES);
const httpAuthMode = enumValue("MCP_HTTP_AUTH_MODE", "token", HTTP_AUTH_MODES);

export const env = {
  appName: normalizeAppName(process.env.APP_NAME, "msoffice"),
  mcpServerName: process.env.MCP_SERVER_NAME ?? "msoffice-mcp",
  mcpServerVersion: process.env.MCP_SERVER_VERSION ?? "0.1.0",
  adminAuthKey: process.env.MCP_ADMIN_AUTH_KEY ?? "",
  allowSensitiveOutput: booleanValue("MCP_ALLOW_SENSITIVE_OUTPUT", false),
  defaultUserId: String(process.env.MCP_CONFIG_DEFAULT_USER_ID ?? "default").trim() || "default",
  graph: {
    baseUrl: required("GRAPH_API_BASE_URL", "https://graph.microsoft.com/v1.0"),
    betaBaseUrl: required("GRAPH_API_BETA_BASE_URL", "https://graph.microsoft.com/beta"),
    defaultScope: String(process.env.GRAPH_DEFAULT_SCOPE ?? "default").trim() || "default",
    defaultUserId: String(process.env.GRAPH_DEFAULT_USER_ID ?? "default").trim() || "default"
  },
  transport: {
    mode: transportMode,
    http: {
      host: required("MCP_HTTP_HOST", "127.0.0.1"),
      port: portNumber("MCP_HTTP_PORT", "3000"),
      mcpPath: required("MCP_HTTP_PATH", "/mcp"),
      healthPath: required("MCP_HTTP_HEALTH_PATH", "/healthz"),
      authMode: httpAuthMode,
      authTokens: parseCsv("MCP_HTTP_AUTH_TOKENS", "replace-me-token"),
      trustedProxy: booleanValue("MCP_HTTP_TRUST_PROXY", false),
      allowedOrigins: parseCsv("MCP_HTTP_ALLOWED_ORIGINS", ""),
      allowedIps: parseCsv("MCP_HTTP_ALLOWED_IPS", ""),
      maxBodyBytes: positiveNumber("MCP_HTTP_MAX_BODY_BYTES", "1048576"),
      rateLimitWindowMs: positiveNumber("MCP_HTTP_RATE_LIMIT_WINDOW_MS", "60000"),
      rateLimitMaxRequests: positiveNumber("MCP_HTTP_RATE_LIMIT_MAX_REQUESTS", "60"),
      tls: {
        enabled: booleanValue("MCP_HTTP_TLS_ENABLED", false),
        certPath: process.env.MCP_HTTP_TLS_CERT_PATH ?? "",
        keyPath: process.env.MCP_HTTP_TLS_KEY_PATH ?? ""
      }
    }
  },
  postgres: {
    host: required("POSTGRES_HOST", "127.0.0.1"),
    port: portNumber("POSTGRES_PORT", "5432"),
    database: required("POSTGRES_DB", "mcp_config"),
    user: required("POSTGRES_USER", "mcp_user"),
    password: required("POSTGRES_PASSWORD", "mcp_password"),
    ssl: booleanValue("POSTGRES_SSL", false)
  },
  vault: {
    addr: required("VAULT_ADDR", "http://127.0.0.1:8200"),
    token: process.env.VAULT_TOKEN ?? "",
    kvMount: String(process.env.VAULT_KV_MOUNT ?? "secret").trim() || "secret",
    writeRetryAttempts: positiveNumber("VAULT_WRITE_RETRY_ATTEMPTS", "3"),
    writeRetryBaseDelayMs: positiveNumber("VAULT_WRITE_RETRY_BASE_DELAY_MS", "200"),
    writeRetryMaxDelayMs: positiveNumber("VAULT_WRITE_RETRY_MAX_DELAY_MS", "2000")
  },
  identifiers: {
    configTable: normalizeIdentifier(`${normalizeAppName(process.env.APP_NAME, "msoffice")}_config`, "msoffice_config")
  }
};

export { normalizeAppName, normalizeIdentifier };
