import { createHash } from "node:crypto";

import { joinVaultPath } from "./vault.js";

function normalizeMethod(method) {
  return String(method ?? "GET").trim().toUpperCase();
}

function normalizePath(path) {
  const raw = String(path ?? "").trim();
  if (!raw) {
    return "/";
  }

  if (/^https?:\/\//i.test(raw)) {
    throw new Error("Graph requests must use relative paths, not absolute URLs");
  }

  return raw.startsWith("/") ? raw : `/${raw}`;
}

function normalizeUserId(userId, fallback) {
  return String(userId ?? fallback).trim() || fallback;
}

function sha256(value) {
  return createHash("sha256").update(String(value ?? "")).digest("hex");
}

function toIso(value) {
  if (!value) {
    return null;
  }
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
}

function toArray(value) {
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return Array.isArray(value) ? value.map((entry) => String(entry).trim()).filter(Boolean) : [String(value).trim()].filter(Boolean);
}

function buildQueryString(query = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        params.append(key, String(entry));
      }
      continue;
    }

    params.set(key, String(value));
  }
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}

function buildTokenIndexPath(appName, userId) {
  return joinVaultPath(appName, "users", userId, "graph", "auth", "token-index");
}

function buildTokenSecretPath(appName, userId, tokenId) {
  return joinVaultPath(appName, "users", userId, "graph", "tokens", tokenId);
}

export class GraphTokenStore {
  constructor({ vaultService, appName, defaultUserId }) {
    this.vaultService = vaultService;
    this.appName = appName;
    this.defaultUserId = normalizeUserId(defaultUserId, "default");
  }

  scope(userId) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    return {
      appName: this.appName,
      userId: effectiveUserId,
      tokenIndexPath: buildTokenIndexPath(this.appName, effectiveUserId),
      tokenSecretPrefix: joinVaultPath(this.appName, "users", effectiveUserId, "graph", "tokens")
    };
  }

  async readTokenIndex(userId) {
    const { tokenIndexPath } = this.scope(userId);
    return (await this.vaultService.readSecret(tokenIndexPath)) ?? { tokens: {} };
  }

  async writeTokenIndex(userId, tokenIndex) {
    const { tokenIndexPath } = this.scope(userId);
    await this.vaultService.setSecret(tokenIndexPath, tokenIndex);
    return tokenIndex;
  }

  async listTokens(userId) {
    const index = await this.readTokenIndex(userId);
    return Object.values(index.tokens ?? {}).sort((left, right) => String(left.updatedAt ?? "").localeCompare(String(right.updatedAt ?? "")));
  }

  async upsertToken({ userId, tokenId, accessToken, refreshToken, expiresAt, scopes = [], audience = [], active = true, tenantId = "", accountType = "work", tokenType = "oauth2", displayName = "" }) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    const resolvedTokenId = String(tokenId ?? `graph-${Date.now()}-${sha256(accessToken).slice(0, 12)}`).trim();
    if (!resolvedTokenId) {
      throw new Error("tokenId is required");
    }

    if (!String(accessToken ?? "").trim()) {
      throw new Error("accessToken is required");
    }

    const secretPath = buildTokenSecretPath(this.appName, effectiveUserId, resolvedTokenId);
    const secret = {
      tokenId: resolvedTokenId,
      userId: effectiveUserId,
      accessToken,
      refreshToken: refreshToken ?? "",
      expiresAt: toIso(expiresAt),
      scopes: toArray(scopes),
      audience: toArray(audience),
      tenantId: String(tenantId ?? "").trim(),
      accountType: String(accountType ?? "work").trim() || "work",
      tokenType: String(tokenType ?? "oauth2").trim() || "oauth2",
      displayName: String(displayName ?? "").trim(),
      active: Boolean(active),
      updatedAt: new Date().toISOString()
    };

    await this.vaultService.setSecret(secretPath, secret);

    const index = await this.readTokenIndex(effectiveUserId);
    index.tokens ??= {};
    index.tokens[resolvedTokenId] = {
      tokenId: resolvedTokenId,
      userId: effectiveUserId,
      secretPath,
      tokenHash: sha256(accessToken),
      refreshTokenHash: refreshToken ? sha256(refreshToken) : null,
      scopes: secret.scopes,
      audience: secret.audience,
      expiresAt: secret.expiresAt,
      active: Boolean(active),
      tokenType: secret.tokenType,
      accountType: secret.accountType,
      displayName: secret.displayName,
      updatedAt: secret.updatedAt
    };
    await this.writeTokenIndex(effectiveUserId, index);

    return this.getTokenMetadata(effectiveUserId, resolvedTokenId);
  }

  async getTokenMetadata(userId, tokenId) {
    const index = await this.readTokenIndex(userId);
    return index.tokens?.[tokenId] ?? null;
  }

  async readTokenSecret(userId, tokenId) {
    const index = await this.readTokenIndex(userId);
    const entry = index.tokens?.[tokenId];
    if (!entry?.secretPath) {
      return null;
    }
    return await this.vaultService.readSecret(entry.secretPath);
  }

  async deactivateToken({ userId, tokenId }) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    const index = await this.readTokenIndex(effectiveUserId);
    const entry = index.tokens?.[tokenId];
    if (!entry) {
      return null;
    }

    entry.active = false;
    entry.updatedAt = new Date().toISOString();
    index.tokens[tokenId] = entry;
    await this.writeTokenIndex(effectiveUserId, index);

    const secret = await this.readTokenSecret(effectiveUserId, tokenId);
    if (secret) {
      await this.vaultService.setSecret(entry.secretPath, { ...secret, active: false, updatedAt: entry.updatedAt });
    }

    return entry;
  }

  async removeToken({ userId, tokenId }) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    const index = await this.readTokenIndex(effectiveUserId);
    const entry = index.tokens?.[tokenId];
    if (!entry) {
      return false;
    }

    delete index.tokens[tokenId];
    await this.writeTokenIndex(effectiveUserId, index);
    if (entry.secretPath) {
      await this.vaultService.deleteSecret(entry.secretPath);
    }
    return true;
  }

  async resolveActiveToken({ userId, tokenId }) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    const primary = await this.resolveActiveTokenForUser(effectiveUserId, tokenId);
    if (primary) {
      return primary;
    }

    if (effectiveUserId !== this.defaultUserId) {
      return await this.resolveActiveTokenForUser(this.defaultUserId, tokenId);
    }

    return null;
  }

  async resolveActiveTokenForUser(userId, tokenId) {
    const index = await this.readTokenIndex(userId);
    const entries = Object.values(index.tokens ?? {});
    const selected = tokenId
      ? entries.find((entry) => entry.tokenId === tokenId)
      : entries.find((entry) => entry.active) ?? entries[0];

    if (!selected) {
      return null;
    }

    const secret = await this.readTokenSecret(userId, selected.tokenId);
    if (!secret?.accessToken) {
      return null;
    }

    return { metadata: selected, secret, scope: this.scope(userId) };
  }
}

export class GraphServiceClient {
  constructor({ baseUrl, betaBaseUrl, tokenStore, configStore, defaultUserId, allowSensitiveOutput = false, fetchImpl = globalThis.fetch }) {
    this.baseUrl = String(baseUrl ?? "https://graph.microsoft.com/v1.0").trim();
    this.betaBaseUrl = String(betaBaseUrl ?? "https://graph.microsoft.com/beta").trim();
    this.tokenStore = tokenStore;
    this.configStore = configStore;
    this.defaultUserId = normalizeUserId(defaultUserId, "default");
    this.allowSensitiveOutput = allowSensitiveOutput;
    this.fetch = fetchImpl;
  }

  getConnectionInfo() {
    return {
      baseUrl: this.baseUrl,
      betaBaseUrl: this.betaBaseUrl,
      defaultUserId: this.defaultUserId,
      tokenModel: "multi-user-vault",
      configModel: "postgres-key-value",
      genericCoverage: true
    };
  }

  listKnownCapabilities() {
    return [
      { family: "users", examples: ["/users", "/users/{id}", "/me"] },
      { family: "groups", examples: ["/groups", "/groups/{id}"] },
      { family: "mail", examples: ["/me/messages", "/users/{id}/mailFolders"] },
      { family: "calendar", examples: ["/me/events", "/users/{id}/calendars"] },
      { family: "drives", examples: ["/me/drive/root/children", "/drives/{id}/items"] },
      { family: "sites", examples: ["/sites", "/sites/{id}/lists"] },
      { family: "teams", examples: ["/teams", "/teams/{id}/channels"] },
      { family: "security", examples: ["/security/alerts_v2", "/security/cases"] },
      { family: "applications", examples: ["/applications", "/servicePrincipals"] },
      { family: "devices", examples: ["/devices", "/deviceManagement"] },
      { family: "copilot-retrieval", examples: ["POST /copilot/retrieval"] },
      { family: "copilot-search-preview", examples: ["POST /copilot/search"] },
      { family: "copilot-chat-preview", examples: ["POST /copilot/conversations", "POST /copilot/conversations/{id}/chat"] },
      { family: "copilot-interaction-export", examples: ["/copilot/users/{id}/interactionHistory/getAllEnterpriseInteractions"] },
      { family: "copilot-meeting-insights", examples: ["/copilot/users/{id}/onlineMeetings/{meetingId}/aiInsights"] },
      { family: "copilot-usage-reports", examples: ["/copilot/reports/getMicrosoft365CopilotUserCountSummary(period='D7')"] },
      { family: "copilot-package-management", examples: ["/copilot/admin/catalog/packages"] },
      { family: "beta", examples: ["Use betaBaseUrl for beta endpoints"] },
      { family: "generic-request", examples: ["Any Graph REST path via graph_api_request"] }
    ];
  }

  listSuggestedQueries(prompt) {
    const normalizedPrompt = String(prompt ?? "").trim().toLowerCase();
    const catalog = [
      {
        intent: ["user", "count", "how many"],
        description: "Count users in the tenant",
        method: "GET",
        path: "/users/$count",
        query: {},
        entity: "user",
        mcpTool: "microsoft_graph_get"
      },
      {
        intent: ["inactive", "sign in", "signin", "last month"],
        description: "Find inactive users by sign-in time",
        method: "GET",
        path: "/users",
        query: { $filter: "signInActivity/lastSignInDateTime le 2026-06-28T00:00:00Z" },
        entity: "user",
        mcpTool: "graph_users_query"
      },
      {
        intent: ["guest", "users"],
        description: "Find guest users",
        method: "GET",
        path: "/users",
        query: { $filter: "userType eq 'Guest'" },
        entity: "user",
        mcpTool: "graph_users_query"
      },
      {
        intent: ["group", "member"],
        description: "List groups",
        method: "GET",
        path: "/groups",
        query: {},
        entity: "group",
        mcpTool: "graph_groups_query"
      },
      {
        intent: ["license", "copilot"],
        description: "Find users assigned a license",
        method: "GET",
        path: "/users",
        query: { $select: "id,displayName,assignedLicenses" },
        entity: "user",
        mcpTool: "graph_users_query"
      },
      {
        intent: ["device"],
        description: "List devices",
        method: "GET",
        path: "/devices",
        query: {},
        entity: "device",
        mcpTool: "graph_devices_query"
      },
      {
        intent: ["application", "app registration"],
        description: "List applications",
        method: "GET",
        path: "/applications",
        query: {},
        entity: "application",
        mcpTool: "graph_applications_query"
      },
      {
        intent: ["copilot", "retrieval", "grounding"],
        description: "Run a Copilot retrieval query",
        method: "POST",
        path: "/copilot/retrieval",
        query: {},
        entity: "copilot",
        mcpTool: "copilot_retrieval_query"
      },
      {
        intent: ["copilot", "search"],
        description: "Run a Copilot search query (preview)",
        method: "POST",
        path: "/copilot/search",
        query: {},
        entity: "copilot",
        mcpTool: "copilot_search_query"
      },
      {
        intent: ["copilot", "interaction", "export"],
        description: "List Copilot interactions for a user",
        method: "GET",
        path: "/copilot/users/{id}/interactionHistory/getAllEnterpriseInteractions",
        query: { $top: 100 },
        entity: "copilot_interaction",
        mcpTool: "copilot_interactions_list"
      },
      {
        intent: ["copilot", "chat", "conversation", "start"],
        description: "Create a Copilot conversation (preview)",
        method: "POST",
        path: "/copilot/conversations",
        query: {},
        entity: "copilot_conversation",
        mcpTool: "copilot_chat_create_conversation"
      },
      {
        intent: ["copilot", "meeting", "insight"],
        description: "List Copilot meeting AI insights",
        method: "GET",
        path: "/copilot/users/{id}/onlineMeetings/{meetingId}/aiInsights",
        query: {},
        entity: "copilot_meeting_insight",
        mcpTool: "copilot_meeting_insights_list"
      },
      {
        intent: ["copilot", "usage", "report", "summary"],
        description: "Get Copilot user count summary report",
        method: "GET",
        path: "/copilot/reports/getMicrosoft365CopilotUserCountSummary(period='D7', version='v2')",
        query: {},
        entity: "copilot_usage_report",
        mcpTool: "copilot_usage_report_user_count_summary"
      },
      {
        intent: ["copilot", "package", "catalog", "agent"],
        description: "List Copilot packages (agents)",
        method: "GET",
        path: "/copilot/admin/catalog/packages",
        query: { $top: 25 },
        entity: "copilot_package",
        mcpTool: "copilot_packages_list"
      }
    ];

    const matches = catalog
      .map((entry) => ({
        ...entry,
        score: entry.intent.reduce((score, token) => score + (normalizedPrompt.includes(token) ? 1 : 0), 0)
      }))
      .filter((entry) => entry.score > 0)
      .sort((left, right) => right.score - left.score);

    return {
      prompt,
      suggestions: matches.slice(0, 10).map((entry) => ({
        description: entry.description,
        method: entry.method,
        path: entry.path,
        query: entry.query,
        entity: entry.entity,
        mcpTool: entry.mcpTool,
        confidence: Math.min(1, entry.score / entry.intent.length)
      }))
    };
  }

  listProperties(entity) {
    const normalizedEntity = String(entity ?? "").trim().toLowerCase();
    const aliases = {
      copilot: "copilot",
      "copilot-interaction": "copilot_interaction",
      copilotinteraction: "copilot_interaction",
      "copilot-meeting-insight": "copilot_meeting_insight",
      copilotmeetinginsight: "copilot_meeting_insight",
      "copilot-conversation": "copilot_conversation",
      copilotconversation: "copilot_conversation",
      "copilot-usage-report": "copilot_usage_report",
      copilotusagereport: "copilot_usage_report",
      "copilot-package": "copilot_package",
      copilotpackage: "copilot_package"
    };
    const lookupKey = aliases[normalizedEntity] ?? normalizedEntity;
    const recommendedToolsByEntity = {
      user: ["graph_users_query", "microsoft_graph_get", "graph_api_request"],
      group: ["graph_groups_query", "microsoft_graph_get", "graph_api_request"],
      application: ["graph_applications_query", "microsoft_graph_get", "graph_api_request"],
      device: ["graph_devices_query", "microsoft_graph_get", "graph_api_request"],
      site: ["graph_sites_query", "microsoft_graph_get", "graph_api_request"],
      message: ["graph_mail_messages", "microsoft_graph_get", "graph_api_request"],
      event: ["graph_calendar_events", "microsoft_graph_get", "graph_api_request"],
      copilot: ["copilot_api_capabilities", "copilot_retrieval_query", "copilot_search_query"],
      copilot_interaction: ["copilot_interactions_list", "copilot_change_notifications_create_subscription", "graph_api_request"],
      copilot_meeting_insight: ["copilot_meeting_insights_list", "copilot_meeting_insight_get", "graph_api_request"],
      copilot_conversation: ["copilot_chat_create_conversation", "copilot_chat_send_message", "copilot_chat_send_message_stream"],
      copilot_usage_report: ["copilot_usage_report_user_count_summary", "copilot_usage_report_user_count_trend", "copilot_usage_report_user_detail"],
      copilot_package: ["copilot_packages_list", "copilot_package_get", "copilot_package_update"]
    };
    const schema = {
      user: {
        entity: "user",
        properties: [
          "id",
          "displayName",
          "userPrincipalName",
          "mail",
          "userType",
          "accountEnabled",
          "jobTitle",
          "department",
          "createdDateTime",
          "signInActivity"
        ],
        relationships: ["manager", "memberOf", "transitiveMemberOf", "licenseDetails"]
      },
      group: {
        entity: "group",
        properties: ["id", "displayName", "mailNickname", "description", "groupTypes", "securityEnabled", "mailEnabled"],
        relationships: ["members", "owners", "transitiveMembers", "sites"]
      },
      application: {
        entity: "application",
        properties: ["id", "appId", "displayName", "signInAudience", "createdDateTime", "identifierUris"],
        relationships: ["owners", "passwordCredentials", "requiredResourceAccess"]
      },
      device: {
        entity: "device",
        properties: ["id", "displayName", "operatingSystem", "operatingSystemVersion", "accountEnabled", "trustType"],
        relationships: ["registeredOwners", "registeredUsers", "memberOf"]
      },
      site: {
        entity: "site",
        properties: ["id", "displayName", "webUrl", "createdDateTime", "lastModifiedDateTime"],
        relationships: ["lists", "drives", "pages"]
      },
      message: {
        entity: "message",
        properties: ["id", "subject", "from", "toRecipients", "ccRecipients", "receivedDateTime", "isRead"],
        relationships: ["attachments", "extensions", "reply", "forward"]
      },
      event: {
        entity: "event",
        properties: ["id", "subject", "start", "end", "organizer", "location", "isAllDay"],
        relationships: ["attendees", "extensions", "calendar"]
      },
      copilot: {
        entity: "copilot",
        properties: ["id", "createdDateTime", "lastModifiedDateTime", "tenantId", "userId"],
        relationships: ["interactions", "conversations", "reports", "packages"]
      },
      copilot_interaction: {
        entity: "copilot_interaction",
        properties: ["id", "createdDateTime", "requestText", "responseText", "appClass", "scenario"],
        relationships: ["user", "resources", "response", "feedback"]
      },
      copilot_meeting_insight: {
        entity: "copilot_meeting_insight",
        properties: ["id", "createdDateTime", "summary", "meetingNotes", "actionItems", "mentionEvents"],
        relationships: ["onlineMeeting", "organizer", "participants"]
      },
      copilot_conversation: {
        entity: "copilot_conversation",
        properties: ["id", "createdDateTime", "lastUpdatedDateTime", "title", "state"],
        relationships: ["messages", "participants", "contextualResources"]
      },
      copilot_usage_report: {
        entity: "copilot_usage_report",
        properties: ["reportDate", "period", "enabledUserCount", "activeUserCount", "reportRefreshDate"],
        relationships: ["users", "tenants"]
      },
      copilot_package: {
        entity: "copilot_package",
        properties: ["id", "displayName", "description", "state", "owner", "lastModifiedDateTime"],
        relationships: ["elements", "publisher", "permissions", "assignments"]
      }
    };

    if (!schema[lookupKey]) {
      return {
        entity: lookupKey || null,
        properties: [],
        relationships: [],
        recommendedTools: [],
        knownEntities: Object.keys(schema)
      };
    }

    return {
      ...schema[lookupKey],
      recommendedTools: recommendedToolsByEntity[lookupKey] ?? ["microsoft_graph_get", "graph_api_request"]
    };
  }

  async healthCheck({ userId, tokenId } = {}) {
    const result = await this.request({ method: "GET", path: "/$metadata", userId, tokenId });
    return { ...result, checkedAt: new Date().toISOString() };
  }

  async request({ method, path, query = {}, body, headers = {}, userId, tokenId, useBetaBaseUrl = false }) {
    const normalizedMethod = normalizeMethod(method);
    const normalizedPath = normalizePath(path);
    const activeBaseUrl = useBetaBaseUrl ? this.betaBaseUrl : this.baseUrl;
    const normalizedBaseUrl = activeBaseUrl.endsWith("/") ? activeBaseUrl : `${activeBaseUrl}/`;
    const requestPath = normalizedPath === "/" ? "" : normalizedPath.replace(/^\/+/, "");
    const url = new URL(requestPath + buildQueryString(query), normalizedBaseUrl);
    const token = await this.tokenStore.resolveActiveToken({ userId: userId ?? this.defaultUserId, tokenId });
    if (!token?.secret?.accessToken) {
      const error = new Error(`No active Graph token found for user ${userId ?? this.defaultUserId}`);
      error.status = 401;
      throw error;
    }

    const requestHeaders = new Headers({
      Authorization: `Bearer ${token.secret.accessToken}`,
      Accept: "application/json",
      ...headers
    });

    const init = { method: normalizedMethod, headers: requestHeaders };
    if (body !== undefined && body !== null && !["GET", "HEAD"].includes(normalizedMethod)) {
      if (typeof body === "string") {
        init.body = body;
      } else {
        requestHeaders.set("Content-Type", "application/json");
        init.body = JSON.stringify(body);
      }
    }

    const response = await this.fetch(url, init);
    const contentType = response.headers.get("content-type") ?? "";
    const responseText = await response.text();
    const parsed = contentType.includes("application/json") && responseText ? JSON.parse(responseText) : responseText;
    return {
      ok: response.ok,
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      data: parsed,
      meta: {
        method: normalizedMethod,
        path: normalizedPath,
        userId: token.scope.userId,
        tokenId: token.metadata.tokenId,
        baseUrl: activeBaseUrl
      }
    };
  }

  async resolveTokenMetadata({ userId, tokenId } = {}) {
    const token = await this.tokenStore.resolveActiveToken({ userId: userId ?? this.defaultUserId, tokenId });
    if (!token) {
      return null;
    }

    return {
      userId: token.scope.userId,
      tokenId: token.metadata.tokenId,
      expiresAt: token.metadata.expiresAt,
      active: token.metadata.active,
      scopes: token.metadata.scopes ?? [],
      audience: token.metadata.audience ?? [],
      accountType: token.metadata.accountType,
      tokenType: token.metadata.tokenType,
      secretPath: token.metadata.secretPath
    };
  }

  async userProfile({ userId, tokenId } = {}) {
    return await this.request({ method: "GET", path: "/me", userId, tokenId });
  }

  async queryCollection({ path, userId, tokenId, query, useBetaBaseUrl = false }) {
    return await this.request({ method: "GET", path, userId, tokenId, query, useBetaBaseUrl });
  }

  async updateToken({ userId, tokenId, accessToken, refreshToken, expiresAt, scopes, audience, active, tenantId, accountType, tokenType, displayName }) {
    return await this.tokenStore.upsertToken({ userId, tokenId, accessToken, refreshToken, expiresAt, scopes, audience, active, tenantId, accountType, tokenType, displayName });
  }

  async deactivateToken({ userId, tokenId }) {
    return await this.tokenStore.deactivateToken({ userId, tokenId });
  }

  async removeToken({ userId, tokenId }) {
    return await this.tokenStore.removeToken({ userId, tokenId });
  }

  async listTokens({ userId } = {}) {
    return await this.tokenStore.listTokens(userId ?? this.defaultUserId);
  }

  async configList({ userId } = {}) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    return await this.configStore.listConfigs(undefined, effectiveUserId);
  }

  async configGet({ key, userId } = {}) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    return await this.configStore.resolveConfig(key, effectiveUserId);
  }

  async configSet({ key, value, userId } = {}) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    return await this.configStore.setConfig(key, value, effectiveUserId);
  }

  async configDelete({ key, userId } = {}) {
    const effectiveUserId = normalizeUserId(userId, this.defaultUserId);
    return await this.configStore.deleteConfig(key, effectiveUserId);
  }
}
