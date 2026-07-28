function normalizeUserId(userId, fallback) {
  return String(userId ?? fallback).trim() || fallback;
}

function normalizeBaseUrl(value, fallback = "https://manage.office.com/api/v1.0") {
  return String(value ?? fallback).trim().replace(/\/+$/, "") || fallback;
}

function normalizeTenantId(value, fallback = "") {
  return String(value ?? fallback).trim();
}

function normalizePublisherIdentifier(value, fallback = "") {
  return String(value ?? fallback).trim();
}

function normalizePath(path) {
  const raw = String(path ?? "").trim();
  if (!raw) {
    return "/";
  }

  if (/^https?:\/\//i.test(raw)) {
    return raw;
  }

  return raw.startsWith("/") ? raw : `/${raw}`;
}

function buildQueryString(query = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }
    params.set(key, String(value));
  }
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}

function parseDateWindow(startTime, endTime) {
  const hasStart = startTime !== undefined && startTime !== null && String(startTime).trim() !== "";
  const hasEnd = endTime !== undefined && endTime !== null && String(endTime).trim() !== "";
  if (hasStart !== hasEnd) {
    const error = new Error("startTime and endTime must both be specified or both omitted");
    error.status = 400;
    throw error;
  }

  if (!hasStart) {
    return {};
  }

  const start = new Date(startTime);
  const end = new Date(endTime);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    const error = new Error("startTime and endTime must be valid datetimes");
    error.status = 400;
    throw error;
  }

  if (end <= start) {
    const error = new Error("endTime must be later than startTime");
    error.status = 400;
    throw error;
  }

  const maxWindowMs = 24 * 60 * 60 * 1000;
  if (end.getTime() - start.getTime() > maxWindowMs) {
    const error = new Error("startTime and endTime must be no more than 24 hours apart");
    error.status = 400;
    throw error;
  }

  return {
    startTime: start.toISOString(),
    endTime: end.toISOString()
  };
}

function toArray(value) {
  if (value === undefined || value === null || value === "") {
    return [];
  }

  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }

  return String(value)
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export class Office365ManagementActivityClient {
  constructor({ baseUrl, defaultTenantId, defaultPublisherIdentifier, tokenStore, configStore, defaultUserId, allowSensitiveOutput = false, fetchImpl = globalThis.fetch }) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.defaultTenantId = normalizeTenantId(defaultTenantId);
    this.defaultPublisherIdentifier = normalizePublisherIdentifier(defaultPublisherIdentifier);
    this.tokenStore = tokenStore;
    this.configStore = configStore;
    this.defaultUserId = normalizeUserId(defaultUserId, "default");
    this.allowSensitiveOutput = allowSensitiveOutput;
    this.fetch = fetchImpl;
  }

  getConnectionInfo() {
    return {
      baseUrl: this.baseUrl,
      defaultTenantId: this.defaultTenantId || null,
      defaultPublisherIdentifier: this.defaultPublisherIdentifier || null,
      tokenModel: "multi-user-vault",
      api: "office-365-management-activity"
    };
  }

  listContentTypes() {
    return ["Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All"];
  }

  scope({ tenantId, publisherIdentifier, userId } = {}) {
    return {
      tenantId: normalizeTenantId(tenantId, this.defaultTenantId),
      publisherIdentifier: normalizePublisherIdentifier(publisherIdentifier, this.defaultPublisherIdentifier),
      userId: normalizeUserId(userId, this.defaultUserId)
    };
  }

  async request({ method, path, query = {}, body, headers = {}, tenantId, publisherIdentifier, userId, tokenId }) {
    const scope = this.scope({ tenantId, publisherIdentifier, userId });
    if (!scope.tenantId) {
      const error = new Error("tenantId is required");
      error.status = 400;
      throw error;
    }

    const token = await this.tokenStore.resolveActiveToken({ userId: scope.userId, tokenId });
    if (!token?.secret?.accessToken) {
      const error = new Error(`No active Office 365 token found for user ${scope.userId}`);
      error.status = 401;
      throw error;
    }

    const requestPath = normalizePath(path);
    const baseRoot = `${this.baseUrl}/${scope.tenantId}/activity/feed/`;
    const resolvedPath = /^https?:\/\//i.test(requestPath) ? requestPath : requestPath.replace(/^\/+/, "");
    const queryWithPublisher = /^https?:\/\//i.test(requestPath) || requestPath.includes("contentUri") ? query : { PublisherIdentifier: scope.publisherIdentifier, ...query };
    const url = new URL(resolvedPath + buildQueryString(queryWithPublisher), baseRoot);
    const requestHeaders = new Headers({
      Authorization: `Bearer ${token.secret.accessToken}`,
      Accept: "application/json",
      ...headers
    });

    const init = { method: String(method ?? "GET").trim().toUpperCase(), headers: requestHeaders };
    if (body !== undefined && body !== null && !["GET", "HEAD"].includes(init.method)) {
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
        tenantId: scope.tenantId,
        publisherIdentifier: scope.publisherIdentifier,
        userId: scope.userId,
        path: normalizePath(path)
      }
    };
  }

  async requestServiceComms({ method, path, query = {}, body, headers = {}, tenantId, userId, tokenId }) {
    const scope = this.scope({ tenantId, userId });
    if (!scope.tenantId) {
      const error = new Error("tenantId is required");
      error.status = 400;
      throw error;
    }

    const token = await this.tokenStore.resolveActiveToken({ userId: scope.userId, tokenId });
    if (!token?.secret?.accessToken) {
      const error = new Error(`No active Office 365 token found for user ${scope.userId}`);
      error.status = 401;
      throw error;
    }

    const requestPath = normalizePath(path);
    const baseRoot = `${this.baseUrl}/${scope.tenantId}/ServiceComms/`;
    const resolvedPath = /^https?:\/\//i.test(requestPath) ? requestPath : requestPath.replace(/^\/+/, "");
    const url = new URL(resolvedPath + buildQueryString(query), baseRoot);
    const requestHeaders = new Headers({
      Authorization: `Bearer ${token.secret.accessToken}`,
      Accept: "application/json",
      ...headers
    });

    const init = { method: String(method ?? "GET").trim().toUpperCase(), headers: requestHeaders };
    if (body !== undefined && body !== null && !["GET", "HEAD"].includes(init.method)) {
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
        tenantId: scope.tenantId,
        userId: scope.userId,
        path: normalizePath(path)
      }
    };
  }

  async listSubscriptions({ tenantId, publisherIdentifier, userId } = {}) {
    const scope = this.scope({ tenantId, publisherIdentifier, userId });
    return await this.request({ method: "GET", path: "/subscriptions/list", query: { PublisherIdentifier: scope.publisherIdentifier }, tenantId: scope.tenantId, userId: scope.userId });
  }

  async startSubscription({ tenantId, publisherIdentifier, contentType, webhook, userId } = {}) {
    const scope = this.scope({ tenantId, publisherIdentifier, userId });
    return await this.request({
      method: "POST",
      path: "/subscriptions/start",
      query: { contentType, PublisherIdentifier: scope.publisherIdentifier },
      body: webhook ? { webhook } : {},
      tenantId: scope.tenantId,
      userId: scope.userId
    });
  }

  async stopSubscription({ tenantId, publisherIdentifier, contentType, userId } = {}) {
    const scope = this.scope({ tenantId, publisherIdentifier, userId });
    return await this.request({
      method: "POST",
      path: "/subscriptions/stop",
      query: { contentType, PublisherIdentifier: scope.publisherIdentifier },
      tenantId: scope.tenantId,
      userId: scope.userId
    });
  }

  async listContent({ tenantId, publisherIdentifier, contentType, startTime, endTime, userId } = {}) {
    const scope = this.scope({ tenantId, publisherIdentifier, userId });
    const window = parseDateWindow(startTime, endTime);
    return await this.request({
      method: "GET",
      path: "/subscriptions/content",
      query: { contentType, PublisherIdentifier: scope.publisherIdentifier, ...window },
      tenantId: scope.tenantId,
      userId: scope.userId
    });
  }

  async listNotifications({ tenantId, publisherIdentifier, contentType, startTime, endTime, userId } = {}) {
    const scope = this.scope({ tenantId, publisherIdentifier, userId });
    const window = parseDateWindow(startTime, endTime);
    return await this.request({
      method: "GET",
      path: "/subscriptions/notifications",
      query: { contentType, PublisherIdentifier: scope.publisherIdentifier, ...window },
      tenantId: scope.tenantId,
      userId: scope.userId
    });
  }

  async getContent({ contentUri, tenantId, userId } = {}) {
    const scope = this.scope({ tenantId, userId });
    if (!contentUri) {
      const error = new Error("contentUri is required");
      error.status = 400;
      throw error;
    }

    return await this.request({ method: "GET", path: contentUri, tenantId: scope.tenantId, userId: scope.userId });
  }

  async listResourceFriendlyNames({ tenantId, publisherIdentifier, acceptLanguage, userId } = {}) {
    const scope = this.scope({ tenantId, publisherIdentifier, userId });
    const headers = acceptLanguage ? { "Accept-Language": acceptLanguage } : {};
    return await this.request({
      method: "GET",
      path: "/resources/dlpSensitiveTypes",
      query: { PublisherIdentifier: scope.publisherIdentifier },
      headers,
      tenantId: scope.tenantId,
      userId: scope.userId
    });
  }

  async apiRequest({ method, path, query, body, headers, tenantId, publisherIdentifier, userId, tokenId, authorizationKey }) {
    if (["POST", "PUT", "PATCH", "DELETE"].includes(String(method ?? "GET").trim().toUpperCase()) && authorizationKey === undefined) {
      // authorization is enforced by the caller when admin auth is configured
    }
    return await this.request({ method, path, query, body, headers, tenantId, publisherIdentifier, userId, tokenId });
  }

  async listServices({ tenantId, userId, select } = {}) {
    const query = {};
    if (select) {
      query.$select = select;
    }
    return await this.requestServiceComms({ method: "GET", path: "/Services", query, tenantId, userId });
  }

  async getCurrentStatus({ tenantId, userId, workload, select } = {}) {
    const query = {};
    if (workload) {
      query.Workload = workload;
    }
    if (select) {
      query.$select = select;
    }
    return await this.requestServiceComms({ method: "GET", path: "/CurrentStatus", query, tenantId, userId });
  }

  async getHistoricalStatus({ tenantId, userId, workload, statusTime, select } = {}) {
    const query = {};
    if (workload) {
      query.Workload = workload;
    }
    if (statusTime) {
      query.StatusTime = String(statusTime);
    }
    if (select) {
      query.$select = select;
    }
    return await this.requestServiceComms({ method: "GET", path: "/HistoricalStatus", query, tenantId, userId });
  }

  async getMessages({ tenantId, userId, workload, startTime, endTime, messageType, id, top, skip, select } = {}) {
    const query = {};
    if (workload) {
      query.Workload = workload;
    }
    if (startTime) {
      query.StartTime = String(startTime);
    }
    if (endTime) {
      query.EndTime = String(endTime);
    }
    if (messageType) {
      query.MessageType = messageType;
    }
    if (id) {
      query.Id = id;
    }
    if (top !== undefined && top !== null && top !== "") {
      query.$top = top;
    }
    if (skip !== undefined && skip !== null && skip !== "") {
      query.$skip = skip;
    }
    if (select) {
      query.$select = select;
    }
    return await this.requestServiceComms({ method: "GET", path: "/Messages", query, tenantId, userId });
  }
}
