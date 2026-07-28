import pg from "pg";

const { Pool } = pg;

function normalizeIdentifier(value, fallback) {
  const candidate = String(value ?? fallback).trim().toLowerCase().replace(/[^a-z0-9_]/g, "_");
  if (!candidate || !/^[a-z][a-z0-9_]*$/.test(candidate)) {
    throw new Error(`Invalid Postgres table name: ${value}`);
  }
  return candidate;
}

function sanitizeUserId(userId, fallback = "default") {
  return String(userId ?? fallback).trim() || fallback;
}

function toJsonText(value) {
  return JSON.stringify(value ?? null);
}

export class ConfigStore {
  constructor(postgresConfig, options = {}) {
    this.pool = new Pool({
      ...postgresConfig,
      ssl: postgresConfig.ssl ? { rejectUnauthorized: false } : undefined
    });
    this.appName = String(options.appName ?? process.env.APP_NAME ?? "msoffice").trim() || "msoffice";
    this.defaultUserId = sanitizeUserId(options.defaultUserId ?? process.env.MCP_CONFIG_DEFAULT_USER_ID, "default");
    this.tableName = normalizeIdentifier(options.tableName ?? `${this.appName}_config`, `${this.appName}_config`);
  }

  normalizeUserId(userId) {
    return sanitizeUserId(userId, this.defaultUserId);
  }

  async init() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        user_id text NOT NULL,
        key text NOT NULL,
        value jsonb NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT NOW(),
        PRIMARY KEY (user_id, key)
      )
    `);
  }

  async healthcheck() {
    await this.pool.query("SELECT 1");
    return { ok: true };
  }

  async listConfigs(prefix, userId) {
    const effectiveUserId = this.normalizeUserId(userId);
    if (prefix && String(prefix).trim()) {
      const result = await this.pool.query(
        `SELECT user_id, key, value, updated_at FROM ${this.tableName} WHERE user_id = $1 AND key ILIKE $2 ORDER BY key ASC`,
        [effectiveUserId, `${String(prefix).trim()}%`]
      );
      return result.rows;
    }

    const result = await this.pool.query(
      `SELECT user_id, key, value, updated_at FROM ${this.tableName} WHERE user_id = $1 ORDER BY key ASC`,
      [effectiveUserId]
    );
    return result.rows;
  }

  async getConfig(key, userId) {
    const effectiveUserId = this.normalizeUserId(userId);
    const result = await this.pool.query(
      `SELECT user_id, key, value, updated_at FROM ${this.tableName} WHERE user_id = $1 AND key = $2`,
      [effectiveUserId, key]
    );
    return result.rows[0] ?? null;
  }

  async setConfig(key, value, userId) {
    const effectiveUserId = this.normalizeUserId(userId);
    const result = await this.pool.query(
      `
      INSERT INTO ${this.tableName} (user_id, key, value, updated_at)
      VALUES ($1, $2, $3::jsonb, NOW())
      ON CONFLICT (user_id, key)
      DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
      RETURNING user_id, key, value, updated_at
      `,
      [effectiveUserId, key, toJsonText(value)]
    );
    return result.rows[0];
  }

  async deleteConfig(key, userId) {
    const effectiveUserId = this.normalizeUserId(userId);
    const result = await this.pool.query(`DELETE FROM ${this.tableName} WHERE user_id = $1 AND key = $2`, [effectiveUserId, key]);
    return result.rowCount > 0;
  }

  async resolveConfig(key, userId) {
    const effectiveUserId = this.normalizeUserId(userId);
    const scoped = await this.getConfig(key, effectiveUserId);
    if (scoped) {
      return { ...scoped, source: "user" };
    }

    const defaultScoped = await this.getConfig(key, this.defaultUserId);
    if (defaultScoped) {
      return { ...defaultScoped, source: "default-user" };
    }

    return null;
  }

  async getTokenRotationIntervalMs({ userId, userIntervalConfigKey, defaultIntervalMs }) {
    const effectiveUserId = this.normalizeUserId(userId);
    const scopedConfig = await this.getConfig(userIntervalConfigKey, effectiveUserId);
    const scopedValue = Number(scopedConfig?.value);
    if (Number.isFinite(scopedValue) && scopedValue > 0) {
      return { intervalMs: scopedValue, source: "user", userId: effectiveUserId, key: userIntervalConfigKey };
    }

    const defaultScopedConfig = await this.getConfig(userIntervalConfigKey, this.defaultUserId);
    const defaultScopedValue = Number(defaultScopedConfig?.value);
    if (Number.isFinite(defaultScopedValue) && defaultScopedValue > 0) {
      return { intervalMs: defaultScopedValue, source: "default-user", userId: this.defaultUserId, key: userIntervalConfigKey };
    }

    return { intervalMs: defaultIntervalMs, source: "env-default", userId: this.defaultUserId, key: userIntervalConfigKey };
  }

  async close() {
    await this.pool.end();
  }
}
