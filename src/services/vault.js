import vault from "node-vault";

function normalizePathSegment(value, fallback = "default") {
  return String(value ?? fallback).trim().replace(/^\/+|\/+$/g, "") || fallback;
}

export function joinVaultPath(...segments) {
  return segments
    .flatMap((segment) => String(segment ?? "").split("/"))
    .map((segment) => segment.trim())
    .filter(Boolean)
    .join("/");
}

export function vaultDataPath(mount, relativePath) {
  return joinVaultPath(mount, "data", relativePath);
}

export function vaultMetadataPath(mount, relativePath) {
  return joinVaultPath(mount, "metadata", relativePath);
}

export class VaultService {
  constructor({ endpoint, token, kvMount, writeRetryAttempts = 3, writeRetryBaseDelayMs = 200, writeRetryMaxDelayMs = 2000 }) {
    this.client = vault({ endpoint, token, apiVersion: "v1" });
    this.endpoint = endpoint;
    this.kvMount = normalizePathSegment(kvMount, "secret");
    this.writeRetryAttempts = writeRetryAttempts;
    this.writeRetryBaseDelayMs = writeRetryBaseDelayMs;
    this.writeRetryMaxDelayMs = writeRetryMaxDelayMs;
    this.writeQueue = Promise.resolve();
  }

  getConnectionInfo() {
    return {
      VAULT_ADDR: this.endpoint,
      VAULT_KV_MOUNT: this.kvMount,
      VAULT_WRITE_RETRY_ATTEMPTS: this.writeRetryAttempts,
      VAULT_WRITE_RETRY_BASE_DELAY_MS: this.writeRetryBaseDelayMs,
      VAULT_WRITE_RETRY_MAX_DELAY_MS: this.writeRetryMaxDelayMs,
      VAULT_TOKEN: this.client.token ? "set" : null
    };
  }

  async healthcheck() {
    await this.client.health();
    return { ok: true };
  }

  async readSecret(path) {
    const response = await this.client.read(vaultDataPath(this.kvMount, path));
    return response?.data?.data ?? response?.data ?? null;
  }

  async setSecret(path, value) {
    await this.enqueueWrite(() => this.client.write(vaultDataPath(this.kvMount, path), { data: value }));
    return { ok: true, path };
  }

  async deleteSecret(path) {
    await this.enqueueWrite(() => this.client.delete(vaultMetadataPath(this.kvMount, path)));
    return { ok: true, path };
  }

  async listSecrets(prefix) {
    const normalizedPrefix = normalizePathSegment(prefix, "");
    const listPath = normalizedPrefix ? vaultMetadataPath(this.kvMount, normalizedPrefix) : vaultMetadataPath(this.kvMount, "");
    const response = await this.client.list(listPath);
    return response?.data?.keys ?? [];
  }

  enqueueWrite(operation) {
    const job = this.writeQueue.then(() => this.withWriteRetry(operation));
    this.writeQueue = job.catch(() => undefined);
    return job;
  }

  async withWriteRetry(operation) {
    let attempt = 0;
    while (true) {
      try {
        return await operation();
      } catch (error) {
        if (attempt >= this.writeRetryAttempts) {
          throw error;
        }

        const delay = Math.min(this.writeRetryBaseDelayMs * Math.pow(2, attempt), this.writeRetryMaxDelayMs);
        await new Promise((resolve) => setTimeout(resolve, delay));
        attempt += 1;
      }
    }
  }
}
