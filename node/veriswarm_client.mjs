/**
 * VeriSwarm Node.js SDK — trust scoring, event ingestion, and agent management.
 * Requires Node.js 18+ for native fetch support.
 *
 * Usage:
 *   import { VeriSwarmClient } from "@veriswarm/sdk";
 *   const client = new VeriSwarmClient({ baseUrl: "https://api.veriswarm.ai", apiKey: "vsk_..." });
 *   const decision = await client.checkDecision({ agentId: "agt_123", actionType: "post_message" });
 */
import { readFileSync } from "node:fs";
import { ensureTripwire } from "./secret_tripwire.mjs";

/**
 * Encode one caller-supplied value as a single URL path segment.
 * `.`/`..` are rejected outright: encodeURIComponent leaves them untouched
 * and URL normalization would resolve them, letting an id walk to a
 * different endpoint. Empty and null/undefined ids are rejected too.
 */
function pathSegment(value) {
  if (value === null || value === undefined) {
    throw new TypeError("path segment must not be null or undefined");
  }
  const segment = String(value);
  if (segment === "" || segment === "." || segment === "..") {
    throw new TypeError(`path segment must not be empty, "." or ".." (got ${JSON.stringify(segment)})`);
  }
  return encodeURIComponent(segment);
}

/**
 * Error thrown by the client. `status` is the HTTP status when a response
 * was received (null for local/network failures); `code` names local
 * failure classes (e.g. ACCOUNT_TOKEN_REQUIRED); `payload` carries the
 * parsed error body for callers that opt in to reading it.
 */
export class VeriSwarmError extends Error {
  constructor(message, { status = null, code = null, payload = undefined, cause = undefined } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "VeriSwarmError";
    this.status = status;
    this.code = code;
    if (payload !== undefined) this.payload = payload;
  }
}

// How long to keep built-in-only tripwire rules before retrying the fetch.
const TRIPWIRE_RETRY_MS = 60_000;

// Cap response bodies at 10 MiB. A compromised or MITM'd endpoint
// returning a multi-hundred-MB body would otherwise OOM the customer's
// Node process. Real API responses are well under the cap.
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const MAX_TIMEOUT_MS = 2 ** 31 - 1; // setTimeout's maximum delay
const LOCAL_HTTP_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** SDK version for the User-Agent, read from this package's package.json. */
function readSdkVersion() {
  try {
    const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
    // Guard against a vendored copy of this file picking up the host
    // project's package.json.
    return pkg.name === "@veriswarm/sdk" && typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

const USER_AGENT = `veriswarm-node-sdk/${readSdkVersion()}`;

function tooLarge(status) {
  return new VeriSwarmError(`VeriSwarm response exceeded ${MAX_RESPONSE_BYTES} bytes`, {
    status,
    code: "RESPONSE_TOO_LARGE",
  });
}

/**
 * Read the body as UTF-8 text, aborting as soon as more than `maxBytes`
 * arrive (a declared Content-Length over the cap is refused up front).
 */
async function readBodyCapped(response, maxBytes) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => {});
    throw tooLarge(response.status);
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw tooLarge(response.status);
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks, total));
}

function isJsonContentType(contentType) {
  const mediaType = contentType.split(";")[0].trim().toLowerCase();
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

/** Parse a JSON body; non-JSON content types are returned as text. */
function parseBody(text, response) {
  if (!isJsonContentType(response.headers.get("content-type") || "")) return text;
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (err) {
    // An error status keeps its status; the unparsed text rides on payload.
    if (!response.ok) return text;
    throw new VeriSwarmError("VeriSwarm API returned invalid JSON", {
      status: response.status,
      code: "INVALID_RESPONSE",
      cause: err,
    });
  }
}

/** Join a CIDR list (array or comma/newline-separated string) into the server's format. */
function normalizeCidrs(cidrs) {
  if (cidrs === null || cidrs === undefined) return "";
  const parts = Array.isArray(cidrs) ? cidrs : String(cidrs).split(/[,\n]/);
  return parts
    .map((part) => String(part).trim())
    .filter((part) => part !== "")
    .join(",");
}

/** Tagged template: every interpolated value becomes one encoded path segment. */
function apiPath(strings, ...values) {
  return strings.reduce(
    (acc, literal, i) => acc + literal + (i < values.length ? pathSegment(values[i]) : ""),
    "",
  );
}

/** Append query params, encoding every value and skipping null/undefined. */
function withQuery(path, query) {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== null && value !== undefined) params.append(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export class VeriSwarmClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl - e.g. https://api.veriswarm.ai
   * @param {string} [options.apiKey] - workspace API key (vsk_...)
   * @param {string} [options.agentKey] - individual agent API key (vak_...)
   * @param {string} [options.accountToken] - account session token, sent as
   *   x-account-access-token. Required by account-administration endpoints
   *   (team, workspaces, notifications, Passport, Vault export, ...) that do
   *   not accept API keys.
   * @param {number} [options.timeoutMs=15000]
   */
  constructor({
    baseUrl,
    apiKey = null,
    agentKey = null,
    accountToken = null,
    timeoutMs = 15000,
    secretsDetection = false,
  }) {
    if (!baseUrl) throw new Error("baseUrl is required");
    if (!apiKey && !agentKey && !accountToken) {
      throw new Error("one of apiKey, agentKey, or accountToken is required");
    }
    // Reject non-https baseUrl. The SDK ships x-api-key on every
    // request; an http baseUrl transmits it in plaintext where any
    // MITM can harvest it. Local development against http://localhost
    // is the only acceptable exception. (Audit 2026-05-08 CRIT-SDK-4.)
    let parsedUrl;
    try {
      parsedUrl = new URL(baseUrl);
    } catch {
      throw new Error(`baseUrl is not a valid URL: ${baseUrl}`);
    }
    // WHATWG URL keeps the brackets on IPv6 hostnames ("[::1]").
    const isLocalhostHttp = parsedUrl.protocol === "http:" && LOCAL_HTTP_HOSTS.has(parsedUrl.hostname);
    if (parsedUrl.protocol !== "https:" && !isLocalhostHttp) {
      throw new Error(
        `baseUrl must be https:// (got ${parsedUrl.protocol}). ` +
        "Only http://localhost, http://127.0.0.1 and http://[::1] are permitted as a dev escape hatch."
      );
    }
    if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
      throw new Error(`timeoutMs must be a finite number between 1 and ${MAX_TIMEOUT_MS}`);
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.agentKey = agentKey;
    this.accountToken = accountToken;
    this.timeoutMs = timeoutMs;
    this.secretsDetection = secretsDetection === true;
    this._tripwire = null;
    this._tripwireRetryAt = 0;
  }

  // --- Decisions ---

  /** Check a trust decision before a sensitive action. */
  async checkDecision({ agentId, actionType, resourceType = null }) {
    return this.#request("/v1/decisions/check", {
      method: "POST",
      body: { agent_id: agentId, action_type: actionType, resource_type: resourceType },
    });
  }

  // --- Events ---

  /** Ingest a single agent behavioral event. */
  async ingestEvent({ eventId, agentId, sourceType, eventType, occurredAt, payload = {}, signature = null }) {
    const body = {
      event_id: eventId,
      agent_id: agentId,
      source_type: sourceType,
      event_type: eventType,
      occurred_at: occurredAt,
      payload,
    };
    if (signature) body.signature = signature;
    return this.#request("/v1/events", { method: "POST", body });
  }

  /** Ingest up to 50 events in a single request. */
  async ingestEventsBatch(events) {
    return this.#request("/v1/events/batch", { method: "POST", body: events });
  }

  // --- Provider Reports ---

  /** Submit a provider report (spam, abuse, quality signal). */
  async ingestProviderReport(report) {
    return this.#request("/v1/public/providers/reports", { method: "POST", body: report });
  }

  /** Submit multiple provider reports in a single request. */
  async ingestProviderReportsBatch(reports) {
    return this.#request("/v1/public/providers/reports/batch", { method: "POST", body: { reports } });
  }

  // --- Agent Management ---

  /** Register a new agent. */
  async registerAgent(payload) {
    return this.#request("/v1/public/agents/register", { method: "POST", body: payload });
  }

  /** Get public agent profile. */
  async getAgent(agentId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}`);
  }

  /** Get an agent's current trust scores. */
  async getAgentScores(agentId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/scores/current`);
  }

  /** Get an agent's score history (last N snapshots). */
  async getAgentScoreHistory(agentId, { limit = 20 } = {}) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/scores/history`, { query: { limit } });
  }

  /** Get detailed score breakdown with contributing factors. */
  async getAgentScoreBreakdown(agentId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/scores/breakdown`);
  }

  /** Get active moderation flags for an agent. */
  async getAgentFlags(agentId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/flags`);
  }

  /** Appeal a moderation flag for review. */
  async appealFlag(agentId, flagId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/flags/${flagId}/appeal`, { method: "POST" });
  }

  /** Get agent capability manifests (public). */
  async getAgentManifests(agentId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/manifests`);
  }

  // --- Credentials (Portable JWT) ---

  // --- Guard (PII + Injection) ---

  /** Tokenize PII in text via Guard. Returns { tokenized_text, session_id, tokens_created }. */
  async tokenizePii({ text, agentId, sessionId } = {}) {
    const body = { text };
    if (agentId) body.agent_id = agentId;
    if (sessionId) body.session_id = sessionId;
    return this.#request("/v1/suite/guard/pii/tokenize", { method: "POST", body });
  }

  /** Restore original PII values from Guard tokens. */
  async rehydratePii({ text, sessionId }) {
    return this.#request("/v1/suite/guard/pii/rehydrate", { method: "POST", body: { text, session_id: sessionId } });
  }

  /** Fetch the canonical client-tripwire secret-rules manifest. */
  async getSecretRules() {
    return this.#request("/v1/suite/guard/secret-rules", { method: "GET" });
  }

  // Returns text safe to emit. No-op when secretsDetection is disabled.
  // Detected secret spans are redacted locally FIRST, so a secret the
  // tripwire found never leaves the process (the tokenize endpoint stores
  // what it receives, rehydratably). The already-redacted text is then sent
  // for PII tokenization when online; if that fails, the locally redacted
  // text is returned (fail-closed). The tripwire is a client-side safety
  // net for obvious provider-prefix secrets — never a substitute for the
  // authoritative Guard scan.
  async guardOutboundText(text, { agentId, sessionId } = {}) {
    if (!this.secretsDetection || typeof text !== "string" || text.length === 0) {
      return text;
    }
    await this.#refreshTripwireIfDue();
    const tripwire = this._tripwire;
    if (tripwire.scan(text).length === 0) return text;
    const redacted = tripwire.redactOffline(text);
    try {
      const result = await this.tokenizePii({ text: redacted, agentId, sessionId });
      const tokenized = result?.tokens_created > 0 ? result.tokenized_text || redacted : redacted;
      // Never trust the response to stay secret-free.
      return tripwire.scan(tokenized).length > 0 ? tripwire.redactOffline(tokenized) : tokenized;
    } catch {
      return redacted;
    }
  }

  /** Scan text for prompt injection patterns. */
  async scanInjection({ text }) {
    return this.#request("/v1/suite/guard/scan", { method: "POST", body: { text } });
  }

  // --- Credentials ---

  /** Issue a signed JWT trust credential. Requires agent key auth. */
  async issueCredential() {
    return this.#request("/v1/credentials/issue", { method: "POST" });
  }

  /** Verify a JWT trust credential. No auth needed. */
  async verifyCredential(credential) {
    return this.#request("/v1/credentials/verify", { method: "POST", body: { credential } });
  }

  // --- Agent Self-Service ---

  /** Get own trust scores with improvement guidance. Requires agent key auth. */
  async getMyScores() {
    return this.#request("/v1/agents/me/scores");
  }

  // --- Scoring Profiles ---

  /** Get the current tenant's scoring profile. */
  async getScoringProfile() {
    this.#requireAccountToken("getScoringProfile");
    return this.#request("/v1/suite/scoring/profile");
  }

  /** Set the tenant's scoring profile. Admin required. */
  async setScoringProfile(profileCode, weightOverrides = null) {
    this.#requireAccountToken("setScoringProfile");
    const body = { profile_code: profileCode };
    if (weightOverrides) body.weight_overrides = weightOverrides;
    return this.#request("/v1/suite/scoring/profile", { method: "POST", body });
  }

  // --- Agent Timeline ---

  /** Get an agent's event timeline. */
  async getAgentTimeline(agentId, { limit = 50 } = {}) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/timeline`, { query: { limit } });
  }

  // --- Agent API Keys ---

  /** List API keys for an agent. */
  async getAgentApiKeys(agentId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/api-keys`);
  }

  /** Rotate (regenerate) an agent's API key. */
  async rotateAgentApiKey(agentId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/api-keys/rotate`, { method: "POST" });
  }

  /** Revoke a specific agent API key. */
  async revokeAgentApiKey(agentId, keyId) {
    return this.#request(apiPath`/v1/public/agents/${agentId}/api-keys/${keyId}/revoke`, { method: "POST" });
  }

  // --- Guard PII Sessions ---

  /** Get details of a PII tokenization session. */
  async getPiiSession(sessionId) {
    return this.#request(apiPath`/v1/suite/guard/pii/sessions/${sessionId}`);
  }

  /** Revoke a PII tokenization session and all its tokens. */
  async revokePiiSession(sessionId) {
    this.#requireAccountToken("revokePiiSession");
    return this.#request(apiPath`/v1/suite/guard/pii/sessions/${sessionId}`, { method: "DELETE" });
  }

  // --- Guard Policies ---

  /** List all Guard policies for the workspace. */
  async listGuardPolicies() {
    return this.#request("/v1/suite/guard/policies");
  }

  /** Create a new Guard policy rule. */
  async createGuardPolicy(policy) {
    return this.#request("/v1/suite/guard/policies", { method: "POST", body: policy });
  }

  /**
   * Activate or deactivate a Guard policy rule.
   * @param {number|string} policyId
   * @param {{isActive?: boolean, is_active?: boolean}} updates
   */
  async updateGuardPolicy(policyId, { isActive, is_active: isActiveSnake } = {}) {
    const active = isActive ?? isActiveSnake;
    if (typeof active !== "boolean") {
      throw new TypeError("updateGuardPolicy requires { isActive: boolean }");
    }
    return this.#request(apiPath`/v1/suite/guard/policies/${policyId}`, {
      method: "PATCH",
      query: { is_active: active },
    });
  }

  /** Delete a Guard policy rule. */
  async deleteGuardPolicy(policyId) {
    return this.#request(apiPath`/v1/suite/guard/policies/${policyId}`, { method: "DELETE" });
  }

  // --- Guard Kill Switch ---

  /** Activate the kill switch for an agent, blocking all trust decisions. */
  async killAgent(agentId, reason) {
    return this.#request(apiPath`/v1/suite/guard/kill/${agentId}`, { method: "POST", body: { reason } });
  }

  /** Deactivate the kill switch for an agent. */
  async unkillAgent(agentId) {
    return this.#request(apiPath`/v1/suite/guard/unkill/${agentId}`, { method: "POST" });
  }

  // --- Guard Findings ---

  /** List Guard security findings, optionally filtered by agent. */
  async listGuardFindings(agentId = null) {
    return this.#request("/v1/suite/guard/findings", { query: { agent_id: agentId || null } });
  }

  /**
   * Set a Guard finding's status.
   * @param {number|string} findingId
   * @param {{newStatus?: "open"|"false_positive"|"mitigated"|"resolved", new_status?: string, status?: string}} updates
   */
  async updateGuardFinding(findingId, { newStatus, new_status: newStatusSnake, status } = {}) {
    this.#requireAccountToken("updateGuardFinding");
    const value = newStatus ?? newStatusSnake ?? status;
    if (typeof value !== "string" || value === "") {
      throw new TypeError("updateGuardFinding requires { newStatus: string }");
    }
    return this.#request(apiPath`/v1/suite/guard/findings/${findingId}`, {
      method: "PATCH",
      query: { new_status: value },
    });
  }

  // --- Passport Delegations ---

  /** Create a new Passport delegation grant. */
  async createDelegation(delegation) {
    this.#requireAccountToken("createDelegation");
    return this.#request("/v1/suite/passport/delegations", { method: "POST", body: delegation });
  }

  /** List active Passport delegations. */
  async listDelegations() {
    this.#requireAccountToken("listDelegations");
    return this.#request("/v1/suite/passport/delegations");
  }

  /** Revoke a Passport delegation. */
  async revokeDelegation(delegationId) {
    this.#requireAccountToken("revokeDelegation");
    return this.#request(apiPath`/v1/suite/passport/delegations/${delegationId}`, { method: "DELETE" });
  }

  // --- Passport Verification ---

  /** Mark an agent as identity-verified in Passport. */
  async verifyAgentIdentity(agentId) {
    this.#requireAccountToken("verifyAgentIdentity");
    return this.#request(apiPath`/v1/suite/passport/verify/${agentId}`, { method: "POST" });
  }

  // --- Passport Manifests ---

  /** Create or update an agent capability manifest. */
  async createManifest(agentId, manifest) {
    this.#requireAccountToken("createManifest");
    return this.#request(apiPath`/v1/suite/passport/manifests/${agentId}`, { method: "POST", body: manifest });
  }

  /** Get agent capability manifests from Passport. */
  async getManifests(agentId) {
    this.#requireAccountToken("getManifests");
    return this.#request(apiPath`/v1/suite/passport/manifests/${agentId}`);
  }

  // --- Vault ---

  /** Query the immutable Vault audit ledger. */
  async queryVaultLedger({ agentId = null, limit = 50 } = {}) {
    return this.#request("/v1/suite/vault/ledger", { query: { limit, agent_id: agentId || null } });
  }

  /** Verify hash-chain integrity of the Vault ledger. */
  async verifyVaultChain({ limit = 100 } = {}) {
    return this.#request("/v1/suite/vault/verify", { query: { limit } });
  }

  /** Create a Vault export job. */
  async exportVault({ exportType = "json" } = {}) {
    this.#requireAccountToken("exportVault");
    return this.#request("/v1/suite/vault/export", { method: "POST", body: { export_type: exportType } });
  }

  /** Check the status of a Vault export job. */
  async getVaultExportStatus(jobId) {
    this.#requireAccountToken("getVaultExportStatus");
    return this.#request(apiPath`/v1/suite/vault/export/${jobId}`);
  }

  // --- Notifications ---

  /** List notifications for the current workspace. */
  async listNotifications() {
    this.#requireAccountToken("listNotifications");
    return this.#request("/v1/suite/notifications");
  }

  /** Mark a single notification as read. */
  async markNotificationRead(notificationId) {
    this.#requireAccountToken("markNotificationRead");
    return this.#request(apiPath`/v1/suite/notifications/${notificationId}/read`, { method: "POST" });
  }

  /** Mark all notifications as read. */
  async markAllNotificationsRead() {
    this.#requireAccountToken("markAllNotificationsRead");
    return this.#request("/v1/suite/notifications/read-all", { method: "POST" });
  }

  // --- IP Allowlist ---

  /** Get the current IP allowlist for the workspace. */
  async getIpAllowlist() {
    this.#requireAccountToken("getIpAllowlist");
    return this.#request("/v1/public/providers/ip-allowlist");
  }

  /**
   * Set the IP allowlist for the workspace.
   * The server stores a comma-separated CIDR string and treats an empty one
   * as "disable", so an empty list is refused unless `enabled: false` is
   * passed explicitly.
   * @param {{cidrs?: string[]|string, enabled?: boolean}} options
   */
  async setIpAllowlist({ cidrs, enabled = true } = {}) {
    this.#requireAccountToken("setIpAllowlist");
    const ipAllowlist = enabled ? normalizeCidrs(cidrs) : "";
    if (enabled && ipAllowlist === "") {
      throw new TypeError(
        "setIpAllowlist: cidrs is empty; pass { enabled: false } to disable the allowlist",
      );
    }
    return this.#request("/v1/public/providers/ip-allowlist", {
      method: "POST",
      body: { ip_allowlist: ipAllowlist },
    });
  }

  // --- Custom Domains ---

  /** Get the custom domain configuration for the workspace. */
  async getCustomDomain() {
    this.#requireAccountToken("getCustomDomain");
    return this.#request("/v1/public/providers/custom-domain");
  }

  /** Set a custom domain for the workspace. */
  async setCustomDomain(domain) {
    this.#requireAccountToken("setCustomDomain");
    return this.#request("/v1/public/providers/custom-domain", { method: "POST", body: { domain } });
  }

  /** Verify DNS configuration for the custom domain. */
  async verifyCustomDomain() {
    this.#requireAccountToken("verifyCustomDomain");
    return this.#request("/v1/public/providers/custom-domain/verify", { method: "POST" });
  }

  /** Remove the custom domain from the workspace. */
  async deleteCustomDomain() {
    this.#requireAccountToken("deleteCustomDomain");
    return this.#request("/v1/public/providers/custom-domain", { method: "DELETE" });
  }

  // --- Team Management ---

  /** List team members in the current workspace. */
  async listTeamMembers() {
    this.#requireAccountToken("listTeamMembers");
    return this.#request("/v1/public/providers/team");
  }

  /** Invite a new team member to the workspace. */
  async inviteTeamMember({ email, role = "member" }) {
    this.#requireAccountToken("inviteTeamMember");
    return this.#request("/v1/public/providers/team/invite", { method: "POST", body: { email, role } });
  }

  /** Remove a team member from the workspace. */
  async removeTeamMember(userId) {
    this.#requireAccountToken("removeTeamMember");
    return this.#request(apiPath`/v1/public/providers/team/${userId}`, { method: "DELETE" });
  }

  // --- Workspaces ---

  /** List workspaces the current user belongs to. */
  async listWorkspaces() {
    this.#requireAccountToken("listWorkspaces");
    return this.#request("/v1/public/accounts/workspaces");
  }

  /** Switch the user's active workspace. */
  async switchWorkspace(tenantId) {
    this.#requireAccountToken("switchWorkspace");
    return this.#request(apiPath`/v1/public/accounts/workspaces/${tenantId}/switch`, { method: "POST" });
  }

  // --- Reputation Lookup ---

  /** Look up an agent's shared reputation by reference (email, URL, slug, ...). */
  async reputationLookup(agentRef) {
    if (!agentRef) throw new TypeError("reputationLookup requires agentRef");
    return this.#request("/v1/public/reputation/lookup", { query: { agent_ref: agentRef } });
  }

  // --- Trust Badges ---

  /** Get the URL for an agent's embeddable trust badge SVG. */
  getBadgeUrl(agentSlug, { style = "compact", theme = "dark" } = {}) {
    return `${this.baseUrl}${withQuery(apiPath`/v1/badge/${agentSlug}.svg`, { style, theme })}`;
  }

  // --- Platform Status ---

  /** Check platform health and feature flags. */
  async getPlatformStatus() {
    return this.#request("/v1/public/status");
  }

  // --- Cortex Workflows ---

  /** List all workflows for the current tenant. */
  async listWorkflows({ isActive = null } = {}) {
    return this.#request("/v1/workflows", { query: { is_active: isActive } });
  }

  /** Get a workflow's details and recent executions. */
  async getWorkflow(workflowId) {
    return this.#request(apiPath`/v1/workflows/${workflowId}`);
  }

  /** Create a new workflow from a definition object. */
  async createWorkflow({ name, slug, definition, description = "" }) {
    return this.#request("/v1/workflows", {
      method: "POST",
      body: { name, slug, description, definition },
    });
  }

  /** Update a workflow's name, description, or definition. */
  async updateWorkflow(workflowId, updates) {
    return this.#request(apiPath`/v1/workflows/${workflowId}`, {
      method: "PUT",
      body: updates,
    });
  }

  /** Delete a workflow. */
  async deleteWorkflow(workflowId) {
    return this.#request(apiPath`/v1/workflows/${workflowId}`, { method: "DELETE" });
  }

  /** Activate a workflow's triggers. */
  async activateWorkflow(workflowId) {
    return this.#request(apiPath`/v1/workflows/${workflowId}/activate`, { method: "POST" });
  }

  /** Deactivate a workflow's triggers. */
  async deactivateWorkflow(workflowId) {
    return this.#request(apiPath`/v1/workflows/${workflowId}/deactivate`, { method: "POST" });
  }

  /** Manually trigger a workflow execution. */
  async runWorkflow(workflowId, { inputs = {} } = {}) {
    return this.#request(apiPath`/v1/workflows/${workflowId}/run`, {
      method: "POST",
      body: { inputs },
    });
  }

  /** Get execution details including step-by-step results. */
  async getExecution(executionId) {
    return this.#request(apiPath`/v1/workflows/executions/${executionId}`);
  }

  /** List executions for a workflow. */
  async listExecutions(workflowId, { status = null } = {}) {
    return this.#request(apiPath`/v1/workflows/${workflowId}/executions`, { query: { status: status || null } });
  }

  /** Cancel a running execution. */
  async cancelExecution(executionId) {
    return this.#request(apiPath`/v1/workflows/executions/${executionId}/cancel`, { method: "POST" });
  }

  /** Retry a failed execution. */
  async retryExecution(executionId) {
    return this.#request(apiPath`/v1/workflows/executions/${executionId}/retry`, { method: "POST" });
  }

  /** Approve, reject, or edit a human review step. */
  async approveStep(executionId, stepId, { action = "approve", editedOutput = null } = {}) {
    this.#requireAccountToken("approveStep");
    const body = { action };
    if (editedOutput) body.edited_output = editedOutput;
    return this.#request(apiPath`/v1/workflows/executions/${executionId}/steps/${stepId}/approve`, {
      method: "POST",
      body,
    });
  }

  /** List available workflow templates. */
  async listWorkflowTemplates() {
    return this.#request("/v1/workflows/templates");
  }

  /** Deploy a workflow template as a new workflow. */
  async deployTemplate(templateId) {
    return this.#request(apiPath`/v1/workflows/templates/${templateId}/deploy`, { method: "POST" });
  }

  // --- Compliance ---

  /** Per-tenant OWASP Agentic AI Top 10 (2026) coverage report. */
  async getOwaspAttestation() {
    return this.#request("/v1/compliance/owasp-attestation");
  }

  /** List supported compliance frameworks (eu-ai-act, nist-ai-rmf, iso-42001). */
  async listComplianceFrameworks() {
    return this.#request("/v1/compliance/frameworks");
  }

  /**
   * Per-tenant compliance report for a specific framework.
   * @param {string} frameworkId - 'eu-ai-act' | 'nist-ai-rmf' | 'iso-42001'
   */
  async getComplianceReport(frameworkId) {
    return this.#request(apiPath`/v1/compliance/${frameworkId}`);
  }

  // --- Cedar Policies ---

  /** List active Cedar policies for the tenant. */
  async listCedarPolicies() {
    return this.#request("/v1/policies");
  }

  /** Create a Cedar policy. Requires Max or Enterprise plan. */
  async createCedarPolicy({ name, policyText, description = "" }) {
    return this.#request("/v1/policies", {
      method: "POST",
      body: { name, description, policy_text: policyText },
    });
  }

  /** Get a Cedar policy by id (includes full policy text). */
  async getCedarPolicy(policyId) {
    return this.#request(apiPath`/v1/policies/${policyId}`);
  }

  /** Update a Cedar policy. Increments version if policy_text changes. */
  async updateCedarPolicy(policyId, { name, description, policyText, isActive } = {}) {
    const body = {};
    if (name !== undefined) body.name = name;
    if (description !== undefined) body.description = description;
    if (policyText !== undefined) body.policy_text = policyText;
    if (isActive !== undefined) body.is_active = isActive;
    return this.#request(apiPath`/v1/policies/${policyId}`, { method: "PUT", body });
  }

  /** Soft-delete a Cedar policy. */
  async deleteCedarPolicy(policyId) {
    return this.#request(apiPath`/v1/policies/${policyId}`, { method: "DELETE" });
  }

  /** Validate Cedar policy syntax without persisting. */
  async validateCedarPolicy(policyText) {
    return this.#request("/v1/policies/validate", {
      method: "POST",
      body: { policy_text: policyText },
    });
  }

  /** Dry-run a Cedar policy against test input. Returns the decision. */
  async testCedarPolicy({
    policyText,
    agentId = "test_agent",
    actionType = "tool_call",
    policyTier = "tier_1",
    riskScore = 50,
    isVerified = false,
  }) {
    return this.#request("/v1/policies/test", {
      method: "POST",
      body: {
        policy_text: policyText,
        agent_id: agentId,
        action_type: actionType,
        policy_tier: policyTier,
        risk_score: riskScore,
        is_verified: isVerified,
      },
    });
  }

  // --- SRE: Circuit Breakers, SLOs, Error Budgets ---

  /** Combined SRE dashboard — circuit breakers + SLO + error budget + provider health. */
  async getSreDashboard() {
    return this.#request("/v1/analytics/sre/dashboard");
  }

  /** Get current state of all LLM provider circuit breakers. */
  async getCircuitBreakers() {
    return this.#request("/v1/analytics/sre/circuit-breakers");
  }

  /** Manually reset a circuit breaker to closed state. */
  async resetCircuitBreaker(provider, model) {
    return this.#request(apiPath`/v1/analytics/sre/circuit-breakers/${provider}/${model}/reset`, {
      method: "POST",
    });
  }

  /** Get error budget status based on SLO targets and recent LLM usage. */
  async getErrorBudget() {
    return this.#request("/v1/analytics/sre/error-budget");
  }

  /** Get the tenant's current SLO configuration. */
  async getSloConfig() {
    return this.#request("/v1/analytics/sre/slo-config");
  }

  /** Update tenant SLO targets. Stored in tenant.llm_config.slo. */
  async updateSloConfig({
    availabilityTarget,
    latencyP95TargetMs,
    errorBudgetWindowHours,
    budgetExhaustedAction,
  } = {}) {
    const body = {};
    if (availabilityTarget !== undefined) body.availability_target = availabilityTarget;
    if (latencyP95TargetMs !== undefined) body.latency_p95_target_ms = latencyP95TargetMs;
    if (errorBudgetWindowHours !== undefined) body.error_budget_window_hours = errorBudgetWindowHours;
    if (budgetExhaustedAction !== undefined) body.budget_exhausted_action = budgetExhaustedAction;
    return this.#request("/v1/analytics/sre/slo-config", { method: "PUT", body });
  }

  // --- Context Governance ---

  /** Combined context governance dashboard — topics + quality + gaps. */
  async getContextDashboard({ days = 30 } = {}) {
    return this.#request("/v1/analytics/context/dashboard", { query: { days } });
  }

  /** Event topic distribution and trending categories. */
  async getContextTopics({ days = 30, limit = 20 } = {}) {
    return this.#request("/v1/analytics/context/topics", { query: { days, limit } });
  }

  /** Knowledge base coverage, event health, per-agent breakdown. */
  async getContextQuality() {
    return this.#request("/v1/analytics/context/quality");
  }

  /** Detect agents with high failure rates and low knowledge base coverage. */
  async getContextGaps({ days = 30 } = {}) {
    return this.#request("/v1/analytics/context/gaps", { query: { days } });
  }

  // --- Guard Extensions: MCP Scanner + Cross-Model Verification ---

  /**
   * Scan MCP tool definitions for security risks (pre-deploy audit).
   * Checks for tool poisoning, typosquatting, schema manipulation,
   * rug-pull patterns, prompt injection, and excessive permissions.
   */
  async scanMcpTools(tools) {
    return this.#request("/v1/suite/guard/scan-mcp", {
      method: "POST",
      body: { tools },
    });
  }

  /**
   * Scan CI workflow YAML + Dockerfiles for secret-exfiltration risk.
   * Each file is `{ path, content?, diff? }`: pass `content` (full file at head)
   * for Layer 1 vulnerable-config checks and `diff` (unified diff hunks) for
   * Layer 2 exfil-pattern checks. Returns a report with `findings`,
   * `highestSeverity`, `blocked` (from the tenant's GuardPolicy enforcement
   * level), and `enforcementLevel`.
   */
  async scanCi(files) {
    return this.#request("/v1/suite/guard/scan-ci", {
      method: "POST",
      body: { files },
    });
  }

  /**
   * Score one conversation turn for multi-turn exfiltration risk (Guard Session Sentry).
   * Tracks cumulative session-level risk across turns; returns a score, severity, and
   * optional block decision based on the tenant's GuardPolicy enforcement level.
   *
   * @param {string} sessionId   - Conversation session id (max 64 chars)
   * @param {number} turnIndex   - Zero-based turn counter within the session
   * @param {object} [opts]
   * @param {string} [opts.userText=""]     - The user's message text for this turn
   * @param {string} [opts.agentText=""]    - The agent's reply text for this turn
   * @param {string} [opts.systemPrompt=""] - System prompt (include on first turn or when it changes)
   * @param {string} [opts.agentId]         - Agent id (`agt_*`); omit when not applicable
   * @param {string} [opts.actorId]         - Human actor / user id; omit when not applicable
   * @returns {Promise<{session_id, enabled, session_score, turn_value, highest_severity,
   *   contributions, enforcement_level, block_threshold, blocked, version}>}
   *   When the feature flag is off, returns the dormant shape:
   *   `{session_id, enabled: false, blocked: false, session_score: 0.0, highest_severity: "info", contributions: []}`.
   */
  async scanSessionTurn(sessionId, turnIndex, { userText = "", agentText = "", systemPrompt = "", agentId, actorId } = {}) {
    const body = {
      session_id: sessionId,
      turn_index: turnIndex,
      user_text: userText,
      agent_text: agentText,
      system_prompt: systemPrompt,
    };
    if (agentId !== undefined) body.agent_id = agentId;
    if (actorId !== undefined) body.actor_id = actorId;
    return this.#request("/v1/suite/guard/scan-session", { method: "POST", body });
  }

  /**
   * Cross-model verification — check a response with multiple LLMs.
   * Defends against memory poisoning (OWASP ASI06).
   */
  async verifyResponse({ prompt, response, models = null }) {
    const body = { prompt, response };
    if (models) body.models = models;
    return this.#request("/v1/suite/guard/verify", { method: "POST", body });
  }

  // --- Operator approval queue (/v1/approvals) ---

  /**
   * Submit a new approval request to the operator queue.
   *
   * @param {object} opts
   * @param {string} [opts.agentId]            - agent the request is on behalf of; omit for system-initiated reviews
   * @param {object} [opts.requestedAction={}] - structured description of what's being approved
   * @param {number} [opts.ttlSeconds=86400]   - seconds the request stays pending before expiring (60 - 30*86400)
   */
  async createApproval({ agentId = null, requestedAction = {}, ttlSeconds = 24 * 3600 } = {}) {
    const body = { requested_action: requestedAction, ttl_seconds: ttlSeconds };
    if (agentId !== null) body.agent_id = agentId;
    return this.#request("/v1/approvals", { method: "POST", body });
  }

  /**
   * List approval requests for the authenticated tenant.
   *
   * @param {object} [opts]
   * @param {"pending"|"approved"|"rejected"|"expired"|"all"} [opts.state="pending"]
   * @param {string}  [opts.agentId]
   * @param {number}  [opts.limit=100]
   */
  async listApprovals({ state = "pending", agentId = null, limit = 100 } = {}) {
    return this.#request("/v1/approvals", { query: { state, limit, agent_id: agentId } });
  }

  /** Get a single approval request. */
  async getApproval(approvalId) {
    return this.#request(apiPath`/v1/approvals/${approvalId}`);
  }

  /** Approve a pending approval request. Requires account session token (operator role). */
  async approveApproval(approvalId, { reason = null } = {}) {
    this.#requireAccountToken("approveApproval");
    const body = {};
    if (reason !== null) body.reason = reason;
    return this.#request(apiPath`/v1/approvals/${approvalId}/approve`, {
      method: "POST",
      body,
    });
  }

  /** Reject a pending approval request. Requires account session token (operator role). */
  async rejectApproval(approvalId, { reason = null } = {}) {
    this.#requireAccountToken("rejectApproval");
    const body = {};
    if (reason !== null) body.reason = reason;
    return this.#request(apiPath`/v1/approvals/${approvalId}/reject`, {
      method: "POST",
      body,
    });
  }

  // --- A2A Protocol (catalog, agent cards, tasks) ---

  /** List the tenant's trust-ranked A2A agent catalog (descending trust score, excludes killed). */
  async listA2aCatalog() {
    return this.#request("/v1/a2a/catalog");
  }

  /** Get an A2A agent card with the `x-veriswarm-trust` (and optional `x-veriswarm-transport`) extension. */
  async getA2aAgentCard(agentId) {
    return this.#request(apiPath`/v1/a2a/${agentId}/card`);
  }

  /**
   * Submit a task to an agent via the A2A protocol.
   *
   * @param {string} agentId - receiving agent (`agt_*`)
   * @param {{requestingAgentId: string, messages: Array<object>, signature?: object}} payload
   *   - requestingAgentId: caller's agent id
   *   - messages: A2A-shaped message list
   *   - signature: optional Ed25519 envelope `{key_id, signature, algo}`
   */
  async submitA2aTask(agentId, { requestingAgentId, messages, signature } = {}) {
    const body = { requesting_agent_id: requestingAgentId, messages };
    if (signature) body.signature = signature;
    return this.#request(apiPath`/v1/a2a/${agentId}/tasks`, {
      method: "POST",
      body,
    });
  }

  /** Get status + result of an A2A task. */
  async getA2aTask(agentId, taskId) {
    return this.#request(
      apiPath`/v1/a2a/${agentId}/tasks/${taskId}`,
    );
  }

  /** Cancel an in-flight A2A task. No-op if already terminated. */
  async cancelA2aTask(agentId, taskId) {
    return this.#request(
      apiPath`/v1/a2a/${agentId}/tasks/${taskId}/cancel`,
      { method: "POST" },
    );
  }

  // --- A2A Transport (Ed25519 signing) ---

  /** Provision Ed25519 transport keys for an agent. Returns the public key. */
  async provisionA2aKeys(agentId) {
    return this.#request(apiPath`/v1/a2a/${agentId}/keys`, { method: "POST" });
  }

  // --- Content Provenance (EU AI Act Article 50) ---

  /**
   * Generate an Ed25519-signed provenance manifest for AI-generated content.
   * Returns the manifest (including signature, content hash, tenant/agent metadata).
   */
  async labelContent({ content, agentId = null, model = null, contentType = "text/plain", metadata = null }) {
    const body = { content, content_type: contentType };
    if (agentId !== null) body.agent_id = agentId;
    if (model !== null) body.model = model;
    if (metadata !== null) body.metadata = metadata;
    return this.#request("/v1/content/label", { method: "POST", body });
  }

  /** Public lookup of a provenance manifest by SHA-256 content hash. */
  async getContentProvenance(contentHash) {
    return this.#request(apiPath`/v1/content/provenance/${contentHash}`);
  }

  /**
   * Verify a provenance manifest's Ed25519 signature.
   * If content is supplied, also verifies the content hash matches.
   */
  async verifyContent({ manifest, content = null }) {
    const body = { manifest };
    if (content !== null) body.content = content;
    return this.#request("/v1/content/verify", { method: "POST", body });
  }

  // --- ABAC: Agent Attributes (Cedar policy context) ---

  /**
   * Read tenant-defined ABAC attributes for an agent.
   * These flow into Cedar policies as principal.<key> at decision time.
   */
  async getAgentAttributes(agentId) {
    return this.#request(apiPath`/v1/agents/${agentId}/attributes`);
  }

  /**
   * Replace an agent's ABAC attributes. Values must be Cedar-compatible types
   * (strings, ints, bools, or lists of those). Reserved keys are rejected.
   */
  async setAgentAttributes(agentId, attributes) {
    return this.#request(apiPath`/v1/agents/${agentId}/attributes`, {
      method: "PUT",
      body: { attributes },
    });
  }

  // --- Passport JIT (Just-in-Time Access Grants) ---

  /**
   * Request a just-in-time access grant for an agent.
   * Trusted agents (composite_trust >= 75, risk_score <= 30, verified,
   * ttl <= 10min) are auto-approved. Others go pending.
   */
  async requestJitGrant({ agentId, actionType, resourceType = null, resourceId = null, reason = null, ttlSeconds = 300 }) {
    const body = {
      agent_id: agentId,
      action_type: actionType,
      ttl_seconds: ttlSeconds,
    };
    if (resourceType !== null) body.resource_type = resourceType;
    if (resourceId !== null) body.resource_id = resourceId;
    if (reason !== null) body.reason = reason;
    return this.#request("/v1/passport/jit/request", { method: "POST", body });
  }

  /** Approve a pending JIT grant (requires account session token). */
  async approveJitGrant(grantId) {
    this.#requireAccountToken("approveJitGrant");
    return this.#request(apiPath`/v1/passport/jit/${grantId}/approve`, { method: "POST" });
  }

  /** Deny a pending JIT grant. */
  async denyJitGrant(grantId, { reason = null } = {}) {
    this.#requireAccountToken("denyJitGrant");
    const body = {};
    if (reason !== null) body.reason = reason;
    return this.#request(apiPath`/v1/passport/jit/${grantId}/deny`, { method: "POST", body });
  }

  /** Revoke an approved JIT grant immediately. */
  async revokeJitGrant(grantId, { reason = null } = {}) {
    const body = {};
    if (reason !== null) body.reason = reason;
    return this.#request(apiPath`/v1/passport/jit/${grantId}/revoke`, { method: "POST", body });
  }

  /**
   * Issue the ES256 JIT token for an approved grant.
   * Only callable once per grant — subsequent calls fail.
   */
  async issueJitToken(grantId) {
    return this.#request(apiPath`/v1/passport/jit/${grantId}/token`, { method: "POST" });
  }

  /**
   * Verify a JIT token at use-time. Public endpoint — no auth required.
   * Checks signature, revocation state, expiry, and optional scope match.
   */
  async verifyJitToken({ token, expectedAction = null, expectedResourceId = null }) {
    const body = { token };
    if (expectedAction !== null) body.expected_action = expectedAction;
    if (expectedResourceId !== null) body.expected_resource_id = expectedResourceId;
    return this.#request("/v1/passport/jit/verify", { method: "POST", body });
  }

  /** List JIT grants for the tenant, optionally filtered by agent or status. */
  async listJitGrants({ agentId = null, status = null, limit = 50 } = {}) {
    return this.#request("/v1/passport/jit/grants", {
      query: { limit, agent_id: agentId || null, status: status || null },
    });
  }

  /** Get a single JIT grant by id. */
  async getJitGrant(grantId) {
    return this.#request(apiPath`/v1/passport/jit/grants/${grantId}`);
  }

  // --- Governance: Anomalies, Discovery, Credential Vault, Compliance Scheduling, Reputation ---

  /** List behavioral anomalies detected for the tenant. */
  async listAnomalies({ agentId = null, limit = 50 } = {}) {
    return this.#request("/v1/governance/anomalies", { query: { limit, agent_id: agentId || null } });
  }

  /** Trigger a shadow-agent discovery scan. */
  async runShadowDiscovery() {
    this.#requireAccountToken("runShadowDiscovery");
    return this.#request("/v1/governance/discovery/scan", { method: "POST" });
  }

  /** List discovered shadow agents, optionally filtered by status. */
  async listDiscoveredAgents({ status = null } = {}) {
    return this.#request("/v1/governance/discovery", { query: { status: status || null } });
  }

  /** Dismiss a discovered shadow agent. */
  async dismissDiscoveredAgent(discoveryId) {
    this.#requireAccountToken("dismissDiscoveredAgent");
    return this.#request(apiPath`/v1/governance/discovery/${discoveryId}/dismiss`, { method: "POST" });
  }

  /** Store an encrypted credential in the governance vault. */
  async storeCredential({ name, credentialType, value, agentId = null, minTrustScore = 0, rotationIntervalHours = null }) {
    this.#requireAccountToken("storeCredential");
    return this.#request("/v1/governance/credentials", {
      method: "POST",
      body: {
        name,
        credential_type: credentialType,
        value,
        agent_id: agentId,
        min_trust_score: minTrustScore,
        rotation_interval_hours: rotationIntervalHours,
      },
    });
  }

  /** Check out a credential for an agent (trust-score gated, audit-logged). */
  async checkoutCredential({ credentialName, agentId }) {
    return this.#request("/v1/governance/credentials/checkout", {
      method: "POST",
      body: { credential_name: credentialName, agent_id: agentId },
    });
  }

  /** List stored credentials (names/metadata only — never values). */
  async listCredentials() {
    return this.#request("/v1/governance/credentials");
  }

  /** Revoke a stored credential by id. */
  async revokeCredential(credentialId) {
    this.#requireAccountToken("revokeCredential");
    return this.#request(apiPath`/v1/governance/credentials/${credentialId}`, { method: "DELETE" });
  }

  /** Get credential checkout audit history. */
  async getCredentialCheckoutHistory({ credentialId = null, agentId = null, limit = 50 } = {}) {
    return this.#request("/v1/governance/credentials/history", {
      query: { limit, credential_id: credentialId, agent_id: agentId || null },
    });
  }

  /** Get the scheduled compliance report delivery config. */
  async getComplianceSchedule() {
    this.#requireAccountToken("getComplianceSchedule");
    return this.#request("/v1/governance/compliance/schedule");
  }

  /** Configure scheduled compliance report delivery (eu-ai-act, soc2, iso42001, hipaa). */
  async setComplianceSchedule({ framework, email, frequency = "monthly" }) {
    this.#requireAccountToken("setComplianceSchedule");
    return this.#request("/v1/governance/compliance/schedule", {
      method: "POST",
      body: { framework, frequency, email },
    });
  }

  /** Remove the scheduled compliance report delivery. */
  async deleteComplianceSchedule() {
    this.#requireAccountToken("deleteComplianceSchedule");
    return this.#request("/v1/governance/compliance/schedule", { method: "DELETE" });
  }

  /** Issue a signed Reputation Passport (W3C VC) for an agent. */
  async issueReputationPassport(agentId) {
    return this.#request(apiPath`/v1/governance/passport/${agentId}`, { method: "POST" });
  }

  /** Get decay-weighted cross-provider reputation for an agent. */
  async getAgentReputation(agentId) {
    return this.#request(apiPath`/v1/governance/reputation/${agentId}`);
  }

  // --- Internal ---

  /**
   * Load the tripwire on first use. If only the built-in rules are active
   * (fetch failed or the manifest was invalid), try again once the retry
   * interval has passed instead of keeping the fallback forever.
   */
  async #refreshTripwireIfDue() {
    const needsRetry = this._tripwire?.source !== "remote" && Date.now() >= this._tripwireRetryAt;
    if (this._tripwire && !needsRetry) return;
    this._tripwire = await ensureTripwire({ fetchManifest: () => this.getSecretRules() });
    if (this._tripwire.source !== "remote") {
      this._tripwireRetryAt = Date.now() + TRIPWIRE_RETRY_MS;
    }
  }

  /** Fail fast for endpoints whose server route accepts only a session token. */
  #requireAccountToken(method) {
    if (this.accountToken) return;
    throw new VeriSwarmError(
      `${method} requires an account session token: pass accountToken to the ` +
        "VeriSwarmClient constructor (this endpoint does not accept API keys)",
      { code: "ACCOUNT_TOKEN_REQUIRED" },
    );
  }

  async #request(path, { method = "GET", body = null, query = null } = {}) {
    const url = `${this.baseUrl}${withQuery(path, query)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.#send(url, method, body, controller.signal);
      const text = await readBodyCapped(response, MAX_RESPONSE_BYTES);
      const payload = parseBody(text, response);
      if (!response.ok) {
        // Do NOT embed the raw response payload in the thrown error.
        // The error rides up through unhandled-rejection logs, Sentry,
        // Datadog, etc. — anything the API echoes back (request
        // context, reflected auth state) ends up in customer logs.
        // Throw with a sanitised summary; surface the payload via
        // a separate property so callers that explicitly want it can
        // opt in. (Audit 2026-05-08 CRIT-SDK-3.)
        throw new VeriSwarmError(`VeriSwarm API ${response.status}`, {
          status: response.status,
          payload,
        });
      }
      return payload;
    } catch (err) {
      if (err instanceof VeriSwarmError) throw err;
      if (controller.signal.aborted) {
        throw new VeriSwarmError(`VeriSwarm request timed out after ${this.timeoutMs}ms`, {
          code: "TIMEOUT",
          cause: err,
        });
      }
      throw new VeriSwarmError(`VeriSwarm request failed: ${err?.message ?? err}`, {
        code: "NETWORK_ERROR",
        cause: err,
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  #send(url, method, body, signal) {
    const headers = {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
    };
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    if (this.agentKey) headers["x-agent-api-key"] = this.agentKey;
    if (this.accountToken) headers["x-account-access-token"] = this.accountToken;

    // redirect:'error' refuses to follow any 3xx. fetch's default
    // would re-attach headers including x-api-key on the redirected
    // request — a compromised/MITM'd response from baseUrl could 302
    // to attacker host and steal the API key. Real APIs don't 302
    // their JSON endpoints; treating a redirect as an error is the
    // safe default. (Audit closure 2026-05-08 CRIT-D-8.)
    return fetch(url, {
      method,
      headers,
      body: body == null ? undefined : JSON.stringify(body),
      signal,
      redirect: "error",
    });
  }
}
