/**
 * VeriSwarm Node.js SDK — trust scoring, event ingestion, and agent management.
 * Requires Node.js 18+ for native fetch support.
 *
 * Usage:
 *   import { VeriSwarmClient } from "veriswarm_client.mjs";
 *   const client = new VeriSwarmClient({ baseUrl: "https://api.veriswarm.ai", apiKey: "vsk_..." });
 *   const decision = await client.checkDecision({ agentId: "agt_123", actionType: "post_message" });
 */
export class VeriSwarmClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl - e.g. https://api.veriswarm.ai
   * @param {string} options.apiKey - workspace API key (vsk_...)
   * @param {number} [options.timeoutMs=15000]
   */
  constructor({ baseUrl, apiKey, timeoutMs = 15000 }) {
    if (!baseUrl) throw new Error("baseUrl is required");
    if (!apiKey) throw new Error("apiKey is required");
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
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
    return this.#request(`/v1/public/agents/${agentId}`);
  }

  /** Get an agent's current trust scores. */
  async getAgentScores(agentId) {
    return this.#request(`/v1/public/agents/${agentId}/scores/current`);
  }

  /** Get an agent's score history (last N snapshots). */
  async getAgentScoreHistory(agentId, { limit = 20 } = {}) {
    return this.#request(`/v1/public/agents/${agentId}/scores/history?limit=${limit}`);
  }

  /** Get detailed score breakdown with contributing factors. */
  async getAgentScoreBreakdown(agentId) {
    return this.#request(`/v1/public/agents/${agentId}/scores/breakdown`);
  }

  /** Get active moderation flags for an agent. */
  async getAgentFlags(agentId) {
    return this.#request(`/v1/public/agents/${agentId}/flags`);
  }

  /** Appeal a moderation flag for review. */
  async appealFlag(agentId, flagId) {
    return this.#request(`/v1/public/agents/${agentId}/flags/${flagId}/appeal`, { method: "POST" });
  }

  /** Get agent capability manifests (public). */
  async getAgentManifests(agentId) {
    return this.#request(`/v1/public/agents/${agentId}/manifests`);
  }

  // --- Platform Status ---

  /** Check platform health and feature flags. */
  async getPlatformStatus() {
    return this.#request("/v1/public/status");
  }

  // --- Internal ---

  async #request(path, { method = "GET", body = null } = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          "content-type": "application/json",
          "x-api-key": this.apiKey,
        },
        body: body == null ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      const contentType = response.headers.get("content-type") || "";
      const payload = contentType.includes("application/json")
        ? await response.json()
        : await response.text();
      if (!response.ok) {
        const details = typeof payload === "string" ? payload : JSON.stringify(payload);
        throw new Error(`VeriSwarm API ${response.status}: ${details}`);
      }
      return payload;
    } finally {
      clearTimeout(timeout);
    }
  }
}
