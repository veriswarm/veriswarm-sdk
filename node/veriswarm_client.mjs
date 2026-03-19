/**
 * Lightweight VeriSwarm provider integration client.
 * Requires Node.js 18+ for native fetch support.
 */
export class VeriSwarmClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl - e.g. https://api.veriswarm.ai
   * @param {string} options.apiKey - provider API key (agk_...)
   * @param {number} [options.timeoutMs]
   */
  constructor({ baseUrl, apiKey, timeoutMs = 15000 }) {
    if (!baseUrl) {
      throw new Error("baseUrl is required");
    }
    if (!apiKey) {
      throw new Error("apiKey is required");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  async checkDecision({ agentId, actionType, resourceType = null }) {
    return this.#request("/v1/decisions/check", {
      method: "POST",
      body: {
        agent_id: agentId,
        action_type: actionType,
        resource_type: resourceType,
      },
    });
  }

  async ingestProviderReport(report) {
    return this.#request("/v1/public/providers/reports", {
      method: "POST",
      body: report,
    });
  }

  async ingestProviderReportsBatch(reports) {
    return this.#request("/v1/public/providers/reports/batch", {
      method: "POST",
      body: { reports },
    });
  }

  async registerAgent(payload) {
    return this.#request("/v1/public/agents/register", {
      method: "POST",
      body: payload,
    });
  }

  async #request(path, { method = "GET", body = null }) {
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
