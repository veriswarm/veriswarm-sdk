/**
 * VeriSwarm API client for the OpenClaw plugin.
 * Lightweight fetch-based client covering the full VeriSwarm suite:
 * Gate (trust), Guard (PII + security), Passport (identity), Vault (audit).
 */

export interface VeriSwarmConfig {
  apiUrl: string;
  apiKey: string;
  agentId: string;
  agentKey?: string;
}

export interface TokenizeResult {
  tokenized_text: string;
  session_id: string;
  tokens_created: number;
  token_manifest: { token: string; type: string; position: number[] }[];
}

export interface RehydrateResult {
  rehydrated_text: string;
  tokens_resolved: number;
}

export interface DecisionResult {
  decision: "allow" | "review" | "deny";
  reason_code: string;
  policy_tier: string;
  agent_id: string;
}

export interface TrustScores {
  agent_id: string;
  identity_score: number;
  risk_score: number;
  reliability_score: number;
  autonomy_score: number;
  policy_tier: string;
  risk_band: string;
}

export class VeriSwarmClient {
  private config: VeriSwarmConfig;

  constructor(config: VeriSwarmConfig) {
    this.config = {
      ...config,
      apiUrl: config.apiUrl.replace(/\/+$/, ""),
    };
  }

  // ── Gate (Trust Scoring) ──────────────────────────────────────────

  async checkTrust(agentId?: string): Promise<TrustScores> {
    return this.request(`/v1/public/agents/${agentId || this.config.agentId}/scores/current`);
  }

  async checkDecision(actionType: string, resourceType?: string): Promise<DecisionResult> {
    return this.request("/v1/decisions/check", "POST", {
      agent_id: this.config.agentId,
      action_type: actionType,
      resource_type: resourceType,
    });
  }

  async getScoreHistory(limit = 10): Promise<any> {
    return this.request(
      `/v1/public/agents/${this.config.agentId}/scores/history?limit=${limit}`
    );
  }

  // ── Guard (PII + Security) ────────────────────────────────────────

  async tokenizePii(text: string, sessionId?: string): Promise<TokenizeResult> {
    const body: Record<string, any> = {
      text,
      agent_id: this.config.agentId,
    };
    if (sessionId) body.session_id = sessionId;
    return this.request("/v1/suite/guard/pii/tokenize", "POST", body);
  }

  async rehydratePii(text: string, sessionId: string): Promise<RehydrateResult> {
    return this.request("/v1/suite/guard/pii/rehydrate", "POST", {
      text,
      session_id: sessionId,
    });
  }

  async getPiiSession(sessionId: string): Promise<any> {
    return this.request(`/v1/suite/guard/pii/sessions/${sessionId}`);
  }

  async getFindings(agentId?: string): Promise<any> {
    const params = agentId ? `?agent_id=${agentId}` : "";
    return this.request(`/v1/suite/guard/findings${params}`);
  }

  // ── Passport (Identity) ───────────────────────────────────────────

  async getCredentials(): Promise<any> {
    if (!this.config.agentKey) {
      throw new Error("agentKey is required for credential issuance. Set it in plugin config.");
    }
    // Credential issuance requires x-agent-api-key, not x-api-key
    const url = `${this.config.apiUrl}/v1/credentials/issue`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "veriswarm-openclaw-plugin/0.1.0",
        "x-agent-api-key": this.config.agentKey,
      },
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`VeriSwarm API ${response.status}: ${text}`);
    }
    return response.json();
  }

  async verifyCredential(token: string): Promise<any> {
    return this.request("/v1/credentials/verify", "POST", {
      credential: token,
    });
  }

  // ── Vault (Audit) ─────────────────────────────────────────────────

  async queryLedger(limit = 20, agentId?: string): Promise<any> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (agentId) params.set("agent_id", agentId);
    return this.request(`/v1/suite/vault/ledger?${params}`);
  }

  async verifyChain(): Promise<any> {
    return this.request("/v1/suite/vault/verify");
  }

  // ── Events ────────────────────────────────────────────────────────

  async ingestEvent(
    eventType: string,
    payload: Record<string, any>
  ): Promise<any> {
    return this.request("/v1/events", "POST", {
      event_id: `oc-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      agent_id: this.config.agentId,
      source_type: "openclaw_plugin",
      event_type: eventType,
      occurred_at: new Date().toISOString(),
      payload,
    });
  }

  // ── Platform ──────────────────────────────────────────────────────

  async getStatus(): Promise<any> {
    return this.request("/v1/public/status");
  }

  // ── Internal ──────────────────────────────────────────────────────

  private async request(
    path: string,
    method: string = "GET",
    body?: Record<string, any>
  ): Promise<any> {
    const url = `${this.config.apiUrl}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "veriswarm-openclaw-plugin/0.1.0",
      "x-api-key": this.config.apiKey,
    };

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`VeriSwarm API ${response.status}: ${text}`);
    }

    const contentType = response.headers.get("content-type") || "";
    return contentType.includes("json") ? response.json() : response.text();
  }
}
