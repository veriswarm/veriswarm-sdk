/**
 * VeriSwarm Node.js SDK — trust scoring, event ingestion, and agent management.
 * Requires Node.js 18+ for native fetch support.
 *
 * Usage:
 *   import { VeriSwarmClient } from "@veriswarm/sdk";
 *   const client = new VeriSwarmClient({ baseUrl: "https://api.veriswarm.ai", apiKey: "vsk_..." });
 *   const decision = await client.checkDecision({ agentId: "agt_123", actionType: "post_message" });
 */
export class VeriSwarmClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl - e.g. https://api.veriswarm.ai
   * @param {string} [options.apiKey] - workspace API key (vsk_...)
   * @param {string} [options.agentKey] - individual agent API key (vak_...)
   * @param {number} [options.timeoutMs=15000]
   */
  constructor({ baseUrl, apiKey = null, agentKey = null, timeoutMs = 15000 }) {
    if (!baseUrl) throw new Error("baseUrl is required");
    if (!apiKey && !agentKey) throw new Error("either apiKey or agentKey is required");
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.agentKey = agentKey;
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
    return this.#request("/v1/suite/scoring/profile");
  }

  /** Set the tenant's scoring profile. Admin required. */
  async setScoringProfile(profileCode, weightOverrides = null) {
    const body = { profile_code: profileCode };
    if (weightOverrides) body.weight_overrides = weightOverrides;
    return this.#request("/v1/suite/scoring/profile", { method: "POST", body });
  }

  // --- Agent Timeline ---

  /** Get an agent's event timeline. */
  async getAgentTimeline(agentId, { limit = 50 } = {}) {
    return this.#request(`/v1/public/agents/${agentId}/timeline?limit=${limit}`);
  }

  // --- Agent API Keys ---

  /** List API keys for an agent. */
  async getAgentApiKeys(agentId) {
    return this.#request(`/v1/public/agents/${agentId}/api-keys`);
  }

  /** Rotate (regenerate) an agent's API key. */
  async rotateAgentApiKey(agentId) {
    return this.#request(`/v1/public/agents/${agentId}/api-keys/rotate`, { method: "POST" });
  }

  /** Revoke a specific agent API key. */
  async revokeAgentApiKey(agentId, keyId) {
    return this.#request(`/v1/public/agents/${agentId}/api-keys/${keyId}/revoke`, { method: "POST" });
  }

  // --- Guard PII Sessions ---

  /** Get details of a PII tokenization session. */
  async getPiiSession(sessionId) {
    return this.#request(`/v1/suite/guard/pii/sessions/${sessionId}`);
  }

  /** Revoke a PII tokenization session and all its tokens. */
  async revokePiiSession(sessionId) {
    return this.#request(`/v1/suite/guard/pii/sessions/${sessionId}`, { method: "DELETE" });
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

  /** Update a Guard policy rule. */
  async updateGuardPolicy(policyId, updates) {
    return this.#request(`/v1/suite/guard/policies/${policyId}`, { method: "PATCH", body: updates });
  }

  /** Delete a Guard policy rule. */
  async deleteGuardPolicy(policyId) {
    return this.#request(`/v1/suite/guard/policies/${policyId}`, { method: "DELETE" });
  }

  // --- Guard Kill Switch ---

  /** Activate the kill switch for an agent, blocking all trust decisions. */
  async killAgent(agentId, reason) {
    return this.#request(`/v1/suite/guard/kill/${agentId}`, { method: "POST", body: { reason } });
  }

  /** Deactivate the kill switch for an agent. */
  async unkillAgent(agentId) {
    return this.#request(`/v1/suite/guard/unkill/${agentId}`, { method: "POST" });
  }

  // --- Guard Findings ---

  /** List Guard security findings, optionally filtered by agent. */
  async listGuardFindings(agentId = null) {
    const path = agentId ? `/v1/suite/guard/findings?agent_id=${agentId}` : "/v1/suite/guard/findings";
    return this.#request(path);
  }

  /** Update a Guard finding (e.g. resolve, dismiss). */
  async updateGuardFinding(findingId, updates) {
    return this.#request(`/v1/suite/guard/findings/${findingId}`, { method: "PATCH", body: updates });
  }

  // --- Passport Delegations ---

  /** Create a new Passport delegation grant. */
  async createDelegation(delegation) {
    return this.#request("/v1/suite/passport/delegations", { method: "POST", body: delegation });
  }

  /** List active Passport delegations. */
  async listDelegations() {
    return this.#request("/v1/suite/passport/delegations");
  }

  /** Revoke a Passport delegation. */
  async revokeDelegation(delegationId) {
    return this.#request(`/v1/suite/passport/delegations/${delegationId}`, { method: "DELETE" });
  }

  // --- Passport Verification ---

  /** Mark an agent as identity-verified in Passport. */
  async verifyAgentIdentity(agentId) {
    return this.#request(`/v1/suite/passport/verify/${agentId}`, { method: "POST" });
  }

  // --- Passport Manifests ---

  /** Create or update an agent capability manifest. */
  async createManifest(agentId, manifest) {
    return this.#request(`/v1/suite/passport/manifests/${agentId}`, { method: "POST", body: manifest });
  }

  /** Get agent capability manifests from Passport. */
  async getManifests(agentId) {
    return this.#request(`/v1/suite/passport/manifests/${agentId}`);
  }

  // --- Vault ---

  /** Query the immutable Vault audit ledger. */
  async queryVaultLedger({ agentId = null, limit = 50 } = {}) {
    let path = `/v1/suite/vault/ledger?limit=${limit}`;
    if (agentId) path += `&agent_id=${agentId}`;
    return this.#request(path);
  }

  /** Verify hash-chain integrity of the Vault ledger. */
  async verifyVaultChain({ limit = 100 } = {}) {
    return this.#request(`/v1/suite/vault/verify?limit=${limit}`);
  }

  /** Create a Vault export job. */
  async exportVault({ exportType = "json" } = {}) {
    return this.#request("/v1/suite/vault/export", { method: "POST", body: { export_type: exportType } });
  }

  /** Check the status of a Vault export job. */
  async getVaultExportStatus(jobId) {
    return this.#request(`/v1/suite/vault/export/${jobId}`);
  }

  // --- Notifications ---

  /** List notifications for the current workspace. */
  async listNotifications() {
    return this.#request("/v1/suite/notifications");
  }

  /** Mark a single notification as read. */
  async markNotificationRead(notificationId) {
    return this.#request(`/v1/suite/notifications/${notificationId}/read`, { method: "POST" });
  }

  /** Mark all notifications as read. */
  async markAllNotificationsRead() {
    return this.#request("/v1/suite/notifications/read-all", { method: "POST" });
  }

  // --- IP Allowlist ---

  /** Get the current IP allowlist for the workspace. */
  async getIpAllowlist() {
    return this.#request("/v1/public/providers/ip-allowlist");
  }

  /** Set the IP allowlist for the workspace. */
  async setIpAllowlist({ cidrs, enabled = true }) {
    return this.#request("/v1/public/providers/ip-allowlist", { method: "POST", body: { cidrs, enabled } });
  }

  // --- Custom Domains ---

  /** Get the custom domain configuration for the workspace. */
  async getCustomDomain() {
    return this.#request("/v1/public/providers/custom-domain");
  }

  /** Set a custom domain for the workspace. */
  async setCustomDomain(domain) {
    return this.#request("/v1/public/providers/custom-domain", { method: "POST", body: { domain } });
  }

  /** Verify DNS configuration for the custom domain. */
  async verifyCustomDomain() {
    return this.#request("/v1/public/providers/custom-domain/verify", { method: "POST" });
  }

  /** Remove the custom domain from the workspace. */
  async deleteCustomDomain() {
    return this.#request("/v1/public/providers/custom-domain", { method: "DELETE" });
  }

  // --- Team Management ---

  /** List team members in the current workspace. */
  async listTeamMembers() {
    return this.#request("/v1/public/providers/team");
  }

  /** Invite a new team member to the workspace. */
  async inviteTeamMember({ email, role = "member" }) {
    return this.#request("/v1/public/providers/team/invite", { method: "POST", body: { email, role } });
  }

  /** Remove a team member from the workspace. */
  async removeTeamMember(userId) {
    return this.#request(`/v1/public/providers/team/${userId}`, { method: "DELETE" });
  }

  // --- Workspaces ---

  /** List workspaces the current user belongs to. */
  async listWorkspaces() {
    return this.#request("/v1/public/accounts/workspaces");
  }

  /** Switch the user's active workspace. */
  async switchWorkspace(tenantId) {
    return this.#request(`/v1/public/accounts/workspaces/${tenantId}/switch`, { method: "POST" });
  }

  // --- Reputation Lookup ---

  /** Look up an agent's shared reputation by slug. */
  async reputationLookup(slug) {
    return this.#request(`/v1/public/reputation/lookup?slug=${slug}`);
  }

  // --- Trust Badges ---

  /** Get the URL for an agent's embeddable trust badge SVG. */
  getBadgeUrl(agentSlug, { style = "compact", theme = "dark" } = {}) {
    return `${this.baseUrl}/v1/badge/${agentSlug}.svg?style=${style}&theme=${theme}`;
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
      const headers = {
        "content-type": "application/json",
      };
      if (this.apiKey) headers["x-api-key"] = this.apiKey;
      if (this.agentKey) headers["x-agent-api-key"] = this.agentKey;

      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
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
