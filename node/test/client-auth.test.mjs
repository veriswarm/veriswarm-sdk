import { describe, it, expect, vi, beforeEach } from "vitest";
import { VeriSwarmClient } from "../veriswarm_client.mjs";

const BASE = "https://api.test";

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sentHeaders() {
  return fetch.mock.calls[0][1].headers;
}

// Every method whose server route accepts ONLY x-account-access-token
// (verified against the API route signatures).
const ACCOUNT_ONLY = {
  getScoringProfile: (c) => c.getScoringProfile(),
  setScoringProfile: (c) => c.setScoringProfile("general"),
  listNotifications: (c) => c.listNotifications(),
  markNotificationRead: (c) => c.markNotificationRead(1),
  markAllNotificationsRead: (c) => c.markAllNotificationsRead(),
  getIpAllowlist: (c) => c.getIpAllowlist(),
  setIpAllowlist: (c) => c.setIpAllowlist({ cidrs: ["10.0.0.0/8"] }),
  getCustomDomain: (c) => c.getCustomDomain(),
  setCustomDomain: (c) => c.setCustomDomain("agents.example.com"),
  verifyCustomDomain: (c) => c.verifyCustomDomain(),
  deleteCustomDomain: (c) => c.deleteCustomDomain(),
  listTeamMembers: (c) => c.listTeamMembers(),
  inviteTeamMember: (c) => c.inviteTeamMember({ email: "a@example.com" }),
  removeTeamMember: (c) => c.removeTeamMember("usr_1"),
  listWorkspaces: (c) => c.listWorkspaces(),
  switchWorkspace: (c) => c.switchWorkspace("ten_1"),
  approveApproval: (c) => c.approveApproval("apr_1"),
  rejectApproval: (c) => c.rejectApproval("apr_1"),
  approveJitGrant: (c) => c.approveJitGrant("jit_1"),
  denyJitGrant: (c) => c.denyJitGrant("jit_1"),
  approveStep: (c) => c.approveStep("exe_1", "step_1"),
  storeCredential: (c) => c.storeCredential({ name: "n", credentialType: "api_key", value: "v" }),
  revokeCredential: (c) => c.revokeCredential(1),
  runShadowDiscovery: (c) => c.runShadowDiscovery(),
  dismissDiscoveredAgent: (c) => c.dismissDiscoveredAgent(1),
  getComplianceSchedule: (c) => c.getComplianceSchedule(),
  setComplianceSchedule: (c) => c.setComplianceSchedule({ framework: "eu-ai-act", email: "a@example.com" }),
  deleteComplianceSchedule: (c) => c.deleteComplianceSchedule(),
  verifyAgentIdentity: (c) => c.verifyAgentIdentity("agt_1"),
  createManifest: (c) => c.createManifest("agt_1", { version: "1.0" }),
  getManifests: (c) => c.getManifests("agt_1"),
  createDelegation: (c) => c.createDelegation({ grantee_agent_id: "agt_2", scopes: ["x"] }),
  listDelegations: (c) => c.listDelegations(),
  revokeDelegation: (c) => c.revokeDelegation(1),
  exportVault: (c) => c.exportVault(),
  getVaultExportStatus: (c) => c.getVaultExportStatus("job_1"),
  revokePiiSession: (c) => c.revokePiiSession("pii_1"),
  updateGuardFinding: (c) => c.updateGuardFinding(1, { newStatus: "resolved" }),
};

describe("constructor auth options", () => {
  it("accepts an account token on its own", () => {
    const c = new VeriSwarmClient({ baseUrl: BASE, accountToken: "acct_tok" });
    expect(c.accountToken).toBe("acct_tok");
  });

  it("still requires at least one credential", () => {
    expect(() => new VeriSwarmClient({ baseUrl: BASE })).toThrow(/apiKey, agentKey, or accountToken/);
  });

  it("refuses to send an account token over plain http", () => {
    expect(() => new VeriSwarmClient({ baseUrl: "http://api.test", accountToken: "t" })).toThrow(/https/);
  });
});

describe("account-token-only endpoints", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({})));
  });

  it.each(Object.entries(ACCOUNT_ONLY))(
    "%s fails locally with a clear error when no account token is configured",
    async (name, call) => {
      const c = new VeriSwarmClient({ baseUrl: BASE, apiKey: "vsk_x" });
      const err = await call(c).then(
        () => null,
        (e) => e,
      );
      expect(err).toBeInstanceOf(Error);
      expect(err.code).toBe("ACCOUNT_TOKEN_REQUIRED");
      expect(err.message).toContain(name);
      expect(err.message).toContain("accountToken");
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(Object.entries(ACCOUNT_ONLY))("%s sends x-account-access-token when configured", async (_name, call) => {
    const c = new VeriSwarmClient({ baseUrl: BASE, accountToken: "acct_tok" });
    await call(c);
    expect(sentHeaders()["x-account-access-token"]).toBe("acct_tok");
  });
});

describe("kill switch and Guard policy CRUD (scoped API key or account token)", () => {
  const CALLS = {
    killAgent: (c) => c.killAgent("agt_1", "compromised"),
    unkillAgent: (c) => c.unkillAgent("agt_1"),
    listGuardPolicies: (c) => c.listGuardPolicies(),
    createGuardPolicy: (c) => c.createGuardPolicy({ name: "p" }),
    updateGuardPolicy: (c) => c.updateGuardPolicy(1, { isActive: false }),
    deleteGuardPolicy: (c) => c.deleteGuardPolicy(1),
  };

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({})));
  });

  it.each(Object.entries(CALLS))("%s sends the API key without a local account-token error", async (_n, call) => {
    const c = new VeriSwarmClient({ baseUrl: BASE, apiKey: "vsk_x" });
    await call(c);
    expect(sentHeaders()["x-api-key"]).toBe("vsk_x");
    expect(sentHeaders()["x-account-access-token"]).toBeUndefined();
  });

  it.each(Object.entries(CALLS))("%s sends both credentials when both are configured", async (_n, call) => {
    const c = new VeriSwarmClient({ baseUrl: BASE, apiKey: "vsk_x", accountToken: "acct_tok" });
    await call(c);
    expect(sentHeaders()["x-api-key"]).toBe("vsk_x");
    expect(sentHeaders()["x-account-access-token"]).toBe("acct_tok");
  });
});

describe("credentials are not exposed when the client is inspected or serialized", () => {
  const SECRETS = { apiKey: "vsk_SECRET_api", agentKey: "vak_SECRET_agent", accountToken: "acct_SECRET_tok" };

  it("util.inspect, console-style formatting, JSON.stringify and key listing omit every credential", async () => {
    const { inspect, format } = await import("node:util");
    const c = new VeriSwarmClient({ baseUrl: BASE, ...SECRETS });
    const renderings = [
      inspect(c, { showHidden: true, depth: Infinity, getters: true }),
      format("%o", c),
      JSON.stringify(c),
      JSON.stringify(Object.keys(c)),
      JSON.stringify({ ...c }),
    ];
    for (const out of renderings) {
      for (const secret of Object.values(SECRETS)) expect(out).not.toContain(secret);
    }
  });

  it("still sends every credential and keeps read-only accessors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({})));
    const c = new VeriSwarmClient({ baseUrl: BASE, ...SECRETS });
    await c.getPlatformStatus();
    expect(sentHeaders()["x-api-key"]).toBe(SECRETS.apiKey);
    expect(sentHeaders()["x-agent-api-key"]).toBe(SECRETS.agentKey);
    expect(sentHeaders()["x-account-access-token"]).toBe(SECRETS.accountToken);
    expect(c.accountToken).toBe(SECRETS.accountToken);
    expect(() => {
      "use strict";
      c.apiKey = "other";
    }).toThrow();
  });
});
