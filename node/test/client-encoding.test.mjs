import { describe, it, expect, vi, beforeEach } from "vitest";
import { VeriSwarmClient } from "../veriswarm_client.mjs";

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function calledUrl() {
  return fetch.mock.calls[0][0];
}

describe("path segment safety", () => {
  let client;
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({})));
    client = new VeriSwarmClient({ baseUrl: "https://api.test", apiKey: "vsk_x" });
  });

  it.each([".", "..", ""])("rejects %j as a path id before any request", async (bad) => {
    await expect(client.getAgent(bad)).rejects.toThrow(/path segment/);
    await expect(client.approveStep("exec_1", bad)).rejects.toThrow(/path segment/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects null/undefined ids instead of sending the string 'undefined'", async () => {
    await expect(client.getAgent(undefined)).rejects.toThrow(/path segment/);
    await expect(client.getWorkflow(null)).rejects.toThrow(/path segment/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("encodes model names containing '/' in resetCircuitBreaker", async () => {
    await client.resetCircuitBreaker("openai", "org/gpt-4o");
    expect(calledUrl()).toBe(
      "https://api.test/v1/analytics/sre/circuit-breakers/openai/org%2Fgpt-4o/reset",
    );
  });

  it("encodes approveStep step ids", async () => {
    await client.approveStep("exec/1", "step 2", { action: "approve" });
    expect(calledUrl()).toBe(
      "https://api.test/v1/workflows/executions/exec%2F1/steps/step%202/approve",
    );
  });

  it("encodes content hashes in getContentProvenance", async () => {
    await client.getContentProvenance("../admin");
    expect(calledUrl()).toBe("https://api.test/v1/content/provenance/..%2Fadmin");
  });

  it("encodes every badge URL part", () => {
    const url = client.getBadgeUrl("a/b?c", { style: "card&x=1", theme: "dark" });
    expect(url).toBe("https://api.test/v1/badge/a%2Fb%3Fc.svg?style=card%26x%3D1&theme=dark");
  });

  it("rejects dot-segment badge slugs", () => {
    expect(() => client.getBadgeUrl("..")).toThrow(/path segment/);
  });
});

describe("query value encoding", () => {
  let client;
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({})));
    client = new VeriSwarmClient({ baseUrl: "https://api.test", apiKey: "vsk_x" });
  });

  it("encodes status in listExecutions", async () => {
    await client.listExecutions("wf_1", { status: "a&b=c" });
    expect(calledUrl()).toBe("https://api.test/v1/workflows/wf_1/executions?status=a%26b%3Dc");
  });

  it("encodes status and limit in listJitGrants", async () => {
    await client.listJitGrants({ status: "x&y", limit: "5&z=1" });
    const url = new URL(calledUrl());
    expect(url.searchParams.get("status")).toBe("x&y");
    expect(url.searchParams.get("limit")).toBe("5&z=1");
    expect([...url.searchParams.keys()].sort()).toEqual(["limit", "status"]);
  });

  it("encodes days/limit in context analytics", async () => {
    await client.getContextTopics({ days: "1&evil=1", limit: 3 });
    const url = new URL(calledUrl());
    expect(url.searchParams.get("days")).toBe("1&evil=1");
    expect(url.searchParams.has("evil")).toBe(false);
  });

  it("encodes is_active in listWorkflows", async () => {
    await client.listWorkflows({ isActive: "true&x=1" });
    const url = new URL(calledUrl());
    expect(url.searchParams.get("is_active")).toBe("true&x=1");
  });

  it("omits unset optional filters", async () => {
    await client.listExecutions("wf_1");
    expect(calledUrl()).toBe("https://api.test/v1/workflows/wf_1/executions");
  });
});
