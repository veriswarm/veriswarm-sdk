import { describe, it, expect, vi, afterEach } from "vitest";
import { VeriSwarmClient } from "../src/client.js";

function jsonResponse(body: Record<string, any>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("VeriSwarmClient API URL security", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn> | undefined;

  afterEach(() => {
    fetchSpy?.mockRestore();
  });

  it("rejects remote plaintext HTTP URLs before any credentialed request can run", () => {
    expect(
      () =>
        new VeriSwarmClient({
          apiUrl: "http://api.veriswarm.ai",
          apiKey: "vsk_test",
          agentId: "agt_test",
        })
    ).toThrow(/apiUrl must be https:\/\//);
  });

  it("rejects malformed API URLs", () => {
    expect(
      () =>
        new VeriSwarmClient({
          apiUrl: "api.veriswarm.ai",
          apiKey: "vsk_test",
          agentId: "agt_test",
        })
    ).toThrow(/apiUrl is not a valid URL/);
  });

  it("allows localhost HTTP for development and normalizes trailing slashes", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        agent_id: "agt_test",
        identity_score: 1,
        risk_score: 0,
        reliability_score: 1,
        autonomy_score: 1,
        policy_tier: "standard",
        risk_band: "low",
      })
    );

    const client = new VeriSwarmClient({
      apiUrl: "http://localhost:8787///",
      apiKey: "vsk_test",
      agentId: "agt_test",
    });

    await client.checkTrust();

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://localhost:8787/v1/public/agents/agt_test/scores/current",
      expect.objectContaining({
        redirect: "error",
      })
    );
  });

  it("refuses redirects and sends only the workspace API key on normal requests", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        status: "ok",
      })
    );

    const client = new VeriSwarmClient({
      apiUrl: "https://api.test.local/",
      apiKey: "vsk_test",
      agentId: "agt_test",
      agentKey: "agta_test",
    });

    await client.getStatus();

    const [, init] = fetchSpy.mock.calls[0];
    expect(init).toEqual(
      expect.objectContaining({
        method: "GET",
        redirect: "error",
      })
    );
    expect(init?.headers).toEqual(
      expect.objectContaining({
        "x-api-key": "vsk_test",
      })
    );
    expect(init?.headers).not.toHaveProperty("x-agent-api-key");
  });

  it("refuses redirects and sends only the agent key when issuing credentials", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        credential: "jwt",
      })
    );

    const client = new VeriSwarmClient({
      apiUrl: "https://api.test.local/",
      apiKey: "vsk_test",
      agentId: "agt_test",
      agentKey: "agta_test",
    });

    await client.getCredentials();

    expect(fetchSpy).toHaveBeenCalledWith(
      "https://api.test.local/v1/credentials/issue",
      expect.objectContaining({
        method: "POST",
        redirect: "error",
      })
    );
    const [, init] = fetchSpy.mock.calls[0];
    expect(init?.headers).toEqual(
      expect.objectContaining({
        "x-agent-api-key": "agta_test",
      })
    );
    expect(init?.headers).not.toHaveProperty("x-api-key");
  });

  it("does not attempt credential issuance without an agent key", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch");
    const client = new VeriSwarmClient({
      apiUrl: "https://api.test.local",
      apiKey: "vsk_test",
      agentId: "agt_test",
    });

    await expect(client.getCredentials()).rejects.toThrow(/agentKey is required/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
