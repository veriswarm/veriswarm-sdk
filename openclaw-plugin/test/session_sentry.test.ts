/**
 * Tests for Session Sentry integration in the message_sending hook.
 *
 * The test harness mirrors the pattern used in secret_tripwire_hook.test.ts:
 * - mock globalThis.fetch to control API responses
 * - register the plugin via pluginEntry.register()
 * - drive the message_sending hook directly
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { pluginEntry } from "../src/index.js";

// Captures hooks the plugin registers so we can invoke them directly.
function makeApi() {
  const hooks: Record<string, (e: any) => Promise<any>> = {};
  const api = {
    registerTool: () => {},
    registerHook: () => {},
    on: (name: string, handler: (e: any) => Promise<any>) => {
      hooks[name] = handler;
    },
    registerHttpRoute: () => {},
    registerService: () => {},
  };
  return { api, hooks };
}

// Base config with all scanning disabled except sessionScan so tests
// are scoped to the feature under test.
const BASE_CONFIG = {
  apiKey: "vsk_test",
  apiUrl: "https://api.test.local",
  piiEnabled: false,
  policyEnabled: false,
  injectionScan: false,
  auditEnabled: false,
  secretsDetection: false,
  sessionScan: true,
};

// Helper: build a standard scan-session response.
function scanResponse(blocked: boolean, extra: Record<string, any> = {}): Response {
  return new Response(
    JSON.stringify({ blocked, enabled: true, session_score: 0.1, ...extra }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
}

// Helper: intercept fetch and match by URL substring.
function mockFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  return vi.spyOn(globalThis, "fetch").mockImplementation((input, init) =>
    Promise.resolve(handler(String(input), init ?? {}))
  );
}

describe("message_sending — Session Sentry", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  afterEach(() => {
    fetchSpy?.mockRestore();
  });

  // ── Core behavior ──────────────────────────────────────────────────

  it("replaces message content when scan returns blocked:true", async () => {
    fetchSpy = mockFetch((_url) =>
      scanResponse(true, { highest_severity: "critical" })
    );

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await hooks["message_sending"]({
      content: "Here is your data: SSN 123-45-6789",
      conversation_id: "conv-block-test",
    });

    expect(result.content).toContain("blocked by VeriSwarm Guard session protection");
    expect(result.content).toContain("multi-turn data-extraction detection");
    // Original content must not appear in the result.
    expect(result.content).not.toContain("SSN");
  });

  it("leaves message content unchanged when scan returns blocked:false", async () => {
    fetchSpy = mockFetch((_url) => scanResponse(false));

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await hooks["message_sending"]({
      content: "Hello, how can I help you today?",
      conversation_id: "conv-allow-test",
    });

    // No content replacement — empty object signals no mutation.
    expect(result).toEqual({});
  });

  it("fails open and sends message unmodified when API throws", async () => {
    fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error("network error"));

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await hooks["message_sending"]({
      content: "Should pass through on API failure",
      conversation_id: "conv-error-test",
    });

    // Fail-open: no content replacement.
    expect(result).toEqual({});
  });

  it("fails open and sends message unmodified when API returns non-200", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("Internal Server Error", { status: 500 })
    );

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await hooks["message_sending"]({
      content: "Should pass through on 500",
      conversation_id: "conv-500-test",
    });

    expect(result).toEqual({});
  });

  // ── Turn counter ───────────────────────────────────────────────────

  it("increments turn_index for each message in the same conversation", async () => {
    const capturedBodies: any[] = [];

    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const event = { content: "msg", conversation_id: "conv-counter-test" };

    await hooks["message_sending"](event);
    await hooks["message_sending"](event);
    await hooks["message_sending"](event);

    // Three calls → turn indices 0, 1, 2 in order.
    expect(capturedBodies).toHaveLength(3);
    expect(capturedBodies[0].turn_index).toBe(0);
    expect(capturedBodies[1].turn_index).toBe(1);
    expect(capturedBodies[2].turn_index).toBe(2);
  });

  it("maintains separate turn counters per conversation", async () => {
    const capturedBodies: any[] = [];

    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    await hooks["message_sending"]({ content: "A-1", conversation_id: "conv-A" });
    await hooks["message_sending"]({ content: "B-1", conversation_id: "conv-B" });
    await hooks["message_sending"]({ content: "A-2", conversation_id: "conv-A" });
    await hooks["message_sending"]({ content: "B-2", conversation_id: "conv-B" });

    const bySession: Record<string, number[]> = {};
    for (const b of capturedBodies) {
      (bySession[b.session_id] ??= []).push(b.turn_index);
    }

    // conv-A: turns 0, 1; conv-B: turns 0, 1 — independent counters.
    expect(bySession["conv-A"]).toEqual([0, 1]);
    expect(bySession["conv-B"]).toEqual([0, 1]);
  });

  // ── Toggle ─────────────────────────────────────────────────────────

  it("skips the scan entirely when sessionScan is false", async () => {
    const calls: string[] = [];
    fetchSpy = mockFetch((url) => {
      calls.push(url);
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, sessionScan: false });

    const result = await hooks["message_sending"]({
      content: "Hello",
      conversation_id: "conv-toggle-off",
    });

    // No scan-session request should have been made.
    const scanCalls = calls.filter((u) => u.includes("scan-session"));
    expect(scanCalls).toHaveLength(0);
    expect(result).toEqual({});
  });

  // ── Dormant server ─────────────────────────────────────────────────

  it("passes message through when server returns enabled:false (dormant mode)", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ blocked: false, enabled: false }),
        { status: 200, headers: { "content-type": "application/json" } }
      )
    );

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await hooks["message_sending"]({
      content: "Perfectly fine message",
      conversation_id: "conv-dormant",
    });

    expect(result).toEqual({});
  });

  // ── Session-id derivation ──────────────────────────────────────────

  it("falls back to 'default' session when no conversation id is on the event", async () => {
    const capturedBodies: any[] = [];
    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    // No conversation_id, conversationId, or session_id on the event.
    await hooks["message_sending"]({ content: "no conv id here" });

    expect(capturedBodies[0].session_id).toBe("default");
  });

  it("truncates session_id to 64 characters when the raw id is longer", async () => {
    const capturedBodies: any[] = [];
    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const longId = "x".repeat(128);
    await hooks["message_sending"]({
      content: "msg with long conv id",
      conversation_id: longId,
    });

    expect(capturedBodies[0].session_id).toHaveLength(64);
    expect(capturedBodies[0].session_id).toBe(longId.slice(0, 64));
  });

  // ── Request payload shape ──────────────────────────────────────────

  it("sends agent_text and leaves user_text empty", async () => {
    const capturedBodies: any[] = [];
    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    await hooks["message_sending"]({
      content: "agent outbound text",
      conversation_id: "conv-payload-test",
    });

    const body = capturedBodies[0];
    expect(body.agent_text).toBe("agent outbound text");
    expect(body.user_text).toBe("");
    expect(body.system_prompt).toBe("");
    expect(body.agent_id).toBeTruthy(); // auto-generated agentId
  });
});
