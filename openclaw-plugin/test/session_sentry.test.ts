/**
 * Tests for Session Sentry integration in the message_sending hook.
 *
 * - mock globalThis.fetch to control API responses
 * - register the plugin via pluginEntry.register()
 * - drive the message_sending hook with the host's real shapes:
 *   event { to, content }, ctx { channelId, sessionKey?, conversationId? };
 *   result { content } to rewrite or { cancel: true, cancelReason } to stop.
 *   (End-to-end through the real host runner: host_contract.integration.test.ts.)
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { pluginEntry, MAX_SESSION_COUNTERS } from "../src/index.js";

// Captures hooks the plugin registers so we can invoke them directly.
function makeApi() {
  const hooks: Record<string, (e: any, ctx?: any) => Promise<any>> = {};
  const api = {
    registerTool: () => {},
    registerHook: () => {},
    on: (name: string, handler: (e: any, ctx?: any) => Promise<any>) => {
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

// Drive message_sending the way the host does.
function send(
  hooks: Record<string, (e: any, ctx?: any) => Promise<any>>,
  content: unknown,
  ctx: Record<string, unknown> = {}
) {
  return hooks["message_sending"]({ to: "user-1", content }, { channelId: "test", ...ctx });
}

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

  it("cancels delivery (cancel:true) when scan returns blocked:true", async () => {
    fetchSpy = mockFetch((_url) =>
      scanResponse(true, { highest_severity: "critical" })
    );

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await send(hooks, "Here is your data: SSN 123-45-6789", { sessionKey: "conv-block-test" });

    // Only cancel:true stops delivery in the host; rewritten content would
    // still be sent, so the block must not be expressed as a content rewrite.
    expect(result.cancel).toBe(true);
    expect(result.cancelReason).toContain("blocked by VeriSwarm Guard session protection");
    expect(result.cancelReason).toContain("multi-turn data-extraction detection");
    expect(result.content).toBeUndefined();
  });

  it("leaves message content unchanged when scan returns blocked:false", async () => {
    fetchSpy = mockFetch((_url) => scanResponse(false));

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await send(hooks, "Hello, how can I help you today?", { sessionKey: "conv-allow-test" });

    // No decision — the host treats an undefined result as "send unchanged".
    expect(result).toBeUndefined();
  });

  it("cancels delivery (fail closed) when the API throws", async () => {
    fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error("network error"));

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await send(hooks, "Should be held on API failure", { sessionKey: "conv-error-test" });

    expect(result).toEqual({
      cancel: true,
      cancelReason: "Message held by VeriSwarm Guard: session protection is unavailable.",
    });
  });

  it("cancels delivery (fail closed) when the API request times out", async () => {
    vi.useFakeTimers();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      return new Promise((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined;
        signal?.addEventListener("abort", () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        });
      });
    });

    try {
      const { api, hooks } = makeApi();
      pluginEntry.register(api as any, BASE_CONFIG);

      const resultPromise = send(hooks, "Should be held on timeout", { sessionKey: "conv-timeout-test" });

      await vi.advanceTimersByTimeAsync(10_000);
      const result = await resultPromise;

      expect(result?.cancel).toBe(true);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("Session Sentry scan failed")
      );
    } finally {
      warnSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it("cancels delivery (fail closed) when the API returns non-200", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("Internal Server Error", { status: 500 })
    );

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await send(hooks, "Should be held on 500", { sessionKey: "conv-500-test" });

    expect(result).toEqual({
      cancel: true,
      cancelReason: "Message held by VeriSwarm Guard: session protection is unavailable.",
    });
  });

  it("cancels delivery (fail closed) on a malformed scan response", async () => {
    fetchSpy = mockFetch(() =>
      new Response(JSON.stringify({ enabled: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await send(hooks, "no blocked field", { sessionKey: "conv-malformed" });

    expect(result).toEqual({
      cancel: true,
      cancelReason: "Message held by VeriSwarm Guard: session protection is unavailable.",
    });
  });

  it("sends unmodified on API failure when failOpen is set", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network error"));

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, failOpen: true });

    const result = await send(hooks, "Should pass through", { sessionKey: "conv-fail-open" });

    expect(result).toBeUndefined();
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

    const ctx = { sessionKey: "conv-counter-test" };

    await send(hooks, "msg", ctx);
    await send(hooks, "msg", ctx);
    await send(hooks, "msg", ctx);

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

    await send(hooks, "A-1", { sessionKey: "conv-A" });
    await send(hooks, "B-1", { sessionKey: "conv-B" });
    await send(hooks, "A-2", { sessionKey: "conv-A" });
    await send(hooks, "B-2", { sessionKey: "conv-B" });

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

    const result = await send(hooks, "Hello", { sessionKey: "conv-toggle-off" });

    // No scan-session request should have been made.
    const scanCalls = calls.filter((u) => u.includes("scan-session"));
    expect(scanCalls).toHaveLength(0);
    expect(result).toBeUndefined();
  });

  // ── Dormant server ─────────────────────────────────────────────────

  it("passes message through when server returns enabled:false (dormant mode)", async () => {
    // A fresh Response per call: the background secret-rules refresh also fetches.
    fetchSpy = mockFetch(
      () =>
        new Response(
          JSON.stringify({ blocked: false, enabled: false }),
          { status: 200, headers: { "content-type": "application/json" } }
        )
    );

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await send(hooks, "Perfectly fine message", { sessionKey: "conv-dormant" });

    expect(result).toBeUndefined();
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

    // No conversation identity on ctx or event.
    await send(hooks, "no conv id here");

    expect(capturedBodies[0].session_id).toBe("default");
  });

  it("hashes ids longer than 64 chars so shared prefixes stay distinct", async () => {
    const capturedBodies: any[] = [];
    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const prefix = "agent:main:telegram:group:" + "x".repeat(60);
    await send(hooks, "first", { sessionKey: `${prefix}:alice` });
    await send(hooks, "second", { sessionKey: `${prefix}:bob` });
    await send(hooks, "short", { sessionKey: "short-id" });

    const [alice, bob, short] = capturedBodies.map((b) => b.session_id);
    expect(alice).toMatch(/^[0-9a-f]{64}$/);
    expect(bob).toMatch(/^[0-9a-f]{64}$/);
    expect(alice).not.toBe(bob);
    expect(short).toBe("short-id");
    // Each hashed id has its own turn counter.
    expect(capturedBodies.map((b) => b.turn_index)).toEqual([0, 0, 0]);
  });

  it("ignores events whose content is not a string", async () => {
    const calls: string[] = [];
    fetchSpy = mockFetch((url) => {
      calls.push(url);
      return scanResponse(true);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await send(hooks, { not: "text" }, { sessionKey: "conv-non-string" });

    expect(result).toBeUndefined();
    expect(calls.filter((u) => u.includes("scan-session"))).toHaveLength(0);
  });

  it("resolves identity: ctx.sessionKey, learned binding, delivery target, legacy event fields", async () => {
    const capturedBodies: any[] = [];
    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    // 1. Agent-path ctx with a sessionKey wins over everything else.
    await hooks["message_sending"](
      { to: "u", content: "both", conversation_id: "event-conv" },
      { channelId: "telegram", sessionKey: "sk-direct", conversationId: "999" }
    );
    // 2. Deliver-path ctx (no sessionKey) maps through the binding that
    //    message_received learned for the same channel + conversation.
    await hooks["message_received"](
      { from: "telegram:123", content: "hi" },
      { channelId: "telegram", conversationId: "telegram:123", sessionKey: "sk-bound" }
    );
    await hooks["message_sending"](
      { to: "123", content: "reply" },
      { channelId: "telegram", accountId: "default", conversationId: "123" }
    );
    // 3. No binding: channel-scoped delivery target.
    await hooks["message_sending"](
      { to: "456", content: "unbound" },
      { channelId: "telegram", conversationId: "456" }
    );
    // 4. Legacy host: identity only on the event.
    await hooks["message_sending"]({ to: "u", content: "legacy", session_id: "legacy-session" }, {});

    expect(capturedBodies.map((body) => body.session_id)).toEqual([
      "sk-direct",
      "sk-bound",
      "target:telegram:456",
      "legacy-session",
    ]);
  });

  // ── Session counter cap ────────────────────────────────────────────

  it("caps sessionTurnCounters at MAX_SESSION_COUNTERS by evicting the oldest entry", async () => {
    // Drive the hook synchronously via a resolved-promise mock so 10k iterations
    // don't accumulate real async overhead.
    fetchSpy = mockFetch((_url) => scanResponse(false));

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    // Insert MAX_SESSION_COUNTERS + 1 distinct conversation ids.
    // The first insertion (conv-0) should be evicted when the (MAX+1)th is added.
    const promises: Promise<any>[] = [];
    for (let i = 0; i < MAX_SESSION_COUNTERS + 1; i++) {
      promises.push(
        send(hooks, "msg", { sessionKey: `cap-evict-${i}` })
      );
    }
    await Promise.all(promises);

    // Verify cap by re-sending for the first conversation id.
    // If it was evicted, its counter resets to 0 (fresh entry).
    const capturedBodies: any[] = [];
    fetchSpy.mockRestore();
    fetchSpy = mockFetch((url, init) => {
      if (url.includes("scan-session")) {
        capturedBodies.push(JSON.parse(String(init.body)));
      }
      return scanResponse(false);
    });

    await send(hooks, "msg", { sessionKey: "cap-evict-0" });

    // conv-0 was evicted — turn_index restarts at 0, not at MAX_SESSION_COUNTERS.
    expect(capturedBodies[0].turn_index).toBe(0);
  }, 30_000);

  // ── Blocked path: logEvent rejection must not fail-open ───────────

  it("still returns the block refusal when logEvent (audit) rejects", async () => {
    // Mock scan to return blocked:true.
    fetchSpy = mockFetch((url, _init) => {
      if (url.includes("scan-session")) {
        return scanResponse(true, { highest_severity: "high" });
      }
      // Mock the logEvent ingestEvent call to reject.
      return Promise.reject(new Error("audit endpoint down")) as any;
    });

    const { api, hooks } = makeApi();
    // auditEnabled:true so logEvent actually attempts to call ingestEvent.
    pluginEntry.register(api as any, { ...BASE_CONFIG, auditEnabled: true });

    const result = await send(hooks, "sensitive data the agent is trying to send", { sessionKey: "conv-audit-reject" });

    // The cancel must still be returned even though audit logging failed.
    expect(result.cancel).toBe(true);
    expect(result.cancelReason).toContain("blocked by VeriSwarm Guard session protection");
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

    await send(hooks, "agent outbound text", { sessionKey: "conv-payload-test" });

    const body = capturedBodies[0];
    expect(body.agent_text).toBe("agent outbound text");
    expect(body.user_text).toBe("");
    expect(body.system_prompt).toBe("");
    expect(body.agent_id).toBeTruthy(); // auto-generated agentId
  });
});
