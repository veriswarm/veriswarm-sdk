/**
 * before_tool_call policy + PII params, and plugin state across re-register.
 * Hooks are driven with the host's real shapes: event { toolName, params },
 * ctx { toolName, sessionKey }; results { block, blockReason } / { params }.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { pluginEntry, MAX_PII_SESSIONS } from "../src/index.js";

type Hook = (e: any, ctx?: any) => any;

function makeApi() {
  const hooks: Record<string, Hook> = {};
  const tools: Record<string, any> = {};
  const api = {
    registerTool: (tool: any, opts?: { name?: string }) => {
      const resolved = typeof tool === "function" ? tool({ sessionKey: "session-1" }) : tool;
      tools[opts?.name ?? resolved.name] = resolved;
    },
    on: (name: string, handler: Hook) => {
      hooks[name] = handler;
    },
  };
  return { api, hooks, tools };
}

const BASE_CONFIG = {
  apiKey: "vsk_test",
  apiUrl: "https://api.test.local",
  piiEnabled: false,
  policyEnabled: true,
  injectionScan: false,
  auditEnabled: false,
  secretsDetection: false,
  sessionScan: false,
};

const json = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

function callTool(hooks: Record<string, Hook>, toolName: string | undefined, params: any = {}) {
  return hooks["before_tool_call"]({ toolName, params }, { toolName, sessionKey: "session-1" });
}

async function guardStatus(tools: Record<string, any>) {
  const result = await tools["veriswarm_guard_status"].execute("call", {});
  return JSON.parse(result.content[0].text);
}

describe("before_tool_call policy", () => {
  afterEach(() => vi.restoreAllMocks());

  it("blocks a blocklisted tool with the host's { block, blockReason } shape", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, blockedTools: ["exec"] });

    const res = await callTool(hooks, "exec", { command: "ls" });

    expect(res).toEqual({
      block: true,
      blockReason: "[VeriSwarm Guard] Tool 'exec' is blocked by policy.",
    });
  });

  it("allowlist permits listed tools and blocks the rest", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, allowedTools: ["read"] });

    expect(await callTool(hooks, "read")).toBeUndefined();
    expect(await callTool(hooks, "write")).toEqual({
      block: true,
      blockReason: "[VeriSwarm Guard] Tool 'write' is not in the allowlist.",
    });
  });

  it("refuses a call the host did not name when a policy list is configured", async () => {
    const { api, hooks } = makeApi();
    // Even an allowlist that happens to contain the old placeholder name
    // must not let an unidentified call through.
    pluginEntry.register(api as any, { ...BASE_CONFIG, allowedTools: ["unknown"] });

    const res = await hooks["before_tool_call"]({ params: {} }, { sessionKey: "session-1" });

    expect(res.block).toBe(true);
    expect(res.blockReason).toContain("did not identify the tool");
  });

  it("does not block an unnamed call when no policy list is configured", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    expect(await hooks["before_tool_call"]({ params: {} }, {})).toBeUndefined();
  });

  it("returns the block without waiting on the audit request", async () => {
    // The audit endpoint never answers; an awaited audit would hang the block.
    vi.spyOn(globalThis, "fetch").mockImplementation(() => new Promise<Response>(() => {}));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, auditEnabled: true, blockedTools: ["exec"] });

    const res = await callTool(hooks, "exec");

    expect(res.block).toBe(true);
  }, 1_000);
});

describe("before_tool_call PII tokenization of params", () => {
  afterEach(() => vi.restoreAllMocks());

  it("tokenizes PII in nested string params and leaves other values intact", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const text = JSON.parse(String(init?.body)).text as string;
      return text.includes("alice@example.com")
        ? json({ tokenized_text: text.replace("alice@example.com", "[VS:EMAIL:1]"), session_id: "pii-1", tokens_created: 1 })
        : json({ tokenized_text: text, session_id: "", tokens_created: 0 });
    });
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });

    const res = await callTool(hooks, "send_email", {
      to: "alice@example.com",
      meta: { retries: 3, cc: ["alice@example.com"] },
    });

    expect(res.params).toEqual({
      to: "[VS:EMAIL:1]",
      meta: { retries: 3, cc: ["[VS:EMAIL:1]"] },
    });
  });

  it("blocks the call (fail closed) when tokenization errors", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("down"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });

    expect(await callTool(hooks, "send_email", { to: "alice@example.com" })).toEqual({
      block: true,
      blockReason: "[VeriSwarm Guard] Tool call blocked: PII protection is unavailable.",
    });
  });

  it("blocks the call (fail closed) on a malformed tokenization response", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockResolvedValue(json({ unexpected: true }));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });

    expect((await callTool(hooks, "send_email", { to: "alice@example.com" })).block).toBe(true);
  });

  it("passes params unchanged on tokenization errors when failOpen is set", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("down"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true, failOpen: true });

    expect(await callTool(hooks, "send_email", { to: "alice@example.com" })).toBeUndefined();
  });

  it("tokenizes every occurrence of a value referenced twice", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const text = JSON.parse(String(init?.body)).text as string;
      return json({ tokenized_text: text.replace("alice@example.com", "[VS:EMAIL:1]"), session_id: "pii-1", tokens_created: text.includes("@") ? 1 : 0 });
    });
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });
    const shared = { email: "alice@example.com" };

    const res = await callTool(hooks, "send_email", { a: shared, b: shared });

    expect(JSON.stringify(res.params)).not.toContain("alice@example.com");
  });
});

describe("message_sending PII fail-closed", () => {
  afterEach(() => vi.restoreAllMocks());

  const sendMessage = (hooks: Record<string, Hook>) =>
    hooks["message_sending"]({ to: "u", content: "mail alice@example.com" }, { channelId: "c", sessionKey: "s" });

  it("cancels delivery when outbound tokenization errors", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("down"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });

    expect(await sendMessage(hooks)).toEqual({
      cancel: true,
      cancelReason: "Message held by VeriSwarm Guard: PII protection is unavailable.",
    });
  });

  it("sends unmodified when outbound tokenization errors and failOpen is set", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("down"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true, failOpen: true });

    expect(await sendMessage(hooks)).toBeUndefined();
  });
});

describe("tool name normalization", () => {
  afterEach(() => vi.restoreAllMocks());

  it("matches config entries the way the host normalizes tool names", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, blockedTools: [" Bash ", "APPLY-PATCH"] });

    // The host hands hooks normalized names: bash -> exec, apply-patch -> apply_patch.
    expect((await callTool(hooks, "exec")).block).toBe(true);
    expect((await callTool(hooks, "apply_patch")).block).toBe(true);
    expect((await callTool(hooks, "Exec")).block).toBe(true);
    expect(await callTool(hooks, "read")).toBeUndefined();
  });

  it("maps the Codex-native exec_command entry to the host's exec", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, blockedTools: ["exec_command"] });

    expect((await callTool(hooks, "exec")).block).toBe(true);
  });

  it("normalizes allowlist entries too", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, allowedTools: ["Bash"] });

    expect(await callTool(hooks, "exec")).toBeUndefined();
    expect((await callTool(hooks, "write")).block).toBe(true);
  });
});

describe("plugin state across re-register", () => {
  afterEach(() => vi.restoreAllMocks());

  it("clears blockedTools and allowedTools when the new config omits them", async () => {
    const first = makeApi();
    pluginEntry.register(first.api as any, { ...BASE_CONFIG, blockedTools: ["exec"], allowedTools: ["read"] });

    const second = makeApi();
    pluginEntry.register(second.api as any, { ...BASE_CONFIG, blockedTools: [], allowedTools: [] });

    expect(await callTool(second.hooks, "exec")).toBeUndefined();
    const status = await guardStatus(second.tools);
    expect(status.policy).toEqual({ blocked_tools: null, allowed_tools: null });
  });

  it("drops a previous client when re-registered without an apiKey", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(json({}));
    vi.spyOn(console, "warn").mockImplementation(() => {});
    pluginEntry.register(makeApi().api as any, { ...BASE_CONFIG, blockedTools: ["exec"] });
    const first = makeApi();
    pluginEntry.register(first.api as any, { ...BASE_CONFIG, blockedTools: ["exec"] });

    pluginEntry.register(makeApi().api as any, {});
    fetchSpy.mockClear();

    // Hooks from the earlier registration must see the passive state.
    expect(await callTool(first.hooks, "exec")).toBeUndefined();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("keeps PII sessions for the same tenant and drops them for a different one", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      json({ tokenized_text: "[VS:EMAIL:1]", session_id: "pii-1", tokens_created: 1 })
    );
    const config = { ...BASE_CONFIG, piiEnabled: true, apiKey: "vsk_tenant_a" };
    const first = makeApi();
    pluginEntry.register(first.api as any, config);
    await callTool(first.hooks, "send_email", { to: "alice@example.com" });
    expect((await guardStatus(first.tools)).active_pii_sessions).toBe(1);

    const sameTenant = makeApi();
    pluginEntry.register(sameTenant.api as any, { ...config });
    expect((await guardStatus(sameTenant.tools)).active_pii_sessions).toBe(1);

    const otherTenant = makeApi();
    pluginEntry.register(otherTenant.api as any, { ...config, apiKey: "vsk_tenant_b" });
    expect((await guardStatus(otherTenant.tools)).active_pii_sessions).toBe(0);
  });

  it("caps PII sessions at MAX_PII_SESSIONS", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      json({ tokenized_text: "[VS:EMAIL:1]", session_id: "pii", tokens_created: 1 })
    );
    const { api, hooks, tools } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true, apiKey: "vsk_cap" });

    const calls: Promise<unknown>[] = [];
    for (let i = 0; i < MAX_PII_SESSIONS + 5; i++) {
      calls.push(
        hooks["before_tool_call"](
          { toolName: "send_email", params: { to: "alice@example.com" } },
          { toolName: "send_email", sessionKey: `conv-${i}` }
        )
      );
    }
    await Promise.all(calls);

    expect((await guardStatus(tools)).active_pii_sessions).toBe(MAX_PII_SESSIONS);
  }, 30_000);
});

describe("PII params rewrite — key safety", () => {
  afterEach(() => vi.restoreAllMocks());

  it("preserves an own __proto__ key in the rewritten params", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const text = JSON.parse(String(init?.body)).text as string;
      return json({ tokenized_text: text.replace("alice@example.com", "[VS:EMAIL:1]"), session_id: "p", tokens_created: text.includes("@") ? 1 : 0 });
    });
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });

    const res = await callTool(hooks, "send", JSON.parse('{"__proto__":{"to":"alice@example.com"},"body":"hello"}'));

    expect(Object.getPrototypeOf(res.params)).toBe(Object.prototype);
    expect(Object.getOwnPropertyDescriptor(res.params, "__proto__")?.value).toEqual({ to: "[VS:EMAIL:1]" });
    expect(Object.keys(res.params)).toEqual(["__proto__", "body"]);
  });
});

describe("unexpected handler errors", () => {
  afterEach(() => vi.restoreAllMocks());

  const throwingParams = () => {
    const params: Record<string, unknown> = {};
    Object.defineProperty(params, "boom", { enumerable: true, get: () => { throw new Error("bad getter"); } });
    return params;
  };
  const throwingMessageEvent = () => {
    const event: Record<string, unknown> = { to: "u" };
    Object.defineProperty(event, "content", { get: () => { throw new Error("bad getter"); } });
    return event;
  };

  it("before_tool_call fails closed with a block", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });

    expect(await callTool(hooks, "send", throwingParams())).toEqual({
      block: true,
      blockReason: "[VeriSwarm Guard] Tool call blocked: Guard could not check this call.",
    });
  });

  it("message_sending fails closed with a cancel", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    expect(await hooks["message_sending"](throwingMessageEvent(), { channelId: "c" })).toEqual({
      cancel: true,
      cancelReason: "Message held by VeriSwarm Guard: Guard could not check this message.",
    });
  });

  it("tool_result_persist fails closed by withholding the result", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true });
    const message: Record<string, unknown> = { role: "toolResult", toolCallId: "c1", toolName: "t" };
    Object.defineProperty(message, "content", { get: () => { throw new Error("bad getter"); } });

    const out = hooks["tool_result_persist"]({ toolName: "t", toolCallId: "c1", message }, {});

    expect(out.message.content).toEqual([
      { type: "text", text: "[VeriSwarm Guard: tool result withheld — Guard could not check it.]" },
    ]);
    expect(out.message.toolCallId).toBe("c1");
  });

  it("passes through on unexpected errors when failOpen is set", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, piiEnabled: true, failOpen: true });

    expect(await callTool(hooks, "send", throwingParams())).toBeUndefined();
    expect(await hooks["message_sending"](throwingMessageEvent(), { channelId: "c" })).toBeUndefined();
  });

  it("observation hooks swallow and log", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);
    const ctx: Record<string, unknown> = {};
    Object.defineProperty(ctx, "channelId", { get: () => { throw new Error("bad ctx"); } });

    expect(hooks["message_received"]({ content: "hi" }, ctx)).toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("message_received handler failed"));
  });
});

describe("unconfigured plugin", () => {
  afterEach(() => vi.restoreAllMocks());

  it("passes through and warns once when the client is gone", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    const first = makeApi();
    pluginEntry.register(first.api as any, { ...BASE_CONFIG, blockedTools: ["exec"] });
    pluginEntry.register(makeApi().api as any, {}); // re-registered without an apiKey
    warn.mockClear();

    expect(await callTool(first.hooks, "exec")).toBeUndefined();
    expect(await callTool(first.hooks, "exec")).toBeUndefined();
    expect(warn.mock.calls.filter(([m]) => String(m).includes("Not configured"))).toHaveLength(1);
  });
});
