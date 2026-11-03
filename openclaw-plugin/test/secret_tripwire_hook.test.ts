import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { pluginEntry } from "../src/index.js";

// Captures the hooks the plugin registers so we can drive them with the
// host's real before_tool_call shapes: event { toolName, params },
// ctx { sessionKey, toolName }; result { params } or { block, blockReason }.
function makeApi() {
  const hooks: Record<string, (e: any, ctx?: any) => Promise<any>> = {};
  const api = {
    registerTool: () => {},
    on: (name: string, handler: (e: any, ctx?: any) => Promise<any>) => {
      hooks[name] = handler;
    },
  };
  return { api, hooks };
}

function callTool(hooks: Record<string, (e: any, ctx?: any) => Promise<any>>, toolName: string, params: any) {
  return hooks["before_tool_call"]({ toolName, params }, { toolName, sessionKey: "session-1" });
}

const GH_PAT = "ghp_" + "A".repeat(36);

const BASE_CONFIG = {
  apiKey: "vsk_test",
  apiUrl: "https://api.test.local",
  secretsDetection: true,
  piiEnabled: false,
  policyEnabled: false,
  auditEnabled: false,
  injectionScan: false,
};

describe("before_tool_call secret tripwire", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // Simulate offline: every outbound request rejects.
    fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error("offline"));
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("fails closed with offline redaction when the API is unreachable", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const res = await callTool(hooks, "http_post", { body: `token=${GH_PAT}` });

    expect(res.params.body).toContain("[VS:");
    expect(res.params.body).toContain(":offline]");
    expect(res.params.body).not.toContain(GH_PAT);
  });

  it("fails closed for secrets nested in structured tool input", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const params = {
      url: "https://example.test",
      headers: {
        Authorization: `Bearer ${GH_PAT}`,
      },
      tags: ["x", `t=${GH_PAT}`],
    };
    const res = await callTool(hooks, "http_post", params);

    expect(res.params.url).toBe("https://example.test");
    expect(res.params.headers.Authorization).toContain("[VS:");
    expect(res.params.headers.Authorization).toContain(":offline]");
    expect(JSON.stringify(res.params)).not.toContain(GH_PAT);
    // The host's params object is not mutated.
    expect(params.headers.Authorization).toContain(GH_PAT);
  });

  it("passes clean input through untouched", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const res = await callTool(hooks, "http_post", { body: "just a normal message with no secrets" });

    expect(res).toBeUndefined();
  });

  it("does nothing when secretsDetection is off", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, secretsDetection: false });

    const res = await callTool(hooks, "http_post", { body: `token=${GH_PAT}` });

    // Tripwire disabled and PII disabled → params untouched.
    expect(res).toBeUndefined();
  });
});

describe("before_tool_call secret tripwire — unnamed tool", () => {
  afterEach(() => vi.restoreAllMocks());

  it("still redacts when the host omits toolName and no policy list is set", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const res = await hooks["before_tool_call"]({ params: { body: `token=${GH_PAT}` } }, {});

    expect(res.params.body).not.toContain(GH_PAT);
  });
});

describe("before_tool_call secret tripwire — keys and shared references", () => {
  afterEach(() => vi.restoreAllMocks());

  it("redacts secrets used as object keys", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const res = await callTool(hooks, "http_post", { headers: { [GH_PAT]: "x" } });

    expect(JSON.stringify(res.params)).not.toContain(GH_PAT);
  });

  it("redacts every occurrence of an object referenced twice", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);
    const shared = { token: GH_PAT };

    const res = await callTool(hooks, "http_post", { first: shared, second: shared });

    expect(JSON.stringify(res.params)).not.toContain(GH_PAT);
  });

  it("terminates on cyclic params", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);
    const cyclic: Record<string, unknown> = { token: GH_PAT };
    cyclic.self = cyclic;

    const res = await callTool(hooks, "http_post", cyclic);

    expect(res.params.token).not.toContain(GH_PAT);
  });
});
