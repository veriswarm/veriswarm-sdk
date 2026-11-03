/**
 * before_tool_call secret tripwire.
 *
 * Hooks are driven with the host's real shapes: event { toolName, params },
 * ctx { toolName, sessionKey }; results { block, blockReason } / { params }.
 * A secret in params BLOCKS the call: a params rewrite is not guaranteed to
 * reach the tool (another plugin's approval request makes the host use the
 * original params), while a block always is.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { pluginEntry } from "../src/index.js";

type Hook = (e: any, ctx?: any) => Promise<any>;

function makeApi() {
  const hooks: Record<string, Hook> = {};
  const api = {
    registerTool: () => {},
    on: (name: string, handler: Hook) => {
      hooks[name] = handler;
    },
  };
  return { api, hooks };
}

function callTool(hooks: Record<string, Hook>, toolName: string | undefined, params: any) {
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

function expectSecretBlock(res: any) {
  expect(res.block).toBe(true);
  expect(res.blockReason).toContain("contain a credential");
  expect(res.blockReason).not.toContain(GH_PAT);
  expect(res.params).toBeUndefined();
}

describe("before_tool_call secret tripwire", () => {
  afterEach(() => vi.restoreAllMocks());

  it("blocks a secret in a top-level value, without any API call", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);
    fetchSpy.mockClear();

    expectSecretBlock(await callTool(hooks, "http_post", { body: `token=${GH_PAT}` }));
    const apiCalls = fetchSpy.mock.calls.filter(([url]) => !String(url).endsWith("/secret-rules"));
    expect(apiCalls).toEqual([]);
  });

  it("blocks secrets nested in structured params", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    expectSecretBlock(
      await callTool(hooks, "http_post", {
        url: "https://example.test",
        headers: { Authorization: `Bearer ${GH_PAT}` },
        tags: ["x"],
      })
    );
    expectSecretBlock(await callTool(hooks, "http_post", { tags: ["x", `t=${GH_PAT}`] }));
  });

  it("blocks a secret used as a key, top-level or nested", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    expectSecretBlock(await callTool(hooks, "http_post", { [GH_PAT]: "x" }));
    expectSecretBlock(await callTool(hooks, "http_post", { headers: { [GH_PAT]: "x" } }));
  });

  it("blocks a secret in an object referenced twice, and terminates on cycles", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);
    const shared = { note: "fine" };
    const cyclic: Record<string, unknown> = { a: shared, b: shared };
    cyclic.self = cyclic;
    (shared as any).token = GH_PAT;

    expectSecretBlock(await callTool(hooks, "http_post", cyclic));
  });

  it("blocks a secret beside an own __proto__ key", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const params = JSON.parse(`{"__proto__":{"x":1},"a":"${GH_PAT}"}`);
    expectSecretBlock(await callTool(hooks, "http_post", params));
  });

  it("scans a call the host did not name", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    expectSecretBlock(await hooks["before_tool_call"]({ params: { body: GH_PAT } }, {}));
  });

  it("passes clean params through untouched", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    expect(await callTool(hooks, "http_post", { body: "no secrets here" })).toBeUndefined();
  });

  it("does nothing when secretsDetection is off", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, secretsDetection: false });

    expect(await callTool(hooks, "http_post", { body: `token=${GH_PAT}` })).toBeUndefined();
  });
});
