import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { pluginEntry } from "../src/index.js";

// Captures the hooks the plugin registers so we can drive them directly.
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

    const res = await hooks["before_tool_call"]({
      name: "http_post",
      input: `token=${GH_PAT}`,
    });

    expect(res.input).toContain("[VS:");
    expect(res.input).toContain(":offline]");
    expect(res.input).not.toContain(GH_PAT);
  });

  it("fails closed for secrets nested in structured tool input", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const res = await hooks["before_tool_call"]({
      name: "http_post",
      input: {
        url: "https://example.test",
        headers: {
          Authorization: `Bearer ${GH_PAT}`,
        },
      },
    });

    expect(res.input.headers.Authorization).toContain("[VS:");
    expect(res.input.headers.Authorization).toContain(":offline]");
    expect(JSON.stringify(res.input)).not.toContain(GH_PAT);
  });

  it("passes clean input through untouched", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const res = await hooks["before_tool_call"]({
      name: "http_post",
      input: "just a normal message with no secrets",
    });

    expect(res).toEqual({});
  });

  it("does nothing when secretsDetection is off", async () => {
    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, { ...BASE_CONFIG, secretsDetection: false });

    const res = await hooks["before_tool_call"]({
      name: "http_post",
      input: `token=${GH_PAT}`,
    });

    // Tripwire disabled and PII disabled → input untouched.
    expect(res).toEqual({});
  });
});
