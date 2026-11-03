/**
 * If the vendored secret rules cannot load, the plugin fails closed: tool
 * calls are blocked and outbound messages held, with no API call made for
 * the content.
 */
import { describe, it, expect, vi, afterEach } from "vitest";

vi.mock("../src/secret_tripwire.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/secret_tripwire.js")>();
  return {
    ...original,
    loadVendoredManifest: () => {
      throw new Error("manifest missing");
    },
  };
});

const { pluginEntry } = await import("../src/index.js");

type Hook = (e: any, ctx?: any) => Promise<any>;

function register(config: Record<string, unknown>) {
  const hooks: Record<string, Hook> = {};
  const api = {
    registerTool: () => {},
    on: (name: string, handler: Hook) => {
      hooks[name] = handler;
    },
  };
  pluginEntry.register(api as any, config);
  return hooks;
}

const CONFIG = {
  apiKey: "vsk_test",
  apiUrl: "https://api.test.local",
  piiEnabled: true,
  policyEnabled: false,
  auditEnabled: false,
  injectionScan: false,
  sessionScan: true,
  failOpen: true, // even with failOpen, a missing tripwire blocks
};

describe("secret rules unavailable", () => {
  afterEach(() => vi.restoreAllMocks());

  it("blocks tool calls and holds messages without sending content", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const hooks = register(CONFIG);

    const tool = await hooks["before_tool_call"](
      { toolName: "http_post", params: { body: "clean text" } },
      { toolName: "http_post", sessionKey: "s-1" }
    );
    expect(tool.block).toBe(true);
    expect(tool.blockReason).toContain("secret rules could not be loaded");

    const sent = await hooks["message_sending"](
      { to: "u", content: "clean text" },
      { channelId: "test", sessionKey: "s-1" }
    );
    expect(sent.cancel).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
