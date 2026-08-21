import { describe, it, expect, vi, afterEach } from "vitest";
import { pluginEntry } from "../src/index.js";

function makeApi() {
  const hooks: Record<string, (e: any) => Promise<any>> = {};
  const tools: Record<string, (params: any) => Promise<any>> = {};
  const api = {
    registerTool: (def: any) => {
      tools[def.name] = def.handler;
    },
    registerHook: () => {},
    on: (name: string, handler: (e: any) => Promise<any>) => {
      hooks[name] = handler;
    },
    registerHttpRoute: () => {},
    registerService: () => {},
  };
  return { api, hooks, tools };
}

const BASE_CONFIG = {
  apiKey: "vsk_test",
  apiUrl: "https://api.test.local",
  piiEnabled: true,
  policyEnabled: false,
  injectionScan: false,
  auditEnabled: false,
  secretsDetection: false,
  sessionScan: false,
};

function jsonResponse(body: Record<string, any>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("veriswarm_rehydrate session scoping", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn> | undefined;

  afterEach(() => {
    fetchSpy?.mockRestore();
  });

  it("does not brute-force unrelated conversation sessions when no matching key is provided", async () => {
    const rehydrateCalls: any[] = [];
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      if (url.includes("/pii/tokenize")) {
        if (String(body.text).includes("Alice")) {
          return jsonResponse({
            tokens_created: 1,
            tokenized_text: "Customer [VS:alice]",
            session_id: "sid-alice",
            token_manifest: [],
          });
        }
        if (String(body.text).includes("Bob")) {
          return jsonResponse({
            tokens_created: 1,
            tokenized_text: "Customer [VS:bob]",
            session_id: "sid-bob",
            token_manifest: [],
          });
        }
      }
      if (url.includes("/pii/rehydrate")) {
        rehydrateCalls.push(body);
        return jsonResponse({
          tokens_resolved: 1,
          rehydrated_text:
            body.session_id === "sid-alice" ? "Customer Alice" : "Customer Bob",
        });
      }
      return jsonResponse({});
    });

    const { api, hooks, tools } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    await hooks["after_tool_call"]({
      name: "lookup_customer",
      output: "Customer Alice",
      conversation_id: "conv-a",
    });
    await hooks["after_tool_call"]({
      name: "lookup_customer",
      output: "Customer Bob",
      conversation_id: "conv-b",
    });

    const result = await tools["veriswarm_rehydrate"]({
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
    });

    expect(result).toBe("Customer [VS:alice]");
    expect(rehydrateCalls).toHaveLength(0);
  });

  it("rehydrates only the session for the provided conversation and tool", async () => {
    const rehydrateCalls: any[] = [];
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      if (url.includes("/pii/tokenize")) {
        return jsonResponse({
          tokens_created: 1,
          tokenized_text: "Customer [VS:alice]",
          session_id: "sid-alice",
          token_manifest: [],
        });
      }
      if (url.includes("/pii/rehydrate")) {
        rehydrateCalls.push(body);
        return jsonResponse({
          tokens_resolved: 1,
          rehydrated_text: "Customer Alice",
        });
      }
      return jsonResponse({});
    });

    const { api, hooks, tools } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    await hooks["after_tool_call"]({
      name: "lookup_customer",
      output: "Customer Alice",
      conversation_id: "conv-a",
    });

    const result = await tools["veriswarm_rehydrate"]({
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
      conversation_id: "conv-a",
    });

    expect(result).toBe("Customer Alice");
    expect(rehydrateCalls).toEqual([
      { text: "Customer [VS:alice]", session_id: "sid-alice" },
    ]);
  });

  it("preserves no-conversation deployments by using the no-conversation key only", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      if (url.includes("/pii/tokenize")) {
        return jsonResponse({
          tokens_created: 1,
          tokenized_text: "Customer [VS:alice]",
          session_id: "sid-no-conv",
          token_manifest: [],
        });
      }
      if (url.includes("/pii/rehydrate")) {
        return jsonResponse({
          tokens_resolved: 1,
          rehydrated_text: `rehydrated via ${body.session_id}`,
        });
      }
      return jsonResponse({});
    });

    const { api, hooks, tools } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    await hooks["after_tool_call"]({
      name: "lookup_customer",
      output: "Customer Alice",
    });

    const result = await tools["veriswarm_rehydrate"]({
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
    });

    expect(result).toBe("rehydrated via sid-no-conv");
  });
});
