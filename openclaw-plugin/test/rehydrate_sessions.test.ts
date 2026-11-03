/**
 * veriswarm_rehydrate session scoping.
 *
 * The tool is registered as a host tool factory: the host calls it with the
 * run's tool context ({ sessionKey, sessionId, ... }) and the returned tool's
 * execute(toolCallId, params) may only rehydrate that conversation's PII.
 * PII sessions are created the way the host drives them: before_tool_call
 * with event { toolName, params } and ctx { sessionKey }.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { pluginEntry } from "../src/index.js";

type Hook = (e: any, ctx?: any) => Promise<any>;

function makeApi() {
  const hooks: Record<string, Hook> = {};
  const factories: Record<string, (ctx: any) => any> = {};
  const api = {
    registerTool: (tool: any, opts?: { name?: string }) => {
      const name = opts?.name ?? tool.name;
      factories[name] = typeof tool === "function" ? tool : () => tool;
    },
    on: (name: string, handler: Hook) => {
      hooks[name] = handler;
    },
  };
  // Resolve a tool the way the host does for a given run context.
  const toolFor = (name: string, ctx: Record<string, unknown> = {}) => factories[name](ctx);
  return { api, hooks, toolFor };
}

let tenant = 0;
// A distinct apiKey per test gives each test its own PII session state.
function config() {
  tenant += 1;
  return {
    apiKey: `vsk_test_${tenant}`,
    apiUrl: "https://api.test.local",
    piiEnabled: true,
    policyEnabled: false,
    injectionScan: false,
    auditEnabled: false,
    secretsDetection: false,
    sessionScan: false,
  };
}

function jsonResponse(body: Record<string, any>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const rehydrateCalls: any[] = [];

// Tokenizes "Alice"/"Bob" into per-person sessions; rehydrate echoes the session.
function mockApi() {
  rehydrateCalls.length = 0;
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (url.includes("/pii/tokenize")) {
      for (const person of ["Alice", "Bob"]) {
        if (String(body.text).includes(person)) {
          return jsonResponse({
            tokens_created: 1,
            tokenized_text: `Customer [VS:${person.toLowerCase()}]`,
            session_id: `sid-${person.toLowerCase()}`,
            token_manifest: [],
          });
        }
      }
      return jsonResponse({ tokens_created: 0, tokenized_text: body.text, session_id: "" });
    }
    if (url.includes("/pii/rehydrate")) {
      rehydrateCalls.push(body);
      return jsonResponse({ tokens_resolved: 1, rehydrated_text: `rehydrated via ${body.session_id}` });
    }
    return jsonResponse({});
  });
}

function lookupCustomer(hooks: Record<string, Hook>, name: string, ctx: Record<string, unknown>) {
  return hooks["before_tool_call"](
    { toolName: "lookup_customer", params: { query: `Customer ${name}` } },
    { toolName: "lookup_customer", ...ctx }
  );
}

const text = (result: any) => result.content[0].text;

describe("veriswarm_rehydrate session scoping", () => {
  afterEach(() => vi.restoreAllMocks());

  it("rehydrates the calling conversation's session", async () => {
    mockApi();
    const { api, hooks, toolFor } = makeApi();
    pluginEntry.register(api as any, config());

    await lookupCustomer(hooks, "Alice", { sessionKey: "conv-a" });
    const result = await toolFor("veriswarm_rehydrate", { sessionKey: "conv-a" }).execute("call-1", {
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
    });

    expect(text(result)).toBe("rehydrated via sid-alice");
    expect(rehydrateCalls).toEqual([{ text: "Customer [VS:alice]", session_id: "sid-alice" }]);
  });

  it("ignores a model-supplied conversation_id naming another conversation", async () => {
    mockApi();
    const { api, hooks, toolFor } = makeApi();
    pluginEntry.register(api as any, config());

    await lookupCustomer(hooks, "Alice", { sessionKey: "conv-a" });
    await lookupCustomer(hooks, "Bob", { sessionKey: "conv-b" });

    // Conversation B asks for conversation A's tokens by name.
    const result = await toolFor("veriswarm_rehydrate", { sessionKey: "conv-b" }).execute("call-2", {
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
      conversation_id: "conv-a",
    });

    expect(rehydrateCalls).toEqual([{ text: "Customer [VS:alice]", session_id: "sid-bob" }]);
    expect(text(result)).toBe("rehydrated via sid-bob");
  });

  it("returns the text unchanged when the calling conversation has no session", async () => {
    mockApi();
    const { api, hooks, toolFor } = makeApi();
    pluginEntry.register(api as any, config());

    await lookupCustomer(hooks, "Alice", { sessionKey: "conv-a" });
    const result = await toolFor("veriswarm_rehydrate", { sessionKey: "conv-c" }).execute("call-3", {
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
      conversation_id: "conv-a",
    });

    expect(text(result)).toBe("Customer [VS:alice]");
    expect(rehydrateCalls).toHaveLength(0);
  });

  it("keys hooks and the tool on the same host ctx field (sessionId fallback)", async () => {
    mockApi();
    const { api, hooks, toolFor } = makeApi();
    pluginEntry.register(api as any, config());

    await lookupCustomer(hooks, "Alice", { sessionId: "uuid-a" });
    const result = await toolFor("veriswarm_rehydrate", { sessionId: "uuid-a" }).execute("call-4", {
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
    });

    expect(text(result)).toBe("rehydrated via sid-alice");
  });

  it("preserves no-conversation deployments by using the no-conversation key only", async () => {
    mockApi();
    const { api, hooks, toolFor } = makeApi();
    pluginEntry.register(api as any, config());

    await lookupCustomer(hooks, "Alice", {});
    const result = await toolFor("veriswarm_rehydrate", {}).execute("call-5", {
      text: "Customer [VS:alice]",
      tool_name: "lookup_customer",
    });

    expect(text(result)).toBe("rehydrated via sid-alice");
  });
});
