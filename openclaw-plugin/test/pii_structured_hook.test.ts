import { describe, it, expect, vi, afterEach } from "vitest";
import { pluginEntry } from "../src/index.js";

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

describe("structured tool I/O PII tokenization", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn> | undefined;

  afterEach(() => {
    fetchSpy?.mockRestore();
  });

  it("tokenizes PII nested inside structured tool input", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      const text = String(body.text);
      if (text.includes("alice@example.com")) {
        return jsonResponse({
          tokens_created: 1,
          tokenized_text: text.replace("alice@example.com", "[VS:email_1]"),
          session_id: body.session_id || "sid-input",
          token_manifest: [],
        });
      }
      return jsonResponse({
        tokens_created: 0,
        tokenized_text: text,
        session_id: body.session_id || "sid-input",
        token_manifest: [],
      });
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await hooks["before_tool_call"]({
      name: "create_customer",
      conversation_id: "conv-structured-input",
      input: {
        customer: {
          email: "alice@example.com",
          notes: ["prefers email", "no PII here"],
        },
      },
    });

    expect(result.input.customer.email).toBe("[VS:email_1]");
    expect(result.input.customer.notes).toEqual(["prefers email", "no PII here"]);
    expect(JSON.stringify(result.input)).not.toContain("alice@example.com");
  });

  it("tokenizes PII nested inside structured tool output", async () => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      const text = String(body.text);
      if (text.includes("bob@example.com")) {
        return jsonResponse({
          tokens_created: 1,
          tokenized_text: text.replace("bob@example.com", "[VS:email_2]"),
          session_id: body.session_id || "sid-output",
          token_manifest: [],
        });
      }
      return jsonResponse({
        tokens_created: 0,
        tokenized_text: text,
        session_id: body.session_id || "sid-output",
        token_manifest: [],
      });
    });

    const { api, hooks } = makeApi();
    pluginEntry.register(api as any, BASE_CONFIG);

    const result = await hooks["after_tool_call"]({
      name: "lookup_customer",
      conversation_id: "conv-structured-output",
      output: {
        records: [
          { email: "bob@example.com", id: "cust_123" },
        ],
      },
    });

    expect(result.output.records[0].email).toBe("[VS:email_2]");
    expect(result.output.records[0].id).toBe("cust_123");
    expect(JSON.stringify(result.output)).not.toContain("bob@example.com");
  });
});
