/**
 * Secrets never reach the VeriSwarm API.
 *
 * Driven through the REAL OpenClaw host (loader, before_tool_call wrapper,
 * hook runner) with `secretsDetection` at its default (off). The secret
 * tripwire is always built, and every string is redacted locally before
 * PII tokenization or Session Sentry sees it: the raw secret must not
 * appear in any outgoing request body.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { FIXTURES, loadPluginInHost, type LoadedHost } from "./helpers/openclaw-host.js";

const GH_PAT = "ghp_" + "b".repeat(36);
const REDACTED = "[VS:GITHUB_TOKEN:offline]";
const EMAIL = "bob@example.com";

const PLUGIN_CONFIG = {
  apiKey: "vsk_test",
  apiUrl: "https://api.test.local",
  agentId: "agt_test",
  piiEnabled: true,
  policyEnabled: false,
  injectionScan: false,
  auditEnabled: false,
  sessionScan: true,
  // secretsDetection omitted: default off.
};

let tokenizeMode: "ok" | "error" = "ok";
const calls: { url: string; body: string }[] = [];

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function fakeVeriSwarmApi(input: unknown, init?: RequestInit): Response {
  const url = String(input);
  const raw = init?.body ? String(init.body) : "";
  calls.push({ url, body: raw });
  const body = raw ? JSON.parse(raw) : {};
  if (url.endsWith("/v1/suite/guard/pii/tokenize")) {
    if (tokenizeMode === "error") return new Response("down", { status: 502 });
    const text = String(body.text);
    if (text.includes(EMAIL)) {
      return json({
        tokenized_text: text.replace(EMAIL, "[VS:EMAIL:1]"),
        session_id: "pii-session-A",
        tokens_created: 1,
        token_manifest: [],
      });
    }
    return json({ tokenized_text: text, session_id: "", tokens_created: 0, token_manifest: [] });
  }
  if (url.endsWith("/v1/suite/guard/scan-session")) {
    return json({ blocked: false, enabled: true, session_score: 0, highest_severity: "none" });
  }
  if (url.endsWith("/v1/suite/guard/secret-rules")) {
    return new Response("unavailable", { status: 503 });
  }
  return json({});
}

function fakeTool(name: string) {
  const received: any[] = [];
  return {
    received,
    tool: {
      name,
      description: `fake ${name}`,
      parameters: { type: "object", properties: {} },
      async execute(_id: string, params: any) {
        received.push(params);
        return { content: [{ type: "text", text: "ran" }] };
      },
    },
  };
}

const textOf = (result: any): string =>
  (result?.content ?? []).filter((b: any) => b?.type === "text").map((b: any) => b.text).join("\n");

function expectNoSecretSent() {
  for (const call of calls) expect(call.body).not.toContain(GH_PAT);
}

let host: LoadedHost;

beforeAll(async () => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => fakeVeriSwarmApi(input, init));
  host = await loadPluginInHost(PLUGIN_CONFIG, [
    { id: "approval-requester", dir: `${FIXTURES}approval-requester` },
  ]);
});

afterAll(() => {
  vi.restoreAllMocks();
});

beforeEach(() => {
  calls.length = 0;
  tokenizeMode = "ok";
});

describe("secrets are redacted locally before any API call (secretsDetection off)", () => {
  it("rewrites tool params with the secret redacted and PII tokenized", async () => {
    const { tool, received } = fakeTool("send_note");
    const wrapped = host.wrapWithBeforeToolCall(tool, { sessionKey: "session-A", agentId: "a" });

    await wrapped.execute("call-1", {
      body: `contact ${EMAIL} with token=${GH_PAT}`,
      headers: { Authorization: `Bearer ${GH_PAT}` },
    });

    expect(received[0]).toEqual({
      body: `contact [VS:EMAIL:1] with token=${REDACTED}`,
      headers: { Authorization: `Bearer ${REDACTED}` },
    });
    expect(calls.some((c) => c.url.endsWith("/pii/tokenize"))).toBe(true);
    expectNoSecretSent();
  });

  it("rewrites a secret-only call without tokenizing it", async () => {
    const { tool, received } = fakeTool("http_post");
    await host
      .wrapWithBeforeToolCall(tool, { sessionKey: "session-A", agentId: "a" })
      .execute("call-2", { body: GH_PAT });

    expect(received[0]).toEqual({ body: REDACTED });
    expectNoSecretSent();
  });

  it("blocks a call whose top-level key is a secret (a key rewrite is not guaranteed)", async () => {
    const { tool, received } = fakeTool("http_post");
    const result = await host
      .wrapWithBeforeToolCall(tool, { sessionKey: "session-A", agentId: "a" })
      .execute("call-3", { url: "https://example.com", [GH_PAT]: "x" });

    expect(received).toEqual([]);
    expect(result.details?.status).toBe("blocked");
    expect(textOf(result)).not.toContain(GH_PAT);
    expectNoSecretSent();
  });

  it("still blocks when PII tokenization fails, without sending the secret", async () => {
    tokenizeMode = "error";
    const { tool, received } = fakeTool("send_note");
    const result = await host
      .wrapWithBeforeToolCall(tool, { sessionKey: "session-A", agentId: "a" })
      .execute("call-4", { body: `token=${GH_PAT} and more text` });

    expect(received).toEqual([]);
    expect(textOf(result)).toContain("PII protection is unavailable");
    expectNoSecretSent();
  });

  it("never sends the secret even when another plugin's approval drops the rewrite", async () => {
    const decision = await host.hookRunner.runBeforeToolCall(
      { toolName: "deploy", params: { note: `token=${GH_PAT} for ${EMAIL}` } },
      { toolName: "deploy", sessionKey: "session-A" }
    );

    expect(decision?.requireApproval).toBeDefined();
    expectNoSecretSent();
  });

  it("redacts secrets in tool results via tool_result_persist, with no API call", () => {
    const message = {
      role: "toolResult",
      toolCallId: "call-tr",
      toolName: "db_query",
      content: [{ type: "text", text: `row key=${GH_PAT}` }],
      details: { [GH_PAT]: { token: GH_PAT } },
      isError: false,
      timestamp: 0,
    };

    const out = host.hookRunner.runToolResultPersist(
      { toolName: "db_query", toolCallId: "call-tr", message },
      { sessionKey: "session-A", toolName: "db_query", toolCallId: "call-tr" }
    );

    expect(textOf(out.message)).toBe(`row key=${REDACTED}`);
    expect(JSON.stringify(out.message)).not.toContain(GH_PAT);
    expect(calls).toEqual([]);
  });

  it("redacts a secret in outbound message content before Sentry and tokenize", async () => {
    const result = await host.hookRunner.runMessageSending(
      { to: "user-1", content: `your key is ${GH_PAT}, mail ${EMAIL}` },
      { channelId: "telegram", sessionKey: "session-A" }
    );

    expect(result?.content).toBe(`your key is ${REDACTED}, mail [VS:EMAIL:1]`);
    const sentry = calls.find((c) => c.url.endsWith("/scan-session"));
    expect(JSON.parse(sentry!.body).agent_text).toBe(`your key is ${REDACTED}, mail ${EMAIL}`);
    expect(calls.some((c) => c.url.endsWith("/pii/tokenize"))).toBe(true);
    expectNoSecretSent();
  });

  it("delivers the locally redacted message when there is no PII", async () => {
    const result = await host.hookRunner.runMessageSending(
      { to: "user-1", content: `your key is ${GH_PAT}` },
      { channelId: "telegram", sessionKey: "session-A" }
    );

    expect(result?.content).toBe(`your key is ${REDACTED}`);
    expectNoSecretSent();
  });

  it("cancels (fail closed) when tokenize fails, without sending the secret", async () => {
    tokenizeMode = "error";
    const result = await host.hookRunner.runMessageSending(
      { to: "user-1", content: `your key is ${GH_PAT}` },
      { channelId: "telegram", sessionKey: "session-A" }
    );

    expect(result?.cancel).toBe(true);
    expectNoSecretSent();
  });
});
