import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { VeriSwarmClient, VeriSwarmError } from "../veriswarm_client.mjs";

const BASE = "https://api.test";
const MiB = 1024 * 1024;
const PKG_VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

/** A body stream of `chunks` x 1 MiB that counts how many chunks were pulled. */
function countingStream(chunks) {
  const state = { pulled: 0, cancelled: false };
  const stream = new ReadableStream({
    pull(controller) {
      if (state.pulled >= chunks) {
        controller.close();
        return;
      }
      state.pulled += 1;
      controller.enqueue(new Uint8Array(MiB));
    },
    cancel() {
      state.cancelled = true;
    },
  });
  return { stream, state };
}

function client(opts = {}) {
  return new VeriSwarmClient({ baseUrl: BASE, apiKey: "vsk_x", ...opts });
}

async function rejection(promise) {
  return promise.then(
    () => {
      throw new Error("expected rejection");
    },
    (err) => err,
  );
}

describe("response size cap", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("aborts while streaming once the 10 MiB cap is exceeded", async () => {
    const { stream, state } = countingStream(64);
    fetch.mockResolvedValueOnce(new Response(stream, { headers: { "content-type": "application/json" } }));
    const err = await rejection(client().getPlatformStatus());
    expect(err).toBeInstanceOf(VeriSwarmError);
    expect(err.message).toMatch(/exceeded/);
    expect(err.status).toBe(200);
    expect(state.pulled).toBeLessThanOrEqual(12);
    expect(state.cancelled).toBe(true);
  });

  it("rejects an oversized Content-Length without reading the body", async () => {
    const { stream, state } = countingStream(64);
    fetch.mockResolvedValueOnce(
      new Response(stream, {
        headers: { "content-type": "application/json", "content-length": String(20 * MiB) },
      }),
    );
    const err = await rejection(client().getPlatformStatus());
    expect(err.message).toMatch(/exceeded/);
    expect(state.pulled).toBeLessThanOrEqual(1);
  });

  it("still reads a normal body", async () => {
    fetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } }),
    );
    expect(await client().getPlatformStatus()).toEqual({ ok: true });
  });
});

describe("timeoutMs validation", () => {
  it.each([0, -1, NaN, Infinity, 2 ** 31, "1000", null])("rejects %j", (timeoutMs) => {
    expect(() => client({ timeoutMs })).toThrow(/timeoutMs/);
  });

  it.each([1, 15000, 2 ** 31 - 1])("accepts %j", (timeoutMs) => {
    expect(client({ timeoutMs }).timeoutMs).toBe(timeoutMs);
  });
});

describe("localhost http escape hatch", () => {
  it.each(["http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"])("accepts %s", (baseUrl) => {
    expect(() => client({ baseUrl })).not.toThrow();
  });

  it.each(["http://[::2]:8000", "http://localhost.evil.test", "http://10.0.0.1"])("rejects %s", (baseUrl) => {
    expect(() => client({ baseUrl })).toThrow(/https/);
  });
});

describe("error bodies and status", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));

  it("parses application/problem+json error bodies and carries status", async () => {
    fetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ title: "Unprocessable", detail: "bad" }), {
        status: 422,
        headers: { "content-type": "application/problem+json" },
      }),
    );
    const err = await rejection(client().getPlatformStatus());
    expect(err).toBeInstanceOf(VeriSwarmError);
    expect(err.status).toBe(422);
    expect(err.payload).toEqual({ title: "Unprocessable", detail: "bad" });
    expect(err.message).toBe("VeriSwarm API 422");
  });

  it("keeps status when an error body claims JSON but is not", async () => {
    fetch.mockResolvedValueOnce(
      new Response("<html>bad gateway</html>", { status: 502, headers: { "content-type": "application/json" } }),
    );
    const err = await rejection(client().getPlatformStatus());
    expect(err).toBeInstanceOf(VeriSwarmError);
    expect(err.status).toBe(502);
    expect(err.payload).toBe("<html>bad gateway</html>");
  });

  it("wraps an invalid JSON success body instead of throwing a bare SyntaxError", async () => {
    fetch.mockResolvedValueOnce(
      new Response("{not json", { status: 200, headers: { "content-type": "application/json" } }),
    );
    const err = await rejection(client().getPlatformStatus());
    expect(err).toBeInstanceOf(VeriSwarmError);
    expect(err.status).toBe(200);
    expect(err.message).toMatch(/invalid JSON/);
  });

  it("parses +json success bodies", async () => {
    fetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ a: 1 }), { headers: { "content-type": "application/vnd.api+json" } }),
    );
    expect(await client().getPlatformStatus()).toEqual({ a: 1 });
  });

  it("wraps network failures with status null", async () => {
    fetch.mockRejectedValueOnce(new TypeError("fetch failed"));
    const err = await rejection(client().getPlatformStatus());
    expect(err).toBeInstanceOf(VeriSwarmError);
    expect(err.status).toBeNull();
    expect(err.code).toBe("NETWORK_ERROR");
  });

  it("reports a timeout as a VeriSwarmError", async () => {
    fetch.mockImplementationOnce(
      (_url, { signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    );
    const err = await rejection(client({ timeoutMs: 5 }).getPlatformStatus());
    expect(err).toBeInstanceOf(VeriSwarmError);
    expect(err.code).toBe("TIMEOUT");
    expect(err.status).toBeNull();
  });
});

describe("User-Agent", () => {
  it("reports the package version", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("{}", { headers: { "content-type": "application/json" } })),
    );
    await client().getPlatformStatus();
    expect(fetch.mock.calls[0][1].headers["User-Agent"]).toBe(`veriswarm-node-sdk/${PKG_VERSION}`);
  });
});
