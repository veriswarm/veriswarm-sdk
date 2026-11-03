import { describe, it, expect, vi } from "vitest";
import { SecretTripwire, ensureTripwire, loadVendoredManifest } from "../secret_tripwire.mjs";
import { VeriSwarmClient } from "../veriswarm_client.mjs";

const GH = "ghp_" + "A".repeat(36);
const MANIFEST = {
  version: "sha256:test",
  rules: [
    {
      name: "github_pat",
      entity_type: "GITHUB_TOKEN",
      prefix_pattern: "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b",
    },
  ],
};

describe("node SecretTripwire", () => {
  it("scans for prefix secrets", () => {
    const tw = new SecretTripwire(MANIFEST);
    expect(tw.scan(`x ${GH} y`)[0].entityType).toBe("GITHUB_TOKEN");
  });

  it("redacts offline fail-closed", () => {
    const tw = new SecretTripwire(MANIFEST);
    expect(tw.redactOffline(GH)).toBe("[VS:GITHUB_TOKEN:offline]");
  });

  it("loads the vendored manifest", () => {
    const m = loadVendoredManifest();
    expect(m.version).toMatch(/^sha256:/);
    expect(m.rules.some((r) => r.name === "github_pat")).toBe(true);
  });

  it("falls back to vendored rules when fetched manifest is empty", async () => {
    const tw = await ensureTripwire({
      fetchManifest: async () => ({ version: "sha256:empty", rules: [] }),
    });
    expect(tw.scan(GH).length).toBeGreaterThan(0);
    expect(tw.version).toMatch(/^sha256:/);
  });
});

describe("guardOutboundText", () => {
  it("redacts fail-closed when tokenize throws (offline)", async () => {
    const c = new VeriSwarmClient({
      baseUrl: "https://example.invalid",
      apiKey: "k",
      secretsDetection: true,
    });
    // force offline: stub tokenizePii to throw, tripwire from vendored manifest
    c.tokenizePii = async () => {
      throw new Error("network down");
    };
    c.getSecretRules = async () => {
      throw new Error("network down");
    };
    const out = await c.guardOutboundText("ghp_" + "A".repeat(36));
    expect(out).toBe("[VS:GITHUB_TOKEN:offline]");
  });

  it("is a no-op when disabled", async () => {
    const c = new VeriSwarmClient({
      baseUrl: "https://example.invalid",
      apiKey: "k",
    });
    const gh = "ghp_" + "A".repeat(36);
    expect(await c.guardOutboundText(gh)).toBe(gh);
  });

  it("redacts when tokenize omits tokenized_text after reporting tokens", async () => {
    const c = new VeriSwarmClient({
      baseUrl: "https://example.invalid",
      apiKey: "k",
      secretsDetection: true,
    });
    c.getSecretRules = async () => MANIFEST;
    c.tokenizePii = async () => ({ tokens_created: 1 });

    const out = await c.guardOutboundText(GH);
    expect(out).toBe("[VS:GITHUB_TOKEN:offline]");
  });
});

const AWS = "AKIA" + "B".repeat(16);
const NEW_RULE = {
  name: "acme_token",
  entity_type: "ACME_TOKEN",
  prefix_pattern: "\\bacme_[a-z0-9]{12}\\b",
};
const ACME = "acme_" + "a".repeat(12);

describe("ensureTripwire — fetched manifest handling", () => {
  it("merges fetched rules with the built-ins instead of replacing them", async () => {
    const tw = await ensureTripwire({
      fetchManifest: async () => ({ version: "sha256:remote", rules: [NEW_RULE] }),
    });
    expect(tw.scan(ACME).map((h) => h.entityType)).toEqual(["ACME_TOKEN"]);
    // built-in AWS rule survives a fetched manifest that omits it
    expect(tw.scan(AWS).map((h) => h.entityType)).toEqual(["AWS_KEY"]);
    expect(tw.source).toBe("remote");
  });

  it("never lets a fetched rule narrow a built-in rule of the same name", async () => {
    const tw = await ensureTripwire({
      fetchManifest: async () => ({
        version: "sha256:remote",
        rules: [{ name: "github_pat", entity_type: "GITHUB_TOKEN", prefix_pattern: "\\bNEVER_MATCHES\\b" }],
      }),
    });
    expect(tw.scan(GH).length).toBeGreaterThan(0);
  });

  it.each([
    ["invalid regex", { ...NEW_RULE, name: "bad_re", prefix_pattern: "(" }],
    ["empty pattern", { ...NEW_RULE, name: "empty", prefix_pattern: "" }],
    ["missing name", { entity_type: "X_KEY", prefix_pattern: "x" }],
    ["entity type that would break the redaction marker", { ...NEW_RULE, name: "m", entity_type: "X]:evil[" }],
    ["non-object rule", "ghp_.*"],
  ])("drops a fetched rule with %s and keeps the rest", async (_label, badRule) => {
    const tw = await ensureTripwire({
      fetchManifest: async () => ({ version: "sha256:remote", rules: [badRule, NEW_RULE] }),
    });
    expect(tw.scan(ACME).length).toBe(1);
    expect(tw.scan(GH).length).toBeGreaterThan(0);
  });

  it.each([[null], ["nope"], [{ rules: "x" }], [{ version: "v" }], [[]]])(
    "keeps built-ins for an invalid manifest %j and marks it for retry",
    async (manifest) => {
      const tw = await ensureTripwire({ fetchManifest: async () => manifest });
      expect(tw.scan(GH).length).toBeGreaterThan(0);
      expect(tw.source).toBe("builtin");
    },
  );

  it("marks a failed fetch for retry", async () => {
    const tw = await ensureTripwire({
      fetchManifest: async () => {
        throw new Error("offline");
      },
    });
    expect(tw.source).toBe("builtin");
  });
});

describe("guardOutboundText — manifest refresh after a failed fetch", () => {
  it("retries the manifest fetch after the retry interval instead of caching the fallback forever", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
      const c = new VeriSwarmClient({ baseUrl: "https://example.invalid", apiKey: "k", secretsDetection: true });
      let calls = 0;
      c.getSecretRules = async () => {
        calls += 1;
        if (calls === 1) throw new Error("offline");
        return { version: "sha256:remote", rules: [NEW_RULE] };
      };
      c.tokenizePii = async () => {
        throw new Error("offline");
      };

      expect(await c.guardOutboundText(ACME)).toBe(ACME); // built-ins only: not a secret yet
      await c.guardOutboundText("hello");
      expect(calls).toBe(1); // no hammering inside the retry window

      vi.setSystemTime(new Date("2026-01-01T00:01:01Z"));
      expect(await c.guardOutboundText(ACME)).toBe("[VS:ACME_TOKEN:offline]");
      expect(calls).toBe(2);

      vi.setSystemTime(new Date("2026-01-01T01:00:00Z"));
      await c.guardOutboundText("hello");
      expect(calls).toBe(2); // a successful fetch is not repeated
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("guardOutboundText — detected secrets never leave the process", () => {
  function captureFetch(tokenizeResponse) {
    const bodies = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url, init) => {
        if (init?.body !== undefined) bodies.push(String(init.body));
        const json = String(url).includes("/secret-rules") ? MANIFEST : tokenizeResponse(JSON.parse(init.body));
        return new Response(JSON.stringify(json), { headers: { "content-type": "application/json" } });
      }),
    );
    return bodies;
  }

  it("redacts locally before the tokenize call and returns safe text", async () => {
    const bodies = captureFetch((req) => ({ tokens_created: 0, tokenized_text: req.text }));
    const c = new VeriSwarmClient({ baseUrl: "https://api.test", apiKey: "k", secretsDetection: true });
    const out = await c.guardOutboundText(`email bob@example.com key ${GH}`);
    expect(out).toBe("email bob@example.com key [VS:GITHUB_TOKEN:offline]");
    expect(bodies.length).toBe(1); // the tokenize call still happens, on redacted text
    for (const body of bodies) expect(body).not.toContain(GH);
    vi.unstubAllGlobals();
  });

  it("keeps PII tokenization of the already-redacted text", async () => {
    const bodies = captureFetch((req) => ({
      tokens_created: 1,
      tokenized_text: req.text.replace("bob@example.com", "[VS:EMAIL:1]"),
    }));
    const c = new VeriSwarmClient({ baseUrl: "https://api.test", apiKey: "k", secretsDetection: true });
    const out = await c.guardOutboundText(`bob@example.com ${GH}`);
    expect(out).toBe("[VS:EMAIL:1] [VS:GITHUB_TOKEN:offline]");
    for (const body of bodies) expect(body).not.toContain(GH);
    vi.unstubAllGlobals();
  });

  it("returns locally redacted text when tokenize fails", async () => {
    captureFetch(() => {
      throw new Error("down");
    });
    const c = new VeriSwarmClient({ baseUrl: "https://api.test", apiKey: "k", secretsDetection: true });
    expect(await c.guardOutboundText(`x ${GH}`)).toBe("x [VS:GITHUB_TOKEN:offline]");
    vi.unstubAllGlobals();
  });
});
