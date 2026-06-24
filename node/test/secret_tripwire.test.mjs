import { describe, it, expect } from "vitest";
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
