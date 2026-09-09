import { describe, it, expect } from "vitest";
import { loadVendoredManifest, ensureTripwire } from "../src/secret_tripwire.js";

describe("vendored manifest loader", () => {
  it("loads the vendored manifest from disk", () => {
    const m = loadVendoredManifest();
    expect(m.version).toMatch(/^sha256:/);
    expect(m.rules.some((r) => r.name === "github_pat")).toBe(true);
  });

  it("ensureTripwire falls back to vendored copy when fetch fails", async () => {
    const tw = await ensureTripwire({
      fetchManifest: async () => {
        throw new Error("network down");
      },
    });
    expect(tw.version).toMatch(/^sha256:/);
  });

  it("ensureTripwire falls back to vendored copy when fetch returns no rules", async () => {
    const tw = await ensureTripwire({
      fetchManifest: async () => ({ version: "sha256:empty", rules: [] }),
    });
    expect(tw.version).toMatch(/^sha256:/);
  });
});
