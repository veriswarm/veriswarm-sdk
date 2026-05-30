import { describe, it, expect } from "vitest";
import { SecretTripwire } from "../src/secret_tripwire.js";

const MANIFEST = {
  version: "sha256:test",
  rules: [
    { name: "github_pat", entity_type: "GITHUB_TOKEN", prefix_pattern: "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b" },
    { name: "aws_access_key", entity_type: "AWS_KEY", prefix_pattern: "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b" },
  ],
};

const GH = "ghp_" + "A".repeat(36);

describe("SecretTripwire", () => {
  it("detects a provider-prefix secret", () => {
    const tw = new SecretTripwire(MANIFEST);
    const hits = tw.scan(`token is ${GH} ok`);
    expect(hits.length).toBe(1);
    expect(hits[0].entityType).toBe("GITHUB_TOKEN");
    expect(hits[0].value).toBe(GH);
  });

  it("returns no hits for clean text", () => {
    const tw = new SecretTripwire(MANIFEST);
    expect(tw.scan("nothing to see here")).toEqual([]);
  });

  it("redacts offline to a non-recoverable marker", () => {
    const tw = new SecretTripwire(MANIFEST);
    const redacted = tw.redactOffline(`a ${GH} b`);
    expect(redacted).toBe("a [VS:GITHUB_TOKEN:offline] b");
    expect(redacted).not.toContain(GH);
  });

  it("redacts multiple spans right-to-left without corrupting offsets", () => {
    const tw = new SecretTripwire(MANIFEST);
    const aws = "AKIA" + "ABCDEFGHIJKLMNOP";
    const redacted = tw.redactOffline(`${GH} mid ${aws}`);
    expect(redacted).toBe("[VS:GITHUB_TOKEN:offline] mid [VS:AWS_KEY:offline]");
  });
});
