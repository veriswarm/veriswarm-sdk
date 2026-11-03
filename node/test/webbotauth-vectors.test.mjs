import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { buildSignatureBase, deriveAuthority } from "../webbotauth.mjs";

// Shared with the Python SDK test suite (python/tests/test_webbotauth_vectors.py).
const VECTORS = JSON.parse(
  readFileSync(new URL("../../testdata/webbotauth_vectors.json", import.meta.url), "utf8"),
);

describe("shared Web Bot Auth golden vectors", () => {
  it.each(VECTORS.authority)("@authority of $url is $authority", ({ url, authority }) => {
    expect(deriveAuthority(url)).toBe(authority);
  });

  it.each(VECTORS.signature_base)("signature base: $name", (v) => {
    expect(
      buildSignatureBase({
        authority: v.authority,
        signatureAgent: v.signature_agent,
        created: v.created,
        expires: v.expires,
        keyid: v.keyid,
        nonce: v.nonce,
      }),
    ).toBe(v.expected);
  });
});
