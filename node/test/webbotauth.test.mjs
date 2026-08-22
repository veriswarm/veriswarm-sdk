import { describe, it, expect } from "vitest";
import { generateKeyPairSync, verify } from "node:crypto";
import { WebBotAuthSigner, buildSignatureBase } from "../webbotauth.mjs";

function makeKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  return { privateKeyPem, publicKey };
}

// Pull the params substring (everything after `sig1=`) out of a
// Signature-Input header value, e.g.
//   sig1=("@authority" "signature-agent");created=1;expires=301;keyid="k"
function paramsFromSignatureInput(signatureInput) {
  expect(signatureInput.startsWith("sig1=")).toBe(true);
  return signatureInput.slice("sig1=".length);
}

// Pull the params substring out of a signature base's last line, e.g.
//   "@signature-params": ("@authority" "signature-agent");created=1...
function paramsFromBase(base) {
  const lines = base.split("\n");
  const lastLine = lines[lines.length - 1];
  const prefix = '"@signature-params": ';
  expect(lastLine.startsWith(prefix)).toBe(true);
  return lastLine.slice(prefix.length);
}

describe("WebBotAuthSigner.signRequest — known-answer round trip", () => {
  it("produces a signature that verifies against the exact base, and fails on tampering", () => {
    const { privateKeyPem, publicKey } = makeKeyPair();
    const signer = new WebBotAuthSigner({
      privateKeyPem,
      keyId: "key-1",
      signatureAgent: "https://api.veriswarm.ai",
    });

    const created = 1_700_000_000;
    const headers = signer.signRequest({
      url: "https://example.com/a/b?q=1",
      created,
    });

    // Reconstruct the base the way a verifier would: authority from the
    // request URL, signature-agent from the emitted header, and the
    // params from Signature-Input.
    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const reconstructedBase = [
      `"@authority": example.com`,
      `"signature-agent": ${headers["Signature-Agent"]}`,
      `"@signature-params": ${params}`,
    ].join("\n");

    const sigMatch = headers["Signature"].match(/^sig1=:([A-Za-z0-9+/=]+):$/);
    expect(sigMatch).not.toBeNull();
    const sigBytes = Buffer.from(sigMatch[1], "base64");

    const ok = verify(null, Buffer.from(reconstructedBase, "utf8"), publicKey, sigBytes);
    expect(ok).toBe(true);

    // Tamper with the base — verification must fail.
    const tamperedBase = reconstructedBase.replace("example.com", "evil.example");
    const tamperedOk = verify(null, Buffer.from(tamperedBase, "utf8"), publicKey, sigBytes);
    expect(tamperedOk).toBe(false);
  });

  it("verifies via buildSignatureBase using the same inputs signRequest used internally", () => {
    const { privateKeyPem, publicKey } = makeKeyPair();
    const signer = new WebBotAuthSigner({
      privateKeyPem,
      keyId: "key-2",
      signatureAgent: "https://api.veriswarm.ai",
    });

    const created = 1_700_000_100;
    const expires = created + 300;
    const headers = signer.signRequest({ url: "https://api.test:9443/x", created });

    const base = buildSignatureBase({
      // RAW origin, per contract — buildSignatureBase quotes internally.
      authority: "api.test:9443",
      signatureAgent: "https://api.veriswarm.ai",
      created,
      expires,
      keyid: "key-2",
    });

    const sigMatch = headers["Signature"].match(/^sig1=:([A-Za-z0-9+/=]+):$/);
    const sigBytes = Buffer.from(sigMatch[1], "base64");
    const ok = verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes);
    expect(ok).toBe(true);
  });
});

describe("WebBotAuthSigner.signRequest — Signature-Input round-trips into the base", () => {
  it("params in Signature-Input are byte-identical to params in @signature-params", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "key-3" });

    const headers = signer.signRequest({
      url: "https://example.com/",
      created: 1_700_000_200,
      nonce: "abc123",
    });

    const base = buildSignatureBase({
      // RAW origin (signer default), per contract.
      authority: "example.com",
      signatureAgent: "https://api.veriswarm.ai",
      created: 1_700_000_200,
      expires: 1_700_000_500,
      keyid: "key-3",
      nonce: "abc123",
    });

    const paramsFromHeader = paramsFromSignatureInput(headers["Signature-Input"]);
    const paramsInBase = paramsFromBase(base);
    expect(paramsFromHeader).toBe(paramsInBase);
  });

  it("emits the params portion of Signature-Input in the exact param order: created, expires, nonce, keyid, tag", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "kk" });

    const headers = signer.signRequest({
      url: "https://example.com/",
      created: 1,
      expiresInSeconds: 300,
      nonce: "n1",
    });

    expect(headers["Signature-Input"]).toBe(
      'sig1=("@authority" "signature-agent");created=1;expires=301;nonce="n1";keyid="kk";tag="web-bot-auth"'
    );
  });
});

describe("WebBotAuthSigner.signRequest — header shape", () => {
  it("Signature matches sig1=:<base64>:", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://example.com/", created: 1 });
    expect(headers["Signature"]).toMatch(/^sig1=:[A-Za-z0-9+/=]+:$/);
  });

  it("Signature-Agent is the quoted origin", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({
      privateKeyPem,
      keyId: "k",
      signatureAgent: "https://api.veriswarm.ai",
    });
    const headers = signer.signRequest({ url: "https://example.com/", created: 1 });
    expect(headers["Signature-Agent"]).toBe('"https://api.veriswarm.ai"');
  });

  it("defaults signatureAgent to https://api.veriswarm.ai", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://example.com/", created: 1 });
    expect(headers["Signature-Agent"]).toBe('"https://api.veriswarm.ai"');
  });
});

describe("authority derivation (via signRequest + reconstructed base match)", () => {
  const { privateKeyPem, publicKey } = makeKeyPair();

  it("https://example.com/a/b?q=1 -> example.com", () => {
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://example.com/a/b?q=1", created: 1 });
    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = `"@authority": example.com\n"signature-agent": ${headers["Signature-Agent"]}\n"@signature-params": ${params}`;
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });

  it("includes a non-default port", () => {
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://example.com:8443/", created: 1 });
    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = `"@authority": example.com:8443\n"signature-agent": ${headers["Signature-Agent"]}\n"@signature-params": ${params}`;
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });

  it("omits the default https port (443)", () => {
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://example.com:443/", created: 1 });
    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = `"@authority": example.com\n"signature-agent": ${headers["Signature-Agent"]}\n"@signature-params": ${params}`;
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });

  it("omits the default http port (80)", () => {
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "http://example.com:80/", created: 1 });
    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = `"@authority": example.com\n"signature-agent": ${headers["Signature-Agent"]}\n"@signature-params": ${params}`;
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });

  it("lowercases the host", () => {
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://EXAMPLE.COM/", created: 1 });
    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = `"@authority": example.com\n"signature-agent": ${headers["Signature-Agent"]}\n"@signature-params": ${params}`;
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });
});

describe("created/expires/nonce handling", () => {
  it("expires defaults to created + 300", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://example.com/", created: 1000 });
    expect(headers["Signature-Input"]).toContain("created=1000;expires=1300");
  });

  it("honors explicit expiresInSeconds", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({
      url: "https://example.com/",
      created: 1000,
      expiresInSeconds: 60,
    });
    expect(headers["Signature-Input"]).toContain("created=1000;expires=1060");
  });

  it("includes nonce in both the base params and the header when provided", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({
      url: "https://example.com/",
      created: 1,
      nonce: "n-xyz",
    });
    expect(headers["Signature-Input"]).toContain('nonce="n-xyz"');
  });

  it("omits nonce entirely when not provided", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const headers = signer.signRequest({ url: "https://example.com/", created: 1 });
    expect(headers["Signature-Input"]).not.toContain("nonce=");
  });

  it("defaults created to roughly now when omitted", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const before = Math.floor(Date.now() / 1000);
    const headers = signer.signRequest({ url: "https://example.com/" });
    const after = Math.floor(Date.now() / 1000);
    const match = headers["Signature-Input"].match(/created=(\d+)/);
    const created = Number(match[1]);
    expect(created).toBeGreaterThanOrEqual(before);
    expect(created).toBeLessThanOrEqual(after);
  });

  it("rejects a zero expiresInSeconds", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    expect(() =>
      signer.signRequest({ url: "https://example.com/", created: 1, expiresInSeconds: 0 })
    ).toThrow(/expiresInSeconds/);
  });

  it("rejects a negative expiresInSeconds instead of silently emitting an already-expired signature", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    expect(() =>
      signer.signRequest({ url: "https://example.com/", created: 1000, expiresInSeconds: -10 })
    ).toThrow(/expiresInSeconds/);
  });
});

describe("quoting / escaping of caller-supplied keyid and nonce", () => {
  it("escapes a double-quote inside keyid so it cannot smuggle extra params into the signed base", () => {
    const { privateKeyPem, publicKey } = makeKeyPair();
    const maliciousKeyId = 'k";x="1';
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: maliciousKeyId });

    const headers = signer.signRequest({ url: "https://example.com/", created: 1 });

    // No unescaped-quote breakout: exactly two `keyid=` / injected-param
    // boundaries should not appear as a bare `x="1"` param.
    expect(headers["Signature-Input"]).not.toContain('x="1"');
    expect(headers["Signature-Input"]).toContain('keyid="k\\";x=\\"1"');

    // The signature must still verify against the base built from the
    // *escaped* keyid — the escaping must not have desynced the base from
    // what actually got signed.
    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = [
      `"@authority": example.com`,
      `"signature-agent": ${headers["Signature-Agent"]}`,
      `"@signature-params": ${params}`,
    ].join("\n");
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });

  it("escapes a double-quote inside nonce so it cannot smuggle extra params into the signed base", () => {
    const { privateKeyPem, publicKey } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });
    const maliciousNonce = 'n";evil="param';

    const headers = signer.signRequest({
      url: "https://example.com/",
      created: 1,
      nonce: maliciousNonce,
    });

    expect(headers["Signature-Input"]).not.toContain('evil="param"');
    expect(headers["Signature-Input"]).toContain('nonce="n\\";evil=\\"param"');

    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = [
      `"@authority": example.com`,
      `"signature-agent": ${headers["Signature-Agent"]}`,
      `"@signature-params": ${params}`,
    ].join("\n");
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });

  it("keeps Signature-Input byte-identical to @signature-params even with quote-containing keyid and nonce", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: 'k"1' });

    const headers = signer.signRequest({
      url: "https://example.com/",
      created: 1,
      nonce: 'n"2',
    });

    const base = buildSignatureBase({
      // RAW origin (signer default), per contract.
      authority: "example.com",
      signatureAgent: "https://api.veriswarm.ai",
      created: 1,
      expires: 301,
      keyid: 'k"1',
      nonce: 'n"2',
    });

    const paramsFromHeader = paramsFromSignatureInput(headers["Signature-Input"]);
    const paramsInBase = paramsFromBase(base);
    expect(paramsFromHeader).toBe(paramsInBase);
  });

  it("escapes a backslash inside keyid", () => {
    const { privateKeyPem, publicKey } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k\\1" });
    const headers = signer.signRequest({ url: "https://example.com/", created: 1 });

    expect(headers["Signature-Input"]).toContain('keyid="k\\\\1"');

    const params = paramsFromSignatureInput(headers["Signature-Input"]);
    const base = [
      `"@authority": example.com`,
      `"signature-agent": ${headers["Signature-Agent"]}`,
      `"@signature-params": ${params}`,
    ].join("\n");
    const sigBytes = Buffer.from(headers["Signature"].match(/:(.+):/)[1], "base64");
    expect(verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes)).toBe(true);
  });
});

describe("WebBotAuthSigner.fetch", () => {
  it("injects the three signed headers and delegates to global fetch", async () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "k" });

    const calls = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 200 };
    };
    try {
      await signer.fetch("https://example.com/path", {
        method: "POST",
        headers: { "content-type": "application/json" },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(calls).toHaveLength(1);
    const { url, init } = calls[0];
    expect(url).toBe("https://example.com/path");
    expect(init.method).toBe("POST");
    expect(init.headers["content-type"]).toBe("application/json");
    expect(init.headers["Signature-Agent"]).toBe('"https://api.veriswarm.ai"');
    expect(init.headers["Signature-Input"]).toMatch(/^sig1=/);
    expect(init.headers["Signature"]).toMatch(/^sig1=:[A-Za-z0-9+/=]+:$/);
  });
});

describe("constructor validation", () => {
  it("throws when privateKeyPem is missing", () => {
    expect(() => new WebBotAuthSigner({ keyId: "k" })).toThrow(/privateKeyPem/);
  });

  it("throws when keyId is missing", () => {
    const { privateKeyPem } = makeKeyPair();
    expect(() => new WebBotAuthSigner({ privateKeyPem })).toThrow(/keyId/);
  });

  it("throws on an unparseable PEM", () => {
    expect(() => new WebBotAuthSigner({ privateKeyPem: "not a pem", keyId: "k" })).toThrow();
  });

  it("throws when the key is not Ed25519 (e.g. RSA)", () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPem = privateKey.export({ type: "pkcs8", format: "pem" });
    expect(() => new WebBotAuthSigner({ privateKeyPem: rsaPem, keyId: "k" })).toThrow(/Ed25519/);
  });

  it("throws when the key is not Ed25519 (e.g. EC P-256)", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const ecPem = privateKey.export({ type: "pkcs8", format: "pem" });
    expect(() => new WebBotAuthSigner({ privateKeyPem: ecPem, keyId: "k" })).toThrow(/Ed25519/);
  });

  it("throws when signatureAgent is explicitly an empty string", () => {
    const { privateKeyPem } = makeKeyPair();
    expect(
      () => new WebBotAuthSigner({ privateKeyPem, keyId: "k", signatureAgent: "" })
    ).toThrow(/signatureAgent/);
  });

  it("throws when signatureAgent is whitespace-only", () => {
    const { privateKeyPem } = makeKeyPair();
    expect(
      () => new WebBotAuthSigner({ privateKeyPem, keyId: "k", signatureAgent: "   " })
    ).toThrow(/signatureAgent/);
  });
});

describe("buildSignatureBase", () => {
  it("takes a RAW signatureAgent and quotes it internally (does not double-quote)", () => {
    const base = buildSignatureBase({
      authority: "example.com",
      signatureAgent: "https://api.veriswarm.ai", // raw, not pre-quoted
      created: 1,
      expires: 301,
      keyid: "k1",
      nonce: "n1",
    });
    expect(base).toBe(
      [
        '"@authority": example.com',
        '"signature-agent": "https://api.veriswarm.ai"',
        '"@signature-params": ("@authority" "signature-agent");created=1;expires=301;nonce="n1";keyid="k1";tag="web-bot-auth"',
      ].join("\n")
    );
  });

  it("omits nonce from params when not provided", () => {
    const base = buildSignatureBase({
      authority: "example.com",
      signatureAgent: "https://api.veriswarm.ai",
      created: 1,
      expires: 301,
      keyid: "k1",
    });
    expect(base).toContain(
      '"@signature-params": ("@authority" "signature-agent");created=1;expires=301;keyid="k1";tag="web-bot-auth"'
    );
  });

  it("rejects an empty signatureAgent", () => {
    expect(() =>
      buildSignatureBase({
        authority: "example.com",
        signatureAgent: "",
        created: 1,
        expires: 301,
        keyid: "k1",
      })
    ).toThrow(/signatureAgent/);
  });

  // Cross-SDK parity vector — captured from a live run of both the Node and
  // Python SDKs signing with the same Ed25519 key. If this value ever needs
  // to change, `python/tests/test_webbotauth.py` and the API server's
  // verifier MUST change in lockstep, or the two SDKs and the server will
  // silently disagree on the wire format.
  it("matches the cross-SDK golden vector", () => {
    const base = buildSignatureBase({
      authority: "example.com",
      signatureAgent: "https://api.veriswarm.ai", // RAW origin
      created: 1000,
      expires: 1300,
      keyid: 'k"1',
      nonce: 'n"2',
    });

    expect(base).toBe(
      [
        '"@authority": example.com',
        '"signature-agent": "https://api.veriswarm.ai"',
        '"@signature-params": ("@authority" "signature-agent");created=1000;expires=1300;nonce="n\\"2";keyid="k\\"1";tag="web-bot-auth"',
      ].join("\n")
    );
  });

  it("golden vector: WebBotAuthSigner emits the matching Signature-Input and Signature-Agent", () => {
    const { privateKeyPem } = makeKeyPair();
    const signer = new WebBotAuthSigner({ privateKeyPem, keyId: 'k"1' });

    const headers = signer.signRequest({
      url: "https://example.com/",
      created: 1000,
      expiresInSeconds: 300,
      nonce: 'n"2',
    });

    expect(headers["Signature-Agent"]).toBe('"https://api.veriswarm.ai"');
    expect(headers["Signature-Input"]).toBe(
      'sig1=("@authority" "signature-agent");created=1000;expires=1300;nonce="n\\"2";keyid="k\\"1";tag="web-bot-auth"'
    );
  });
});
