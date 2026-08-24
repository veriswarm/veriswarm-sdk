import { describe, it, expect } from "vitest";
import { createPrivateKey, generateKeyPairSync, verify } from "node:crypto";
import { canonicalManifestContent, signManifest } from "../manifest-signing.mjs";

// --- Golden vector, computed from the server's own canonicalization ---
const GOLDEN_SEED_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const GOLDEN_PUBLIC_KEY_B64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
const GOLDEN_INPUTS = {
  version: "1.0",
  capabilities: ["calendar.read", "email.send"],
  required_tools: ["calendar"],
  ai_disclosure: "You are chatting with an AI assistant operated by Acme Corp.",
  principal_ref: {
    type: "organization",
    name: "Acme Corp",
    identifier: "acme-001",
    source: "explicit",
  },
};
const GOLDEN_CANONICAL_CONTENT =
  '{"ai_disclosure":"You are chatting with an AI assistant operated by Acme Corp.","capabilities":["calendar.read","email.send"],"principal_ref":{"identifier":"acme-001","name":"Acme Corp","source":"explicit","type":"organization"},"required_tools":["calendar"],"version":"1.0"}';
const GOLDEN_SIGNATURE_B64 =
  "c305VIG0K4UqbtUfc5haTC2q2TyS95uPCHWOSM4WqOSmEDnRF/snBVWFc3YAyL2lz01DjK9HDMVspmxrdM/pCA==";

/** Build a PEM (PKCS8) Ed25519 private key from a raw 32-byte seed via a JWK. */
function pemFromRawSeed(seedB64, publicKeyB64) {
  const d = Buffer.from(seedB64, "base64").toString("base64url");
  const x = Buffer.from(publicKeyB64, "base64").toString("base64url");
  const keyObject = createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d, x },
    format: "jwk",
  });
  return keyObject.export({ type: "pkcs8", format: "pem" });
}

function makeKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  return { privateKeyPem, publicKey };
}

describe("canonicalManifestContent — golden vector", () => {
  it("matches the exact canonical string, proving recursive key sorting", () => {
    const content = canonicalManifestContent(GOLDEN_INPUTS);
    expect(content).toBe(GOLDEN_CANONICAL_CONTENT);
  });
});

describe("signManifest — golden vector", () => {
  it("produces the exact expected signature and signing_kid", () => {
    const privateKeyPem = pemFromRawSeed(GOLDEN_SEED_B64, GOLDEN_PUBLIC_KEY_B64);

    const result = signManifest({
      ...GOLDEN_INPUTS,
      privateKeyPem,
      kid: "kid_golden",
    });

    expect(result.signature).toBe(GOLDEN_SIGNATURE_B64);
    expect(result.signing_kid).toBe("kid_golden");
  });
});

describe("signManifest — round trip with a fresh key", () => {
  it("verifies against the canonical content, and fails when the content is tampered", () => {
    const { privateKeyPem, publicKey } = makeKeyPair();

    const inputs = {
      version: "1.0",
      capabilities: ["b", "a"],
      required_tools: ["z", "y"],
      ai_disclosure: "disclosure text",
      principal_ref: { type: "individual" },
    };

    const { signature } = signManifest({ ...inputs, privateKeyPem, kid: "kid-1" });
    const content = canonicalManifestContent(inputs);
    const sigBytes = Buffer.from(signature, "base64");

    expect(verify(null, Buffer.from(content, "utf8"), publicKey, sigBytes)).toBe(true);

    const tampered = content.replace('"a"', '"x"');
    expect(verify(null, Buffer.from(tampered, "utf8"), publicKey, sigBytes)).toBe(false);
  });
});

describe("canonicalManifestContent — nested key sorting", () => {
  it("produces the same canonical string regardless of principal_ref key order", () => {
    const reverseOrderInputs = {
      ...GOLDEN_INPUTS,
      principal_ref: {
        source: "explicit",
        identifier: "acme-001",
        name: "Acme Corp",
        type: "organization",
      },
    };

    const content = canonicalManifestContent(reverseOrderInputs);
    expect(content).toBe(GOLDEN_CANONICAL_CONTENT);
  });

  it("escapes non-ASCII strings and keys like Python json.dumps ensure_ascii", () => {
    const content = canonicalManifestContent({
      version: "1.0",
      ai_disclosure: "Caf\u00e9 \u{1f600}",
      principal_ref: {
        type: "organization",
        ["na\u00efve"]: "M\u00fcnchen",
      },
    });

    expect(content).toBe(
      '{"ai_disclosure":"Caf\\u00e9 \\ud83d\\ude00","capabilities":[],"principal_ref":{"na\\u00efve":"M\\u00fcnchen","type":"organization"},"required_tools":[],"version":"1.0"}'
    );
  });
});

describe("canonicalManifestContent — unset fields and array sorting", () => {
  it("emits ai_disclosure and principal_ref as null when unset, keys always present", () => {
    const content = canonicalManifestContent({
      version: "1.0",
      capabilities: ["b", "a"],
      required_tools: ["y", "x"],
    });

    expect(content).toBe(
      '{"ai_disclosure":null,"capabilities":["a","b"],"principal_ref":null,"required_tools":["x","y"],"version":"1.0"}'
    );
  });

  it("sorts capabilities and required_tools ascending", () => {
    const content = canonicalManifestContent({
      version: "1.0",
      capabilities: ["email.send", "calendar.read", "admin.write"],
      required_tools: ["slack", "calendar"],
    });

    expect(content).toContain('"capabilities":["admin.write","calendar.read","email.send"]');
    expect(content).toContain('"required_tools":["calendar","slack"]');
  });

  it("defaults capabilities/required_tools to empty arrays when omitted", () => {
    const content = canonicalManifestContent({ version: "1.0" });
    expect(content).toBe('{"ai_disclosure":null,"capabilities":[],"principal_ref":null,"required_tools":[],"version":"1.0"}');
  });
});

describe("canonicalManifestContent — input validation", () => {
  it("throws when version is missing", () => {
    expect(() => canonicalManifestContent({})).toThrow(/version/);
  });

  it("throws when version is empty string", () => {
    expect(() => canonicalManifestContent({ version: "" })).toThrow(/version/);
  });

  it("throws when capabilities is not an array", () => {
    expect(() =>
      canonicalManifestContent({ version: "1.0", capabilities: "not-an-array" })
    ).toThrow(/capabilities/);
  });

  it("throws when required_tools is not an array", () => {
    expect(() =>
      canonicalManifestContent({ version: "1.0", required_tools: "not-an-array" })
    ).toThrow(/required_tools/);
  });
});

describe("signManifest — input validation", () => {
  it("throws when privateKeyPem is missing", () => {
    expect(() => signManifest({ version: "1.0", kid: "k" })).toThrow(/privateKeyPem/);
  });

  it("throws when kid is missing", () => {
    const { privateKeyPem } = makeKeyPair();
    expect(() => signManifest({ version: "1.0", privateKeyPem })).toThrow(/kid/);
  });

  it("throws on an unparseable PEM", () => {
    expect(() =>
      signManifest({ version: "1.0", privateKeyPem: "not a pem", kid: "k" })
    ).toThrow();
  });

  it("throws when the key is not Ed25519 (e.g. RSA)", () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPem = privateKey.export({ type: "pkcs8", format: "pem" });
    expect(() => signManifest({ version: "1.0", privateKeyPem: rsaPem, kid: "k" })).toThrow(
      /Ed25519/
    );
  });

  it("throws when the key is not Ed25519 (e.g. EC P-256)", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const ecPem = privateKey.export({ type: "pkcs8", format: "pem" });
    expect(() => signManifest({ version: "1.0", privateKeyPem: ecPem, kid: "k" })).toThrow(
      /Ed25519/
    );
  });
});
