/**
 * Ed25519 signing for VeriSwarm Passport manifests.
 *
 * The VeriSwarm API's `create_manifest` endpoint verifies a signature over
 * the canonical JSON of five manifest content fields — `version`,
 * `capabilities`, `required_tools`, `ai_disclosure`, `principal_ref` —
 * serialized exactly the way Python's `json.dumps(obj, sort_keys=True,
 * separators=(",", ":"))` would serialize them. This module reproduces that
 * canonicalization in JS (which `JSON.stringify` does not do on its own —
 * it neither sorts object keys nor sorts them recursively) and signs the
 * resulting UTF-8 bytes with Ed25519.
 *
 * VeriSwarm issues the Ed25519 signing key via
 * `POST /v1/suite/passport/webbotauth/keys`; the customer holds the private
 * key and VeriSwarm never stores it after issuance.
 *
 * Usage:
 *   import { signManifest } from "@veriswarm/sdk/manifest-signing.mjs";
 *   const { signature, signing_kid } = signManifest({
 *     version: "1.0",
 *     capabilities: ["calendar.read", "email.send"],
 *     required_tools: ["calendar"],
 *     ai_disclosure: "You are chatting with an AI assistant operated by Acme Corp.",
 *     principal_ref: { type: "organization", name: "Acme Corp", identifier: "acme-001", source: "explicit" },
 *     privateKeyPem,
 *     kid: "key_abc123",
 *   });
 */
import { createPrivateKey, sign as cryptoSign } from "node:crypto";

/**
 * Quote a JSON string the way Python's json.dumps(..., ensure_ascii=True)
 * does. JSON.stringify leaves non-ASCII characters as UTF-8, while the
 * server-side Python canonicalizer escapes them as \uXXXX sequences.
 */
function quotePythonJsonString(value) {
  const str = String(value);
  let out = '"';
  for (let i = 0; i < str.length; i += 1) {
    const code = str.charCodeAt(i);
    switch (code) {
      case 0x08:
        out += "\\b";
        break;
      case 0x09:
        out += "\\t";
        break;
      case 0x0a:
        out += "\\n";
        break;
      case 0x0c:
        out += "\\f";
        break;
      case 0x0d:
        out += "\\r";
        break;
      case 0x22:
        out += '\\"';
        break;
      case 0x5c:
        out += "\\\\";
        break;
      default:
        if (code < 0x20 || code >= 0x7f) {
          out += `\\u${code.toString(16).padStart(4, "0")}`;
        } else {
          out += str[i];
        }
    }
  }
  out += '"';
  return out;
}

/**
 * Recursively serialize a JSON-compatible value the way Python's
 * `json.dumps(value, sort_keys=True, separators=(",", ":"))` would:
 * object keys sorted ascending at every nesting level, no whitespace.
 * Array element order is preserved as-is (callers that need sorted arrays,
 * e.g. `capabilities`/`required_tools`, must sort them before calling in).
 *
 * @param {*} value
 * @returns {string}
 */
function canonicalize(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return quotePythonJsonString(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("cannot canonicalize a non-finite number (NaN/Infinity)");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => `${quotePythonJsonString(key)}:${canonicalize(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new Error(`cannot canonicalize value of type ${typeof value}`);
}

/**
 * Build the exact canonical JSON string the VeriSwarm API signs/verifies
 * for a Passport manifest's content fields.
 *
 * `capabilities` and `required_tools` are sorted ascending (string sort)
 * before serialization. `ai_disclosure` and `principal_ref` are emitted as
 * `null` when unset (the keys are always present). Keys inside
 * `principal_ref` (and any other nested object) are sorted recursively.
 *
 * @param {object} options
 * @param {string} options.version
 * @param {string[]} [options.capabilities=[]]
 * @param {string[]} [options.required_tools=[]]
 * @param {string|null} [options.ai_disclosure=null]
 * @param {object|null} [options.principal_ref=null]
 * @returns {string} the exact canonical JSON string that gets signed.
 */
export function canonicalManifestContent({
  version,
  capabilities = [],
  required_tools = [],
  ai_disclosure = null,
  principal_ref = null,
} = {}) {
  if (!version || typeof version !== "string") {
    throw new Error("version is required and must be a non-empty string");
  }
  if (!Array.isArray(capabilities)) throw new Error("capabilities must be an array of strings");
  if (!Array.isArray(required_tools)) throw new Error("required_tools must be an array of strings");

  const content = {
    version,
    capabilities: [...capabilities].sort(),
    required_tools: [...required_tools].sort(),
    ai_disclosure: ai_disclosure ?? null,
    principal_ref: principal_ref ?? null,
  };
  return canonicalize(content);
}

/**
 * Sign a Passport manifest's canonical content with an Ed25519 private key.
 *
 * @param {object} options
 * @param {string} options.version
 * @param {string[]} [options.capabilities=[]]
 * @param {string[]} [options.required_tools=[]]
 * @param {string|null} [options.ai_disclosure=null]
 * @param {object|null} [options.principal_ref=null]
 * @param {string} options.privateKeyPem - PEM-encoded Ed25519 private key (PKCS8), as issued by VeriSwarm.
 * @param {string} options.kid - the key id VeriSwarm assigned when it issued the key.
 * @returns {{ signature: string, signing_kid: string }} base64-encoded Ed25519 signature and the kid to submit alongside it.
 */
export function signManifest({
  version,
  capabilities = [],
  required_tools = [],
  ai_disclosure = null,
  principal_ref = null,
  privateKeyPem,
  kid,
} = {}) {
  if (!privateKeyPem) throw new Error("privateKeyPem is required");
  if (!kid) throw new Error("kid is required");

  let keyObject;
  try {
    keyObject = createPrivateKey(privateKeyPem);
  } catch (err) {
    throw new Error(`privateKeyPem is not a valid PEM-encoded (or JWK) private key: ${err.message}`);
  }
  if (keyObject.asymmetricKeyType !== "ed25519") {
    throw new Error(`privateKeyPem must be an Ed25519 key (got "${keyObject.asymmetricKeyType}")`);
  }

  const content = canonicalManifestContent({
    version,
    capabilities,
    required_tools,
    ai_disclosure,
    principal_ref,
  });

  const signatureBytes = cryptoSign(null, Buffer.from(content, "utf8"), keyObject);

  return {
    signature: signatureBytes.toString("base64"),
    signing_kid: kid,
  };
}
