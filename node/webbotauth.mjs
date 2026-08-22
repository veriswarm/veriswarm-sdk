/**
 * Web Bot Auth request signing (IETF "Web Bot Auth" profile of RFC 9421 HTTP
 * Message Signatures, Ed25519). Signs outbound requests so an agent is
 * cryptographically identifiable at the edge (e.g. Cloudflare, Google).
 * VeriSwarm issues the Ed25519 key pair; the customer holds the private key
 * — VeriSwarm never stores it after issuance.
 *
 * The signature base this module builds MUST match the VeriSwarm API
 * server's verifier byte-for-byte:
 *
 *   "@authority": <authority>
 *   "signature-agent": <signature_agent>
 *   "@signature-params": ("@authority" "signature-agent");created=<created>;expires=<expires>[;nonce="<nonce>"];keyid="<keyid>";tag="web-bot-auth"
 *
 * Usage:
 *   import { WebBotAuthSigner } from "@veriswarm/sdk/webbotauth.mjs";
 *   const signer = new WebBotAuthSigner({ privateKeyPem, keyId: "key_123" });
 *   const response = await signer.fetch("https://target.example/api", { method: "GET" });
 */
import { createPrivateKey, sign as cryptoSign } from "node:crypto";

const DEFAULT_SIGNATURE_AGENT = "https://api.veriswarm.ai";
const DEFAULT_EXPIRES_IN_SECONDS = 300;
const TAG = "web-bot-auth";

/** Lowercased host, with the port included only when it is non-default. */
function deriveAuthority(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`url is not a valid URL: ${url}`);
  }
  const hostname = parsed.hostname.toLowerCase();
  // URL normalizes an explicit default port (443 for https, 80 for http)
  // away, leaving `.port` empty — so a non-empty `.port` here is already
  // guaranteed non-default.
  return parsed.port ? `${hostname}:${parsed.port}` : hostname;
}

/** Wrap a value as an RFC 8941 String (quoted, with minimal escaping). */
function quoteString(value) {
  return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function buildSignatureParams({ created, expires, nonce = null, keyid, tag = TAG }) {
  let params = `("@authority" "signature-agent");created=${created};expires=${expires}`;
  // keyid and nonce are caller-supplied (nonce is fully caller-controlled via
  // the public signRequest() API) and MUST be quoted as RFC 8941 Strings —
  // an unescaped `"` would break out of its quoted-string param and let
  // arbitrary extra params be smuggled into both the signed base and the
  // Signature-Input header.
  if (nonce) params += `;nonce=${quoteString(nonce)}`;
  params += `;keyid=${quoteString(keyid)};tag=${quoteString(tag)}`;
  return params;
}

/**
 * Build the RFC 9421 signature base for the Web Bot Auth profile.
 *
 * `signatureAgent` is the RAW directory origin (e.g. `https://api.veriswarm.ai`)
 * — callers never pre-quote it. This function does the RFC 8941 String
 * quoting/escaping internally (same as it already does for `keyid`/`nonce`),
 * so the origin appears quoted exactly once in the returned base, matching
 * what a verifier reconstructs from the `Signature-Agent` header.
 *
 * @param {object} options
 * @param {string} options.authority - request host[:port], lowercase, from deriveAuthority().
 * @param {string} options.signatureAgent - the RAW directory origin, e.g. `https://api.veriswarm.ai` (not pre-quoted).
 * @param {number} options.created - integer Unix seconds.
 * @param {number} options.expires - integer Unix seconds.
 * @param {string} options.keyid - the signer's key id.
 * @param {string} [options.nonce] - optional nonce, included in params when present.
 * @param {string} [options.tag="web-bot-auth"]
 * @returns {string} the exact UTF-8 string that gets Ed25519-signed.
 */
export function buildSignatureBase({ authority, signatureAgent, created, expires, keyid, nonce = null, tag = TAG }) {
  if (!authority) throw new Error("authority is required");
  if (!signatureAgent || !String(signatureAgent).trim()) {
    throw new Error("signatureAgent is required");
  }
  if (!Number.isInteger(created)) throw new Error("created must be an integer (Unix seconds)");
  if (!Number.isInteger(expires)) throw new Error("expires must be an integer (Unix seconds)");
  if (!keyid) throw new Error("keyid is required");
  const params = buildSignatureParams({ created, expires, nonce, keyid, tag });
  return [
    `"@authority": ${authority}`,
    `"signature-agent": ${quoteString(signatureAgent)}`,
    `"@signature-params": ${params}`,
  ].join("\n");
}

export class WebBotAuthSigner {
  /**
   * @param {object} options
   * @param {string} options.privateKeyPem - PEM-encoded Ed25519 private key (PKCS8), as issued by VeriSwarm.
   * @param {string} options.keyId - the key id VeriSwarm assigned when it issued the key.
   * @param {string} [options.signatureAgent="https://api.veriswarm.ai"] - the directory origin, unquoted.
   */
  constructor({ privateKeyPem, keyId, signatureAgent = DEFAULT_SIGNATURE_AGENT } = {}) {
    if (!privateKeyPem) throw new Error("privateKeyPem is required");
    if (!keyId) throw new Error("keyId is required");
    if (!signatureAgent || !String(signatureAgent).trim()) {
      throw new Error("signatureAgent must be a non-empty string");
    }
    let keyObject;
    try {
      keyObject = createPrivateKey(privateKeyPem);
    } catch (err) {
      throw new Error(`privateKeyPem is not a valid PEM-encoded private key: ${err.message}`);
    }
    if (keyObject.asymmetricKeyType !== "ed25519") {
      throw new Error(
        `privateKeyPem must be an Ed25519 key (got "${keyObject.asymmetricKeyType}")`
      );
    }
    this.keyObject = keyObject;
    this.keyId = keyId;
    this.signatureAgent = signatureAgent;
  }

  /**
   * Sign a request and return the three Web Bot Auth headers to attach.
   *
   * @param {object} options
   * @param {string} options.url - the target request URL (authority is derived from it).
   * @param {number} [options.created=<now>] - integer Unix seconds.
   * @param {number} [options.expiresInSeconds=300]
   * @param {string} [options.nonce=null]
   * @returns {{ "Signature-Agent": string, "Signature-Input": string, "Signature": string }}
   */
  signRequest({ url, created = Math.floor(Date.now() / 1000), expiresInSeconds = DEFAULT_EXPIRES_IN_SECONDS, nonce = null } = {}) {
    if (!url) throw new Error("url is required");
    if (!Number.isInteger(created)) throw new Error("created must be an integer (Unix seconds)");
    if (!Number.isInteger(expiresInSeconds) || expiresInSeconds <= 0) {
      throw new Error("expiresInSeconds must be a positive integer");
    }

    const authority = deriveAuthority(url);
    const expires = created + expiresInSeconds;

    // Pass the RAW origin — buildSignatureBase does the RFC 8941 quoting
    // internally. Passing an already-quoted value here would double-quote it.
    const base = buildSignatureBase({
      authority,
      signatureAgent: this.signatureAgent,
      created,
      expires,
      keyid: this.keyId,
      nonce,
    });

    // Extract the quoted signature-agent and the params substring directly
    // from the base we just signed, rather than recomputing them, so both
    // Signature-Agent and Signature-Input are byte-identical to what's in
    // the signed base by construction — never by coincidence.
    const lines = base.split("\n");
    const agentLinePrefix = '"signature-agent": ';
    const quotedAgent = lines[1].slice(agentLinePrefix.length);
    const paramsLinePrefix = '"@signature-params": ';
    const params = lines[lines.length - 1].slice(paramsLinePrefix.length);

    const signatureBytes = cryptoSign(null, Buffer.from(base, "utf8"), this.keyObject);

    return {
      "Signature-Agent": quotedAgent,
      "Signature-Input": `sig1=${params}`,
      "Signature": `sig1=:${signatureBytes.toString("base64")}:`,
    };
  }

  /**
   * Sign and perform a fetch() with the Web Bot Auth headers attached.
   * Existing headers on `init.headers` are preserved; the three signed
   * headers are added on top (and win on collision).
   *
   * @param {string} url
   * @param {RequestInit} [init={}]
   */
  async fetch(url, init = {}) {
    const signedHeaders = this.signRequest({ url });
    const headers = { ...(init.headers || {}), ...signedHeaders };
    return fetch(url, { ...init, headers });
  }
}
