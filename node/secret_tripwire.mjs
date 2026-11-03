// Zero-dependency client secret tripwire for the Node SDK. Mirror of the
// plugin tripwire; consumes the same generated manifest. Detection logic is
// never re-implemented — the manifest's prefix patterns are the single source
// of truth (mirrors main-repo secret_rules.py).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// entity_type is interpolated into the `[VS:<ENTITY_TYPE>:offline]`
// redaction marker, so it is restricted to a safe identifier alphabet.
const ENTITY_TYPE_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
const MAX_PATTERN_LENGTH = 1000;

export class SecretTripwire {
  constructor(manifest, { source = "builtin" } = {}) {
    this.version = manifest.version;
    // "remote" when a fetched manifest was merged in; "builtin" when only the
    // vendored rules are active (no fetch, failed fetch, or invalid manifest).
    this.source = source;
    this.compiled = manifest.rules.map((rule) => ({
      // global flag so matchAll iterates every match span
      re: new RegExp(rule.prefix_pattern, "g"),
      rule,
    }));
  }

  scan(text) {
    const hits = [];
    if (typeof text !== "string" || text.length === 0) return hits;
    for (const { re, rule } of this.compiled) {
      for (const m of text.matchAll(re)) {
        if (m[0].length === 0) continue;
        const start = m.index ?? 0;
        hits.push({
          start,
          end: start + m[0].length,
          value: m[0],
          entityType: rule.entity_type,
          ruleName: rule.name,
        });
      }
    }
    return hits;
  }

  // Fail-closed local redaction. Applies spans right-to-left so earlier
  // offsets stay valid as we mutate the string. Overlaps resolve by the
  // first (left-most start) hit winning.
  redactOffline(text) {
    const hits = this.scan(text).sort((a, b) => a.start - b.start);
    const chosen = [];
    let cursor = -1;
    for (const h of hits) {
      if (h.start >= cursor) {
        chosen.push(h);
        cursor = h.end;
      }
    }
    let out = text;
    for (let i = chosen.length - 1; i >= 0; i--) {
      const h = chosen[i];
      out = out.slice(0, h.start) + `[VS:${h.entityType}:offline]` + out.slice(h.end);
    }
    return out;
  }
}

export function loadVendoredManifest() {
  const path = fileURLToPath(new URL("./secret_rules_manifest.json", import.meta.url));
  return JSON.parse(readFileSync(path, "utf-8"));
}

/** True when a fetched rule is well-formed and its pattern compiles here. */
export function isValidRule(rule) {
  if (rule === null || typeof rule !== "object" || Array.isArray(rule)) return false;
  const { name, entity_type: entityType, prefix_pattern: pattern } = rule;
  if (typeof name !== "string" || name.length === 0) return false;
  if (typeof entityType !== "string" || !ENTITY_TYPE_RE.test(entityType)) return false;
  if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > MAX_PATTERN_LENGTH) {
    return false;
  }
  try {
    new RegExp(pattern, "g");
  } catch {
    return false;
  }
  return true;
}

function isManifestShape(manifest) {
  return (
    manifest !== null &&
    typeof manifest === "object" &&
    !Array.isArray(manifest) &&
    Array.isArray(manifest.rules)
  );
}

/**
 * Built-in rules plus every valid fetched rule. Fetched rules can only add
 * coverage: built-ins are always kept, and a fetched rule identical to an
 * existing one is skipped.
 */
export function mergeManifests(vendored, fetched) {
  const seen = new Set(vendored.rules.map((r) => `${r.name}\u0000${r.prefix_pattern}`));
  const extra = fetched.rules.filter(isValidRule).filter((r) => {
    const key = `${r.name}\u0000${r.prefix_pattern}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const version = typeof fetched.version === "string" && fetched.version ? fetched.version : vendored.version;
  return {
    version,
    rules: [
      ...vendored.rules,
      ...extra.map(({ name, entity_type, prefix_pattern }) => ({ name, entity_type, prefix_pattern })),
    ],
  };
}

export async function ensureTripwire({ fetchManifest } = {}) {
  const vendored = loadVendoredManifest();
  if (!fetchManifest) return new SecretTripwire(vendored);
  let fetched;
  try {
    fetched = await fetchManifest();
  } catch {
    // offline — built-ins only; the caller retries later
    return new SecretTripwire(vendored);
  }
  if (!isManifestShape(fetched)) return new SecretTripwire(vendored);
  return new SecretTripwire(mergeManifests(vendored, fetched), { source: "remote" });
}
