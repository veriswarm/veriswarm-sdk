// Zero-dependency client secret tripwire for the Node SDK. Mirror of the
// plugin tripwire; consumes the same generated manifest. Detection logic is
// never re-implemented — the manifest's prefix patterns are the single source
// of truth (mirrors main-repo secret_rules.py).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export class SecretTripwire {
  constructor(manifest) {
    this.version = manifest.version;
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

export async function ensureTripwire({ fetchManifest } = {}) {
  const vendored = loadVendoredManifest();
  if (!fetchManifest) return new SecretTripwire(vendored);
  try {
    const fresh = await fetchManifest();
    if (fresh && Array.isArray(fresh.rules) && fresh.rules.length > 0) {
      return new SecretTripwire(fresh);
    }
  } catch {
    // offline fallback — vendored baseline
  }
  return new SecretTripwire(vendored);
}
