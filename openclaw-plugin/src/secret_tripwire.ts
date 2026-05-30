// Client-side secret tripwire. Compiles the manifest's prefix patterns once
// and scans outbound text. Never re-implements detection logic — the manifest
// is the single source of truth (mirrors main-repo secret_rules.py).

export interface SecretRule {
  name: string;
  entity_type: string;
  prefix_pattern: string;
}

export interface SecretManifest {
  version: string;
  rules: SecretRule[];
}

export interface SecretHit {
  start: number;
  end: number;
  value: string;
  entityType: string;
  ruleName: string;
}

export class SecretTripwire {
  readonly version: string;
  private readonly compiled: { re: RegExp; rule: SecretRule }[];

  constructor(manifest: SecretManifest) {
    this.version = manifest.version;
    this.compiled = manifest.rules.map((rule) => ({
      // global flag so matchAll iterates every match span
      re: new RegExp(rule.prefix_pattern, "g"),
      rule,
    }));
  }

  scan(text: string): SecretHit[] {
    const hits: SecretHit[] = [];
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
  // offsets remain valid as we mutate the string. Overlaps resolve by the
  // first (left-most start) hit winning.
  redactOffline(text: string): string {
    const hits = this.scan(text).sort((a, b) => a.start - b.start);
    const chosen: SecretHit[] = [];
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
      const marker = `[VS:${h.entityType}:offline]`;
      out = out.slice(0, h.start) + marker + out.slice(h.end);
    }
    return out;
  }
}

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function loadVendoredManifest(): SecretManifest {
  const path = fileURLToPath(new URL("./secret_rules_manifest.json", import.meta.url));
  return JSON.parse(readFileSync(path, "utf-8")) as SecretManifest;
}

export interface EnsureOptions {
  // injected for testability; defaults to the vendored copy only
  fetchManifest?: () => Promise<SecretManifest>;
}

export async function ensureTripwire(opts: EnsureOptions = {}): Promise<SecretTripwire> {
  const vendored = loadVendoredManifest();
  if (!opts.fetchManifest) return new SecretTripwire(vendored);
  try {
    const fresh = await opts.fetchManifest();
    if (fresh && Array.isArray(fresh.rules)) return new SecretTripwire(fresh);
  } catch {
    // fall through to vendored — offline baseline
  }
  return new SecretTripwire(vendored);
}
