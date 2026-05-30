#!/usr/bin/env node
// Copy the canonical secret-rules manifest into every vendored location.
// Vendored copies are never hand-edited — run this after updating the
// canonical reference from the main-repo generator.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const canonical = join(here, "secret_rules_manifest.canonical.json");

const VENDORED = [
  "openclaw-plugin/src/secret_rules_manifest.json",
  "node/secret_rules_manifest.json",
  "python/src/veriswarm/secret_rules_manifest.json",
  "mcp-server/veriswarm_mcp/secret_rules_manifest.json",
];

// Re-serialize through a parse so all copies are byte-identical and minified.
const parsed = JSON.parse(readFileSync(canonical, "utf-8"));
const out = JSON.stringify(parsed) + "\n";

for (const rel of VENDORED) {
  const dest = join(root, rel);
  writeFileSync(dest, out, "utf-8");
  console.log(`synced ${rel}`);
}
console.log(`version ${parsed.version}`);
