#!/usr/bin/env node
// CI drift guard: every vendored manifest must parse-equal the canonical
// reference. Exits non-zero on any mismatch. No network, no subprocess.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const canonical = JSON.parse(
  readFileSync(join(here, "secret_rules_manifest.canonical.json"), "utf-8"),
);
const canonicalStr = JSON.stringify(canonical);

const VENDORED = [
  "openclaw-plugin/src/secret_rules_manifest.json",
  "node/secret_rules_manifest.json",
  "python/src/veriswarm/secret_rules_manifest.json",
  "mcp-server/veriswarm_mcp/secret_rules_manifest.json",
];

let failed = 0;
for (const rel of VENDORED) {
  let vendored;
  try {
    vendored = JSON.parse(readFileSync(join(root, rel), "utf-8"));
  } catch (err) {
    console.error(`MISSING/UNPARSEABLE ${rel}: ${err.message}`);
    failed++;
    continue;
  }
  if (JSON.stringify(vendored) !== canonicalStr) {
    console.error(`DRIFT ${rel}: version ${vendored.version} != ${canonical.version}`);
    failed++;
  } else {
    console.log(`ok ${rel}`);
  }
}
if (failed) {
  console.error(`secret-rules manifest drift check FAILED (${failed} mismatch)`);
  process.exit(1);
}
console.log(`secret-rules manifest drift check OK (version ${canonical.version})`);
