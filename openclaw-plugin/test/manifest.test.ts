/**
 * openclaw.plugin.json must stay in step with the runtime entry: the host
 * validates config against the manifest schema before loading code, and
 * drops any registered tool not listed in contracts.tools.
 */
import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { pluginEntry } from "../src/index.js";

const readJson = (relative: string) =>
  JSON.parse(readFileSync(new URL(relative, import.meta.url), "utf8"));

const manifest = readJson("../openclaw.plugin.json");
const pkg = readJson("../package.json");

describe("openclaw.plugin.json", () => {
  it("matches the entry's id and config schema", () => {
    expect(manifest.id).toBe(pluginEntry.id);
    expect(manifest.configSchema).toEqual(pluginEntry.configSchema);
  });

  it("declares exactly the tools the plugin registers", () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const names: string[] = [];
    pluginEntry.register(
      {
        registerTool: (tool: any, opts?: { name?: string }) =>
          names.push(opts?.name ?? tool.name),
        on: () => {},
      } as any,
      { apiKey: "vsk_test", apiUrl: "https://api.test.local", auditEnabled: false }
    );
    vi.restoreAllMocks();

    expect([...manifest.contracts.tools].sort()).toEqual([...names].sort());
  });

  it("ships with the published package", () => {
    expect(pkg.files).toEqual(
      expect.arrayContaining(["dist", "openclaw.plugin.json", "README.md", "SKILL.md"])
    );
    expect(pkg.openclaw.extensions).toEqual(["./dist/index.js"]);
  });
});
