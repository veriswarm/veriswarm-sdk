/**
 * Drives the REAL OpenClaw host from node_modules (not a hand-rolled fake).
 *
 * The plugin loader, tool resolver and before_tool_call wrapper live in
 * content-hashed dist chunks that are not public package exports, so we
 * locate each one by its exported symbol name. If a host upgrade renames a
 * symbol, this throws loudly instead of silently testing nothing.
 */
import { readdirSync, readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const PLUGIN_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const HOST_DIST = fileURLToPath(new URL("../../node_modules/openclaw/dist/", import.meta.url));

async function importHostSymbol<T = any>(symbol: string): Promise<T> {
  const pattern = new RegExp(`export \\{[^}]*\\b${symbol} as (\\w+)`);
  for (const file of readdirSync(HOST_DIST)) {
    if (!file.endsWith(".js")) continue;
    const match = readFileSync(join(HOST_DIST, file), "utf8").match(pattern);
    if (match) {
      const mod = await import(join(HOST_DIST, file));
      return mod[match[1]] as T;
    }
  }
  throw new Error(`openclaw host symbol not found in dist/: ${symbol}`);
}

const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

export interface LoadedHost {
  registry: any;
  hookRunner: any;
  config: any;
  env: NodeJS.ProcessEnv;
  resolveTools: (ctx: Record<string, unknown>) => any[];
  wrapWithBeforeToolCall: (
    tool: any,
    ctx: Record<string, unknown>,
    options?: { approvalMode?: "report" }
  ) => any;
}

export const FIXTURES = fileURLToPath(new URL("../fixtures/", import.meta.url));

/**
 * Load the built plugin from PLUGIN_ROOT through the host's own plugin
 * loader, optionally alongside other (fixture) plugins by id + directory.
 */
export async function loadPluginInHost(
  pluginConfig: Record<string, unknown>,
  extraPlugins: { id: string; dir: string }[] = []
): Promise<LoadedHost> {
  const loadOpenClawPlugins = await importHostSymbol("loadOpenClawPlugins");
  const resolvePluginTools = await importHostSymbol("resolvePluginTools");
  const wrapToolWithBeforeToolCallHook = await importHostSymbol("wrapToolWithBeforeToolCallHook");
  const { getGlobalHookRunner } = await import(join(HOST_DIST, "plugin-sdk/plugin-runtime.js"));

  const home = mkdtempSync(join(tmpdir(), "openclaw-host-"));
  const env = { ...process.env, HOME: home, OPENCLAW_STATE_DIR: home };
  const config = {
    plugins: {
      load: { paths: [PLUGIN_ROOT, ...extraPlugins.map((p) => p.dir)] },
      entries: {
        veriswarm: { enabled: true, config: pluginConfig },
        ...Object.fromEntries(extraPlugins.map((p) => [p.id, { enabled: true, config: {} }])),
      },
    },
  };

  const registry = loadOpenClawPlugins({
    config,
    env,
    workspaceDir: home,
    cache: false,
    onlyPluginIds: ["veriswarm", ...extraPlugins.map((p) => p.id)],
    logger: silentLogger,
  });

  return {
    registry,
    hookRunner: getGlobalHookRunner(),
    config,
    env,
    resolveTools: (ctx) =>
      resolvePluginTools({
        context: { config, workspaceDir: home, ...ctx },
        env,
        onlyPluginIds: ["veriswarm"],
      }).filter((t: any) => String(t.name).startsWith("veriswarm_")),
    wrapWithBeforeToolCall: (tool, ctx, options) => wrapToolWithBeforeToolCallHook(tool, ctx, options),
  };
}
