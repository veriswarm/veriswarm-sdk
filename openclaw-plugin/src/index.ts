/**
 * VeriSwarm Plugin for OpenClaw
 *
 * Complete VeriSwarm suite integration for OpenClaw agents:
 *
 * GUARD (automatic, transparent — OpenClaw plugin hooks):
 *   - before_tool_call: policy enforcement (allowlist/blocklist), local
 *     secret redaction (or a block, with secretsDetection), PII tokenization
 *     of tool-call params
 *   - tool_result_persist: local secret + structured-PII redaction and a
 *     prompt-injection banner on tool results
 *   - message_received: links channel conversations to their session
 *   - after_tool_call: audit logging of tool calls to VeriSwarm Vault
 *   - message_sending: local secret redaction (or a cancel, with
 *     secretsDetection), Session Sentry (cancels delivery on block) and PII
 *     tokenization of outbound messages
 *
 * GATE (tools the agent can call):
 *   - check_trust: Get current trust scores
 *   - check_decision: Ask if an action should be allowed
 *   - get_score_history: View trust score changes over time
 *
 * GUARD (tools the agent can call):
 *   - guard_rehydrate: Restore PII tokens for writing to real systems
 *   - guard_status: Check active protections
 *   - guard_findings: View security findings
 *
 * PASSPORT (tools the agent can call):
 *   - get_credentials: Issue a portable trust credential
 *   - verify_credential: Verify another agent's credential
 *
 * VAULT (tools the agent can call):
 *   - query_ledger: Search the audit trail
 *   - verify_chain: Verify audit chain integrity
 *
 * Configuration (in openclaw config):
 *   plugins.entries.veriswarm.config.apiKey: "vsk_..."
 *   plugins.entries.veriswarm.config.apiUrl: "https://api.veriswarm.ai" (optional)
 *   plugins.entries.veriswarm.config.agentId: "agt_..." (optional, auto-generated)
 *   plugins.entries.veriswarm.config.piiEnabled: true (default)
 *   plugins.entries.veriswarm.config.policyEnabled: true (default)
 *   plugins.entries.veriswarm.config.injectionScan: true (default)
 *   plugins.entries.veriswarm.config.auditEnabled: true (default)
 *   plugins.entries.veriswarm.config.blockedTools: [] (optional)
 *   plugins.entries.veriswarm.config.allowedTools: [] (optional, allowlist mode)
 */

import { VeriSwarmClient, type TokenizeResult } from "./client.js";
import { SecretTripwire, ensureTripwire, loadVendoredManifest } from "./secret_tripwire.js";
import { mapStringLeavesSync, rebuildRecord, redactPiiPatterns } from "./local_redaction.js";
import { createHash } from "node:crypto";

// ── Injection Patterns (BASIC HEURISTIC ONLY) ──────────────────────────
//
// IMPORTANT: This is a basic pattern-matching hint, NOT a security
// guarantee. The list below is trivially bypassed by Unicode lookalikes,
// zero-width characters between tokens, base64 encoding, splitting the
// phrase across two tool calls, or paraphrase. It exists to surface the
// most obvious literal payloads to the agent's runtime; do not treat
// detection-misses as evidence the input is safe.
//
// For real prompt-injection defence, route content through VeriSwarm's
// API endpoint at /v1/suite/guard/scan which uses a DeBERTa ML
// classifier with broader coverage. See guard_scan_content tool below.
// (Audit 2026-05-08 HIGH-SDK-12: explicit downgrade in docs/comments
// rather than removing — useful as a fast pre-filter.)

const INJECTION_PATTERNS = [
  "ignore previous instructions",
  "ignore all previous",
  "disregard your instructions",
  "you are now",
  "new instructions:",
  "system prompt:",
  "forget everything",
  "override:",
  "jailbreak",
  "<|im_start|>",
];

function scanForInjection(text: string): string[] {
  const lower = text.toLowerCase();
  return INJECTION_PATTERNS.filter((p) => lower.includes(p.toLowerCase()));
}

// Build the per-session PII map key from the conversation context.
// Keying by tool name alone collides across concurrent agent
// conversations using the same tool — leaking PII tokens *across
// user sessions* in shared deployments. (Audit 2026-05-08 HIGH-SDK-13.)
function piiSessionKey(toolName: string, conversationId: string): string {
  return `${conversationId}:${toolName}`;
}

function firstNonEmptyString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

// Session Sentry bucket when the host gives no conversation identity at all.
// PII sessions are never stored under it, so nothing is shared through it.
const NO_CONVERSATION = "default";

// Tool names are compared the way the host normalizes them before running
// before_tool_call (trim, lowercase, aliases), so `blockedTools: ["Bash"]`
// matches the host's `exec`. `exec_command` is the Codex-native name the
// host's native hook relay maps to `exec`.
const TOOL_NAME_ALIASES: Record<string, string> = {
  bash: "exec",
  "apply-patch": "apply_patch",
  exec_command: "exec",
};

export function normalizeToolName(name: string): string {
  const normalized = name.trim().toLowerCase();
  return TOOL_NAME_ALIASES[normalized] ?? normalized;
}

// `${channel}:${target}` for a message-hook context, with the same prefix
// stripping the host applies to inbound conversation ids.
function deliveryTargetKey(channelId: unknown, target: unknown): string | undefined {
  const channel = typeof channelId === "string" ? channelId.trim().toLowerCase() : "";
  if (!channel || typeof target !== "string" || !target.trim()) return undefined;
  let value = target.trim();
  const generic = ["channel:", "chat:", "user:"].find((prefix) => value.startsWith(prefix));
  if (generic) value = value.slice(generic.length);
  else if (value.startsWith(`${channel}:`)) value = value.slice(channel.length + 1);
  return `${channel}:${value}`;
}

// Canonical conversation identity, shared by tool hooks, message hooks and
// the rehydrate tool. Precedence:
//   1. ctx.sessionKey, then ctx.sessionId (tool hooks, tool factories,
//      agent-path message hooks)
//   2. the sessionKey learned from message_received for the same
//      channel + conversation (outbound delivery passes no session key)
//   3. `target:<channel>:<conversation>` from the message ctx
//   4. legacy event fields from older hosts
function resolveConversationId(ctx: any, event?: any): string | undefined {
  const direct = firstNonEmptyString(ctx?.sessionKey, ctx?.sessionId);
  if (direct) return direct;
  const target = deliveryTargetKey(ctx?.channelId, ctx?.conversationId);
  const bound = target ? state.sessionBindings.get(target) : undefined;
  if (bound) return bound;
  if (target) return `target:${target}`;
  return firstNonEmptyString(
    event?.sessionKey,
    event?.conversation_id,
    event?.conversationId,
    event?.session_id
  );
}

// Session Sentry accepts ids up to 64 chars. Longer ids are hashed (sha256
// hex is exactly 64 chars) so conversations sharing a long prefix stay apart.
function sentrySessionId(conversationId: string): string {
  return conversationId.length <= 64
    ? conversationId
    : createHash("sha256").update(conversationId).digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Insert into a size-capped Map. Re-setting a key moves it to the end, so the
// least-recently-written entry is the one evicted once the cap is reached.
function setBounded<K, V>(map: Map<K, V>, key: K, value: V, cap: number): void {
  map.delete(key);
  if (map.size >= cap) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(key, value);
}

// Rebuild `value` with every string leaf passed through `fn`. Only the
// current path is tracked for cycle detection, so a value referenced twice
// is still visited twice. Keys are kept as-is. Never mutates input.
async function mapStringLeaves(
  value: unknown,
  fn: (text: string) => Promise<string>,
  ancestors = new Set<object>()
): Promise<{ value: unknown; changed: boolean }> {
  if (typeof value === "string") {
    const next = await fn(value);
    return { value: next, changed: next !== value };
  }
  if (!value || typeof value !== "object" || ancestors.has(value)) {
    return { value, changed: false };
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const next = [...value];
      let changed = false;
      for (let i = 0; i < value.length; i++) {
        const child = await mapStringLeaves(value[i], fn, ancestors);
        if (child.changed) {
          next[i] = child.value;
          changed = true;
        }
      }
      return changed ? { value: next, changed } : { value, changed };
    }
    const entries: [string, string, unknown][] = [];
    let changed = false;
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const mapped = await mapStringLeaves(child, fn, ancestors);
      changed ||= mapped.changed;
      entries.push([key, key, mapped.value]);
    }
    return changed ? { value: rebuildRecord(entries), changed } : { value, changed };
  } finally {
    ancestors.delete(value);
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return String(value);
  }
}

// Text the model will see from a tool result: string results as-is, text
// blocks of host-format results (`{content:[{type:"text",text}]}`), and any
// other structured value serialized so it is still scanned and measured.
function serializeToolOutput(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) {
    return value
      .map((block) => {
        if (isRecord(block) && block.type === "text") return String(block.text ?? "");
        if (isRecord(block) && block.type === "image") return "";
        return serializeToolOutput(block);
      })
      .filter((text) => text.length > 0)
      .join("\n");
  }
  if (isRecord(value) && "content" in value) return serializeToolOutput(value.content);
  return typeof value === "object" ? safeStringify(value) : String(value);
}

// Thrown when a fail-closed Guard dependency (PII tokenization, Session
// Sentry) errors or answers with an unexpected shape.
class GuardUnavailableError extends Error {}

function assertTokenizeResult(result: TokenizeResult): TokenizeResult {
  const ok =
    isRecord(result) &&
    typeof result.tokens_created === "number" &&
    (result.tokens_created === 0 || typeof result.tokenized_text === "string");
  if (!ok) throw new Error("malformed PII tokenization response");
  return result;
}

// Redact secrets in every string of `value` — values and object keys, at
// any depth — and name the rules that matched. Local and synchronous: runs
// before any API call, so a secret is never sent to VeriSwarm.
function redactSecrets(
  value: unknown,
  tripwire: SecretTripwire
): { value: unknown; changed: boolean; rules: Set<string> } {
  const rules = new Set<string>();
  const mapped = mapStringLeavesSync(
    value,
    (text) => {
      const hits = tripwire.scan(text);
      if (hits.length === 0) return text;
      for (const hit of hits) rules.add(hit.ruleName);
      return tripwire.redactOffline(text);
    },
    { keys: true }
  );
  return { value: mapped.value, changed: mapped.changed, rules };
}

// Tokenize PII in every string leaf of the tool params. On an API error or
// malformed response this throws GuardUnavailableError (fail closed) unless
// the operator opted into `failOpen`, which passes the text through.
async function tokenizeParamsPii(
  params: unknown,
  state: PluginState,
  toolName: string,
  piiKey: string | null
): Promise<{ value: unknown; changed: boolean }> {
  const client = state.client;
  if (!client) return { value: params, changed: false };
  return mapStringLeaves(params, async (text) => {
    if (text.length < MIN_PII_TEXT_LENGTH) return text;
    try {
      const result = assertTokenizeResult(
        await client.tokenizePii(text, piiKey ? state.piiSessions.get(piiKey) : undefined)
      );
      if (result.tokens_created > 0) {
        if (piiKey && result.session_id) {
          setBounded(state.piiSessions, piiKey, result.session_id, MAX_PII_SESSIONS);
        }
        return result.tokenized_text;
      }
      return text;
    } catch (e) {
      const message = (e as Error)?.message ?? String(e);
      if (!state.failOpen) throw new GuardUnavailableError(message);
      console.warn(
        `[VeriSwarm] PII tokenization (input) failed for tool=${toolName}; ` +
          `passing through unredacted (failOpen). Error: ${message}`
      );
      return text;
    }
  });
}

// Synchronous redaction of a tool result for tool_result_persist: offline
// secret rules (always) and local PII patterns (when piiEnabled). Image
// blocks are left alone. Returns null when nothing changed.
function redactToolResultMessage(
  message: Record<string, unknown>,
  tripwire: SecretTripwire
): { message: Record<string, unknown>; entities: Set<string> } | null {
  const entities = new Set<string>();
  const redactText = (text: string) => {
    let out = text;
    if (tripwire.scan(out).length > 0) {
      out = tripwire.redactOffline(out);
      entities.add("SECRET");
    }
    if (state.piiEnabled) {
      const local = redactPiiPatterns(out);
      for (const entity of local.entities) entities.add(entity);
      out = local.text;
    }
    return out;
  };
  const redactValue = (value: unknown) => mapStringLeavesSync(value, redactText, { keys: true });

  let changed = false;
  let content: unknown = message.content;
  if (Array.isArray(message.content)) {
    content = message.content.map((block) => {
      if (isRecord(block) && block.type === "image") return block;
      const mapped = redactValue(block);
      changed ||= mapped.changed;
      return mapped.value;
    });
  } else {
    const mapped = redactValue(message.content);
    changed ||= mapped.changed;
    content = mapped.value;
  }
  const details = redactValue(message.details);
  changed ||= details.changed;
  if (!changed) return null;
  const next: Record<string, unknown> = { ...message, content };
  if (message.details !== undefined) next.details = details.value;
  return { message: next, entities };
}

// ── Plugin State ────────────────────────────────────────────────────────

interface PluginState {
  client: VeriSwarmClient | null;
  piiEnabled: boolean;
  policyEnabled: boolean;
  injectionScan: boolean;
  auditEnabled: boolean;
  sessionScan: boolean;
  // Operator opt-out: let messages/tool calls through when PII tokenization
  // or Session Sentry is unreachable. Default false (fail closed).
  failOpen: boolean;
  blockedTools: Set<string>; // normalized tool names
  allowedTools: Set<string> | null; // normalized tool names
  piiSessions: Map<string, string>; // `${conversationId}:${toolName}` -> Guard PII session id
  // Per-conversation outbound-turn counters for Session Sentry.
  // Key: Sentry session id. Value: next turn_index to use.
  sessionTurnCounters: Map<string, number>;
  // `${channel}:${conversation}` -> sessionKey, learned from message_received
  // so outbound delivery (which carries no session key) maps to the same
  // conversation as the tool hooks.
  sessionBindings: Map<string, string>;
  secretsDetection: boolean;
  tripwire: SecretTripwire | null;
}

// Caps for the per-conversation maps. All evict the least-recently-written
// entry (see setBounded). For turn counters the only risk is that a long-idle
// conversation restarts at turn 0 — the server keys turn state by turn_index
// overwrite, so that under-counts (the fail-safe direction). For PII sessions
// an evicted conversation simply can no longer rehydrate its oldest tokens.
export const MAX_SESSION_COUNTERS = 10_000;
export const MAX_PII_SESSIONS = 10_000;
export const MAX_SESSION_BINDINGS = 10_000;

// Shortest text worth sending to the PII tokenizer.
const MIN_PII_TEXT_LENGTH = 4;

// The host runs hooks in descending priority and, for before_tool_call and
// message_sending, merges `params` / `content` last-defined-wins while every
// handler sees the ORIGINAL event. Running last means that, when VeriSwarm
// rewrites, its rewrite (built from the original event) replaces other
// plugins' changes. It does not survive another plugin's approval request on
// the same tool call, so secrets are blocked rather than rewritten; blocks
// and cancels are sticky in the host and always hold.
const GUARD_HOOK_PRIORITY = Number.MIN_SAFE_INTEGER;

function initialState(): PluginState {
  return {
    client: null,
    piiEnabled: true,
    policyEnabled: true,
    injectionScan: true,
    auditEnabled: true,
    sessionScan: true,
    failOpen: false,
    blockedTools: new Set(),
    allowedTools: null,
    piiSessions: new Map(),
    sessionTurnCounters: new Map(),
    sessionBindings: new Map(),
    secretsDetection: false,
    tripwire: null,
  };
}

// Build the secret tripwire from the vendored manifest so it is live from
// the very first hook call, then refresh it from the API in the background
// (keeping the vendored baseline if that fails). register is synchronous,
// so the network is not awaited. If even the vendored rules cannot load,
// the tripwire stays null and the hooks block / cancel (fail closed).
function startTripwire(client: VeriSwarmClient): void {
  const registeredState = state;
  try {
    registeredState.tripwire = new SecretTripwire(loadVendoredManifest());
  } catch (e) {
    console.warn(
      "[VeriSwarm] Secret rules failed to load; tool calls and messages will be blocked. " +
        `Error: ${(e as Error)?.message ?? String(e)}`
    );
    return;
  }
  ensureTripwire({ fetchManifest: async () => client.getSecretRules() })
    .then((tw) => {
      registeredState.tripwire = tw;
    })
    .catch(() => {
      /* keep vendored baseline — offline is fine */
    });
}

function toolNameList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v): v is string => typeof v === "string")
    .map(normalizeToolName)
    .filter((v) => v.length > 0);
}

// Policy verdict for a tool call, or null when allowed. A call the host did
// not name is refused whenever a list is configured: falling back to a
// placeholder name could match (or miss) a list entry and invert the policy.
function policyBlock(toolName: string | undefined): { reason: string; message: string } | null {
  const hasPolicy = state.blockedTools.size > 0 || state.allowedTools !== null;
  const normalized = toolName ? normalizeToolName(toolName) : "";
  if (!normalized) {
    return hasPolicy
      ? {
          reason: "unidentified_tool",
          message: "[VeriSwarm Guard] Tool call blocked: the host did not identify the tool.",
        }
      : null;
  }
  if (state.blockedTools.has(normalized)) {
    return { reason: "blocklist", message: `[VeriSwarm Guard] Tool '${toolName}' is blocked by policy.` };
  }
  if (state.allowedTools && !state.allowedTools.has(normalized)) {
    return {
      reason: "not_in_allowlist",
      message: `[VeriSwarm Guard] Tool '${toolName}' is not in the allowlist.`,
    };
  }
  return null;
}

const SENTRY_CANCEL_REASON =
  "Message blocked by VeriSwarm Guard session protection: " +
  "this conversation has triggered multi-turn data-extraction detection.";
const SENTRY_UNAVAILABLE_REASON =
  "Message held by VeriSwarm Guard: session protection is unavailable.";
const PII_UNAVAILABLE_MESSAGE_REASON =
  "Message held by VeriSwarm Guard: PII protection is unavailable.";
const PII_UNAVAILABLE_TOOL_REASON =
  "[VeriSwarm Guard] Tool call blocked: PII protection is unavailable.";

const NOT_CONFIGURED = "VeriSwarm not configured";

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

const SECRET_MESSAGE_CANCEL_REASON =
  "Message blocked by VeriSwarm Guard: it contains a credential (API key, token or secret).";
const SECRET_CHECK_UNAVAILABLE_TOOL_REASON =
  "[VeriSwarm Guard] Tool call blocked: the secret rules could not be loaded. Reinstall the plugin.";
const SECRET_CHECK_UNAVAILABLE_MESSAGE_REASON =
  "Message held by VeriSwarm Guard: the secret rules could not be loaded.";

function secretBlockReason(rules: Set<string>): string {
  return (
    `[VeriSwarm Guard] Tool call blocked: its parameters contain a credential ` +
    `(${Array.from(rules).join(", ")}). Remove it and retry.`
  );
}

const KEY_REWRITE_BLOCK_REASON =
  "[VeriSwarm Guard] Tool call blocked: a parameter name needed redaction.";
const HOOK_ERROR_TOOL_REASON =
  "[VeriSwarm Guard] Tool call blocked: Guard could not check this call.";
const HOOK_ERROR_MESSAGE_REASON =
  "Message held by VeriSwarm Guard: Guard could not check this message.";
const WITHHELD_TOOL_RESULT =
  "[VeriSwarm Guard: tool result withheld — Guard could not check it.]";

function topLevelKeysChanged(before: Record<string, unknown>, after: Record<string, unknown>): boolean {
  const a = Object.keys(before);
  const b = new Set(Object.keys(after));
  return a.length !== b.size || a.some((key) => !b.has(key));
}

// Unconfigured (no client) means pass-through, like the plugin not being
// installed; say so once instead of on every hook call.
let unconfiguredWarned = false;

function warnUnconfiguredOnce(): undefined {
  if (!unconfiguredWarned) {
    unconfiguredWarned = true;
    console.warn(
      "[VeriSwarm] Not configured (no apiKey); Guard hooks pass traffic through unchecked."
    );
  }
  return undefined;
}

// The host's default for most hooks is fail-open: an error thrown by a
// handler is logged and the call or message proceeds. These wrappers turn an
// unexpected error into the hook's fail-closed result (unless failOpen).
// Observation hooks pass `undefined` and only log.
function hookFailure<R>(hookName: string, error: unknown, closed: R | undefined): R | undefined {
  const message = (error as Error)?.message ?? String(error);
  if (state.failOpen || closed === undefined) {
    console.warn(
      `[VeriSwarm] ${hookName} handler failed; continuing` +
        `${closed === undefined ? "" : " (failOpen)"}. Error: ${message}`
    );
    return undefined;
  }
  console.warn(`[VeriSwarm] ${hookName} handler failed; failing closed. Error: ${message}`);
  void logEvent("guard.error", { hook: hookName }).catch(() => {});
  return closed;
}

function guardAsyncHook<R>(
  hookName: string,
  handler: (event: any, ctx: any) => Promise<R | undefined>,
  closed: R | undefined
): (event: any, ctx: any) => Promise<R | undefined> {
  return async (event, ctx) => {
    try {
      return await handler(event, ctx);
    } catch (e) {
      return hookFailure(hookName, e, closed);
    }
  };
}

function guardSyncHook<R>(
  hookName: string,
  handler: (event: any, ctx: any) => R | undefined,
  closed: (event: any) => R | undefined
): (event: any, ctx: any) => R | undefined {
  return (event, ctx) => {
    try {
      return handler(event, ctx);
    } catch (e) {
      return hookFailure(hookName, e, safeClosed(closed, event));
    }
  };
}

function safeClosed<R>(closed: (event: any) => R | undefined, event: any): R | undefined {
  try {
    return closed(event);
  } catch {
    return closed(undefined);
  }
}

// Fail-closed replacement for a tool result that could not be checked.
function withheldToolResult(event: any) {
  const read = (key: string) => {
    try {
      return event?.message?.[key] ?? event?.[key];
    } catch {
      return undefined;
    }
  };
  return {
    message: {
      role: "toolResult",
      toolCallId: read("toolCallId"),
      toolName: read("toolName"),
      content: [{ type: "text", text: WITHHELD_TOOL_RESULT }],
      isError: true,
      timestamp: Date.now(),
    },
  };
}

// NOTE: Module-level state is shared within a single OpenClaw gateway process.
// This is safe for single-agent deployments. For multi-agent OpenClaw instances,
// each agent should run its own gateway process (separate Docker container).
let state: PluginState = initialState();

// Identity of the tenant whose PII sessions / turn counters `state` holds.
let stateFingerprint: string | null = null;

function tenantFingerprint(cfg: any): string {
  return JSON.stringify([cfg?.apiUrl ?? "", cfg?.apiKey ?? "", cfg?.agentId ?? ""]);
}

// ── Plugin Entry ────────────────────────────────────────────────────────

// The subset of the OpenClaw plugin API this plugin uses (see the host's
// docs/plugins/hooks.md and building-plugins.md). Kept structural so the
// plugin does not import the host at runtime.
type PluginApi = {
  pluginConfig?: unknown;
  registerTool: (tool: any, opts?: { name?: string; names?: string[]; optional?: boolean }) => void;
  on: (hookName: string, handler: (event: any, ctx: any) => any, opts?: { priority?: number }) => void;
};

type PluginEntry = {
  id: string;
  name: string;
  description: string;
  configSchema: any;
  register: (api: PluginApi, config: any) => void;
};

// Export as both default and named for compatibility
export const pluginEntry: PluginEntry = {
  id: "veriswarm",
  name: "VeriSwarm Guard",
  description:
    "Trust scoring, PII tokenization, policy enforcement, and audit for OpenClaw agents. " +
    "Protects against data exposure, prompt injection, and unauthorized tool usage.",

  configSchema: {
    type: "object",
    properties: {
      apiKey: {
        type: "string",
        description: "VeriSwarm workspace API key (vsk_...)",
      },
      apiUrl: {
        type: "string",
        description: "VeriSwarm API URL",
        default: "https://api.veriswarm.ai",
      },
      agentId: {
        type: "string",
        description: "Agent ID for this OpenClaw instance",
        default: "",
      },
      agentKey: {
        type: "string",
        description: "Agent API key (agta_...) for credential issuance and self-reporting",
        default: "",
      },
      piiEnabled: {
        type: "boolean",
        description: "Enable PII tokenization on outbound messages and tool-call params",
        default: true,
      },
      policyEnabled: {
        type: "boolean",
        description: "Enable tool policy enforcement",
        default: true,
      },
      injectionScan: {
        type: "boolean",
        description: "Enable prompt injection scanning on tool outputs",
        default: true,
      },
      auditEnabled: {
        type: "boolean",
        description: "Enable audit logging to VeriSwarm Vault",
        default: true,
      },
      blockedTools: {
        type: "array",
        items: { type: "string" },
        description: "Tools to block",
        default: [],
      },
      allowedTools: {
        type: "array",
        items: { type: "string" },
        description: "Only these tools allowed (allowlist mode). Empty = allow all.",
        default: [],
      },
      secretsDetection: {
        type: "boolean",
        description:
          "Block tool calls and cancel outbound messages that contain provider-prefix " +
          "secrets (values or keys). When off " +
          "(default), secrets in tool params and outbound messages are redacted locally " +
          "instead (a call whose top-level parameter name is a secret is still blocked). " +
          "Either way secrets are never sent to the VeriSwarm API, and secrets in tool " +
          "results are always redacted locally.",
        default: false,
      },
      sessionScan: {
        type: "boolean",
        description:
          "Enable Session Sentry multi-turn exfiltration detection. " +
          "Each outbound message is submitted to /v1/suite/guard/scan-session; " +
          "if the conversation-level risk score triggers a block, delivery of the " +
          "message is cancelled. An API error also cancels delivery unless " +
          "failOpen is set. Safe to leave on while the platform " +
          "flag is dormant — the server returns {enabled:false, blocked:false}. " +
          "Default: true.",
        default: true,
      },
      failOpen: {
        type: "boolean",
        description:
          "Let tool calls and messages through without PII tokenization or Session " +
          "Sentry when the VeriSwarm API is unreachable or returns an unexpected " +
          "response. Default false: the tool call is blocked or the message delivery " +
          "cancelled. Local secret redaction and blocking are not relaxed by this flag, " +
          "with one exception: if a Guard hook crashes unexpectedly while failOpen is " +
          "set, that tool call, message or tool result passes through unchecked.",
        default: false,
      },
    },
    required: ["apiKey"],
    additionalProperties: false,
  },

  register(api: PluginApi, config?: any) {
    // ── Initialize ────────────────────────────────────────────────────

    // OpenClaw provides plugin-specific config via api.pluginConfig
    const cfg: any = api.pluginConfig || config || {};

    // Start from clean state on every register: no client, flag or policy
    // list from a previous config may survive. The host also re-invokes
    // register in the same process (e.g. for tool discovery), so the
    // per-conversation maps are carried over only while the tenant identity
    // is unchanged — otherwise live PII sessions would be dropped mid-run.
    const previous = state;
    state = initialState();
    const fingerprint = tenantFingerprint(cfg);
    if (fingerprint === stateFingerprint) {
      state.piiSessions = previous.piiSessions;
      state.sessionTurnCounters = previous.sessionTurnCounters;
      state.sessionBindings = previous.sessionBindings;
    }
    stateFingerprint = fingerprint;
    unconfiguredWarned = false;

    console.log(`[VeriSwarm] Plugin config: apiKey=${cfg.apiKey ? "set" : "missing"}, agentId=${cfg.agentId || "auto"}`);

    const agentId =
      cfg.agentId || `openclaw-${Date.now().toString(36)}`;

    if (!cfg.apiKey) {
      console.warn("[VeriSwarm] No apiKey configured. Plugin running in passive mode. Set plugins.entries.veriswarm.config.apiKey.");
      return;
    }

    state.client = new VeriSwarmClient({
      apiUrl: cfg.apiUrl || "https://api.veriswarm.ai",
      apiKey: cfg.apiKey,
      agentId,
      agentKey: cfg.agentKey || "",
    });

    state.piiEnabled = cfg.piiEnabled ?? true;
    state.policyEnabled = cfg.policyEnabled ?? true;
    state.injectionScan = cfg.injectionScan ?? true;
    state.auditEnabled = cfg.auditEnabled ?? true;
    state.sessionScan = cfg.sessionScan ?? true;
    state.failOpen = cfg.failOpen === true;

    // secretsDetection only chooses between blocking and redacting on a
    // hit; the tripwire itself always runs.
    state.secretsDetection = cfg.secretsDetection === true;
    startTripwire(state.client);

    // Always assigned (even when empty) so a previous config's lists never
    // survive a re-register. An empty allowlist means "allow all". Entries
    // are normalized like the host normalizes tool names.
    state.blockedTools = new Set(toolNameList(cfg.blockedTools));
    const allowed = toolNameList(cfg.allowedTools);
    state.allowedTools = allowed.length > 0 ? new Set(allowed) : null;

    console.log(
      `[VeriSwarm] Guard active — PII: ${state.piiEnabled}, Policy: ${state.policyEnabled}, ` +
        `Injection scan: ${state.injectionScan}, Audit: ${state.auditEnabled}, ` +
        `Session Sentry: ${state.sessionScan}, Fail open: ${state.failOpen}`
    );

    // ── HOOKS: Transparent Protection ─────────────────────────────────

    // Hook: before_tool_call — policy check, secret redaction/block, PII tokenize params.
    // Host event: { toolName, params, toolCallId?, runId? }; ctx carries
    // sessionKey/sessionId. Host result: { block, blockReason } or { params }.
    //
    // Guarantees: a block is always honored (the host treats block as
    // sticky and terminal). A params rewrite is NOT guaranteed: when another
    // plugin requests approval for the same call, the host runs the tool with
    // the approver's params over the ORIGINAL params and drops this rewrite.
    // Secrets are redacted locally before PII tokenization, so they never
    // reach the VeriSwarm API either way; with secretsDetection on they
    // block the call, which also keeps them from the tool on that path.
    api.on(
      "before_tool_call",
      guardAsyncHook(
        "before_tool_call",
        async (event: any, ctx: any) => {
          if (!state.client) return warnUnconfiguredOnce();
          const toolName = firstNonEmptyString(event?.toolName, ctx?.toolName);

          if (state.policyEnabled) {
            const verdict = policyBlock(toolName);
            if (verdict) {
              // Fire-and-forget: the block must not wait on (or fail with) audit I/O.
              void logEvent("tool.blocked", {
                tool_name: toolName ?? null,
                reason: verdict.reason,
              }).catch(() => {});
              return { block: true, blockReason: verdict.message };
            }
          }

          const params = event?.params;
          if (!isRecord(params)) return;

          // Secret tripwire: provider-prefix secrets anywhere in the params
          // (values or keys, any depth) are redacted locally, or block the
          // call when secretsDetection is on. An unnamed call is scanned too.
          const tripwire = state.tripwire;
          if (!tripwire) return { block: true, blockReason: SECRET_CHECK_UNAVAILABLE_TOOL_REASON };
          const secrets = redactSecrets(params, tripwire);
          if (secrets.rules.size > 0) {
            void logEvent("secret.tripwire", {
              tool_name: toolName ?? null,
              rules: Array.from(secrets.rules),
              mode: state.secretsDetection ? "blocked" : "redacted",
            }).catch(() => {});
            if (state.secretsDetection) {
              return { block: true, blockReason: secretBlockReason(secrets.rules) };
            }
          }
          let nextParams = secrets.value as Record<string, unknown>;
          // The host shallow-merges {...original, ...rewrite}: a renamed
          // top-level key would leave the original key in place.
          if (topLevelKeysChanged(params, nextParams)) {
            return { block: true, blockReason: KEY_REWRITE_BLOCK_REASON };
          }
          if (!state.piiEnabled) return secrets.changed ? { params: nextParams } : undefined;

          const scanName = toolName ?? "_unidentified";
          const conversationId = resolveConversationId(ctx, event);
          const key = conversationId ? piiSessionKey(scanName, conversationId) : null;
          let tokenized: { value: unknown; changed: boolean };
          try {
            tokenized = await tokenizeParamsPii(nextParams, state, scanName, key);
          } catch (e) {
            if (!(e instanceof GuardUnavailableError)) throw e;
            console.warn(
              `[VeriSwarm] PII tokenization (input) failed for tool=${scanName}; ` +
                `blocking the call. Error: ${e.message}`
            );
            void logEvent("guard.unavailable", {
              tool_name: toolName ?? null,
              component: "pii_tokenization",
            }).catch(() => {});
            return { block: true, blockReason: PII_UNAVAILABLE_TOOL_REASON };
          }
          if (!tokenized.changed && !secrets.changed) return;
          nextParams = tokenized.value as Record<string, unknown>;
          if (topLevelKeysChanged(params, nextParams)) {
            return { block: true, blockReason: KEY_REWRITE_BLOCK_REASON };
          }
          return { params: nextParams };
        },
        { block: true, blockReason: HOOK_ERROR_TOOL_REASON }
      ),
      { priority: GUARD_HOOK_PRIORITY }
    );

    // Hook: after_tool_call — audit only. The host runs this fire-and-forget
    // and ignores its return value, so it cannot change what the model sees.
    api.on(
      "after_tool_call",
      guardAsyncHook(
        "after_tool_call",
        async (event: any, ctx: any) => {
          if (!state.client) return warnUnconfiguredOnce();
          if (!state.auditEnabled) return;
          const output = serializeToolOutput(event?.result);
          await logEvent("tool.call.success", {
            tool_name: firstNonEmptyString(event?.toolName, ctx?.toolName) ?? null,
            output_length: output.length,
            is_error: Boolean(event?.error),
          });
        },
        undefined
      )
    );

    // Hook: tool_result_persist — the host's result-rewriting hook. It is
    // SYNCHRONOUS (a returned Promise is ignored by the host), so only local
    // checks run here: offline secret redaction (always on, independent of
    // secretsDetection), local PII-pattern redaction
    // (emails, SSNs, phones, Luhn-valid cards, IPv4) and the injection banner.
    // API-based NER tokenization applies to tool inputs and outbound messages.
    api.on(
      "tool_result_persist",
      guardSyncHook("tool_result_persist", (event: any, ctx: any) => {
        if (!state.client) return warnUnconfiguredOnce();
        const original = event?.message;
        if (!isRecord(original)) return;
        const toolName = firstNonEmptyString(event?.toolName, ctx?.toolName) ?? null;

        // Missing secret rules withhold the result whatever failOpen says.
        if (!state.tripwire) return withheldToolResult(event);
        let message = original;
        const redacted = redactToolResultMessage(original, state.tripwire);
        if (redacted) {
          message = redacted.message;
          void logEvent("tool.output.redacted", {
            tool_name: toolName,
            entities: Array.from(redacted.entities),
          }).catch(() => {});
        }

        if (state.injectionScan) {
          const detected = scanForInjection(serializeToolOutput(message));
          if (detected.length > 0) {
            void logEvent("injection.detected", { tool_name: toolName, patterns: detected }).catch(
              () => {}
            );
            const banner = {
              type: "text",
              text:
                `[VeriSwarm Guard: Potential prompt injection detected. ` +
                `Patterns: ${detected.join(", ")}]`,
            };
            const content = Array.isArray(message.content)
              ? [banner, ...message.content]
              : [banner, { type: "text", text: serializeToolOutput(message.content) }];
            message = { ...message, content };
          }
        }

        return message === original ? undefined : { message };
      }, withheldToolResult),
      { priority: GUARD_HOOK_PRIORITY }
    );

    // Hook: message_received — observation only. Learns which sessionKey a
    // channel conversation belongs to, so outbound delivery (whose ctx has
    // only channelId + conversationId) resolves to the same conversation.
    api.on(
      "message_received",
      guardSyncHook(
        "message_received",
        (event: any, ctx: any) => {
          const target = deliveryTargetKey(ctx?.channelId, ctx?.conversationId);
          const sessionKey = firstNonEmptyString(ctx?.sessionKey, event?.sessionKey);
          if (target && sessionKey) {
            setBounded(state.sessionBindings, target, sessionKey, MAX_SESSION_BINDINGS);
          }
          return undefined;
        },
        () => undefined
      )
    );

    // Hook: message_sending — secret redaction/cancel, Session Sentry, and
    // PII tokenization of outbound content. Secrets are redacted locally
    // first, so neither Session Sentry nor tokenization ever receives one.
    // Host event: { to, content, ... }; ctx carries channelId/conversationId
    // and, on agent paths, sessionKey. Host result: { content } to rewrite,
    // { cancel, cancelReason } to stop delivery (cancel is terminal).
    api.on(
      "message_sending",
      guardAsyncHook("message_sending", async (event: any, ctx: any) => {
        if (!state.client) return warnUnconfiguredOnce();
        const content = typeof event?.content === "string" ? event.content : "";
        if (!content) return;

        // ── Secret tripwire (local) ───────────────────────────────────
        const tripwire = state.tripwire;
        if (!tripwire) return { cancel: true, cancelReason: SECRET_CHECK_UNAVAILABLE_MESSAGE_REASON };
        let outbound = content;
        const secretHits = tripwire.scan(content);
        if (secretHits.length > 0) {
          void logEvent("secret.tripwire", {
            surface: "message_sending",
            rules: Array.from(new Set(secretHits.map((h) => h.ruleName))),
            mode: state.secretsDetection ? "blocked" : "redacted",
          }).catch(() => {});
          if (state.secretsDetection) {
            return { cancel: true, cancelReason: SECRET_MESSAGE_CANCEL_REASON };
          }
          outbound = tripwire.redactOffline(content);
        }
        const rewrite = () => (outbound === content ? undefined : { content: outbound });

        const conversationId = resolveConversationId(ctx, event);
        const sessionId = sentrySessionId(conversationId ?? NO_CONVERSATION);

        // ── Per-conversation turn counter ─────────────────────────────
        // turn_index is the index of THIS turn; store the next one.
        const turnIndex = state.sessionTurnCounters.get(sessionId) ?? 0;
        setBounded(state.sessionTurnCounters, sessionId, turnIndex + 1, MAX_SESSION_COUNTERS);

        // ── Session Sentry scan ───────────────────────────────────────
        // Fails CLOSED by default: an API error, timeout or malformed
        // response cancels delivery unless `failOpen` is set. The dormant
        // server returns {enabled:false, blocked:false}, which passes.
        if (state.sessionScan) {
          let blocked: boolean;
          let scanResult: any;
          try {
            scanResult = await state.client.scanSessionTurn({
              session_id: sessionId,
              turn_index: turnIndex,
              // Only the outbound (agent) side is visible to message_sending.
              agent_text: outbound,
              user_text: "",
              system_prompt: "",
              agent_id: agentId,
            });
            if (!isRecord(scanResult) || typeof scanResult.blocked !== "boolean") {
              throw new Error("malformed Session Sentry response");
            }
            blocked = scanResult.blocked;
          } catch (e) {
            const message = (e as Error)?.message ?? String(e);
            if (!state.failOpen) {
              console.warn(
                `[VeriSwarm] Session Sentry scan failed for session=${sessionId} ` +
                  `turn=${turnIndex}; cancelling delivery. Error: ${message}`
              );
              void logEvent("guard.unavailable", {
                session_id: sessionId,
                component: "session_sentry",
              }).catch(() => {});
              return { cancel: true, cancelReason: SENTRY_UNAVAILABLE_REASON };
            }
            console.warn(
              `[VeriSwarm] Session Sentry scan failed for session=${sessionId} ` +
                `turn=${turnIndex}; sending unmodified (failOpen). Error: ${message}`
            );
            blocked = false;
          }

          if (blocked) {
            // Fire-and-forget: audit loss is acceptable; a leaked message is not.
            void logEvent("session.sentry.blocked", {
              session_id: sessionId,
              turn_index: turnIndex,
              session_score: scanResult?.session_score,
              highest_severity: scanResult?.highest_severity,
            }).catch(() => {});
            // Only `cancel: true` short-circuits delivery in the host;
            // rewritten content would still be sent.
            return { cancel: true, cancelReason: SENTRY_CANCEL_REASON };
          }
        }

        // ── PII tokenization ──────────────────────────────────────────
        if (state.piiEnabled && outbound.length >= MIN_PII_TEXT_LENGTH) {
          const key = conversationId ? piiSessionKey("__message__", conversationId) : null;
          try {
            const result = assertTokenizeResult(
              await state.client.tokenizePii(outbound, key ? state.piiSessions.get(key) : undefined)
            );
            if (result.tokens_created > 0) {
              if (key && result.session_id) {
                setBounded(state.piiSessions, key, result.session_id, MAX_PII_SESSIONS);
              }
              return { content: result.tokenized_text };
            }
          } catch (e) {
            const message = (e as Error)?.message ?? String(e);
            if (!state.failOpen) {
              console.warn(
                `[VeriSwarm] PII tokenization (outbound message) failed; ` +
                  `cancelling delivery. Error: ${message}`
              );
              void logEvent("guard.unavailable", {
                session_id: sessionId,
                component: "pii_tokenization",
              }).catch(() => {});
              return { cancel: true, cancelReason: PII_UNAVAILABLE_MESSAGE_REASON };
            }
            console.warn(
              `[VeriSwarm] PII tokenization (outbound message) failed; ` +
                `passing through without PII tokenization (failOpen). Error: ${message}`
            );
          }
        }

        return rewrite();
      }, { cancel: true, cancelReason: HOOK_ERROR_MESSAGE_REASON }),
      { priority: GUARD_HOOK_PRIORITY }
    );

    // ── TOOLS ─────────────────────────────────────────────────────────
    // Host tool contract: `execute(toolCallId, params)` returning
    // `{ content: [{ type: "text", text }] }`. Every name registered here
    // must also be listed in openclaw.plugin.json `contracts.tools`.

    const registerApiTool = (
      name: string,
      description: string,
      parameters: Record<string, unknown>,
      run: (client: VeriSwarmClient, params: any) => Promise<unknown>
    ) => {
      api.registerTool({
        name,
        description,
        parameters,
        async execute(_toolCallId: string, params: any) {
          const client = state.client;
          if (!client) return textResult(NOT_CONFIGURED);
          try {
            return textResult(JSON.stringify(await run(client, params ?? {}), null, 2));
          } catch (e: any) {
            return textResult(`Error: ${e?.message ?? e}`);
          }
        },
      });
    };

    const NO_PARAMS = { type: "object", properties: {} };

    // ── TOOLS: Gate (Trust Scoring) ───────────────────────────────────

    registerApiTool(
      "veriswarm_check_trust",
      "Get your current VeriSwarm trust scores — identity confidence, " +
        "risk level, reliability, autonomy, and policy tier.",
      NO_PARAMS,
      (client) => client.checkTrust()
    );

    registerApiTool(
      "veriswarm_check_decision",
      "Ask VeriSwarm whether an action should be allowed, reviewed, or denied " +
        "based on your current trust scores and policy tier.",
      {
        type: "object",
        properties: {
          action_type: {
            type: "string",
            description: "The action to check (e.g., 'send_email', 'write_database', 'call_api')",
          },
          resource_type: {
            type: "string",
            description: "Optional resource the action targets",
          },
        },
        required: ["action_type"],
      },
      (client, params) => client.checkDecision(params.action_type, params.resource_type)
    );

    registerApiTool(
      "veriswarm_score_history",
      "View how your trust scores have changed over time.",
      {
        type: "object",
        properties: {
          limit: { type: "number", description: "Number of snapshots to return (default 10)" },
        },
      },
      (client, params) => client.getScoreHistory(params.limit || 10)
    );

    // ── TOOLS: Guard (PII + Security) ────────────────────────────────

    // Registered as a factory so the tool is bound to the calling
    // conversation from the host's tool context. The model cannot choose
    // which conversation's PII session to rehydrate: any model-supplied
    // conversation id is ignored.
    api.registerTool(
      (toolCtx: any) => ({
        name: "veriswarm_rehydrate",
        description:
          "Restore original PII values from VeriSwarm Guard tokens. " +
          "Use when you need to write tokenized data back to a database, email, " +
          "CRM, or other real system. Guard will restore the original values securely.",
        parameters: {
          type: "object",
          properties: {
            text: {
              type: "string",
              description: "Text containing [VS:...] tokens to restore",
            },
            tool_name: {
              type: "string",
              description: "The tool whose output contained the tokens (helps find the right session)",
            },
          },
          required: ["text"],
        },
        async execute(_toolCallId: string, params: any) {
          const client = state.client;
          if (!client) return textResult(NOT_CONFIGURED);
          const text = typeof params?.text === "string" ? params.text : "";
          const toolName = firstNonEmptyString(params?.tool_name) ?? "__message__";
          // Without a host-provided conversation identity there is no session
          // to scope to, and no shared fallback bucket exists.
          const conversationId = resolveConversationId(toolCtx);
          if (!conversationId) return textResult(text);
          const sessionId = state.piiSessions.get(piiSessionKey(toolName, conversationId));
          // No PII session for this tool in the calling conversation.
          if (!sessionId) return textResult(text);
          try {
            const result = await client.rehydratePii(text, sessionId);
            return textResult(result.rehydrated_text);
          } catch (e: any) {
            return textResult(`Error: ${e?.message ?? e}`);
          }
        },
      }),
      { name: "veriswarm_rehydrate" }
    );

    api.registerTool({
      name: "veriswarm_guard_status",
      description: "Check VeriSwarm Guard protection status and active policies.",
      parameters: NO_PARAMS,
      async execute() {
        return textResult(
          JSON.stringify(
            {
              guard: "active",
              protections: {
                pii_tokenization: state.piiEnabled,
                policy_enforcement: state.policyEnabled,
                injection_scanning: state.injectionScan,
                audit_logging: state.auditEnabled,
              },
              policy: {
                blocked_tools: state.blockedTools.size ? [...state.blockedTools] : null,
                allowed_tools: state.allowedTools ? [...state.allowedTools] : null,
              },
              active_pii_sessions: state.piiSessions.size,
            },
            null,
            2
          )
        );
      },
    });

    registerApiTool(
      "veriswarm_findings",
      "View Guard security findings — credential leaks, PII detections, unsafe patterns.",
      NO_PARAMS,
      (client) => client.getFindings()
    );

    // ── TOOLS: Passport (Identity) ───────────────────────────────────

    registerApiTool(
      "veriswarm_get_credentials",
      "Issue a portable trust credential (signed JWT) for this agent. " +
        "The credential can be presented to other platforms as proof of trust.",
      NO_PARAMS,
      (client) => client.getCredentials()
    );

    registerApiTool(
      "veriswarm_verify_credential",
      "Verify another agent's VeriSwarm trust credential. " +
        "Checks the signature, expiration, and trust scores embedded in the JWT.",
      {
        type: "object",
        properties: {
          credential_token: {
            type: "string",
            description: "The JWT credential token to verify",
          },
        },
        required: ["credential_token"],
      },
      (client, params) => client.verifyCredential(params.credential_token)
    );

    // ── TOOLS: Vault (Audit) ─────────────────────────────────────────

    registerApiTool(
      "veriswarm_query_ledger",
      "Search the VeriSwarm Vault audit ledger — a tamper-proof record of " +
        "all agent actions, trust decisions, and Guard events.",
      {
        type: "object",
        properties: {
          limit: { type: "number", description: "Number of entries (default 20)" },
          agent_id: { type: "string", description: "Filter by agent ID" },
        },
      },
      (client, params) => client.queryLedger(params.limit || 20, params.agent_id)
    );

    registerApiTool(
      "veriswarm_verify_chain",
      "Verify the cryptographic hash chain integrity of the VeriSwarm Vault. " +
        "Confirms that no audit records have been tampered with.",
      NO_PARAMS,
      (client) => client.verifyChain()
    );

    // ── TOOLS: Platform ──────────────────────────────────────────────

    registerApiTool(
      "veriswarm_status",
      "Check VeriSwarm platform health, uptime, and feature flags.",
      NO_PARAMS,
      (client) => client.getStatus()
    );

    // ── Report plugin startup ────────────────────────────────────────

    logEvent("plugin.started", {
      pii_enabled: state.piiEnabled,
      policy_enabled: state.policyEnabled,
      injection_scan: state.injectionScan,
      audit_enabled: state.auditEnabled,
    }).catch(() => {});

    console.log(
      `[VeriSwarm] Plugin registered — 11 tools, 5 hooks (incl. Session Sentry). Agent: ${agentId}`
    );
  },
};

// ── Helpers ─────────────────────────────────────────────────────────────

async function logEvent(eventType: string, payload: Record<string, any>) {
  if (!state.client || !state.auditEnabled) return;
  try {
    await state.client.ingestEvent(eventType, payload);
  } catch {
    // Fire and forget
  }
}

// ── Export ───────────────────────────────────────────────────────────────

export default pluginEntry;
