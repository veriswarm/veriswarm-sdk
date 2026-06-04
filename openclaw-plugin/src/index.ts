/**
 * VeriSwarm Plugin for OpenClaw
 *
 * Complete VeriSwarm suite integration for OpenClaw agents:
 *
 * GUARD (automatic, transparent):
 *   - PII tokenization on outbound LLM messages (names, emails, phones, SSNs, addresses, cards)
 *   - PII tokenization on inbound tool results before agent sees them
 *   - Prompt injection scanning on tool outputs
 *   - Policy enforcement on tool calls (allowlist/blocklist)
 *   - Audit logging of all tool calls to VeriSwarm Vault
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
// user sessions* in shared deployments. Pass conversationId from
// the OpenClaw event context. (Audit 2026-05-08 HIGH-SDK-13.)
function piiSessionKey(toolName: string, conversationId?: string | null): string {
  const conv = conversationId || "_no_conv";
  return `${conv}:${toolName}`;
}

// ── Plugin State ────────────────────────────────────────────────────────

interface PluginState {
  client: VeriSwarmClient | null;
  piiEnabled: boolean;
  policyEnabled: boolean;
  injectionScan: boolean;
  auditEnabled: boolean;
  sessionScan: boolean;
  blockedTools: Set<string>;
  allowedTools: Set<string> | null;
  piiSessions: Map<string, string>; // toolName -> sessionId
  // Per-conversation outbound-turn counters for Session Sentry.
  // Key: conversation/session id (or "default" when the event carries none).
  // Value: next turn_index to use (pre-increment on each send).
  sessionTurnCounters: Map<string, number>;
  secretsDetection: boolean;
  tripwire: SecretTripwire | null;
}

// Maximum number of conversation ids tracked in sessionTurnCounters.
// Map preserves insertion order; when the cap is reached the oldest-inserted
// entry is evicted (FIFO, not LRU). Stale conversations are the ones most
// likely to be evicted; the only risk is that a still-live old conversation
// gets its counter reset to 0. The server stores turn state server-side
// (keyed by turn_index overwrite), so eviction causes at-worst under-counting
// in the edge — the fail-safe direction.
export const MAX_SESSION_COUNTERS = 10_000;

// NOTE: Module-level state is shared within a single OpenClaw gateway process.
// This is safe for single-agent deployments. For multi-agent OpenClaw instances,
// each agent should run its own gateway process (separate Docker container).
const state: PluginState = {
  client: null,
  piiEnabled: true,
  policyEnabled: true,
  injectionScan: true,
  auditEnabled: true,
  sessionScan: true,
  blockedTools: new Set(),
  allowedTools: null,
  piiSessions: new Map(),
  sessionTurnCounters: new Map(),
  secretsDetection: false,
  tripwire: null,
};

// ── Plugin Entry ────────────────────────────────────────────────────────

// OpenClaw plugin entry point. Uses definePluginEntry pattern.
// At build time this resolves via the openclaw peer dependency.
// For development without openclaw installed, we use a shim.
type PluginApi = {
  registerTool: (def: any) => void;
  registerHook: (name: string, handler: any) => void;
  on: (event: string, handler: any) => void;
  registerHttpRoute: (def: any) => void;
  registerService: (def: any) => void;
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
        description: "Enable PII tokenization on messages and tool I/O",
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
          "Scan outbound tool-call args for provider-prefix secrets. " +
          "On a hit, tokenize via the API when online, or redact locally " +
          "(fail-closed) when offline. Default off.",
        default: false,
      },
      sessionScan: {
        type: "boolean",
        description:
          "Enable Session Sentry multi-turn exfiltration detection. " +
          "Each outbound message is submitted to /v1/suite/guard/scan-session; " +
          "if the conversation-level risk score triggers a block the message is " +
          "replaced with a Guard refusal. Fail-open: any API error is logged and " +
          "the message is sent unmodified. Safe to leave on while the platform " +
          "flag is dormant — the server returns {enabled:false, blocked:false}. " +
          "Default: true.",
        default: true,
      },
    },
    required: ["apiKey"],
    additionalProperties: false,
  },

  register(api: PluginApi, config?: any) {
    // ── Initialize ────────────────────────────────────────────────────

    // OpenClaw provides plugin-specific config via api.pluginConfig
    const cfg: any = (api as any).pluginConfig || config || {};

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

    // Reset per-conversation turn counters on each register call
    // (covers hot-reload / test re-use of the module-level state).
    state.sessionTurnCounters = new Map();

    state.secretsDetection = cfg.secretsDetection === true;
    if (state.secretsDetection) {
      // Build immediately from the vendored manifest so the tripwire is
      // live from the very first tool call (no startup race window).
      // Then refresh from the API in the background; if that fetch fails
      // we keep the vendored baseline. (register is synchronous, so we
      // must not await the network here.)
      state.tripwire = new SecretTripwire(loadVendoredManifest());
      ensureTripwire({
        fetchManifest: async () => state.client!.getSecretRules(),
      })
        .then((tw) => {
          state.tripwire = tw;
        })
        .catch(() => {
          /* keep vendored baseline — offline is fine */
        });
    }

    if (cfg.blockedTools?.length) {
      state.blockedTools = new Set(cfg.blockedTools);
    }
    if (cfg.allowedTools?.length) {
      state.allowedTools = new Set(cfg.allowedTools);
    }

    console.log(
      `[VeriSwarm] Guard active — PII: ${state.piiEnabled}, Policy: ${state.policyEnabled}, ` +
        `Injection scan: ${state.injectionScan}, Audit: ${state.auditEnabled}, ` +
        `Session Sentry: ${state.sessionScan}`
    );

    // ── HOOKS: Transparent Protection ─────────────────────────────────

    // Hook: Before tool call — policy check + PII tokenize inputs
    api.on("before_tool_call", async (event: any) => {
      if (!state.client) return {};
      const toolName = event.tool?.name || event.name || "unknown";

      // Policy check
      if (state.policyEnabled) {
        if (state.blockedTools.has(toolName)) {
          await logEvent("tool.blocked", { tool_name: toolName, reason: "blocklist" });
          return { block: true, message: `[VeriSwarm Guard] Tool '${toolName}' is blocked by policy.` };
        }
        if (state.allowedTools && !state.allowedTools.has(toolName)) {
          await logEvent("tool.blocked", { tool_name: toolName, reason: "not_in_allowlist" });
          return { block: true, message: `[VeriSwarm Guard] Tool '${toolName}' is not in the allowlist.` };
        }
      }

      // Secret tripwire — runs ahead of PII tokenization. Catches obvious
      // provider-prefix secrets (API keys, tokens) in the agent's native
      // outbound path. On a hit we escalate to authoritative tokenization
      // when online, and fail closed to local non-recoverable redaction
      // when offline or when the API leaves any known-prefix span intact.
      if (
        state.secretsDetection &&
        state.tripwire &&
        event.input &&
        typeof event.input === "string"
      ) {
        const hits = state.tripwire.scan(event.input);
        if (hits.length > 0) {
          const convId = event.conversation_id || event.conversationId || event.session_id;
          const key = piiSessionKey(toolName, convId);
          try {
            const result = await state.client.tokenizePii(event.input);
            let guarded =
              result.tokens_created > 0 ? result.tokenized_text : event.input;
            if (result.tokens_created > 0) {
              state.piiSessions.set(key, result.session_id);
            }
            // Belt-and-suspenders: if any known-prefix span survived the
            // API's tokenization, redact it locally so no recognized
            // secret leaves unprotected.
            if (state.tripwire.scan(guarded).length > 0) {
              guarded = state.tripwire.redactOffline(guarded);
            }
            await logEvent("secret.tripwire", {
              tool_name: toolName,
              rules: hits.map((h) => h.ruleName),
              mode: "online",
            });
            return { input: guarded };
          } catch (e) {
            // Offline / API failure → fail closed with local redaction.
            console.warn(
              `[VeriSwarm] Secret tripwire: API unreachable for tool=${toolName}; ` +
              `applying offline redaction. Error: ${(e as Error)?.message ?? e}`
            );
            await logEvent("secret.tripwire", {
              tool_name: toolName,
              rules: hits.map((h) => h.ruleName),
              mode: "offline",
            }).catch(() => {});
            return { input: state.tripwire.redactOffline(event.input) };
          }
        }
      }

      // PII tokenize tool input
      if (state.piiEnabled && event.input && typeof event.input === "string") {
        const convId = event.conversation_id || event.conversationId || event.session_id;
        const key = piiSessionKey(toolName, convId);
        try {
          const result = await state.client.tokenizePii(event.input);
          if (result.tokens_created > 0) {
            state.piiSessions.set(key, result.session_id);
            return { input: result.tokenized_text };
          }
        } catch (e) {
          // Fail open — but observable, not silent. The customer's
          // log aggregator can alert on this.
          // (Audit 2026-05-08 HIGH-SDK-11.)
          console.warn(
            `[VeriSwarm] PII tokenization (input) failed for tool=${toolName}; ` +
            `passing through unredacted. Error: ${(e as Error)?.message ?? e}`
          );
        }
      }

      return {};
    });

    // Hook: After tool call — PII tokenize output + injection scan
    api.on("after_tool_call", async (event: any) => {
      if (!state.client) return {};
      const toolName = event.tool?.name || event.name || "unknown";
      let output = event.output || event.result || "";

      if (typeof output !== "string") return {};

      // PII tokenize output
      if (state.piiEnabled && output.length > 3) {
        const convId = event.conversation_id || event.conversationId || event.session_id;
        const key = piiSessionKey(toolName, convId);
        try {
          const sessionId = state.piiSessions.get(key);
          const result = await state.client.tokenizePii(output, sessionId);
          if (result.tokens_created > 0) {
            state.piiSessions.set(key, result.session_id);
            output = result.tokenized_text;
          }
        } catch (e) {
          // Fail open — but observable. (HIGH-SDK-11.)
          console.warn(
            `[VeriSwarm] PII tokenization (output) failed for tool=${toolName}; ` +
            `passing through unredacted. Error: ${(e as Error)?.message ?? e}`
          );
        }
      }

      // Injection scan
      if (state.injectionScan) {
        const detected = scanForInjection(output);
        if (detected.length > 0) {
          await logEvent("injection.detected", {
            tool_name: toolName,
            patterns: detected,
          });
          output =
            `[VeriSwarm Guard: Potential prompt injection detected. ` +
            `Patterns: ${detected.join(", ")}]\n\n${output}`;
        }
      }

      // Audit
      if (state.auditEnabled) {
        await logEvent("tool.call.success", {
          tool_name: toolName,
          output_length: output.length,
        });
      }

      return { output };
    });

    // Hook: Before message sending — PII tokenize outbound to LLM + Session Sentry
    //
    // The message_sending event fires for each outbound agent message. OpenClaw
    // exposes the content as event.content or event.text. The conversation
    // identity is carried in event.conversation_id / event.conversationId /
    // event.session_id (in priority order). If none of these are present we fall
    // back to the literal key "default" and note the limitation below.
    //
    // Content mutation: the hook returns { content: newText } to replace the
    // outbound message, matching exactly how the PII tokenization branch works
    // above. For a block we substitute a fixed refusal string rather than the
    // tokenized text — same return shape, different content.
    api.on("message_sending", async (event: any) => {
      if (!state.client) return {};
      const content = event.content || event.text || "";
      if (typeof content !== "string") return {};

      // ── Derive session identity ─────────────────────────────────────
      // OpenClaw provides conversation_id / conversationId / session_id depending
      // on version. We use the first truthy value. If none is present the entire
      // agent's message stream is bucketed under "default"; this means the turn
      // counter is shared across all conversations handled by this gateway
      // process, which is a known limitation when OpenClaw does not expose a
      // conversation id. Deployments where multiple simultaneous conversations
      // are served by a single process should upgrade to an OpenClaw version that
      // exposes conversation_id on the message_sending event.
      const rawConvId: string =
        event.conversation_id ||
        event.conversationId ||
        event.session_id ||
        "default";

      // Truncate/hash to ≤64 chars. UUIDs and short IDs fit natively.
      // For longer ids (e.g. base64 thread blobs) we take a 64-char prefix —
      // this preserves monotonicity without adding a crypto dependency.
      // If perfect uniqueness across very long ids matters, callers can pre-hash
      // before passing to OpenClaw; we document this in the README.
      const sessionId: string =
        rawConvId.length <= 64 ? rawConvId : rawConvId.slice(0, 64);

      // ── Per-conversation turn counter ───────────────────────────────
      // Each call to message_sending for a given session_id increments the
      // counter so the API can detect multi-turn patterns. We read, use, then
      // write-back the incremented value (turn_index is the index of THIS turn).
      const turnIndex = state.sessionTurnCounters.get(sessionId) ?? 0;
      // FIFO eviction: if this is a new key and the map is at the cap, delete
      // the oldest-inserted entry before inserting. Map preserves insertion
      // order, so .keys().next().value is always the oldest key.
      if (!state.sessionTurnCounters.has(sessionId) &&
          state.sessionTurnCounters.size >= MAX_SESSION_COUNTERS) {
        const oldest = state.sessionTurnCounters.keys().next().value;
        if (oldest !== undefined) state.sessionTurnCounters.delete(oldest);
      }
      state.sessionTurnCounters.set(sessionId, turnIndex + 1);

      // ── Session Sentry scan (FAIL-OPEN) ─────────────────────────────
      // Must never block the message on any failure. Any exception or non-200
      // is caught and logged at debug level so it is observable without being
      // noisy in production. The dormant server returns {enabled:false,
      // blocked:false} which passes through immediately.
      let scannedContent = content;
      if (state.sessionScan && content.length > 0) {
        try {
          const scanResult = await state.client.scanSessionTurn({
            session_id: sessionId,
            turn_index: turnIndex,
            // Only the outbound (agent) side of the message is visible here.
            // user_text is left empty because the message_sending hook fires on
            // the agent's outbound turn; the user's inbound text is not exposed
            // by this hook event. If OpenClaw adds a prior-user-message field to
            // the event in future, wire it here.
            agent_text: content,
            user_text: "",
            // system_prompt: not surfaced in the message_sending event or plugin
            // config — left empty. If config.systemPrompt is added in future,
            // read it from cfg and pass it through here.
            system_prompt: "",
            // agent_id is the identity this plugin registered under.
            agent_id: agentId,
          });

          if (scanResult.blocked === true) {
            // Replace the outbound content with the Guard refusal string.
            // This is the same { content } return shape used by PII tokenization,
            // consistent with how the secret tripwire replaces { input } in
            // before_tool_call. The session has triggered multi-turn exfiltration
            // detection — we do NOT log an error; we log an audit event and
            // return the refusal.
            //
            // Fire-and-forget: do NOT await inside the try-block. A synchronous
            // throw from logEvent (e.g. future refactor breaks its internals)
            // would propagate to the outer catch and FAIL-OPEN past a legitimate
            // block. The .catch(() => {}) mirrors logEvent's own internal catch —
            // audit loss is acceptable; allowing a blocked message is not.
            void logEvent("session.sentry.blocked", {
              session_id: sessionId,
              turn_index: turnIndex,
              session_score: scanResult.session_score,
              highest_severity: scanResult.highest_severity,
            }).catch(() => {});
            return {
              content:
                "Message blocked by VeriSwarm Guard session protection: " +
                "this conversation has triggered multi-turn data-extraction detection.",
            };
          }
        } catch (e) {
          // FAIL-OPEN: any network error, timeout, or unexpected response must
          // not interrupt message delivery. Log at warn level (same as the PII
          // branches above) so the customer's log aggregator can alert on it.
          console.warn(
            `[VeriSwarm] Session Sentry scan failed for session=${sessionId} ` +
            `turn=${turnIndex}; sending unmodified. Error: ${(e as Error)?.message ?? e}`
          );
        }
      }

      // ── PII tokenization (existing) ─────────────────────────────────
      if (state.piiEnabled && scannedContent.length >= 4) {
        const key = piiSessionKey("__message__", rawConvId);
        try {
          const result = await state.client.tokenizePii(scannedContent);
          if (result.tokens_created > 0) {
            state.piiSessions.set(key, result.session_id);
            return { content: result.tokenized_text };
          }
        } catch (e) {
          // Fail open — but observable. (HIGH-SDK-11.)
          console.warn(
            `[VeriSwarm] PII tokenization (outbound message) failed; ` +
            `passing through unredacted. Error: ${(e as Error)?.message ?? e}`
          );
        }
      }

      return {};
    });

    // ── TOOLS: Gate (Trust Scoring) ───────────────────────────────────

    api.registerTool({
      name: "veriswarm_check_trust",
      description:
        "Get your current VeriSwarm trust scores — identity confidence, " +
        "risk level, reliability, autonomy, and policy tier.",
      parameters: {},
      handler: async () => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const scores = await state.client.checkTrust();
          return JSON.stringify(scores, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    api.registerTool({
      name: "veriswarm_check_decision",
      description:
        "Ask VeriSwarm whether an action should be allowed, reviewed, or denied " +
        "based on your current trust scores and policy tier.",
      parameters: {
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
      handler: async (params: any) => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const result = await state.client.checkDecision(
            params.action_type,
            params.resource_type
          );
          return JSON.stringify(result, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    api.registerTool({
      name: "veriswarm_score_history",
      description: "View how your trust scores have changed over time.",
      parameters: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Number of snapshots to return (default 10)" },
        },
      },
      handler: async (params: any) => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const history = await state.client.getScoreHistory(params.limit || 10);
          return JSON.stringify(history, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    // ── TOOLS: Guard (PII + Security) ────────────────────────────────

    api.registerTool({
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
      handler: async (params: any) => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          // Find session ID from the tool name or try all sessions
          let sessionId = params.tool_name
            ? state.piiSessions.get(params.tool_name)
            : undefined;

          if (!sessionId) {
            // Try each session until one resolves tokens
            for (const [, sid] of state.piiSessions) {
              const result = await state.client.rehydratePii(params.text, sid);
              if (result.tokens_resolved > 0) {
                return result.rehydrated_text;
              }
            }
            return params.text; // No tokens resolved
          }

          const result = await state.client.rehydratePii(params.text, sessionId);
          return result.rehydrated_text;
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    api.registerTool({
      name: "veriswarm_guard_status",
      description: "Check VeriSwarm Guard protection status and active policies.",
      parameters: {},
      handler: async () => {
        return JSON.stringify(
          {
            guard: "active",
            protections: {
              pii_tokenization: state.piiEnabled,
              policy_enforcement: state.policyEnabled,
              injection_scanning: state.injectionScan,
              audit_logging: state.auditEnabled,
            },
            policy: {
              blocked_tools: state.blockedTools.size
                ? [...state.blockedTools]
                : null,
              allowed_tools: state.allowedTools
                ? [...state.allowedTools]
                : null,
            },
            active_pii_sessions: state.piiSessions.size,
          },
          null,
          2
        );
      },
    });

    api.registerTool({
      name: "veriswarm_findings",
      description: "View Guard security findings — credential leaks, PII detections, unsafe patterns.",
      parameters: {},
      handler: async () => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const findings = await state.client.getFindings();
          return JSON.stringify(findings, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    // ── TOOLS: Passport (Identity) ───────────────────────────────────

    api.registerTool({
      name: "veriswarm_get_credentials",
      description:
        "Issue a portable trust credential (signed JWT) for this agent. " +
        "The credential can be presented to other platforms as proof of trust.",
      parameters: {},
      handler: async () => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const cred = await state.client.getCredentials();
          return JSON.stringify(cred, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    api.registerTool({
      name: "veriswarm_verify_credential",
      description:
        "Verify another agent's VeriSwarm trust credential. " +
        "Checks the signature, expiration, and trust scores embedded in the JWT.",
      parameters: {
        type: "object",
        properties: {
          credential_token: {
            type: "string",
            description: "The JWT credential token to verify",
          },
        },
        required: ["credential_token"],
      },
      handler: async (params: any) => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const result = await state.client.verifyCredential(params.credential_token);
          return JSON.stringify(result, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    // ── TOOLS: Vault (Audit) ─────────────────────────────────────────

    api.registerTool({
      name: "veriswarm_query_ledger",
      description:
        "Search the VeriSwarm Vault audit ledger — a tamper-proof record of " +
        "all agent actions, trust decisions, and Guard events.",
      parameters: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Number of entries (default 20)" },
          agent_id: { type: "string", description: "Filter by agent ID" },
        },
      },
      handler: async (params: any) => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const ledger = await state.client.queryLedger(
            params.limit || 20,
            params.agent_id
          );
          return JSON.stringify(ledger, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    api.registerTool({
      name: "veriswarm_verify_chain",
      description:
        "Verify the cryptographic hash chain integrity of the VeriSwarm Vault. " +
        "Confirms that no audit records have been tampered with.",
      parameters: {},
      handler: async () => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const result = await state.client.verifyChain();
          return JSON.stringify(result, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    // ── TOOLS: Platform ──────────────────────────────────────────────

    api.registerTool({
      name: "veriswarm_status",
      description: "Check VeriSwarm platform health, uptime, and feature flags.",
      parameters: {},
      handler: async () => {
        if (!state.client) return "VeriSwarm not configured";
        try {
          const status = await state.client.getStatus();
          return JSON.stringify(status, null, 2);
        } catch (e: any) {
          return `Error: ${e.message}`;
        }
      },
    });

    // ── Report plugin startup ────────────────────────────────────────

    logEvent("plugin.started", {
      pii_enabled: state.piiEnabled,
      policy_enabled: state.policyEnabled,
      injection_scan: state.injectionScan,
      audit_enabled: state.auditEnabled,
    }).catch(() => {});

    console.log(
      `[VeriSwarm] Plugin registered — 11 tools, 3 hooks (incl. Session Sentry). Agent: ${agentId}`
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
