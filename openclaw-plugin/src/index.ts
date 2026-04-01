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

// ── Injection Patterns ──────────────────────────────────────────────────

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

// ── Plugin State ────────────────────────────────────────────────────────

interface PluginState {
  client: VeriSwarmClient | null;
  piiEnabled: boolean;
  policyEnabled: boolean;
  injectionScan: boolean;
  auditEnabled: boolean;
  blockedTools: Set<string>;
  allowedTools: Set<string> | null;
  piiSessions: Map<string, string>; // toolName -> sessionId
}

// NOTE: Module-level state is shared within a single OpenClaw gateway process.
// This is safe for single-agent deployments. For multi-agent OpenClaw instances,
// each agent should run its own gateway process (separate Docker container).
const state: PluginState = {
  client: null,
  piiEnabled: true,
  policyEnabled: true,
  injectionScan: true,
  auditEnabled: true,
  blockedTools: new Set(),
  allowedTools: null,
  piiSessions: new Map(),
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

    if (cfg.blockedTools?.length) {
      state.blockedTools = new Set(cfg.blockedTools);
    }
    if (cfg.allowedTools?.length) {
      state.allowedTools = new Set(cfg.allowedTools);
    }

    console.log(
      `[VeriSwarm] Guard active — PII: ${state.piiEnabled}, Policy: ${state.policyEnabled}, ` +
        `Injection scan: ${state.injectionScan}, Audit: ${state.auditEnabled}`
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

      // PII tokenize tool input
      if (state.piiEnabled && event.input && typeof event.input === "string") {
        try {
          const result = await state.client.tokenizePii(event.input);
          if (result.tokens_created > 0) {
            state.piiSessions.set(toolName, result.session_id);
            return { input: result.tokenized_text };
          }
        } catch (e) {
          // Fail open — don't block tool calls if PII service is down
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
        try {
          const sessionId = state.piiSessions.get(toolName);
          const result = await state.client.tokenizePii(output, sessionId);
          if (result.tokens_created > 0) {
            state.piiSessions.set(toolName, result.session_id);
            output = result.tokenized_text;
          }
        } catch (e) {
          // Fail open
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

    // Hook: Before message sending — PII tokenize outbound to LLM
    api.on("message_sending", async (event: any) => {
      if (!state.client || !state.piiEnabled) return {};
      const content = event.content || event.text || "";
      if (typeof content !== "string" || content.length < 4) return {};

      try {
        const result = await state.client.tokenizePii(content);
        if (result.tokens_created > 0) {
          state.piiSessions.set("__message__", result.session_id);
          return { content: result.tokenized_text };
        }
      } catch (e) {
        // Fail open
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
      `[VeriSwarm] Plugin registered — 11 tools, 3 hooks. Agent: ${agentId}`
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
