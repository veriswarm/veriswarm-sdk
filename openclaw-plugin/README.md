# VeriSwarm Plugin for OpenClaw

Complete VeriSwarm suite integration for OpenClaw agents — trust scoring, PII protection, policy enforcement, and audit.

## Install

```bash
openclaw plugins install veriswarm
```

Set your API key:
```bash
export VERISWARM_API_KEY=vsk_your_key_here
```

## What It Does

### Automatic Protection (transparent, no agent action needed)

| Protection | What Happens |
|---|---|
| **PII Tokenization** | Personal data (names, emails, phones, SSNs, addresses, cards) tokenized in tool-call parameters before the tool runs and in outbound messages before delivery. See [Tool output and PII](#tool-output-and-pii) for tool results. |
| **Tool Policy** | Blocked tools return errors. Allowlist mode restricts to approved tools only. |
| **Injection Scan** | Tool results scanned for prompt injection patterns; a warning banner is added to the persisted tool result |
| **Tool Output Redaction** | Secrets and structured PII (emails, SSNs, phones, cards, IPv4) redacted locally from tool results |
| **Audit** | Every tool call, block, and PII event logged to VeriSwarm Vault |
| **Session Sentry** | Multi-turn exfiltration detection: each outbound message is scanned against the full conversation history. If the session-level risk score crosses the configured threshold, delivery of the outbound message is cancelled. Fails closed by default (an API error also cancels delivery); see `failOpen`. |

### Tools Registered (11 total)

**Gate (Trust):**
- `veriswarm_check_trust` — Current trust scores
- `veriswarm_check_decision` — Should an action be allowed?
- `veriswarm_score_history` — Trust score changes over time

**Guard (Security):**
- `veriswarm_rehydrate` — Restore PII tokens for real writes
- `veriswarm_guard_status` — Active protections
- `veriswarm_findings` — Security findings

**Passport (Identity):**
- `veriswarm_get_credentials` — Issue portable trust credential
- `veriswarm_verify_credential` — Verify another agent's credential

**Vault (Audit):**
- `veriswarm_query_ledger` — Search audit trail
- `veriswarm_verify_chain` — Verify chain integrity

**Platform:**
- `veriswarm_status` — Platform health

### Hooks Registered (5)

- `before_tool_call` — Policy check (blocklist/allowlist), secret tripwire, PII tokenize tool params
- `tool_result_persist` — Local redaction of tool results (secrets + structured PII) and injection-pattern banner
- `after_tool_call` — Audit (observation only; the host ignores its result)
- `message_received` — Observation only: links a channel conversation to its session (see Session identity)
- `message_sending` — Session Sentry multi-turn scan (cancels delivery on block) + PII tokenize outbound messages

`before_tool_call`, `tool_result_persist` and `message_sending` are registered at the lowest hook priority. OpenClaw runs higher priorities first and applies the last handler's `params`/`content`, so VeriSwarm's redaction is the one that takes effect — another plugin rewriting the original values cannot undo it. (Values another plugin *adds* in its own rewrite are not seen by VeriSwarm.)

Tool names in `blockedTools` / `allowedTools` are matched the way OpenClaw normalizes them before hooks run: trimmed, lowercased, and aliased (`bash` → `exec`, `apply-patch` → `apply_patch`).

The plugin ships an `openclaw.plugin.json` manifest declaring its config schema and all 11 tools.

### Tool output and PII

OpenClaw's only result-rewriting hook available to external plugins, `tool_result_persist`, is synchronous (its asynchronous tool-result middleware is restricted to plugins bundled with OpenClaw), so tool results cannot be sent to the VeriSwarm API. Instead the plugin redacts them locally, with no network call:

- **Secrets** — provider-prefix keys and tokens, using the same offline rules as the secret tripwire (when `secretsDetection` is on).
- **Structured PII** — emails, US SSNs, phone numbers, payment card numbers (Luhn-checked) and IPv4 addresses, replaced with `[VS:<TYPE>:local]` markers (when `piiEnabled` is on). Local redaction is irreversible and pattern-based: it does not catch names or free-text PII.

Full NER tokenization through the VeriSwarm API applies to tool-call parameters and outbound messages. Redaction is applied to the tool result OpenClaw persists to the session transcript.

### Rehydration and tool inputs

`veriswarm_rehydrate` returns real values to the agent so it can act on them, but tool-call parameters are still tokenized before any tool runs. Real values flowing into a tool are guarded like any other input; this is intentional.

### Failure behavior

PII tokenization and Session Sentry **fail closed** by default: if the VeriSwarm API errors, times out, or returns an unexpected response, the tool call is blocked or the message delivery is cancelled. Set `failOpen: true` to let traffic through unmodified instead (a `[VeriSwarm] … failed` warning is logged either way). The secret tripwire always falls back to local redaction, regardless of `failOpen`.

## Configuration

```json5
{
  plugins: {
    entries: {
      veriswarm: {
        enabled: true,
        config: {
          apiKey: "vsk_...",                    // Required
          apiUrl: "https://api.veriswarm.ai",   // Optional
          agentId: "agt_my_agent",              // Optional (auto-generated)
          agentKey: "agta_...",                  // Optional (needed for portable credentials)
          piiEnabled: true,                     // Strip PII (default: true)
          policyEnabled: true,                  // Enforce tool policies (default: true)
          injectionScan: true,                  // Scan for injection (default: true)
          auditEnabled: true,                   // Log to Vault (default: true)
          sessionScan: true,                    // Session Sentry multi-turn exfil detection (default: true)
          blockedTools: ["dangerous_tool"],      // Optional blocklist
          allowedTools: [],                     // Optional allowlist (empty = allow all)
          secretsDetection: false,              // Secret tripwire on tool params + tool results (default: false)
          failOpen: false,                      // Let traffic through if VeriSwarm is unreachable (default: false)
        }
      }
    }
  }
}
```

## Session Sentry — Multi-Turn Exfiltration Detection

Session Sentry detects data-extraction patterns that only become visible across multiple conversation turns — e.g. an adversarial user probing an agent across turns to assemble sensitive data piecemeal. Each outbound agent message is submitted to `POST /v1/suite/guard/scan-session` with a per-conversation turn counter. The server accumulates session state and returns a risk score; if `blocked: true` is returned, the hook returns `{ cancel: true }` and OpenClaw does not deliver the message.

**Behavior when the platform flag is dormant:** The server returns `{enabled: false, blocked: false}`. The message is sent unmodified. No action needed — the toggle is safe to leave on at all times.

**Session identity:** One conversation identity is shared by tool hooks, message hooks and `veriswarm_rehydrate`. Precedence:

1. `ctx.sessionKey`, then `ctx.sessionId` from the hook context (tool hooks, tools, agent-path message hooks).
2. For outbound delivery, whose context carries only `channelId` + `conversationId`, the session key learned from the inbound `message_received` hook for the same channel conversation.
3. Otherwise a channel-scoped `target:<channel>:<conversation>` id.
4. Legacy event fields (`conversation_id`, `conversationId`, `session_id`) from older hosts.

`veriswarm_rehydrate` only restores tokens from the calling conversation, and does nothing when the tool context has no identity. With no identity at all, Session Sentry uses the shared `"default"` bucket and no PII session is recorded. Ids longer than 64 characters are sent to Session Sentry as their SHA-256 hex digest, so long ids sharing a prefix stay distinct.

**Failure behavior:** Fails closed by default — an API error, timeout, or malformed response cancels delivery and logs `[VeriSwarm] Session Sentry scan failed`. With `failOpen: true` the message is sent unmodified instead.

**Toggle:** `sessionScan: false` disables the scan entirely. No API calls are made.

**Memory caps:** The per-conversation turn counter map, the PII session map and the conversation-binding map are each capped at 10,000 entries. When a cap is reached the least-recently-written conversation is evicted; an evicted conversation's turn counter restarts at 0 (the server treats this safely: under-counting, not over-blocking), and its oldest PII tokens can no longer be rehydrated.

## Development

```bash
cd openclaw-plugin
npm install
npm run build
openclaw plugins install -l .
```

## Links

- [VeriSwarm](https://veriswarm.ai)
- [Guard Documentation](https://veriswarm.ai/docs/guard)
- [API Reference](https://veriswarm.ai/docs/api)
- [OpenClaw](https://openclaw.ai)
