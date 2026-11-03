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
| **Audit** | Every tool call, block, and PII event logged to VeriSwarm Vault |
| **Session Sentry** | Multi-turn exfiltration detection: each outbound message is scanned against the full conversation history. If the session-level risk score crosses the configured threshold, delivery of the outbound message is cancelled. Fail-open — any API error lets the message through unchanged. |

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

### Hooks Registered (4)

- `before_tool_call` — Policy check (block/allowlist), secret tripwire, PII tokenize tool params
- `tool_result_persist` — Injection-pattern banner on tool results
- `after_tool_call` — Audit (observation only; the host ignores its result)
- `message_sending` — Session Sentry multi-turn scan (cancels delivery on block) + PII tokenize outbound messages

The plugin ships an `openclaw.plugin.json` manifest declaring its config schema and all 11 tools.

### Tool output and PII

OpenClaw's only result-rewriting hook available to external plugins, `tool_result_persist`, is synchronous, and its asynchronous tool-result middleware is restricted to plugins bundled with OpenClaw. PII tokenization needs a VeriSwarm API call, so it cannot rewrite tool results; the injection banner (a local check) can. The banner is applied to the tool result OpenClaw persists to the session transcript.

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
        }
      }
    }
  }
}
```

## Session Sentry — Multi-Turn Exfiltration Detection

Session Sentry detects data-extraction patterns that only become visible across multiple conversation turns — e.g. an adversarial user probing an agent across turns to assemble sensitive data piecemeal. Each outbound agent message is submitted to `POST /v1/suite/guard/scan-session` with a per-conversation turn counter. The server accumulates session state and returns a risk score; if `blocked: true` is returned, the hook returns `{ cancel: true }` and OpenClaw does not deliver the message.

**Behavior when the platform flag is dormant:** The server returns `{enabled: false, blocked: false}`. The message is sent unmodified. No action needed — the toggle is safe to leave on at all times.

**Session identity:** The plugin derives a `session_id` from the hook context OpenClaw passes (`ctx.sessionKey`, then `ctx.sessionId`, then `ctx.conversationId`), falling back to legacy event fields (`conversation_id`, `conversationId`, `session_id`) for older hosts. The same identity scopes PII sessions, so `veriswarm_rehydrate` only restores tokens from the calling conversation. If no identity is present, all messages in this gateway process share the key `"default"`. Session ids longer than 64 characters are truncated by slicing to the first 64 chars; if your deployment uses ids where the first 64 chars are not unique, consider pre-hashing them before passing to OpenClaw.

**Fail-open guarantee:** Any network error, timeout, or unexpected API response causes the scan to be skipped and the message to be sent unmodified. An observable `[VeriSwarm] Session Sentry scan failed` warning is logged.

**Toggle:** `sessionScan: false` disables the scan entirely. No API calls are made.

**Memory caps:** The per-conversation turn counter map and the PII session map are each capped at 10,000 entries. When a cap is reached the least-recently-written conversation is evicted; an evicted conversation's turn counter restarts at 0 (the server treats this safely: under-counting, not over-blocking), and its oldest PII tokens can no longer be rehydrated.

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
