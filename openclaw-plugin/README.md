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
| **PII Tokenization** | Personal data (names, emails, phones, SSNs, addresses, cards) stripped from messages and tool I/O before the LLM sees them |
| **Tool Policy** | Blocked tools return errors. Allowlist mode restricts to approved tools only. |
| **Injection Scan** | Tool outputs scanned for prompt injection patterns before reaching the agent |
| **Audit** | Every tool call, block, and PII event logged to VeriSwarm Vault |
| **Session Sentry** | Multi-turn exfiltration detection: each outbound message is scanned against the full conversation history. If the session-level risk score crosses the configured threshold the outbound message is replaced with a Guard refusal. Fail-open — any API error lets the message through unchanged. |

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

### Hooks Registered (3)

- `before_tool_call` — Policy check + PII tokenize inputs
- `after_tool_call` — PII tokenize outputs + injection scan + audit
- `message_sending` — PII tokenize outbound messages to LLM + Session Sentry multi-turn scan

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

Session Sentry detects data-extraction patterns that only become visible across multiple conversation turns — e.g. an adversarial user probing an agent across turns to assemble sensitive data piecemeal. Each outbound agent message is submitted to `POST /v1/suite/guard/scan-session` with a per-conversation turn counter. The server accumulates session state and returns a risk score; if `blocked: true` is returned, the outbound message is replaced with a Guard refusal before it reaches the LLM.

**Behavior when the platform flag is dormant:** The server returns `{enabled: false, blocked: false}`. The message is sent unmodified. No action needed — the toggle is safe to leave on at all times.

**Session identity:** The plugin derives a `session_id` from `event.conversation_id`, `event.conversationId`, or `event.session_id` (first truthy value). If none is present, all messages in this gateway process share the key `"default"` — a limitation when OpenClaw does not expose a conversation id on the `message_sending` event. Session ids longer than 64 characters are truncated by slicing to the first 64 chars; if your deployment uses ids where the first 64 chars are not unique, consider pre-hashing them before passing to OpenClaw.

**Fail-open guarantee:** Any network error, timeout, or unexpected API response causes the scan to be skipped and the message to be sent unmodified. An observable `[VeriSwarm] Session Sentry scan failed` warning is logged.

**Toggle:** `sessionScan: false` disables the scan entirely. No API calls are made.

**Counter memory cap:** The per-conversation turn counter map is capped at 10,000 entries. When the cap is reached the oldest-inserted conversation id is evicted (FIFO); if that conversation is still active its turn counter resets to 0 on the next message, which the server treats safely (under-counting, not over-blocking).

## Development

```bash
cd packages/openclaw-plugin
npm install
npm run build
openclaw plugins install -l .
```

## Links

- [VeriSwarm](https://veriswarm.ai)
- [Guard Documentation](https://veriswarm.ai/docs/guard)
- [API Reference](https://veriswarm.ai/docs/api)
- [OpenClaw](https://openclaw.ai)
