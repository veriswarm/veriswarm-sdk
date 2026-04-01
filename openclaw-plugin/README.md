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
- `message_sending` — PII tokenize outbound messages to LLM

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
          blockedTools: ["dangerous_tool"],      // Optional blocklist
          allowedTools: [],                     // Optional allowlist (empty = allow all)
        }
      }
    }
  }
}
```

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
