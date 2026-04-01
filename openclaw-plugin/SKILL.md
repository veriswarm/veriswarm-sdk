---
name: veriswarm
description: "Trust scoring, PII protection, and audit for OpenClaw agents. Strips personal data before it reaches the LLM. Blocks dangerous tools. Detects prompt injection. Audits everything."
version: 0.1.0
metadata:
  openclaw:
    primaryEnv: VERISWARM_API_KEY
    requires:
      env:
        - VERISWARM_API_KEY
    emoji: "🦞🛡️"
    homepage: https://veriswarm.ai
    skillKey: veriswarm
---

# VeriSwarm Guard for OpenClaw

Protect your OpenClaw agent with VeriSwarm's full trust and security suite.

## What it does

**Automatic (transparent, no agent action needed):**
- Strips PII (names, emails, phones, SSNs, addresses, credit cards) from messages before they reach the LLM
- Strips PII from tool outputs before the agent sees them
- Scans tool outputs for prompt injection attempts
- Enforces tool allowlists and blocklists
- Logs every action to VeriSwarm's tamper-proof audit ledger

**Tools the agent can use:**
- `veriswarm_check_trust` — Get current trust scores
- `veriswarm_check_decision` — Ask if an action should be allowed
- `veriswarm_rehydrate` — Restore PII tokens when writing to real systems
- `veriswarm_guard_status` — Check active protections
- `veriswarm_get_credentials` — Issue a portable trust credential
- `veriswarm_verify_credential` — Verify another agent's credential
- `veriswarm_query_ledger` — Search the audit trail
- `veriswarm_verify_chain` — Verify audit chain integrity

## Setup

1. Get a free VeriSwarm API key at https://veriswarm.ai
2. Set `VERISWARM_API_KEY` in your OpenClaw environment
3. Install the plugin:
   ```bash
   openclaw plugins install veriswarm
   ```
4. Guard is now active. PII is automatically stripped from all messages and tool I/O.

## Configuration

In your OpenClaw config:
```json5
{
  plugins: {
    entries: {
      veriswarm: {
        enabled: true,
        config: {
          apiKey: "vsk_your_key_here",
          // All protections on by default:
          piiEnabled: true,
          policyEnabled: true,
          injectionScan: true,
          auditEnabled: true,
          // Optional: block specific tools
          blockedTools: ["dangerous_tool"],
        }
      }
    }
  }
}
```

## Rehydrating PII

When the agent needs to write tokenized data back to a real system:
1. Tool output arrives with tokens: "Customer [VS:PERSON:a1b2c3] at [VS:EMAIL:d4e5f6]"
2. Agent processes data (LLM never sees real PII)
3. Agent calls `veriswarm_rehydrate` to restore real values for the write
4. Every rehydration is logged for audit compliance
