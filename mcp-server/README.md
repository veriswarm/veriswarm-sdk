# VeriSwarm MCP Server

Trust infrastructure for AI agents via Model Context Protocol.

## Quick Start

```bash
pip install veriswarm-mcp
veriswarm-setup
```

The setup wizard configures everything for your platform (Claude Code, Gemini CLI, or Codex):

1. **MCP Server** — 90+ tools spanning trust scoring, Guard security, Passport identity (including JIT access grants), Vault audit, compliance (OWASP/EU AI Act/NIST/ISO 42001), Cedar policies, ABAC agent attributes, SRE (circuit breakers + SLOs), context governance, cross-model verification, content provenance (EU AI Act Art. 50), and A2A transport keys
2. **Guard Hooks** — Automatic PII protection for prompts and tool calls
3. **Guard Proxy** — Transparent MCP interception for any tool server (optional)

### What the hooks do

| Hook | Event | Action |
|------|-------|--------|
| Prompt Guard | `UserPromptSubmit` | Blocks prompts containing PII (emails, SSNs, etc.) |
| Tool Input Guard | `PreToolUse` | Tokenizes PII in tool arguments before execution |
| Tool Output Guard | `PostToolUse` | Tokenizes PII in tool responses before the LLM sees them |

### Manual setup

If you prefer manual configuration:

```json
{
  "mcpServers": {
    "veriswarm": {
      "command": "python",
      "args": ["-m", "src"],
      "env": {
        "VERISWARM_API_URL": "https://api.veriswarm.ai",
        "VERISWARM_API_KEY": "vs_your_platform_key"
      }
    }
  }
}
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `VERISWARM_API_URL` | No | API base URL (default: `https://api.veriswarm.ai`) |
| `VERISWARM_API_KEY` | Yes (or `AGENT_KEY`) | Platform API key for workspace operations |
| `VERISWARM_AGENT_KEY` | Yes (or `API_KEY`) | Agent-scoped key for self-reporting tools |

## Tools (67 total)

> **Auth note:** Tools marked with (session) require `x-account-access-token` and are not available with API key only. All other tools work with `x-api-key`.

### Trust Scoring (6)
| Tool | Description |
|---|---|
| `check_trust` | Get agent's current trust scores, policy tier, and risk band |
| `check_decision` | Check if an agent is allowed to perform an action (allow/review/deny) |
| `get_my_score` | Get your own trust scores with improvement guidance (agent key) |
| `get_score_history` | Get score history over time for an agent |
| `get_score_breakdown` | Get detailed score breakdown with contributing factors |
| `explain_score` | Get human-readable explanation of an agent's scores |

### Event Reporting (4)
| Tool | Description |
|---|---|
| `report_action` | Report a generic behavioral event for scoring |
| `report_tool_call` | Shorthand for tool.call.success / tool.call.failure events |
| `report_interaction` | Report an agent-to-agent interaction |
| `report_incident` | Report a security incident for Guard review |

### Guard Security (12)
| Tool | Description |
|---|---|
| `scan_tool` | Request a security scan for a tool or MCP server |
| `scan_injection` | Scan text for prompt injection patterns |
| `check_tool_allowed` | Check if a tool is permitted under active Guard policies |
| `get_findings` | List Guard security findings, optionally filtered by agent |
| `list_guard_policies` | List all active Guard policies for the workspace |
| `kill_agent` | Activate kill switch for an agent (blocks all trust decisions) |
| `unkill_agent` | Deactivate kill switch, restoring normal processing |
| `tokenize_pii` | Remove PII from text, replacing with safe tokens |
| `rehydrate_pii` | Restore original PII values from VeriSwarm tokens |
| `get_pii_session` | Get details of a PII tokenization session |
| `revoke_pii_session` | Revoke a PII session, deleting all stored tokens |

### Passport Identity (4)
| Tool | Description |
|---|---|
| `get_credentials` | Issue a signed JWT Passport credential (agent key required) |
| `verify_credential` | Verify a Passport JWT and return decoded trust claims |
| `verify_identity` | Mark an agent as identity-verified (admin action) |
| `check_delegation` | Check active delegation grants for an agent |

### Vault Audit (3)
| Tool | Description |
|---|---|
| `query_ledger` | Query the immutable Vault audit ledger |
| `verify_chain` | Verify hash-chain integrity of the Vault ledger |
| `export_vault` | Create a Vault export job (JSON or CSV) |

### Agent Management (5)
| Tool | Description |
|---|---|
| `register_agent` | Register a new agent and return its agent_id |
| `get_agent` | Get full agent profile including trust scores |
| `get_agent_timeline` | Get an agent's event timeline |
| `get_agent_flags` | Get active moderation flags for an agent |
| `list_agents` | List workspace agents with search and tier filtering |

### Platform & Workspace (9)
| Tool | Description |
|---|---|
| `platform_status` | Check platform health, uptime, and feature flags |
| `get_scoring_profile` | Get workspace scoring profile and weights |
| `set_scoring_profile` | Set workspace scoring profile |
| `list_notifications` | List recent workspace notifications |
| `get_ip_allowlist` | Get IP allowlist configuration |
| `set_ip_allowlist` | Set IP allowlist CIDRs |
| `get_custom_domain` | Get custom domain configuration |
| `set_custom_domain` | Set a custom domain |
| `list_team_members` | List workspace team members |
| `invite_team_member` | Invite a new team member |

### Conversation Analytics (2)
| Tool | Description |
|---|---|
| `get_agent_analytics` | Get aggregated quality analytics for an agent (resolution, accuracy, tone, efficiency, security) |
| `get_cost_recommendations` | Get cost optimization recommendations (model downgrades, KB gaps, prompt tuning) |

### Security Testing (3)
| Tool | Description |
|---|---|
| `list_red_team_attacks` | List available adversarial attack patterns (36 attacks across 5 categories) |
| `check_tool_permission` | Check trust-gated permission for a tool based on agent's trust score |
| `score_conversation_security` | Compute per-conversation security grade (A-F) from Guard + Vault data |

### GDPR Compliance (3)
| Tool | Description |
|---|---|
| `forget_contact` | Delete all data associated with a contact (with cryptographic deletion proof) |
| `list_deletion_records` | List GDPR deletion records with verification hashes |
| `verify_deletion` | Verify a deletion record exists and return its proof |

### A2A Trust (2)
| Tool | Description |
|---|---|
| `get_agent_reputation` | Get cross-platform reputation score for an agent |
| `get_a2a_history` | Get agent-to-agent interaction history (inbound or outbound) |

### Benchmarking & Operations (2)
| Tool | Description |
|---|---|
| `get_benchmark_history` | Get benchmark results for an agent across versions |
| `get_provider_health` | Get LLM provider health status (success rate, latency, cooldown) |

## Development

```bash
cd packages/mcp-server
pip install -e .
python -m pytest tests/ -v
```
