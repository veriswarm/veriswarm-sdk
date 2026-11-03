# VeriSwarm MCP Server

<!-- mcp-name: io.github.veriswarm/veriswarm-mcp -->

[![PyPI version](https://img.shields.io/pypi/v/veriswarm-mcp)](https://pypi.org/project/veriswarm-mcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/veriswarm-mcp)](https://pypi.org/project/veriswarm-mcp/)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.veriswarm%2Fveriswarm--mcp-1f6feb)](https://github.com/mcp/veriswarm/veriswarm-mcp)

Trust infrastructure for AI agents via Model Context Protocol.

## Quick Start

```bash
pip install veriswarm-mcp
veriswarm-setup
```

The setup wizard configures everything for your platform (Claude Code, Gemini CLI, or Codex):

1. **MCP Server** — 102 tools spanning trust scoring, Guard security, Passport identity (including JIT access grants), Vault audit, compliance (OWASP/EU AI Act/NIST/ISO 42001), Cedar policies, ABAC agent attributes, SRE (circuit breakers + SLOs), context governance, cross-model verification, content provenance (EU AI Act Art. 50), and A2A transport keys
2. **Guard Hooks** — Automatic PII protection for prompts and tool calls
3. **Guard Proxy** — Transparent MCP interception for any tool server (optional)

### What the hooks do

| Hook | Event | Action |
|------|-------|--------|
| Prompt Guard | `UserPromptSubmit` | Blocks prompts containing secrets (always) or PII (on by default; `GUARD_BLOCK_PROMPT_PII=0` turns the PII check off) |
| Tool Input Guard | `PreToolUse` | Redacts secrets and tokenizes PII in MCP tool arguments before execution |
| Tool Output Guard | `PostToolUse` | Redacts secrets and tokenizes PII in MCP tool responses before the LLM sees them |

How the guards behave when something goes wrong or needs a decision:

- **Rewritten tool calls ask for confirmation.** When the Tool Input Guard changes an MCP call's arguments,
  it returns the rewritten call with permission decision `ask`, so you review it before it runs. In headless
  runs (`claude -p`) nobody can answer that prompt, so those calls are denied.
- **Tool output is withheld, not leaked.** If the PII scan of a tool response can't finish (API unreachable,
  invalid response, or out of time), the response is replaced with a "withheld" notice.
- **Prompt PII check fails open.** If the PII check on a prompt can't finish, the prompt is sent and you see
  a warning. Secrets in prompts are checked locally and always blocked.
- **Secrets are always redacted locally.** Known-prefix secrets (`ghp_`, `sk-`, `AKIA`, …) are caught without
  any network call in prompts (blocked), MCP tool arguments, and MCP tool responses (redacted), whatever
  `GUARD_SECRETS_DETECTION` is set to. Any error in a guard blocks the prompt or tool call, or withholds the
  tool output.
- **Time limit.** All API calls share a 6-second wall-clock budget inside the 10-second hook timeout. When it
  runs out, secrets are redacted locally and unscanned tool output is withheld.
- **A broken secret-rules manifest blocks.** If the bundled secret rules can't load, prompts and MCP tool
  calls are blocked and MCP tool output is withheld. Reinstall the package to fix it.
- **Upload warnings.** Activity-upload problems (events rejected as invalid, buffer evictions, missing
  `GUARD_AGENT_ID`) are recorded in `~/.veriswarm/activity_reporter.log`; the next hook run prints a one-line
  summary to stderr and clears the file.
- **Hook failures block.** `veriswarm-setup` installs the prompt and tool-input guards with
  `"onFailure": "block"`, so a crash or timeout blocks the prompt or tool call instead of letting it through.
  This needs Claude Code v2.1.295 or later.

### Manual setup

If you prefer manual configuration:

```json
{
  "mcpServers": {
    "veriswarm": {
      "command": "python",
      "args": ["-m", "veriswarm_mcp"],
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
| `GUARD_AGENT_ID` | For activity upload | Agent that Guard hook activity events are attributed to. Without it, events stay in the local buffer and are not uploaded |
| `GUARD_BLOCK_PROMPT_PII` | No | Block prompts that contain PII (default on). Set to `0` to allow them. Prompts with secrets are always blocked |
| `GUARD_SECRETS_DETECTION` | No | `1` also sends secrets found in MCP tool arguments to the Guard API for tokenization (recoverable tokens) before falling back to local redaction. Local secret redaction in prompts, tool arguments and tool responses is always on, regardless of this setting |
| `GUARD_PII_EXEMPT_PREFIXES` | No | Comma-separated tool-name prefixes (e.g. `mcp__mystore__`) that skip PII tokenization and the PII warning. Empty by default. The secret tripwire still applies |

## Tools (102 total)

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
| `guard_scan_session` | Score one conversation turn for multi-turn exfiltration risk (Session Sentry); check `blocked` before sending the reply |

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

### Platform & Workspace (10)
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

### A2A Trust (3)
| Tool | Description |
|---|---|
| `get_agent_reputation` | Get cross-platform reputation score for an agent |
| `get_a2a_history` | Get agent-to-agent interaction history (inbound or outbound) |
| `invoke_a2a_agent` | Submit a task to a trust-ranked agent and wait for the result — submits, polls until the task is terminal (completed/failed/canceled) or `max_wait_seconds` elapses, and returns the final task (status + artifacts). On timeout returns the latest task with `"timed_out": true`; keep polling with `get_a2a_task`. Convenience over `submit_a2a_task` + `get_a2a_task`. |

### Benchmarking & Operations (2)
| Tool | Description |
|---|---|
| `get_benchmark_history` | Get benchmark results for an agent across versions |
| `get_provider_health` | Get LLM provider health status (success rate, latency, cooldown) |

### A2A Protocol (5)
| Tool | Description |
|---|---|
| `list_a2a_catalog` | List the tenant's trust-ranked A2A agent catalog |
| `get_a2a_agent_card` | Get an A2A agent card for the given agent |
| `submit_a2a_task` | Submit a task to an agent via the A2A protocol |
| `get_a2a_task` | Get the status + result of an A2A task |
| `cancel_a2a_task` | Cancel an in-flight A2A task |

### Human Approvals (5)
| Tool | Description |
|---|---|
| `create_approval` | Submit a new approval request to the operator queue |
| `list_approvals` | List approval requests for the authenticated tenant |
| `get_approval` | Get a single approval request by id (`apr_*`) |
| `approve_approval` | Approve a pending approval request |
| `reject_approval` | Reject a pending approval request |

### Cortex Workflows (12)
| Tool | Description |
|---|---|
| `list_workflows` | List all Cortex Workflows for the current tenant |
| `get_workflow` | Get details of a specific workflow including recent executions |
| `create_workflow` | Create a new Cortex Workflow from a JSON definition |
| `run_workflow` | Manually trigger a workflow execution |
| `get_execution` | Get the status and step-by-step results of a workflow execution |
| `activate_workflow` | Activate a workflow so its triggers (schedule/event/webhook) start firing |
| `deactivate_workflow` | Deactivate a workflow, stopping all triggers |
| `list_workflow_templates` | List available workflow templates (both built-in and custom) |
| `deploy_template` | Deploy a workflow template as a new workflow in your workspace |
| `workflow_stats` | Get workflow usage statistics: execution counts, success rates, and LLM costs |
| `cancel_workflow_execution` | Cancel a running or paused workflow execution |
| `retry_workflow_execution` | Retry a failed workflow execution from where it left off |

### Compliance, Policy & SRE (23)
| Tool | Description |
|---|---|
| `get_owasp_attestation` | Get a per-tenant OWASP Agentic AI Top 10 (2026) coverage report |
| `list_compliance_frameworks` | List supported compliance frameworks (eu-ai-act, nist-ai-rmf, iso-42001) |
| `get_compliance_report` | Get a per-tenant compliance report for a specific framework |
| `list_cedar_policies` | List active Cedar declarative policies for the tenant |
| `validate_cedar_policy` | Validate Cedar policy syntax without persisting |
| `test_cedar_policy` | Dry-run a Cedar policy against test input. Returns the decision |
| `get_sre_dashboard` | Combined SRE dashboard — circuit breakers + SLO + error budget + provider health |
| `get_circuit_breakers` | Get current state of all LLM provider circuit breakers (closed/open/half-open) |
| `reset_circuit_breaker` | Manually reset a circuit breaker to closed state (e.g., after fixing a provider outage) |
| `get_error_budget` | Get error budget status based on tenant SLO targets and recent LLM usage |
| `get_context_dashboard` | Combined context governance dashboard — topics + quality + gaps |
| `get_context_gaps` | Detect agents with high failure rates and low knowledge base coverage |
| `scan_mcp_tools` | Scan MCP tool definitions for security risks (pre-deploy audit) |
| `scan_ci` | Scan CI workflow YAML + Dockerfiles for secret-exfiltration risk |
| `verify_response` | Cross-model verification — route a response through multiple LLMs and check consensus |
| `provision_a2a_keys` | Provision Ed25519 transport keys for an agent. Returns the public key |
| `label_content` | Generate an Ed25519-signed provenance manifest for AI-generated content |
| `get_content_provenance` | Public lookup of a provenance manifest by SHA-256 content hash |
| `get_agent_attributes` | Read the tenant-defined ABAC attributes for an agent |
| `set_agent_attributes` | Set ABAC attributes for an agent (replaces existing) |
| `request_jit_grant` | Request a just-in-time access grant for an agent |
| `revoke_jit_grant` | Revoke an approved JIT grant immediately |
| `list_jit_grants` | List JIT grants for the tenant, optionally filtered by agent or status |

## Development

```bash
cd packages/mcp-server
pip install -e .
python -m pytest tests/ -v
```
