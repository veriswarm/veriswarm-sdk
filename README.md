# VeriSwarm SDK & Integrations

[![pip veriswarm](https://img.shields.io/pypi/v/veriswarm?label=pip%20veriswarm)](https://pypi.org/project/veriswarm/)
[![pip veriswarm-mcp](https://img.shields.io/pypi/v/veriswarm-mcp?label=pip%20veriswarm-mcp)](https://pypi.org/project/veriswarm-mcp/)
[![npm @veriswarm/sdk](https://img.shields.io/npm/v/@veriswarm/sdk?label=npm%20%40veriswarm%2Fsdk)](https://www.npmjs.com/package/@veriswarm/sdk)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.veriswarm%2Fveriswarm--mcp-1f6feb)](https://github.com/mcp/veriswarm/veriswarm-mcp)

Official client libraries, MCP server, and plugins for [VeriSwarm](https://veriswarm.ai) — trust infrastructure for AI agents.

## Packages

| Package | Language | Install | Description |
|---------|----------|---------|-------------|
| [**Python SDK**](./python/) | Python | `pip install veriswarm` | REST client with Workflows, credential issuance, scoring profiles, LangChain adapter |
| [**Node.js SDK**](./node/) | JavaScript | `npm install @veriswarm/sdk` | ESM client for decisions, events, Workflows, agent management |
| [**MCP Server**](./mcp-server/) | Python | `pip install veriswarm-mcp` | 89 MCP tools for trust scoring, Guard, Passport, Vault, Workflows, Compliance (OWASP/EU AI Act/NIST/ISO 42001), Cedar policies + ABAC attributes, SRE, context governance, and content provenance (EU AI Act Art. 50). Works with Claude Desktop, Cursor, and any MCP client. (`approve_jit_grant` and `issue_jit_token` are deliberately not exposed to the LLM — those actions live behind an authenticated session in the web UI.) |
| [**OpenClaw Plugin**](./openclaw-plugin/) | TypeScript | `openclaw plugins install veriswarm` | 11 tools + 5 hooks for OpenClaw agents. Local secret redaction, PII tokenization, policy enforcement, Session Sentry, audit. Per-feature enable/disable. |
| [**GitHub Action**](./github-action/) | Python | GitHub Marketplace | CI/CD trust gate — check agent trust scores in your pipeline |
| [**JSON Schemas**](./schemas/) | JSON | `npm install @veriswarm/schemas` | Schema definitions for events, profiles, scores, and workflows |

## Secret & PII protection at a glance

The packages share setting names but not behaviour. "Redacted locally" means replaced in-process, before any
network call; "fails closed" lists what blocks (or withholds) instead of passing data through when a check
can't run.

| Package | Setting (default) | Redacted locally | Sent to the VeriSwarm API | Fails closed |
|---------|-------------------|------------------|---------------------------|--------------|
| **Node SDK** | `secretsDetection` (`false`) | When on, `guardOutboundText()` redacts provider-prefix secrets (`ghp_`, `sk-`, `AKIA`, …). When off it is a no-op. Other methods are not filtered | When on and a secret was found, the already-redacted text, for PII tokenization. Everything else you pass to a method is sent as-is | `guardOutboundText()` returns the locally redacted text if tokenization fails |
| **Python SDK** | `secrets_detection` (`False`) | Same as the Node SDK, via `guard_outbound_text()` | Same as the Node SDK | Same as the Node SDK |
| **Python adapters** (decorator, Claude Agent SDK, OpenAI Agents, CrewAI; LangChain handler) | `guard_secrets` (`True`), `guard_pii` (`True`). The LangChain handler always guards secrets, does no PII tokenization, and enforces decisions only with `enforce=True` | Secrets in string tool arguments, string tool output, error messages and audit events | The trust-decision check (tool name), and secret-redacted strings for PII tokenization; wrapped functions receive the tokenized arguments (non-string arguments pass unchanged) | Anything but an explicit `allow` decision (including `review` and API errors) blocks the call; an input PII-tokenization failure blocks it; output that can't be tokenized, or a secret check that errors, is replaced with `[VS:REDACTED:guard_unavailable]` |
| **MCP Guard hooks** (Claude Code) | `GUARD_SECRETS_DETECTION` (off), `GUARD_BLOCK_PROMPT_PII` (on), `GUARD_PII_FAIL_OPEN` (off) | Always: secrets in prompts (the prompt is blocked), MCP tool arguments and MCP tool responses | With `VERISWARM_API_KEY` set: prompts (a prompt with a secret is blocked before this) and secret-redacted tool arguments/responses, for PII tokenization. With `GUARD_SECRETS_DETECTION=1`, tool-argument strings that contain a secret are sent unredacted first, for recoverable tokens | Secret checks block. A tool-argument PII scan that can't finish blocks the call (unless `GUARD_PII_FAIL_OPEN=1`); a tool-response scan that can't finish withholds the output. The prompt PII check fails open with a warning |
| **OpenClaw plugin** | `secretsDetection` (`false`), `piiEnabled` (`true`), `failOpen` (`false`) | Always: secrets in tool params and outbound messages (with `secretsDetection` on, these block / cancel instead). Tool results: structured PII patterns, plus secrets when `secretsDetection` is on | Secret-redacted param strings and message text, for PII tokenization and Session Sentry | PII tokenization, Session Sentry and hook errors block / cancel / withhold unless `failOpen`; missing secret rules always block. With `secretsDetection` off, another plugin's approval request can drop the param rewrite, so the tool itself may receive the secret |
| **GitHub Action** | `fail-on-pii`, `fail-on-injection`, `fail-on-deny`, `fail-on-ci-exfil` (all `true`) | Nothing. Sensitive-named files (`.env`, keys, `.git/`) and files outside the workspace are skipped | Scanned file chunks (scan mode) and CI files/diffs (ci-exfil mode), as-is | An enabled gate fails on API errors or unexpected responses. The decision gate fails only on `deny`: a `review` decision passes CI, unlike the Python adapters |

## Quick Start

### MCP Server (Recommended)

Add to your MCP client config (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "veriswarm": {
      "command": "python3",
      "args": ["-m", "veriswarm_mcp"],
      "env": {
        "VERISWARM_API_URL": "https://api.veriswarm.ai",
        "VERISWARM_API_KEY": "YOUR_API_KEY"
      }
    }
  }
}
```

Or use the setup CLI:

```bash
pip install veriswarm-mcp
veriswarm-setup --platform claude --api-key YOUR_API_KEY
```

This installs the MCP server, Guard hooks (PII protection + activity logging), and Guard Proxy config.

### Python SDK

```python
from veriswarm import VeriSwarmClient

client = VeriSwarmClient("https://api.veriswarm.ai", "YOUR_API_KEY")

# Register an agent
agent = client.register_agent({"slug": "my-agent", "display_name": "My Agent"})

# Check if an action should be allowed
result = client.check_decision(agent_id="agt_123", action_type="send_email")
print(result["decision"])  # "allow", "review", or "deny"

# Ingest events
client.ingest_event(
    event_id="evt_001", agent_id="agt_123", source_type="platform",
    event_type="task.completed", occurred_at="2026-04-01T00:00:00Z",
    payload={"task": "onboarding", "success": True}
)
```

### Node.js SDK

```javascript
import { VeriSwarmClient } from '@veriswarm/sdk'

const client = new VeriSwarmClient({
  baseUrl: 'https://api.veriswarm.ai',
  apiKey: 'YOUR_API_KEY'
})

const result = await client.checkDecision({
  agentId: 'agt_123',
  actionType: 'send_email'
})
```

### OpenClaw Plugin

```json5
{
  plugins: {
    entries: {
      veriswarm: {
        enabled: true,
        config: {
          apiKey: "YOUR_API_KEY",
          piiEnabled: true,
          policyEnabled: true,
          injectionScan: true,
          auditEnabled: true
        }
      }
    }
  }
}
```

## Free Plan

Get started with no credit card:
- 5,000 trust score queries/day
- Up to 10 agents
- Unlimited event ingestion
- Portable credentials issued on demand (rate-limited per plan; see [pricing](https://veriswarm.ai/pricing) for current limits)

Sign up at [veriswarm.ai](https://veriswarm.ai/auth?mode=register).

## Links

- [VeriSwarm Platform](https://veriswarm.ai)
- [Documentation](https://veriswarm.ai/docs)
- [API Reference](https://veriswarm.ai/docs/api)
- [Quickstart](https://veriswarm.ai/docs/quickstart)
- [Pricing](https://veriswarm.ai/pricing)

## License

MIT
