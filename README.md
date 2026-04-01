# VeriSwarm SDK & Integrations

Official client libraries, MCP server, and plugins for [VeriSwarm](https://veriswarm.ai) — trust infrastructure for AI agents.

## Packages

| Package | Language | Install | Description |
|---------|----------|---------|-------------|
| [**Python SDK**](./python/) | Python | `pip install veriswarm` | REST client with Workflows, credential issuance, scoring profiles, LangChain adapter |
| [**Node.js SDK**](./node/) | JavaScript | `npm install @veriswarm/sdk` | ESM client for decisions, events, Workflows, agent management |
| [**MCP Server**](./mcp-server/) | Python | `pip install veriswarm-mcp` | 65+ MCP tools for trust scoring, Guard, Passport, Vault, Workflows. Works with Claude Desktop, Cursor, and any MCP client. |
| [**OpenClaw Plugin**](./openclaw-plugin/) | TypeScript | `openclaw plugins install veriswarm` | 11 tools + 3 hooks for OpenClaw agents. PII tokenization, policy enforcement, audit. Per-feature enable/disable. |
| [**GitHub Action**](./github-action/) | Python | GitHub Marketplace | CI/CD trust gate — check agent trust scores in your pipeline |
| [**JSON Schemas**](./schemas/) | JSON | `npm install @veriswarm/schemas` | Schema definitions for events, profiles, scores, and workflows |

## Quick Start

### MCP Server (Recommended)

Add to your MCP client config (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "veriswarm": {
      "command": "python3",
      "args": ["-m", "src"],
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
from veriswarm_client import VeriSwarmClient

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
- Unlimited portable credentials

Sign up at [veriswarm.ai](https://veriswarm.ai/auth?mode=register).

## Links

- [VeriSwarm Platform](https://veriswarm.ai)
- [Documentation](https://veriswarm.ai/docs)
- [API Reference](https://veriswarm.ai/docs/api)
- [Quickstart](https://veriswarm.ai/docs/quickstart)
- [Pricing](https://veriswarm.ai/pricing)

## License

MIT
