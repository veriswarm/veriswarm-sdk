# VeriSwarm SDK & MCP Server

Official client libraries and MCP server for [VeriSwarm](https://veriswarm.ai) — trust infrastructure for AI agents.

## Packages

| Package | Language | Install | Description |
|---------|----------|---------|-------------|
| [**MCP Server**](./mcp-server/) | Python | `pip install veriswarm-mcp` | 25 MCP tools for trust scoring, Guard, Passport, Evidence. Works with Claude Desktop, Cursor, and any MCP client. |
| [**Python SDK**](./python/) | Python | `pip install veriswarm` | REST client with credential issuance, scoring profiles, LangChain adapter. |
| [**Node.js SDK**](./node/) | JavaScript | `npm install @veriswarm/sdk` | ESM client for decision checks, event ingestion, agent management. |

## Quick Start

### MCP Server (Recommended)

Add to your MCP client config:

```json
{
  "mcpServers": {
    "veriswarm": {
      "command": "python",
      "args": ["-m", "src"],
      "env": {
        "VERISWARM_API_URL": "https://api.veriswarm.ai",
        "VERISWARM_API_KEY": "vs_your_key"
      }
    }
  }
}
```

Your agent now has access to 25 trust tools: `check_trust`, `check_decision`, `report_tool_call`, `get_credentials`, `kill_agent`, and more.

### Python SDK

```python
from veriswarm_client import VeriSwarmClient

client = VeriSwarmClient("https://api.veriswarm.ai", "vs_your_key")

# Check if an agent is trusted
result = client.check_decision("agt_123", "post_message")
print(result["decision"])  # "allow", "review", or "deny"

# Report agent activity
client.ingest_event("evt_1", "agt_123", "agent", "tool.call.success",
                    payload={"tool_name": "web_search"})
```

### LangChain Integration

```python
from veriswarm.adapters.langchain import VeriSwarmCallbackHandler

handler = VeriSwarmCallbackHandler(api_key="vs_...", agent_id="agt_...")
agent = initialize_agent(tools, llm, callbacks=[handler])
# All tool calls are automatically reported to VeriSwarm
```

### Node.js SDK

```javascript
import { VeriSwarmClient } from '@veriswarm/sdk'

const client = new VeriSwarmClient({
  baseUrl: 'https://api.veriswarm.ai',
  apiKey: 'vs_your_key'
})

const result = await client.checkDecision({
  agentId: 'agt_123',
  actionType: 'post_message'
})
```

## Links

- [VeriSwarm Platform](https://veriswarm.ai)
- [API Documentation](https://veriswarm.ai/docs/api)
- [Agent Tracker](https://veriswarm.ai/operations)

## License

MIT
