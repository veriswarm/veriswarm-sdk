# VeriSwarm MCP Server

Trust infrastructure for AI agents via Model Context Protocol.

## Quick Start

```bash
pip install veriswarm-mcp
```

Add to your MCP client config (Claude Desktop, Cursor, etc.):

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

## Tools (24 total)

### Trust Scoring
| Tool | Description |
|---|---|
| `check_trust` | Get agent's current trust scores, policy tier, and risk band |
| `check_decision` | Check if an agent is allowed to perform an action (allow/review/deny) |
| `get_my_score` | Get your own trust scores with improvement guidance (agent key) |
| `get_score_history` | Get score history over time for an agent |
| `explain_score` | Get human-readable explanation of an agent's scores |

### Event Reporting
| Tool | Description |
|---|---|
| `report_action` | Report a generic behavioral event for scoring |
| `report_tool_call` | Shorthand for tool.call.success / tool.call.failure events |
| `report_interaction` | Report an agent-to-agent interaction |
| `report_incident` | Report a security incident for Guard review |

### Guard Security
| Tool | Description |
|---|---|
| `scan_tool` | Request a security scan for a tool or MCP server |
| `check_tool_allowed` | Check if a tool is permitted under active Guard policies |
| `get_findings` | List Guard security findings, optionally filtered by agent |
| `kill_agent` | Activate kill switch for an agent (blocks all trust decisions) |
| `unkill_agent` | Deactivate kill switch, restoring normal processing |

### Passport Identity
| Tool | Description |
|---|---|
| `get_credentials` | Issue a signed JWT Passport credential (agent key required) |
| `verify_credential` | Verify a Passport JWT and return decoded trust claims |
| `verify_identity` | Mark an agent as identity-verified (admin action) |
| `check_delegation` | Check active delegation grants for an agent |

### Evidence Audit
| Tool | Description |
|---|---|
| `query_ledger` | Query the immutable Evidence audit ledger |
| `verify_chain` | Verify hash-chain integrity of the Evidence ledger |
| `export_evidence` | Create an Evidence export job (JSON or CSV) |

### Agent Management
| Tool | Description |
|---|---|
| `register_agent` | Register a new agent and return its agent_id |
| `get_agent` | Get full agent profile including trust scores |
| `list_agents` | List workspace agents with search and tier filtering |

### Platform
| Tool | Description |
|---|---|
| `platform_status` | Check platform health, uptime, and feature flags |

## Development

```bash
cd packages/mcp-server
pip install -e .
python -m pytest tests/ -v
```
