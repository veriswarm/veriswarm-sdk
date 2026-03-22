"""VeriSwarm MCP Server — Trust infrastructure for AI agents."""
from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP

from .client import VeriSwarmAPIClient
from .tools import agents, events, evidence, guard, passport, platform, trust


def create_server() -> tuple[FastMCP, VeriSwarmAPIClient]:
    api_url = os.environ.get("VERISWARM_API_URL", "https://api.veriswarm.ai")
    api_key = os.environ.get("VERISWARM_API_KEY", "")
    agent_key = os.environ.get("VERISWARM_AGENT_KEY", "")

    if not api_key and not agent_key:
        print("Warning: No VERISWARM_API_KEY or VERISWARM_AGENT_KEY set", file=sys.stderr)

    client = VeriSwarmAPIClient(api_url, api_key, agent_key)
    server = FastMCP("veriswarm")

    # Register all tools
    trust.register(server, client)
    events.register(server, client)
    guard.register(server, client)
    passport.register(server, client)
    evidence.register(server, client)
    agents.register(server, client)
    platform.register(server, client)

    return server, client


def main() -> None:
    server, _ = create_server()
    server.run(transport="stdio")
