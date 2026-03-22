"""Guard security tools for VeriSwarm MCP."""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def scan_tool(tool_name: str, tool_config: str = "") -> str:
        """Request a Guard security scan for a tool or MCP server.

        tool_name: name of the tool or MCP server to scan
        tool_config: optional JSON string with tool configuration/schema details
        """
        try:
            body: dict = {"tool_name": tool_name}
            if tool_config:
                try:
                    body["tool_config"] = json.loads(tool_config)
                except json.JSONDecodeError:
                    body["tool_config"] = tool_config
            result = client.post("/v1/guard/scan", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def check_tool_allowed(tool_name: str) -> str:
        """Check whether a tool is permitted under active Guard policies for this workspace."""
        try:
            result = client.get("/v1/guard/policies/check", params={"tool_name": tool_name})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_findings(agent_id: str = "") -> str:
        """List Guard security findings. Optionally filter by agent_id."""
        try:
            params = {}
            if agent_id:
                params["agent_id"] = agent_id
            result = client.get("/v1/guard/findings", params=params if params else None)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def kill_agent(agent_id: str, reason: str) -> str:
        """Activate the kill switch for an agent, immediately blocking all trust decisions.

        agent_id: the agent to kill-switch
        reason: human-readable reason for the kill switch activation
        """
        try:
            result = client.post(
                f"/v1/guard/kill-switch/{agent_id}",
                json={"reason": reason},
            )
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def unkill_agent(agent_id: str) -> str:
        """Deactivate the kill switch for an agent, restoring normal trust decision processing."""
        try:
            result = client.delete(f"/v1/guard/kill-switch/{agent_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
