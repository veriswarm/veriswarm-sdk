"""Agent management tools for VeriSwarm MCP."""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def register_agent(
        slug: str,
        display_name: str,
        description: str = "",
    ) -> str:
        """Register a new agent in VeriSwarm and return its agent_id.

        slug: URL-safe unique identifier for the agent, e.g. my-coding-agent
        display_name: human-readable name shown in dashboards
        description: optional description of the agent's purpose
        """
        try:
            body: dict = {"slug": slug, "display_name": display_name}
            if description:
                body["description"] = description
            result = client.post("/v1/public/agents/register", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_agent(agent_id: str) -> str:
        """Get a full agent profile including current trust scores and metadata.

        agent_id: the agent's unique identifier
        """
        try:
            result = client.get(f"/v1/public/agents/{agent_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_agent_timeline(agent_id: str, limit: int = 50) -> str:
        """Get an agent's event timeline.

        agent_id: the agent's unique identifier
        limit: maximum number of timeline entries (default 50)
        """
        try:
            result = client.get(
                f"/v1/public/agents/{agent_id}/timeline",
                params={"limit": limit},
            )
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_agent_flags(agent_id: str) -> str:
        """Get active moderation flags for an agent.

        agent_id: the agent's unique identifier
        """
        try:
            result = client.get(f"/v1/public/agents/{agent_id}/flags")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def list_agents(
        query: str = "",
        tier: str = "",
        page: int = 1,
    ) -> str:
        """List agents in the workspace. Supports search and filtering by trust tier.

        query: optional search string to filter agents by name or slug
        tier: optional tier filter — trusted, standard, restricted, or blocked
        page: page number for pagination (default 1)
        """
        try:
            params: dict = {"page": page}
            if query:
                params["q"] = query
            if tier:
                params["tier"] = tier
            result = client.get("/v1/agents", params=params)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
