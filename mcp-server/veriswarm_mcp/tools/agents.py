"""Agent management tools for VeriSwarm MCP."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import ToolValidationError, call_api, safe_error_response, safe_id


# Values the server matches against ScoreSnapshot.policy_tier
# (GET /v1/agents/overview?tier=...); "all" disables the filter.
POLICY_TIERS = ("tier_0", "tier_1", "tier_2", "tier_3", "all")


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
            result = await call_api(client.post, "/v1/public/agents/register", json=body)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="register_agent")

    @server.tool()
    async def get_agent(agent_id: str) -> str:
        """Get a full agent profile including current trust scores and metadata.

        agent_id: the agent's unique identifier
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            result = await call_api(client.get, f"/v1/public/agents/{agent_id}")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_agent")

    @server.tool()
    async def get_agent_timeline(agent_id: str, limit: int = 50) -> str:
        """Get an agent's event timeline.

        agent_id: the agent's unique identifier
        limit: maximum number of timeline entries (default 50)
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            result = await call_api(
                client.get,
                f"/v1/public/agents/{agent_id}/timeline",
                params={"limit": limit},
            )
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_agent_timeline")

    @server.tool()
    async def get_agent_flags(agent_id: str) -> str:
        """Get active moderation flags for an agent.

        agent_id: the agent's unique identifier
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            result = await call_api(client.get, f"/v1/public/agents/{agent_id}/flags")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_agent_flags")

    @server.tool()
    async def list_agents(
        query: str = "",
        tier: str = "",
        page: int = 1,
    ) -> str:
        """List agents in the workspace. Supports search and filtering by policy tier.

        query: optional search string to filter agents by name or slug
        tier: optional policy tier filter — tier_0 (most restricted), tier_1,
            tier_2, tier_3 (most trusted), or all
        page: page number for pagination (default 1)
        """
        try:
            if tier and tier not in POLICY_TIERS:
                raise ToolValidationError(
                    f"tier must be one of {', '.join(POLICY_TIERS)}"
                )
            params: dict = {"page": page}
            if query:
                params["query"] = query
            if tier:
                params["tier"] = tier
            result = await call_api(client.get, "/v1/agents/overview", params=params)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="list_agents")
