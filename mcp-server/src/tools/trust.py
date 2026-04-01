"""Trust scoring tools for VeriSwarm MCP."""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def check_trust(agent_id: str) -> str:
        """Get an agent's current trust scores, policy tier, and risk band."""
        try:
            result = client.get(f"/v1/public/agents/{agent_id}/scores/current")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def check_decision(
        agent_id: str,
        action_type: str,
        resource_type: str = "",
    ) -> str:
        """Check if an agent is allowed to perform an action. Returns allow, review, or deny.

        Uses x-api-key auth. The agent must belong to the tenant that owns the API key."""
        try:
            body: dict = {"agent_id": agent_id, "action_type": action_type}
            if resource_type:
                body["resource_type"] = resource_type
            result = client.post("/v1/decisions/check", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_my_score() -> str:
        """Get your own trust scores with improvement guidance.

        Requires agent key auth (VERISWARM_AGENT_KEY). Not available with API key only."""
        try:
            result = client.get("/v1/agents/me/scores", use_agent_key=True)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_score_history(agent_id: str, limit: int = 10) -> str:
        """Get score history over time for an agent."""
        try:
            result = client.get(
                f"/v1/public/agents/{agent_id}/scores/history",
                params={"limit": limit},
            )
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_score_breakdown(agent_id: str) -> str:
        """Get detailed score breakdown with contributing factors for an agent."""
        try:
            result = client.get(f"/v1/public/agents/{agent_id}/scores/breakdown")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def explain_score(agent_id: str) -> str:
        """Get a human-readable explanation of an agent's current trust scores."""
        try:
            result = client.get(f"/v1/public/agents/{agent_id}/scores/current")
            explanations = result.get("explanations", [])
            return "\n".join(explanations) if explanations else "No score explanations available."
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
