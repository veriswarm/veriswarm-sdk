"""Passport identity tools for VeriSwarm MCP."""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def get_credentials() -> str:
        """Issue a signed JWT Passport credential for the authenticated agent. Requires VERISWARM_AGENT_KEY."""
        try:
            result = client.post("/v1/passport/credentials/issue", use_agent_key=True)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def verify_credential(credential: str) -> str:
        """Verify a Passport JWT credential and return the decoded trust claims.

        credential: the JWT string issued by VeriSwarm Passport
        """
        try:
            result = client.post("/v1/passport/credentials/verify", json={"credential": credential})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def verify_identity(agent_id: str) -> str:
        """Mark an agent as identity-verified in VeriSwarm Passport (admin action).

        agent_id: the agent to mark as verified
        """
        try:
            result = client.post(f"/v1/passport/verify/{agent_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def check_delegation(agent_id: str, scope: str = "") -> str:
        """Check active delegation grants for an agent.

        agent_id: the agent whose delegations to check
        scope: optional scope filter, e.g. read, write, admin
        """
        try:
            params = {}
            if scope:
                params["scope"] = scope
            result = client.get(
                f"/v1/passport/delegations/{agent_id}",
                params=params if params else None,
            )
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
