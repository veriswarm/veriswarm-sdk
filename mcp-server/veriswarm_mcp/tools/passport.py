"""Passport identity tools for VeriSwarm MCP."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import call_api, safe_error_response, safe_id


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def get_credentials() -> str:
        """Issue a signed JWT Passport credential for the authenticated agent.

        Requires agent key auth (VERISWARM_AGENT_KEY). Not available with API key only.
        Also requires the platform signing key to be configured."""
        try:
            result = await call_api(client.post, "/v1/credentials/issue", use_agent_key=True)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_credentials")

    @server.tool()
    async def verify_credential(credential: str) -> str:
        """Verify a Passport JWT credential and return the decoded trust claims.

        credential: the JWT string issued by VeriSwarm Passport
        """
        try:
            result = await call_api(client.post, "/v1/credentials/verify", json={"credential": credential})
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="verify_credential")

    @server.tool()
    async def verify_identity(agent_id: str) -> str:
        """Mark an agent as identity-verified in VeriSwarm Passport (admin action).

        Requires session auth (x-account-access-token). Not available with API key only.

        agent_id: the agent to mark as verified
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            result = await call_api(client.post, f"/v1/suite/passport/verify/{agent_id}")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="verify_identity")

    @server.tool()
    async def check_delegation(agent_id: str, scope: str = "") -> str:
        """Check active delegation grants for an agent.

        Requires session auth (x-account-access-token). Not available with API key only.

        agent_id: the agent whose delegations to check
        scope: optional scope filter, e.g. read, write, admin
        """
        try:
            params = {"agent_id": agent_id}
            if scope:
                params["scope"] = scope
            result = await call_api(
                client.get,
                "/v1/suite/passport/delegations",
                params=params,
            )
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="check_delegation")
