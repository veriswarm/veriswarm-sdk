"""Vault audit ledger tools for VeriSwarm MCP."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import call_api, safe_error_response


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def query_ledger(agent_id: str = "", limit: int = 50) -> str:
        """Query the immutable Vault audit ledger. Optionally filter by agent.

        agent_id: filter ledger entries to a specific agent (optional)
        limit: maximum number of entries to return (default 50)
        """
        try:
            params: dict = {"limit": limit}
            if agent_id:
                params["agent_id"] = agent_id
            result = await call_api(client.get, "/v1/suite/vault/ledger", params=params)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="query_ledger")

    @server.tool()
    async def verify_chain(limit: int = 100) -> str:
        """Verify the hash-chain integrity of the Vault audit ledger.

        limit: number of recent entries to verify (default 100)
        """
        try:
            result = await call_api(client.get, "/v1/suite/vault/verify", params={"limit": limit})
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="verify_chain")

    @server.tool()
    async def export_vault(export_type: str = "json") -> str:
        """Create a Vault export job. Returns the job ID and status.

        export_type: format for the export — json or csv (default json)
        """
        try:
            result = await call_api(client.post, "/v1/suite/vault/export", json={"export_type": export_type})
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="export_vault")
