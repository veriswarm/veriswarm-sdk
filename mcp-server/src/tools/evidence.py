"""Evidence audit ledger tools for VeriSwarm MCP."""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def query_ledger(agent_id: str = "", limit: int = 50) -> str:
        """Query the immutable Evidence audit ledger. Optionally filter by agent.

        agent_id: filter ledger entries to a specific agent (optional)
        limit: maximum number of entries to return (default 50)
        """
        try:
            params: dict = {"limit": limit}
            if agent_id:
                params["agent_id"] = agent_id
            result = client.get("/v1/evidence/ledger", params=params)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def verify_chain(limit: int = 100) -> str:
        """Verify the hash-chain integrity of the Evidence ledger.

        limit: number of recent entries to verify (default 100)
        """
        try:
            result = client.get("/v1/evidence/chain/verify", params={"limit": limit})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def export_evidence(export_type: str = "json") -> str:
        """Create an Evidence export job. Returns the job ID and status.

        export_type: format for the export — json or csv (default json)
        """
        try:
            result = client.post("/v1/evidence/exports", json={"export_type": export_type})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
