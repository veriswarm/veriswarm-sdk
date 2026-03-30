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
            # Note: scan endpoint submits to guard findings pipeline
            result = client.post("/v1/suite/guard/findings", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def check_tool_allowed(tool_name: str) -> str:
        """Check whether a tool is permitted under active Guard policies for this workspace."""
        try:
            result = client.get("/v1/suite/guard/policies", params={"tool_name": tool_name})
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
            result = client.get("/v1/suite/guard/findings", params=params if params else None)
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
                f"/v1/suite/guard/kill/{agent_id}",
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
            result = client.post(f"/v1/suite/guard/unkill/{agent_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def tokenize_pii(text: str, agent_id: str = "", session_id: str = "") -> str:
        """Remove PII from text, replacing with safe tokens like [VS:EMAIL:a1b2c3].

        Use BEFORE sending text containing personal data to an LLM.
        The LLM will see tokens instead of real emails, phone numbers, SSNs, etc.
        Tokens carry type information so the LLM knows what kind of data was there.

        text: the text that may contain PII
        agent_id: optional agent ID to associate with the tokenization
        session_id: optional session ID to group tokens (auto-generated if empty)
        """
        try:
            body: dict = {"text": text}
            if agent_id:
                body["agent_id"] = agent_id
            if session_id:
                body["session_id"] = session_id
            result = client.post("/v1/suite/guard/pii/tokenize", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def scan_injection(text: str) -> str:
        """Scan text for prompt injection patterns.

        Returns is_injection (bool), confidence score, and matched patterns.
        """
        try:
            result = client.post("/v1/suite/guard/scan", json={"text": text})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_pii_session(session_id: str) -> str:
        """Get details of a PII tokenization session including all tokens created."""
        try:
            result = client.get(f"/v1/suite/guard/pii/sessions/{session_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def revoke_pii_session(session_id: str) -> str:
        """Revoke a PII tokenization session, deleting all stored tokens."""
        try:
            result = client.delete(f"/v1/suite/guard/pii/sessions/{session_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def list_guard_policies() -> str:
        """List all active Guard policies for the workspace."""
        try:
            result = client.get("/v1/suite/guard/policies")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def rehydrate_pii(text: str, session_id: str) -> str:
        """Restore original PII values from VeriSwarm tokens in text.

        Use AFTER the LLM has processed tokenized text and you need to write
        the real values back to a database, email, CRM, or other system.

        text: text containing VeriSwarm tokens like [VS:EMAIL:a1b2c3]
        session_id: the session ID from the original tokenize_pii call
        """
        try:
            result = client.post("/v1/suite/guard/pii/rehydrate", json={
                "text": text,
                "session_id": session_id,
            })
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
