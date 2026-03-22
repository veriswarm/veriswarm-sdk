"""Event reporting tools for VeriSwarm MCP."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def report_action(
        event_type: str,
        agent_id: str = "",
        payload: str = "",
    ) -> str:
        """Report a generic agent behavioral event to VeriSwarm for scoring.

        event_type: dot-separated event type, e.g. tool.call.success
        agent_id: the agent performing the action (optional if using agent key)
        payload: JSON string of additional event metadata (optional)
        """
        try:
            body: dict = {
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": json.loads(payload) if payload else {},
            }
            if agent_id:
                body["agent_id"] = agent_id
            result = client.post("/v1/events", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def report_tool_call(
        tool_name: str,
        success: bool = True,
        duration_ms: int = None,
        error_type: str = "",
        agent_id: str = "",
    ) -> str:
        """Report a tool call event. Shorthand for tool.call.success / tool.call.failure events."""
        try:
            event_type = "tool.call.success" if success else "tool.call.failure"
            payload: dict = {"tool_name": tool_name}
            if duration_ms is not None:
                payload["duration_ms"] = duration_ms
            if error_type:
                payload["error_type"] = error_type

            body: dict = {
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": payload,
            }
            if agent_id:
                body["agent_id"] = agent_id
            result = client.post("/v1/events", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def report_interaction(
        other_agent_id: str,
        interaction_type: str,
        outcome: str,
        agent_id: str = "",
    ) -> str:
        """Report an agent-to-agent interaction event.

        other_agent_id: the agent being interacted with
        interaction_type: type of interaction, e.g. delegate, collaborate, query
        outcome: outcome of the interaction, e.g. success, failure, refused
        agent_id: the acting agent (optional if using agent key)
        """
        try:
            body: dict = {
                "event_id": str(uuid.uuid4()),
                "event_type": "agent.interaction",
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": {
                    "other_agent_id": other_agent_id,
                    "interaction_type": interaction_type,
                    "outcome": outcome,
                },
            }
            if agent_id:
                body["agent_id"] = agent_id
            result = client.post("/v1/events", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def report_incident(
        severity: str,
        description: str,
        pattern_type: str = "",
        agent_id: str = "",
    ) -> str:
        """Report a security incident or anomalous behavior for Guard review.

        severity: critical, high, medium, or low
        description: human-readable description of the incident
        pattern_type: optional classification, e.g. prompt_injection, data_exfil, abuse
        agent_id: the agent involved (optional if using agent key)
        """
        try:
            payload: dict = {
                "severity": severity,
                "description": description,
            }
            if pattern_type:
                payload["pattern_type"] = pattern_type

            body: dict = {
                "event_id": str(uuid.uuid4()),
                "event_type": "security.incident",
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": payload,
            }
            if agent_id:
                body["agent_id"] = agent_id
            result = client.post("/v1/events", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
