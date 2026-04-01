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
        agent_id: str,
        payload: str = "",
    ) -> str:
        """Report a generic agent behavioral event to VeriSwarm for scoring.

        event_type: dot-separated event type, e.g. tool.call.success
        agent_id: the agent performing the action (required)
        payload: JSON string of additional event metadata (optional)
        """
        try:
            body: dict = {
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "agent_id": agent_id,
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": json.loads(payload) if payload else {},
            }
            result = client.post("/v1/events", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def report_tool_call(
        tool_name: str,
        agent_id: str,
        success: bool = True,
        duration_ms: int = None,
        error_type: str = "",
    ) -> str:
        """Report a tool call event. Shorthand for tool.call.success / tool.call.failure events.

        agent_id is required by the event ingestion API.
        """
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
                "agent_id": agent_id,
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": payload,
            }
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
        agent_id: str,
    ) -> str:
        """Report an agent-to-agent interaction event.

        other_agent_id: the agent being interacted with
        interaction_type: type of interaction, e.g. delegate, collaborate, query
        outcome: outcome of the interaction, e.g. success, failure, refused
        agent_id: the acting agent (required)
        """
        try:
            body: dict = {
                "event_id": str(uuid.uuid4()),
                "event_type": "agent.interaction",
                "agent_id": agent_id,
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": {
                    "other_agent_id": other_agent_id,
                    "interaction_type": interaction_type,
                    "outcome": outcome,
                },
            }
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
        agent_id: str,
        pattern_type: str = "",
    ) -> str:
        """Report a security incident or anomalous behavior for Guard review.

        severity: critical, high, medium, or low
        description: human-readable description of the incident
        agent_id: the agent involved (required)
        pattern_type: optional classification, e.g. prompt_injection, data_exfil, abuse
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
                "agent_id": agent_id,
                "source_type": "mcp",
                "occurred_at": _now_iso(),
                "payload": payload,
            }
            result = client.post("/v1/events", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
