"""MCP tools for the A2A (agent-to-agent) protocol.

These wrap `/v1/a2a/*` endpoints — trust-ranked catalog, agent cards
(with the `x-veriswarm-trust` extension), and task submit / status /
cancel. Plan-gated to Pro+ on the API side.
"""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import bounded_string, safe_error_response, safe_id


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    # ── Catalog + agent cards ──────────────────────────────────────

    @server.tool()
    async def list_a2a_catalog() -> str:
        """List the tenant's trust-ranked A2A agent catalog.

        Returns agents in descending trust-score order, excluding any
        agent currently in the kill-switch state. Each entry includes
        the agent's id, slug, current trust score, and a short
        description suitable for an A2A discovery flow.
        """
        try:
            result = client.get("/v1/a2a/catalog")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="list_a2a_catalog")

    @server.tool()
    async def get_a2a_agent_card(agent_id: str) -> str:
        """Get an A2A agent card for the given agent.

        The card is an A2A-compatible JSON document that includes the
        `x-veriswarm-trust` extension (current trust score + tier),
        and — when keys are provisioned — the `x-veriswarm-transport`
        extension carrying the agent's Ed25519 public key for inter-agent
        message signing.

        agent_id: VeriSwarm agent id (`agt_*`).
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            result = client.get(f"/v1/a2a/{agent_id}/card")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="get_a2a_agent_card")

    # ── Task lifecycle ─────────────────────────────────────────────

    @server.tool()
    async def submit_a2a_task(
        agent_id: str,
        requesting_agent_id: str,
        messages_json: str,
        signature_json: str = "",
    ) -> str:
        """Submit a task to an agent via the A2A protocol.

        agent_id: the receiving agent (`agt_*`).
        requesting_agent_id: the calling agent's id (`agt_*`).
        messages_json: JSON-encoded list of message dicts (A2A message shape).
        signature_json: optional JSON-encoded Ed25519 signature envelope
            (`{"key_id": "...", "signature": "...", "algo": "ed25519"}`).

        Returns the new task id and accepted status, or an error if the
        receiving agent is killed, paused, or stopped (lifecycle-blocked).
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            requesting_agent_id = safe_id(requesting_agent_id, "requesting_agent_id")
            messages_json = bounded_string(
                messages_json, field_name="messages_json", max_chars=32_768
            )
            try:
                messages = json.loads(messages_json)
            except json.JSONDecodeError:
                return json.dumps({"error": "messages_json must be valid JSON"})
            if not isinstance(messages, list):
                return json.dumps({"error": "messages_json must decode to a list"})

            payload: dict = {
                "requesting_agent_id": requesting_agent_id,
                "messages": messages,
            }
            if signature_json:
                signature_json = bounded_string(
                    signature_json, field_name="signature_json", max_chars=4096
                )
                try:
                    payload["signature"] = json.loads(signature_json)
                except json.JSONDecodeError:
                    return json.dumps({"error": "signature_json must be valid JSON"})

            result = client.post(f"/v1/a2a/{agent_id}/tasks", json=payload)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="submit_a2a_task")

    @server.tool()
    async def get_a2a_task(agent_id: str, task_id: str) -> str:
        """Get the status + result of an A2A task.

        agent_id: the receiving agent (`agt_*`).
        task_id: the task id returned by `submit_a2a_task` (`a2a_*`).

        Returns the task's status (submitted / running / succeeded /
        failed / cancelled), the response messages (when complete), and
        any error context.
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            task_id = safe_id(task_id, "task_id")
            result = client.get(f"/v1/a2a/{agent_id}/tasks/{task_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="get_a2a_task")

    @server.tool()
    async def cancel_a2a_task(agent_id: str, task_id: str) -> str:
        """Cancel an in-flight A2A task.

        agent_id: the receiving agent (`agt_*`).
        task_id: the task id to cancel (`a2a_*`).

        Returns the updated task state. No-op if the task already
        terminated.
        """
        try:
            agent_id = safe_id(agent_id, "agent_id")
            task_id = safe_id(task_id, "task_id")
            result = client.post(f"/v1/a2a/{agent_id}/tasks/{task_id}/cancel")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="cancel_a2a_task")
