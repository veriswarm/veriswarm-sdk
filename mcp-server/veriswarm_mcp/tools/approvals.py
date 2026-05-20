"""MCP tools for the operator approval queue.

Wraps the ``/v1/approvals`` endpoints — submit, list, fetch, approve,
reject. Approve / reject require an account-session token (operator
role), so they error on api-key-only clients.
"""
from __future__ import annotations

import json
from urllib.parse import urlencode

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import bounded_string, safe_error_response, safe_id, safe_optional_id


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def create_approval(
        agent_id: str = "",
        requested_action_json: str = "{}",
        ttl_seconds: int = 86_400,
    ) -> str:
        """Submit a new approval request to the operator queue.

        agent_id: optional VeriSwarm agent id (`agt_*`); omit for
            system-initiated reviews.
        requested_action_json: JSON-encoded dict describing the action
            being approved (free-form per-tenant schema).
        ttl_seconds: how long the request stays pending before expiring.
            Server enforces 60 ≤ ttl_seconds ≤ 30 days.
        """
        try:
            ttl_seconds = int(ttl_seconds)
        except (TypeError, ValueError):
            return json.dumps({"error": "ttl_seconds must be an integer"})
        if not 60 <= ttl_seconds <= 30 * 24 * 3600:
            return json.dumps({"error": "ttl_seconds must be between 60 and 2,592,000"})

        try:
            requested_action_json = bounded_string(
                requested_action_json, field_name="requested_action_json", max_chars=16_384
            )
            try:
                requested_action = json.loads(requested_action_json)
            except json.JSONDecodeError:
                return json.dumps({"error": "requested_action_json must be valid JSON"})
            if not isinstance(requested_action, dict):
                return json.dumps({"error": "requested_action_json must decode to an object"})

            body: dict = {
                "requested_action": requested_action,
                "ttl_seconds": ttl_seconds,
            }
            agent_id_clean = safe_optional_id(agent_id, "agent_id")
            if agent_id_clean:
                body["agent_id"] = agent_id_clean

            result = client.post("/v1/approvals", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="create_approval")

    @server.tool()
    async def list_approvals(
        state: str = "pending",
        agent_id: str = "",
        limit: int = 100,
    ) -> str:
        """List approval requests for the authenticated tenant.

        state: one of "pending", "approved", "rejected", "expired", "all".
        agent_id: optional filter to a single agent (`agt_*`).
        limit: 1..500 (server-enforced).
        """
        if state not in {"pending", "approved", "rejected", "expired", "all"}:
            return json.dumps({
                "error": "state must be one of pending/approved/rejected/expired/all"
            })
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            return json.dumps({"error": "limit must be an integer"})
        if not 1 <= limit <= 500:
            return json.dumps({"error": "limit must be between 1 and 500"})

        try:
            params: dict = {"state": state, "limit": limit}
            agent_id_clean = safe_optional_id(agent_id, "agent_id")
            if agent_id_clean:
                params["agent_id"] = agent_id_clean
            result = client.get(f"/v1/approvals?{urlencode(params)}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="list_approvals")

    @server.tool()
    async def get_approval(approval_id: str) -> str:
        """Get a single approval request by id (`apr_*`)."""
        try:
            approval_id = safe_id(approval_id, "approval_id")
            result = client.get(f"/v1/approvals/{approval_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="get_approval")

    @server.tool()
    async def approve_approval(approval_id: str, reason: str = "") -> str:
        """Approve a pending approval request.

        Requires an account-session token (operator role); api-key-only
        callers get a 401. `reason` is captured in the audit ledger.
        """
        try:
            approval_id = safe_id(approval_id, "approval_id")
            body: dict = {}
            if reason:
                body["reason"] = bounded_string(reason, field_name="reason", max_chars=2000)
            result = client.post(f"/v1/approvals/{approval_id}/approve", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="approve_approval")

    @server.tool()
    async def reject_approval(approval_id: str, reason: str = "") -> str:
        """Reject a pending approval request.

        Requires an account-session token (operator role); api-key-only
        callers get a 401. `reason` is captured in the audit ledger.
        """
        try:
            approval_id = safe_id(approval_id, "approval_id")
            body: dict = {}
            if reason:
                body["reason"] = bounded_string(reason, field_name="reason", max_chars=2000)
            result = client.post(f"/v1/approvals/{approval_id}/reject", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="reject_approval")
