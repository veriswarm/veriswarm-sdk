from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class VeriSwarmClientError(RuntimeError):
    pass


@dataclass(slots=True)
class VeriSwarmClient:
    """VeriSwarm Python SDK — trust scoring, event ingestion, and agent management.

    Usage:
        client = VeriSwarmClient(base_url="https://api.veriswarm.ai", api_key="vsk_...")
        decision = client.check_decision(agent_id="agt_123", action_type="post_message")
    """
    base_url: str
    api_key: str
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if not self.base_url:
            raise ValueError("base_url is required")
        if not self.api_key:
            raise ValueError("api_key is required")
        self.base_url = self.base_url.rstrip("/")

    # --- Decisions ---

    def check_decision(
        self,
        *,
        agent_id: str,
        action_type: str,
        resource_type: str | None = None,
    ) -> dict[str, Any]:
        """Check a trust decision before a sensitive action."""
        return self._request(
            "/v1/decisions/check",
            method="POST",
            body={
                "agent_id": agent_id,
                "action_type": action_type,
                "resource_type": resource_type,
            },
        )

    # --- Events ---

    def ingest_event(
        self,
        *,
        event_id: str,
        agent_id: str,
        source_type: str,
        event_type: str,
        occurred_at: str,
        payload: dict[str, Any] | None = None,
        signature: str | None = None,
    ) -> dict[str, Any]:
        """Ingest a single agent behavioral event."""
        body: dict[str, Any] = {
            "event_id": event_id,
            "agent_id": agent_id,
            "source_type": source_type,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "payload": payload or {},
        }
        if signature:
            body["signature"] = signature
        return self._request("/v1/events", method="POST", body=body)

    def ingest_events_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Ingest up to 50 events in a single request."""
        return self._request("/v1/events/batch", method="POST", body=events)

    # --- Provider Reports ---

    def ingest_provider_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Submit a provider report (spam, abuse, quality signal)."""
        return self._request("/v1/public/providers/reports", method="POST", body=report)

    def ingest_provider_reports_batch(self, reports: list[dict[str, Any]]) -> dict[str, Any]:
        """Submit multiple provider reports in a single request."""
        return self._request(
            "/v1/public/providers/reports/batch",
            method="POST",
            body={"reports": reports},
        )

    # --- Agent Management ---

    def register_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Register a new agent."""
        return self._request("/v1/public/agents/register", method="POST", body=payload)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Get public agent profile."""
        return self._request(f"/v1/public/agents/{agent_id}")

    def get_agent_scores(self, agent_id: str) -> dict[str, Any]:
        """Get an agent's current trust scores."""
        return self._request(f"/v1/public/agents/{agent_id}/scores/current")

    def get_agent_score_history(self, agent_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Get an agent's score history (last N snapshots)."""
        return self._request(f"/v1/public/agents/{agent_id}/scores/history?limit={limit}")

    def get_agent_score_breakdown(self, agent_id: str) -> dict[str, Any]:
        """Get detailed score breakdown with contributing factors."""
        return self._request(f"/v1/public/agents/{agent_id}/scores/breakdown")

    def get_agent_flags(self, agent_id: str) -> list[dict[str, Any]]:
        """Get active moderation flags for an agent."""
        return self._request(f"/v1/public/agents/{agent_id}/flags")

    def appeal_flag(self, agent_id: str, flag_id: int) -> dict[str, Any]:
        """Appeal a moderation flag for review."""
        return self._request(
            f"/v1/public/agents/{agent_id}/flags/{flag_id}/appeal",
            method="POST",
        )

    def get_agent_manifests(self, agent_id: str) -> list[dict[str, Any]]:
        """Get agent capability manifests (public)."""
        return self._request(f"/v1/public/agents/{agent_id}/manifests")

    # --- Platform Status ---

    def get_platform_status(self) -> dict[str, Any]:
        """Check platform health and feature flags."""
        return self._request("/v1/public/status")

    # --- Internal ---

    def _request(self, path: str, *, method: str = "GET", body: Any = None) -> Any:
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=encoded,
            method=method,
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            details = ""
            try:
                details = exc.read().decode("utf-8")
            except Exception:
                details = str(exc)
            raise VeriSwarmClientError(f"VeriSwarm API {exc.code}: {details}") from exc
        except URLError as exc:
            raise VeriSwarmClientError(f"VeriSwarm request failed: {exc.reason}") from exc
