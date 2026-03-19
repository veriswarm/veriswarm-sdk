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
    base_url: str
    api_key: str
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if not self.base_url:
            raise ValueError("base_url is required")
        if not self.api_key:
            raise ValueError("api_key is required")
        self.base_url = self.base_url.rstrip("/")

    def check_decision(
        self,
        *,
        agent_id: str,
        action_type: str,
        resource_type: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "/v1/decisions/check",
            method="POST",
            body={
                "agent_id": agent_id,
                "action_type": action_type,
                "resource_type": resource_type,
            },
        )

    def ingest_provider_report(self, report: dict[str, Any]) -> dict[str, Any]:
        return self._request("/v1/public/providers/reports", method="POST", body=report)

    def ingest_provider_reports_batch(self, reports: list[dict[str, Any]]) -> dict[str, Any]:
        return self._request(
            "/v1/public/providers/reports/batch",
            method="POST",
            body={"reports": reports},
        )

    def register_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("/v1/public/agents/register", method="POST", body=payload)

    def _request(self, path: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
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
