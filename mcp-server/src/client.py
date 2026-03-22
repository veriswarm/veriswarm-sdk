"""VeriSwarm API client for the MCP server."""
from __future__ import annotations

import httpx


class VeriSwarmAPIClient:
    def __init__(self, base_url: str, api_key: str = "", agent_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_key = agent_key
        self._http = httpx.Client(timeout=15.0)

    def _headers(self, use_agent_key: bool = False) -> dict:
        h = {"Content-Type": "application/json"}
        if use_agent_key and self.agent_key:
            h["x-agent-api-key"] = self.agent_key
        elif self.api_key:
            h["x-api-key"] = self.api_key
        return h

    def get(self, path: str, params: dict = None, use_agent_key: bool = False) -> dict:
        r = self._http.get(
            f"{self.base_url}{path}",
            params=params,
            headers=self._headers(use_agent_key),
        )
        r.raise_for_status()
        return r.json()

    def post(self, path: str, json: dict = None, use_agent_key: bool = False) -> dict:
        r = self._http.post(
            f"{self.base_url}{path}",
            json=json,
            headers=self._headers(use_agent_key),
        )
        r.raise_for_status()
        return r.json()

    def delete(self, path: str, use_agent_key: bool = False) -> dict:
        r = self._http.delete(
            f"{self.base_url}{path}",
            headers=self._headers(use_agent_key),
        )
        r.raise_for_status()
        return r.json()
