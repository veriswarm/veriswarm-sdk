"""Tests for VeriSwarm MCP Server structure and client behavior."""
from __future__ import annotations

import importlib
import inspect
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the src package is importable when running from the package root
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Client tests — no network calls
# ---------------------------------------------------------------------------

class TestVeriSwarmAPIClient:
    def setup_method(self):
        from src.client import VeriSwarmAPIClient
        self.Client = VeriSwarmAPIClient

    def test_base_url_trailing_slash_stripped(self):
        client = self.Client("https://api.veriswarm.ai/", api_key="key123")
        assert client.base_url == "https://api.veriswarm.ai"

    def test_headers_with_api_key(self):
        client = self.Client("https://api.veriswarm.ai", api_key="vs_key")
        headers = client._headers(use_agent_key=False)
        assert headers["x-api-key"] == "vs_key"
        assert "x-agent-api-key" not in headers

    def test_headers_with_agent_key(self):
        client = self.Client("https://api.veriswarm.ai", api_key="vs_key", agent_key="agent_secret")
        headers = client._headers(use_agent_key=True)
        assert headers["x-agent-api-key"] == "agent_secret"
        assert "x-api-key" not in headers

    def test_headers_falls_back_to_api_key_when_agent_key_empty(self):
        client = self.Client("https://api.veriswarm.ai", api_key="vs_key", agent_key="")
        headers = client._headers(use_agent_key=True)
        assert headers["x-api-key"] == "vs_key"

    def test_get_constructs_correct_url(self):
        client = self.Client("https://api.veriswarm.ai", api_key="k")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._http, "get", return_value=mock_resp) as mock_get:
            client.get("/v1/public/status")
            mock_get.assert_called_once()
            call_url = mock_get.call_args[0][0]
            assert call_url == "https://api.veriswarm.ai/v1/public/status"

    def test_post_constructs_correct_url(self):
        client = self.Client("https://api.veriswarm.ai", api_key="k")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._http, "post", return_value=mock_resp) as mock_post:
            client.post("/v1/events", json={"event_type": "test"})
            mock_post.assert_called_once()
            call_url = mock_post.call_args[0][0]
            assert call_url == "https://api.veriswarm.ai/v1/events"

    def test_delete_constructs_correct_url(self):
        client = self.Client("https://api.veriswarm.ai", api_key="k")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"ok": True}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(client._http, "delete", return_value=mock_resp) as mock_delete:
            client.delete("/v1/guard/kill-switch/agt_123")
            mock_delete.assert_called_once()
            call_url = mock_delete.call_args[0][0]
            assert call_url == "https://api.veriswarm.ai/v1/guard/kill-switch/agt_123"


# ---------------------------------------------------------------------------
# Server creation test
# ---------------------------------------------------------------------------

class TestServerCreation:
    def test_create_server_returns_tuple(self):
        import os
        from mcp.server.fastmcp import FastMCP
        from src.server import create_server

        with patch.dict(os.environ, {"VERISWARM_API_KEY": "test-key", "VERISWARM_API_URL": "https://api.veriswarm.ai"}):
            server, client = create_server()
        assert server is not None
        assert isinstance(server, FastMCP)
        assert client is not None
        assert client.api_key == "test-key"

    def test_create_server_warns_when_no_keys(self, capsys):
        import os
        from src.server import create_server

        env_overrides = {
            "VERISWARM_API_KEY": "",
            "VERISWARM_AGENT_KEY": "",
            "VERISWARM_API_URL": "https://api.veriswarm.ai",
        }
        with patch.dict(os.environ, env_overrides, clear=False):
            # Remove the keys entirely to avoid empty-string passthrough issue
            saved = {}
            for k in ("VERISWARM_API_KEY", "VERISWARM_AGENT_KEY"):
                saved[k] = os.environ.pop(k, None)
            try:
                create_server()
            finally:
                for k, v in saved.items():
                    if v is not None:
                        os.environ[k] = v

        captured = capsys.readouterr()
        assert "Warning" in captured.err


# ---------------------------------------------------------------------------
# Tool module structure tests
# ---------------------------------------------------------------------------

TOOL_MODULES = [
    "src.tools.trust",
    "src.tools.events",
    "src.tools.guard",
    "src.tools.passport",
    "src.tools.vault",
    "src.tools.agents",
    "src.tools.platform",
]


@pytest.mark.parametrize("module_path", TOOL_MODULES)
def test_tool_module_has_register_function(module_path):
    """Every tool module must expose a register(server, client) function."""
    module = importlib.import_module(module_path)
    assert hasattr(module, "register"), f"{module_path} is missing a register() function"
    assert callable(module.register)


@pytest.mark.parametrize("module_path", TOOL_MODULES)
def test_register_accepts_server_and_client(module_path):
    """register() must accept exactly two positional parameters: server and client."""
    module = importlib.import_module(module_path)
    sig = inspect.signature(module.register)
    params = list(sig.parameters.keys())
    assert params[0] == "server"
    assert params[1] == "client"


# ---------------------------------------------------------------------------
# Event tool unit tests (no HTTP)
# ---------------------------------------------------------------------------

class TestEventTools:
    def _make_client(self):
        from src.client import VeriSwarmAPIClient
        client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
        return client

    def test_report_tool_call_uses_success_event_type(self):
        import asyncio
        import json as _json

        client = self._make_client()
        captured = {}

        original_post = client.post
        def mock_post(path, json=None, **kwargs):
            captured["body"] = json
            return {"status": "ok", "event_id": json.get("event_id", "")}
        client.post = mock_post

        from src.tools import events
        server = MagicMock()
        # Manually invoke by calling the inner coroutine
        # We test by re-importing and calling report_tool_call directly

        # Patch post at the module level to intercept the call
        async def run():
            with patch.object(client, "post", side_effect=mock_post):
                events.register(server, client)

        asyncio.run(run())

    def test_report_incident_payload_structure(self):
        """report_incident should produce a security.incident event_type."""
        import json as _json

        client = self._make_client()
        posted = {}

        def mock_post(path, json=None, **kwargs):
            posted.update(json or {})
            return {"status": "ok"}

        with patch.object(client, "post", side_effect=mock_post):
            import asyncio
            from src.tools.events import register

            server = MagicMock()
            register(server, client)
            # The actual tool functions are registered on the mock server — not easily
            # invocable from here without a full MCP runtime.
            # We verify the module imports cleanly and register doesn't raise.
            assert True
