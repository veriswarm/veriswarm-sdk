"""Tests for VeriSwarmClient.scan_session_turn (Guard Session Sentry)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from veriswarm.client import VeriSwarmClient


def _client() -> VeriSwarmClient:
    return VeriSwarmClient(base_url="https://example.invalid", api_key="test-key")


# ---------------------------------------------------------------------------
# Helpers to capture what _post sends without network
# ---------------------------------------------------------------------------

def _mock_post(client: VeriSwarmClient, return_value: dict) -> MagicMock:
    """Patch client._post and return the mock so callers can assert on it."""
    m = MagicMock(return_value=return_value)
    # VeriSwarmClient is a slots dataclass — patch at the class level.
    client.__class__._post = m  # type: ignore[method-assign]
    return m


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_scan_session_turn_posts_correct_path(monkeypatch):
    """_post is called with the /v1/suite/guard/scan-session path."""
    c = _client()
    captured: list[tuple] = []

    def fake_post(self, path, body=None):
        captured.append((path, body))
        return {"session_id": "s1", "enabled": False, "blocked": False,
                "session_score": 0.0, "highest_severity": "info", "contributions": []}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    c.scan_session_turn("s1", 0)
    assert len(captured) == 1
    assert captured[0][0] == "/v1/suite/guard/scan-session"


def test_scan_session_turn_required_fields_in_body(monkeypatch):
    """session_id and turn_index are always in the request body."""
    c = _client()
    captured: list[dict] = []

    def fake_post(self, path, body=None):
        captured.append(body or {})
        return {}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    c.scan_session_turn("sess-abc", 3)
    body = captured[0]
    assert body["session_id"] == "sess-abc"
    assert body["turn_index"] == 3


def test_scan_session_turn_text_fields_default_empty(monkeypatch):
    """user_text, agent_text, system_prompt default to empty string."""
    c = _client()
    captured: list[dict] = []

    def fake_post(self, path, body=None):
        captured.append(body or {})
        return {}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    c.scan_session_turn("s1", 0)
    body = captured[0]
    assert body["user_text"] == ""
    assert body["agent_text"] == ""
    assert body["system_prompt"] == ""


def test_scan_session_turn_text_fields_passed_when_provided(monkeypatch):
    """user_text, agent_text, system_prompt are forwarded when given."""
    c = _client()
    captured: list[dict] = []

    def fake_post(self, path, body=None):
        captured.append(body or {})
        return {}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    c.scan_session_turn(
        "s1", 1,
        user_text="hello",
        agent_text="world",
        system_prompt="be helpful",
    )
    body = captured[0]
    assert body["user_text"] == "hello"
    assert body["agent_text"] == "world"
    assert body["system_prompt"] == "be helpful"


def test_scan_session_turn_optional_agent_id_omitted_when_none(monkeypatch):
    """agent_id is absent from the body when not supplied."""
    c = _client()
    captured: list[dict] = []

    def fake_post(self, path, body=None):
        captured.append(body or {})
        return {}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    c.scan_session_turn("s1", 0)
    assert "agent_id" not in captured[0]


def test_scan_session_turn_optional_actor_id_omitted_when_none(monkeypatch):
    """actor_id is absent from the body when not supplied."""
    c = _client()
    captured: list[dict] = []

    def fake_post(self, path, body=None):
        captured.append(body or {})
        return {}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    c.scan_session_turn("s1", 0)
    assert "actor_id" not in captured[0]


def test_scan_session_turn_optional_fields_included_when_provided(monkeypatch):
    """agent_id and actor_id appear in body when explicitly supplied."""
    c = _client()
    captured: list[dict] = []

    def fake_post(self, path, body=None):
        captured.append(body or {})
        return {}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    c.scan_session_turn("s1", 0, agent_id="agt_42", actor_id="usr_7")
    body = captured[0]
    assert body["agent_id"] == "agt_42"
    assert body["actor_id"] == "usr_7"


def test_scan_session_turn_returns_parsed_response(monkeypatch):
    """The method returns the dict returned by _post unchanged."""
    c = _client()
    fake_response = {
        "session_id": "s1",
        "enabled": True,
        "session_score": 0.72,
        "turn_value": 0.31,
        "highest_severity": "medium",
        "contributions": [{"check": "sensitive_topic", "value": 0.31}],
        "enforcement_level": "monitor",
        "block_threshold": 0.9,
        "blocked": False,
        "version": "1.0",
    }

    def fake_post(self, path, body=None):
        return fake_response

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    result = c.scan_session_turn("s1", 2, user_text="some text")
    assert result == fake_response
    assert result["blocked"] is False
    assert result["session_score"] == 0.72


def test_scan_session_turn_disabled_response(monkeypatch):
    """Handles the disabled (flag-off) response shape correctly."""
    c = _client()
    disabled_response = {
        "session_id": "s1",
        "enabled": False,
        "blocked": False,
        "session_score": 0.0,
        "highest_severity": "info",
        "contributions": [],
    }

    def fake_post(self, path, body=None):
        return disabled_response

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)
    result = c.scan_session_turn("s1", 0)
    assert result["enabled"] is False
    assert result["blocked"] is False
