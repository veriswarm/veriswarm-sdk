"""Shared fake HTTP layer for adapter tests (patches VeriSwarmClient._request)."""
from __future__ import annotations

import threading
from typing import Any

from veriswarm.client import VeriSwarmClient

GH_TOKEN = "ghp_" + "A" * 36
EMAIL = "john.doe@example.com"


class FakeApi:
    """Records every request and answers like the real server would."""

    def __init__(self, decision: Any = "allow", decision_error: Exception | None = None):
        self.decision = decision
        self.decision_error = decision_error
        self.calls: list[tuple[str, str, Any, str]] = []
        self.event_error: Exception | None = None

    def request(self, client, path, *, method="GET", body=None):
        self.calls.append((path, method, body, threading.current_thread().name))
        if path == "/v1/decisions/check":
            if self.decision_error:
                raise self.decision_error
            if self.decision is None:
                return {}
            return {"decision": self.decision, "reason_code": "test_reason"}
        if path == "/v1/suite/guard/pii/tokenize":
            text = body["text"]
            n = text.count(EMAIL)
            return {
                "tokenized_text": text.replace(EMAIL, "[EMAIL_1]"),
                "tokens_created": n,
                "session_id": "sess_1",
            }
        if path == "/v1/events":
            if self.event_error:
                raise self.event_error
            return {}
        if path == "/v1/suite/guard/secret-rules":
            raise RuntimeError("offline")  # forces the vendored manifest
        return {}

    def to(self, path: str) -> list[Any]:
        return [b for p, _m, b, _t in self.calls if p == path]

    def all_text_sent(self) -> str:
        """Everything sent to endpoints that persist data (events, decision checks).

        The tokenize endpoint is deliberately excluded: the tripwire sends a
        prefix hit there on purpose so the server can tokenize it.
        """
        return " ".join(
            str(b) for p, _m, b, _t in self.calls if p != "/v1/suite/guard/pii/tokenize"
        )


def install(monkeypatch, api: FakeApi) -> FakeApi:
    monkeypatch.setattr(
        VeriSwarmClient, "_request",
        lambda self, path, *, method="GET", body=None: api.request(self, path, method=method, body=body),
    )
    return api

