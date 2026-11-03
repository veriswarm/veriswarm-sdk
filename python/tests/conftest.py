"""Shared fixtures: capture outbound requests from VeriSwarmClient without a network."""
from __future__ import annotations

import io
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from veriswarm import client as client_module


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes = b"{}", status: int = 200) -> None:
        super().__init__(body)
        self.status = status

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class Recorder:
    """Records each urllib Request the client sends and returns a canned body."""

    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.body: bytes = b"{}"
        self.raise_exc: BaseException | None = None

    def open(self, request: Any, timeout: Any = None) -> FakeResponse:
        self.requests.append(request)
        if self.raise_exc is not None:
            raise self.raise_exc
        return FakeResponse(self.body)

    @property
    def last(self) -> Any:
        return self.requests[-1]

    @property
    def url(self) -> str:
        return self.last.full_url

    @property
    def query(self) -> dict[str, list[str]]:
        return parse_qs(urlsplit(self.url).query)

    @property
    def json_body(self) -> Any:
        data = self.last.data
        return None if data is None else json.loads(data)

    def header(self, name: str) -> str | None:
        # urllib stores header names via str.capitalize()
        return self.last.get_header(name.capitalize())


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    rec = Recorder()
    monkeypatch.setattr(client_module, "_OPENER", rec)
    return rec
