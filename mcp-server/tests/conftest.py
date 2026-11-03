"""Shared test fixtures.

Every test runs with an isolated HOME and without inherited VeriSwarm /
Guard environment variables, so nothing reads the developer's real
~/.veriswarm/env or reaches a real API with real credentials.
"""
from __future__ import annotations

import os

import pytest

_ISOLATED_PREFIXES = ("VERISWARM_", "GUARD_", "CLAUDE_SESSION_ID")


@pytest.fixture(autouse=True)
def _isolated_home(monkeypatch, tmp_path_factory):
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    for key in list(os.environ):
        if key.startswith(_ISOLATED_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    return home
