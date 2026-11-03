"""Packaging metadata matches what the code and docs promise."""
from __future__ import annotations

import dataclasses
from importlib import metadata

import pytest

from veriswarm import VeriSwarmClient


@pytest.mark.parametrize(
    "extra, requirement",
    [
        ("langchain", "langchain-core"),
        ("webbotauth", "cryptography"),
        # documented in veriswarm/adapters/__init__.py
        ("crewai", "crewai"),
        ("openai-agents", "openai-agents"),
        ("claude-sdk", "claude-agent-sdk"),
    ],
)
def test_documented_extras_are_declared(extra, requirement):
    meta = metadata.metadata("veriswarm")
    assert extra in (meta.get_all("Provides-Extra") or [])
    requires = metadata.requires("veriswarm") or []
    assert any(r.startswith(requirement) and f'extra == "{extra}"' in r for r in requires), requires


def test_client_dataclass_avoids_310_only_options():
    # dataclass(slots=True) needs Python 3.10, but the package supports 3.8+.
    params = VeriSwarmClient.__dataclass_params__  # type: ignore[attr-defined]
    assert not getattr(params, "slots", False)
    assert dataclasses.is_dataclass(VeriSwarmClient)
