"""Packaging metadata matches what the code and docs promise."""
from __future__ import annotations

import dataclasses
from importlib import metadata

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

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
    # Parse instead of string-matching: setuptools quotes the marker as
    # extra == "x" on recent versions and extra == 'x' on Python 3.8.
    assert any(_requires_for_extra(r, requirement, extra) for r in requires), requires


def _requires_for_extra(spec: str, name: str, extra: str) -> bool:
    req = Requirement(spec)
    if canonicalize_name(req.name) != canonicalize_name(name) or req.marker is None:
        return False
    return req.marker.evaluate({"extra": extra}) and not req.marker.evaluate({"extra": ""})


def test_extra_marker_parsing_accepts_both_quote_styles():
    for spec in ("crewai ; extra == 'crewai'", 'crewai; extra == "crewai"'):
        assert _requires_for_extra(spec, "crewai", "crewai")
    assert not _requires_for_extra("crewai", "crewai", "crewai")  # unconditional
    assert not _requires_for_extra("crewai ; extra == 'other'", "crewai", "crewai")
    assert not _requires_for_extra("crewai-tools ; extra == 'crewai'", "crewai", "crewai")


def test_client_dataclass_avoids_310_only_options():
    # dataclass(slots=True) needs Python 3.10, but the package supports 3.8+.
    params = VeriSwarmClient.__dataclass_params__  # type: ignore[attr-defined]
    assert not getattr(params, "slots", False)
    assert dataclasses.is_dataclass(VeriSwarmClient)
