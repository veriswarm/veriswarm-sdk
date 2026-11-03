"""Shared Web Bot Auth golden vectors (also run by the Node SDK test suite)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from veriswarm.webbotauth import _derive_authority, build_signature_base

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "testdata" / "webbotauth_vectors.json").read_text(
        encoding="utf-8"
    )
)


@pytest.mark.parametrize("vector", VECTORS["authority"], ids=lambda v: v["url"])
def test_authority_matches_node(vector):
    assert _derive_authority(vector["url"]) == vector["authority"]


@pytest.mark.parametrize("vector", VECTORS["signature_base"], ids=lambda v: v["name"])
def test_signature_base_matches_node(vector):
    base = build_signature_base(
        authority=vector["authority"],
        signature_agent=vector["signature_agent"],
        created=vector["created"],
        expires=vector["expires"],
        keyid=vector["keyid"],
        nonce=vector["nonce"],
    )
    assert base == vector["expected"]
