"""Fetched secret-rule manifests may only add coverage; failures are retried."""
from __future__ import annotations

import pytest

from veriswarm import VeriSwarmClient
from veriswarm import client as client_module
from veriswarm.secret_tripwire import ensure_tripwire

GH = "ghp_" + "A" * 36
AWS = "AKIA" + "B" * 16
NEW_RULE = {
    "name": "acme_token",
    "entity_type": "ACME_TOKEN",
    "prefix_pattern": r"\bacme_[a-z0-9]{12}\b",
}
ACME = "acme_" + "a" * 12


def test_merges_fetched_rules_with_builtins():
    tw = ensure_tripwire(fetch_manifest=lambda: {"version": "sha256:remote", "rules": [NEW_RULE]})
    assert [h.entity_type for h in tw.scan(ACME)] == ["ACME_TOKEN"]
    assert [h.entity_type for h in tw.scan(AWS)] == ["AWS_KEY"]
    assert tw.source == "remote"


def test_fetched_rule_cannot_narrow_builtin_of_same_name():
    narrowed = {"name": "github_pat", "entity_type": "GITHUB_TOKEN", "prefix_pattern": r"\bNEVER\b"}
    tw = ensure_tripwire(fetch_manifest=lambda: {"version": "v", "rules": [narrowed]})
    assert tw.scan(GH)


@pytest.mark.parametrize(
    "bad_rule",
    [
        {**NEW_RULE, "name": "bad_re", "prefix_pattern": "("},
        {**NEW_RULE, "name": "empty", "prefix_pattern": ""},
        {"entity_type": "X_KEY", "prefix_pattern": "x"},
        {**NEW_RULE, "name": "m", "entity_type": "X]:evil["},
        "ghp_.*",
    ],
)
def test_drops_invalid_fetched_rule_and_keeps_the_rest(bad_rule):
    tw = ensure_tripwire(fetch_manifest=lambda: {"version": "v", "rules": [bad_rule, NEW_RULE]})
    assert len(tw.scan(ACME)) == 1
    assert tw.scan(GH)


@pytest.mark.parametrize("manifest", [None, "nope", {"rules": "x"}, {"version": "v"}, []])
def test_invalid_manifest_keeps_builtins_and_is_marked_for_retry(manifest):
    tw = ensure_tripwire(fetch_manifest=lambda: manifest)
    assert tw.scan(GH)
    assert tw.source == "builtin"


def test_failed_fetch_is_marked_for_retry():
    def boom():
        raise OSError("offline")

    tw = ensure_tripwire(fetch_manifest=boom)
    assert tw.source == "builtin"


def test_client_retries_fetch_after_interval(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(client_module.time, "monotonic", lambda: now[0])
    calls = []

    def fake_rules(self):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("offline")
        return {"version": "sha256:remote", "rules": [NEW_RULE]}

    def offline_tokenize(self, **_kw):
        raise OSError("offline")

    monkeypatch.setattr(VeriSwarmClient, "get_secret_rules", fake_rules)
    monkeypatch.setattr(VeriSwarmClient, "tokenize_pii", offline_tokenize)
    c = VeriSwarmClient(base_url="https://example.invalid", api_key="k", secrets_detection=True)

    assert c.guard_outbound_text(ACME) == ACME  # built-ins only
    c.guard_outbound_text("hello")
    assert len(calls) == 1  # no hammering inside the retry window

    now[0] += 61
    assert c.guard_outbound_text(ACME) == "[VS:ACME_TOKEN:offline]"
    assert len(calls) == 2

    now[0] += 3600
    c.guard_outbound_text("hello")
    assert len(calls) == 2  # a successful fetch is not repeated


# --- detected secrets never leave the process --------------------------------

import json as _json  # noqa: E402

GH_MANIFEST = {
    "version": "sha256:t",
    "rules": [
        {"name": "github_pat", "entity_type": "GITHUB_TOKEN", "prefix_pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"}
    ],
}


def _route(recorder, tokenize):
    class Opener:
        def open(self, request, timeout=None):
            recorder.requests.append(request)
            if request.full_url.endswith("/secret-rules"):
                body = GH_MANIFEST
            else:
                body = tokenize(_json.loads(request.data))
            from .conftest import FakeResponse

            return FakeResponse(_json.dumps(body).encode())

    return Opener()


def _bodies(recorder):
    return [r.data.decode() for r in recorder.requests if r.data is not None]


def test_secret_is_redacted_before_tokenize_call(recorder, monkeypatch):
    monkeypatch.setattr(client_module, "_OPENER", _route(recorder, lambda req: {"tokens_created": 0, "tokenized_text": req["text"]}))
    c = VeriSwarmClient(base_url="https://api.test", api_key="k", secrets_detection=True)
    out = c.guard_outbound_text(f"email bob@example.com key {GH}")
    assert out == "email bob@example.com key [VS:GITHUB_TOKEN:offline]"
    bodies = _bodies(recorder)
    assert len(bodies) == 1  # tokenize still called, on redacted text
    assert all(GH not in b for b in bodies)


def test_pii_tokenization_applies_to_redacted_text(recorder, monkeypatch):
    def tokenize(req):
        return {"tokens_created": 1, "tokenized_text": req["text"].replace("bob@example.com", "[VS:EMAIL:1]")}

    monkeypatch.setattr(client_module, "_OPENER", _route(recorder, tokenize))
    c = VeriSwarmClient(base_url="https://api.test", api_key="k", secrets_detection=True)
    assert c.guard_outbound_text(f"bob@example.com {GH}") == "[VS:EMAIL:1] [VS:GITHUB_TOKEN:offline]"
    assert all(GH not in b for b in _bodies(recorder))


def test_tokenize_failure_returns_local_redaction(recorder, monkeypatch):
    def tokenize(req):
        raise OSError("down")

    monkeypatch.setattr(client_module, "_OPENER", _route(recorder, tokenize))
    c = VeriSwarmClient(base_url="https://api.test", api_key="k", secrets_detection=True)
    assert c.guard_outbound_text(f"x {GH}") == "x [VS:GITHUB_TOKEN:offline]"
    assert all(GH not in b for b in _bodies(recorder))
