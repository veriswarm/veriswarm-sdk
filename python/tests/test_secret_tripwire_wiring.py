from __future__ import annotations

from veriswarm.client import VeriSwarmClient

GH = "ghp_" + "A" * 36


def _client(**kw):
    return VeriSwarmClient(base_url="https://example.invalid", api_key="k", **kw)


def test_guard_outbound_text_noop_when_disabled():
    c = _client()
    assert c.guard_outbound_text(GH) == GH


def test_guard_outbound_text_redacts_fail_closed_offline(monkeypatch):
    c = _client(secrets_detection=True)

    def _boom(*a, **k):
        raise RuntimeError("network down")

    # both manifest fetch and tokenize fail → vendored manifest + local redact.
    # VeriSwarmClient is a slots dataclass, so patch at the class level.
    monkeypatch.setattr(VeriSwarmClient, "get_secret_rules", _boom)
    monkeypatch.setattr(VeriSwarmClient, "tokenize_pii", _boom)
    assert c.guard_outbound_text(GH) == "[VS:GITHUB_TOKEN:offline]"
