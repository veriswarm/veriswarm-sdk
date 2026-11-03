"""GuardMixin: fail-closed policy, secret tripwire wiring, nested PII tokenization."""
import pytest

from veriswarm.adapters.guard_mixin import GuardMixin

from .adapter_fakes import EMAIL, GH_TOKEN, FakeApi, install


def _guard(**kw):
    return GuardMixin(api_key="k", agent_id="agt_t", base_url="https://example.invalid", **kw)


@pytest.mark.parametrize("decision", ["review", "deny", "escalate", "", None, 7])
def test_non_allow_decision_blocks_when_enforcing(monkeypatch, decision):
    install(monkeypatch, FakeApi(decision=decision))
    g = _guard(on_deny="skip")
    _, ctx = g.guard_before_tool("send_email", "hello there")
    assert ctx.blocked
    assert "send_email" in ctx.block_message


def test_review_message_is_clear(monkeypatch):
    install(monkeypatch, FakeApi(decision="review"))
    g = _guard(on_deny="skip")
    _, ctx = g.guard_before_tool("send_email", "hello there")
    assert "review" in ctx.block_message.lower()


def test_review_raises_with_on_deny_raise(monkeypatch):
    install(monkeypatch, FakeApi(decision="review"))
    with pytest.raises(PermissionError, match="review"):
        _guard(on_deny="raise").guard_before_tool("t", "hello there")


def test_allow_passes(monkeypatch):
    install(monkeypatch, FakeApi(decision="allow"))
    _, ctx = _guard(guard_pii=False).guard_before_tool("t", "hello there")
    assert not ctx.blocked


def test_decision_api_failure_fails_closed(monkeypatch):
    install(monkeypatch, FakeApi(decision_error=RuntimeError("boom")))
    _, ctx = _guard(on_deny="skip").guard_before_tool("t", "hello there")
    assert ctx.blocked


def test_on_deny_log_never_blocks(monkeypatch):
    install(monkeypatch, FakeApi(decision="deny"))
    _, ctx = _guard(on_deny="log").guard_before_tool("t", "hello there")
    assert not ctx.blocked


def test_secret_in_tool_input_never_reaches_api_or_tool(monkeypatch):
    api = install(monkeypatch, FakeApi())
    g = _guard(guard_enforce=False)
    out, _ = g.guard_before_tool("t", {"cmd": f"export TOKEN={GH_TOKEN}"})
    assert GH_TOKEN not in str(out)
    assert GH_TOKEN not in api.all_text_sent()


def test_secret_in_tool_output_is_redacted_and_not_sent_in_audit(monkeypatch):
    api = install(monkeypatch, FakeApi())
    g = _guard(guard_enforce=False)
    _, ctx = g.guard_before_tool("t", "hello there")
    out = g.guard_after_tool("t", f"token is {GH_TOKEN}", ctx)
    assert GH_TOKEN not in out
    assert GH_TOKEN not in api.all_text_sent()


def test_secret_in_error_audit_payload_is_redacted(monkeypatch):
    api = install(monkeypatch, FakeApi())
    g = _guard(guard_enforce=False)
    _, ctx = g.guard_before_tool("t", "hello there")
    g.guard_on_error("t", RuntimeError(f"bad key {GH_TOKEN}"), ctx)
    assert GH_TOKEN not in api.all_text_sent()


def test_secret_guard_failure_fails_closed(monkeypatch):
    install(monkeypatch, FakeApi())
    g = _guard(guard_enforce=False)

    def boom(*a, **k):
        raise RuntimeError("tripwire broke")

    monkeypatch.setattr(type(g._guard_client), "guard_outbound_text", boom)
    out, _ = g.guard_before_tool("t", {"cmd": f"export TOKEN={GH_TOKEN}"})
    assert GH_TOKEN not in str(out)


def test_nested_pii_tokenized_in_dicts_and_lists(monkeypatch):
    api = install(monkeypatch, FakeApi())
    g = _guard(guard_enforce=False)
    payload = {
        "to": {"primary": f"mail {EMAIL}", "cc": [f"cc {EMAIL}", {"deep": f"x {EMAIL}"}]},
        "n": 3,
        "flag": True,
    }
    out, ctx = g.guard_before_tool("t", payload)
    assert EMAIL not in str(out)
    assert out["to"]["cc"][1]["deep"] == "x [EMAIL_1]"
    assert out["n"] == 3 and out["flag"] is True
    assert ctx.tokens_created == 3
    assert EMAIL in str(payload)  # original not mutated


def test_pii_tokenization_failure_on_input_fails_closed(monkeypatch):
    api = FakeApi()
    install(monkeypatch, api)
    g = _guard(guard_enforce=False, on_deny="skip")
    orig = api.request

    def failing(client, path, **kw):
        if path.endswith("/pii/tokenize"):
            raise RuntimeError("tokenizer down")
        return orig(client, path, **kw)

    api.request = failing
    out, ctx = g.guard_before_tool("t", f"mail {EMAIL}")
    assert ctx.blocked
