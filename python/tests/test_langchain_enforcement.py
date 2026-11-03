"""LangChain handler against real langchain-core: enforcement, timestamps, secrets."""
import asyncio
import logging
from datetime import datetime

import pytest

pytest.importorskip("langchain_core", reason="requires the veriswarm[langchain] extra")
from langchain_core.tools import tool  # noqa: E402

from veriswarm.adapters.langchain import VeriSwarmCallbackHandler  # noqa: E402

from .adapter_fakes import GH_TOKEN, FakeApi, install  # noqa: E402

RAN: list[str] = []


@tool
def danger(x: str) -> str:
    """Do a dangerous thing."""
    RAN.append(x)
    return f"done {x}"


@tool
def leaky(x: str) -> str:
    """Returns a secret."""
    return f"key={GH_TOKEN}"


@pytest.fixture(autouse=True)
def _clear():
    from veriswarm.adapters import guard_mixin

    RAN.clear()
    guard_mixin._last_warned.clear()


def _handler(**kw):
    return VeriSwarmCallbackHandler(
        api_key="k", agent_id="agt_t", base_url="https://example.invalid", **kw
    )


@pytest.mark.parametrize("decision", ["deny", "review"])
def test_enforce_blocks_real_tool_execution(monkeypatch, decision):
    install(monkeypatch, FakeApi(decision=decision))
    h = _handler(enforce=True)
    with pytest.raises(PermissionError):
        danger.invoke("hi", config={"callbacks": [h]})
    assert RAN == []


def test_enforce_blocks_async_tool_execution(monkeypatch):
    install(monkeypatch, FakeApi(decision="deny"))
    h = _handler(enforce=True)

    async def go():
        await danger.ainvoke("hi", config={"callbacks": [h]})

    with pytest.raises(PermissionError):
        asyncio.run(go())
    assert RAN == []


def test_enforce_allows_when_allowed(monkeypatch):
    install(monkeypatch, FakeApi(decision="allow"))
    assert danger.invoke("hi", config={"callbacks": [_handler(enforce=True)]}) == "done hi"
    assert RAN == ["hi"]


def test_enforce_fails_closed_when_decision_api_down(monkeypatch):
    install(monkeypatch, FakeApi(decision_error=RuntimeError("down")))
    with pytest.raises(PermissionError):
        danger.invoke("hi", config={"callbacks": [_handler(enforce=True)]})
    assert RAN == []


def test_on_deny_log_continues(monkeypatch):
    install(monkeypatch, FakeApi(decision="deny"))
    h = _handler(enforce=True, on_deny="log")
    assert danger.invoke("hi", config={"callbacks": [h]}) == "done hi"


def test_not_enforcing_never_raises(monkeypatch):
    api = install(monkeypatch, FakeApi(decision="deny"))
    api.event_error = RuntimeError("events down")
    assert danger.invoke("hi", config={"callbacks": [_handler()]}) == "done hi"


def test_events_carry_utc_iso_timestamp(monkeypatch):
    api = install(monkeypatch, FakeApi())
    danger.invoke("hi", config={"callbacks": [_handler()]})
    events = api.to("/v1/events")
    assert events
    for e in events:
        ts = datetime.fromisoformat(e["occurred_at"])
        assert ts.tzinfo is not None and ts.utcoffset().total_seconds() == 0


def test_denied_tool_does_not_leak_active_run(monkeypatch):
    install(monkeypatch, FakeApi(decision="deny"))
    h = _handler(enforce=True)
    with pytest.raises(PermissionError):
        danger.invoke("hi", config={"callbacks": [h]})
    assert h._active_tools == {}


def test_event_failure_logs_warning_rate_limited(monkeypatch, caplog):
    api = install(monkeypatch, FakeApi())
    api.event_error = RuntimeError("events down")
    h = _handler()
    with caplog.at_level(logging.WARNING, logger="veriswarm.langchain"):
        for _ in range(5):
            danger.invoke("hi", config={"callbacks": [h]})
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert 1 <= len(warns) < 5


def test_output_summary_secret_never_sent(monkeypatch):
    api = install(monkeypatch, FakeApi())
    leaky.invoke("x", config={"callbacks": [_handler()]})
    assert GH_TOKEN not in api.all_text_sent()
    summaries = [e["payload"].get("output_summary") for e in api.to("/v1/events")]
    assert any(s for s in summaries)


def test_secret_straddling_truncation_cut_is_not_leaked_in_output_summary(monkeypatch):
    api = install(monkeypatch, FakeApi())
    # 170 chars + " key=" puts the token start at col 175; the 200-char cut would
    # keep only "ghp_" + 21 of its 36 body chars if truncation ran first.
    out = "x" * 170 + " key=" + GH_TOKEN + " tail"
    h = _handler()
    h.on_tool_end(out, run_id=__import__("uuid").uuid4(), name="t")
    sent = api.all_text_sent()
    assert "ghp_" not in sent
    assert "A" * 10 not in sent
    summary = api.to("/v1/events")[0]["payload"]["output_summary"]
    assert len(summary) <= 200
