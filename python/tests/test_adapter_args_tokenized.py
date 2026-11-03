"""Wrapped functions receive the PII-tokenized / secret-redacted arguments.

The callable wrappers used to tokenize a string rendering of the arguments
and then call the function with the ORIGINAL arguments, so raw PII and
secrets reached the tool. String arguments (positional, keyword, *args,
**kwargs) are now replaced with their guarded values; other argument types
are passed through unchanged.
"""
import asyncio

import pytest

from .adapter_fakes import EMAIL, GH_TOKEN, FakeApi, install

TOKENIZED = "[EMAIL_1]"


def _decorator(monkeypatch):
    from veriswarm.adapters.decorator import configure_guard, guard_protected

    configure_guard(api_key="k", agent_id="agt_t", base_url="https://example.invalid")
    return guard_protected


def _claude(monkeypatch):
    from veriswarm.adapters.claude_sdk import VeriSwarmClaudeGuard

    return VeriSwarmClaudeGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid").protect


def _openai(monkeypatch):
    from veriswarm.adapters.openai_agents import VeriSwarmOpenAIGuard

    return VeriSwarmOpenAIGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid").wrap_tool


def _crewai(monkeypatch):
    from veriswarm.adapters.crewai import VeriSwarmCrewGuard

    return VeriSwarmCrewGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid").wrap_tool


WRAPPERS = {"decorator": _decorator, "claude": _claude, "openai": _openai, "crewai": _crewai}


@pytest.mark.parametrize("which", sorted(WRAPPERS))
def test_sync_wrapper_passes_tokenized_args(monkeypatch, which):
    install(monkeypatch, FakeApi())
    wrap = WRAPPERS[which](monkeypatch)
    seen = {}
    marker = object()

    def tool(note, count, *extra, obj=None, **more):
        seen.update(note=note, count=count, extra=extra, obj=obj, more=more)
        return "done"

    wrapped = wrap(tool)
    result = wrapped(
        f"mail {EMAIL}", 3, f"cc {EMAIL}", 7,
        obj=marker, subject=f"token {GH_TOKEN}", n=1,
    )

    assert result == "done"
    assert seen["note"] == f"mail {TOKENIZED}"
    assert seen["count"] == 3
    assert seen["extra"] == (f"cc {TOKENIZED}", 7)
    assert seen["obj"] is marker  # non-str values untouched (identity kept)
    assert seen["more"]["n"] == 1
    assert GH_TOKEN not in seen["more"]["subject"]
    assert EMAIL not in repr(seen)


@pytest.mark.parametrize("which", ["decorator", "claude", "openai"])
def test_async_wrapper_passes_tokenized_args(monkeypatch, which):
    install(monkeypatch, FakeApi())
    wrap = WRAPPERS[which](monkeypatch)
    seen = {}

    async def tool(note: str, *, other: str = "") -> str:
        seen.update(note=note, other=other)
        return "done"

    wrapped = wrap(tool)
    assert asyncio.run(wrapped(f"to {EMAIL}", other=f"also {EMAIL}")) == "done"
    assert seen == {"note": f"to {TOKENIZED}", "other": f"also {TOKENIZED}"}


@pytest.mark.parametrize("which", sorted(WRAPPERS))
def test_tokenizer_failure_blocks_before_the_function_runs(monkeypatch, which):
    api = FakeApi()
    original = api.request

    def failing(client, path, *, method="GET", body=None):
        if path == "/v1/suite/guard/pii/tokenize":
            raise RuntimeError("tokenizer down")
        return original(client, path, method=method, body=body)

    api.request = failing
    install(monkeypatch, api)
    wrap = WRAPPERS[which](monkeypatch)
    ran = []

    def tool(note):
        ran.append(note)
        return "done"

    with pytest.raises(PermissionError):
        wrap(tool)(f"mail {EMAIL}")
    assert ran == []


def test_method_self_is_passed_through(monkeypatch):
    install(monkeypatch, FakeApi())
    guard_protected = _decorator(monkeypatch)

    class Repo:
        @guard_protected
        def save(self, note):
            return (self, note)

    repo = Repo()
    got_self, note = repo.save(f"mail {EMAIL}")
    assert got_self is repo
    assert note == f"mail {TOKENIZED}"
