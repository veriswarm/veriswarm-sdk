"""Claude Agent SDK / OpenAI Agents / decorator adapters: wrapping + non-blocking async."""
import asyncio
import threading

import pytest

from .adapter_fakes import EMAIL, FakeApi, install


# ---------- decorator ----------

def test_decorator_async_does_not_block_event_loop(monkeypatch):
    from veriswarm.adapters.decorator import configure_guard, guard_protected

    api = install(monkeypatch, FakeApi())
    configure_guard(api_key="k", agent_id="agt_t", base_url="https://example.invalid")

    @guard_protected
    async def fetch(q: str) -> str:
        return "ok result"

    async def go():
        main = threading.current_thread().name
        res = await fetch("query text")
        return main, res

    main, res = asyncio.run(go())
    assert res == "ok result"
    assert api.calls
    assert all(t != main for _p, _m, _b, t in api.calls), "blocking HTTP ran on the loop thread"


# ---------- claude_sdk ----------

def test_claude_plain_async_callable_nonblocking(monkeypatch):
    from veriswarm.adapters.claude_sdk import VeriSwarmClaudeGuard

    api = install(monkeypatch, FakeApi())
    g = VeriSwarmClaudeGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid")

    @g.protect
    async def tool_fn(q: str) -> str:
        return "fine"

    async def go():
        return threading.current_thread().name, await tool_fn("some query")

    main, res = asyncio.run(go())
    assert res == "fine"
    assert all(t != main for _p, _m, _b, t in api.calls)


def test_claude_sdk_mcp_tool_is_wrapped_and_blocks(monkeypatch):
    sdk = pytest.importorskip("claude_agent_sdk")
    from veriswarm.adapters.claude_sdk import VeriSwarmClaudeGuard

    api = install(monkeypatch, FakeApi(decision="deny"))
    ran = []

    @sdk.tool("danger", "does a thing", {"x": str})
    async def danger(args):
        ran.append(args)
        return {"content": [{"type": "text", "text": "executed"}]}

    g = VeriSwarmClaudeGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid", on_deny="skip")
    wrapped = g.wrap_tool(danger)
    assert isinstance(wrapped, sdk.SdkMcpTool)
    assert wrapped.name == "danger" and wrapped.input_schema == danger.input_schema
    res = asyncio.run(wrapped.handler({"x": "hi"}))
    assert ran == []
    assert res.get("is_error") is True
    assert "blocked" in res["content"][0]["text"]


def test_claude_sdk_mcp_tool_allowed_filters_input_and_output(monkeypatch):
    sdk = pytest.importorskip("claude_agent_sdk")
    from veriswarm.adapters.claude_sdk import VeriSwarmClaudeGuard

    api = install(monkeypatch, FakeApi(decision="allow"))
    seen = []

    @sdk.tool("lookup", "lookup", {"who": str})
    async def lookup(args):
        seen.append(args)
        return {"content": [{"type": "text", "text": f"user is {EMAIL}"}]}

    g = VeriSwarmClaudeGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid")
    wrapped = g.wrap_tool(lookup)

    async def go():
        main = threading.current_thread().name
        return main, await wrapped.handler({"who": f"find {EMAIL}"})

    main, res = asyncio.run(go())
    assert seen == [{"who": "find [EMAIL_1]"}]
    assert res["content"][0]["text"] == "user is [EMAIL_1]"
    assert all(t != main for _p, _m, _b, t in api.calls)
    assert len(api.to("/v1/events")) == 1  # one audit event, not one per content block


def test_claude_sdk_original_tool_not_mutated(monkeypatch):
    sdk = pytest.importorskip("claude_agent_sdk")
    from veriswarm.adapters.claude_sdk import VeriSwarmClaudeGuard

    install(monkeypatch, FakeApi())

    @sdk.tool("t", "d", {"x": str})
    async def t(args):
        return {"content": []}

    orig = t.handler
    VeriSwarmClaudeGuard(api_key="k", agent_id="a", base_url="https://example.invalid").wrap_tool(t)
    assert t.handler is orig


# ---------- openai_agents ----------

def test_openai_sync_callable_stays_sync(monkeypatch):
    from veriswarm.adapters.openai_agents import VeriSwarmOpenAIGuard

    install(monkeypatch, FakeApi())
    g = VeriSwarmOpenAIGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid")

    def tool_fn(q: str) -> str:
        return "sync result"

    wrapped = g.wrap_tool(tool_fn)
    assert not asyncio.iscoroutinefunction(wrapped)
    assert wrapped("some query") == "sync result"


def test_openai_async_callable_nonblocking_and_kwargs_seen(monkeypatch):
    from veriswarm.adapters.openai_agents import VeriSwarmOpenAIGuard

    api = install(monkeypatch, FakeApi())
    g = VeriSwarmOpenAIGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid")

    async def tool_fn(q: str) -> str:
        return "async result"

    wrapped = g.wrap_tool(tool_fn)
    assert asyncio.iscoroutinefunction(wrapped)

    async def go():
        return threading.current_thread().name, await wrapped(q="some query")

    main, res = asyncio.run(go())
    assert res == "async result"
    assert all(t != main for _p, _m, _b, t in api.calls)


def test_openai_function_tool_invoke_nonblocking_and_blocks(monkeypatch):
    agents = pytest.importorskip("agents")
    from veriswarm.adapters.openai_agents import VeriSwarmOpenAIGuard

    api = install(monkeypatch, FakeApi(decision="review"))
    ran = []

    async def invoke(ctx, input_str):
        ran.append(input_str)
        return "executed"

    ft = agents.FunctionTool(
        name="danger", description="d",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )
    g = VeriSwarmOpenAIGuard(api_key="k", agent_id="agt_t", base_url="https://example.invalid", on_deny="skip")
    wrapped = g.wrap_tool(ft)

    async def go():
        return threading.current_thread().name, await wrapped.on_invoke_tool(None, "{}")

    main, res = asyncio.run(go())
    assert ran == [] and "requires review" in res
    assert all(t != main for _p, _m, _b, t in api.calls)
