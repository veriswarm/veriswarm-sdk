"""Hardening tests for the MCP tool layer.

Covers path-segment injection, sanitised HTTP error responses, keeping
blocking HTTP off the event loop, and the agents-overview query contract.
"""
from __future__ import annotations

import ast
import asyncio
import json
import threading
from pathlib import Path

import httpx
import pytest

from veriswarm_mcp.client import VeriSwarmAPIClient
from veriswarm_mcp.tools import (
    a2a,
    agents,
    approvals,
    compliance_and_sre,
    events,
    guard,
    passport,
    platform,
    runtime,
    trust,
    vault,
    workflows,
)
from veriswarm_mcp.tools._shared import ToolValidationError, q_path, safe_id

TOOLS_DIR = Path(__file__).resolve().parent.parent / "veriswarm_mcp" / "tools"
ALL_MODULES = [
    a2a, agents, approvals, compliance_and_sre, events, guard,
    passport, platform, runtime, trust, vault, workflows,
]
HTTP_METHODS = ("get", "post", "put", "patch", "delete")


class _CaptureServer:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


def _tools_for(module, client):
    server = _CaptureServer()
    module.register(server, client)
    return server.tools


def _forbid_http(monkeypatch, client):
    sent = []
    for method in HTTP_METHODS:
        def _record(*args, _m=method, **kwargs):
            sent.append((_m, args, kwargs))
            return {}
        monkeypatch.setattr(client, method, _record)
    return sent


@pytest.fixture
def client():
    return VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")


# ── Path injection ───────────────────────────────────────────────────

EXPLOIT = "../../guard/unkill/agt_x?"

# (module, tool, kwargs) — the injected value goes into the path parameter.
PATH_TOOLS = [
    (trust, "check_trust", {"agent_id": EXPLOIT}),
    (trust, "get_score_history", {"agent_id": EXPLOIT}),
    (trust, "get_score_breakdown", {"agent_id": EXPLOIT}),
    (trust, "explain_score", {"agent_id": EXPLOIT}),
    (agents, "get_agent", {"agent_id": EXPLOIT}),
    (agents, "get_agent_timeline", {"agent_id": EXPLOIT}),
    (agents, "get_agent_flags", {"agent_id": EXPLOIT}),
    (passport, "verify_identity", {"agent_id": EXPLOIT}),
    (workflows, "get_workflow", {"workflow_id": EXPLOIT}),
    (workflows, "run_workflow", {"workflow_id": EXPLOIT}),
    (workflows, "get_execution", {"execution_id": EXPLOIT}),
    (workflows, "activate_workflow", {"workflow_id": EXPLOIT}),
    (workflows, "deactivate_workflow", {"workflow_id": EXPLOIT}),
    (workflows, "deploy_template", {"template_id": EXPLOIT}),
    (workflows, "cancel_workflow_execution", {"execution_id": EXPLOIT}),
    (workflows, "retry_workflow_execution", {"execution_id": EXPLOIT}),
    (runtime, "get_agent_analytics", {"agent_id": EXPLOIT}),
    (runtime, "get_cost_recommendations", {"agent_id": EXPLOIT}),
    (runtime, "verify_deletion", {"record_id": EXPLOIT}),
    (runtime, "get_agent_reputation", {"agent_id": EXPLOIT}),
    (runtime, "get_a2a_history", {"agent_id": EXPLOIT}),
    (runtime, "get_benchmark_history", {"agent_id": EXPLOIT}),
    (compliance_and_sre, "get_compliance_report", {"framework_id": EXPLOIT}),
    (compliance_and_sre, "reset_circuit_breaker", {"provider": EXPLOIT, "model": "gpt-4.1"}),
    (compliance_and_sre, "reset_circuit_breaker", {"provider": "openai", "model": ".."}),
    (compliance_and_sre, "provision_a2a_keys", {"agent_id": EXPLOIT}),
    (compliance_and_sre, "get_content_provenance", {"content_hash": EXPLOIT}),
    (compliance_and_sre, "get_agent_attributes", {"agent_id": EXPLOIT}),
    (compliance_and_sre, "set_agent_attributes", {"agent_id": EXPLOIT, "attributes_json": "{}"}),
    (compliance_and_sre, "revoke_jit_grant", {"grant_id": EXPLOIT}),
]


@pytest.mark.parametrize(
    "module,tool_name,kwargs", PATH_TOOLS,
    ids=[f"{t}-{'-'.join(k)}" for _, t, k in PATH_TOOLS],
)
def test_path_tools_reject_traversal_without_sending(monkeypatch, client, module, tool_name, kwargs):
    sent = _forbid_http(monkeypatch, client)
    tool = _tools_for(module, client)[tool_name]

    result = json.loads(asyncio.run(tool(**kwargs)))

    assert sent == [], f"{tool_name} sent a request for a traversal id: {sent}"
    assert result["type"] == "ToolValidationError"


def test_verify_identity_unkill_exploit_sends_nothing(monkeypatch, client):
    """Regression: verify_identity('../../guard/unkill/agt_x?') used to POST
    to /v1/suite/guard/unkill/agt_x — an un-kill via a passport tool."""
    sent = _forbid_http(monkeypatch, client)
    tool = _tools_for(passport, client)["verify_identity"]

    asyncio.run(tool(agent_id="../../guard/unkill/agt_x?"))

    assert sent == []


def test_valid_id_still_reaches_expected_path(monkeypatch, client):
    sent = _forbid_http(monkeypatch, client)
    tool = _tools_for(passport, client)["verify_identity"]

    asyncio.run(tool(agent_id="agt_abc-123"))

    assert sent == [("post", ("/v1/suite/passport/verify/agt_abc-123",), {})]


def test_circuit_breaker_model_with_dots_is_encoded_not_rejected(monkeypatch, client):
    sent = _forbid_http(monkeypatch, client)
    tool = _tools_for(compliance_and_sre, client)["reset_circuit_breaker"]

    asyncio.run(tool(provider="openai", model="gpt-4.1/mini"))

    assert sent[0][1][0] == "/v1/analytics/sre/circuit-breakers/openai/gpt-4.1%2Fmini/reset"


@pytest.mark.parametrize("bad", [".", "..", "a/b", "a?b", "a#b", "a%2Fb", "", "x" * 129, "a.b"])
def test_safe_id_rejects_path_metacharacters(bad):
    with pytest.raises(ToolValidationError):
        safe_id(bad, "agent_id")


@pytest.mark.parametrize("bad", [".", "..", ""])
def test_q_path_rejects_dot_segments(bad):
    with pytest.raises(ToolValidationError):
        q_path(bad)


@pytest.mark.parametrize("value,expected", [
    ("gpt-4.1", "gpt-4.1"), ("a/b", "a%2Fb"), ("a?b#c", "a%3Fb%23c"), ("50%", "50%25"),
])
def test_q_path_encodes_reserved_characters(value, expected):
    assert q_path(value) == expected


def test_no_tool_interpolates_a_raw_name_into_a_path():
    """Every `{...}` in an f-string API path must be a safe_id/q_path result.

    Enforced structurally: each interpolated name must have been assigned
    from safe_id(...) / q_path(...) earlier in the same function.
    """
    offenders = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.AsyncFunctionDef):
                continue
            sanitized = set()
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call)
                    and getattr(node.value.func, "id", "") in {"safe_id", "q_path"}
                ):
                    sanitized.update(t.id for t in node.targets if isinstance(t, ast.Name))
            for node in ast.walk(fn):
                if not isinstance(node, ast.JoinedStr):
                    continue
                head = node.values[0] if node.values else None
                if not (isinstance(head, ast.Constant) and str(head.value).startswith("/v1")):
                    continue
                for part in node.values:
                    if isinstance(part, ast.FormattedValue):
                        name = getattr(part.value, "id", None)
                        if name not in sanitized:
                            offenders.append(f"{path.name}:{node.lineno} {fn.name} -> {ast.unparse(part.value)}")
    assert offenders == []


# ── Sanitised HTTP errors ────────────────────────────────────────────

def _http_error(status=500, body="internal host db-7.corp.local:5432 stack trace"):
    request = httpx.Request("GET", "https://api.veriswarm.ai/v1/x")
    response = httpx.Response(status, text=body, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


def test_http_status_errors_never_leak_response_body():
    """No tool module may put exc.response.text into a tool result."""
    offenders = [
        p.name for p in TOOLS_DIR.glob("*.py") if "response.text" in p.read_text()
    ]
    assert offenders == []


@pytest.mark.parametrize("module,tool_name,kwargs", [
    (trust, "check_trust", {"agent_id": "agt_1"}),
    (passport, "verify_identity", {"agent_id": "agt_1"}),
    (a2a, "get_a2a_task", {"agent_id": "agt_1", "task_id": "a2a_1"}),
    (platform, "platform_status", {}),
])
def test_http_status_error_result_is_sanitised(monkeypatch, client, module, tool_name, kwargs):
    def _raise(*a, **k):
        raise _http_error(403)
    for method in HTTP_METHODS:
        monkeypatch.setattr(client, method, _raise)
    tool = _tools_for(module, client)[tool_name]

    raw = asyncio.run(tool(**kwargs))
    result = json.loads(raw)

    assert "db-7.corp.local" not in raw
    assert result["status_code"] == 403
    assert result["type"] == "HTTPStatusError"


def test_a2a_poll_failure_does_not_leak_response_body(monkeypatch, client):
    monkeypatch.setattr(client, "post", lambda *a, **k: {"id": "a2a_t1", "status": "submitted"})

    def _raise(*a, **k):
        raise _http_error(502)
    monkeypatch.setattr(client, "get", _raise)
    tool = _tools_for(a2a, client)["invoke_a2a_agent"]

    raw = asyncio.run(tool(
        agent_id="agt_1", requesting_agent_id="agt_2",
        messages_json="[]", max_wait_seconds=1, poll_interval_seconds=0.25,
    ))

    assert "db-7.corp.local" not in raw
    assert json.loads(raw)["poll_failed"] is True


# ── Blocking I/O off the event loop ──────────────────────────────────

def test_no_tool_calls_the_sync_client_directly():
    """Every API call in an async tool must go through the shared async
    helper so the sync httpx client never blocks the event loop."""
    offenders = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in HTTP_METHODS
                and getattr(node.func.value, "id", None) == "client"
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


@pytest.mark.parametrize("module,tool_name,kwargs", [
    (trust, "check_trust", {"agent_id": "agt_1"}),
    (events, "report_incident", {"severity": "low", "description": "y", "agent_id": "agt_1"}),
    (vault, "verify_chain", {}),
])
def test_tool_http_runs_off_the_event_loop_thread(monkeypatch, client, module, tool_name, kwargs):
    threads = []

    def _record(*a, **k):
        threads.append(threading.current_thread())
        return {}
    for method in HTTP_METHODS:
        monkeypatch.setattr(client, method, _record)
    tool = _tools_for(module, client)[tool_name]

    asyncio.run(tool(**kwargs))

    assert threads, "tool made no API call"
    assert all(t is not threading.main_thread() for t in threads)


# ── list_agents query contract ───────────────────────────────────────

def test_list_agents_sends_query_param_the_server_reads(monkeypatch, client):
    captured = {}
    monkeypatch.setattr(client, "get", lambda path, params=None, **k: captured.update(params=params) or {})
    tool = _tools_for(agents, client)["list_agents"]

    asyncio.run(tool(query="billing", tier="tier_2"))

    assert captured["params"] == {"page": 1, "query": "billing", "tier": "tier_2"}


def test_list_agents_rejects_tier_values_the_server_never_matches(monkeypatch, client):
    sent = _forbid_http(monkeypatch, client)
    tool = _tools_for(agents, client)["list_agents"]

    result = json.loads(asyncio.run(tool(tier="trusted")))

    assert sent == []
    assert "tier_0" in result["error"]
