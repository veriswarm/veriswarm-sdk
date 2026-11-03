"""Path-segment and query-value encoding for every caller-supplied value."""
from __future__ import annotations

import pytest

from veriswarm import VeriSwarmClient

BASE = "https://api.test"


@pytest.fixture
def client() -> VeriSwarmClient:
    return VeriSwarmClient(base_url=BASE, api_key="vsk_x")


@pytest.mark.parametrize("bad", [".", "..", ""])
def test_rejects_dot_and_empty_path_ids_before_any_request(client, recorder, bad):
    with pytest.raises(ValueError, match="path segment"):
        client.get_agent(bad)
    with pytest.raises(ValueError, match="path segment"):
        client.approve_step("exec_1", bad)
    assert recorder.requests == []


def test_rejects_none_path_ids(client, recorder):
    with pytest.raises(ValueError, match="path segment"):
        client.get_workflow(None)  # type: ignore[arg-type]
    assert recorder.requests == []


def test_reset_circuit_breaker_encodes_model_with_slash(client, recorder):
    client.reset_circuit_breaker("openai", "org/gpt-4o")
    assert recorder.url == f"{BASE}/v1/analytics/sre/circuit-breakers/openai/org%2Fgpt-4o/reset"


def test_reset_circuit_breaker_rejects_dot_segments(client, recorder):
    with pytest.raises(ValueError, match="path segment"):
        client.reset_circuit_breaker("..", "x")
    assert recorder.requests == []


def test_approve_step_encodes_step_id(client, recorder):
    client.approve_step("exec/1", "step 2")
    assert recorder.url == f"{BASE}/v1/workflows/executions/exec%2F1/steps/step%202/approve"


def test_get_content_provenance_encodes_hash(client, recorder):
    client.get_content_provenance("../admin")
    assert recorder.url == f"{BASE}/v1/content/provenance/..%2Fadmin"


def test_badge_url_encodes_every_part(client):
    url = client.get_badge_url("a/b?c", style="card&x=1", theme="dark")
    assert url == f"{BASE}/v1/badge/a%2Fb%3Fc.svg?style=card%26x%3D1&theme=dark"


def test_badge_url_rejects_dot_slug(client):
    with pytest.raises(ValueError, match="path segment"):
        client.get_badge_url("..")


def test_list_executions_encodes_status(client, recorder):
    client.list_executions("wf_1", status="a&b=c")
    assert recorder.url == f"{BASE}/v1/workflows/wf_1/executions?status=a%26b%3Dc"


def test_list_executions_omits_unset_status(client, recorder):
    client.list_executions("wf_1")
    assert recorder.url == f"{BASE}/v1/workflows/wf_1/executions"


def test_list_jit_grants_encodes_status_and_limit(client, recorder):
    client.list_jit_grants(status="x&y", limit="5&z=1")  # type: ignore[arg-type]
    assert recorder.query == {"status": ["x&y"], "limit": ["5&z=1"]}


def test_list_discovered_agents_encodes_status(client, recorder):
    client.list_discovered_agents(status="new&x=1")
    assert recorder.query == {"status": ["new&x=1"]}


def test_context_topics_encodes_days_and_limit(client, recorder):
    client.get_context_topics(days="1&evil=1", limit=3)  # type: ignore[arg-type]
    assert recorder.query == {"days": ["1&evil=1"], "limit": ["3"]}


def test_vault_ledger_encodes_limit(client, recorder):
    client.query_vault_ledger(limit="1&x=2", agent_id="agt 1")  # type: ignore[arg-type]
    assert recorder.query == {"limit": ["1&x=2"], "agent_id": ["agt 1"]}
