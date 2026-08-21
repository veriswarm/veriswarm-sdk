import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest
from veriswarm_mcp.client import VeriSwarmAPIClient
from veriswarm_mcp.tools import a2a


def _get_invoke_tool(client):
    """Register a2a tools on a fake server and return the captured invoke_a2a_agent fn."""
    captured = {}

    class FakeServer:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    a2a.register(FakeServer(), client)
    return captured["invoke_a2a_agent"]


def test_invoke_submits_polls_and_returns_completed():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    poll = {"n": 0}

    def fake_post(path, json=None, **kw):
        assert path == "/v1/a2a/agt_x/tasks"
        return {"id": "a2a_task_1", "status": "submitted"}

    def fake_get(path, **kw):
        poll["n"] += 1
        if poll["n"] < 2:
            return {"id": "a2a_task_1", "status": "working"}
        return {"id": "a2a_task_1", "status": "completed",
                "artifacts": [{"role": "assistant", "content": "done"}]}

    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", side_effect=fake_get):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}]),
                             max_wait_seconds=5, poll_interval_seconds=0.25))
    data = json.loads(out)
    assert data["status"] == "completed"
    assert data["artifacts"][0]["content"] == "done"
    assert poll["n"] >= 2


def test_invoke_includes_signature_envelope_in_submission():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    posted = {}

    def fake_post(path, json=None, **kw):
        posted["path"] = path
        posted["body"] = json
        return {"id": "a2a_task_1", "status": "submitted"}

    def fake_get(path, **kw):
        return {"id": "a2a_task_1", "status": "completed"}

    signature = {"key_id": "key_1", "signature": "sig_abc", "algo": "ed25519"}
    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", side_effect=fake_get):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn(
            "agt_x",
            "agt_req",
            json.dumps([{"role": "user", "content": "go"}]),
            signature_json=json.dumps(signature),
            max_wait_seconds=5,
            poll_interval_seconds=0.25,
        ))

    assert json.loads(out)["status"] == "completed"
    assert posted["path"] == "/v1/a2a/agt_x/tasks"
    assert posted["body"]["signature"] == signature


@pytest.mark.parametrize("terminal_status", ["failed", "canceled"])
def test_invoke_stops_on_non_success_terminal_statuses(terminal_status):
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")

    def fake_post(path, json=None, **kw):
        return {"id": "a2a_task_1", "status": "submitted"}

    def fake_get(path, **kw):
        return {"id": "a2a_task_1", "status": terminal_status}

    sleep_mock = AsyncMock()
    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", side_effect=fake_get), \
         patch("asyncio.sleep", sleep_mock):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn(
            "agt_x",
            "agt_req",
            json.dumps([{"role": "user", "content": "go"}]),
            max_wait_seconds=5,
            poll_interval_seconds=0.25,
        ))

    data = json.loads(out)
    assert data["status"] == terminal_status
    assert "timed_out" not in data
    sleep_mock.assert_not_awaited()


def test_invoke_rejects_invalid_signature_json_before_submit():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")

    with patch.object(client, "post") as post:
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn(
            "agt_x",
            "agt_req",
            json.dumps([{"role": "user", "content": "go"}]),
            signature_json="{not valid json",
        ))

    data = json.loads(out)
    assert "error" in data
    post.assert_not_called()


def test_invoke_times_out_without_raising():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    with patch.object(client, "post", side_effect=lambda *a, **k: {"id": "t1", "status": "submitted"}), \
         patch.object(client, "get", side_effect=lambda *a, **k: {"id": "t1", "status": "working"}):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}]),
                             max_wait_seconds=1, poll_interval_seconds=0.25))
    data = json.loads(out)
    assert data["status"] == "working"
    assert data["timed_out"] is True


def test_invoke_rejects_bad_agent_id():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    fn = _get_invoke_tool(client)
    out = asyncio.run(fn("../etc/passwd", "agt_req", "[]"))
    assert "error" in json.loads(out)  # safe_error_response, no raise


def test_invoke_rejects_non_list_messages():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    fn = _get_invoke_tool(client)
    out = asyncio.run(fn("agt_x", "agt_req", json.dumps({"not": "a list"})))
    assert "error" in json.loads(out)
