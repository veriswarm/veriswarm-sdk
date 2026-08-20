import asyncio
import json
from unittest.mock import patch

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


def test_invoke_forwards_signature_payload_when_present():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    messages = [{"role": "user", "content": "go"}]
    signature = {"key_id": "key_1", "signature": "sig", "algo": "ed25519"}
    posted = {}

    def fake_post(path, json=None, **kw):
        posted["path"] = path
        posted["body"] = json
        return {"id": "a2a_task_1", "status": "submitted"}

    def fake_get(path, **kw):
        return {"id": "a2a_task_1", "status": "completed"}

    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", side_effect=fake_get):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn(
            "agt_x",
            "agt_req",
            json.dumps(messages),
            signature_json=json.dumps(signature),
            max_wait_seconds=5,
            poll_interval_seconds=0.25,
        ))

    assert json.loads(out)["status"] == "completed"
    assert posted["path"] == "/v1/a2a/agt_x/tasks"
    assert posted["body"] == {
        "requesting_agent_id": "agt_req",
        "messages": messages,
        "signature": signature,
    }


@pytest.mark.parametrize("terminal_status", ["failed", "canceled"])
def test_invoke_returns_terminal_failures_without_timing_out(terminal_status):
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")

    def fake_post(path, json=None, **kw):
        return {"id": "a2a_task_1", "status": "submitted"}

    def fake_get(path, **kw):
        return {"id": "a2a_task_1", "status": terminal_status}

    async def fail_if_sleeping(interval):
        raise AssertionError("terminal A2A task should not sleep before returning")

    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", side_effect=fake_get), \
         patch("asyncio.sleep", new=fail_if_sleeping):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}])))

    data = json.loads(out)
    assert data["status"] == terminal_status
    assert "timed_out" not in data


def test_invoke_rejects_unsafe_submitted_task_id_before_polling():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")

    with patch.object(client, "post", return_value={"id": "../admin", "status": "submitted"}), \
         patch.object(client, "get") as mock_get:
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}])))

    data = json.loads(out)
    assert "error" in data
    assert data["type"] == "ToolValidationError"
    mock_get.assert_not_called()


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
