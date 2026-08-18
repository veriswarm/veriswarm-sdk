import asyncio
import json
from unittest.mock import Mock, patch

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


def test_invoke_forwards_signature_envelope_in_submit_payload():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    captured = {}
    messages = [{"role": "user", "content": "signed request"}]
    signature = {"key_id": "key_1", "signature": "sig", "algo": "ed25519"}

    def fake_post(path, json=None, **kw):
        captured["path"] = path
        captured["payload"] = json
        return {"id": "a2a_task_1", "status": "submitted"}

    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", return_value={"id": "a2a_task_1", "status": "completed"}):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn(
            "agt_x",
            "agt_req",
            json.dumps(messages),
            signature_json=json.dumps(signature),
        ))

    data = json.loads(out)
    assert data["status"] == "completed"
    assert captured["path"] == "/v1/a2a/agt_x/tasks"
    assert captured["payload"] == {
        "requesting_agent_id": "agt_req",
        "messages": messages,
        "signature": signature,
    }


def test_invoke_rejects_invalid_signature_json_before_submit():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    post = Mock()

    with patch.object(client, "post", post):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn(
            "agt_x",
            "agt_req",
            json.dumps([{"role": "user", "content": "go"}]),
            signature_json="{not-json",
        ))

    data = json.loads(out)
    assert "error" in data
    post.assert_not_called()


def test_invoke_rejects_unsafe_submitted_task_id_before_polling():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    get = Mock()

    with patch.object(client, "post", return_value={"id": "../tasks/other", "status": "submitted"}), \
         patch.object(client, "get", get):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}])))

    data = json.loads(out)
    assert "error" in data
    get.assert_not_called()


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
