import asyncio
import json
import time
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


def test_invoke_forwards_signature_and_returns_failed_terminal_status():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    captured = {"payload": None, "poll_paths": []}
    signature = {"key_id": "key_1", "signature": "sig_1", "algo": "ed25519"}

    def fake_post(path, json=None, **kw):
        assert path == "/v1/a2a/agt_x/tasks"
        captured["payload"] = json
        return {"id": "a2a_task_1", "status": "submitted"}

    def fake_get(path, **kw):
        captured["poll_paths"].append(path)
        return {"id": "a2a_task_1", "status": "failed", "error": "policy_denied"}

    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", side_effect=fake_get):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}]),
                             signature_json=json.dumps(signature),
                             max_wait_seconds=5, poll_interval_seconds=0.25))

    assert captured["payload"] == {
        "requesting_agent_id": "agt_req",
        "messages": [{"role": "user", "content": "go"}],
        "signature": signature,
    }
    assert captured["poll_paths"] == ["/v1/a2a/agt_x/tasks/a2a_task_1"]
    data = json.loads(out)
    assert data["status"] == "failed"
    assert "timed_out" not in data


def test_invoke_rejects_bad_signature_json_without_submitting():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    fn = _get_invoke_tool(client)

    with patch.object(client, "post") as post:
        out = asyncio.run(fn("agt_x", "agt_req", "[]", signature_json="{not-json"))

    post.assert_not_called()
    data = json.loads(out)
    assert data["error"]
    assert data["type"] == "JSONDecodeError"


def test_invoke_returns_task_id_when_polling_fails_after_submit():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")

    with patch.object(client, "post", return_value={"id": "a2a_task_1", "status": "submitted"}), \
         patch.object(client, "get", side_effect=RuntimeError("network down")):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn(
            "agt_x",
            "agt_req",
            json.dumps([{"role": "user", "content": "go"}]),
            max_wait_seconds=5,
            poll_interval_seconds=0.25,
        ))

    data = json.loads(out)
    assert data["id"] == "a2a_task_1"
    assert data["status"] == "submitted"
    assert data["poll_failed"] is True
    assert "get_a2a_task" in data["error"]


def test_invoke_polling_does_not_block_event_loop():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    get_started = asyncio.Event()
    ticker_ran_during_get = asyncio.Event()

    def fake_post(path, json=None, **kw):
        return {"id": "a2a_task_1", "status": "submitted"}

    def fake_get(path, **kw):
        get_started_loop.call_soon_threadsafe(get_started.set)
        time.sleep(0.2)
        return {"id": "a2a_task_1", "status": "completed"}

    async def run_invoke_and_ticker():
        nonlocal get_started_loop
        get_started_loop = asyncio.get_running_loop()
        fn = _get_invoke_tool(client)

        async def ticker():
            await get_started.wait()
            await asyncio.sleep(0.01)
            ticker_ran_during_get.set()

        task = asyncio.create_task(
            fn(
                "agt_x",
                "agt_req",
                json.dumps([{"role": "user", "content": "go"}]),
                max_wait_seconds=5,
                poll_interval_seconds=0.25,
            )
        )
        ticker_task = asyncio.create_task(ticker())
        out = await task
        # Sampled *before* awaiting the ticker: if the poll blocked the event
        # loop, the ticker cannot have resumed while invoke was still running.
        observed = ticker_ran_during_get.is_set()
        ticker_task.cancel()
        await asyncio.gather(ticker_task, return_exceptions=True)
        return out, observed

    get_started_loop = None
    with patch.object(client, "post", side_effect=fake_post), \
         patch.object(client, "get", side_effect=fake_get):
        out, ticker_ran_before_invoke_returned = asyncio.run(run_invoke_and_ticker())

    data = json.loads(out)
    assert data["status"] == "completed"
    assert ticker_ran_before_invoke_returned


@pytest.mark.parametrize("terminal_status", ["failed", "canceled"])
def test_invoke_returns_terminal_failure_states_without_timing_out(terminal_status):
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    poll = {"n": 0}

    def fake_get(path, **kw):
        poll["n"] += 1
        assert path == "/v1/a2a/agt_x/tasks/a2a_task_1"
        return {
            "id": "a2a_task_1",
            "status": terminal_status,
            "error": {"message": "terminal result"},
        }

    with patch.object(client, "post", return_value={"id": "a2a_task_1", "status": "submitted"}), \
         patch.object(client, "get", side_effect=fake_get):
        fn = _get_invoke_tool(client)
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}])))

    data = json.loads(out)
    assert data["status"] == terminal_status
    assert data["error"]["message"] == "terminal result"
    assert "timed_out" not in data
    assert poll["n"] == 1


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


def test_invoke_rejects_invalid_signature_json_without_submitting():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    fn = _get_invoke_tool(client)

    with patch.object(client, "post") as post, patch.object(client, "get") as get:
        out = asyncio.run(
            fn(
                "agt_x",
                "agt_req",
                json.dumps([{"role": "user", "content": "go"}]),
                signature_json="{not valid json",
            )
        )

    data = json.loads(out)
    assert "error" in data
    post.assert_not_called()
    get.assert_not_called()


def test_invoke_rejects_missing_submitted_task_id_without_polling():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    fn = _get_invoke_tool(client)

    with patch.object(client, "post", return_value={"status": "submitted"}) as post, \
         patch.object(client, "get") as get:
        out = asyncio.run(fn("agt_x", "agt_req", json.dumps([{"role": "user", "content": "go"}])))

    data = json.loads(out)
    assert "error" in data
    post.assert_called_once()
    get.assert_not_called()
