import json

from veriswarm_mcp.hooks import activity_reporter


class _OkResponse:
    def raise_for_status(self):
        return None


def test_flush_uploads_shell_activity_entries(monkeypatch, tmp_path):
    buffer_file = tmp_path / "activity.jsonl"
    monkeypatch.setattr(activity_reporter, "BUFFER_FILE", buffer_file)
    monkeypatch.setenv("VERISWARM_API_KEY", "test-key")
    monkeypatch.delenv("VERISWARM_AGENT_KEY", raising=False)
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_test")

    buffer_file.write_text(
        json.dumps(
            {
                "ts": "2026-08-17T07:00:00Z",
                "sid": "session-1",
                "event": "PreToolUse",
                "tool": "Shell",
                "input_bytes": 42,
                "output_bytes": 0,
            }
        )
        + "\n"
    )

    posted = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posted.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return _OkResponse()

    monkeypatch.setattr(activity_reporter.httpx, "post", fake_post)

    activity_reporter.flush_to_api()

    assert len(posted) == 1
    payload = posted[0]["json"]
    assert payload["agent_id"] == "agt_test"
    assert payload["source_type"] == "guard_hook"
    assert payload["event_type"] == "PreToolUse"
    assert payload["payload"] == {
        "session_id": "session-1",
        "tool": "Shell",
        "input_bytes": 42,
        "output_bytes": 0,
    }
    assert not buffer_file.exists()


def test_flush_requeues_unsent_events(monkeypatch, tmp_path):
    buffer_file = tmp_path / "activity.jsonl"
    monkeypatch.setattr(activity_reporter, "BUFFER_FILE", buffer_file)
    monkeypatch.setenv("VERISWARM_API_KEY", "test-key")
    monkeypatch.delenv("VERISWARM_AGENT_KEY", raising=False)
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_test")

    event = {
        "event_id": "evt1",
        "event_type": "agent.session.started",
        "session_id": "session-1",
        "ts": "2026-08-17T07:00:00Z",
        "meta": {"cwd": "/workspace"},
    }
    buffer_file.write_text(json.dumps(event) + "\n")

    def fake_post(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(activity_reporter.httpx, "post", fake_post)

    activity_reporter.flush_to_api()

    assert buffer_file.exists()
    assert [json.loads(line) for line in buffer_file.read_text().splitlines()] == [event]


# ── Config precedence, buffer bounds, error handling ─────────────────

import os
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

LOGGER_SH = Path(activity_reporter.__file__).with_name("activity_logger.sh")


class _StatusResponse:
    def __init__(self, status):
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://api.veriswarm.ai/v1/events")
            raise httpx.HTTPStatusError(
                "err", request=request, response=httpx.Response(self.status_code, request=request)
            )


def _write_env_file(home, **values):
    env_dir = Path(home) / ".veriswarm"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / "env").write_text("".join(f"{k}={v}\n" for k, v in values.items()))


def _buffer(monkeypatch, tmp_path, events):
    buffer_file = tmp_path / "activity.jsonl"
    monkeypatch.setattr(activity_reporter, "BUFFER_FILE", buffer_file)
    buffer_file.write_text("".join(json.dumps(e) + "\n" for e in events))
    return buffer_file


def _capture_posts(monkeypatch, status=200):
    posted = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posted.append({"url": url, "json": json, "headers": headers})
        return _StatusResponse(status(json) if callable(status) else status)

    monkeypatch.setattr(activity_reporter.httpx, "post", fake_post)
    return posted


def test_env_vars_take_precedence_over_env_file_per_key(monkeypatch, _isolated_home):
    _write_env_file(
        _isolated_home,
        VERISWARM_API_KEY="file-key",
        VERISWARM_API_URL="https://file.example.com",
        GUARD_AGENT_ID="agt_file",
        VERISWARM_AGENT_KEY="file-agent-key",
    )
    monkeypatch.setenv("VERISWARM_API_URL", "https://env.example.com")
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_env")

    api_url, api_key, agent_id, agent_key = activity_reporter._load_config()

    assert api_url == "https://env.example.com"
    assert agent_id == "agt_env"
    # Keys absent from the environment are still filled from the file.
    assert api_key == "file-key"
    assert agent_key == "file-agent-key"


def test_flush_without_agent_id_skips_upload_keeps_buffer_and_warns_once(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    event = {"event_id": "e1", "event_type": "x", "session_id": "s", "ts": "t", "meta": {}}
    buffer_file = _buffer(monkeypatch, tmp_path, [event])
    posted = _capture_posts(monkeypatch)

    activity_reporter.flush_to_api()
    activity_reporter.flush_to_api()

    assert posted == []
    assert [json.loads(l) for l in buffer_file.read_text().splitlines()] == [event]
    assert capsys.readouterr().err.count("GUARD_AGENT_ID") == 1


def test_payload_never_uses_a_fake_default_agent_id():
    payload = activity_reporter._event_payload({"event_type": "x"}, "agt_real")
    assert payload["agent_id"] == "agt_real"
    assert "claude-code-session" not in json.dumps(payload)


@pytest.mark.parametrize("status,requeued", [
    # Payload-specific rejections: the same event will never be accepted.
    (400, False), (413, False), (422, False),
    # Configuration errors (bad key, wrong agent id): keep for after the fix.
    (401, True), (403, True), (404, True),
    # Transient.
    (408, True), (429, True), (500, True), (503, True),
])
def test_only_payload_rejections_are_dropped(monkeypatch, tmp_path, capsys, status, requeued):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_test")
    event = {"event_id": "e1", "event_type": "x", "session_id": "s", "ts": "t", "meta": {}}
    buffer_file = _buffer(monkeypatch, tmp_path, [event])
    _capture_posts(monkeypatch, status)

    activity_reporter.flush_to_api()

    remaining = buffer_file.read_text().splitlines() if buffer_file.exists() else []
    assert (len(remaining) == 1) is requeued
    err = capsys.readouterr().err
    if not requeued:
        assert "dropped 1" in err


def test_dropped_count_is_reported_once_per_flush(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_test")
    events = [{"event_id": f"e{i}", "event_type": "x", "meta": {}} for i in range(3)]
    _buffer(monkeypatch, tmp_path, events)
    _capture_posts(monkeypatch, lambda payload: 422 if payload["event_id"] != "e1" else 200)

    activity_reporter.flush_to_api()

    err = capsys.readouterr().err
    assert err.count("dropped") == 1
    assert "dropped 2" in err


def test_config_error_events_survive_until_config_is_fixed(monkeypatch, tmp_path):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_wrong")
    event = {"event_id": "e1", "event_type": "x", "session_id": "s", "ts": "t", "meta": {}}
    _buffer(monkeypatch, tmp_path, [event])
    _capture_posts(monkeypatch, 403)
    activity_reporter.flush_to_api()

    monkeypatch.setenv("GUARD_AGENT_ID", "agt_right")
    posted = _capture_posts(monkeypatch, 200)
    activity_reporter.flush_to_api()

    assert [p["json"]["event_id"] for p in posted] == ["e1"]
    assert posted[0]["json"]["agent_id"] == "agt_right"


def test_buffer_event_evicts_oldest_past_max_and_warns(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(activity_reporter, "MAX_BUFFER_SIZE", 5)
    monkeypatch.setattr(activity_reporter, "maybe_flush", lambda count: None)
    buffer_file = _buffer(monkeypatch, tmp_path, [])

    for i in range(12):
        activity_reporter.buffer_event("x", {"i": i})

    kept = [json.loads(l)["meta"]["i"] for l in buffer_file.read_text().splitlines()]
    assert kept == [7, 8, 9, 10, 11]
    assert "evicted" in capsys.readouterr().err


def test_requeue_evicts_oldest_past_max_and_warns(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(activity_reporter, "MAX_BUFFER_SIZE", 3)
    buffer_file = _buffer(monkeypatch, tmp_path, [{"n": "new"}])

    activity_reporter._requeue_events([{"n": i} for i in range(10)])

    # Requeued events are older than ones buffered meanwhile; oldest go first.
    assert [json.loads(l)["n"] for l in buffer_file.read_text().splitlines()] == [8, 9, "new"]
    assert "evicted 8" in capsys.readouterr().err


def test_buffer_event_records_given_session_id(monkeypatch, tmp_path):
    monkeypatch.setattr(activity_reporter, "maybe_flush", lambda count: None)
    buffer_file = _buffer(monkeypatch, tmp_path, [])

    activity_reporter.buffer_event("x", {}, session_id="sess-from-hook")

    assert json.loads(buffer_file.read_text())["session_id"] == "sess-from-hook"


# ── activity_logger.sh (Claude Code hook payload) ────────────────────

def _post_tool_payload():
    return {
        "session_id": "sess-abc",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/work",
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/work/a.txt", "content": "hi"},
        "tool_response": {"filePath": "/work/a.txt", "type": "create"},
        "tool_use_id": "toolu_1",
    }


def _run_logger(home, path_env=None):
    env = {"HOME": str(home), "PATH": path_env or os.environ["PATH"]}
    subprocess.run(
        ["bash", str(LOGGER_SH)],
        input=json.dumps(_post_tool_payload()), text=True, env=env, check=True, timeout=20,
    )
    lines = (Path(home) / ".veriswarm" / "activity.jsonl").read_text().splitlines()
    return [json.loads(l) for l in lines]


def _python_only_path(tmp_path):
    """A PATH with the tools the logger needs but without jq."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("bash", "cat", "mkdir", "dirname", "python3", "wc", "tr"):
        found = shutil.which(tool)
        if found:
            (bindir / tool).symlink_to(found)
    return str(bindir)


@pytest.mark.parametrize("mode", ["jq", "python"])
def test_activity_logger_reads_tool_response_and_payload_session_id(tmp_path, _isolated_home, mode):
    if mode == "jq" and not shutil.which("jq"):
        pytest.skip("jq not installed")
    path_env = _python_only_path(tmp_path) if mode == "python" else None

    entries = _run_logger(_isolated_home, path_env)

    assert entries[-1]["sid"] == "sess-abc"
    assert entries[-1]["tool"] == "Write"
    assert entries[-1]["output_bytes"] > 0


def test_activity_logger_stops_appending_at_max_buffer(tmp_path, _isolated_home):
    buffer_file = Path(_isolated_home) / ".veriswarm" / "activity.jsonl"
    buffer_file.parent.mkdir(parents=True)
    buffer_file.write_text("{}\n" * activity_reporter.MAX_BUFFER_SIZE)

    _run_logger(_isolated_home)

    assert len(buffer_file.read_text().splitlines()) == activity_reporter.MAX_BUFFER_SIZE
