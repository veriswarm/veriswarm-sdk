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
import sys
import time
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
    assert (tmp_path / "activity_reporter.log").read_text().count("GUARD_AGENT_ID") == 1


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
    log = tmp_path / "activity_reporter.log"
    if not requeued:
        assert "dropped 1" in log.read_text()


def test_dropped_count_is_reported_once_per_flush(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_test")
    events = [{"event_id": f"e{i}", "event_type": "x", "meta": {}} for i in range(3)]
    _buffer(monkeypatch, tmp_path, events)
    _capture_posts(monkeypatch, lambda payload: 422 if payload["event_id"] != "e1" else 200)

    activity_reporter.flush_to_api()

    log = (tmp_path / "activity_reporter.log").read_text()
    assert log.count("dropped") == 1
    assert "dropped 2" in log


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
    assert "evicted" in (tmp_path / "activity_reporter.log").read_text()


def test_requeue_evicts_oldest_past_max_and_warns(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(activity_reporter, "MAX_BUFFER_SIZE", 3)
    buffer_file = _buffer(monkeypatch, tmp_path, [{"n": "new"}])

    activity_reporter._requeue_events([{"n": i} for i in range(10)])

    # Requeued events are older than ones buffered meanwhile; oldest go first.
    assert [json.loads(l)["n"] for l in buffer_file.read_text().splitlines()] == [8, 9, "new"]
    assert "evicted 8" in (tmp_path / "activity_reporter.log").read_text()


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


def test_forked_flush_does_not_hold_the_hook_output_pipe(tmp_path, _isolated_home):
    """The hook's caller waits for stdout EOF; a flush child that inherits
    stdout would keep the hook 'running' until the upload finishes."""
    script = tmp_path / "hook_like.py"
    script.write_text(
        "import time\n"
        "from veriswarm_mcp.hooks import activity_reporter as ar\n"
        "ar.flush_to_api = lambda: time.sleep(3)\n"
        "ar.maybe_flush(ar.FLUSH_THRESHOLD)\n"
        "print('done', flush=True)\n"
    )
    start = time.monotonic()
    result = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=20,
        env={**os.environ, "HOME": str(_isolated_home)},
    )
    elapsed = time.monotonic() - start

    assert result.stdout.strip() == "done"
    assert elapsed < 2.0


# ── Warnings from the detached flush child ───────────────────────────

import threading


def _warnings_log(home):
    return Path(home) / ".veriswarm" / "activity_reporter.log"


def test_drop_warning_reaches_the_log_when_stderr_is_gone(monkeypatch, tmp_path, _isolated_home, capfd):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    monkeypatch.setenv("GUARD_AGENT_ID", "agt_test")
    _buffer(monkeypatch, tmp_path, [{"event_id": "e1", "event_type": "x", "meta": {}}])
    monkeypatch.setattr(activity_reporter, "WARNINGS_LOG", _warnings_log(_isolated_home))
    _capture_posts(monkeypatch, 422)

    activity_reporter.flush_to_api()

    assert "dropped 1" in _warnings_log(_isolated_home).read_text()


def test_eviction_warning_reaches_the_log(monkeypatch, tmp_path, _isolated_home):
    monkeypatch.setattr(activity_reporter, "MAX_BUFFER_SIZE", 1)
    monkeypatch.setattr(activity_reporter, "WARNINGS_LOG", _warnings_log(_isolated_home))
    _buffer(monkeypatch, tmp_path, [{"n": 1}])

    activity_reporter._requeue_events([{"n": 0}])

    assert "evicted 1" in _warnings_log(_isolated_home).read_text()


def test_pending_warnings_are_surfaced_once_on_stderr_then_cleared(monkeypatch, _isolated_home, capsys):
    log = _warnings_log(_isolated_home)
    monkeypatch.setattr(activity_reporter, "WARNINGS_LOG", log)
    activity_reporter._warn("Activity upload: dropped 2 event(s) ...")
    activity_reporter._warn("Activity buffer full; evicted 5 oldest event(s).")

    activity_reporter.surface_pending_warnings()
    first = capsys.readouterr().err
    activity_reporter.surface_pending_warnings()
    second = capsys.readouterr().err

    assert first.count("\n") == 1
    assert "2 warning(s)" in first and "evicted 5" in first
    assert second == ""
    assert not log.exists() or log.read_text() == ""


def test_warnings_log_is_size_capped(monkeypatch, _isolated_home):
    log = _warnings_log(_isolated_home)
    monkeypatch.setattr(activity_reporter, "WARNINGS_LOG", log)
    monkeypatch.setattr(activity_reporter, "WARNINGS_LOG_MAX_BYTES", 2_000)

    for i in range(500):
        activity_reporter._warn(f"warning number {i}")

    assert log.stat().st_size <= 2_000
    assert "warning number 499" in log.read_text()


def test_no_fork_while_another_thread_is_alive(monkeypatch):
    stop = threading.Event()
    worker = threading.Thread(target=stop.wait, daemon=True)
    worker.start()

    def _no_fork():
        raise AssertionError("forked with a live thread")

    monkeypatch.setattr(activity_reporter.os, "fork", _no_fork)
    try:
        activity_reporter.maybe_flush(activity_reporter.FLUSH_THRESHOLD)
    finally:
        stop.set()
        worker.join()


# ── Buffer locking (shell logger + reporter share one flock) ─────────

import threading

LOGGER_SH = Path(activity_reporter.__file__).with_name("activity_logger.sh")


def _point_buffer_at_home(monkeypatch, home):
    buffer_file = home / ".veriswarm" / "activity.jsonl"
    buffer_file.parent.mkdir(parents=True)
    monkeypatch.setattr(activity_reporter, "BUFFER_FILE", buffer_file)
    return buffer_file


@pytest.mark.skipif(
    activity_reporter.fcntl is None
    or not (shutil.which("flock") or shutil.which("perl")),
    reason="needs flock(2) and a locking tool for the shell logger",
)
def test_shell_logger_waits_for_the_reporter_lock(monkeypatch, tmp_path):
    """Regression: the shell logger appended without a lock, so an event
    written while the reporter drained could land in a file that was then
    read and deleted."""
    buffer_file = _point_buffer_at_home(monkeypatch, tmp_path)
    env = {**os.environ, "HOME": str(tmp_path)}
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1"})

    with activity_reporter._buffer_lock():
        proc = subprocess.Popen(
            ["bash", str(LOGGER_SH)], stdin=subprocess.PIPE, env=env,
        )
        proc.stdin.write(payload.encode())
        proc.stdin.close()
        time.sleep(0.5)
        assert proc.poll() is None, "logger finished while the reporter held the lock"
        assert not buffer_file.exists() or buffer_file.read_text() == ""

    assert proc.wait(timeout=10) == 0
    lines = buffer_file.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["tool"] == "Bash"


@pytest.mark.skipif(activity_reporter.fcntl is None, reason="needs flock(2)")
def test_concurrent_appends_drains_and_requeues_lose_nothing(monkeypatch, tmp_path):
    _point_buffer_at_home(monkeypatch, tmp_path)
    monkeypatch.setattr(activity_reporter, "MAX_BUFFER_SIZE", 10_000)
    writers, per_writer = 4, 150
    drained: list[dict] = []
    done = threading.Event()

    def write(n):
        for i in range(per_writer):
            activity_reporter.buffer_event("tool.call", {"w": n, "i": i}, session_id="s")

    def drain():
        requeue_next = True
        while not done.is_set():
            batch = activity_reporter._read_and_clear_buffer()
            if batch and requeue_next:
                activity_reporter._requeue_events(batch)  # simulate a failed upload
            else:
                drained.extend(batch)
            requeue_next = not requeue_next

    drainer = threading.Thread(target=drain)
    threads = [threading.Thread(target=write, args=(n,)) for n in range(writers)]
    drainer.start()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    done.set()
    drainer.join()
    drained.extend(activity_reporter._read_and_clear_buffer())

    seen = sorted((e["meta"]["w"], e["meta"]["i"]) for e in drained)
    assert seen == sorted((n, i) for n in range(writers) for i in range(per_writer))
