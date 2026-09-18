import json
import threading
import time
from contextlib import contextmanager

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


def test_drain_does_not_lose_concurrent_append(monkeypatch, tmp_path):
    buffer_file = tmp_path / "activity.jsonl"
    monkeypatch.setattr(activity_reporter, "BUFFER_FILE", buffer_file)

    existing = {
        "event_id": "old",
        "event_type": "tool.call.success",
        "session_id": "session-1",
        "ts": "2026-08-17T07:00:00Z",
        "meta": {"tool": "first"},
    }
    buffer_file.write_text(json.dumps(existing) + "\n")

    original_lock = activity_reporter._activity_lock
    writer_started = threading.Event()
    writer_done = threading.Event()

    def concurrent_writer():
        writer_started.set()
        activity_reporter.buffer_event("tool.call.success", {"tool": "second"})
        writer_done.set()

    writer_thread = threading.Thread(target=concurrent_writer)

    @contextmanager
    def instrumented_lock():
        with original_lock():
            if (
                threading.current_thread() is threading.main_thread()
                and not writer_started.is_set()
            ):
                writer_thread.start()
                assert writer_started.wait(timeout=1)
                # Give the writer a chance to try to take the same lock.
                time.sleep(0.05)
            yield

    monkeypatch.setattr(activity_reporter, "_activity_lock", instrumented_lock)

    drained = activity_reporter._read_and_clear_buffer()
    writer_thread.join(timeout=1)

    assert writer_done.is_set()
    assert drained == [existing]
    remaining = [json.loads(line) for line in buffer_file.read_text().splitlines()]
    assert len(remaining) == 1
    assert remaining[0]["event_type"] == "tool.call.success"
    assert remaining[0]["meta"] == {"tool": "second"}
