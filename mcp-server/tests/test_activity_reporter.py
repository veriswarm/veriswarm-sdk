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


def test_flush_preserves_buffer_when_api_url_is_unsafe(monkeypatch, tmp_path):
    buffer_file = tmp_path / "activity.jsonl"
    monkeypatch.setattr(activity_reporter, "BUFFER_FILE", buffer_file)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VERISWARM_API_KEY", "test-key")
    monkeypatch.delenv("VERISWARM_AGENT_KEY", raising=False)
    monkeypatch.setenv("VERISWARM_API_URL", "http://api.veriswarm.ai")

    event = {
        "event_id": "evt1",
        "event_type": "agent.session.started",
        "session_id": "session-1",
        "ts": "2026-08-17T07:00:00Z",
        "meta": {"cwd": "/workspace"},
    }
    original_buffer = json.dumps(event) + "\n"
    buffer_file.write_text(original_buffer)

    def fail_if_posted(*args, **kwargs):
        raise AssertionError("unsafe API URL must not receive audit credentials")

    monkeypatch.setattr(activity_reporter.httpx, "post", fail_if_posted)

    activity_reporter.flush_to_api()

    assert buffer_file.read_text() == original_buffer


def test_flush_requeues_only_events_that_fail_upload(monkeypatch, tmp_path):
    buffer_file = tmp_path / "activity.jsonl"
    monkeypatch.setattr(activity_reporter, "BUFFER_FILE", buffer_file)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VERISWARM_API_KEY", "test-key")
    monkeypatch.delenv("VERISWARM_AGENT_KEY", raising=False)
    monkeypatch.setenv("VERISWARM_API_URL", "https://api.veriswarm.ai")

    sent_event = {
        "event_id": "sent",
        "event_type": "agent.session.started",
        "session_id": "session-1",
        "ts": "2026-08-17T07:00:00Z",
        "meta": {"cwd": "/workspace"},
    }
    failed_event = {
        "event_id": "failed",
        "event_type": "guard.pii.detected",
        "session_id": "session-1",
        "ts": "2026-08-17T07:00:01Z",
        "meta": {"pii_types": ["email"], "pii_count": 1},
    }
    buffer_file.write_text(
        json.dumps(sent_event) + "\n" + json.dumps(failed_event) + "\n"
    )
    posted_event_ids = []

    def post_first_then_fail(url, json=None, headers=None, timeout=None):
        posted_event_ids.append(json["event_id"])
        if json["event_id"] == "failed":
            raise RuntimeError("network down")
        return _OkResponse()

    monkeypatch.setattr(activity_reporter.httpx, "post", post_first_then_fail)

    activity_reporter.flush_to_api()

    assert posted_event_ids == ["sent", "failed"]
    assert buffer_file.exists()
    assert [json.loads(line) for line in buffer_file.read_text().splitlines()] == [
        failed_event
    ]
