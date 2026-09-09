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
