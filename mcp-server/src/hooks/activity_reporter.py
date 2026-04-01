"""VeriSwarm Activity Reporter — buffer + fork-and-flush to API.

Provides session-start logging, PII detection logging, and the flush
mechanism that sends buffered events to VeriSwarm's event ingestion API.

Per-tool activity logging is handled by the companion activity_logger.sh
shell script (sub-10ms per event). This module is called from guard_hook.py
for session start and PII detection events only.

The buffer file (~/.veriswarm/activity.jsonl) is shared between the bash
logger and this module. The flush mechanism reads and clears the buffer,
sending events to the API in a forked child process.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

BUFFER_FILE = Path.home() / ".veriswarm" / "activity.jsonl"
FLUSH_THRESHOLD = 50
MAX_BUFFER_SIZE = 500


def _load_config() -> tuple[str, str, str, str]:
    """Load API URL, API key, agent ID, and agent key from env or ~/.veriswarm/env."""
    api_url = os.environ.get("VERISWARM_API_URL", "")
    api_key = os.environ.get("VERISWARM_API_KEY", "")
    agent_id = os.environ.get("GUARD_AGENT_ID", "")
    agent_key = os.environ.get("VERISWARM_AGENT_KEY", "")

    if not api_key or not agent_key:
        env_file = Path.home() / ".veriswarm" / "env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    k, v = key.strip(), value.strip()
                    if k == "VERISWARM_API_KEY" and not api_key:
                        api_key = v
                    elif k == "VERISWARM_API_URL":
                        api_url = v
                    elif k == "GUARD_AGENT_ID":
                        agent_id = v
                    elif k == "VERISWARM_AGENT_KEY":
                        agent_key = v

    api_url = (api_url or "https://api.veriswarm.ai").rstrip("/")
    return api_url, api_key, agent_id, agent_key


def _session_id() -> str:
    """Stable session ID from Claude Code or fallback to parent PID."""
    return os.environ.get("CLAUDE_SESSION_ID", "local-" + str(os.getppid()))


def buffer_event(event_type: str, metadata: dict | None = None) -> int:
    """Append an activity event to the local buffer. Returns buffer line count."""
    BUFFER_FILE.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "event_id": uuid.uuid4().hex[:16],
        "event_type": event_type,
        "session_id": _session_id(),
        "ts": datetime.now(timezone.utc).isoformat(),
        "meta": metadata or {},
    }

    with open(BUFFER_FILE, "a") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    try:
        with open(BUFFER_FILE) as f:
            count = sum(1 for _ in f)
    except OSError:
        count = 0

    return count


def _read_and_clear_buffer() -> list[dict]:
    """Atomically read all buffered events and truncate the file."""
    if not BUFFER_FILE.exists():
        return []

    events = []
    try:
        with open(BUFFER_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        BUFFER_FILE.write_text("")
    except (OSError, json.JSONDecodeError):
        pass

    return events


def flush_to_api() -> None:
    """Send all buffered events to VeriSwarm. Called in a forked child process."""
    api_url, api_key, agent_id, agent_key = _load_config()
    if not api_key and not agent_key:
        return

    events = _read_and_clear_buffer()
    if not events:
        return

    # Use agent key if available (agent may be in a different tenant than the API key)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if agent_key:
        headers["x-agent-api-key"] = agent_key
    else:
        headers["x-api-key"] = api_key

    for event in events:
        try:
            payload = {
                "event_id": event["event_id"],
                "agent_id": agent_id or "claude-code-session",
                "source_type": "guard_hook",
                "event_type": event["event_type"],
                "occurred_at": event["ts"],
                "payload": {
                    "session_id": event.get("session_id", ""),
                    **event.get("meta", {}),
                },
            }
            httpx.post(
                api_url + "/v1/events",
                json=payload,
                headers=headers,
                timeout=5.0,
            )
        except Exception:
            pass


def maybe_flush(buffer_count: int) -> None:
    """If the buffer has enough events, fork a child to flush them."""
    if buffer_count < FLUSH_THRESHOLD:
        return

    try:
        pid = os.fork()
        if pid == 0:
            try:
                flush_to_api()
            except Exception:
                pass
            os._exit(0)
    except OSError:
        pass


def log_session_start(cwd: str = "", **kwargs) -> None:
    """Log a session start event."""
    meta = {"cwd": cwd}
    meta.update(kwargs)
    count = buffer_event("agent.session.started", meta)
    maybe_flush(count)


def log_pii_detected(pii_types: list[str], count: int, context: str = "") -> None:
    """Log a PII detection event (types only, never values)."""
    meta = {"pii_types": pii_types, "pii_count": count, "context": context}
    c = buffer_event("guard.pii.detected", meta)
    maybe_flush(c)


