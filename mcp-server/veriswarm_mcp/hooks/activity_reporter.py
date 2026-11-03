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
import signal
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from veriswarm_mcp.url_security import validate_api_url


# Reap fork()-ed children automatically rather than letting them
# accumulate as zombies between flushes. Set once at module load —
# safe because this hook runs in the MCP server's main process.
# (Audit 2026-05-08 MED-SDK-10.)
try:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
except (AttributeError, ValueError):
    # SIGCHLD doesn't exist on Windows (AttributeError) and signal
    # handlers can only be set in the main thread (ValueError when
    # imported from a thread). Silently fall through; the fork path
    # below stays available either way.
    pass

BUFFER_FILE = Path.home() / ".veriswarm" / "activity.jsonl"
FLUSH_THRESHOLD = 50
MAX_BUFFER_SIZE = 500


_CONFIG_KEYS = ("VERISWARM_API_URL", "VERISWARM_API_KEY", "GUARD_AGENT_ID", "VERISWARM_AGENT_KEY")

# Created after the first "no agent id" warning so later flushes (each in a
# fresh hook process) stay quiet.
NO_AGENT_ID_MARKER = ".no-agent-id-warned"


def _read_env_file() -> dict[str, str]:
    env_file = Path.home() / ".veriswarm" / "env"
    values: dict[str, str] = {}
    try:
        text = env_file.read_text()
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def _load_config() -> tuple[str, str, str, str]:
    """Load API URL, API key, agent ID, and agent key.

    Each setting comes from its environment variable when set, otherwise
    from ~/.veriswarm/env.
    """
    file_values = _read_env_file()
    cfg = {k: os.environ.get(k) or file_values.get(k, "") for k in _CONFIG_KEYS}
    api_url, api_key = cfg["VERISWARM_API_URL"], cfg["VERISWARM_API_KEY"]
    agent_id, agent_key = cfg["GUARD_AGENT_ID"], cfg["VERISWARM_AGENT_KEY"]

    try:
        api_url = validate_api_url(
            api_url or "https://api.veriswarm.ai",
            field_name="VERISWARM_API_URL",
        )
    except ValueError:
        # Do not risk sending auth headers to a non-HTTPS external endpoint.
        return "", "", agent_id, ""
    return api_url, api_key, agent_id, agent_key


def _fallback_session_id() -> str:
    """Used only when the hook payload carried no session_id."""
    return "local-" + str(os.getppid())


def _line_count(path: Path) -> int:
    try:
        with open(path) as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def buffer_event(event_type: str, metadata: dict | None = None, session_id: str = "") -> int:
    """Append an activity event to the local buffer. Returns buffer line count.

    The buffer holds at most MAX_BUFFER_SIZE events; once full, new events
    are dropped until a flush drains it.
    """
    BUFFER_FILE.parent.mkdir(parents=True, exist_ok=True)

    count = _line_count(BUFFER_FILE)
    if count >= MAX_BUFFER_SIZE:
        return count

    entry = {
        "event_id": uuid.uuid4().hex[:16],
        "event_type": event_type,
        "session_id": session_id or _fallback_session_id(),
        "ts": datetime.now(timezone.utc).isoformat(),
        "meta": metadata or {},
    }

    with open(BUFFER_FILE, "a") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    return count + 1


def _read_and_clear_buffer() -> list[dict]:
    """Atomically drain buffered events without deleting concurrent writes."""
    if not BUFFER_FILE.exists():
        return []

    drained_file = BUFFER_FILE.with_name(
        f"{BUFFER_FILE.name}.{os.getpid()}.{uuid.uuid4().hex}.flush"
    )
    events = []
    try:
        BUFFER_FILE.replace(drained_file)
    except FileNotFoundError:
        return []
    except OSError:
        return []

    try:
        with open(drained_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    finally:
        try:
            drained_file.unlink()
        except OSError:
            pass

    return events


def _event_payload(event: dict, agent_id: str) -> dict:
    """Convert both Python reporter and shell hook entries to /v1/events."""
    metadata = event.get("meta")
    payload_meta = dict(metadata) if isinstance(metadata, dict) else {}

    # activity_logger.sh writes a compact legacy shape. Preserve its audit
    # fields instead of dropping the line when the Python schema keys are absent.
    for key in ("tool", "input_bytes", "output_bytes"):
        if key in event and key not in payload_meta:
            payload_meta[key] = event[key]

    session_id = event.get("session_id") or event.get("sid") or ""
    event_type = event.get("event_type") or event.get("event") or "guard.activity"

    return {
        "event_id": str(event.get("event_id") or uuid.uuid4().hex[:16]),
        "agent_id": agent_id,
        "source_type": "guard_hook",
        "event_type": str(event_type),
        "occurred_at": str(event.get("ts") or datetime.now(timezone.utc).isoformat()),
        "payload": {
            "session_id": session_id,
            **payload_meta,
        },
    }


def _requeue_events(events: list[dict]) -> None:
    """Append unsent events back to the shared buffer, keeping the newest
    events when the total would exceed MAX_BUFFER_SIZE."""
    if not events:
        return
    room = MAX_BUFFER_SIZE - _line_count(BUFFER_FILE)
    if room <= 0:
        return
    events = events[-room:]
    try:
        BUFFER_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BUFFER_FILE, "a") as f:
            for event in events:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError:
        pass


def _is_permanent_rejection(exc: Exception) -> bool:
    """4xx responses other than 408/429 will fail the same way on retry."""
    if not isinstance(exc, httpx.HTTPStatusError):
        return False
    status = exc.response.status_code
    return 400 <= status < 500 and status not in (408, 429)


def _warn_missing_agent_id() -> None:
    marker = BUFFER_FILE.parent / NO_AGENT_ID_MARKER
    if marker.exists():
        return
    print(
        "[VeriSwarm Guard] Activity upload skipped: no GUARD_AGENT_ID configured. "
        "Set it in the environment or ~/.veriswarm/env (veriswarm-setup --agent-id).",
        file=sys.stderr,
    )
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except OSError:
        pass


def flush_to_api() -> None:
    """Send all buffered events to VeriSwarm. Called in a forked child process."""
    api_url, api_key, agent_id, agent_key = _load_config()
    if not api_key and not agent_key:
        return
    if not agent_id:
        # Events must be attributed to a real agent; keep them buffered
        # (bounded by MAX_BUFFER_SIZE) until one is configured.
        _warn_missing_agent_id()
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

    unsent: list[dict] = []
    for event in events:
        try:
            response = httpx.post(
                api_url + "/v1/events",
                json=_event_payload(event, agent_id),
                headers=headers,
                timeout=5.0,
            )
            response.raise_for_status()
        except Exception as exc:
            if not _is_permanent_rejection(exc):
                unsent.append(event)

    _requeue_events(unsent)


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


def log_session_start(cwd: str = "", session_id: str = "", **kwargs) -> None:
    """Log a session start event."""
    meta = {"cwd": cwd}
    meta.update(kwargs)
    count = buffer_event("agent.session.started", meta, session_id=session_id)
    maybe_flush(count)


def log_pii_detected(
    pii_types: list[str], count: int, context: str = "", session_id: str = ""
) -> None:
    """Log a PII detection event (types only, never values)."""
    meta = {"pii_types": pii_types, "pii_count": count, "context": context}
    c = buffer_event("guard.pii.detected", meta, session_id=session_id)
    maybe_flush(c)


