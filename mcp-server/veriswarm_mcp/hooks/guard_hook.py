#!/usr/bin/env python3
"""VeriSwarm Guard Hook — PII scanning for MCP tool calls + session tracking.

Handles three hook events:
  - SessionStart:  Log session metadata, flush previous session's events
  - PreToolUse:    Tokenize PII in MCP tool arguments (matcher: ^mcp__)
  - PostToolUse:   Flag PII in MCP tool responses (matcher: ^mcp__)

Activity logging for ALL tools (including built-in Read/Grep/Edit/Bash)
is handled by the companion activity_logger.sh shell script, which runs
as a separate hook entry with sub-10ms overhead.

Configuration via environment variables:
  VERISWARM_API_URL   — API base URL (default: https://api.veriswarm.ai)
  VERISWARM_API_KEY   — Platform API key (required)
  GUARD_AGENT_ID      — Agent ID for audit trail (optional)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

# Import activity reporter (sibling module)
sys.path.insert(0, str(Path(__file__).parent))
from activity_reporter import (  # noqa: E402
    log_pii_detected,
    log_session_start,
)


def _load_env_file() -> None:
    """Load API key from ~/.veriswarm/env if env vars aren't set."""
    if os.environ.get("VERISWARM_API_KEY"):
        return
    env_file = Path.home() / ".veriswarm" / "env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


_load_env_file()

API_URL = os.environ.get("VERISWARM_API_URL", "https://api.veriswarm.ai").rstrip("/")
API_KEY = os.environ.get("VERISWARM_API_KEY", "")
AGENT_ID = os.environ.get("GUARD_AGENT_ID", "")

# MCP tool prefix
MCP_PREFIX = "mcp__"

# Short timeout: fail open fast so the hook never blocks the agent
API_TIMEOUT = 3.0


def _api_headers() -> dict:
    return {"Content-Type": "application/json", "x-api-key": API_KEY}


def _tokenize(text: str) -> dict | None:
    """Call VeriSwarm Guard PII tokenize API. Returns None on failure (fail-open)."""
    if not API_KEY or not text or len(text) < 4:
        return None
    try:
        r = httpx.post(
            API_URL + "/v1/suite/guard/pii/tokenize",
            json={"text": text, "agent_id": AGENT_ID or None},
            headers=_api_headers(),
            timeout=API_TIMEOUT,
        )
        r.raise_for_status()
        result = r.json()
        if result.get("tokens_created", 0) > 0:
            return result
    except Exception:
        pass
    return None


# -- Event Handlers -------------------------------------------------------


def handle_session_start(event: dict) -> None:
    """Log session start and flush any events from previous sessions."""
    cwd = event.get("cwd", "")
    log_session_start(
        cwd=cwd,
        permission_mode=event.get("permission_mode", ""),
    )
    output = (
        "[VeriSwarm Guard] Active. "
        "PII scanning on MCP tool calls. "
        "Activity logging on all tools."
    )
    print(output)
    sys.exit(0)


def handle_pre_tool_use(event: dict) -> None:
    """Tokenize PII in MCP tool arguments before the tool executes.

    Only fires for MCP tools (matcher: ^mcp__). Built-in tools are handled
    by activity_logger.sh for logging only — no PII scanning needed.
    """
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})

    if not tool_input or not isinstance(tool_input, dict):
        sys.exit(0)

    if not tool_name.startswith(MCP_PREFIX):
        sys.exit(0)

    # Scan all string fields in MCP tool args
    fields_to_scan = {
        k: v for k, v in tool_input.items()
        if isinstance(v, str) and len(v) > 3
    }
    if not fields_to_scan:
        sys.exit(0)

    updated = dict(tool_input)
    changed = False

    for key, value in fields_to_scan.items():
        result = _tokenize(value)
        if result and result.get("tokens_created", 0) > 0:
            updated[key] = result["tokenized_text"]
            changed = True
            types_found = sorted({t["type"] for t in result.get("token_manifest", [])})
            log_pii_detected(types_found, result["tokens_created"], context="pre:" + tool_name)

    if changed:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": updated,
            }
        }
        json.dump(output, sys.stdout)

    sys.exit(0)


def handle_post_tool_use(event: dict) -> None:
    """Flag MCP tool responses containing PII.

    Only fires for MCP tools (matcher: ^mcp__). Cannot rewrite tool output
    (tool already executed). Injects context warning instead.
    """
    tool_name = event.get("tool_name", "")
    tool_result = event.get("tool_result", "")

    if not tool_name.startswith(MCP_PREFIX):
        sys.exit(0)

    if isinstance(tool_result, dict):
        text = json.dumps(tool_result)
    elif isinstance(tool_result, str):
        text = tool_result
    else:
        sys.exit(0)

    if not text or len(text) < 4:
        sys.exit(0)

    scan_text = text[:4000]
    result = _tokenize(scan_text)
    if result and result.get("tokens_created", 0) > 0:
        types_found = sorted({t["type"] for t in result.get("token_manifest", [])})
        count = result["tokens_created"]
        type_list = ", ".join(types_found)

        log_pii_detected(types_found, count, context="post:" + tool_name)

        output = {
            "additionalContext": (
                "[VeriSwarm Guard] Warning: " + str(count) + " PII item(s) detected in "
                "tool response (" + type_list + "). Use the tokenize_pii tool before "
                "storing or forwarding this data."
            )
        }
        json.dump(output, sys.stdout)

    sys.exit(0)


# -- Main Dispatcher -------------------------------------------------------


def main() -> None:
    if not API_KEY:
        sys.exit(0)

    try:
        raw = sys.stdin.read()
        if not raw:
            sys.exit(0)
        event = json.loads(raw)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    hook_event = event.get("hook_event_name", "")

    if hook_event == "SessionStart":
        handle_session_start(event)
    elif hook_event == "PreToolUse":
        handle_pre_tool_use(event)
    elif hook_event == "PostToolUse":
        handle_post_tool_use(event)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
