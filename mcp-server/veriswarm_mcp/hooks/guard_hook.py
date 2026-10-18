#!/usr/bin/env python3
"""VeriSwarm Guard Hook — PII scanning for MCP tool calls + session tracking.

Handles three hook events:
  - SessionStart:  Log session metadata, flush previous session's events
  - PreToolUse:    Tokenize PII in MCP tool arguments (matcher: ^mcp__)
  - PostToolUse:   Tokenize/redact MCP tool responses (matcher: ^mcp__)

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
from veriswarm_mcp.url_security import validate_api_url  # noqa: E402


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

try:
    API_URL = validate_api_url(
        os.environ.get("VERISWARM_API_URL", "https://api.veriswarm.ai"),
        field_name="VERISWARM_API_URL",
    )
except ValueError as exc:
    print(f"[VeriSwarm Guard] {exc}; API calls disabled", file=sys.stderr)
    API_URL = ""

API_KEY = os.environ.get("VERISWARM_API_KEY", "") if API_URL else ""
AGENT_ID = os.environ.get("GUARD_AGENT_ID", "")

# MCP tool prefix
MCP_PREFIX = "mcp__"

# Short timeout: fail open fast so the hook never blocks the agent
API_TIMEOUT = 3.0

# Opt-in fail-closed secret tripwire. When enabled, obvious provider-prefix
# secrets (ghp_, sk-, AKIA, …) that survive tokenization are locally redacted
# rather than passed through. Default OFF — ships dormant.
SECRETS_DETECTION = os.environ.get("GUARD_SECRETS_DETECTION", "").lower() in (
    "1",
    "true",
    "yes",
)


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


# -- Fail-closed secret tripwire (opt-in) ---------------------------------

_TRIPWIRE = None


def _get_tripwire():
    """Lazily build the vendored-manifest tripwire. None if unavailable."""
    global _TRIPWIRE
    if _TRIPWIRE is None:
        try:
            from veriswarm_mcp.secret_tripwire import (
                SecretTripwire,
                load_vendored_manifest,
            )

            _TRIPWIRE = SecretTripwire(load_vendored_manifest())
        except Exception:
            _TRIPWIRE = False  # sentinel: tried and failed, don't retry
    return _TRIPWIRE or None


def apply_secret_tripwire(text: str) -> str:
    """Escalate obvious-secret strings to fail-closed redaction.

    No-op unless GUARD_SECRETS_DETECTION is enabled. On a known-prefix hit,
    try authoritative tokenization first; if it doesn't clear the secret,
    fall back to local non-recoverable redaction ([VS:<TYPE>:offline]).
    """
    if not SECRETS_DETECTION or not isinstance(text, str) or not text:
        return text
    tw = _get_tripwire()
    if tw is None or not tw.scan(text):
        return text
    result = _tokenize(text)
    guarded = text
    if result and result.get("tokens_created", 0) > 0:
        guarded = result.get("tokenized_text") or text
    if tw.scan(guarded):
        guarded = tw.redact_offline(guarded)
    return guarded


def _guard_value(value):
    """Apply Guard redaction recursively to JSON-like tool payloads."""
    if isinstance(value, str):
        if len(value) <= 3:
            return value, False, set(), 0

        guarded = apply_secret_tripwire(value)
        changed = guarded != value
        pii_types: set[str] = set()
        pii_count = 0

        result = _tokenize(guarded)
        if result and result.get("tokens_created", 0) > 0:
            tokenized_text = result.get("tokenized_text")
            if isinstance(tokenized_text, str):
                guarded = tokenized_text
                changed = True
                pii_types = {t["type"] for t in result.get("token_manifest", [])}
                pii_count = int(result["tokens_created"])

        return guarded, changed, pii_types, pii_count

    if isinstance(value, dict):
        updated = {}
        changed = False
        pii_types: set[str] = set()
        pii_count = 0
        for key, child in value.items():
            guarded_child, child_changed, child_types, child_count = _guard_value(child)
            updated[key] = guarded_child
            changed = changed or child_changed
            pii_types.update(child_types)
            pii_count += child_count
        return (updated if changed else value), changed, pii_types, pii_count

    if isinstance(value, list):
        updated = []
        changed = False
        pii_types: set[str] = set()
        pii_count = 0
        for child in value:
            guarded_child, child_changed, child_types, child_count = _guard_value(child)
            updated.append(guarded_child)
            changed = changed or child_changed
            pii_types.update(child_types)
            pii_count += child_count
        return (updated if changed else value), changed, pii_types, pii_count

    return value, False, set(), 0


def _guard_pre_tool_value(value, tool_name: str):
    """Apply PreToolUse redaction recursively to JSON-like tool arguments."""
    updated, changed, pii_types, pii_count = _guard_value(value)
    if pii_count:
        log_pii_detected(sorted(pii_types), pii_count, context="pre:" + tool_name)
    return updated, changed


def _guard_post_tool_value(value, tool_name: str):
    """Apply PostToolUse redaction recursively to JSON-like tool results."""
    updated, changed, pii_types, pii_count = _guard_value(value)
    if pii_count:
        log_pii_detected(sorted(pii_types), pii_count, context="post:" + tool_name)
    return updated, changed, sorted(pii_types), pii_count


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

    updated, changed = _guard_pre_tool_value(tool_input, tool_name)

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
    """Tokenize/redact MCP tool responses containing PII or obvious secrets.

    Only fires for MCP tools (matcher: ^mcp__). The tool has already executed,
    but updatedToolOutput replaces the result before Claude sees it.
    """
    tool_name = event.get("tool_name", "")
    tool_result = event.get("tool_result", "")

    if not tool_name.startswith(MCP_PREFIX):
        sys.exit(0)

    if not isinstance(tool_result, (dict, list, str)):
        sys.exit(0)

    if not tool_result:
        sys.exit(0)

    updated, changed, types_found, count = _guard_post_tool_value(tool_result, tool_name)

    if changed:
        hook_output = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": updated,
            }
        }
        if count > 0:
            type_list = ", ".join(types_found)
            hook_output["hookSpecificOutput"]["additionalContext"] = (
                "[VeriSwarm Guard] Redacted "
                + str(count)
                + " PII item(s) in tool response ("
                + type_list
                + ")."
            )
        json.dump(hook_output, sys.stdout)

    sys.exit(0)


# -- Main Dispatcher -------------------------------------------------------


def main() -> None:
    if not API_KEY and not SECRETS_DETECTION:
        sys.exit(0)

    try:
        raw = sys.stdin.read()
        if not raw:
            sys.exit(0)
        event = json.loads(raw)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    hook_event = event.get("hook_event_name", "")

    if not API_KEY and hook_event not in ("PreToolUse", "PostToolUse"):
        sys.exit(0)

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
