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
  VERISWARM_API_URL          — API base URL (default: https://api.veriswarm.ai)
  VERISWARM_API_KEY          — Platform API key (required for PII scanning)
  GUARD_AGENT_ID             — Agent ID for audit trail (optional)
  GUARD_SECRETS_DETECTION    — "1" enables the fail-closed secret tripwire
  GUARD_PII_EXEMPT_PREFIXES  — comma-separated tool-name prefixes that skip
                               PII tokenization (default: none). The secret
                               tripwire still runs on exempt tools.

Exit codes: 0 = proceed (stdout may carry a hookSpecificOutput JSON),
2 = block the tool call (PreToolUse only; reason on stderr).
"""

from __future__ import annotations

import json
import os
import sys
import time
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

# Per-request ceiling for a single tokenize call.
API_TIMEOUT = 3.0

# Total time the hook may spend on API calls. Hook entries are installed with
# `timeout: 10`; stay under it with headroom for process start-up.
HOOK_BUDGET_SECONDS = 7.0

# Set by main(); None means "no overall deadline" (direct handler calls).
_deadline: float | None = None

# Claude Code session id from the current hook payload (for audit events).
_session_id = ""

# Opt-in fail-closed secret tripwire. When enabled, obvious provider-prefix
# secrets (ghp_, sk-, AKIA, …) that survive tokenization are locally redacted
# rather than passed through. Default OFF — ships dormant.
SECRETS_DETECTION = os.environ.get("GUARD_SECRETS_DETECTION", "").lower() in (
    "1",
    "true",
    "yes",
)

# Opt-in PII exemption: tools whose names start with one of these prefixes
# skip PII tokenization and the PostToolUse PII warning. Empty by default —
# no tool is exempt unless the operator lists it. The secret tripwire still
# runs on exempt tools.
PII_EXEMPT_PREFIXES = tuple(
    p.strip()
    for p in os.environ.get("GUARD_PII_EXEMPT_PREFIXES", "").split(",")
    if p.strip()
)

PRE_TOOL_ASK_REASON = (
    "VeriSwarm Guard replaced sensitive values in this tool call's arguments. "
    "Review the modified input before it runs."
)


class SecretBlocked(Exception):
    """A secret was detected that could not be safely redacted."""


def _is_pii_exempt(tool_name: str) -> bool:
    return any(tool_name.startswith(p) for p in PII_EXEMPT_PREFIXES)


def _api_headers() -> dict:
    return {"Content-Type": "application/json", "x-api-key": API_KEY}


def _remaining_budget() -> float:
    if _deadline is None:
        return API_TIMEOUT
    return min(API_TIMEOUT, _deadline - time.monotonic())


def _tokenize(text: str) -> dict | None:
    """Call VeriSwarm Guard PII tokenize API.

    Returns the result only when it is well-formed and created tokens;
    None on any failure, malformed response, or exhausted time budget.
    """
    if not API_KEY or not text or len(text) < 4:
        return None
    timeout = _remaining_budget()
    if timeout <= 0.05:
        return None
    try:
        r = httpx.post(
            API_URL + "/v1/suite/guard/pii/tokenize",
            json={"text": text, "agent_id": AGENT_ID or None},
            headers=_api_headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        result = r.json()
    except Exception:
        return None
    if not isinstance(result, dict):
        return None
    created = result.get("tokens_created", 0)
    if not isinstance(created, int) or created <= 0:
        return None
    return result


def _manifest_types(result: dict) -> list[str]:
    """PII type names from a tokenize result, ignoring malformed entries."""
    manifest = result.get("token_manifest")
    if not isinstance(manifest, list):
        return []
    return sorted({
        str(entry["type"])
        for entry in manifest
        if isinstance(entry, dict) and entry.get("type")
    })


def _log_pii(result: dict, context: str) -> None:
    try:
        log_pii_detected(
            _manifest_types(result),
            result.get("tokens_created", 0),
            context=context,
            session_id=_session_id,
        )
    except Exception:
        pass  # audit logging must never break the hook


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


def _contains_secret(text: str) -> bool:
    """True when the tripwire is on and `text` carries a known secret.

    Fails closed: with detection enabled but the tripwire unavailable,
    any non-empty text counts as possibly carrying a secret.
    """
    if not SECRETS_DETECTION or not text:
        return False
    tw = _get_tripwire()
    if tw is None:
        return True
    return bool(tw.scan(text))


def apply_secret_tripwire(text: str) -> str:
    """Escalate obvious-secret strings to fail-closed redaction.

    No-op unless GUARD_SECRETS_DETECTION is enabled. On a known-prefix hit,
    try authoritative tokenization first; if it doesn't clear the secret,
    fall back to local non-recoverable redaction ([VS:<TYPE>:offline]).
    Raises SecretBlocked when detection is on but the tripwire is unavailable.
    """
    if not SECRETS_DETECTION or not isinstance(text, str) or not text:
        return text
    tw = _get_tripwire()
    if tw is None:
        raise SecretBlocked("secret tripwire unavailable")
    if not tw.scan(text):
        return text
    result = _tokenize(text)
    guarded = text
    if result:
        tokenized = result.get("tokenized_text")
        if isinstance(tokenized, str) and tokenized:
            guarded = tokenized
    if tw.scan(guarded):
        guarded = tw.redact_offline(guarded)
    return guarded


def _pii_tokenize_string(value: str, tool_name: str) -> str:
    """Replace PII in one string. Returns the input unchanged on any failure."""
    result = _tokenize(value)
    if not result:
        return value
    tokenized = result.get("tokenized_text")
    if not isinstance(tokenized, str):
        return value
    _log_pii(result, "pre:" + tool_name)
    return tokenized


def _guard_strings(value, transform):
    """Apply `transform` to every string in a JSON-like value — dict keys
    included — returning (new_value, changed)."""
    if isinstance(value, str):
        guarded = transform(value)
        return guarded, guarded != value

    if isinstance(value, dict):
        updated = {}
        changed = False
        for key, child in value.items():
            new_key, key_changed = _guard_strings(key, transform) if isinstance(key, str) else (key, False)
            new_child, child_changed = _guard_strings(child, transform)
            updated[new_key] = new_child
            changed = changed or key_changed or child_changed
        return (updated if changed else value), changed

    if isinstance(value, list):
        pairs = [_guard_strings(child, transform) for child in value]
        changed = any(c for _, c in pairs)
        return ([v for v, _ in pairs] if changed else value), changed

    return value, False


def _block(reason: str) -> None:
    print(f"[VeriSwarm Guard] Blocked: {reason}", file=sys.stderr)
    sys.exit(2)


# -- Event Handlers -------------------------------------------------------


def handle_session_start(event: dict) -> None:
    """Log session start and flush any events from previous sessions."""
    try:
        log_session_start(
            cwd=str(event.get("cwd") or ""),
            permission_mode=str(event.get("permission_mode") or ""),
            session_id=str(event.get("session_id") or ""),
        )
    except Exception:
        pass  # audit logging must never break the session
    print(
        "[VeriSwarm Guard] Active. "
        "PII scanning on MCP tool calls. "
        "Activity logging on all tools."
    )
    sys.exit(0)


def handle_pre_tool_use(event: dict) -> None:
    """Redact secrets and tokenize PII in MCP tool arguments before the tool runs.

    Secrets are handled first and fail closed: once the tripwire has
    redacted a value, the redacted input is emitted even if PII
    tokenization later fails. A secret that cannot be redacted blocks the
    call (exit 2). PII tokenization itself fails open.

    The modified input is returned with permissionDecision "ask": Claude
    Code applies `updatedInput` together with a decision, and "allow" would
    silently skip the user's permission prompt.
    """
    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input")

    if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        if _contains_secret(json.dumps(tool_input, default=str)):
            _block("tool input carries a secret but could not be parsed for redaction")
        sys.exit(0)

    if not tool_name.startswith(MCP_PREFIX):
        sys.exit(0)

    try:
        updated, changed = _guard_strings(tool_input, apply_secret_tripwire)
    except Exception:
        if _contains_secret(json.dumps(tool_input, default=str)):
            _block("secret detected in tool input and redaction failed")
        updated, changed = tool_input, False

    if not _is_pii_exempt(tool_name):
        try:
            updated, pii_changed = _guard_strings(
                updated, lambda v: _pii_tokenize_string(v, tool_name) if len(v) > 3 else v
            )
            changed = changed or pii_changed
        except Exception:
            pass  # PII tokenization fails open; secret redaction above stands

    if _contains_secret(json.dumps(updated)):
        _block("secret remained in tool input after redaction")

    if changed:
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": PRE_TOOL_ASK_REASON,
                    "updatedInput": updated,
                }
            },
            sys.stdout,
        )

    sys.exit(0)


def _response_text(event: dict) -> str:
    """Text of the tool's result. Claude Code sends `tool_response`;
    `tool_result` is accepted from older hosts."""
    response = event.get("tool_response")
    if response is None:
        response = event.get("tool_result")
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    return json.dumps(response, default=str)


def handle_post_tool_use(event: dict) -> None:
    """Flag MCP tool responses containing PII.

    The tool has already run, so this only adds a warning to Claude's
    context (hookSpecificOutput.additionalContext).
    """
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.startswith(MCP_PREFIX):
        sys.exit(0)
    if _is_pii_exempt(tool_name):
        sys.exit(0)

    text = _response_text(event)
    if len(text) < 4:
        sys.exit(0)

    result = _tokenize(text[:4000])
    if not result:
        sys.exit(0)

    types_found = _manifest_types(result)
    count = result.get("tokens_created", 0)
    _log_pii(result, "post:" + tool_name)

    type_list = ", ".join(types_found) or "unknown types"
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    f"[VeriSwarm Guard] Warning: {count} PII item(s) detected in "
                    f"tool response ({type_list}). Use the tokenize_pii tool before "
                    "storing or forwarding this data."
                ),
            }
        },
        sys.stdout,
    )
    sys.exit(0)


# -- Main Dispatcher -------------------------------------------------------


def _read_stdin() -> tuple[str, bool]:
    """Return (text, decoded_cleanly). Invalid UTF-8 is replaced, not raised."""
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        data = buffer.read()
        try:
            return data.decode("utf-8"), True
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace"), False
    try:
        return sys.stdin.read(), True
    except UnicodeDecodeError:
        return "", False


def _dispatch(raw: str, clean: bool) -> None:
    global _session_id
    if not raw:
        sys.exit(0)
    event = None
    if clean:
        try:
            event = json.loads(raw)
        except ValueError:
            event = None
    if not isinstance(event, dict):
        if _contains_secret(raw):
            _block("unparseable hook input carries a secret")
        sys.exit(0)

    hook_event = event.get("hook_event_name")
    _session_id = str(event.get("session_id") or "")

    if not API_KEY and hook_event != "PreToolUse":
        sys.exit(0)

    if hook_event == "SessionStart":
        handle_session_start(event)
    elif hook_event == "PreToolUse":
        handle_pre_tool_use(event)
    elif hook_event == "PostToolUse":
        handle_post_tool_use(event)
    sys.exit(0)


def main() -> None:
    global _deadline
    if not API_KEY and not SECRETS_DETECTION:
        sys.exit(0)

    _deadline = time.monotonic() + HOOK_BUDGET_SECONDS
    raw = ""
    try:
        raw, clean = _read_stdin()
        _dispatch(raw, clean)
    except SystemExit:
        raise
    except Exception:
        # Never exit 1 (a non-blocking error that lets the call proceed
        # unmodified). Block if the input carries a secret; otherwise proceed.
        try:
            secret = _contains_secret(raw)
        except Exception:
            secret = SECRETS_DETECTION
        if secret:
            _block("internal error while redacting a secret")
        sys.exit(0)


if __name__ == "__main__":
    main()
