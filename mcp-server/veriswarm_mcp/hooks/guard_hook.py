#!/usr/bin/env python3
"""VeriSwarm Guard Hook — secret and PII protection for Claude Code.

Handles four hook events:
  - SessionStart:      Log session metadata, flush previous session's events
  - UserPromptSubmit:  Block prompts carrying secrets (always) or PII
                       (GUARD_BLOCK_PROMPT_PII, default on)
  - PreToolUse:        Redact secrets / tokenize PII in MCP tool arguments
                       (matcher: ^mcp__)
  - PostToolUse:       Redact secrets / tokenize PII in MCP tool responses
                       before Claude sees them (matcher: ^mcp__)

Activity logging for ALL tools (including built-in Read/Grep/Edit/Bash)
is handled by the companion activity_logger.sh shell script, which runs
as a separate hook entry with sub-10ms overhead.

Configuration via environment variables:
  VERISWARM_API_URL          — API base URL (default: https://api.veriswarm.ai)
  VERISWARM_API_KEY          — Platform API key (required for PII scanning)
  GUARD_AGENT_ID             — Agent ID for audit trail (optional)
  GUARD_SECRETS_DETECTION    — "1" also sends detected secrets in MCP tool
                               arguments to the Guard API for tokenization
                               (local secret redaction is always on)
  GUARD_BLOCK_PROMPT_PII     — "0" stops blocking prompts that contain PII
                               (default on). Secrets in prompts are always
                               blocked.
  GUARD_PII_EXEMPT_PREFIXES  — comma-separated tool-name prefixes that skip
                               PII tokenization (default: none). The secret
                               tripwire still runs on exempt tools.

Exit codes: 0 = proceed (stdout may carry decision JSON), 2 = block the
tool call (PreToolUse only; reason on stderr).

Secrets are always redacted locally (no network) in prompts, MCP tool
arguments and MCP tool responses.

Every API call shares one wall-clock budget (HOOK_BUDGET_SECONDS) that ends
well before the installed 10s hook timeout, because Claude Code discards
the output of a hook that times out.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import httpx

# Import activity reporter (sibling module)
sys.path.insert(0, str(Path(__file__).parent))
from activity_reporter import (  # noqa: E402
    log_pii_detected,
    log_session_start,
    surface_pending_warnings,
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


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


# MCP tool prefix
MCP_PREFIX = "mcp__"

# Per-request ceiling for a single tokenize call.
API_TIMEOUT = 3.0

# Total wall-clock time the hook may spend waiting on the API. Hook entries
# are installed with `timeout: 10`; stay well under it, leaving headroom for
# interpreter start-up and output on a loaded machine (a timed-out
# PostToolUse hook lets the original tool output through).
HOOK_BUDGET_SECONDS = 6.0

# Below this much remaining budget, API calls are skipped: secrets go
# straight to offline redaction, and scans that need the API fail closed.
MIN_API_BUDGET = 0.25

# Set by main(); None means "no overall deadline" (direct handler calls).
_deadline: float | None = None

# Claude Code session id from the current hook payload (for audit events).
_session_id = ""

# The parsed hook payload, for the crash handler in main().
_current_event: dict | None = None

# Opt-in: also send detected secrets in tool arguments to the Guard API for
# authoritative tokenization. Local redaction runs regardless.
SECRETS_DETECTION = _env_flag("GUARD_SECRETS_DETECTION", False)

# Prompts containing PII are blocked unless this is turned off.
BLOCK_PROMPT_PII = _env_flag("GUARD_BLOCK_PROMPT_PII", True)

# Opt-in PII exemption: tools whose names start with one of these prefixes
# skip PII tokenization and PostToolUse PII handling. Empty by default —
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


class ScanUnavailable(Exception):
    """The PII scan could not complete (API error, bad response, or no time left)."""


def _is_pii_exempt(tool_name: str) -> bool:
    return any(tool_name.startswith(p) for p in PII_EXEMPT_PREFIXES)


def _api_headers() -> dict:
    return {"Content-Type": "application/json", "x-api-key": API_KEY}


def _remaining_budget() -> float:
    if _deadline is None:
        return API_TIMEOUT
    return min(API_TIMEOUT, _deadline - time.monotonic())


def _post_within(url: str, payload: dict, seconds: float) -> httpx.Response:
    """POST with a hard wall-clock limit.

    httpx timeouts apply per phase (connect, each read, write), so a server
    that trickles bytes can hold a request far longer than `timeout`. The
    request runs in a daemon thread that is abandoned if it overruns.
    """
    box: dict = {}

    def run() -> None:
        try:
            box["response"] = httpx.post(url, json=payload, headers=_api_headers(), timeout=seconds)
        except BaseException as exc:  # noqa: BLE001 — re-raised in the caller
            box["error"] = exc

    worker = threading.Thread(target=run, name="veriswarm-guard-api", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise ScanUnavailable("API call exceeded the hook time budget")
    if "error" in box:
        raise box["error"]
    return box["response"]


def _tokenize_strict(text: str) -> dict | None:
    """Tokenize PII in `text` via the Guard API.

    Returns the result when PII was found, None when the text was scanned
    and is clean (or too short to scan). Raises ScanUnavailable when the
    scan could not be completed.
    """
    if not text or len(text) < 4:
        return None
    if not API_KEY:
        raise ScanUnavailable("no API key configured")
    seconds = _remaining_budget()
    if seconds < MIN_API_BUDGET:
        raise ScanUnavailable("hook time budget exhausted")
    try:
        response = _post_within(
            API_URL + "/v1/suite/guard/pii/tokenize",
            {"text": text, "agent_id": AGENT_ID or None},
            seconds,
        )
        response.raise_for_status()
        result = response.json()
    except ScanUnavailable:
        raise
    except Exception as exc:
        raise ScanUnavailable(type(exc).__name__) from exc
    if not isinstance(result, dict):
        raise ScanUnavailable("malformed response")
    created = result.get("tokens_created", 0)
    if not isinstance(created, int) or created < 0:
        raise ScanUnavailable("malformed response")
    if created == 0:
        return None
    if not isinstance(result.get("tokenized_text"), str):
        raise ScanUnavailable("malformed response")
    return result


def _tokenize(text: str) -> dict | None:
    """Best-effort tokenization: the result when PII was found, else None
    (including on any failure). Used where PII handling fails open."""
    if not API_KEY:
        return None
    try:
        return _tokenize_strict(text)
    except Exception:
        return None


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


# -- Secret tripwire ------------------------------------------------------

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


def _has_secret(text: str) -> bool:
    """Local tripwire scan. Fails closed: an unavailable tripwire counts
    every non-empty text as a hit."""
    if not text:
        return False
    tw = _get_tripwire()
    if tw is None:
        return True
    return bool(tw.scan(text))


_contains_secret = _has_secret


def apply_secret_tripwire(text: str) -> str:
    """Redact obvious-secret strings (always on).

    On a known-prefix hit, try authoritative tokenization first when
    GUARD_SECRETS_DETECTION is on and there is time; if that doesn't clear
    the secret, redact locally ([VS:<TYPE>:offline]). Raises SecretBlocked
    when the tripwire is unavailable.
    """
    if not isinstance(text, str) or not text:
        return text
    tw = _get_tripwire()
    if tw is None:
        raise SecretBlocked("secret tripwire unavailable")
    if not tw.scan(text):
        return text
    guarded = text
    if SECRETS_DETECTION and _remaining_budget() >= MIN_API_BUDGET:
        result = _tokenize(text)
        if result:
            tokenized = result.get("tokenized_text")
            if isinstance(tokenized, str) and tokenized:
                guarded = tokenized
    if tw.scan(guarded):
        guarded = tw.redact_offline(guarded)
    return guarded


def redact_secrets_offline(text: str) -> str:
    """Local-only secret redaction (no API call, always on)."""
    if not isinstance(text, str) or not text:
        return text
    tw = _get_tripwire()
    if tw is None:
        raise SecretBlocked("secret tripwire unavailable")
    return tw.redact_offline(text) if tw.scan(text) else text


def _pii_tokenize_string(value: str, tool_name: str) -> str:
    """Replace PII in one string. Returns the input unchanged on any failure."""
    result = _tokenize(value)
    if not result:
        return value
    _log_pii(result, "pre:" + tool_name)
    return result["tokenized_text"]


def _guard_strings(value, transform, *, keys: bool = True):
    """Apply `transform` to every string in a JSON-like value (dict keys
    too, unless keys=False), returning (new_value, changed)."""
    if isinstance(value, str):
        guarded = transform(value)
        return guarded, guarded != value

    if isinstance(value, dict):
        updated = {}
        changed = False
        for key, child in value.items():
            if keys and isinstance(key, str):
                new_key, key_changed = _guard_strings(key, transform, keys=keys)
            else:
                new_key, key_changed = key, False
            new_child, child_changed = _guard_strings(child, transform, keys=keys)
            updated[new_key] = new_child
            changed = changed or key_changed or child_changed
        return (updated if changed else value), changed

    if isinstance(value, list):
        pairs = [_guard_strings(child, transform, keys=keys) for child in value]
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
        "Secret and PII protection on prompts and MCP tool calls. "
        "Activity logging on all tools."
    )
    sys.exit(0)


def _block_prompt(reason: str) -> None:
    json.dump(
        {
            "decision": "block",
            "reason": f"[VeriSwarm Guard] {reason}",
            # Keep the blocked text out of the block message.
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "suppressOriginalPrompt": True,
            },
        },
        sys.stdout,
    )
    sys.exit(0)


PROMPT_CHECK_FAILED = "Prompt blocked: the secret check could not run. Try again, or reinstall veriswarm-mcp."


def handle_user_prompt_submit(event: dict) -> None:
    """Block prompts that carry secrets (always) or PII (GUARD_BLOCK_PROMPT_PII).

    Secrets are detected locally and fail closed: any error blocks the
    prompt without echoing it. The PII check needs the API; if it cannot
    complete, the prompt proceeds with a visible warning.
    """
    try:
        _check_prompt(event)
    except SystemExit:
        raise
    except Exception:
        _block_prompt(PROMPT_CHECK_FAILED)


def _check_prompt(event: dict) -> None:
    prompt = event.get("prompt")
    if not isinstance(prompt, str):
        if prompt is not None and _has_secret(json.dumps(prompt, default=str)):
            _block_prompt("Prompt blocked: it may contain a secret (API key, token, or credential).")
        sys.exit(0)

    if _has_secret(prompt):
        _block_prompt(
            "Prompt blocked: it contains what looks like a secret (API key, token, or "
            "credential). Remove it and send the prompt again."
        )

    if not BLOCK_PROMPT_PII or not API_KEY:
        sys.exit(0)

    try:
        result = _tokenize_strict(prompt)
    except ScanUnavailable:
        json.dump(
            {"systemMessage": "[VeriSwarm Guard] PII check on this prompt could not complete; it was sent unscanned."},
            sys.stdout,
        )
        sys.exit(0)

    if result:
        _log_pii(result, "prompt")
        types = ", ".join(_manifest_types(result)) or "personal data"
        _block_prompt(
            f"Prompt blocked: it contains personal data ({types}). Remove it, or use the "
            "tokenize_pii tool, and send the prompt again. "
            "Set GUARD_BLOCK_PROMPT_PII=0 to allow PII in prompts."
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


def _post_tool_output(output, context: str) -> None:
    hook_output = {"hookEventName": "PostToolUse", "updatedToolOutput": output}
    if context:
        hook_output["additionalContext"] = context
    json.dump({"hookSpecificOutput": hook_output}, sys.stdout)
    sys.exit(0)


def _withheld_output(response, why: str):
    message = f"[VeriSwarm Guard] Tool output withheld: {why}."
    if isinstance(response, str):
        return message
    return [{"type": "text", "text": message}]


def _withhold_post_tool_output(event: dict, why: str) -> None:
    response = event.get("tool_response")
    if response is None:
        response = event.get("tool_result")
    _post_tool_output(
        _withheld_output(response, why),
        f"VeriSwarm Guard withheld this tool output: {why}.",
    )


def handle_post_tool_use(event: dict) -> None:
    """Protect MCP tool output; any unexpected error withholds the output."""
    try:
        _protect_tool_output(event)
    except SystemExit:
        raise
    except Exception:
        _withhold_post_tool_output(event, "the Guard check failed")


def _protect_tool_output(event: dict) -> None:
    """Protect MCP tool output before Claude sees it.

    Secrets are redacted locally first (always). PII is
    then tokenized through the API (when an API key is configured and the
    tool is not exempt). If either step cannot complete, the output is
    replaced with a withheld notice instead of passing through unscanned.
    The result replaces the tool output via hookSpecificOutput.updatedToolOutput.
    """
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.startswith(MCP_PREFIX):
        sys.exit(0)

    response = event.get("tool_response")
    if response is None:
        response = event.get("tool_result")
    if response is None:
        sys.exit(0)

    scan_pii = bool(API_KEY) and not _is_pii_exempt(tool_name)

    try:
        updated, changed = _guard_strings(response, redact_secrets_offline)
    except Exception:
        _post_tool_output(
            _withheld_output(response, "secret redaction could not run"),
            "VeriSwarm Guard withheld this tool output because its secret scan failed.",
        )

    pii_total = 0
    pii_types: set[str] = set()
    if scan_pii:
        cache: dict[str, str] = {}

        def tokenize_value(text: str) -> str:
            nonlocal pii_total
            if len(text) < 4:
                return text
            if text not in cache:
                result = _tokenize_strict(text)
                if result:
                    pii_total += result.get("tokens_created", 0)
                    pii_types.update(_manifest_types(result))
                    _log_pii(result, "post:" + tool_name)
                    cache[text] = result["tokenized_text"]
                else:
                    cache[text] = text
            return cache[text]

        try:
            updated, pii_changed = _guard_strings(updated, tokenize_value, keys=False)
            changed = changed or pii_changed
        except Exception:
            _post_tool_output(
                _withheld_output(response, "the PII scan could not complete"),
                "VeriSwarm Guard withheld this tool output because its PII scan could "
                "not complete. Retry the tool call, or ask the user to check the "
                "VeriSwarm API connection.",
            )

    try:
        if _contains_secret(json.dumps(updated, default=str)):
            raise SecretBlocked("secret remained after redaction")
    except Exception:
        _post_tool_output(
            _withheld_output(response, "a secret could not be redacted"),
            "VeriSwarm Guard withheld this tool output because it contained a secret.",
        )

    if not changed:
        sys.exit(0)

    context = ""
    if pii_total:
        context = (
            f"[VeriSwarm Guard] {pii_total} PII item(s) in this tool response "
            f"({', '.join(sorted(pii_types)) or 'unknown types'}) were replaced with "
            "tokens. Use rehydrate_pii only where the real values are required."
        )
    _post_tool_output(updated, context)


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
        if _has_secret(raw):
            _block("unparseable hook input carries a secret")
        sys.exit(0)

    global _current_event
    _current_event = event
    hook_event = event.get("hook_event_name")
    _session_id = str(event.get("session_id") or "")

    if hook_event == "UserPromptSubmit":
        handle_user_prompt_submit(event)
    elif hook_event == "PreToolUse":
        handle_pre_tool_use(event)
    elif hook_event == "PostToolUse":
        handle_post_tool_use(event)
    elif hook_event == "SessionStart" and API_KEY:
        handle_session_start(event)
    sys.exit(0)


def _fail_closed(raw: str) -> None:
    """Crash path: never exit 1 (a non-blocking error that lets the action
    proceed unchanged). Block or withhold according to the event."""
    event = _current_event or {}
    hook_event = event.get("hook_event_name")
    if hook_event == "UserPromptSubmit":
        _block_prompt(PROMPT_CHECK_FAILED)
    if hook_event == "PostToolUse" and str(event.get("tool_name") or "").startswith(MCP_PREFIX):
        _withhold_post_tool_output(event, "the Guard check failed")
    try:
        secret = _has_secret(raw)
    except Exception:
        secret = True
    if secret:
        _block("internal error while checking for secrets")
    sys.exit(0)


def main() -> None:
    global _deadline
    _deadline = time.monotonic() + HOOK_BUDGET_SECONDS
    try:
        surface_pending_warnings()
    except Exception:
        pass
    raw = ""
    try:
        raw, clean = _read_stdin()
        _dispatch(raw, clean)
    except SystemExit:
        raise
    except Exception:
        _fail_closed(raw)


if __name__ == "__main__":
    main()
