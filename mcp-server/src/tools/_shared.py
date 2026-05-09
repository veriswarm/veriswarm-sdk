"""Shared validation + error-handling helpers for MCP tools.

Centralises three patterns that previously lived inline (and inconsistently)
in every tool module:

1. ID validation — every tool that takes an `agent_id` / `framework_id` /
   etc. used to interpolate the value directly into the API path. A
   prompt-injected `agent_id="../suite/admin/suspend-tenant"` could reach
   an entirely different route. (Audit 2026-05-08 HIGH-SDK-14.)

2. Sanitised error responses — `str(exc)` returned to the LLM as the
   tool result could expose internal hostnames, URLs, SSL details, env-var
   fragments. (Audit 2026-05-08 HIGH-SDK-18.)

3. Bounded string inputs — tools like `scan_mcp_tools(tools_json)`,
   `verify_response(prompt, response)`, `label_content(content)` accept
   unbounded LLM-supplied strings, exhausting the customer's API quota
   or OOMing the MCP process. (Audit 2026-05-08 HIGH-SDK-17.)
"""
from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger("veriswarm.mcp.tools")

# Allowlist regex for ID-shaped fields. Permits typed prefixes
# (`agt_`, `evt_`, `wfl_`, etc.), uppercase, lowercase, digits,
# hyphens, underscores. Cap length at 128 characters.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,127}$")


class ToolValidationError(ValueError):
    """Raised when a tool's caller-supplied input fails validation."""


def safe_id(value: str, field_name: str = "id") -> str:
    """Validate an ID for safe interpolation into a URL path.

    Returns the validated value unchanged. Raises ToolValidationError
    on a missing, empty, too-long, or character-class-violating value.
    """
    if not isinstance(value, str):
        raise ToolValidationError(f"{field_name} must be a string")
    if not value:
        raise ToolValidationError(f"{field_name} is required")
    if not _ID_RE.match(value):
        raise ToolValidationError(
            f"{field_name} must match ^[A-Za-z0-9][A-Za-z0-9_-]{{0,127}}$ "
            f"(got len={len(value)}; first chars rejected)"
        )
    return value


def safe_optional_id(value: str | None, field_name: str = "id") -> str | None:
    """Same as safe_id but allows None / empty for optional filter params."""
    if value is None or value == "":
        return None
    return safe_id(value, field_name)


def safe_error_response(exc: Exception, *, context: str = "request") -> str:
    """Return a JSON-string error suitable for the MCP tool result.

    Logs the real exception to stderr (logger.error) but never returns
    its repr or args to the LLM. The LLM context is the user's eyes;
    raw exception strings can include URLs, hosts, or env fragments
    that should not surface there.
    """
    logger.error("MCP tool %s failed: %r", context, exc, exc_info=True)
    return json.dumps({
        "error": f"VeriSwarm {context} failed. Check connectivity / inputs.",
        "type": type(exc).__name__,
    })


def q_path(value: object) -> str:
    """Percent-encode a value for safe use as a URL path component.

    Cheaper than safe_id when the caller wants traversal-resistance
    rather than format-validation. A value of `"../admin"` becomes
    `"..%2Fadmin"` and cannot escape the path segment.
    """
    from urllib.parse import quote as _quote
    return _quote(str(value), safe="")


def bounded_string(value: str, *, field_name: str, max_chars: int) -> str:
    """Validate a string-input field length. Raises ToolValidationError
    when the LLM-supplied value would exhaust quota / memory."""
    if not isinstance(value, str):
        raise ToolValidationError(f"{field_name} must be a string")
    if len(value) > max_chars:
        raise ToolValidationError(
            f"{field_name} exceeds maximum length ({len(value)} > {max_chars} chars)"
        )
    return value
