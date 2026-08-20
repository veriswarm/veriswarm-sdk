"""URL validation helpers for outbound VeriSwarm API clients."""
from __future__ import annotations

from urllib.parse import urlparse

_LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1"}


def validate_api_url(url: str, *, field_name: str = "VERISWARM_API_URL") -> str:
    """Return a normalized API URL if it is safe to receive auth headers.

    The MCP server sends workspace or agent credentials on every API request.
    Require HTTPS except for explicit localhost development endpoints.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f"{field_name} is required")

    normalized = url.strip().rstrip("/")
    parsed = urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"{field_name} must be an absolute URL")

    is_localhost_http = (
        parsed.scheme == "http"
        and (parsed.hostname or "").lower() in _LOCALHOST_NAMES
    )
    if parsed.scheme != "https" and not is_localhost_http:
        raise ValueError(
            f"{field_name} must be https:// (got {parsed.scheme!r}). "
            "Only http://localhost is permitted as a dev escape hatch."
        )

    return normalized
