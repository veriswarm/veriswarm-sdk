"""Minimal HTTP client for the CLI. Zero external dependencies."""
from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _StripAuthRedirectHandler(HTTPRedirectHandler):
    """Strip credential headers when urllib follows a redirect.

    Default behaviour re-attaches custom headers like `x-api-key` to
    the redirected URL. A compromised/MITM'd response can 302 to
    attacker host and steal the user's API key. (Audit delta CRIT-D-7.)
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        new_req.headers = {
            k: v for k, v in new_req.headers.items()
            if k.lower() not in ("x-api-key", "authorization")
        }
        return new_req


_OPENER = build_opener(_StripAuthRedirectHandler())


def get_config() -> tuple[str, str]:
    """Get API base URL and key from env or config file."""
    base_url = os.environ.get("VERISWARM_API_URL", "")
    api_key = os.environ.get("VERISWARM_API_KEY", "")

    # Try config file if env not set
    if not base_url or not api_key:
        config_path = os.path.expanduser("~/.veriswarm/config.json")
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = json.load(f)
                base_url = base_url or config.get("api_url", "")
                api_key = api_key or config.get("api_key", "")

    base_url = base_url or "https://api.veriswarm.ai"
    return base_url.rstrip("/"), api_key


def api_request(path: str, *, method: str = "GET", body: dict | list | None = None, timeout: int = 15) -> dict:
    """Make an API request. Returns parsed JSON response."""
    base_url, api_key = get_config()

    if not api_key:
        raise SystemExit("No API key configured. Run 'veriswarm init' or set VERISWARM_API_KEY.")

    encoded = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(
        f"{base_url}{path}",
        data=encoded,
        method=method,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
        },
    )

    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)
        raise SystemExit(f"API error {exc.code}: {detail}")
    except URLError as exc:
        raise SystemExit(f"Connection failed: {exc.reason}")
